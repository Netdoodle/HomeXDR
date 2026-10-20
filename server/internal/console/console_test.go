package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/pki"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const rule = `title: Whoami executed
id: 6f1b1a52-0000-4000-8000-000000000002
level: low
tags: [attack.discovery, attack.t1033]
logsource: {category: process_creation}
detection:
  sel:
    Image|endswith: '\whoami.exe'
  condition: sel
`

type client struct {
	t   *testing.T
	srv *httptest.Server
	hc  *http.Client
}

func (c *client) do(method, path string, body any, csrf bool) (int, map[string]any) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rdr)
	if csrf {
		req.Header.Set("X-HomeXDR-CSRF", "1")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func setup(t *testing.T) (*core.Core, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	os.MkdirAll(rules, 0o755)
	os.WriteFile(filepath.Join(rules, "r.yml"), []byte(rule), 0o644)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	p, err := pki.Load(filepath.Join(dir, "pki"), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: dir, RulesDir: rules, RetentionDays: 30, AgentURL: "https://localhost:8443", EventStore: "sqlite"}
	c, err := core.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, p)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(c))
	t.Cleanup(srv.Close)
	return c, srv
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, hc: &http.Client{Jar: jar}}
}

func TestConsoleFlow(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)

	if code, body := admin.do("GET", "/api/setup/status", nil, false); code != 200 || body["needs_setup"] != true {
		t.Fatalf("setup status = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, false); code != http.StatusForbidden {
		t.Fatalf("setup without CSRF header = %d", code)
	}
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "evil", "password": "a long enough password"}, true); code != http.StatusConflict {
		t.Fatalf("second setup = %d", code)
	}
	if code, body := admin.do("GET", "/api/auth/me", nil, false); code != 200 || body["user"].(map[string]any)["role"] != "admin" {
		t.Fatalf("me = %d %v", code, body)
	}

	// A viewer can read but not administer.
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "wrong password"}, true); code != 401 {
		t.Fatalf("bad login = %d", code)
	}
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("viewer login = %d", code)
	}
	if code, _ := viewer.do("GET", "/api/hosts", nil, false); code != 200 {
		t.Fatalf("viewer hosts = %d", code)
	}
	if code, _ := viewer.do("POST", "/api/enrollment-tokens", map[string]any{"name": "x"}, true); code != http.StatusForbidden {
		t.Fatalf("viewer create token = %d", code)
	}
	anon := newClient(t, srv)
	if code, _ := anon.do("GET", "/api/alerts", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("anonymous alerts = %d", code)
	}

	code, tok := admin.do("POST", "/api/enrollment-tokens", map[string]any{"name": "lab", "max_uses": 2}, true)
	if code != 201 || tok["token"] == "" {
		t.Fatalf("create token = %d %v", code, tok)
	}

	// Seed a host and a small process tree through the ingest path.
	host, err := c.State.CreateEndpoint(ctx, "agent-x", api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows"}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(entity, parent, name string, at time.Time) *event.Event {
		return &event.Event{ID: event.NewID(), Timestamp: at,
			Event: event.Meta{Kind: "event", Category: []string{"process"}, Type: []string{"start"}},
			Process: &event.Process{EntityID: entity, PID: int64(len(name) * 100), Name: name, Executable: `C:\Windows\System32\` + name,
				Parent: &event.Process{EntityID: parent, Name: "explorer.exe"}}}
	}
	evs := []*event.Event{
		mk("e-explorer", "", "explorer.exe", now.Add(-3*time.Minute)),
		mk("e-ps", "e-explorer", "powershell.exe", now.Add(-2*time.Minute)),
		mk("e-who", "e-ps", "whoami.exe", now.Add(-time.Minute)),
		{ID: event.NewID(), Timestamp: now, Event: event.Meta{Kind: "event", Category: []string{"network"}, Type: []string{"connection"}},
			Process: &event.Process{EntityID: "e-ps", PID: 1400}, Destination: &event.Endpoint{IP: "203.0.113.5", Port: 443}},
	}
	if err := c.Ingest(ctx, host, evs); err != nil {
		t.Fatal(err)
	}

	code, alerts := admin.do("GET", "/api/alerts?status=new", nil, false)
	if code != 200 || alerts["total"].(float64) != 1 {
		t.Fatalf("alerts = %d %v", code, alerts)
	}
	alertID := alerts["alerts"].([]any)[0].(map[string]any)["id"].(string)
	if code, a := admin.do("GET", "/api/alerts/"+alertID, nil, false); code != 200 || len(a["events"].([]any)) != 1 {
		t.Fatalf("alert detail = %d %v", code, a)
	}
	if code, _ := admin.do("PATCH", "/api/alerts/"+alertID, map[string]string{"status": "bogus"}, true); code != 400 {
		t.Fatalf("bad status = %d", code)
	}
	if code, a := admin.do("PATCH", "/api/alerts/"+alertID, map[string]string{"status": "resolved"}, true); code != 200 || a["status"] != "resolved" {
		t.Fatalf("resolve = %d %v", code, a)
	}

	code, tree := admin.do("GET", "/api/process-tree?host_id=agent-x&entity_id=e-ps", nil, false)
	if code != 200 {
		t.Fatalf("tree = %d %v", code, tree)
	}
	root := tree["root"].(map[string]any)
	if root["entity_id"] != "e-explorer" {
		t.Fatalf("root = %v", root["entity_id"])
	}
	ps := root["children"].([]any)[0].(map[string]any)
	if ps["entity_id"] != "e-ps" || ps["is_target"] != true || ps["event_counts"].(map[string]any)["network"].(float64) != 1 {
		t.Fatalf("target node = %v", ps)
	}
	who := ps["children"].([]any)[0].(map[string]any)
	if who["entity_id"] != "e-who" || who["alert_count"].(float64) != 1 {
		t.Fatalf("child node = %v", who)
	}

	code, res := admin.do("POST", "/api/events/search", map[string]any{"query": "process.name:whoami.exe"}, true)
	if code != 200 || res["total"].(float64) != 1 {
		t.Fatalf("search = %d %v", code, res)
	}
	if code, _ := admin.do("POST", "/api/events/search", map[string]any{"query": "(broken"}, true); code != 400 {
		t.Fatalf("bad query = %d", code)
	}

	// Actions are validated and queued.
	if code, _ := admin.do("POST", "/api/hosts/agent-x/actions", map[string]any{"type": "process.kill", "params": map[string]any{"pid": 1}}, true); code != 400 {
		t.Fatalf("kill pid 1 = %d", code)
	}
	if code, _ := admin.do("POST", "/api/hosts/agent-x/actions", map[string]any{"type": "run.anything", "params": map[string]any{}}, true); code != 409 {
		t.Fatalf("unknown action = %d", code)
	}
	if code, cmd := admin.do("POST", "/api/hosts/agent-x/actions", map[string]any{"type": "process.kill", "params": map[string]any{"pid": 1400, "entity_id": "e-ps"}}, true); code != 201 || cmd["status"] != "queued" {
		t.Fatalf("kill = %d %v", code, cmd)
	}
	if code, cmd := admin.do("POST", "/api/hosts/agent-x/actions", map[string]any{"type": "file.hash", "params": map[string]any{"path": "relative.txt"}}, true); code != 400 {
		t.Fatalf("relative path = %d %v", code, cmd)
	}

	// Rules: list, validate, test, custom create/disable/delete.
	if code, rl := admin.do("GET", "/api/rules", nil, false); code != 200 || rl["total"].(float64) != 1 {
		t.Fatalf("rules = %d %v", code, rl)
	}
	custom := "title: Custom\nid: custom-1\nlevel: high\nlogsource: {category: process_creation}\ndetection:\n  sel: {Image|endswith: 'powershell.exe'}\n  condition: sel\n"
	if code, v := admin.do("POST", "/api/rules/validate", map[string]string{"yaml": "nope: ["}, true); code != 200 || v["ok"] != false {
		t.Fatalf("validate bad = %d %v", code, v)
	}
	if code, v := admin.do("POST", "/api/rules/test", map[string]string{"yaml": custom}, true); code != 200 || len(v["matches"].([]any)) != 1 {
		t.Fatalf("test rule = %d %v", code, v)
	}
	if code, _ := admin.do("POST", "/api/rules", map[string]string{"yaml": custom}, true); code != 201 {
		t.Fatalf("create rule = %d", code)
	}
	if code, r := admin.do("PATCH", "/api/rules/custom-1", map[string]bool{"enabled": false}, true); code != 200 || r["enabled"] != false {
		t.Fatalf("disable rule = %d %v", code, r)
	}
	if code, _ := admin.do("DELETE", "/api/rules/6f1b1a52-0000-4000-8000-000000000002", nil, true); code != 400 {
		t.Fatalf("delete builtin = %d", code)
	}
	if code, _ := admin.do("DELETE", "/api/rules/custom-1", nil, true); code != 204 {
		t.Fatalf("delete custom = %d", code)
	}

	// Files added to the rules folder are picked up without a restart.
	if changed, _ := c.Rules.ReloadIfChanged(ctx); changed {
		t.Fatal("reloaded although nothing changed")
	}
	extra := strings.Replace(rule, "6f1b1a52-0000-4000-8000-000000000002", "folder-rule-1", 1)
	if err := os.WriteFile(filepath.Join(c.Cfg.RulesDir, "extra.yml"), []byte(extra), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := c.Rules.ReloadIfChanged(ctx); !changed || err != nil {
		t.Fatalf("ReloadIfChanged = %v, %v", changed, err)
	}
	if code, _ := viewer.do("POST", "/api/rules/reload", nil, true); code != http.StatusForbidden {
		t.Fatalf("viewer reload = %d", code)
	}
	if code, rr := admin.do("POST", "/api/rules/reload", nil, true); code != 200 || rr["total"].(float64) != 2 {
		t.Fatalf("reload = %d %v", code, rr)
	}

	// Hunts queue a command per matching host.
	code, hunt := admin.do("POST", "/api/hunts", map[string]any{"artifact": "process.list", "target": map[string]any{"all": true}}, true)
	if code != 201 || hunt["stats"].(map[string]any)["scheduled"].(float64) != 1 {
		t.Fatalf("hunt = %d %v", code, hunt)
	}

	if code, ov := admin.do("GET", "/api/stats/overview", nil, false); code != 200 || ov["events_total"].(float64) != 4 {
		t.Fatalf("overview = %d %v", code, ov)
	}
	if code, au := admin.do("GET", "/api/audit", nil, false); code != 200 || au["total"].(float64) < 5 {
		t.Fatalf("audit = %d %v", code, au)
	}
}

func TestAISettingsAndTriage(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	const key = "sk-ant-test-1234567890abcdef"
	noKey := func(body map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		if strings.Contains(string(b), key) || strings.Contains(string(b), "1234567890") {
			t.Fatalf("API key leaked: %s", b)
		}
	}
	code, body := admin.do("GET", "/api/settings/ai", nil, false)
	if code != 200 || body["key_set"] != false || body["ready"] != false || body["min_severity"] != "medium" || body["model"] != "claude-opus-5-5" {
		t.Fatalf("defaults = %d %v", code, body)
	}
	settings := map[string]any{"enabled": true, "provider": "anthropic", "model": "claude-opus-5-5", "min_severity": "medium",
		"daily_limit": 25, "max_tool_calls": 15, "api_key": key}
	code, body = admin.do("PUT", "/api/settings/ai", settings, true)
	if code != 200 || body["key_set"] != true || body["key_hint"] != "...cdef" || body["ready"] != true || body["daily_limit"] != float64(25) {
		t.Fatalf("put = %d %v", code, body)
	}
	noKey(body)
	// Saving without api_key keeps the stored key.
	delete(settings, "api_key")
	settings["min_severity"] = "high"
	code, body = admin.do("PUT", "/api/settings/ai", settings, true)
	if code != 200 || body["key_set"] != true || body["min_severity"] != "high" {
		t.Fatalf("put without key = %d %v", code, body)
	}
	_, body = admin.do("GET", "/api/settings/ai", nil, false)
	noKey(body)
	_, audit := admin.do("GET", "/api/audit", nil, false)
	noKey(audit)
	if !strings.Contains(fmt.Sprint(audit), "API key changed") {
		t.Fatalf("audit does not record the key change: %v", audit)
	}
	if code, _ := admin.do("PUT", "/api/settings/ai", map[string]any{"provider": "acme", "min_severity": "medium", "daily_limit": 1, "max_tool_calls": 1}, true); code != 400 {
		t.Fatalf("bad provider = %d", code)
	}

	// Triage endpoints on a real alert.
	if _, err := c.State.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "lab-1", OS: event.OS{Platform: "linux"}}, nil, "1"); err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{ID: event.NewID(), Timestamp: time.Now(), Host: event.Host{ID: "h1", Name: "lab-1"},
		Event: event.Meta{Category: []string{"process"}, Type: []string{"start"}}, Process: &event.Process{EntityID: "p1", Name: "nc"}}
	a, _, err := c.State.RecordAlert(ctx, store.AlertInput{Rule: store.AlertRule{ID: "r", Title: "Netcat", Level: "high"}, Severity: "high", Event: ev})
	if err != nil {
		t.Fatal(err)
	}
	code, body = admin.do("GET", "/api/alerts/"+a.ID+"/triage", nil, false)
	if code != 200 || body["triage"] != nil || body["available"] != true {
		t.Fatalf("triage before = %d %v", code, body)
	}
	if code, body := admin.do("POST", "/api/alerts/"+a.ID+"/triage", nil, true); code != http.StatusAccepted || body["status"] != "queued" || body["trigger"] != "manual" {
		t.Fatalf("request = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/alerts/"+a.ID+"/triage", nil, true); code != http.StatusConflict {
		t.Fatalf("second request = %d", code)
	}
	code, body = admin.do("GET", "/api/alerts/"+a.ID+"/triage", nil, false)
	if code != 200 || body["triage"].(map[string]any)["status"] != "queued" {
		t.Fatalf("triage after = %d %v", code, body)
	}
	if code, body := admin.do("GET", "/api/alerts?limit=5", nil, false); code != 200 ||
		body["alerts"].([]any)[0].(map[string]any)["ai_triage"].(map[string]any)["status"] != "queued" {
		t.Fatalf("alert list lacks ai_triage: %v", body)
	}
	if code, _ := admin.do("GET", "/api/alerts/nope/triage", nil, false); code != 404 {
		t.Fatalf("missing alert = %d", code)
	}
}
