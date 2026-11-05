package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

func TestNotificationSettingsAPI(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := adminClient(t, newClient(t, srv))

	var mu sync.Mutex
	var got []string
	status := 200
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(b))
		w.WriteHeader(status)
	}))
	defer hook.Close()
	hookURL := hook.URL + "/hook-secret-path"

	// Off by default, with the safe routes.
	code, body := admin.do("GET", "/api/settings/notifications", nil, false)
	if code != 200 || len(body["channels"].([]any)) != 0 || body["rate_per_hour"] != float64(10) {
		t.Fatalf("defaults = %d %v", code, body)
	}
	routes := body["severity_routes"].(map[string]any)
	if routes["critical"] != "now" || routes["high"] != "now" || routes["medium"] != "digest" || routes["low"] != "log" || routes["informational"] != "log" {
		t.Fatalf("default routes = %v", routes)
	}

	// A bad value is the owner's to fix: 400, with a reason.
	settings := map[string]any{
		"severity_routes": routes, "rate_per_hour": 10, "digest_enabled": true, "digest_time": "seven",
		"channels": []map[string]any{{"id": "c1", "kind": "webhook", "name": "hook", "enabled": true, "url": hookURL, "token": "tok-secret"}},
	}
	code, body = admin.do("PUT", "/api/settings/notifications", settings, true)
	if code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "digest time") {
		t.Fatalf("bad time = %d %v", code, body)
	}

	settings["digest_time"] = "07:30"
	code, body = admin.do("PUT", "/api/settings/notifications", settings, true)
	if code != 200 {
		t.Fatalf("save = %d %v", code, body)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "hook-secret-path") || strings.Contains(string(raw), "tok-secret") {
		t.Fatalf("the API returned a secret: %s", raw)
	}
	ch := body["channels"].([]any)[0].(map[string]any)
	if ch["url_set"] != true || ch["token_set"] != true || body["digest_time"] != "07:30" {
		t.Fatalf("view = %v", body)
	}
	if _, ok := body["status"].(map[string]any); !ok {
		t.Fatalf("no status in %v", body)
	}

	// The test button works, and a failure says why without showing the URL.
	code, body = admin.do("POST", "/api/settings/notifications/channels/c1/test", nil, true)
	if code != 200 || body["ok"] != true || len(got) != 1 {
		t.Fatalf("test = %d %v, %d received", code, body, len(got))
	}
	mu.Lock()
	status = 403
	mu.Unlock()
	code, body = admin.do("POST", "/api/settings/notifications/channels/c1/test", nil, true)
	if code != 200 || body["ok"] != false || !strings.Contains(body["error"].(string), "403") || strings.Contains(body["error"].(string), "hook-secret-path") {
		t.Fatalf("failed test = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/settings/notifications/channels/nope/test", nil, true); code != http.StatusNotFound {
		t.Fatalf("test of a missing channel = %d", code)
	}

	// Admin only.
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "ann", "password": "analyst password!", "role": "analyst"}, true); code != 201 {
		t.Fatalf("create analyst = %d", code)
	}
	analyst := newClient(t, srv)
	if code, _ := analyst.do("POST", "/api/auth/login", map[string]string{"username": "ann", "password": "analyst password!"}, true); code != 200 {
		t.Fatalf("analyst login = %d", code)
	}
	if code, _ := analyst.do("GET", "/api/settings/notifications", nil, false); code != http.StatusForbidden {
		t.Fatalf("analyst read = %d", code)
	}
	if code, _ := analyst.do("POST", "/api/settings/notifications/channels/c1/test", nil, true); code != http.StatusForbidden {
		t.Fatalf("analyst test = %d", code)
	}

	// The audit log says what changed and holds no secret.
	entries, _, err := c.State.ListAudit(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
		if strings.Contains(e.Details, "hook-secret-path") || strings.Contains(e.Details, "tok-secret") {
			t.Fatalf("the audit log holds a secret: %+v", e)
		}
	}
	if !seen["notify.settings"] || !seen["notify.test"] {
		t.Fatalf("audit actions: %v", seen)
	}
}

// A rule hit reaches the outbox through the same path as everything else, and a suppressed
// one does not.
func TestHitsReachNotifications(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := adminClient(t, newClient(t, srv))
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hook.Close()
	if code, body := admin.do("PUT", "/api/settings/notifications", map[string]any{
		"severity_routes": map[string]string{"high": "now"}, "rate_per_hour": 10, "digest_time": "07:00",
		"channels": []map[string]any{{"id": "c1", "kind": "webhook", "enabled": true, "url": hook.URL}},
	}, true); code != 200 {
		t.Fatalf("save = %d %v", code, body)
	}
	finding := func(id string) error {
		return c.RaiseFinding(ctx, core.Finding{RuleID: id, Title: id, Severity: store.SevHigh, Entity: "e1", HostID: "h1", Hostname: "tower"})
	}
	if err := finding("net:one"); err != nil {
		t.Fatal(err)
	}
	if code, body := admin.do("POST", "/api/suppressions", map[string]any{
		"rule_id": "net:two", "host_id": "h1", "reason": "known",
	}, true); code != http.StatusCreated {
		t.Fatalf("suppress = %d %v", code, body)
	}
	if err := finding("net:two"); err != nil {
		t.Fatal(err)
	}
	status, err := c.Notify.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != 1 {
		t.Fatalf("pending = %d, want only the unsuppressed finding", status.Pending)
	}
}
