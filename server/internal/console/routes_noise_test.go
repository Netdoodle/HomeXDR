package console

import (
	"context"
	"net/http"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// adminClient finishes setup and returns a signed-in admin.
func adminClient(t *testing.T, c *client) *client {
	t.Helper()
	if code, _ := c.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	return c
}

func TestSuppressionsAPI(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := adminClient(t, newClient(t, srv))

	for i := range 3 {
		ev := &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1", Name: "tower"},
			Process: &event.Process{EntityID: "p" + string(rune('a'+i)), Name: "wget", Executable: "/usr/bin/wget",
				Parent: &event.Process{Executable: "/usr/bin/php", CommandLine: "php plugin check x.plg"}}}
		if _, _, err := c.State.RecordAlert(ctx, store.AlertInput{
			Rule: store.AlertRule{ID: "r1", Title: "Wget to tmp", Level: "medium"}, Severity: "medium", Event: ev,
		}); err != nil {
			t.Fatal(err)
		}
	}

	spec := map[string]any{
		"rule_id": "r1",
		"conditions": []map[string]string{
			{"field": "process.parent.command_line", "op": "contains", "value": "plugin check"},
		},
	}

	// Preview changes nothing and needs no reason.
	code, body := admin.do("POST", "/api/suppressions/preview", spec, true)
	if code != 200 || body["matches"] != float64(1) || body["hits"] != float64(3) || len(body["sample"].([]any)) != 1 {
		t.Fatalf("preview = %d %v", code, body)
	}

	// Refusals.
	if code, _ := admin.do("POST", "/api/suppressions", map[string]any{"reason": "x"}, true); code != http.StatusBadRequest {
		t.Fatalf("no scope = %d", code)
	}
	if code, _ := admin.do("POST", "/api/suppressions", spec, true); code != http.StatusBadRequest {
		t.Fatalf("no reason = %d", code)
	}
	broad := map[string]any{"rule_id": "r1", "reason": "x"}
	if code, _ := admin.do("POST", "/api/suppressions", broad, true); code != http.StatusBadRequest {
		t.Fatalf("broad without confirm = %d", code)
	}

	// Create and close the matching alerts.
	spec["reason"] = "Unraid plugin check"
	spec["apply"] = true
	code, body = admin.do("POST", "/api/suppressions", spec, true)
	if code != http.StatusCreated || body["closed"] != float64(1) {
		t.Fatalf("create = %d %v", code, body)
	}
	sp := body["suppression"].(map[string]any)
	id := sp["id"].(string)
	if sp["created_by"] != "admin" || sp["expires_at"] == nil || sp["rule_title"] != "Wget to tmp" || sp["enabled"] != true {
		t.Fatalf("created: %v", sp)
	}

	// The default list hides suppressed alerts, and a filter finds them.
	if code, body := admin.do("GET", "/api/alerts", nil, false); code != 200 || body["total"] != float64(0) {
		t.Fatalf("default list = %d %v", code, body)
	}
	if code, body := admin.do("GET", "/api/alerts?status=suppressed", nil, false); code != 200 || body["total"] != float64(1) {
		t.Fatalf("filtered list = %d %v", code, body)
	}
	if code, body := admin.do("GET", "/api/stats/overview", nil, false); code != 200 || body["alerts_open"] != float64(0) {
		t.Fatalf("overview = %d %v", code, body)
	}
	// An analyst cannot mark an alert suppressed by hand.
	if code, _ := admin.do("POST", "/api/alerts/bulk", map[string]any{"ids": []string{"x"}, "status": "suppressed"}, true); code != http.StatusBadRequest {
		t.Fatalf("hand-suppressed = %d", code)
	}

	// Patch: scope rules still apply, the rest changes.
	if code, _ := admin.do("PATCH", "/api/suppressions/"+id, map[string]any{"conditions": []any{}}, true); code != http.StatusBadRequest {
		t.Fatalf("patch to a broad scope without confirm = %d", code)
	}
	code, body = admin.do("PATCH", "/api/suppressions/"+id, map[string]any{"enabled": false, "never_expires": true}, true)
	if code != 200 || body["enabled"] != false || body["expires_at"] != nil {
		t.Fatalf("patch = %d %v", code, body)
	}
	if code, _ := admin.do("PATCH", "/api/suppressions/nope", map[string]any{"enabled": true}, true); code != http.StatusNotFound {
		t.Fatalf("patch missing = %d", code)
	}

	// Roles: a viewer can read but not write.
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("viewer login = %d", code)
	}
	if code, body := viewer.do("GET", "/api/suppressions", nil, false); code != 200 || len(body["suppressions"].([]any)) != 1 {
		t.Fatalf("viewer list = %d %v", code, body)
	}
	if code, _ := viewer.do("POST", "/api/suppressions", spec, true); code != http.StatusForbidden {
		t.Fatalf("viewer create = %d", code)
	}
	if code, _ := viewer.do("DELETE", "/api/suppressions/"+id, nil, true); code != http.StatusForbidden {
		t.Fatalf("viewer delete = %d", code)
	}
	if code, _ := viewer.do("POST", "/api/suppressions/preview", spec, true); code != http.StatusForbidden {
		t.Fatalf("viewer preview = %d", code)
	}

	// Must-alert list.
	code, body = admin.do("PUT", "/api/settings/noise", map[string]any{"must_alert_rules": []string{"r9", " r9 "}}, true)
	if code != 200 || len(body["must_alert_rules"].([]any)) != 1 {
		t.Fatalf("put noise = %d %v", code, body)
	}
	if code, _ := viewer.do("PUT", "/api/settings/noise", map[string]any{"must_alert_rules": []string{}}, true); code != http.StatusForbidden {
		t.Fatalf("viewer put noise = %d", code)
	}

	// Delete.
	if code, _ := admin.do("DELETE", "/api/suppressions/"+id, nil, true); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if code, _ := admin.do("DELETE", "/api/suppressions/"+id, nil, true); code != http.StatusNotFound {
		t.Fatalf("delete again = %d", code)
	}

	// Audit trail.
	entries, _, err := c.State.ListAudit(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"suppression.create": false, "suppression.apply": false, "suppression.update": false, "suppression.delete": false, "suppression.must_alert": false}
	for _, e := range entries {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("no audit entry for %s", action)
		}
	}
}

func TestAlertNoise(t *testing.T) {
	ctx := context.Background()
	c, srv := setup(t)
	admin := adminClient(t, newClient(t, srv))
	record := func(entity, parent string, n int) {
		for range n {
			ev := &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1", Name: "tower"},
				Process: &event.Process{EntityID: event.NewID(), Name: "wget", Executable: "/usr/bin/wget",
					Parent: &event.Process{Executable: parent}}}
			// Each run its own key, as alerts from before grouping by shape are stored.
			if _, _, err := c.State.RecordAlert(ctx, store.AlertInput{
				Rule: store.AlertRule{ID: "r1", Title: "Wget to tmp", Level: "medium"}, Severity: "medium", Event: ev,
				DedupEntity: entity + ev.ID,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	record("a", "/usr/bin/php", 5)
	record("b", "/bin/bash", 2)
	record("c", "/bin/once", 1)

	code, body := admin.do("GET", "/api/alerts/noise", nil, false)
	if code != 200 {
		t.Fatalf("noise = %d", code)
	}
	shapes := body["shapes"].([]any)
	if len(shapes) != 2 {
		t.Fatalf("shapes = %v", shapes)
	}
	top := shapes[0].(map[string]any)
	if top["parent"] != "/usr/bin/php" || top["process"] != "/usr/bin/wget" || top["hits"] != float64(5) ||
		top["alerts"] != float64(5) || top["rule_title"] != "Wget to tmp" || top["sample_alert_id"] == "" {
		t.Fatalf("top shape = %v", top)
	}
}
