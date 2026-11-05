package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// signedIn returns an admin and a viewer on a fresh server.
func signedIn(t *testing.T, srv *httptest.Server) (admin, viewer *client) {
	t.Helper()
	admin = newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": store.RoleViewer}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer = newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("login = %d", code)
	}
	return admin, viewer
}

func TestFeedHealthRoutes(t *testing.T) {
	c, s := setup(t)
	admin, viewer := signedIn(t, s)
	h, err := c.State.CreateEndpoint(context.Background(), "tower-id", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux"}}, nil, "serial")
	if err != nil {
		t.Fatal(err)
	}

	code, body := viewer.do("GET", "/api/health/feeds", nil, false)
	if code != 200 {
		t.Fatalf("viewer read = %d", code)
	}
	found := false
	for _, x := range body["sources"].([]any) {
		m := x.(map[string]any)
		if m["dataset"] == "inventory.software.list" && m["status"] == "never_seen" && m["hostname"] == "tower" {
			found = true
		}
	}
	if !found {
		t.Fatalf("known feed not listed: %v", body)
	}

	patch := map[string]any{"host_id": h.ID, "module": "inventory", "dataset": "inventory.software.list", "muted": true}
	if code, _ := viewer.do("PATCH", "/api/health/feeds", patch, true); code != http.StatusForbidden {
		t.Fatalf("viewer patch = %d", code)
	}
	code, body = admin.do("PATCH", "/api/health/feeds", patch, true)
	if code != 200 {
		t.Fatalf("admin patch = %d %v", code, body)
	}
	muted := false
	for _, x := range body["sources"].([]any) {
		m := x.(map[string]any)
		if m["dataset"] == "inventory.software.list" {
			muted = m["muted"] == true && m["status"] == "muted"
		}
	}
	if !muted {
		t.Fatalf("not muted: %v", body)
	}

	if code, _ := admin.do("PATCH", "/api/health/feeds", map[string]any{"host_id": "nope", "muted": true}, true); code != 404 {
		t.Fatalf("unknown host = %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/health/feeds", map[string]any{"host_id": h.ID}, true); code != 400 {
		t.Fatalf("no change = %d", code)
	}
}
