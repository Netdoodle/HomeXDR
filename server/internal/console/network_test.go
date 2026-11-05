package console

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestDevicesAPI(t *testing.T) {
	c, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("login = %d", code)
	}

	host := &store.Host{ID: "fw", Kind: store.HostNetwork, Hostname: "fw"}
	c.Inventory.Observe(host, []*event.Event{{
		Event:  event.Meta{Module: event.ModuleDHCP},
		Source: &event.Endpoint{IP: "192.168.20.50", MAC: "00:11:22:33:44:55", Domain: "printer"},
		Data:   map[string]any{"dhcp_message": "ACK"},
	}})

	code, body := viewer.do("GET", "/api/devices", nil, false)
	if code != 200 || body["total"] != float64(1) || body["learning"] != true {
		t.Fatalf("list = %d %v", code, body)
	}
	d := body["devices"].([]any)[0].(map[string]any)
	if d["id"] != "00:11:22:33:44:55" || d["hostname"] != "printer" || d["ip"] != "192.168.20.50" || d["known"] != false {
		t.Fatalf("device %v", d)
	}

	path := "/api/devices/" + url.PathEscape("00:11:22:33:44:55")
	if code, _ := viewer.do("PATCH", path, map[string]any{"known": true}, true); code != http.StatusForbidden {
		t.Fatalf("viewer patch = %d", code)
	}
	code, body = admin.do("PATCH", path, map[string]any{"name": "Office printer", "note": "second floor", "known": true}, true)
	if code != 200 || body["name"] != "Office printer" || body["known"] != true || body["note"] != "second floor" {
		t.Fatalf("patch = %d %v", code, body)
	}
	if code, _ := admin.do("PATCH", "/api/devices/nope", map[string]any{"known": true}, true); code != 404 {
		t.Fatalf("missing device = %d", code)
	}
	if code, _ := admin.do("PATCH", path, map[string]any{}, true); code != 400 {
		t.Fatalf("empty patch = %d", code)
	}
	stored, err := c.State.ListDevices(context.Background())
	if err != nil || len(stored) != 1 || stored[0].Name != "Office printer" {
		t.Fatalf("stored %+v %v", stored, err)
	}

	// Settings are for admins, and bad values are refused with the reason.
	if code, _ := viewer.do("GET", "/api/settings/network", nil, false); code != http.StatusForbidden {
		t.Fatalf("viewer settings = %d", code)
	}
	code, body = admin.do("GET", "/api/settings/network", nil, false)
	if code != 200 || body["new_device_alerts"] != true || body["learning_days"] != float64(3) || len(body["subnets_seen"].([]any)) != 1 {
		t.Fatalf("settings = %d %v", code, body)
	}
	code, body = admin.do("PUT", "/api/settings/network", map[string]any{"subnets": []string{"not a subnet"}, "learning_days": 3}, true)
	if code != 400 || body["error"] == nil {
		t.Fatalf("bad settings = %d %v", code, body)
	}
	code, body = admin.do("PUT", "/api/settings/network", map[string]any{"subnets": []string{"192.168.20.0/24"}, "learning_days": 5, "new_device_alerts": false}, true)
	if code != 200 || body["new_device_alerts"] != false || body["learning_days"] != float64(5) {
		t.Fatalf("put settings = %d %v", code, body)
	}
}

func TestBehaviorAPI(t *testing.T) {
	_, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("login = %d", code)
	}
	code, body := viewer.do("GET", "/api/behavior/status", nil, false)
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	list := body["detectors"].([]any)
	if len(list) != 8 {
		t.Fatalf("%d detectors", len(list))
	}
	first := list[0].(map[string]any)
	if first["id"] != "beaconing" || first["status"] != "pending" || first["enabled"] != true || first["last_finding_count"] != float64(0) {
		t.Fatalf("status %v", first)
	}
	if code, _ := viewer.do("GET", "/api/settings/behavior", nil, false); code != http.StatusForbidden {
		t.Fatalf("viewer settings = %d", code)
	}
	code, body = admin.do("GET", "/api/settings/behavior", nil, false)
	if code != 200 || body["detectors"].([]any)[0].(map[string]any)["values"].(map[string]any)["max_cv"] != 0.15 {
		t.Fatalf("settings = %d %v", code, body)
	}
	code, body = admin.do("PUT", "/api/settings/behavior", map[string]any{"detectors": map[string]any{"beaconing": map[string]any{"values": map[string]any{"max_cv": 9}}}}, true)
	if code != 400 || body["error"] == nil {
		t.Fatalf("bad settings = %d %v", code, body)
	}
	code, body = admin.do("PUT", "/api/settings/behavior", map[string]any{"detectors": map[string]any{"beaconing": map[string]any{"enabled": false, "values": map[string]any{"max_cv": 0.1}}}}, true)
	if code != 200 || body["detectors"].([]any)[0].(map[string]any)["enabled"] != false {
		t.Fatalf("put settings = %d %v", code, body)
	}
	if _, body = viewer.do("GET", "/api/behavior/status", nil, false); body["detectors"].([]any)[0].(map[string]any)["status"] != "disabled" {
		t.Fatalf("after disabling %v", body)
	}
}
