package console

import (
	"net/http"
	"testing"
)

func TestVulnRoutes(t *testing.T) {
	_, s := setup(t)
	admin, viewer := signedIn(t, s)
	code, body := viewer.do("GET", "/api/vulnerabilities", nil, false)
	if code != 200 {
		t.Fatalf("viewer read = %d", code)
	}
	if m, ok := body["matches"].([]any); !ok || len(m) != 0 {
		t.Fatalf("matches should be an empty list: %v", body)
	}
	if kev := body["kev"].(map[string]any); kev["enabled"] != true {
		t.Fatalf("catalog should be on by default: %v", kev)
	}
	if osv := body["osv"].(map[string]any); osv["enabled"] != false {
		t.Fatalf("OSV must be off by default: %v", osv)
	}
	if code, _ := viewer.do("POST", "/api/vulnerabilities/refresh", nil, true); code != http.StatusForbidden {
		t.Fatalf("viewer refresh = %d", code)
	}
	if code, _ := viewer.do("PUT", "/api/settings/vuln", map[string]any{"osv": true}, true); code != http.StatusForbidden {
		t.Fatalf("viewer settings = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/settings/vuln", map[string]any{}, true); code != 400 {
		t.Fatalf("no value = %d", code)
	}
	code, body = admin.do("PUT", "/api/settings/vuln", map[string]any{"osv": true}, true)
	if code != 200 || body["osv"].(map[string]any)["enabled"] != true {
		t.Fatalf("settings = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/vulnerabilities/refresh", nil, true); code != 200 {
		t.Fatalf("refresh = %d", code)
	}
}
