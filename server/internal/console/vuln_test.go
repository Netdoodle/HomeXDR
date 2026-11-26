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
	if m, ok := body["findings"].([]any); !ok || len(m) != 0 {
		t.Fatalf("findings should be an empty list: %v", body)
	}
	for _, src := range body["sources"].([]any) {
		if src.(map[string]any)["enabled"] != true {
			t.Fatalf("sources should be on by default: %v", src)
		}
	}
	if osv := body["osv_api"].(map[string]any); osv["enabled"] != false {
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
	if code != 200 || body["osv_api"].(map[string]any)["enabled"] != true {
		t.Fatalf("settings = %d %v", code, body)
	}
	accept := map[string]any{"host_id": "h1", "package": "exim", "cve": "CVE-2010-4344", "accepted": true, "note": "lab box"}
	if code, _ := viewer.do("PUT", "/api/vulnerabilities/accept", accept, true); code != http.StatusForbidden {
		t.Fatalf("viewer accept = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/vulnerabilities/accept", accept, true); code != http.StatusNotFound {
		t.Fatalf("accept unknown = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/vulnerabilities/accept", map[string]any{"accepted": true}, true); code != http.StatusBadRequest {
		t.Fatalf("accept empty = %d", code)
	}
	if code, _ := admin.do("POST", "/api/vulnerabilities/refresh", nil, true); code != 200 {
		t.Fatalf("refresh = %d", code)
	}
}
