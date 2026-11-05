package console

import (
	"net/http"
	"testing"
)

func TestListRoutes(t *testing.T) {
	c, s := setup(t)
	admin, viewer := signedIn(t, s)
	if code, _ := viewer.do("GET", "/api/settings/lists", nil, false); code != http.StatusForbidden {
		t.Fatalf("viewer lists = %d", code)
	}
	code, body := admin.do("GET", "/api/settings/lists", nil, false)
	if code != 200 || len(body["lists"].([]any)) < 5 {
		t.Fatalf("lists = %d %v", code, body)
	}
	if code, _ := admin.do("PUT", "/api/settings/lists/nope", map[string]any{"enabled": true}, true); code != 404 {
		t.Fatalf("unknown list = %d", code)
	}
	if code, _ := admin.do("POST", "/api/settings/lists/nope/refresh", nil, true); code != 404 {
		t.Fatalf("unknown refresh = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/settings/lists/tranco", map[string]any{}, true); code != 400 {
		t.Fatalf("no value = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/settings/lists/tranco", map[string]any{"enabled": false}, true); code != 200 {
		t.Fatalf("turn off = %d", code)
	}
	if c.Health.Lists.Enabled("tranco") {
		t.Fatal("still on")
	}
	// Works for a viewer and needs no list: the registrable domain is built in.
	code, body = viewer.do("POST", "/api/lists/lookup", map[string]any{"indicators": []string{"a.b.example.co.uk", "d41d8cd98f00b204e9800998ecf8427e"}}, true)
	if code != 200 {
		t.Fatalf("lookup = %d", code)
	}
	results := body["results"].(map[string]any)
	dom := results["a.b.example.co.uk"].(map[string]any)["domain"].(map[string]any)
	if dom["registered"] != "example.co.uk" || len(results) != 1 {
		t.Fatalf("%v", results)
	}
}

func TestIntelViewCarriesOfflineFacts(t *testing.T) {
	_, s := setup(t)
	admin, _ := signedIn(t, s)
	code, body := admin.do("POST", "/api/intel/lookup", map[string]any{"indicator": "www.example.co.uk"}, true)
	if code != 200 {
		t.Fatalf("lookup = %d %v", code, body)
	}
	off, _ := body["offline"].(map[string]any)
	if off == nil || off["domain"].(map[string]any)["registered"] != "example.co.uk" {
		t.Fatalf("%v", body)
	}
}
