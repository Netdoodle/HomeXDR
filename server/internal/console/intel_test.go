package console

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeIntelService struct{}

func (fakeIntelService) RoundTrip(req *http.Request) (*http.Response, error) {
	status, body := http.StatusNotFound, `{}`
	if req.URL.Host == "internetdb.shodan.io" {
		status, body = http.StatusOK, `{"ports":[443],"hostnames":["dns.example"],"tags":[],"vulns":[]}`
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: req}, nil
}

func TestIntelAPI(t *testing.T) {
	c, srv := setup(t)
	c.Intel.HTTP = &http.Client{Transport: fakeIntelService{}}
	t.Cleanup(c.Intel.Wait)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true); code != 201 {
		t.Fatalf("create viewer = %d", code)
	}
	viewer := newClient(t, srv)
	if code, _ := viewer.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); code != 200 {
		t.Fatalf("viewer login = %d", code)
	}
	get := "/api/intel/lookup?indicator=" + url.QueryEscape("9.9.9.9")

	// A lookup sends the indicator to outside services: viewers cannot start one.
	if code, _ := viewer.do("POST", "/api/intel/lookup", map[string]any{"indicator": "9.9.9.9"}, true); code != http.StatusForbidden {
		t.Fatalf("viewer lookup = %d", code)
	}
	if code, _ := viewer.do("GET", get, nil, false); code != http.StatusNotFound {
		t.Fatalf("never looked up = %d", code)
	}
	if code, body := admin.do("POST", "/api/intel/lookup", map[string]any{"indicator": "not an indicator"}, true); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["error"]), "IP address") {
		t.Fatalf("bad indicator = %d %v", code, body)
	}
	code, body := admin.do("POST", "/api/intel/lookup", map[string]any{"indicator": "9[.]9[.]9[.]9"}, true)
	if code != 200 || body["running"] != true || body["indicator"].(map[string]any)["value"] != "9.9.9.9" {
		t.Fatalf("lookup = %d %v", code, body)
	}
	c.Intel.Wait()
	code, body = viewer.do("GET", get, nil, false)
	if code != 200 || body["running"] != false {
		t.Fatalf("get = %d %v", code, body)
	}
	summary := body["summary"].(map[string]any)
	if summary["verdict"] != "unknown" || summary["coverage"].(map[string]any)["needs_key"].(float64) != 4 {
		t.Fatalf("summary = %v", summary)
	}
	if code, body := viewer.do("GET", "/api/intel/history", nil, false); code != 200 || len(body["lookups"].([]any)) != 1 {
		t.Fatalf("history = %d %v", code, body)
	}
	if code, body := viewer.do("GET", "/api/intel/sightings?days=7&indicator=9.9.9.9", nil, false); code != 200 || body["events"] != float64(0) || body["days"] != float64(7) {
		t.Fatalf("sightings = %d %v", code, body)
	}
	if code, _ := viewer.do("GET", "/api/intel/sightings?indicator=nope", nil, false); code != http.StatusBadRequest {
		t.Fatalf("bad sightings = %d", code)
	}

	// Settings: admin only; keys go in and never come back.
	if code, _ := viewer.do("GET", "/api/settings/intel", nil, false); code != http.StatusForbidden {
		t.Fatalf("viewer settings = %d", code)
	}
	const secret = "vt-secret-key-1234567890abcd"
	code, body = admin.do("PUT", "/api/settings/intel", map[string]any{
		"providers":        map[string]any{"virustotal": map[string]any{"key": secret}, "otx": map[string]any{"enabled": false}},
		"cache_hours":      6,
		"ai_access":        false,
		"internal_domains": []string{"Corp.Example.org"},
	}, true)
	if code != 200 || body["cache_hours"] != float64(6) || body["ai_access"] != false || body["internal_domains"].([]any)[0] != "corp.example.org" {
		t.Fatalf("put = %d %v", code, body)
	}
	provider := func(body map[string]any, id string) map[string]any {
		for _, p := range body["providers"].([]any) {
			if m := p.(map[string]any); m["id"] == id {
				return m
			}
		}
		t.Fatalf("no provider %s", id)
		return nil
	}
	if vt := provider(body, "virustotal"); vt["key_set"] != true || vt["key_hint"] != "...abcd" || vt["key"] != nil {
		t.Fatalf("virustotal = %v", vt)
	}
	if otx := provider(body, "otx"); otx["enabled"] != false {
		t.Fatalf("otx = %v", otx)
	}
	raw := func(path string) string {
		_, b := admin.do("GET", path, nil, false)
		out, _ := json.Marshal(b)
		return string(out)
	}
	for _, path := range []string{"/api/settings/intel", "/api/audit?limit=50", get} {
		if s := raw(path); strings.Contains(s, secret) {
			t.Fatalf("%s leaked the key: %s", path, s)
		}
	}
	if s := raw("/api/audit?limit=50"); !strings.Contains(s, "virustotal API key changed") || !strings.Contains(s, "intel.lookup") {
		t.Fatalf("audit: %s", s)
	}
	// Saving without a key keeps it; clear_key removes it.
	_, body = admin.do("PUT", "/api/settings/intel", map[string]any{"providers": map[string]any{"virustotal": map[string]any{"enabled": true}}}, true)
	if provider(body, "virustotal")["key_set"] != true {
		t.Fatalf("key lost: %v", body)
	}
	_, body = admin.do("PUT", "/api/settings/intel", map[string]any{"providers": map[string]any{"virustotal": map[string]any{"clear_key": true}}}, true)
	if provider(body, "virustotal")["key_set"] != false {
		t.Fatalf("key kept: %v", body)
	}
	if code, _ := admin.do("PUT", "/api/settings/intel", map[string]any{"cache_hours": 99999}, true); code != http.StatusBadRequest {
		t.Fatalf("bad cache = %d", code)
	}
	if code, _ := admin.do("PUT", "/api/settings/intel", map[string]any{"providers": map[string]any{"acme": map[string]any{"enabled": true}}}, true); code != http.StatusBadRequest {
		t.Fatalf("unknown provider = %d", code)
	}

	// An internal domain stays on the server.
	code, body = admin.do("POST", "/api/intel/lookup", map[string]any{"indicator": "nas.corp.example.org"}, true)
	if code != 200 || body["indicator"].(map[string]any)["private"] != true {
		t.Fatalf("internal = %d %v", code, body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body = admin.do("GET", "/api/intel/lookup?indicator=nas.corp.example.org", nil, false)
		if body["running"] == false || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if body["summary"].(map[string]any)["verdict"] != "internal" {
		t.Fatalf("internal verdict: %v", body)
	}
}
