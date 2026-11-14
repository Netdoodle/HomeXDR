package console

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func post(t *testing.T, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("X-HomeXDR-CSRF", "1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// The first account cannot be claimed through a reverse proxy by a visitor from the
// internet, and the session cookie is Secure whenever the request came over HTTPS.
func TestSetupOnlyFromLocalNetwork(t *testing.T) {
	_, srv := setup(t)
	creds := `{"username":"admin","password":"a long enough password"}`
	if resp := post(t, srv.URL+"/api/setup", creds, map[string]string{"X-Forwarded-For": "203.0.113.9"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("setup for an internet visitor = %d", resp.StatusCode)
	}
	if resp := post(t, srv.URL+"/api/setup", creds, map[string]string{"X-Forwarded-For": "192.168.20.5, 203.0.113.9"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("setup with a forged first hop = %d", resp.StatusCode)
	}
	resp := post(t, srv.URL+"/api/setup", creds, map[string]string{"X-Forwarded-For": "192.168.20.5", "X-Forwarded-Proto": "https"})
	if resp.StatusCode != 200 {
		t.Fatalf("setup from the local network = %d", resp.StatusCode)
	}
	if cks := resp.Cookies(); len(cks) != 1 || !cks[0].Secure {
		t.Fatalf("cookie over HTTPS is not Secure: %+v", cks)
	}
	resp = post(t, srv.URL+"/api/auth/login", creds, nil)
	if cks := resp.Cookies(); resp.StatusCode != 200 || len(cks) != 1 || cks[0].Secure {
		t.Fatalf("plain HTTP login = %d %+v", resp.StatusCode, cks)
	}
}

// Changing your own password needs the current one; an admin sets another user's
// without it.
func TestOwnPasswordNeedsCurrent(t *testing.T) {
	_, srv := setup(t)
	admin := newClient(t, srv)
	_, body := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a long enough password"}, true)
	adminID := body["user"].(map[string]any)["id"].(string)
	_, vic := admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true)
	vicID := vic["id"].(string)

	if code, _ := admin.do("PATCH", "/api/users/"+adminID, map[string]string{"password": "another long password"}, true); code != http.StatusForbidden {
		t.Fatalf("own password without the current one = %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/users/"+adminID, map[string]string{"password": "another long password", "current_password": "not it"}, true); code != http.StatusForbidden {
		t.Fatalf("own password with a wrong current one = %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/users/"+vicID, map[string]string{"password": "reset by the admin"}, true); code != 200 {
		t.Fatalf("admin reset of another user = %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/users/"+adminID, map[string]string{"password": "another long password", "current_password": "a long enough password"}, true); code != 200 {
		t.Fatalf("own password with the current one = %d", code)
	}
	if code, _ := newClient(t, srv).do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "another long password"}, true); code != 200 {
		t.Fatalf("login with the new password = %d", code)
	}
}

// X-Forwarded-For names the client only when the request comes from a trusted proxy.
func TestClientIP(t *testing.T) {
	c, _ := setup(t)
	h := New(c)
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	if got := h.clientIP(req("192.168.20.10:5555", "1.2.3.4")); got != "192.168.20.10" {
		t.Errorf("untrusted peer: %s", got)
	}
	c.Cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.168.20.10/32")}
	for xff, want := range map[string]string{
		"1.2.3.4":                "1.2.3.4",
		"9.9.9.9, 1.2.3.4":       "1.2.3.4", // the first entry is the visitor's own claim
		"1.2.3.4, 192.168.20.10": "1.2.3.4",
		"":                       "192.168.20.10",
		"junk":                   "192.168.20.10",
	} {
		if got := h.clientIP(req("192.168.20.10:5555", xff)); got != want {
			t.Errorf("xff %q: %s, want %s", xff, got, want)
		}
	}
}
