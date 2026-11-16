package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/totp"
)

const adminPW = "a long enough password"

type mfaEnv struct {
	h      *Handler
	srv    *httptest.Server
	admin  *client
	secret string
	codes  []string
	last   time.Time // the time whose code turned two-factor on
}

func at(d time.Duration) time.Time { return time.Now().Add(d) }

// newMFAEnv sets up an admin with two-factor on. Turning it on used the code for the
// previous step, so the current and the next step's codes are still fresh.
func newMFAEnv(t *testing.T) *mfaEnv {
	t.Helper()
	c, _ := setup(t)
	h := New(c)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": adminPW}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if code, body := admin.do("GET", "/api/account/totp", nil, false); code != 200 || body["enabled"] != false {
		t.Fatalf("status = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/account/totp/setup", map[string]string{"password": "wrong password!!"}, true); code != http.StatusForbidden {
		t.Fatalf("setup with a wrong password = %d", code)
	}
	code, body := admin.do("POST", "/api/account/totp/setup", map[string]string{"password": adminPW}, true)
	if code != 200 {
		t.Fatalf("setup = %d %v", code, body)
	}
	secret, _ := body["secret"].(string)
	if uri, _ := body["uri"].(string); secret == "" || !strings.HasPrefix(uri, "otpauth://totp/HomeXDR:admin?") || !strings.Contains(uri, secret) {
		t.Fatalf("setup body %v", body)
	}
	if code, _ := admin.do("POST", "/api/account/totp/enable", map[string]string{"code": "000000"}, true); code != http.StatusForbidden && code != 200 {
		t.Fatalf("enable with a wrong code = %d", code)
	} else if code == 200 {
		t.Skip("000000 happened to be the right code")
	}
	prev := at(-30 * time.Second)
	code, body = admin.do("POST", "/api/account/totp/enable", map[string]string{"code": totp.Code(secret, prev)}, true)
	if code != 200 {
		t.Fatalf("enable = %d %v", code, body)
	}
	var codes []string
	for _, c := range body["recovery_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	if len(codes) != 10 {
		t.Fatalf("recovery codes: %v", codes)
	}
	return &mfaEnv{h: h, srv: srv, admin: admin, secret: secret, codes: codes, last: prev}
}

// passwordStep logs in with the password and returns the client and the MFA token.
func (e *mfaEnv) passwordStep(t *testing.T, user, pw string) (*client, string) {
	t.Helper()
	cl := newClient(t, e.srv)
	code, body := cl.do("POST", "/api/auth/login", map[string]string{"username": user, "password": pw}, true)
	if code != 200 || body["mfa_required"] != true {
		t.Fatalf("login = %d %v", code, body)
	}
	if _, has := body["user"]; has {
		t.Fatal("login with two-factor on returned a user")
	}
	tok, _ := body["mfa_token"].(string)
	if len(tok) != 64 {
		t.Fatalf("token %q", tok)
	}
	if code, _ := cl.do("GET", "/api/auth/me", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("me before the code = %d", code)
	}
	return cl, tok
}

func (e *mfaEnv) mfa(cl *client, tok, code string) int {
	c, _ := cl.do("POST", "/api/auth/mfa", map[string]string{"mfa_token": tok, "code": code}, true)
	return c
}

func TestMFALoginFlow(t *testing.T) {
	e := newMFAEnv(t)

	// Wrong code, then the code that turned it on (reused), both refused.
	cl, tok := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl, tok, "123456"); c != http.StatusUnauthorized && c != http.StatusOK {
		t.Fatalf("wrong code = %d", c)
	}
	if c := e.mfa(cl, tok, totp.Code(e.secret, e.last)); c != http.StatusUnauthorized {
		t.Fatalf("reused code = %d", c)
	}
	// The right code (with spaces) works once, and the token is spent.
	cur := totp.Code(e.secret, time.Now())
	if c := e.mfa(cl, tok, cur[:3]+" "+cur[3:]); c != http.StatusOK {
		t.Fatalf("right code = %d", c)
	}
	if code, body := cl.do("GET", "/api/auth/me", nil, false); code != 200 || body["user"].(map[string]any)["username"] != "admin" {
		t.Fatalf("me after the code = %d %v", code, body)
	}
	if c := e.mfa(cl, tok, totp.Code(e.secret, at(30*time.Second))); c != http.StatusUnauthorized {
		t.Fatalf("used token = %d", c)
	}

	// The same code in a new login is a replay.
	cl2, tok2 := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl2, tok2, cur); c != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d", c)
	}
	// The next step's code is still fresh.
	if c := e.mfa(cl2, tok2, totp.Code(e.secret, at(30*time.Second))); c != http.StatusOK {
		t.Fatalf("next-step code = %d", c)
	}

	// Unknown token.
	if c := e.mfa(cl2, strings.Repeat("a", 64), cur); c != http.StatusUnauthorized {
		t.Fatalf("unknown token = %d", c)
	}
}

func TestMFATokenExpiresAndIsBoundToIP(t *testing.T) {
	e := newMFAEnv(t)
	cl, tok := e.passwordStep(t, "admin", adminPW)
	e.h.mfa.mu.Lock()
	e.h.mfa.m[tok].exp = time.Now().Add(-time.Second)
	e.h.mfa.mu.Unlock()
	if c := e.mfa(cl, tok, totp.Code(e.secret, time.Now())); c != http.StatusUnauthorized {
		t.Fatalf("expired token = %d", c)
	}

	cl, tok = e.passwordStep(t, "admin", adminPW)
	e.h.mfa.mu.Lock()
	e.h.mfa.m[tok].ip = "203.0.113.7"
	e.h.mfa.mu.Unlock()
	if c := e.mfa(cl, tok, totp.Code(e.secret, time.Now())); c != http.StatusUnauthorized {
		t.Fatalf("token from another address = %d", c)
	}
}

func TestMFATokenAttemptLimit(t *testing.T) {
	e := newMFAEnv(t)
	cl, tok := e.passwordStep(t, "admin", adminPW)
	for i := 0; i < 5; i++ {
		if c := e.mfa(cl, tok, "000000"); c == http.StatusOK {
			t.Skip("000000 was the right code")
		}
	}
	if c := e.mfa(cl, tok, totp.Code(e.secret, time.Now())); c == http.StatusOK {
		t.Fatal("a sixth attempt on one token succeeded")
	}
	// The failures are throttled like failed logins.
	cl2, tok2 := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl2, tok2, totp.Code(e.secret, time.Now())); c != http.StatusTooManyRequests {
		t.Fatalf("after repeated failures = %d", c)
	}
}

func TestMFARecoveryCode(t *testing.T) {
	e := newMFAEnv(t)
	rc := e.codes[0]
	cl, tok := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl, tok, strings.ToUpper(rc)); c != http.StatusOK {
		t.Fatalf("recovery code = %d", c)
	}
	if code, body := e.admin.do("GET", "/api/account/totp", nil, false); code != 200 || body["recovery_left"] != float64(9) {
		t.Fatalf("status = %d %v", code, body)
	}
	cl2, tok2 := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl2, tok2, rc); c != http.StatusUnauthorized {
		t.Fatalf("recovery code used twice = %d", c)
	}
	if c := e.mfa(cl2, tok2, e.codes[1]); c != http.StatusOK {
		t.Fatalf("second recovery code = %d", c)
	}
	// The audit log notes the recovery use, never the code.
	found := false
	rows, _, _ := e.h.c.State.ListAudit(t.Context(), 100, 0)
	for _, a := range rows {
		if a.Action == "auth.mfa" && strings.Contains(a.Details, "recovery code") && strings.Contains(a.Details, "left") {
			found = true
		}
		if strings.Contains(a.Details, rc) || strings.Contains(a.Details, e.secret) {
			t.Fatalf("audit detail leaks a secret: %q", a.Details)
		}
	}
	if !found {
		t.Fatal("no audit entry for the recovery login")
	}
}

func TestTOTPDisableRecoveryAndSecrecy(t *testing.T) {
	e := newMFAEnv(t)

	// No secret or hash appears in /me, the user list or the status.
	check := func(path string) {
		code, body := e.admin.do("GET", path, nil, false)
		b, _ := json.Marshal(body)
		if code != 200 || strings.Contains(string(b), e.secret) || strings.Contains(strings.ToLower(string(b)), "secret") || strings.Contains(string(b), "recovery_hash") {
			t.Fatalf("%s = %d %s", path, code, b)
		}
	}
	check("/api/auth/me")
	check("/api/account/totp")
	_, list := e.admin.do("GET", "/api/users", nil, false)
	if b, _ := json.Marshal(list); strings.Contains(string(b), e.secret) || strings.Contains(string(b), "secret") {
		t.Fatalf("users list leaks: %s", b)
	}
	if _, body := e.admin.do("GET", "/api/auth/me", nil, false); body["user"].(map[string]any)["totp_enabled"] != true {
		t.Fatalf("me: %v", body)
	}

	// New recovery codes invalidate the old ones.
	if c, _ := e.admin.do("POST", "/api/account/totp/recovery", map[string]string{"password": adminPW, "code": "111111"}, true); c != http.StatusForbidden {
		t.Fatalf("recovery with a wrong code = %d", c)
	}
	c, body := e.admin.do("POST", "/api/account/totp/recovery", map[string]string{"password": adminPW, "code": totp.Code(e.secret, time.Now())}, true)
	if c != 200 || len(body["recovery_codes"].([]any)) != 10 {
		t.Fatalf("new recovery codes = %d %v", c, body)
	}
	newCode := body["recovery_codes"].([]any)[0].(string)
	cl, tok := e.passwordStep(t, "admin", adminPW)
	if e.mfa(cl, tok, e.codes[2]) != http.StatusUnauthorized {
		t.Fatal("an old recovery code still works")
	}

	// Turning off: wrong password, wrong code, then a recovery code does it.
	if c, _ := e.admin.do("POST", "/api/account/totp/disable", map[string]string{"password": "wrong password!!", "code": newCode}, true); c != http.StatusForbidden {
		t.Fatalf("disable with a wrong password = %d", c)
	}
	if c, _ := e.admin.do("POST", "/api/account/totp/disable", map[string]string{"password": adminPW, "code": "111111"}, true); c != http.StatusForbidden {
		t.Fatalf("disable with a wrong code = %d", c)
	}
	if c, _ := e.admin.do("POST", "/api/account/totp/disable", map[string]string{"password": adminPW, "code": newCode}, true); c != 200 {
		t.Fatalf("disable = %d", c)
	}
	if code, body := e.admin.do("GET", "/api/account/totp", nil, false); code != 200 || body["enabled"] != false {
		t.Fatalf("status after disable = %d %v", code, body)
	}
	st, err := e.h.c.State.GetTOTP(t.Context(), mustAdminID(t, e))
	if err != nil || st.Secret != "" || st.Enabled || st.LastStep != 0 || st.RecoveryLeft != 0 {
		t.Fatalf("state after disable: %+v %v", st, err)
	}
	if code, body := newClient(t, e.srv).do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": adminPW}, true); code != 200 || body["user"] == nil {
		t.Fatalf("login after disable = %d %v", code, body)
	}
}

func mustAdminID(t *testing.T, e *mfaEnv) string {
	t.Helper()
	_, body := e.admin.do("GET", "/api/auth/me", nil, false)
	return body["user"].(map[string]any)["id"].(string)
}

func TestAdminResetTOTP(t *testing.T) {
	e := newMFAEnv(t)
	_, vic := e.admin.do("POST", "/api/users", map[string]string{"username": "vic", "password": "viewer password!", "role": "viewer"}, true)
	vicID := vic["id"].(string)

	v := newClient(t, e.srv)
	if c, _ := v.do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); c != 200 {
		t.Fatalf("viewer login = %d", c)
	}
	_, body := v.do("POST", "/api/account/totp/setup", map[string]string{"password": "viewer password!"}, true)
	secret := body["secret"].(string)
	if c, _ := v.do("POST", "/api/account/totp/enable", map[string]string{"code": totp.Code(secret, time.Now())}, true); c != 200 {
		t.Fatalf("viewer enable = %d", c)
	}
	if c, _ := newClient(t, e.srv).do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); c != 200 {
		t.Fatalf("login = %d", c)
	}
	if st, _ := e.h.c.State.GetTOTP(t.Context(), vicID); !st.Enabled {
		t.Fatal("two-factor is not on for the viewer")
	}

	// A viewer cannot reset anyone; the admin can.
	if c, _ := v.do("POST", "/api/users/"+vicID+"/totp/reset", nil, true); c != http.StatusForbidden {
		t.Fatalf("viewer reset = %d", c)
	}
	if c, _ := e.admin.do("POST", "/api/users/nope/totp/reset", nil, true); c != http.StatusNotFound {
		t.Fatalf("reset of an unknown user = %d", c)
	}
	if c, _ := e.admin.do("POST", "/api/users/"+vicID+"/totp/reset", nil, true); c != 200 {
		t.Fatalf("admin reset = %d", c)
	}
	if c, body := newClient(t, e.srv).do("POST", "/api/auth/login", map[string]string{"username": "vic", "password": "viewer password!"}, true); c != 200 || body["user"] == nil {
		t.Fatalf("login after reset = %d %v", c, body)
	}
	found := false
	rows, _, _ := e.h.c.State.ListAudit(t.Context(), 100, 0)
	for _, a := range rows {
		if a.Action == "user.totp.reset" && a.Target == vicID {
			found = true
		}
	}
	if !found {
		t.Fatal("reset not audited")
	}
}
