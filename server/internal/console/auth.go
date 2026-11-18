package console

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/version"
)

func (h *Handler) setupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := h.c.State.CountUsers(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_setup": n == 0, "version": version.Version})
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	var req credentials
	if !decode(w, r, &req) {
		return
	}
	// The first account is the admin, and whoever asks first gets it. That is only safe
	// for someone on the home network: a console that is reachable from the internet
	// before setup could otherwise be claimed by a stranger.
	if !h.localRequest(r) {
		writeErr(w, http.StatusForbidden, "the first account can only be created from the local network: open the console from a device on the same network as the server")
		return
	}
	u, err := h.c.State.CreateFirstUser(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "setup is already complete")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.c.Audit(r.Context(), u.Username, "setup", u.ID, "initial admin created from "+h.clientIP(r))
	h.startSession(w, r, u)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req credentials
	if !decode(w, r, &req) {
		return
	}
	key := h.passwordKey(r, req.Username)
	if !h.limiter.take(key, loginMaxFails) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again in 15 minutes")
		return
	}
	u, err := h.c.State.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrNotFound) {
		h.c.Audit(r.Context(), req.Username, "login.failed", "", "from "+h.clientIP(r))
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err != nil {
		h.limiter.success(key)
		h.fail(w, err)
		return
	}
	h.limiter.reset(key)
	if u.TOTPEnabled {
		// The password is only the first step: no session until a code is given.
		writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": h.mfa.create(u.ID, h.clientIP(r))})
		return
	}
	h.startSession(w, r, u)
}

func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	tok, exp, err := h.c.State.CreateSession(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.secure(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		_ = h.c.State.DeleteSession(r.Context(), ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.secure(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request, u *store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// secure reports whether the session cookie is marked Secure: when configured, and
// whenever the request arrived over HTTPS (directly or at a reverse proxy). Believing
// the proxy header here can only make the cookie stricter.
func (h *Handler) secure(r *http.Request) bool {
	return h.c.Cfg.SecureCookies || r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// caCert serves the HomeXDR CA certificate so a browser can be told to trust the console
// when it uses the server's own certificate. Public: a certificate is not a secret.
func (h *Handler) caCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="homexdr-ca.crt"`)
	_, _ = w.Write(h.c.PKI.CAPEM)
}

func forwardedFor(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func inPrefixes(list []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address failed logins are counted against. Behind a reverse proxy
// every request comes from the proxy, so its X-Forwarded-For is used, but only when the
// proxy is listed in HOMEXDR_TRUSTED_PROXIES: anyone else could put any address there.
func (h *Handler) clientIP(r *http.Request) string {
	ip := remoteIP(r)
	if !inPrefixes(h.c.Cfg.TrustedProxies, ip) {
		return ip
	}
	fwd := forwardedFor(r)
	for i := len(fwd) - 1; i >= 0; i-- {
		if _, err := netip.ParseAddr(fwd[i]); err != nil {
			break
		}
		ip = fwd[i]
		if !inPrefixes(h.c.Cfg.TrustedProxies, ip) {
			break
		}
	}
	return ip
}

// localRequest reports whether a request comes from the home network: the peer is a
// local address, and so is every address a reverse proxy says it forwarded for (a
// visitor cannot take out what the proxy adds).
func (h *Handler) localRequest(r *http.Request) bool {
	local := config.LocalNetworks()
	if !inPrefixes(local, remoteIP(r)) {
		return false
	}
	for _, ip := range forwardedFor(r) {
		if !inPrefixes(local, ip) {
			return false
		}
	}
	return true
}

// loginLimiter counts password and code attempts per key in a sliding window. An attempt
// is reserved with take before the check and only given back (success) or cleared (reset)
// once it passed, so parallel requests cannot all get past the limit before the first
// failure is recorded.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	loginWindow   = 15 * time.Minute
	loginMaxFails = 5
	// limiterMaxKeys bounds memory under a spray; above it the keys idle longest go first.
	limiterMaxKeys = 10000
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{failures: map[string][]time.Time{}} }

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	cut := now.Add(-loginWindow)
	var keep []time.Time
	for _, t := range l.failures[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = keep
	}
	return keep
}

// take reserves one attempt for key, allowing max per window. It reports false, and
// reserves nothing, when the key is at its limit. A reserved attempt counts as a failure
// until success or reset gives it back.
func (l *loginLimiter) take(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cur := l.recent(key, now)
	if len(cur) >= max {
		return false
	}
	l.failures[key] = append(cur, now)
	if len(l.failures) > limiterMaxKeys {
		l.evict(now)
	}
	return true
}

// evict drops expired keys, then the keys whose last attempt is oldest, down to half the
// cap. The key being attacked stays: it has the newest attempts.
func (l *loginLimiter) evict(now time.Time) {
	type kv struct {
		k    string
		last time.Time
	}
	var all []kv
	for k := range l.failures {
		if r := l.recent(k, now); len(r) > 0 {
			all = append(all, kv{k, r[len(r)-1]})
		}
	}
	if len(all) <= limiterMaxKeys/2 {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	for _, e := range all[:len(all)-limiterMaxKeys/2] {
		delete(l.failures, e.k)
	}
}

// success gives back one attempt reserved by take, for a check that passed or could not
// be made (a server error is not a wrong password).
func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.failures[key]; len(f) > 1 {
		l.failures[key] = f[:len(f)-1]
	} else {
		delete(l.failures, key)
	}
}

// count is the number of attempts counted against key in the window.
func (l *loginLimiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, time.Now()))
}

// reset clears a key after a successful sign-in.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// limitIP is the address part of a limiter key. IPv6 addresses count per /64, since one
// home or host usually gets a whole /64 and can pick any address in it.
func limitIP(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// passwordKey is the limiter key for password checks of a user from a request.
func (h *Handler) passwordKey(r *http.Request, username string) string {
	return limitIP(h.clientIP(r)) + "|" + strings.ToLower(strings.TrimSpace(username))
}
