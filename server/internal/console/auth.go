package console

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
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
	key := h.clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(req.Username))
	if !h.limiter.allow(key) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again in 15 minutes")
		return
	}
	u, err := h.c.State.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrNotFound) {
		h.limiter.fail(key)
		h.c.Audit(r.Context(), req.Username, "login.failed", "", "from "+h.clientIP(r))
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	h.limiter.reset(key)
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

// loginLimiter allows 5 failures per key per 15 minutes.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	loginWindow   = 15 * time.Minute
	loginMaxFails = 5
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{failures: map[string][]time.Time{}} }

func (l *loginLimiter) recent(key string) []time.Time {
	cut := time.Now().Add(-loginWindow)
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

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < loginMaxFails
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recent(key), time.Now())
	if len(l.failures) > 10000 { // bound memory under a spray attack
		for k := range l.failures {
			delete(l.failures, k)
			if len(l.failures) < 5000 {
				break
			}
		}
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
