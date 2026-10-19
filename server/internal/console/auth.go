package console

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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
	u, err := h.c.State.CreateFirstUser(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "setup is already complete")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.c.Audit(r.Context(), u.Username, "setup", u.ID, "initial admin created from "+remoteIP(r))
	h.startSession(w, r, u)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req credentials
	if !decode(w, r, &req) {
		return
	}
	key := remoteIP(r) + "|" + strings.ToLower(strings.TrimSpace(req.Username))
	if !h.limiter.allow(key) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again in 15 minutes")
		return
	}
	u, err := h.c.State.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrNotFound) {
		h.limiter.fail(key)
		h.c.Audit(r.Context(), req.Username, "login.failed", "", "from "+remoteIP(r))
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
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.c.Cfg.SecureCookies,
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		_ = h.c.State.DeleteSession(r.Context(), ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.c.Cfg.SecureCookies,
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
