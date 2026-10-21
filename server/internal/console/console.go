// Package console serves the web console's REST API (docs/api.md).
package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Handler serves /api.
type Handler struct {
	c       *core.Core
	mux     *http.ServeMux
	limiter *loginLimiter
}

type userKey struct{}

// New returns the console API handler.
func New(c *core.Core) *Handler {
	h := &Handler{c: c, mux: http.NewServeMux(), limiter: newLoginLimiter()}

	// Public.
	h.mux.HandleFunc("GET /api/setup/status", h.setupStatus)
	h.mux.HandleFunc("POST /api/setup", h.setup)
	h.mux.HandleFunc("POST /api/auth/login", h.login)
	h.mux.HandleFunc("POST /api/auth/logout", h.logout)

	viewer, analyst, admin := store.RoleViewer, store.RoleAnalyst, store.RoleAdmin
	h.route("GET /api/auth/me", viewer, h.me)
	h.route("GET /api/stats/overview", viewer, h.overview)

	h.route("GET /api/hosts", viewer, h.listHosts)
	h.route("GET /api/hosts/{id}", viewer, h.getHost)
	h.route("PATCH /api/hosts/{id}", analyst, h.patchHost)
	h.route("DELETE /api/hosts/{id}", admin, h.deleteHost)
	h.route("POST /api/hosts/{id}/actions", analyst, h.hostAction)
	h.route("GET /api/hosts/{id}/commands", viewer, h.hostCommands)
	h.route("GET /api/hosts/{id}/timeline", viewer, h.hostTimeline)

	h.route("GET /api/commands/{id}", viewer, h.getCommand)
	h.route("GET /api/commands/{id}/rows", viewer, h.commandRows)
	h.route("GET /api/commands/{id}/download", analyst, h.commandDownload)

	h.route("POST /api/events/search", viewer, h.searchEvents)
	h.route("GET /api/events/{id}", viewer, h.getEvent)
	h.route("GET /api/process-tree", viewer, h.processTree)
	h.route("GET /api/process-events", viewer, h.processEvents)

	h.route("GET /api/alerts", viewer, h.listAlerts)
	h.route("GET /api/alerts/{id}", viewer, h.getAlert)
	h.route("PATCH /api/alerts/{id}", analyst, h.patchAlert)
	h.route("POST /api/alerts/bulk", analyst, h.bulkAlerts)
	h.route("POST /api/alerts/{id}/notes", analyst, h.addNote)
	h.route("GET /api/alerts/{id}/triage", viewer, h.alertTriage)
	h.route("POST /api/alerts/{id}/triage", analyst, h.requestTriage)

	h.route("GET /api/rules", viewer, h.listRules)
	h.route("GET /api/rules/{id}", viewer, h.getRule)
	h.route("POST /api/rules", admin, h.createRule)
	h.route("PUT /api/rules/{id}", admin, h.updateRule)
	h.route("PATCH /api/rules/{id}", admin, h.patchRule)
	h.route("DELETE /api/rules/{id}", admin, h.deleteRule)
	h.route("POST /api/rules/validate", analyst, h.validateRule)
	h.route("POST /api/rules/reload", admin, h.reloadRules)
	h.route("POST /api/rules/test", analyst, h.testRule)

	h.route("GET /api/artifacts", viewer, h.listArtifacts)
	h.route("GET /api/hunts", viewer, h.listHunts)
	h.route("POST /api/hunts", analyst, h.createHunt)
	h.route("GET /api/hunts/{id}", viewer, h.getHunt)
	h.route("POST /api/hunts/{id}/stop", analyst, h.stopHunt)
	h.route("GET /api/hunts/{id}/results", viewer, h.huntResults)

	h.route("GET /api/settings/server", viewer, h.serverSettings)
	h.route("GET /api/enrollment-tokens", admin, h.listTokens)
	h.route("POST /api/enrollment-tokens", admin, h.createToken)
	h.route("DELETE /api/enrollment-tokens/{id}", admin, h.deleteToken)
	h.route("GET /api/agent-config", viewer, h.getAgentConfig)
	h.route("PUT /api/agent-config", admin, h.putAgentConfig)
	h.route("GET /api/users", admin, h.listUsers)
	h.route("POST /api/users", admin, h.createUser)
	h.route("PATCH /api/users/{id}", viewer, h.patchUser) // self-service password; role checked inside
	h.route("DELETE /api/users/{id}", admin, h.deleteUser)
	h.route("GET /api/audit", admin, h.listAudit)
	h.route("GET /api/integrations", viewer, h.integrations)
	h.route("GET /api/settings/ai", admin, h.getAISettings)
	h.route("PUT /api/settings/ai", admin, h.putAISettings)
	h.route("POST /api/settings/ai/test", admin, h.testAISettings)
	h.route("POST /api/settings/ai/models", admin, h.listAIModels)
	h.route("GET /api/settings/ai/mcp-tokens", admin, h.listMCPTokens)
	h.route("POST /api/settings/ai/mcp-tokens", admin, h.createMCPToken)
	h.route("DELETE /api/settings/ai/mcp-tokens/{id}", admin, h.deleteMCPToken)

	h.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "no such endpoint")
	})
	return h
}

// ServeHTTP enforces the CSRF header on mutating requests, then routes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-HomeXDR-CSRF") != "1" {
		writeErr(w, http.StatusForbidden, "missing X-HomeXDR-CSRF header")
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) route(pattern, minRole string, fn func(http.ResponseWriter, *http.Request, *store.User)) {
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		u := h.sessionUser(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if !store.RoleAtLeast(u.Role, minRole) {
			writeErr(w, http.StatusForbidden, "your role does not allow this")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)), u)
	})
}

const sessionCookie = "homexdr_session"

func (h *Handler) sessionUser(r *http.Request) *store.User {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	u, err := h.c.State.SessionUser(r.Context(), ck.Value)
	if err != nil {
		return nil
	}
	return u
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps an error to a response.
func (h *Handler) fail(w http.ResponseWriter, err error) {
	var ve *core.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, events.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "already exists")
	case errors.Is(err, core.ErrNotAllowed):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.As(err, &ve), events.IsQueryError(err), errors.Is(err, store.ErrWeakPassword):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, context.Canceled):
	default:
		h.c.Log.Error("console api", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func qInt(r *http.Request, key string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil {
		return v
	}
	return def
}

func qList(r *http.Request, key string) []string {
	var out []string
	for _, v := range strings.Split(r.URL.Query().Get(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func qTime(r *http.Request, key string) (time.Time, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
