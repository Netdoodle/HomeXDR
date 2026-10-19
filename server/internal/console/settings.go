package console

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/version"
)

func (h *Handler) serverSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	cfg := h.c.Cfg
	writeJSON(w, http.StatusOK, map[string]any{
		"version": version.Version, "agent_url": cfg.AgentURL, "ca_pin": h.c.PKI.CAPin(),
		"server_names": cfg.ServerNames, "event_store": cfg.EventStore, "retention_days": cfg.RetentionDays,
		"syslog_addr": cfg.SyslogAddr,
	})
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request, _ *store.User) {
	toks, err := h.c.State.ListTokens(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": toks})
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Name         string   `json:"name"`
		ExpiresHours int      `json:"expires_hours"`
		MaxUses      *int     `json:"max_uses"`
		Labels       []string `json:"labels"`
	}
	if !decode(w, r, &req) {
		return
	}
	var exp *time.Time
	if req.ExpiresHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresHours) * time.Hour).UTC()
		exp = &t
	}
	if req.MaxUses != nil && *req.MaxUses <= 0 {
		req.MaxUses = nil
	}
	tok, err := h.c.State.CreateToken(r.Context(), req.Name, u.Username, exp, req.MaxUses, req.Labels)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "token.create", tok.ID, tok.Name)
	writeJSON(w, http.StatusCreated, tok)
}

func (h *Handler) deleteToken(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.State.DeleteToken(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "token.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getAgentConfig(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.c.AgentConfig(r.Context()))
}

func (h *Handler) putAgentConfig(w http.ResponseWriter, r *http.Request, u *store.User) {
	var cfg api.AgentConfig
	if !decode(w, r, &cfg) {
		return
	}
	saved, err := h.c.SetAgentConfig(r.Context(), cfg)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "agent_config.update", "", "version "+strconv.FormatInt(saved.Version, 10))
	writeJSON(w, http.StatusOK, saved)
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, _ *store.User) {
	users, err := h.c.State.ListUsers(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	if users == nil {
		users = []*store.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	nu, err := h.c.State.CreateUser(r.Context(), req.Username, req.Password, req.Role)
	if err != nil {
		if err == store.ErrConflict {
			writeErr(w, http.StatusConflict, "username is taken")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.c.Audit(r.Context(), u.Username, "user.create", nu.ID, nu.Username+" ("+nu.Role+")")
	writeJSON(w, http.StatusCreated, nu)
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	var req struct {
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	isAdmin := u.Role == store.RoleAdmin
	if !isAdmin && (id != u.ID || req.Role != "") {
		writeErr(w, http.StatusForbidden, "you can only change your own password")
		return
	}
	nu, err := h.c.State.UpdateUser(r.Context(), id, req.Role, req.Password)
	if err != nil {
		if err == store.ErrNotFound {
			h.fail(w, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := ""
	if req.Role != "" {
		detail += "role=" + req.Role + " "
	}
	if req.Password != "" {
		detail += "password changed"
	}
	h.c.Audit(r.Context(), u.Username, "user.update", nu.ID, detail)
	writeJSON(w, http.StatusOK, nu)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if id == u.ID {
		writeErr(w, http.StatusBadRequest, "you cannot delete yourself")
		return
	}
	if err := h.c.State.DeleteUser(r.Context(), id); err != nil {
		if err == store.ErrNotFound {
			h.fail(w, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.c.Audit(r.Context(), u.Username, "user.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request, _ *store.User) {
	entries, total, err := h.c.State.ListAudit(r.Context(), qInt(r, "limit", 100), qInt(r, "offset", 0))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": total})
}

func (h *Handler) integrations(w http.ResponseWriter, r *http.Request, _ *store.User) {
	s := h.c.Syslog
	writeJSON(w, http.StatusOK, map[string]any{"syslog": map[string]any{
		"listening": s.Listening.Load(), "addr": s.Addr.Load(),
		"received": s.Received.Load(), "parsed": s.Parsed.Load(), "failed": s.Failed.Load(),
		"sources": s.Sources(),
	}})
}
