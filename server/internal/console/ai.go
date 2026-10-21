package console

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
)

// aiSettingsView is the settings as the console sees them. API keys are never
// returned: only whether each provider has one, where it comes from and its last
// characters.
type aiSettingsView struct {
	triage.Settings
	APIKey         string                `json:"api_key,omitempty"`  // shadows the embedded field; always empty
	APIKeys        map[string]string     `json:"api_keys,omitempty"` // shadows the embedded field; always empty
	KeySet         bool                  `json:"key_set"`            // for the selected provider
	KeySource      string                `json:"key_source,omitempty"`
	KeyHint        string                `json:"key_hint,omitempty"`
	Keys           map[string]keyStatus  `json:"keys"` // per provider
	Ready          bool                  `json:"ready"`
	NotReadyReason string                `json:"not_ready_reason,omitempty"`
	Providers      []triage.ProviderInfo `json:"providers"`
	DefaultModel   string                `json:"default_model"`
	AutoToday      int                   `json:"auto_today"`
	MCP            mcpStatus             `json:"mcp"`
}

// mcpStatus shows how MCP clients are using the analyst.
type mcpStatus struct {
	Pending      int        `json:"pending"` // investigations waiting for an MCP client
	Tokens       int        `json:"tokens"`
	RunnerName   string     `json:"runner_name,omitempty"`
	RunnerSeenAt *time.Time `json:"runner_seen_at,omitempty"`
}

type keyStatus struct {
	Set    bool   `json:"set"`
	Source string `json:"source,omitempty"` // settings | environment
	Hint   string `json:"hint,omitempty"`
}

func keyHint(key string) string {
	if len(key) > 8 {
		return "..." + key[len(key)-4:]
	}
	return ""
}

func (h *Handler) aiView(r *http.Request, set triage.Settings) aiSettingsView {
	svc := h.c.Triage
	ready, why := svc.Ready(set)
	v := aiSettingsView{
		Settings: set, Ready: ready, NotReadyReason: why, Keys: map[string]keyStatus{},
		Providers: triage.Providers, DefaultModel: triage.DefaultModel, AutoToday: svc.AutoToday(r.Context()),
	}
	v.Settings.APIKey, v.Settings.APIKeys = "", nil
	for _, p := range triage.Providers {
		key, source := triage.KeyFor(set, p.ID)
		v.Keys[p.ID] = keyStatus{Set: key != "", Source: source, Hint: keyHint(key)}
	}
	sel := v.Keys[set.Provider]
	v.KeySet, v.KeySource, v.KeyHint = sel.Set, sel.Source, sel.Hint
	v.MCP.Pending = svc.PendingMCP(r.Context())
	if toks, err := h.c.State.ListMCPTokens(r.Context()); err == nil {
		v.MCP.Tokens = len(toks)
	}
	if name, at := svc.Runner(); !at.IsZero() {
		v.MCP.RunnerName, v.MCP.RunnerSeenAt = name, &at
	}
	return v
}

func (h *Handler) listMCPTokens(w http.ResponseWriter, r *http.Request, _ *store.User) {
	toks, err := h.c.State.ListMCPTokens(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": toks})
}

func (h *Handler) createMCPToken(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Name) > 80 {
		writeErr(w, http.StatusBadRequest, "name is too long")
		return
	}
	t, err := h.c.State.CreateMCPToken(r.Context(), req.Name, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "mcp.token.create", t.ID, t.Name)
	writeJSON(w, http.StatusCreated, t)
}

func (h *Handler) deleteMCPToken(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.State.DeleteMCPToken(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "mcp.token.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getAISettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.aiView(r, h.c.Triage.Settings(r.Context())))
}

// aiSettingsRequest is a PUT/test/models body. api_key sets the selected provider's
// key when not empty; clear_api_key removes it; other providers' keys are kept.
type aiSettingsRequest struct {
	triage.Settings
	ClearAPIKey bool `json:"clear_api_key"`
}

func (h *Handler) mergeAISettings(r *http.Request, req aiSettingsRequest) triage.Settings {
	cur := h.c.Triage.Settings(r.Context())
	next := req.Settings
	next.APIKeys = map[string]string{} // only ever changed through api_key / clear_api_key
	for id, k := range cur.APIKeys {
		next.APIKeys[id] = k
	}
	switch {
	case req.ClearAPIKey:
		delete(next.APIKeys, next.Provider)
		next.APIKey = ""
	case strings.TrimSpace(next.APIKey) != "":
		next.APIKeys[next.Provider] = strings.TrimSpace(next.APIKey)
		next.APIKey = ""
	}
	return next
}

func (h *Handler) putAISettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req aiSettingsRequest
	if !decode(w, r, &req) {
		return
	}
	cur := h.c.Triage.Settings(r.Context())
	next, err := h.c.Triage.SaveSettings(r.Context(), h.mergeAISettings(r, req))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	details := "engine " + next.Engine + ", provider " + next.Provider + ", model " + next.Model + ", min severity " + next.MinSeverity
	if next.MCPEnabled {
		details += ", MCP access on"
		if next.MCPAutoTrigger {
			details += " (auto-trigger)"
		}
	}
	if next.BaseURL != "" {
		details += ", base URL " + next.BaseURL
	}
	if next.Enabled {
		details = "on, " + details
	} else {
		details = "off, " + details
	}
	was, now := cur.APIKeys[next.Provider], next.APIKeys[next.Provider]
	switch {
	case was != "" && now == "":
		details += ", " + next.Provider + " API key removed"
	case now != was:
		details += ", " + next.Provider + " API key changed"
	}
	h.c.Audit(r.Context(), u.Username, "ai.settings", "ai_triage", details)
	writeJSON(w, http.StatusOK, h.aiView(r, next))
}

// listAIModels asks the selected provider which models it offers.
func (h *Handler) listAIModels(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req aiSettingsRequest
	if !decode(w, r, &req) {
		return
	}
	models, err := h.c.Triage.ListModels(r.Context(), h.mergeAISettings(r, req))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"models": []string{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

func (h *Handler) testAISettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req aiSettingsRequest
	if !decode(w, r, &req) {
		return
	}
	model, err := h.c.Triage.Test(r.Context(), h.mergeAISettings(r, req))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "model": model})
}

// alertTriage returns the AI analyst's investigation of an alert, plus whether a
// (re)investigation can be requested right now.
func (h *Handler) alertTriage(w http.ResponseWriter, r *http.Request, _ *store.User) {
	id := r.PathValue("id")
	if _, err := h.c.State.GetAlert(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	t, err := h.c.State.GetTriage(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.fail(w, err)
		return
	}
	ready, why := h.c.Triage.Ready(h.c.Triage.Settings(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"triage": t, "available": ready, "reason": why})
}

func (h *Handler) requestTriage(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	t, err := h.c.Triage.Request(r.Context(), id, u.Username)
	switch {
	case errors.Is(err, triage.ErrNotReady):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "an investigation of this alert is already queued or running")
		return
	case err != nil:
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "ai.triage.request", id, "")
	writeJSON(w, http.StatusAccepted, t)
}
