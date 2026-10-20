package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
)

// aiSettingsView is the settings as the console sees them: the API key is never
// returned, only whether one is set and its last characters.
type aiSettingsView struct {
	triage.Settings
	APIKey         string                `json:"api_key,omitempty"` // always empty
	KeySet         bool                  `json:"key_set"`
	KeySource      string                `json:"key_source,omitempty"` // settings | environment
	KeyHint        string                `json:"key_hint,omitempty"`
	Ready          bool                  `json:"ready"`
	NotReadyReason string                `json:"not_ready_reason,omitempty"`
	Providers      []triage.ProviderInfo `json:"providers"`
	DefaultModel   string                `json:"default_model"`
	AutoToday      int                   `json:"auto_today"`
}

func (h *Handler) aiView(r *http.Request, set triage.Settings) aiSettingsView {
	svc := h.c.Triage
	key, source := svc.Key(set)
	ready, why := svc.Ready(set)
	v := aiSettingsView{
		Settings: set, KeySet: key != "", KeySource: source, Ready: ready, NotReadyReason: why,
		Providers: triage.Providers, DefaultModel: triage.DefaultModel, AutoToday: svc.AutoToday(r.Context()),
	}
	v.Settings.APIKey = ""
	if len(key) > 8 {
		v.KeyHint = "..." + key[len(key)-4:]
	}
	return v
}

func (h *Handler) getAISettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.aiView(r, h.c.Triage.Settings(r.Context())))
}

// aiSettingsRequest is a PUT/test body. api_key replaces the stored key when not
// empty; clear_api_key removes it. Otherwise the stored key is kept.
type aiSettingsRequest struct {
	triage.Settings
	ClearAPIKey bool `json:"clear_api_key"`
}

func (h *Handler) mergeAISettings(r *http.Request, req aiSettingsRequest) triage.Settings {
	cur := h.c.Triage.Settings(r.Context())
	next := req.Settings
	switch {
	case req.ClearAPIKey:
		next.APIKey = ""
	case strings.TrimSpace(next.APIKey) == "":
		next.APIKey = cur.APIKey
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
	details := "provider " + next.Provider + ", model " + next.Model + ", min severity " + next.MinSeverity
	if next.Enabled {
		details = "on, " + details
	} else {
		details = "off, " + details
	}
	switch {
	case cur.APIKey != "" && next.APIKey == "":
		details += ", API key removed"
	case next.APIKey != cur.APIKey:
		details += ", API key changed"
	}
	h.c.Audit(r.Context(), u.Username, "ai.settings", "ai_triage", details)
	writeJSON(w, http.StatusOK, h.aiView(r, next))
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
