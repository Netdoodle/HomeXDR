package console

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/intel"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// startIntelLookup asks the threat intelligence services about an indicator, reusing recent
// answers unless refresh is set. The response has "running": true until they have answered.
func (h *Handler) startIntelLookup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Indicator string `json:"indicator"`
		Refresh   bool   `json:"refresh"`
	}
	if !decode(w, r, &req) {
		return
	}
	v, err := h.c.Intel.Start(r.Context(), req.Indicator, req.Refresh, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) getIntelLookup(w http.ResponseWriter, r *http.Request, _ *store.User) {
	v, err := h.c.Intel.Get(r.Context(), r.URL.Query().Get("indicator"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) intelHistory(w http.ResponseWriter, r *http.Request, _ *store.User) {
	list, err := h.c.Intel.History(r.Context(), qInt(r, "limit", 20))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lookups": list})
}

// intelSightings finds an indicator in the stored events. Nothing leaves this server, so
// anyone who can search can use it.
func (h *Handler) intelSightings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	s, err := h.c.Intel.Sightings(r.Context(), r.URL.Query().Get("indicator"), qInt(r, "days", 30))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// intelProviderView is a provider with its settings. Keys are never returned: only whether
// one is set and its last characters.
type intelProviderView struct {
	intel.Provider
	Enabled bool   `json:"enabled"`
	KeySet  bool   `json:"key_set"`
	KeyHint string `json:"key_hint,omitempty"`
}

type intelSettingsView struct {
	Providers       []intelProviderView `json:"providers"`
	CacheHours      int                 `json:"cache_hours"`
	AIAccess        bool                `json:"ai_access"`
	InternalDomains []string            `json:"internal_domains"`
}

func intelView(set intel.Settings) intelSettingsView {
	v := intelSettingsView{CacheHours: set.CacheHours, AIAccess: set.AIAccess, InternalDomains: set.InternalDomains}
	for _, p := range intel.Providers {
		s := set.Providers[p.ID]
		v.Providers = append(v.Providers, intelProviderView{Provider: p, Enabled: !s.Disabled, KeySet: s.Key != "", KeyHint: keyHint(s.Key)})
	}
	return v
}

func (h *Handler) getIntelSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, intelView(h.c.Intel.Settings(r.Context())))
}

// putIntelSettings saves settings. A provider's key is kept unless a new "key" is given or
// "clear_key" is set.
func (h *Handler) putIntelSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Providers map[string]struct {
			Enabled  *bool  `json:"enabled"`
			Key      string `json:"key"`
			ClearKey bool   `json:"clear_key"`
		} `json:"providers"`
		CacheHours      *int      `json:"cache_hours"`
		AIAccess        *bool     `json:"ai_access"`
		InternalDomains *[]string `json:"internal_domains"`
	}
	if !decode(w, r, &req) {
		return
	}
	set := h.c.Intel.Settings(r.Context())
	var changes []string
	for id, p := range req.Providers {
		cur := set.Providers[id]
		if p.Enabled != nil && cur.Disabled == *p.Enabled {
			cur.Disabled = !*p.Enabled
			if cur.Disabled {
				changes = append(changes, id+" off")
			} else {
				changes = append(changes, id+" on")
			}
		}
		if k := strings.TrimSpace(p.Key); k != "" {
			cur.Key = k
			changes = append(changes, id+" API key changed")
		} else if p.ClearKey && cur.Key != "" {
			cur.Key = ""
			changes = append(changes, id+" API key removed")
		}
		set.Providers[id] = cur
	}
	if req.CacheHours != nil && *req.CacheHours != set.CacheHours {
		set.CacheHours = *req.CacheHours
		changes = append(changes, fmt.Sprintf("reuse answers for %d hours", *req.CacheHours))
	}
	if req.AIAccess != nil && *req.AIAccess != set.AIAccess {
		set.AIAccess = *req.AIAccess
		changes = append(changes, fmt.Sprintf("AI analyst lookups %v", *req.AIAccess))
	}
	if req.InternalDomains != nil {
		set.InternalDomains = *req.InternalDomains
		changes = append(changes, "internal domains: "+strings.Join(*req.InternalDomains, ", "))
	}
	saved, err := h.c.Intel.SaveSettings(r.Context(), set)
	if err != nil {
		h.fail(w, err)
		return
	}
	sort.Strings(changes)
	h.c.Audit(r.Context(), u.Username, "intel.settings", "", strings.Join(changes, "; "))
	writeJSON(w, http.StatusOK, intelView(saved))
}
