package console

import (
	"net/http"
	"strconv"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// ruleRepoBody holds rule repository settings; fields left out keep their current value
// (or the default, when adding).
type ruleRepoBody struct {
	Name          *string   `json:"name"`
	URL           *string   `json:"url"`
	Ref           *string   `json:"ref"`
	Paths         *[]string `json:"paths"`
	MinLevel      *string   `json:"min_level"`
	Statuses      *[]string `json:"statuses"`
	EnableRules   *bool     `json:"enable_rules"`
	AutoUpdate    *bool     `json:"auto_update"`
	IntervalHours *int      `json:"interval_hours"`
	Enabled       *bool     `json:"enabled"`
}

func (b ruleRepoBody) apply(s store.RuleRepoSettings) store.RuleRepoSettings {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&s.Name, b.Name)
	set(&s.URL, b.URL)
	set(&s.Ref, b.Ref)
	set(&s.MinLevel, b.MinLevel)
	if b.Paths != nil {
		s.Paths = *b.Paths
	}
	if b.Statuses != nil {
		s.Statuses = *b.Statuses
	}
	for _, f := range []struct {
		dst *bool
		src *bool
	}{{&s.EnableRules, b.EnableRules}, {&s.AutoUpdate, b.AutoUpdate}, {&s.Enabled, b.Enabled}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if b.IntervalHours != nil {
		s.IntervalHours = *b.IntervalHours
	}
	return s
}

func (h *Handler) listRuleRepos(w http.ResponseWriter, r *http.Request, _ *store.User) {
	repos, err := h.c.RuleRepos.List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repos": repos})
}

func (h *Handler) getRuleRepo(w http.ResponseWriter, r *http.Request, _ *store.User) {
	v, err := h.c.RuleRepos.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// addRuleRepo adds a repository and starts the first download; the response has
// "syncing": true until it finishes.
func (h *Handler) addRuleRepo(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req ruleRepoBody
	if !decode(w, r, &req) {
		return
	}
	defaults := store.RuleRepoSettings{EnableRules: true, AutoUpdate: true, Enabled: true}
	v, err := h.c.RuleRepos.Add(r.Context(), req.apply(defaults), u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *Handler) patchRuleRepo(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req ruleRepoBody
	if !decode(w, r, &req) {
		return
	}
	cur, err := h.c.State.GetRuleRepo(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	v, err := h.c.RuleRepos.Update(r.Context(), cur.ID, req.apply(cur.RuleRepoSettings), u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) deleteRuleRepo(w http.ResponseWriter, r *http.Request, u *store.User) {
	if err := h.c.RuleRepos.Delete(r.Context(), r.PathValue("id"), u.Username); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkRuleRepo looks for a new version now without installing it.
func (h *Handler) checkRuleRepo(w http.ResponseWriter, r *http.Request, u *store.User) {
	v, err := h.c.RuleRepos.Check(r.Context(), r.PathValue("id"), u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// updateRuleRepo downloads and installs the newest version in the background.
func (h *Handler) updateRuleRepo(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if _, err := h.c.State.GetRuleRepo(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	if !h.c.RuleRepos.Start(id, true, u.Username) {
		h.fail(w, core.ErrRepoBusy)
		return
	}
	v, err := h.c.RuleRepos.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, v)
}

// ruleRepoFiles lists every rule document in a repository's installed version (to choose
// folders with counts) and the rules in its chosen folders that are not loaded.
func (h *Handler) ruleRepoFiles(w http.ResponseWriter, r *http.Request, _ *store.User) {
	repo, err := h.c.State.GetRuleRepo(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	files, skipped := h.c.Rules.RepoFiles(repo)
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "skipped": skipped})
}

// setRuleRepoRulesEnabled enables or disables every loaded rule of a repository.
func (h *Handler) setRuleRepoRulesEnabled(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled is required")
		return
	}
	repo, err := h.c.State.GetRuleRepo(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	n, err := h.c.Rules.SetRepoEnabled(r.Context(), repo.ID, *req.Enabled)
	if err != nil {
		h.fail(w, err)
		return
	}
	verb := "disabled"
	if *req.Enabled {
		verb = "enabled"
	}
	h.c.Audit(r.Context(), u.Username, "rule_repo.rules_enabled", repo.ID, repo.Name+": "+verb+" "+strconv.Itoa(n)+" rules")
	writeJSON(w, http.StatusOK, map[string]any{"changed": n})
}
