package console

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func (h *Handler) listRules(w http.ResponseWriter, r *http.Request, _ *store.User) {
	q := r.URL.Query()
	f := core.RuleFilter{Q: q.Get("q"), Level: q.Get("level"), Source: q.Get("source"), Repo: q.Get("repo")}
	if v := q.Get("enabled"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			f.Enabled = &b
		}
	}
	rules, err := h.c.Rules.List(r.Context(), f)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "total": len(rules), "load_errors": h.c.Rules.LoadErrors()})
}

func (h *Handler) getRule(w http.ResponseWriter, r *http.Request, _ *store.User) {
	ri, err := h.c.Rules.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ri)
}

type yamlBody struct {
	YAML  string `json:"yaml"`
	Hours int    `json:"hours"`
}

func (h *Handler) createRule(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req yamlBody
	if !decode(w, r, &req) {
		return
	}
	ri, err := h.c.Rules.SaveCustom(r.Context(), "", req.YAML)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "rule.create", ri.ID, ri.Title)
	writeJSON(w, http.StatusCreated, ri)
}

func (h *Handler) updateRule(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req yamlBody
	if !decode(w, r, &req) {
		return
	}
	ri, err := h.c.Rules.SaveCustom(r.Context(), r.PathValue("id"), req.YAML)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "rule.update", ri.ID, ri.Title)
	writeJSON(w, http.StatusOK, ri)
}

func (h *Handler) patchRule(w http.ResponseWriter, r *http.Request, u *store.User) {
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
	ri, err := h.c.Rules.SetEnabled(r.Context(), r.PathValue("id"), *req.Enabled)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "rule.enabled", ri.ID, strconv.FormatBool(*req.Enabled))
	writeJSON(w, http.StatusOK, ri)
}

func (h *Handler) deleteRule(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.Rules.DeleteCustom(r.Context(), id); err != nil {
		if err == store.ErrNotFound {
			h.fail(w, err)
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.c.Audit(r.Context(), u.Username, "rule.delete", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// reloadRules re-reads the rules folder now instead of waiting for the next
// once-a-minute change check.
func (h *Handler) reloadRules(w http.ResponseWriter, r *http.Request, u *store.User) {
	if err := h.c.Rules.Reload(r.Context()); err != nil {
		h.fail(w, err)
		return
	}
	total, enabled := h.c.Rules.Stats()
	errs := h.c.Rules.LoadErrors()
	h.c.Audit(r.Context(), u.Username, "rules.reload", "", strconv.Itoa(total)+" rules, "+strconv.Itoa(len(errs))+" errors")
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "enabled": enabled, "load_errors": errs})
}

func (h *Handler) validateRule(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req yamlBody
	if !decode(w, r, &req) {
		return
	}
	rule, err := h.c.Rules.Validate(req.YAML)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": map[string]any{
		"id": rule.ID, "title": rule.Title, "level": rule.Level, "tags": rule.Tags,
		"logsource": rule.LogSource, "mitre": detect.MitreFromTags(rule.Tags),
	}})
}

const (
	maxTestScan    = 50000
	maxTestMatches = 100
)

func (h *Handler) testRule(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req yamlBody
	if !decode(w, r, &req) {
		return
	}
	rule, err := h.c.Rules.Validate(req.YAML)
	if err != nil {
		h.fail(w, err)
		return
	}
	hours := req.Hours
	if hours <= 0 || hours > 24*7 {
		hours = 24
	}
	now := time.Now()
	matches := []*event.Event{}
	scanned := 0
	err = h.c.Events.Scan(r.Context(), now.Add(-time.Duration(hours)*time.Hour), now.Add(time.Minute), maxTestScan,
		func(e *event.Event) bool {
			scanned++
			if rule.Match(detect.NewDoc(e)) {
				matches = append(matches, e)
			}
			return len(matches) < maxTestMatches
		})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matches": matches, "scanned": scanned})
}

func (h *Handler) listArtifacts(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": api.Artifacts})
}

func (h *Handler) listHunts(w http.ResponseWriter, r *http.Request, _ *store.User) {
	hunts, err := h.c.State.ListHunts(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hunts": hunts})
}

func (h *Handler) createHunt(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Artifact     string            `json:"artifact"`
		Params       map[string]string `json:"params"`
		Description  string            `json:"description"`
		Target       store.HuntTarget  `json:"target"`
		ExpiresHours int               `json:"expires_hours"`
	}
	if !decode(w, r, &req) {
		return
	}
	hunt, err := h.c.CreateHunt(r.Context(), req.Artifact, req.Params, req.Description, req.Target, u.Username,
		time.Duration(req.ExpiresHours)*time.Hour)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, hunt)
}

func (h *Handler) getHunt(w http.ResponseWriter, r *http.Request, _ *store.User) {
	hunt, err := h.c.State.GetHunt(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hunt)
}

func (h *Handler) stopHunt(w http.ResponseWriter, r *http.Request, u *store.User) {
	hunt, err := h.c.State.StopHunt(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "hunt.stop", hunt.ID, "")
	writeJSON(w, http.StatusOK, hunt)
}

func (h *Handler) huntResults(w http.ResponseWriter, r *http.Request, _ *store.User) {
	rows, total, err := h.c.State.HuntResults(r.Context(), r.PathValue("id"), r.URL.Query().Get("host_id"),
		qInt(r, "limit", 100), qInt(r, "offset", 0))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "total": total})
}
