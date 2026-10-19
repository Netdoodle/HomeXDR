package console

import (
	"net/http"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

func (h *Handler) listAlerts(w http.ResponseWriter, r *http.Request, _ *store.User) {
	q := r.URL.Query()
	alerts, total, err := h.c.State.ListAlerts(r.Context(), store.AlertFilter{
		Statuses: qList(r, "status"), Severities: qList(r, "severity"),
		HostID: q.Get("host_id"), RuleID: q.Get("rule_id"), Q: q.Get("q"),
		Limit: qInt(r, "limit", 100), Offset: qInt(r, "offset", 0),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts, "total": total})
}

func (h *Handler) getAlert(w http.ResponseWriter, r *http.Request, _ *store.User) {
	a, err := h.c.State.GetAlert(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	ids := a.EventIDs
	if len(ids) > 20 {
		ids = ids[:20]
	}
	evs, err := h.c.Events.GetMany(r.Context(), ids)
	if err != nil {
		h.c.Log.Warn("alert events", "err", err)
	}
	a.Events = evs
	writeJSON(w, http.StatusOK, a)
}

type alertPatch struct {
	Status   *string `json:"status"`
	Assignee *string `json:"assignee"`
}

func (h *Handler) patchAlert(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req alertPatch
	if !decode(w, r, &req) {
		return
	}
	if req.Status != nil && !store.ValidAlertStatus(*req.Status) {
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	a, err := h.c.State.UpdateAlert(r.Context(), r.PathValue("id"), req.Status, req.Assignee)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "alert.update", a.ID, describePatch(req))
	writeJSON(w, http.StatusOK, a)
}

func (h *Handler) bulkAlerts(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		IDs []string `json:"ids"`
		alertPatch
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 1000 {
		writeErr(w, http.StatusBadRequest, "ids must have 1-1000 entries")
		return
	}
	if req.Status != nil && !store.ValidAlertStatus(*req.Status) {
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	n, err := h.c.State.BulkUpdateAlerts(r.Context(), req.IDs, req.Status, req.Assignee)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "alert.bulk_update", strings.Join(req.IDs, ","), describePatch(req.alertPatch))
	writeJSON(w, http.StatusOK, map[string]int{"updated": n})
}

func describePatch(p alertPatch) string {
	var parts []string
	if p.Status != nil {
		parts = append(parts, "status="+*p.Status)
	}
	if p.Assignee != nil {
		parts = append(parts, "assignee="+*p.Assignee)
	}
	return strings.Join(parts, " ")
}

func (h *Handler) addNote(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Text string `json:"text"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "text is required")
		return
	}
	a, err := h.c.State.AddAlertNote(r.Context(), r.PathValue("id"), u.Username, strings.TrimSpace(req.Text))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request, _ *store.User) {
	ctx := r.Context()
	hours := qInt(r, "hours", 24)
	if hours < 1 || hours > 24*30 {
		hours = 24
	}
	now := time.Now().UTC()
	from := now.Add(-time.Duration(hours) * time.Hour)

	total, online, isolated, err := h.c.State.HostCounts(ctx)
	if err != nil {
		h.fail(w, err)
		return
	}
	open, bySev, err := h.c.State.OpenAlertCounts(ctx)
	if err != nil {
		h.fail(w, err)
		return
	}
	alertsTL, err := h.c.State.AlertTimeline(ctx, from)
	if err != nil {
		h.fail(w, err)
		return
	}
	topRules, err := h.c.State.TopRules(ctx, from, 10)
	if err != nil {
		h.fail(w, err)
		return
	}
	topHosts, err := h.c.State.TopHosts(ctx, from, 10)
	if err != nil {
		h.fail(w, err)
		return
	}
	st, err := h.c.Events.Stats(ctx, from, now.Add(time.Minute))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts_total": total, "hosts_online": online, "hosts_isolated": isolated,
		"alerts_open": open, "alerts_by_severity": bySev,
		"events_total": st.Total, "events_timeline": st.Timeline, "alerts_timeline": alertsTL,
		"top_rules": topRules, "top_hosts": topHosts, "events_by_category": st.Categories,
	})
}
