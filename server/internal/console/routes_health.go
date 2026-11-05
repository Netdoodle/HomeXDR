package console

import (
	"net/http"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesHealth registers the health feature's routes.
func (h *Handler) routesHealth(viewer, analyst, admin string) {
	h.route("GET /api/health/feeds", viewer, h.getFeeds)
	h.route("PATCH /api/health/feeds", admin, h.patchFeed)
}

func (h *Handler) getFeeds(w http.ResponseWriter, r *http.Request, _ *store.User) {
	rep, err := h.c.Health.Feeds.Report(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// patchFeed sets the owner's choice for one source: muted, expected, or both.
func (h *Handler) patchFeed(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		HostID   string `json:"host_id"`
		Module   string `json:"module"`
		Dataset  string `json:"dataset"`
		Muted    *bool  `json:"muted"`
		Expected *bool  `json:"expected"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.HostID == "" || (req.Muted == nil && req.Expected == nil) {
		writeErr(w, http.StatusBadRequest, "host_id and muted or expected are required")
		return
	}
	if err := h.c.Health.Feeds.SetChoice(r.Context(), req.HostID, req.Module, req.Dataset, req.Muted, req.Expected); err != nil {
		h.fail(w, err)
		return
	}
	details := strings.TrimPrefix(req.Module+"/"+req.Dataset, "/")
	if req.Muted != nil {
		if *req.Muted {
			details += " muted"
		} else {
			details += " unmuted"
		}
	}
	if req.Expected != nil {
		if *req.Expected {
			details += " marked expected"
		} else {
			details += " no longer expected"
		}
	}
	h.c.Audit(r.Context(), u.Username, "feed.change", req.HostID, details)
	rep, err := h.c.Health.Feeds.Report(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
