package console

import (
	"net/http"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesMaintenance registers Settings → Maintenance: SSH key tags and maintenance
// suppressions.
func (h *Handler) routesMaintenance(viewer, admin string) {
	h.route("GET /api/settings/maintenance", viewer, h.getMaintenance)
	h.route("PUT /api/settings/maintenance", admin, h.putMaintenance)
	h.route("GET /api/stats/inbound", viewer, h.inboundThreats)
	h.route("GET /api/stats/inbound/events", viewer, h.inboundEvents)
}

func (h *Handler) getMaintenance(w http.ResponseWriter, r *http.Request, _ *store.User) {
	days := qInt(r, "days", 30)
	if days < 1 || days > 365 {
		days = 30
	}
	v, err := h.c.MaintenanceView(r.Context(), days)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) putMaintenance(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in core.MaintenanceInput
	if !decode(w, r, &in) {
		return
	}
	v, err := h.c.SaveMaintenance(r.Context(), in, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// inboundThreats is the inbound threats page: internet sources reaching the firewall.
func (h *Handler) inboundThreats(w http.ResponseWriter, r *http.Request, _ *store.User) {
	hours := qInt(r, "hours", 24)
	if hours < 1 || hours > 24*30 {
		hours = 24
	}
	v, err := h.c.InboundThreats(r.Context(), hours)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// inboundEvents lists the firewall events behind one number on the threat map.
func (h *Handler) inboundEvents(w http.ResponseWriter, r *http.Request, _ *store.User) {
	hours := qInt(r, "hours", 24)
	if hours < 1 || hours > 24*30 {
		hours = 24
	}
	kind := r.URL.Query().Get("kind")
	switch kind {
	case "all", "blocked", "allowed":
	default:
		writeErr(w, http.StatusBadRequest, "kind must be all, blocked or allowed")
		return
	}
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	if len(country) > 2 {
		writeErr(w, http.StatusBadRequest, "country is a two-letter code")
		return
	}
	offset := qInt(r, "offset", 0)
	if offset < 0 || offset > 10000 {
		offset = 0
	}
	v, err := h.c.InboundEvents(r.Context(), hours, country, kind, offset)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
