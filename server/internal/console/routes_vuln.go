package console

import (
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/vuln"
)

func (h *Handler) routesVuln(viewer, admin string) {
	h.route("GET /api/vulnerabilities", viewer, h.getVulns)
	h.route("POST /api/vulnerabilities/refresh", admin, h.refreshVulns)
	h.route("PUT /api/settings/vuln", admin, h.putVulnSettings)
}

func (h *Handler) vulnResponse(w http.ResponseWriter, r *http.Request) {
	rep, err := h.c.Health.Vuln.Report(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (h *Handler) getVulns(w http.ResponseWriter, r *http.Request, _ *store.User) {
	h.vulnResponse(w, r)
}

// refreshVulns compares software with the catalog now, in the background.
func (h *Handler) refreshVulns(w http.ResponseWriter, r *http.Request, _ *store.User) {
	h.c.Health.Vuln.StartScan()
	h.vulnResponse(w, r)
}

// putVulnSettings turns the optional OSV check on or off.
func (h *Handler) putVulnSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		OSV *bool `json:"osv"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.OSV == nil {
		writeErr(w, http.StatusBadRequest, "osv is required")
		return
	}
	if err := h.c.Health.Vuln.SaveSettings(r.Context(), vuln.Settings{OSV: *req.OSV}); err != nil {
		h.fail(w, err)
		return
	}
	state := "off"
	if *req.OSV {
		state = "on"
	}
	h.c.Audit(r.Context(), u.Username, "vuln.osv", "", state)
	h.c.Health.Vuln.Poke()
	h.vulnResponse(w, r)
}
