package console

import (
	"net/http"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// hostApplications lists the software the agent last reported for a host.
func (h *Handler) hostApplications(w http.ResponseWriter, r *http.Request, _ *store.User) {
	host, err := h.c.State.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	apps, at, err := h.c.Health.Vuln.Applications(r.Context(), host.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	var reported *time.Time
	if !at.IsZero() {
		reported = &at
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": apps, "total": len(apps), "reported_at": reported})
}

// hostVulnRescan compares software with the catalog now. Only a full rescan of every
// host is possible: the scan covers all hosts in one pass.
func (h *Handler) hostVulnRescan(w http.ResponseWriter, r *http.Request, u *store.User) {
	host, err := h.c.State.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	started := h.c.Health.Vuln.StartScan()
	detail := "full rescan started (all hosts)"
	if !started {
		detail = "a scan was already running"
	}
	h.c.Audit(r.Context(), u.Username, "host.vuln_rescan", host.ID, host.Hostname+": "+detail)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": started, "scope": "all"})
}
