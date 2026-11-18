package console

import (
	"errors"
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/storyline"
)

// storyline serves GET /api/storyline: the attack-chain graph around a process, given by
// host_id and entity_id or by alert_id (docs/storyline.md).
func (h *Handler) storyline(w http.ResponseWriter, r *http.Request, _ *store.User) {
	ctx := r.Context()
	q := r.URL.Query()
	hostID, focus := q.Get("host_id"), q.Get("entity_id")
	if id := q.Get("alert_id"); id != "" {
		a, err := h.c.State.GetAlert(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "alert not found")
			return
		}
		if err != nil {
			h.fail(w, err)
			return
		}
		if a.ProcessEntityID == "" || a.HostID == "" {
			writeErr(w, http.StatusNotFound, "the alert is not about a process on a host")
			return
		}
		hostID, focus = a.HostID, a.ProcessEntityID
	}
	if hostID == "" || focus == "" {
		writeErr(w, http.StatusBadRequest, "host_id and entity_id, or alert_id, are required")
		return
	}
	g, err := storyline.Build(ctx, storyline.Sources{Events: h.c.Events, State: h.c.State}, hostID, focus,
		qInt(r, "depth", storyline.DefaultDepth))
	if errors.Is(err, storyline.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "process not found")
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}
