package console

import (
	"errors"
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/lists"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

const maxOfflineLookups = 50

func (h *Handler) routesLists(viewer, admin string) {
	h.route("GET /api/settings/lists", admin, h.getLists)
	h.route("PUT /api/settings/lists/{id}", admin, h.putList)
	h.route("POST /api/settings/lists/{id}/refresh", admin, h.refreshList)
	h.route("POST /api/lists/lookup", viewer, h.lookupLists)
}

func (h *Handler) listsResponse(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"lists": h.c.Health.Lists.Views()})
}

func (h *Handler) getLists(w http.ResponseWriter, _ *http.Request, _ *store.User) {
	h.listsResponse(w)
}

// putList switches a list on or off.
func (h *Handler) putList(w http.ResponseWriter, r *http.Request, u *store.User) {
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
	id := r.PathValue("id")
	if err := h.c.Health.Lists.SetEnabled(r.Context(), id, *req.Enabled); err != nil {
		if errors.Is(err, lists.ErrNoSuchList) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		h.fail(w, err)
		return
	}
	state := "off"
	if *req.Enabled {
		state = "on"
	}
	h.c.Audit(r.Context(), u.Username, "list.change", id, state)
	h.listsResponse(w)
}

// refreshList checks a list for a new copy in the background.
func (h *Handler) refreshList(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if !h.c.Health.Lists.Known(id) {
		writeErr(w, http.StatusNotFound, lists.ErrNoSuchList.Error())
		return
	}
	if h.c.Health.Lists.StartRefresh(id) {
		h.c.Audit(r.Context(), u.Username, "list.refresh", id, "")
	}
	h.listsResponse(w)
}

// lookupLists answers from the offline lists, for pages showing several indicators at once.
// Nothing leaves this server, so anyone who can read alerts can use it.
func (h *Handler) lookupLists(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var req struct {
		Indicators []string `json:"indicators"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Indicators) > maxOfflineLookups {
		req.Indicators = req.Indicators[:maxOfflineLookups]
	}
	results := map[string]*enrich.Facts{}
	for _, q := range req.Indicators {
		if f := enrich.Describe(h.c.Enrich, q); f != nil {
			results[q] = f
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
