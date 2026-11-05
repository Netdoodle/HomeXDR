package console

import (
	"net/http"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesNoise registers the noise feature's routes.
func (h *Handler) routesNoise(viewer, analyst, admin string) {
	h.route("GET /api/alerts/noise", viewer, h.alertNoise)
	h.route("GET /api/suppressions", viewer, h.listSuppressions)
	h.route("POST /api/suppressions", admin, h.createSuppression)
	h.route("POST /api/suppressions/preview", analyst, h.previewSuppression)
	h.route("PATCH /api/suppressions/{id}", admin, h.patchSuppression)
	h.route("DELETE /api/suppressions/{id}", admin, h.deleteSuppression)
	h.route("GET /api/settings/noise", viewer, h.getNoiseSettings)
	h.route("PUT /api/settings/noise", admin, h.putNoiseSettings)
}

func (h *Handler) alertNoise(w http.ResponseWriter, r *http.Request, _ *store.User) {
	hours := qInt(r, "hours", 24)
	if hours < 1 || hours > 24*30 {
		hours = 24
	}
	limit := qInt(r, "limit", 8)
	if limit < 1 || limit > 50 {
		limit = 8
	}
	shapes, err := h.c.State.TopRepeating(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour), limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shapes": shapes, "hours": hours})
}

func (h *Handler) listSuppressions(w http.ResponseWriter, r *http.Request, _ *store.User) {
	list, err := h.c.State.ListSuppressions(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"suppressions": list})
}

func (h *Handler) createSuppression(w http.ResponseWriter, r *http.Request, u *store.User) {
	var spec core.SuppressionSpec
	if !decode(w, r, &spec) {
		return
	}
	res, err := h.c.CreateSuppression(r.Context(), spec, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (h *Handler) previewSuppression(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var spec core.SuppressionSpec
	if !decode(w, r, &spec) {
		return
	}
	p, err := h.c.PreviewSuppression(r.Context(), spec)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) patchSuppression(w http.ResponseWriter, r *http.Request, u *store.User) {
	var patch core.SuppressionPatch
	if !decode(w, r, &patch) {
		return
	}
	sp, err := h.c.UpdateSuppression(r.Context(), r.PathValue("id"), patch, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sp)
}

func (h *Handler) deleteSuppression(w http.ResponseWriter, r *http.Request, u *store.User) {
	if err := h.c.DeleteSuppression(r.Context(), r.PathValue("id"), u.Username); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getNoiseSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	n, err := core.LoadNoiseSettings(r.Context(), h.c.State)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (h *Handler) putNoiseSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var n core.NoiseSettings
	if !decode(w, r, &n) {
		return
	}
	saved, err := h.c.SaveNoiseSettings(r.Context(), n, u.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}
