package console

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesRetention registers the data retention routes.
func (h *Handler) routesRetention(viewer, admin string) {
	h.route("GET /api/retention", viewer, h.getRetention)
	h.route("POST /api/retention/preview", admin, h.previewRetention)
	h.route("PUT /api/settings/retention", admin, h.putRetention)
}

func (h *Handler) getRetention(w http.ResponseWriter, r *http.Request, _ *store.User) {
	st, err := h.c.RetentionStatus(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handler) previewRetention(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var in core.RetentionSettings
	if !decode(w, r, &in) {
		return
	}
	pv, err := h.c.PreviewRetention(r.Context(), in)
	if h.retentionFail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

func (h *Handler) putRetention(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		core.RetentionSettings
		Acknowledge   bool   `json:"acknowledge"`
		ConfirmPhrase string `json:"confirm_phrase"`
	}
	if !decode(w, r, &in) {
		return
	}
	old := h.c.Retention()
	pv, err := h.c.SetRetention(r.Context(), in.RetentionSettings, in.Acknowledge, in.ConfirmPhrase)
	if h.retentionFail(w, err) {
		return
	}
	h.c.Audit(r.Context(), u.Username, "settings.retention", "", fmt.Sprintf("days %d -> %d, size cap %d -> %d bytes, removes %d events",
		old.Days, in.Days, old.MaxBytes, in.MaxBytes, pv.RemovesEvents))
	st, err := h.c.RetentionStatus(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handler) retentionFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ve *core.ValidationError
	if errors.As(err, &ve) {
		writeErr(w, http.StatusBadRequest, ve.Msg)
		return true
	}
	h.fail(w, err)
	return true
}
