package console

import (
	"errors"
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/adguard"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

func (h *Handler) getAdGuardSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	v := h.c.AdGuard.View()
	v.Backfill = h.c.AdGuard.BackfillState(r.Context())
	writeJSON(w, http.StatusOK, v)
}

// backfillAdGuard imports AdGuard Home's query log from before live importing began.
func (h *Handler) backfillAdGuard(w http.ResponseWriter, r *http.Request, u *store.User) {
	if h.adguardFail(w, h.c.AdGuard.Backfill(r.Context())) {
		return
	}
	h.c.Audit(r.Context(), u.Username, "adguard.backfill", "", "")
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) putAdGuardSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in adguard.Input
	if !decode(w, r, &in) {
		return
	}
	v, err := h.c.AdGuard.Save(r.Context(), in)
	if h.adguardFail(w, err) {
		return
	}
	details := "off"
	if v.Enabled {
		details = "on, " + v.URL
	}
	h.c.Audit(r.Context(), u.Username, "settings.adguard", "", details)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) testAdGuardSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var in adguard.Input
	if !decode(w, r, &in) {
		return
	}
	res, err := h.c.AdGuard.Test(r.Context(), in)
	if h.adguardFail(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) adguardFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ie *adguard.InputError
	if errors.As(err, &ie) {
		writeErr(w, http.StatusBadRequest, ie.Msg)
		return true
	}
	h.fail(w, err)
	return true
}
