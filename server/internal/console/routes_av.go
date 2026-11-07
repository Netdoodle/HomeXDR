package console

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/Netdoodle/homexdr/server/internal/av"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesAV registers the antivirus routes.
func (h *Handler) routesAV(viewer, analyst, admin string) {
	h.route("GET /api/antivirus", viewer, h.getAV)
	h.route("PUT /api/settings/antivirus", admin, h.putAV)
	h.route("DELETE /api/antivirus/verdicts/{sha256}", analyst, h.forgetAVVerdict)
}

func (h *Handler) getAV(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.c.AV.Status(r.Context()))
}

func (h *Handler) putAV(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in av.Settings
	if !decode(w, r, &in) {
		return
	}
	set, err := h.c.AV.Save(r.Context(), in)
	var ie *av.InputError
	if errors.As(err, &ie) {
		writeErr(w, http.StatusBadRequest, ie.Msg)
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	details := "off"
	if set.Enabled {
		details = fmt.Sprintf("on, action %s, scan unknown %v, intel %v, %d blocked, %d allowed",
			set.Action, set.ScanUnknown, set.UseIntel, len(set.BlockedHashes), len(set.AllowedHashes))
	}
	h.c.Audit(r.Context(), u.Username, "settings.antivirus", "", details)
	writeJSON(w, http.StatusOK, h.c.AV.Status(r.Context()))
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// forgetAVVerdict drops a stored verdict (a false positive, or to force a rescan); the
// file is judged again the next time it runs.
func (h *Handler) forgetAVVerdict(w http.ResponseWriter, r *http.Request, u *store.User) {
	sha := r.PathValue("sha256")
	if !sha256Re.MatchString(sha) {
		writeErr(w, http.StatusBadRequest, "not a SHA-256 hash")
		return
	}
	if err := h.c.State.DeleteAVVerdict(r.Context(), sha); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "antivirus.forget", sha, "")
	w.WriteHeader(http.StatusNoContent)
}
