package console

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/backup"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesBackup registers the cold archive routes (Data retention page).
func (h *Handler) routesBackup(admin string) {
	h.route("GET /api/backup", admin, h.getBackup)
	h.route("PUT /api/settings/backup", admin, h.putBackup)
	h.route("POST /api/backup/test", admin, h.testBackup)
	h.route("POST /api/backup/run", admin, h.runBackup)
	h.route("GET /api/backup/archives", admin, h.listArchives)
	h.route("POST /api/backup/import", admin, h.importArchive)
}

func (h *Handler) getBackup(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.c.Backup.View(r.Context()))
}

func (h *Handler) putBackup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in backup.Input
	if !decode(w, r, &in) {
		return
	}
	v, err := h.c.Backup.Save(r.Context(), in)
	if h.backupFail(w, err) {
		return
	}
	details := "off"
	if v.Enabled {
		details = fmt.Sprintf("on, %s bucket %s prefix %q", v.Endpoint, v.Bucket, v.Prefix)
	}
	h.c.Audit(r.Context(), u.Username, "settings.backup", "", details)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) testBackup(w http.ResponseWriter, r *http.Request, _ *store.User) {
	var in backup.Input
	if !decode(w, r, &in) {
		return
	}
	if err := h.c.Backup.Test(r.Context(), in); err != nil {
		var ie *backup.InputError
		if errors.As(err, &ie) {
			writeErr(w, http.StatusBadRequest, ie.Msg)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Wrote, read back and deleted a test object: the bucket and keys work."})
}

func (h *Handler) runBackup(w http.ResponseWriter, r *http.Request, u *store.User) {
	if h.backupFail(w, h.c.Backup.RunNow()) {
		return
	}
	h.c.Audit(r.Context(), u.Username, "backup.run", "", "")
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) listArchives(w http.ResponseWriter, r *http.Request, _ *store.User) {
	days, err := h.c.Backup.Archived(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not list the bucket: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, days)
}

func (h *Handler) importArchive(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		Day string `json:"day"`
	}
	if !decode(w, r, &in) {
		return
	}
	// A day older than the time limit would be purged again within hours.
	if d := h.c.Retention().Days; d > 0 {
		if t, err := time.Parse("2006-01-02", in.Day); err == nil && t.Before(time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -d)) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is older than the %d-day retention limit, so it would be removed again at the next cleanup. Raise the time limit first.", in.Day, d))
			return
		}
	}
	if h.backupFail(w, h.c.Backup.Import(r.Context(), in.Day)) {
		return
	}
	h.c.Audit(r.Context(), u.Username, "backup.import", in.Day, "")
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) backupFail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ie *backup.InputError
	if errors.As(err, &ie) {
		writeErr(w, http.StatusBadRequest, ie.Msg)
		return true
	}
	h.fail(w, err)
	return true
}
