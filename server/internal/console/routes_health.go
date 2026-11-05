package console

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesHealth registers the health feature's routes.
func (h *Handler) routesHealth(viewer, analyst, admin string) {
	h.route("GET /api/health/feeds", viewer, h.getFeeds)
	h.route("PATCH /api/health/feeds", admin, h.patchFeed)
	h.route("GET /api/doctor", admin, h.getDoctor)
	h.route("GET /api/selfcheck", admin, h.getSelfCheck)
	h.route("POST /api/selfcheck", admin, h.startSelfCheck)
}

func (h *Handler) getFeeds(w http.ResponseWriter, r *http.Request, _ *store.User) {
	rep, err := h.c.Health.Feeds.Report(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// patchFeed sets the owner's choice for one source: muted, expected, or both.
func (h *Handler) patchFeed(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		HostID   string `json:"host_id"`
		Module   string `json:"module"`
		Dataset  string `json:"dataset"`
		Muted    *bool  `json:"muted"`
		Expected *bool  `json:"expected"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.HostID == "" || (req.Muted == nil && req.Expected == nil) {
		writeErr(w, http.StatusBadRequest, "host_id and muted or expected are required")
		return
	}
	if err := h.c.Health.Feeds.SetChoice(r.Context(), req.HostID, req.Module, req.Dataset, req.Muted, req.Expected); err != nil {
		h.fail(w, err)
		return
	}
	details := strings.TrimPrefix(req.Module+"/"+req.Dataset, "/")
	if req.Muted != nil {
		if *req.Muted {
			details += " muted"
		} else {
			details += " unmuted"
		}
	}
	if req.Expected != nil {
		if *req.Expected {
			details += " marked expected"
		} else {
			details += " no longer expected"
		}
	}
	h.c.Audit(r.Context(), u.Username, "feed.change", req.HostID, details)
	rep, err := h.c.Health.Feeds.Report(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// doctorCache keeps a recent report: the doctor writes one test row per run, so opening the
// page repeatedly should not write repeatedly.
var doctorCache struct {
	sync.Mutex
	rep *core.DoctorReport
}

const doctorCacheFor = 30 * time.Second

// getDoctor runs the checks, reusing a report from the last 30 seconds unless refresh is set.
func (h *Handler) getDoctor(w http.ResponseWriter, r *http.Request, _ *store.User) {
	doctorCache.Lock()
	defer doctorCache.Unlock()
	if rep := doctorCache.rep; rep != nil && r.URL.Query().Get("refresh") == "" && time.Since(rep.At) < doctorCacheFor {
		writeJSON(w, http.StatusOK, rep)
		return
	}
	rep := h.c.RunDoctor(r.Context())
	doctorCache.rep = rep
	writeJSON(w, http.StatusOK, rep)
}

type selfCheckState struct {
	Running bool                  `json:"running"`
	Last    *core.SelfCheckResult `json:"last,omitempty"`
}

func (h *Handler) getSelfCheck(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, selfCheckState{Running: h.c.Health.SelfCheckRunning(), Last: h.c.LastSelfCheck(r.Context())})
}

// startSelfCheck starts a run in the background; it can take a minute on a large install.
func (h *Handler) startSelfCheck(w http.ResponseWriter, r *http.Request, u *store.User) {
	if h.c.Health.StartSelfCheck(h.c) {
		h.c.Audit(r.Context(), u.Username, "selfcheck.run", "", "")
	}
	writeJSON(w, http.StatusAccepted, selfCheckState{Running: h.c.Health.SelfCheckRunning(), Last: h.c.LastSelfCheck(r.Context())})
}
