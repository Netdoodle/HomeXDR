package console

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/behavior"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesNetwork registers the network feature's routes.
func (h *Handler) routesNetwork(viewer, analyst, admin string) {
	h.route("GET /api/devices", viewer, h.listDevices)
	h.route("PATCH /api/devices/{id}", analyst, h.patchDevice)
	h.route("GET /api/settings/network", admin, h.getNetworkSettings)
	h.route("PUT /api/settings/network", admin, h.putNetworkSettings)
	h.route("GET /api/behavior/status", viewer, h.behaviorStatus)
	h.route("GET /api/settings/behavior", admin, h.getBehaviorSettings)
	h.route("PUT /api/settings/behavior", admin, h.putBehaviorSettings)
}

// netflowStats is the NetFlow section of the integrations page.
func (h *Handler) netflowStats() map[string]any {
	f := h.c.Flow
	return map[string]any{
		"enabled": h.c.Cfg.NetFlowAddr != "", "listening": f.Listening.Load(), "addr": f.Addr.Load(),
		"packets": f.Packets.Load(), "records": f.Records.Load(), "dropped": f.Dropped.Load(),
		"refused": f.Refused.Load(), "malformed": f.Malformed.Load(), "waiting": f.Waiting.Load(),
		"discarded": f.Discarded.Load(), "failed": f.Failed.Load(), "exporters": f.Exporters(),
	}
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.c.Inventory.List())
}

func (h *Handler) patchDevice(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req core.DevicePatch
	if !decode(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	d, err := h.c.Inventory.Patch(r.Context(), id, req)
	if err != nil {
		h.fail(w, err)
		return
	}
	var changed []string
	if req.Name != nil {
		changed = append(changed, "name")
	}
	if req.Note != nil {
		changed = append(changed, "note")
	}
	if req.Known != nil {
		changed = append(changed, "known")
	}
	h.c.Audit(r.Context(), u.Username, "device.update", id, strings.Join(changed, ","))
	writeJSON(w, http.StatusOK, d)
}

// networkSettingsView is the settings with what the server has worked out by itself.
type networkSettingsView struct {
	core.NetworkSettings
	FirewallLearned []string           `json:"firewall_learned"`
	SubnetsSeen     []core.SubnetCount `json:"subnets_seen"`
	LearningUntil   time.Time          `json:"learning_until"`
}

func (h *Handler) networkSettingsView() networkSettingsView {
	inv := h.c.Inventory
	list := inv.List()
	return networkSettingsView{
		NetworkSettings: inv.Settings(), FirewallLearned: inv.FirewallAddrs(),
		SubnetsSeen: list.Subnets, LearningUntil: list.LearningUntil,
	}
}

func (h *Handler) getNetworkSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.networkSettingsView())
}

func (h *Handler) putNetworkSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req core.NetworkSettings
	if !decode(w, r, &req) {
		return
	}
	if _, err := h.c.Inventory.SetSettings(r.Context(), req); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "settings.network", "", "")
	writeJSON(w, http.StatusOK, h.networkSettingsView())
}

func (h *Handler) behaviorStatus(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"detectors": h.c.Behavior.Statuses()})
}

func (h *Handler) getBehaviorSettings(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"detectors": h.c.Behavior.DetectorViews()})
}

func (h *Handler) putBehaviorSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req behavior.Settings
	if !decode(w, r, &req) {
		return
	}
	if err := h.c.Behavior.SetSettings(r.Context(), req); err != nil {
		var ie *behavior.InputError
		if errors.As(err, &ie) {
			writeErr(w, http.StatusBadRequest, ie.Msg)
			return
		}
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "settings.behavior", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"detectors": h.c.Behavior.DetectorViews()})
}
