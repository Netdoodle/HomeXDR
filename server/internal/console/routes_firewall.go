package console

import (
	"net/http"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesFirewall registers host firewall control (Settings → Firewall): the blocked
// addresses, the global on/off switch and each host's state. Viewers see it; changes
// need the admin role.
func (h *Handler) routesFirewall(viewer, admin string) {
	h.route("GET /api/firewall", viewer, h.getFirewall)
	h.route("POST /api/firewall/blocks", admin, h.addFirewallBlock)
	h.route("DELETE /api/firewall/blocks/{id}", admin, h.removeFirewallBlock)
	h.route("PUT /api/settings/firewall", admin, h.putFirewallSettings)
}

func (h *Handler) getFirewall(w http.ResponseWriter, r *http.Request, _ *store.User) {
	v, err := h.c.FirewallStatus(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) addFirewallBlock(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in core.FirewallBlockInput
	if !decode(w, r, &in) {
		return
	}
	if _, err := h.c.AddFirewallBlock(r.Context(), u.Username, in); err != nil {
		h.fail(w, err)
		return
	}
	h.getFirewall(w, r, u)
}

func (h *Handler) removeFirewallBlock(w http.ResponseWriter, r *http.Request, u *store.User) {
	if err := h.c.RemoveFirewallBlock(r.Context(), u.Username, r.PathValue("id")); err != nil {
		h.fail(w, err)
		return
	}
	h.getFirewall(w, r, u)
}

func (h *Handler) putFirewallSettings(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in core.FirewallSettings
	if !decode(w, r, &in) {
		return
	}
	if err := h.c.SetFirewallSettings(r.Context(), in); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "settings.firewall", "", "host firewall blocking "+onOffInherit(&in.Enabled)+" globally")
	h.c.ReconcileFirewall(r.Context())
	h.getFirewall(w, r, u)
}
