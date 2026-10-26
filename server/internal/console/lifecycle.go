package console

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// hostView is a host with its agent update status.
type hostView struct {
	*store.Host
	Update *core.HostUpdate `json:"update,omitempty"`
}

// hostViews attaches update status to endpoint agents.
func (h *Handler) hostViews(ctx context.Context, hosts []*store.Host) []hostView {
	l := h.c.AgentLifecycle(ctx)
	archive := h.c.Release.Archive()
	var fleet []*store.Host
	if l.Updates.Staged.Enabled {
		fleet, _ = h.c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	}
	now := time.Now()
	out := make([]hostView, len(hosts))
	for i, host := range hosts {
		out[i] = hostView{Host: host}
		if host.Kind == store.HostEndpoint && !host.Revoked {
			hu := h.c.UpdateStatus(l, host, archive, fleet, now)
			out[i].Update = &hu
		}
	}
	return out
}

// releaseView is an archived release with how many agents run it.
type releaseView struct {
	core.ArchivedRelease
	Agents int `json:"agents"`
}

func (h *Handler) lifecycleView(ctx context.Context, l core.AgentLifecycle) map[string]any {
	hosts, _ := h.c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint, IncludeDecommissioned: true})
	running := map[string]int{}
	canaries, decommissioned := 0, 0
	for _, host := range hosts {
		if host.Revoked {
			continue
		}
		running[host.AgentVersion]++
		if host.DecommissionedAt != nil {
			decommissioned++
			continue
		}
		// Counted as the staged rollout does: case-insensitive, active agents only.
		if slices.ContainsFunc(host.Labels, func(lab string) bool { return strings.EqualFold(lab, l.Updates.Staged.CanaryLabel) }) {
			canaries++
		}
	}
	releases := []releaseView{}
	for _, a := range h.c.Release.Archive() {
		releases = append(releases, releaseView{ArchivedRelease: a, Agents: running[a.Version]})
	}
	return map[string]any{
		"settings": l, "releases": releases, "release_status": h.c.Release.Status(),
		"canary_agents": canaries, "decommissioned_agents": decommissioned,
	}
}

func (h *Handler) getAgentLifecycle(w http.ResponseWriter, r *http.Request, _ *store.User) {
	writeJSON(w, http.StatusOK, h.lifecycleView(r.Context(), h.c.AgentLifecycle(r.Context())))
}

func (h *Handler) putAgentLifecycle(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req core.AgentLifecycle
	if !decode(w, r, &req) {
		return
	}
	l, err := h.c.SaveAgentLifecycle(r.Context(), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	up := l.Updates
	details := fmt.Sprintf("decommission after %d days (0 = off); updates %s", l.DecommissionAfterDays, up.Default.Mode)
	if up.Default.Version != "" {
		details += " " + up.Default.Version
	}
	if len(up.Labels) > 0 {
		details += fmt.Sprintf(", %d label rules", len(up.Labels))
	}
	if up.Staged.Enabled {
		details += fmt.Sprintf(", staged (%q first, %dh)", up.Staged.CanaryLabel, up.Staged.DelayHours)
	}
	if up.Window.Enabled {
		details += fmt.Sprintf(", window %s-%s %s", up.Window.Start, up.Window.End, up.Window.Timezone)
	}
	h.c.Audit(r.Context(), u.Username, "agent.lifecycle.settings", "agents", details)
	writeJSON(w, http.StatusOK, h.lifecycleView(r.Context(), l))
}

func (h *Handler) decommissionHost(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.State.DecommissionHost(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "agent.decommission", id, "by hand")
	h.respondHost(w, r, id)
}

func (h *Handler) recommissionHost(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	was, err := h.c.State.RecommissionHost(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if was {
		h.c.Audit(r.Context(), u.Username, "agent.recommission", id, "by hand")
	}
	h.respondHost(w, r, id)
}

func (h *Handler) updateHostNow(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	if err := h.c.State.RequestUpdateNow(r.Context(), id, time.Now()); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "agent.update_now", id, "")
	h.respondHost(w, r, id)
}

func (h *Handler) respondHost(w http.ResponseWriter, r *http.Request, id string) {
	host, err := h.c.State.GetHost(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.hostViews(r.Context(), []*store.Host{host})[0])
}
