package console

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// routesGroups registers the host group routes: the organisation (Global), its parent
// and child groups, their setting overrides and which hosts are in them.
func (h *Handler) routesGroups(viewer, admin string) {
	h.route("GET /api/groups", viewer, h.listGroups)
	h.route("PUT /api/org", admin, h.putOrg)
	h.route("POST /api/groups", admin, h.createGroup)
	h.route("PATCH /api/groups/{id}", admin, h.patchGroup)
	h.route("DELETE /api/groups/{id}", admin, h.deleteGroup)
	h.route("PUT /api/hosts/group", admin, h.setHostsGroup)
}

// groupView is a group with its settings after inheritance.
type groupView struct {
	*store.HostGroup
	Effective core.EffectiveAV `json:"effective"`
}

type groupsView struct {
	Org core.Org `json:"org"`
	// Global holds the organisation-wide values (Settings → Antivirus).
	Global struct {
		ClamAV bool   `json:"clamav"`
		YARA   bool   `json:"yara"`
		Action string `json:"action"`
		AIAuto bool   `json:"ai_auto"`
		// AppControl is the Windows App Control mode.
		AppControl string `json:"app_control"`
	} `json:"global"`
	Groups    []groupView `json:"groups"`
	Ungrouped int         `json:"ungrouped"` // hosts in no group
}

func (h *Handler) groupsView(r *http.Request) (*groupsView, error) {
	gs, err := h.c.State.ListGroups(r.Context())
	if err != nil {
		return nil, err
	}
	v := &groupsView{Org: h.c.GetOrg(r.Context()), Groups: []groupView{}}
	set := h.c.AV.Settings()
	v.Global.ClamAV, v.Global.YARA, v.Global.Action, v.Global.AIAuto = set.UseClamAV, set.UseYARA, set.Action, true
	v.Global.AppControl = set.AppControl
	for _, g := range gs {
		v.Groups = append(v.Groups, groupView{HostGroup: g, Effective: h.c.ResolveAV(g.ID)})
	}
	hosts, err := h.c.State.ListHosts(r.Context(), store.HostFilter{Kind: store.HostEndpoint, GroupIDs: []string{""}})
	if err != nil {
		return nil, err
	}
	v.Ungrouped = len(hosts)
	return v, nil
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, _ *store.User) {
	v, err := h.groupsView(r)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// groupResult reloads the cache after a change and answers with the whole tree.
func (h *Handler) groupResult(w http.ResponseWriter, r *http.Request, err error) {
	var ge *store.GroupError
	switch {
	case errors.As(err, &ge):
		writeErr(w, http.StatusBadRequest, ge.Msg)
		return
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "no such group")
		return
	case err != nil:
		h.fail(w, err)
		return
	}
	if err := h.c.ReloadGroups(r.Context()); err != nil {
		h.fail(w, err)
		return
	}
	h.listGroups(w, r, nil)
}

func (h *Handler) putOrg(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in core.Org
	if !decode(w, r, &in) {
		return
	}
	o, err := h.c.SetOrg(r.Context(), in)
	if err == nil {
		h.c.Audit(r.Context(), u.Username, "org.rename", "", o.Name)
	}
	h.groupResult(w, r, err)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		Name     string `json:"name"`
		ParentID string `json:"parent_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	g, err := h.c.State.CreateGroup(r.Context(), in.Name, in.ParentID)
	if err == nil {
		h.c.Audit(r.Context(), u.Username, "group.create", g.ID, h.groupPath(r, g))
	}
	h.groupResult(w, r, err)
}

func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in store.GroupUpdate
	if !decode(w, r, &in) {
		return
	}
	g, err := h.c.State.UpdateGroup(r.Context(), r.PathValue("id"), in)
	if err == nil {
		var parts []string
		if in.Name != nil || in.ParentID != nil {
			parts = append(parts, "now "+h.groupPath(r, g))
		}
		if in.Policy != nil {
			action := "inherit"
			if a := in.Policy.AV.Action; a != nil {
				action = *a
			}
			ac := "inherit"
			if a := in.Policy.AV.AppControl; a != nil {
				ac = *a
			}
			parts = append(parts, "ClamAV "+onOffInherit(in.Policy.AV.ClamAV), "YARA "+onOffInherit(in.Policy.AV.YARA),
				"antivirus response "+action, "App Control "+ac, "AI auto-investigation "+onOffInherit(in.Policy.AI.Auto))
		}
		h.c.Audit(r.Context(), u.Username, "group.update", g.ID, g.Name+": "+strings.Join(parts, ", "))
	}
	h.groupResult(w, r, err)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	g, err := h.c.State.GetGroup(r.Context(), id)
	if err == nil {
		err = h.c.State.DeleteGroup(r.Context(), id)
	}
	if err == nil {
		h.c.Audit(r.Context(), u.Username, "group.delete", id, fmt.Sprintf("%s (%d hosts moved up)", g.Name, g.Hosts))
	}
	h.groupResult(w, r, err)
}

func (h *Handler) setHostsGroup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct {
		HostIDs []string `json:"host_ids"`
		GroupID string   `json:"group_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.HostIDs) > 5000 {
		writeErr(w, http.StatusBadRequest, "at most 5000 hosts at a time")
		return
	}
	n, err := h.c.State.SetHostsGroup(r.Context(), in.HostIDs, in.GroupID)
	if err == nil {
		name := h.c.GetOrg(r.Context()).Name + " (no group)"
		if in.GroupID != "" {
			if g, gerr := h.c.State.GetGroup(r.Context(), in.GroupID); gerr == nil {
				name = h.groupPath(r, g)
			}
		}
		h.c.Audit(r.Context(), u.Username, "host.group", in.GroupID, fmt.Sprintf("%d hosts moved to %s", n, name))
	}
	h.groupResult(w, r, err)
}

// groupFilter reads ?group=: a group ID (with its child groups) or "none" for hosts in
// no group. No parameter: no filter.
func (h *Handler) groupFilter(r *http.Request) []string {
	g := r.URL.Query().Get("group")
	switch g {
	case "":
		return nil
	case "none":
		return []string{""}
	}
	return h.c.GroupAndChildren(g)
}

// groupPath names a group with its parent: "DTS Assets > Marketing Dept".
func (h *Handler) groupPath(r *http.Request, g *store.HostGroup) string {
	if g.ParentID == "" {
		return g.Name
	}
	if p, err := h.c.State.GetGroup(r.Context(), g.ParentID); err == nil {
		return p.Name + " > " + g.Name
	}
	return g.Name
}

func onOffInherit(b *bool) string {
	switch {
	case b == nil:
		return "inherit"
	case *b:
		return "on"
	}
	return "off"
}
