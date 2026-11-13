package core

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/Netdoodle/homexdr/server/internal/av"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Host groups (store.HostGroup) and the settings they override. The organisation is the
// top of the tree ("Global"): its settings are the antivirus' own. A host takes each
// setting from its group if the group sets it, else from the parent group, else Global.

const orgKey = "org"

// Org is the organisation at the top of the group tree.
type Org struct {
	Name string `json:"name"`
}

// DefaultOrgName is shown until the organisation is named.
const DefaultOrgName = "Global"

// groupCache keeps the (small) group tree in memory for the ingest path.
type groupCache struct {
	mu     sync.RWMutex
	byID   map[string]*store.HostGroup
	loaded bool
}

// GetOrg returns the organisation.
func (c *Core) GetOrg(ctx context.Context) Org {
	o := Org{Name: DefaultOrgName}
	if err := c.State.GetKV(ctx, orgKey, &o); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("read organisation", "err", err)
	}
	if strings.TrimSpace(o.Name) == "" {
		o.Name = DefaultOrgName
	}
	return o
}

// SetOrg names the organisation.
func (c *Core) SetOrg(ctx context.Context, o Org) (Org, error) {
	o.Name = strings.TrimSpace(o.Name)
	if o.Name == "" || len(o.Name) > 80 {
		return o, &store.GroupError{Msg: "the organisation name is 1 to 80 characters"}
	}
	return o, c.State.SetKV(ctx, orgKey, o)
}

// ReloadGroups refreshes the in-memory group tree; call it after every change.
func (c *Core) ReloadGroups(ctx context.Context) error {
	gs, err := c.State.ListGroups(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]*store.HostGroup, len(gs))
	for _, g := range gs {
		m[g.ID] = g
	}
	c.groups.mu.Lock()
	c.groups.byID, c.groups.loaded = m, true
	c.groups.mu.Unlock()
	return nil
}

// groupChain returns the group and its ancestors, nearest first.
func (c *Core) groupChain(groupID string) []*store.HostGroup {
	c.groups.mu.RLock()
	defer c.groups.mu.RUnlock()
	var chain []*store.HostGroup
	for id := groupID; id != "" && len(chain) <= store.MaxGroupDepth; {
		g, ok := c.groups.byID[id]
		if !ok {
			break
		}
		chain = append(chain, g)
		id = g.ParentID
	}
	return chain
}

// SettingSource says where an effective setting comes from.
type SettingSource struct {
	Value bool `json:"value"`
	// GroupID and GroupName name the group that sets it; both empty for Global.
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

// StringSource is a string-valued effective setting and where it comes from.
type StringSource struct {
	Value     string `json:"value"`
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

// EffectiveAV is a group's antivirus settings after inheritance.
type EffectiveAV struct {
	ClamAV SettingSource `json:"clamav"`
	YARA   SettingSource `json:"yara"`
	Action StringSource  `json:"action"`
	// AppControl is the Windows App Control mode (off, audit, enforce).
	AppControl StringSource `json:"app_control"`
	// AIAuto: whether the AI analyst investigates the group's alerts on its own (when it
	// is set up and automatic investigations are on globally).
	AIAuto SettingSource `json:"ai_auto"`
}

// ResolveAV works out which file scanners apply to hosts in a group ("" for hosts in
// no group).
func (c *Core) ResolveAV(groupID string) EffectiveAV {
	set := c.AV.Settings()
	eff := EffectiveAV{ClamAV: SettingSource{Value: set.UseClamAV}, YARA: SettingSource{Value: set.UseYARA},
		Action: StringSource{Value: set.Action}, AIAuto: SettingSource{Value: true}, AppControl: StringSource{Value: set.AppControl}}
	var clamDone, yaraDone, actionDone, aiDone, acDone bool
	for _, g := range c.groupChain(groupID) {
		if p := g.Policy.AV.AppControl; p != nil && !acDone {
			eff.AppControl, acDone = StringSource{Value: *p, GroupID: g.ID, GroupName: g.Name}, true
		}
		if p := g.Policy.AV.Action; p != nil && !actionDone {
			eff.Action, actionDone = StringSource{Value: *p, GroupID: g.ID, GroupName: g.Name}, true
		}
		if p := g.Policy.AI.Auto; p != nil && !aiDone {
			eff.AIAuto, aiDone = SettingSource{Value: *p, GroupID: g.ID, GroupName: g.Name}, true
		}
		if p := g.Policy.AV.ClamAV; p != nil && !clamDone {
			eff.ClamAV, clamDone = SettingSource{Value: *p, GroupID: g.ID, GroupName: g.Name}, true
		}
		if p := g.Policy.AV.YARA; p != nil && !yaraDone {
			eff.YARA, yaraDone = SettingSource{Value: *p, GroupID: g.ID, GroupName: g.Name}, true
		}
	}
	return eff
}

// avScanners is the antivirus' view of ResolveAV.
func (c *Core) avScanners(groupID string) av.Scanners {
	e := c.ResolveAV(groupID)
	return av.Scanners{ClamAV: e.ClamAV.Value, YARA: e.YARA.Value, Action: e.Action.Value}
}

// GroupAndChildren returns a group's ID and its child groups' IDs.
func (c *Core) GroupAndChildren(id string) []string {
	out := []string{id}
	c.groups.mu.RLock()
	defer c.groups.mu.RUnlock()
	for _, g := range c.groups.byID {
		if g.ParentID == id {
			out = append(out, g.ID)
		}
	}
	return out
}

// aiAutoForHost reports whether the host's group lets the AI analyst investigate its
// alerts on its own.
func (c *Core) aiAutoForHost(ctx context.Context, hostID string) bool {
	if hostID == "" || hostID == ServerHostID {
		return true
	}
	h, err := c.State.GetHost(ctx, hostID)
	if err != nil {
		return true
	}
	return c.ResolveAV(h.GroupID).AIAuto.Value
}
