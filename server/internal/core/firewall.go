package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Host firewall control: addresses blocked in each endpoint's own firewall (Windows
// Firewall rules in the "HomeXDR" group, nftables table inet homexdr_block, a pf anchor).
// A block applies everywhere (Global) or to one group and its child groups; a group can
// switch blocking off for its hosts (firewall.enabled, default on). A reconcile loop sends
// each host its complete rule set (firewall.apply) whenever its version differs from the
// one the agent last applied, like Windows App Control. See docs/firewall.md.

const (
	firewallIssuer      = "firewall"
	firewallKVPref      = "firewall.host."
	firewallSettingsKey = "firewall.settings"
	firewallRetry       = 30 * time.Minute
	firewallPending     = time.Hour
	firewallNoteMax     = 300
	// MaxFirewallBlocks caps the block policies in all, so no host can get more than the
	// agent accepts (api.FirewallMaxRules).
	MaxFirewallBlocks = api.FirewallMaxRules
)

// firewallPlatforms are the agent platforms with host firewall control.
var firewallPlatforms = []string{"windows", "linux", "darwin"}

// Server address discovery, replaceable in tests.
var (
	firewallLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	firewallInterfaceAddrs = net.InterfaceAddrs
)

type firewallRuntime struct {
	mu       sync.Mutex // serializes reconciles and result handling
	loadOnce sync.Once
	off      atomic.Bool // the global setting is off (the zero value is on)

	addrMu  sync.Mutex
	addrs   []netip.Addr
	addrsAt time.Time
}

// FirewallSettings are the global host firewall settings.
type FirewallSettings struct {
	// Enabled: whether block policies apply to hosts whose group does not say otherwise.
	Enabled bool `json:"enabled"`
}

func (c *Core) loadFirewallSettings() {
	c.firewall.loadOnce.Do(func() {
		s := FirewallSettings{Enabled: true}
		if err := c.State.GetKV(context.Background(), firewallSettingsKey, &s); err != nil && !errors.Is(err, store.ErrNotFound) {
			c.Log.Warn("host firewall: read settings", "err", err)
		}
		c.firewall.off.Store(!s.Enabled)
	})
}

// FirewallGlobalEnabled is the global firewall.enabled value.
func (c *Core) FirewallGlobalEnabled() bool {
	c.loadFirewallSettings()
	return !c.firewall.off.Load()
}

// SetFirewallSettings saves the global settings.
func (c *Core) SetFirewallSettings(ctx context.Context, s FirewallSettings) error {
	c.loadFirewallSettings()
	if err := c.State.SetKV(ctx, firewallSettingsKey, s); err != nil {
		return err
	}
	c.firewall.off.Store(!s.Enabled)
	return nil
}

// ServerAddrs returns the HomeXDR server's own addresses, which are never blocked: the
// addresses and resolved names in HOMEXDR_SERVER_NAMES, the agent URL's host and the
// server's interface addresses. Cached for five minutes.
func (c *Core) ServerAddrs(ctx context.Context) []netip.Addr {
	rt := &c.firewall
	rt.addrMu.Lock()
	defer rt.addrMu.Unlock()
	if rt.addrs != nil && time.Since(rt.addrsAt) < 5*time.Minute {
		return rt.addrs
	}
	out := []netip.Addr{}
	add := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		if a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	names := slices.Clone(c.Cfg.ServerNames)
	if u, err := url.Parse(c.Cfg.AgentURL); err == nil && u.Hostname() != "" {
		names = append(names, u.Hostname())
	}
	if h, _, err := net.SplitHostPort(c.Cfg.AgentAddr); err == nil && h != "" {
		names = append(names, h)
	}
	for _, n := range names {
		n = strings.Trim(strings.TrimSpace(n), "[]")
		if n == "" {
			continue
		}
		if a, err := netip.ParseAddr(n); err == nil {
			add(a)
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		res, err := firewallLookup(lctx, n)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range res {
			add(a)
		}
	}
	if ifs, err := firewallInterfaceAddrs(); err == nil {
		for _, ia := range ifs {
			if p, err := netip.ParsePrefix(ia.String()); err == nil {
				add(p.Addr())
			} else if a, err := netip.ParseAddr(ia.String()); err == nil {
				add(a)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	rt.addrs, rt.addrsAt = out, time.Now()
	return out
}

// FirewallBlockInput is a new block from the console.
type FirewallBlockInput struct {
	CIDR      string `json:"cidr"`
	Direction string `json:"direction"`
	GroupID   string `json:"group_id"` // "" for every host
	Note      string `json:"note"`
	AlertID   string `json:"alert_id"`
}

// AddFirewallBlock validates and stores a block, then sends hosts their new rule sets.
func (c *Core) AddFirewallBlock(ctx context.Context, user string, in FirewallBlockInput) (*store.FirewallBlock, error) {
	p, err := hostfw.ParseCIDR(in.CIDR)
	if err != nil {
		return nil, invalid("%v", err)
	}
	if err := hostfw.CheckProtected(p, c.ServerAddrs(ctx)); err != nil {
		return nil, invalid("%v", err)
	}
	if in.Direction == "" {
		in.Direction = api.FirewallBoth
	}
	if err := hostfw.CheckDirection(in.Direction); err != nil {
		return nil, invalid("%v", err)
	}
	in.Note = strings.TrimSpace(in.Note)
	if len(in.Note) > firewallNoteMax {
		return nil, invalid("the note is at most %d characters", firewallNoteMax)
	}
	in.AlertID = strings.TrimSpace(in.AlertID)
	if len(in.AlertID) > 64 {
		return nil, invalid("invalid alert id")
	}
	if in.GroupID != "" {
		if _, err := c.State.GetGroup(ctx, in.GroupID); errors.Is(err, store.ErrNotFound) {
			return nil, invalid("the group does not exist")
		} else if err != nil {
			return nil, err
		}
	}
	n, err := c.State.CountFirewallBlocks(ctx)
	if err != nil {
		return nil, err
	}
	if n >= MaxFirewallBlocks {
		return nil, invalid("at most %d addresses can be blocked; remove some first", MaxFirewallBlocks)
	}
	b := &store.FirewallBlock{CIDR: hostfw.Format(p), Direction: in.Direction, GroupID: in.GroupID, Note: in.Note,
		AlertID: in.AlertID, CreatedBy: user}
	if err := c.State.CreateFirewallBlock(ctx, b); errors.Is(err, store.ErrConflict) {
		return nil, invalid("%s is already blocked for %s", b.CIDR, c.firewallScopeName(ctx, b.GroupID))
	} else if err != nil {
		return nil, err
	}
	c.Audit(ctx, user, "firewall.block.add", b.ID, fmt.Sprintf("%s (%s) for %s: %s", b.CIDR, b.Direction, c.firewallScopeName(ctx, b.GroupID), b.Note))
	c.ReconcileFirewall(ctx)
	return b, nil
}

// RemoveFirewallBlock deletes a block, then sends hosts their new rule sets.
func (c *Core) RemoveFirewallBlock(ctx context.Context, user, id string) error {
	b, err := c.State.GetFirewallBlock(ctx, id)
	if err != nil {
		return err
	}
	if err := c.State.DeleteFirewallBlock(ctx, id); err != nil {
		return err
	}
	c.Audit(ctx, user, "firewall.block.remove", b.ID, fmt.Sprintf("%s (%s) for %s: %s", b.CIDR, b.Direction, c.firewallScopeName(ctx, b.GroupID), b.Note))
	c.ReconcileFirewall(ctx)
	return nil
}

// firewallScopeName names a block's scope: the organisation or the group's path.
func (c *Core) firewallScopeName(ctx context.Context, groupID string) string {
	if groupID == "" {
		return c.GetOrg(ctx).Name
	}
	chain := c.groupChain(groupID)
	if len(chain) == 0 {
		return "a deleted group"
	}
	names := make([]string, len(chain))
	for i, g := range chain {
		names[len(chain)-1-i] = g.Name
	}
	return strings.Join(names, " > ")
}

// firewallRulesFor returns the rules for a host in groupID: global blocks plus those of
// its group and the group's ancestors. Blocks covering a server address (it may have
// changed since they were added) are left out.
func (c *Core) firewallRulesFor(groupID string, blocks []*store.FirewallBlock, protected []netip.Addr) []api.FirewallRule {
	scopes := map[string]bool{"": true}
	for _, g := range c.groupChain(groupID) {
		scopes[g.ID] = true
	}
	rules := []api.FirewallRule{}
	for _, b := range blocks {
		if !scopes[b.GroupID] {
			continue
		}
		p, err := hostfw.ParseCIDR(b.CIDR)
		if err != nil || hostfw.CheckProtected(p, protected) != nil {
			continue
		}
		r := api.FirewallRule{CIDR: hostfw.Format(p), Direction: b.Direction}
		if r.Direction == "" {
			r.Direction = api.FirewallBoth
		}
		if !slices.Contains(rules, r) {
			rules = append(rules, r)
		}
	}
	slices.SortFunc(rules, func(a, b api.FirewallRule) int {
		return strings.Compare(a.CIDR+"|"+a.Direction, b.CIDR+"|"+b.Direction)
	})
	if len(rules) > api.FirewallMaxRules {
		rules = rules[:api.FirewallMaxRules]
	}
	return rules
}

// firewallVersion identifies a rule set; "none" is the empty set.
func firewallVersion(rules []api.FirewallRule) string {
	if len(rules) == 0 {
		return "none"
	}
	h := sha256.New()
	for _, r := range rules {
		h.Write([]byte(r.CIDR + "|" + r.Direction + ";"))
	}
	return "fw-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// FirewallHost is the host firewall state of one host.
type FirewallHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	Enabled  bool   `json:"enabled"` // what the host's group says
	// EnabledFrom is the group that sets it; "" for Global.
	EnabledFrom string `json:"enabled_from,omitempty"`
	// Status: off, empty (nothing to block), applied, pending, failed, not_allowed, offline.
	Status       string    `json:"status"`
	Desired      string    `json:"desired,omitempty"`
	Rules        int       `json:"rules"` // rules in the desired set
	Applied      string    `json:"applied,omitempty"`
	AppliedRules int       `json:"applied_rules"`
	Backend      string    `json:"backend,omitempty"`
	Message      string    `json:"message,omitempty"`
	CommandID    string    `json:"command_id,omitempty"`
	Attempted    string    `json:"attempted,omitempty"` // the version last sent
	AttemptAt    time.Time `json:"attempt_at,omitzero"`
	UpdatedAt    time.Time `json:"updated_at,omitzero"`
}

func (c *Core) firewallState(ctx context.Context, hostID string) FirewallHost {
	var st FirewallHost
	if err := c.State.GetKV(ctx, firewallKVPref+hostID, &st); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("host firewall: read state", "host", hostID, "err", err)
	}
	st.HostID = hostID
	return st
}

func (c *Core) saveFirewallState(ctx context.Context, st FirewallHost) {
	st.UpdatedAt = time.Now().UTC()
	if err := c.State.SetKV(ctx, firewallKVPref+st.HostID, st); err != nil {
		c.Log.Warn("host firewall: save state", "host", st.HostID, "err", err)
	}
}

// FirewallHostState returns one host's stored state.
func (c *Core) FirewallHostState(ctx context.Context, hostID string) FirewallHost {
	return c.firewallState(ctx, hostID)
}

func (c *Core) firewallHosts(ctx context.Context) ([]*store.Host, error) {
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return nil, err
	}
	out := hosts[:0]
	for _, h := range hosts {
		if slices.Contains(firewallPlatforms, h.OS.Platform) {
			out = append(out, h)
		}
	}
	return out, nil
}

func (c *Core) runFirewall(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		c.ReconcileFirewall(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReconcileFirewall brings every endpoint's HomeXDR firewall rules in line with the block
// policies that apply to it.
func (c *Core) ReconcileFirewall(ctx context.Context) {
	c.firewall.mu.Lock()
	defer c.firewall.mu.Unlock()
	hosts, err := c.firewallHosts(ctx)
	if err != nil {
		c.Log.Warn("host firewall: list hosts", "err", err)
		return
	}
	blocks, err := c.State.ListFirewallBlocks(ctx)
	if err != nil {
		c.Log.Warn("host firewall: list blocks", "err", err)
		return
	}
	protected := c.ServerAddrs(ctx)
	now := time.Now().UTC()
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		eff := c.ResolveAV(h.GroupID).Firewall
		st := c.firewallState(ctx, h.ID)
		st.Hostname, st.Platform, st.Enabled, st.EnabledFrom = h.Hostname, h.OS.Platform, eff.Value, eff.GroupName
		rules := []api.FirewallRule{}
		if eff.Value {
			rules = c.firewallRulesFor(h.GroupID, blocks, protected)
		}
		st.Desired, st.Rules = firewallVersion(rules), len(rules)
		// Nothing wanted, nothing applied, nothing on its way: no command.
		if st.Desired == "none" && (st.Applied == "" || st.Applied == "none") && st.CommandID == "" {
			want := "empty"
			if !eff.Value {
				want = "off"
			}
			if st.Status != want {
				st.Status, st.Message = want, ""
				c.saveFirewallState(ctx, st)
			}
			continue
		}
		if st.CommandID != "" {
			rec, err := c.State.GetCommand(ctx, st.CommandID)
			if err == nil && !store.FinalStatus(rec.Status) && now.Sub(rec.IssuedAt) < firewallPending {
				continue // still on its way
			}
			if err == nil && store.FinalStatus(rec.Status) {
				// The result arrived without CommandFinished (e.g. a server restart).
				applyFirewallResult(&st, rec)
			}
			st.CommandID = ""
		}
		if st.Applied == st.Desired {
			if st.Status != "applied" {
				st.Status = "applied"
				c.saveFirewallState(ctx, st)
			}
			continue
		}
		// A failed version is tried again after a while; a new version goes out at once.
		if (st.Status == "failed" || st.Status == "not_allowed") && st.Attempted == st.Desired && now.Sub(st.AttemptAt) < firewallRetry {
			c.saveFirewallState(ctx, st)
			continue
		}
		if h.Status != "online" {
			st.Status, st.Message = "offline", "applies when the host is back online"
			c.saveFirewallState(ctx, st)
			continue
		}
		params, _ := json.Marshal(api.FirewallParams{Version: st.Desired, Rules: rules})
		st.AttemptAt, st.Attempted = now, st.Desired
		rec, err := c.IssueCommand(ctx, h, api.CmdFirewall, params, firewallIssuer, "", firewallPending)
		switch {
		case errors.Is(err, ErrNotAllowed):
			st.Status = "not_allowed"
			st.Message = "the host's local policy does not allow firewall.apply: add it to allowed_actions in agent.json, or update the agent"
		case err != nil:
			st.Status, st.Message = "failed", err.Error()
		default:
			st.Status, st.CommandID, st.Message = "pending", rec.ID, ""
			c.Audit(ctx, firewallIssuer, api.CmdFirewall, h.ID, fmt.Sprintf("%s: %s (%d rules)", h.Hostname, st.Desired, len(rules)))
		}
		c.saveFirewallState(ctx, st)
	}
}

func applyFirewallResult(st *FirewallHost, rec *store.CommandRecord) {
	if rec.Status == api.StatusCompleted {
		var r api.FirewallResult
		_ = json.Unmarshal(rec.Output, &r)
		st.Applied, st.AppliedRules, st.Backend, st.Message, st.Status = r.Version, r.Rules, r.Backend, r.Message, "applied"
		return
	}
	st.Status, st.Message = "failed", firstNonEmpty(rec.Error, rec.Status)
}

// firewallCommandFinished records a firewall.apply result (from CommandFinished).
func (c *Core) firewallCommandFinished(ctx context.Context, host *store.Host, rec *store.CommandRecord) {
	c.firewall.mu.Lock()
	defer c.firewall.mu.Unlock()
	st := c.firewallState(ctx, host.ID)
	if st.CommandID != rec.ID {
		return
	}
	st.CommandID = ""
	applyFirewallResult(&st, rec)
	c.saveFirewallState(ctx, st)
}

// FirewallBlockView is a block with its scope's name.
type FirewallBlockView struct {
	*store.FirewallBlock
	Scope string `json:"scope"`
	// Problem says why the block is not sent anywhere, if it is not.
	Problem string `json:"problem,omitempty"`
}

// FirewallView is the console's Firewall page.
type FirewallView struct {
	Settings    FirewallSettings    `json:"settings"`
	Blocks      []FirewallBlockView `json:"blocks"`
	Hosts       []FirewallHost      `json:"hosts"`
	ServerAddrs []string            `json:"server_addrs"`
	Limits      struct {
		MaxBlocks   int `json:"max_blocks"`
		MinPrefixV4 int `json:"min_prefix_v4"`
		MinPrefixV6 int `json:"min_prefix_v6"`
	} `json:"limits"`
}

// FirewallStatus is the console's view.
func (c *Core) FirewallStatus(ctx context.Context) (FirewallView, error) {
	v := FirewallView{Settings: FirewallSettings{Enabled: c.FirewallGlobalEnabled()}, Blocks: []FirewallBlockView{}, Hosts: []FirewallHost{}, ServerAddrs: []string{}}
	v.Limits.MaxBlocks, v.Limits.MinPrefixV4, v.Limits.MinPrefixV6 = MaxFirewallBlocks, api.FirewallMinPrefixV4, api.FirewallMinPrefixV6
	protected := c.ServerAddrs(ctx)
	for _, a := range protected {
		v.ServerAddrs = append(v.ServerAddrs, a.String())
	}
	blocks, err := c.State.ListFirewallBlocks(ctx)
	if err != nil {
		return v, err
	}
	for _, b := range blocks {
		bv := FirewallBlockView{FirewallBlock: b, Scope: c.firewallScopeName(ctx, b.GroupID)}
		if b.GroupID != "" && len(c.groupChain(b.GroupID)) == 0 {
			bv.Problem = "its group was deleted, so it applies to no host"
		} else if p, err := hostfw.ParseCIDR(b.CIDR); err != nil {
			bv.Problem = err.Error()
		} else if err := hostfw.CheckProtected(p, protected); err != nil {
			bv.Problem = err.Error() + "; it is not sent to hosts"
		}
		v.Blocks = append(v.Blocks, bv)
	}
	hosts, err := c.firewallHosts(ctx)
	if err != nil {
		return v, err
	}
	for _, h := range hosts {
		st := c.firewallState(ctx, h.ID)
		eff := c.ResolveAV(h.GroupID).Firewall
		st.Hostname, st.Platform, st.Enabled, st.EnabledFrom = h.Hostname, h.OS.Platform, eff.Value, eff.GroupName
		if st.Status == "" {
			st.Status = "empty"
			if !eff.Value {
				st.Status = "off"
			}
		}
		v.Hosts = append(v.Hosts, st)
	}
	return v, nil
}
