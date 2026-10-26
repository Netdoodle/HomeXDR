package core

// Agent lifecycle: decommissioning agents that have been offline too long, and the update
// policy that decides which signed release each agent is offered and when.
//
// Update policy, per agent:
//  1. The first label rule matching one of the agent's labels applies, else the default.
//  2. The rule picks a target: the newest archived release (latest), the one before it
//     (n-1), a specific version (pinned), or none (off).
//  3. Agents never downgrade (they refuse older releases), so an agent already running a
//     newer build than the target is left alone.
//  4. Unless an analyst clicked "Update now": outside the maintenance window nothing is
//     offered, and with a staged rollout, agents without the canary label wait until the
//     release has been out for the delay and no canary failed to install it.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // maintenance windows in any time zone, even without system tzdata

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

const lifecycleKey = "agent_lifecycle"

// Update policy modes.
const (
	UpdateLatest = "latest"
	UpdateN1     = "n-1"
	UpdatePinned = "pinned"
	UpdateOff    = "off"
)

// AgentLifecycle are the agent lifecycle settings.
type AgentLifecycle struct {
	// DecommissionAfterDays decommissions endpoint agents offline this long (0: never).
	DecommissionAfterDays int          `json:"decommission_after_days"`
	Updates               UpdatePolicy `json:"updates"`
}

// UpdatePolicy decides which release agents are offered, and when.
type UpdatePolicy struct {
	Default UpdateRule        `json:"default"`
	Labels  []LabelRule       `json:"labels"` // first match wins
	Staged  StagedRollout     `json:"staged"`
	Window  MaintenanceWindow `json:"window"`
}

// UpdateRule picks a target version.
type UpdateRule struct {
	Mode    string `json:"mode"`              // latest | n-1 | pinned | off
	Version string `json:"version,omitempty"` // pinned only
}

// LabelRule applies a rule to agents with a label.
type LabelRule struct {
	Label string     `json:"label"`
	Rule  UpdateRule `json:"rule"`
}

// StagedRollout updates canary agents first.
type StagedRollout struct {
	Enabled     bool   `json:"enabled"`
	CanaryLabel string `json:"canary_label"`
	DelayHours  int    `json:"delay_hours"`
}

// MaintenanceWindow limits when agents are offered updates.
type MaintenanceWindow struct {
	Enabled  bool   `json:"enabled"`
	Start    string `json:"start"`    // "HH:MM"
	End      string `json:"end"`      // "HH:MM"; earlier than Start wraps past midnight
	Timezone string `json:"timezone"` // IANA name, e.g. America/Chicago
}

// DefaultAgentLifecycle: no decommissioning, everyone on the latest release, no staging
// or window (how agents updated before policies existed).
func DefaultAgentLifecycle() AgentLifecycle {
	return AgentLifecycle{Updates: UpdatePolicy{
		Default: UpdateRule{Mode: UpdateLatest},
		Labels:  []LabelRule{},
		Staged:  StagedRollout{CanaryLabel: "canary", DelayHours: 24},
		Window:  MaintenanceWindow{Start: "02:00", End: "05:00", Timezone: "UTC"},
	}}
}

var clockRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func (r *UpdateRule) validate() error {
	r.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	r.Version = strings.TrimSpace(r.Version)
	switch r.Mode {
	case UpdateLatest, UpdateN1, UpdateOff:
		r.Version = ""
	case UpdatePinned:
		if !versionDirRe.MatchString(r.Version) {
			return errors.New("a pinned rule needs a release version")
		}
	default:
		return fmt.Errorf("update mode must be latest, n-1, pinned or off, not %q", r.Mode)
	}
	return nil
}

// Validate checks and normalizes the settings.
func (l *AgentLifecycle) Validate() error {
	if l.DecommissionAfterDays < 0 || l.DecommissionAfterDays > 3650 {
		return errors.New("decommission_after_days must be between 0 (off) and 3650")
	}
	u := &l.Updates
	if err := u.Default.validate(); err != nil {
		return fmt.Errorf("default rule: %w", err)
	}
	if u.Labels == nil {
		u.Labels = []LabelRule{}
	}
	seen := map[string]bool{}
	for i := range u.Labels {
		lr := &u.Labels[i]
		lr.Label = strings.TrimSpace(lr.Label)
		if lr.Label == "" || len(lr.Label) > 64 {
			return fmt.Errorf("label rule %d: a label is required (at most 64 characters)", i+1)
		}
		if seen[strings.ToLower(lr.Label)] {
			return fmt.Errorf("label %q has more than one rule", lr.Label)
		}
		seen[strings.ToLower(lr.Label)] = true
		if err := lr.Rule.validate(); err != nil {
			return fmt.Errorf("label %q: %w", lr.Label, err)
		}
	}
	u.Staged.CanaryLabel = strings.TrimSpace(u.Staged.CanaryLabel)
	if u.Staged.CanaryLabel == "" {
		u.Staged.CanaryLabel = "canary"
	}
	if u.Staged.DelayHours < 0 || u.Staged.DelayHours > 24*90 {
		return errors.New("staged rollout delay must be between 0 and 2160 hours")
	}
	w := &u.Window
	if w.Timezone == "" {
		w.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(w.Timezone); err != nil {
		return fmt.Errorf("unknown time zone %q", w.Timezone)
	}
	if !clockRe.MatchString(w.Start) || !clockRe.MatchString(w.End) {
		return errors.New("maintenance window times must look like 02:00")
	}
	if w.Enabled && w.Start == w.End {
		return errors.New("the maintenance window must not start and end at the same time")
	}
	return nil
}

// AgentLifecycle returns the stored settings (defaults when none are stored).
func (c *Core) AgentLifecycle(ctx context.Context) AgentLifecycle {
	l := DefaultAgentLifecycle()
	if err := c.State.GetKV(ctx, lifecycleKey, &l); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("read agent lifecycle settings", "err", err)
	}
	if l.Updates.Labels == nil {
		l.Updates.Labels = []LabelRule{}
	}
	return l
}

// SaveAgentLifecycle validates and stores the settings.
func (c *Core) SaveAgentLifecycle(ctx context.Context, l AgentLifecycle) (AgentLifecycle, error) {
	if err := l.Validate(); err != nil {
		return l, &ValidationError{Msg: err.Error()}
	}
	return l, c.State.SetKV(ctx, lifecycleKey, l)
}

// pinnedVersions are versions the policy pins; the archive keeps them.
func (c *Core) pinnedVersions() []string {
	l := c.AgentLifecycle(context.Background())
	var out []string
	if l.Updates.Default.Mode == UpdatePinned {
		out = append(out, l.Updates.Default.Version)
	}
	for _, lr := range l.Updates.Labels {
		if lr.Rule.Mode == UpdatePinned {
			out = append(out, lr.Rule.Version)
		}
	}
	return out
}

// decommissionInactive decommissions endpoint agents offline longer than the setting.
func (c *Core) decommissionInactive(ctx context.Context) {
	days := c.AgentLifecycle(ctx).DecommissionAfterDays
	if days <= 0 {
		return
	}
	hosts, err := c.State.DecommissionInactive(ctx, time.Now().AddDate(0, 0, -days))
	if err != nil {
		c.Log.Warn("decommission inactive agents", "err", err)
	}
	for _, h := range hosts {
		last := "never"
		if h.LastSeen != nil {
			last = h.LastSeen.UTC().Format(time.DateOnly)
		}
		c.Audit(ctx, "system", "agent.decommission", h.ID, fmt.Sprintf("%s: offline since %s (more than %d days)", h.Hostname, last, days))
		c.Log.Info("decommissioned inactive agent", "host", h.ID, "hostname", h.Hostname, "last_seen", last)
	}
}

// Update states shown for an agent.
const (
	UpdStateCurrent  = "current"  // running the target
	UpdStatePending  = "pending"  // waiting (window, staging)
	UpdStateUpdating = "updating" // offered, not installed yet
	UpdStateFailed   = "failed"   // the agent reported an error installing the target
	UpdStateAhead    = "ahead"    // running a newer build than the target (no downgrades)
	UpdStateOff      = "off"      // the policy turns updates off
	UpdStateNone     = "none"     // no release to offer (unsigned, not archived yet, N-1 missing)
)

// HostUpdate is an agent's update status.
type HostUpdate struct {
	Rule   UpdateRule `json:"rule"`
	Source string     `json:"source"` // "default" or the matching label
	Target string     `json:"target,omitempty"`
	State  string     `json:"state"`
	Reason string     `json:"reason,omitempty"`
	// offer is what to send the agent (nil: nothing).
	offer *api.AgentUpdate
}

// ruleFor returns the rule for an agent's labels and where it came from.
func (p UpdatePolicy) ruleFor(labels []string) (UpdateRule, string) {
	for _, lr := range p.Labels {
		for _, l := range labels {
			if strings.EqualFold(l, lr.Label) {
				return lr.Rule, lr.Label
			}
		}
	}
	return p.Default, "default"
}

// inWindow reports whether t falls in the window.
func (w MaintenanceWindow) inWindow(t time.Time) bool {
	if !w.Enabled {
		return true
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		loc = time.UTC
	}
	minutes := func(s string) int {
		h, _ := strconv.Atoi(s[:2])
		m, _ := strconv.Atoi(s[3:])
		return h*60 + m
	}
	lt := t.In(loc)
	now, start, end := lt.Hour()*60+lt.Minute(), minutes(w.Start), minutes(w.End)
	if start < end {
		return now >= start && now < end
	}
	return now >= start || now < end // wraps past midnight
}

var versionTimeRe = regexp.MustCompile(`-(\d{14})\.`)

// commitTimeOf finds a build's commit time: from the archive, or from its version string
// (0.0.0-YYYYMMDDHHMMSS.commit). 0 when unknown.
func commitTimeOf(version string, archive []ArchivedRelease) int64 {
	for _, a := range archive {
		if a.Version == version {
			return a.CommitTime
		}
	}
	if m := versionTimeRe.FindStringSubmatch(version); m != nil {
		if t, err := time.Parse("20060102150405", m[1]); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// UpdateStatus works out an agent's update target, state and the offer to make. hosts
// is the fleet (for canary health); it may be nil when staging is off.
func (c *Core) UpdateStatus(l AgentLifecycle, h *store.Host, archive []ArchivedRelease, hosts []*store.Host, now time.Time) HostUpdate {
	rule, source := l.Updates.ruleFor(h.Labels)
	hu := HostUpdate{Rule: rule, Source: source}
	updateNow := h.UpdateNowAt != nil
	if rule.Mode == UpdateOff && !updateNow {
		hu.State, hu.Reason = UpdStateOff, "updates are off for these agents"
		return hu
	}
	var target *ArchivedRelease
	switch {
	case len(archive) == 0:
		hu.State, hu.Reason = UpdStateNone, "no signed release is available"
		return hu
	case rule.Mode == UpdateLatest, rule.Mode == UpdateOff: // off with "update now": latest
		target = &archive[0]
	case rule.Mode == UpdateN1:
		if len(archive) < 2 {
			hu.State, hu.Reason = UpdStateNone, "only one release is archived; N-1 needs the release before it"
			return hu
		}
		target = &archive[1]
	case rule.Mode == UpdatePinned:
		for i := range archive {
			if archive[i].Version == rule.Version {
				target = &archive[i]
			}
		}
		if target == nil {
			hu.State, hu.Reason = UpdStateNone, "pinned version "+rule.Version+" is not in the release archive"
			return hu
		}
	}
	hu.Target = target.Version
	switch running := commitTimeOf(h.AgentVersion, archive); {
	case h.AgentVersion == target.Version:
		hu.State = UpdStateCurrent
		return hu
	case running > 0 && running >= target.CommitTime:
		hu.State, hu.Reason = UpdStateAhead, "the agent runs a newer build; agents do not downgrade"
		return hu
	}
	if !updateNow {
		if !l.Updates.Window.inWindow(now) {
			w := l.Updates.Window
			hu.State, hu.Reason = UpdStatePending, fmt.Sprintf("waiting for the maintenance window (%s-%s %s)", w.Start, w.End, w.Timezone)
			return hu
		}
		if s := l.Updates.Staged; s.Enabled && !hasLabel(h.Labels, s.CanaryLabel) {
			if why := canaryHold(s, *target, hosts, now); why != "" {
				hu.State, hu.Reason = UpdStatePending, why
				return hu
			}
		}
	}
	hu.offer = &api.AgentUpdate{Version: target.Version, CommitTime: target.CommitTime, Path: target.Path()}
	if h.UpdateError != "" && strings.HasPrefix(h.UpdateError, target.Version+":") {
		hu.State, hu.Reason = UpdStateFailed, h.UpdateError
		return hu
	}
	hu.State = UpdStateUpdating
	if updateNow {
		hu.Reason = "update requested now"
	}
	return hu
}

func hasLabel(labels []string, l string) bool {
	for _, x := range labels {
		if strings.EqualFold(x, l) {
			return true
		}
	}
	return false
}

// canaryHold explains why a non-canary agent must wait for target, or returns "".
func canaryHold(s StagedRollout, target ArchivedRelease, hosts []*store.Host, now time.Time) string {
	if wait := target.ArchivedAt.Add(time.Duration(s.DelayHours) * time.Hour).Sub(now); wait > 0 {
		return fmt.Sprintf("staged rollout: canary agents first; others in %s", wait.Round(time.Minute))
	}
	canaries, onTarget := 0, 0
	for _, h := range hosts {
		if h.Kind != store.HostEndpoint || h.Revoked || h.DecommissionedAt != nil || !hasLabel(h.Labels, s.CanaryLabel) {
			continue
		}
		canaries++
		if h.AgentVersion == target.Version {
			onTarget++
		}
		if strings.HasPrefix(h.UpdateError, target.Version+":") {
			return fmt.Sprintf("staged rollout: canary %s failed to install %s", h.Hostname, target.Version)
		}
	}
	if canaries > 0 && onTarget == 0 {
		return fmt.Sprintf("staged rollout: waiting for a %q agent to run %s", s.CanaryLabel, target.Version)
	}
	return ""
}

// UpdateOffer returns the release to offer an agent that just checked in, records the
// offer, and clears a fulfilled "update now" request.
func (c *Core) UpdateOffer(ctx context.Context, h *store.Host) *api.AgentUpdate {
	l := c.AgentLifecycle(ctx)
	archive := c.Release.Archive()
	var hosts []*store.Host
	if l.Updates.Staged.Enabled {
		hosts, _ = c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	}
	hu := c.UpdateStatus(l, h, archive, hosts, time.Now())
	if h.UpdateNowAt != nil && (hu.State == UpdStateCurrent || hu.State == UpdStateAhead) {
		_ = c.State.RequestUpdateNow(ctx, h.ID, time.Time{})
	}
	if hu.offer == nil {
		if len(archive) == 0 && c.Release.Offer() != nil {
			// The archive is off or failed: fall back to the bundled release, as before.
			rel := c.Release.Offer()
			if rel.Version != h.AgentVersion && l.Updates.Default.Mode != UpdateOff {
				return &api.AgentUpdate{Version: rel.Version, CommitTime: rel.CommitTime}
			}
		}
		return nil
	}
	if err := c.State.NoteUpdateOffer(ctx, h.ID, hu.offer.Version); err != nil {
		c.Log.Warn("record update offer", "host", h.ID, "err", err)
	}
	return hu.offer
}
