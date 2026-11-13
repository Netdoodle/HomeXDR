package core

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

// Defender hardening: each Windows host gets the hardening mode its group resolves to
// (off, audit, enforce). The agent carries the profile (a fixed list of ASR rules plus
// Network Protection and Controlled Folder Access); the server only sends the mode. A
// reconcile loop sends defender.harden when a host's applied version differs, like App
// Control. Off is only sent to hosts HomeXDR hardened before, and the agent then puts
// back the settings it found.

const (
	hardeningIssuer = "defender-hardening"
	hardeningKVPref = "defenderhardening.host."
	// hardeningRetry: a failed or refused command is tried again after this long.
	hardeningRetry = 30 * time.Minute
	// hardeningPartialRetry: settings Defender kept (Group Policy, MDM) rarely change on
	// their own; check again daily.
	hardeningPartialRetry = 24 * time.Hour
	hardeningPending      = time.Hour
)

// HardeningHost is the Defender hardening state of one Windows host.
type HardeningHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`                // what the host's group asks for
	ModeFrom string `json:"mode_from,omitempty"` // the group that sets it; "" for Global
	// Status: off, applied, partial (some settings did not take effect), pending, failed,
	// not_allowed, offline.
	Status      string                 `json:"status"`
	Desired     string                 `json:"desired,omitempty"`
	Applied     string                 `json:"applied,omitempty"`
	AppliedMode string                 `json:"applied_mode,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Failures    []string               `json:"failures,omitempty"`
	Settings    []api.HardeningSetting `json:"settings,omitempty"`
	CommandID   string                 `json:"command_id,omitempty"`
	AttemptAt   time.Time              `json:"attempt_at,omitzero"`
	UpdatedAt   time.Time              `json:"updated_at,omitzero"`
}

// HardeningView is the console's Defender hardening panel.
type HardeningView struct {
	Mode    string          `json:"mode"` // global
	Profile string          `json:"profile"`
	Hosts   []HardeningHost `json:"hosts"`
}

// hardeningVersion identifies a mode and the profile revision.
func hardeningVersion(mode string) string {
	if mode == api.HardeningOff {
		return "off"
	}
	return mode + "-p" + api.HardeningProfile
}

var hardenVersionRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)

// validateHarden checks defender.harden parameters: a mode and a version, nothing else.
func validateHarden(h *store.Host, params json.RawMessage) (api.DefenderHardenParams, error) {
	var p api.DefenderHardenParams
	if err := decodeStrict(params, &p); err != nil {
		return p, err
	}
	if h.OS.Platform != "windows" {
		return p, invalid("Defender hardening is only available on Windows hosts")
	}
	switch p.Mode {
	case api.HardeningOff, api.HardeningAudit, api.HardeningEnforce:
	default:
		return p, invalid("Defender hardening mode must be off, audit or enforce")
	}
	if !hardenVersionRe.MatchString(p.Version) {
		return p, invalid("invalid version %q", p.Version)
	}
	return p, nil
}

func (c *Core) hardeningState(ctx context.Context, hostID string) HardeningHost {
	var st HardeningHost
	if err := c.State.GetKV(ctx, hardeningKVPref+hostID, &st); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("defender hardening: read state", "host", hostID, "err", err)
	}
	st.HostID = hostID
	return st
}

func (c *Core) saveHardeningState(ctx context.Context, st HardeningHost) {
	st.UpdatedAt = time.Now().UTC()
	if err := c.State.SetKV(ctx, hardeningKVPref+st.HostID, st); err != nil {
		c.Log.Warn("defender hardening: save state", "host", st.HostID, "err", err)
	}
}

func (c *Core) runDefenderHardening(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		c.ReconcileDefenderHardening(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReconcileDefenderHardening brings every Windows host's Defender hardening in line with
// its group's mode.
func (c *Core) ReconcileDefenderHardening(ctx context.Context) {
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint, Platform: "windows"})
	if err != nil {
		c.Log.Warn("defender hardening: list hosts", "err", err)
		return
	}
	now := time.Now().UTC()
	for _, h := range hosts {
		eff := c.ResolveAV(h.GroupID).DefenderHardening
		st := c.hardeningState(ctx, h.ID)
		st.Hostname, st.Mode, st.ModeFrom = h.Hostname, eff.Value, eff.GroupName
		// Never hardened and nothing on its way: off needs no command.
		if eff.Value == api.HardeningOff && (st.AppliedMode == "" || st.AppliedMode == api.HardeningOff) && st.CommandID == "" {
			// A removal that left settings behind stays "partial" with its failures.
			if st.Desired != "off" || (st.Status != "off" && st.Status != "partial") {
				st.Status, st.Desired = "off", "off"
				if st.AppliedMode == "" {
					st.Message, st.Failures, st.Settings = "", nil, nil
				}
				c.saveHardeningState(ctx, st)
			}
			continue
		}
		st.Desired = hardeningVersion(eff.Value)
		if st.Applied == st.Desired && st.CommandID == "" {
			retryPartial := st.Status == "partial" && now.Sub(st.AttemptAt) >= hardeningPartialRetry && eff.Value != api.HardeningOff
			if !retryPartial {
				if st.Status != "applied" && st.Status != "partial" {
					st.Status = "applied"
					c.saveHardeningState(ctx, st)
				}
				continue
			}
		}
		if st.CommandID != "" {
			rec, err := c.State.GetCommand(ctx, st.CommandID)
			if err == nil && !store.FinalStatus(rec.Status) && now.Sub(rec.IssuedAt) < hardeningPending {
				continue // still on its way
			}
			if err == nil && store.FinalStatus(rec.Status) && rec.Status != api.StatusCompleted {
				st.Status, st.Message = "failed", firstNonEmpty(rec.Error, rec.Status)
			}
			st.CommandID = ""
		}
		if (st.Status == "failed" || st.Status == "not_allowed") && now.Sub(st.AttemptAt) < hardeningRetry {
			c.saveHardeningState(ctx, st)
			continue
		}
		if h.Status != "online" {
			st.Status, st.Message = "offline", "applies when the host is back online"
			c.saveHardeningState(ctx, st)
			continue
		}
		params, _ := json.Marshal(api.DefenderHardenParams{Mode: eff.Value, Version: st.Desired})
		st.AttemptAt = now
		rec, err := c.IssueCommand(ctx, h, api.CmdDefenderHarden, params, hardeningIssuer, "", hardeningPending)
		switch {
		case errors.Is(err, ErrNotAllowed):
			st.Status = "not_allowed"
			st.Message = "the host's local policy does not allow defender.harden: add it to allowed_actions in agent.json, or update the agent"
		case err != nil:
			st.Status, st.Message = "failed", err.Error()
		default:
			st.Status, st.CommandID, st.Message = "pending", rec.ID, ""
			c.Audit(ctx, hardeningIssuer, "defender.harden", h.ID, h.Hostname+": "+st.Desired)
		}
		c.saveHardeningState(ctx, st)
	}
}

// defenderHardeningFinished records a defender.harden result.
func (c *Core) defenderHardeningFinished(ctx context.Context, host *store.Host, rec *store.CommandRecord) {
	st := c.hardeningState(ctx, host.ID)
	if st.CommandID != rec.ID {
		return
	}
	st.CommandID = ""
	if rec.Status == api.StatusCompleted {
		var r api.DefenderHardenResult
		_ = json.Unmarshal(rec.Output, &r)
		st.Applied, st.AppliedMode, st.Message, st.Failures, st.Settings = r.Version, r.Mode, r.Message, r.Failures, r.Settings
		st.Status = "applied"
		if len(r.Failures) > 0 {
			st.Status = "partial"
		}
		if r.Mode == api.HardeningOff && len(r.Failures) == 0 {
			st.Status = "off"
		}
	} else {
		st.Status, st.Message = "failed", firstNonEmpty(rec.Error, rec.Status)
	}
	c.saveHardeningState(ctx, st)
}

// DefenderHardeningHostState returns one host's stored state.
func (c *Core) DefenderHardeningHostState(ctx context.Context, hostID string) HardeningHost {
	return c.hardeningState(ctx, hostID)
}

// DefenderHardeningStatus is the console's view.
func (c *Core) DefenderHardeningStatus(ctx context.Context) (HardeningView, error) {
	v := HardeningView{Mode: c.AV.Settings().DefenderHardening, Profile: api.HardeningProfile, Hosts: []HardeningHost{}}
	if strings.TrimSpace(v.Mode) == "" {
		v.Mode = api.HardeningOff
	}
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint, Platform: "windows"})
	if err != nil {
		return v, err
	}
	for _, h := range hosts {
		st := c.hardeningState(ctx, h.ID)
		eff := c.ResolveAV(h.GroupID).DefenderHardening
		st.Hostname, st.Mode, st.ModeFrom = h.Hostname, eff.Value, eff.GroupName
		if st.Status == "" {
			st.Status = "off"
		}
		v.Hosts = append(v.Hosts, st)
	}
	return v, nil
}
