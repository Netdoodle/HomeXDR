package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/av"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

// Windows App Control: confirmed malware becomes a deny policy on Windows hosts, so
// Windows refuses to start those files. Each Windows host gets the mode its group
// resolves to (off, audit, enforce). The block list is every malicious verdict with
// Authenticode hashes (taken from files the server scanned, or reported by the agent when
// it quarantined one), except hacking tools and suspicious traits and allowlisted hashes.
// A reconcile loop sends appcontrol.apply when a host's applied version differs.

const (
	appControlIssuer  = "appcontrol"
	appControlKVPref  = "appcontrol.host."
	appControlRetry   = 30 * time.Minute
	appControlPending = time.Hour
)

// AppControlHost is the App Control state of one Windows host.
type AppControlHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`                // what the host's group asks for
	ModeFrom string `json:"mode_from,omitempty"` // the group that sets it; "" for Global
	// Status: off, applied, pending, failed, not_allowed, offline.
	Status      string    `json:"status"`
	Desired     string    `json:"desired,omitempty"`
	Applied     string    `json:"applied,omitempty"`
	AppliedMode string    `json:"applied_mode,omitempty"`
	Rules       int       `json:"rules"`
	Message     string    `json:"message,omitempty"`
	CommandID   string    `json:"command_id,omitempty"`
	AttemptAt   time.Time `json:"attempt_at,omitzero"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
}

// AppControlRuleView is one blocked file.
type AppControlRuleView struct {
	SHA256     string    `json:"sha256"`
	AuthSHA256 string    `json:"auth_sha256"`
	Name       string    `json:"name"`
	Signature  string    `json:"signature,omitempty"`
	Source     string    `json:"source"`
	Path       string    `json:"path,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

// AppControlView is the console's App Control page.
type AppControlView struct {
	Mode  string               `json:"mode"` // global
	Rules []AppControlRuleView `json:"rules"`
	Hosts []AppControlHost     `json:"hosts"`
}

// appControlRules returns the block list.
func (c *Core) appControlRules(ctx context.Context) ([]api.AppControlRule, []AppControlRuleView, error) {
	vs, err := c.State.AVBlockList(ctx, []string{av.SourceYaraTool, av.SourceYaraSuspicious}, api.AppControlMaxRules)
	if err != nil {
		return nil, nil, err
	}
	allowed := map[string]bool{}
	for _, h := range c.AV.Settings().AllowedHashes {
		allowed[h] = true
	}
	rules := []api.AppControlRule{}
	views := []AppControlRuleView{}
	for _, v := range vs {
		if allowed[v.SHA256] {
			continue
		}
		name := path.Base(strings.ReplaceAll(v.Path, `\`, "/"))
		if name == "." || name == "/" {
			name = v.SHA256[:12]
		}
		label := name
		if v.Signature != "" {
			label += " (" + v.Signature + ")"
		}
		if len(label) > 120 {
			label = label[:120]
		}
		rules = append(rules, api.AppControlRule{Name: label, SHA256: v.AuthSHA256, SHA1: v.AuthSHA1})
		views = append(views, AppControlRuleView{SHA256: v.SHA256, AuthSHA256: v.AuthSHA256, Name: name, Signature: v.Signature,
			Source: v.Source, Path: v.Path, CheckedAt: v.CheckedAt})
	}
	return rules, views, nil
}

// appControlVersion identifies a mode and rule set.
func appControlVersion(mode string, rules []api.AppControlRule) string {
	if mode == api.AppControlOff {
		return "off"
	}
	h := sha256.New()
	h.Write([]byte(mode))
	for _, r := range rules {
		h.Write([]byte("|" + r.SHA256 + r.SHA1))
	}
	return mode + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func (c *Core) appControlState(ctx context.Context, hostID string) AppControlHost {
	var st AppControlHost
	if err := c.State.GetKV(ctx, appControlKVPref+hostID, &st); err != nil && !errors.Is(err, store.ErrNotFound) {
		c.Log.Warn("app control: read state", "host", hostID, "err", err)
	}
	st.HostID = hostID
	return st
}

func (c *Core) saveAppControlState(ctx context.Context, st AppControlHost) {
	st.UpdatedAt = time.Now().UTC()
	if err := c.State.SetKV(ctx, appControlKVPref+st.HostID, st); err != nil {
		c.Log.Warn("app control: save state", "host", st.HostID, "err", err)
	}
}

func (c *Core) runAppControl(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		c.ReconcileAppControl(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReconcileAppControl brings every Windows host's policy in line with its group's mode.
func (c *Core) ReconcileAppControl(ctx context.Context) {
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint, Platform: "windows"})
	if err != nil {
		c.Log.Warn("app control: list hosts", "err", err)
		return
	}
	var rules []api.AppControlRule
	rulesLoaded := false
	now := time.Now().UTC()
	for _, h := range hosts {
		eff := c.ResolveAV(h.GroupID).AppControl
		st := c.appControlState(ctx, h.ID)
		st.Hostname, st.Mode, st.ModeFrom = h.Hostname, eff.Value, eff.GroupName
		if eff.Value == api.AppControlOff && (st.AppliedMode == "" || st.AppliedMode == api.AppControlOff) && st.CommandID == "" {
			if st.Status != "off" || st.Desired != "off" {
				st.Status, st.Desired, st.Message = "off", "off", ""
				c.saveAppControlState(ctx, st)
			}
			continue
		}
		if !rulesLoaded {
			if rules, _, err = c.appControlRules(ctx); err != nil {
				c.Log.Warn("app control: block list", "err", err)
				return
			}
			rulesLoaded = true
		}
		hostRules := rules
		if eff.Value == api.AppControlOff {
			hostRules = nil
		}
		st.Desired = appControlVersion(eff.Value, hostRules)
		if st.Applied == st.Desired && st.CommandID == "" {
			if st.Status != "applied" {
				st.Status = "applied"
				c.saveAppControlState(ctx, st)
			}
			continue
		}
		if st.CommandID != "" {
			rec, err := c.State.GetCommand(ctx, st.CommandID)
			if err == nil && !store.FinalStatus(rec.Status) && now.Sub(rec.IssuedAt) < appControlPending {
				continue // still on its way
			}
			if err == nil && store.FinalStatus(rec.Status) && rec.Status != api.StatusCompleted {
				st.Status, st.Message = "failed", firstNonEmpty(rec.Error, rec.Status)
			}
			st.CommandID = ""
		}
		if (st.Status == "failed" || st.Status == "not_allowed") && now.Sub(st.AttemptAt) < appControlRetry {
			c.saveAppControlState(ctx, st)
			continue
		}
		if h.Status != "online" {
			st.Status, st.Message = "offline", "applies when the host is back online"
			c.saveAppControlState(ctx, st)
			continue
		}
		params, _ := json.Marshal(api.AppControlParams{Mode: eff.Value, Version: st.Desired, Rules: hostRules})
		st.AttemptAt = now
		rec, err := c.IssueCommand(ctx, h, api.CmdAppControl, params, appControlIssuer, "", appControlPending)
		switch {
		case errors.Is(err, ErrNotAllowed):
			st.Status = "not_allowed"
			st.Message = "the host's local policy does not allow appcontrol.apply: add it to allowed_actions in agent.json, or update the agent"
		case err != nil:
			st.Status, st.Message = "failed", err.Error()
		default:
			st.Status, st.CommandID, st.Message = "pending", rec.ID, ""
			c.Audit(ctx, appControlIssuer, "appcontrol.apply", h.ID, h.Hostname+": "+st.Desired)
		}
		c.saveAppControlState(ctx, st)
	}
}

// CommandFinished takes what finished commands tell the server: App Control results, and
// the Authenticode hashes of files the agent quarantined.
func (c *Core) CommandFinished(ctx context.Context, host *store.Host, rec *store.CommandRecord) {
	switch rec.Type {
	case api.CmdAppControl:
		st := c.appControlState(ctx, host.ID)
		if st.CommandID != rec.ID {
			return
		}
		st.CommandID = ""
		if rec.Status == api.StatusCompleted {
			var r api.AppControlResult
			_ = json.Unmarshal(rec.Output, &r)
			st.Applied, st.AppliedMode, st.Rules, st.Message, st.Status = r.Version, r.Mode, r.Rules, r.Message, "applied"
		} else {
			st.Status, st.Message = "failed", firstNonEmpty(rec.Error, rec.Status)
		}
		c.saveAppControlState(ctx, st)
	case api.CmdFileQuarantine:
		if rec.Status != api.StatusCompleted {
			return
		}
		var r api.QuarantineResult
		if json.Unmarshal(rec.Output, &r) != nil || r.AuthSHA256 == "" || r.SHA256 == "" {
			return
		}
		blocked := false
		for _, h := range c.AV.Settings().BlockedHashes {
			blocked = blocked || h == r.SHA256
		}
		// Only files the antivirus judged (or the blocklist names) join the block list;
		// a file someone quarantined by hand only gets its hashes recorded if it has a
		// verdict already.
		if _, err := c.State.GetAVVerdict(ctx, r.SHA256); err != nil && !blocked {
			return
		}
		if err := c.State.SetAVAuthHashes(ctx, r.SHA256, r.AuthSHA256, r.AuthSHA1, "blocklist", "Blocked hash", r.OriginalPath, host.ID); err != nil {
			c.Log.Warn("app control: record Authenticode hashes", "err", err)
		}
	}
}

// AppControlHostState returns one host's stored state.
func (c *Core) AppControlHostState(ctx context.Context, hostID string) AppControlHost {
	return c.appControlState(ctx, hostID)
}

// AppControlStatus is the console's view.
func (c *Core) AppControlStatus(ctx context.Context) (AppControlView, error) {
	v := AppControlView{Mode: c.AV.Settings().AppControl, Hosts: []AppControlHost{}}
	var err error
	if _, v.Rules, err = c.appControlRules(ctx); err != nil {
		return v, err
	}
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint, Platform: "windows"})
	if err != nil {
		return v, err
	}
	for _, h := range hosts {
		st := c.appControlState(ctx, h.ID)
		eff := c.ResolveAV(h.GroupID).AppControl
		st.Hostname, st.Mode, st.ModeFrom = h.Hostname, eff.Value, eff.GroupName
		if st.Status == "" {
			st.Status = "off"
		}
		v.Hosts = append(v.Hosts, st)
	}
	return v, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
