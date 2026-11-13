package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Host firewall control (commands.FirewallApplier). The server sends the host's whole
// HomeXDR-owned block list; the agent checks it once more against its own idea of the
// server's addresses (defence in depth: a rule covering them would cut the agent off from
// the server that could remove it), applies it, and keeps it in FirewallStateFile so it
// is applied again after a restart (nftables and pf rules do not survive a reboot).

// FirewallStateFile in the data dir holds the last applied rule set.
const FirewallStateFile = "firewall.json"

var firewallMu sync.Mutex // serializes applies

type firewallState struct {
	Version string             `json:"version"`
	Rules   []api.FirewallRule `json:"rules"`
}

// ApplyFirewall implements commands.FirewallApplier.
func (a *Agent) ApplyFirewall(ctx context.Context, p api.FirewallParams) (api.FirewallResult, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	res := api.FirewallResult{Version: p.Version}
	fw, ok := a.plat.(platform.HostFirewall)
	if !ok {
		return res, fmt.Errorf("host firewall control is not supported on %s", a.plat.Name())
	}
	if err := hostfw.CheckVersion(p.Version); err != nil {
		return res, err
	}
	ips, _, err := a.serverAddrs(ctx, a.st.Snapshot().ServerIPs)
	if err != nil && len(p.Rules) > 0 {
		return res, fmt.Errorf("refusing to block addresses: %w", err)
	}
	set, err := hostfw.Normalize(p.Rules, ips)
	if err != nil {
		return res, fmt.Errorf("refusing the rule set: %w", err)
	}
	backend, msg, err := fw.ApplyFirewall(ctx, a.env, p.Version, set)
	res.Backend, res.Message = backend, msg
	if err != nil {
		return res, err
	}
	res.Rules = set.Len()
	a.saveFirewallState(firewallState{Version: p.Version, Rules: p.Rules})
	a.log.Info("host firewall rules applied", "version", p.Version, "addresses", res.Rules, "backend", backend)
	return res, nil
}

func (a *Agent) firewallStatePath() string { return filepath.Join(a.dataDir, FirewallStateFile) }

func (a *Agent) saveFirewallState(st firewallState) {
	path := a.firewallStatePath()
	if len(st.Rules) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("host firewall: cannot remove saved rules", "err", err)
		}
		return
	}
	b, _ := json.Marshal(st)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		a.log.Warn("host firewall: cannot save rules", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		a.log.Warn("host firewall: cannot save rules", "err", err)
	}
}

// reapplyFirewall applies the saved rule set again on start.
func (a *Agent) reapplyFirewall(ctx context.Context) {
	b, err := os.ReadFile(a.firewallStatePath())
	if err != nil {
		return
	}
	var st firewallState
	if err := json.Unmarshal(b, &st); err != nil || len(st.Rules) == 0 {
		return
	}
	if _, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: st.Version, Rules: st.Rules}); err != nil {
		a.log.Error("cannot re-apply host firewall rules", "version", st.Version, "err", err)
	}
}
