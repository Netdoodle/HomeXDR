//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/fwrules"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Host firewall control (CmdFirewall): Windows Firewall block rules in their own group,
// "HomeXDR", made with the NetSecurity PowerShell module. fwrules renders the script
// from validated addresses only; it goes to PowerShell on stdin like every other script
// the agent runs. Windows keeps the rules across reboots; `uninstall` removes the group.

// ApplyFirewall implements platform.HostFirewall.
func (*Platform) ApplyFirewall(ctx context.Context, _ platform.Env, version string, s hostfw.Set) (string, string, error) {
	const backend = "windows-firewall"
	out, err := runPowerShell(ctx, fwrules.WindowsScript(s, version))
	if err != nil {
		return backend, "", fmt.Errorf("Windows Firewall: %w", err)
	}
	var r struct {
		Changed     bool     `json:"changed"`
		Rules       int      `json:"rules"`
		ProfilesOff []string `json:"profiles_off"`
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if err := json.Unmarshal(bytes.TrimSpace(lines[len(lines)-1]), &r); err != nil {
		return backend, "", fmt.Errorf("Windows Firewall: unexpected output: %s", trimOutput(string(out)))
	}
	want := len(fwrules.WindowsRules(s, version))
	if r.Rules != want {
		return backend, "", fmt.Errorf("Windows Firewall: the HomeXDR group holds %d rules, expected %d", r.Rules, want)
	}
	msg := "nothing to block: no HomeXDR rules in Windows Firewall"
	if !s.Empty() {
		msg = fmt.Sprintf("%d Windows Firewall rule(s) in group %s block %d address(es) or network(s)", r.Rules, fwrules.WindowsGroup, s.Len())
		if !r.Changed {
			msg += " (already in place)"
		}
	}
	if len(r.ProfilesOff) > 0 {
		msg += "; warning: Windows Firewall is off for the " + strings.Join(r.ProfilesOff, ", ") + " profile(s), where the rules do nothing"
	}
	return backend, msg, nil
}

// RemoveFirewall implements platform.HostFirewall.
func (*Platform) RemoveFirewall(ctx context.Context, _ platform.Env) error {
	if _, err := runPowerShell(ctx, fwrules.WindowsRemoveScript); err != nil {
		return fmt.Errorf("remove the HomeXDR Windows Firewall rules: %w", err)
	}
	return nil
}
