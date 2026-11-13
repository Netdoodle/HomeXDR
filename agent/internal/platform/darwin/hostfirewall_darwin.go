//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/fwrules"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Host firewall control (CmdFirewall): tables and block rules in their own pf anchor,
// com.apple/001.HomeXDR-block, beside isolation's anchor. pf is enabled with a reference
// token of its own (pf-block.token), so removing the blocks never turns off pf that
// isolation or another program needs. pf rules do not survive a reboot; the agent
// applies the last rule set again when it starts.

func blockTokenPath(env platform.Env) string { return filepath.Join(env.DataDir, "pf-block.token") }

// ApplyFirewall implements platform.HostFirewall.
func (*Platform) ApplyFirewall(ctx context.Context, env platform.Env, _ string, s hostfw.Set) (string, string, error) {
	const backend = "pf"
	if s.Empty() {
		if err := removePfBlock(ctx, env); err != nil {
			return backend, "", err
		}
		return backend, "nothing to block: pf anchor " + fwrules.PfAnchor + " flushed", nil
	}
	if _, err := runPfctl(ctx, []byte(fwrules.PfRules(s)), "-a", fwrules.PfAnchor, "-f", "-"); err != nil {
		return backend, "", err
	}
	main, err := runPfctl(ctx, nil, "-s", "rules")
	if err == nil && !pfMainHasAppleAnchor(main) {
		// pf was never configured since boot: load the stock ruleset, which has it.
		if _, err := runPfctl(ctx, nil, "-f", "/etc/pf.conf"); err != nil {
			return backend, "", err
		}
		main, err = runPfctl(ctx, nil, "-s", "rules")
	}
	if err != nil {
		return backend, "", err
	}
	if !pfMainHasAppleAnchor(main) {
		_, _ = runPfctl(ctx, nil, "-a", fwrules.PfAnchor, "-F", "all")
		return backend, "", errors.New(`the pf main ruleset has no anchor "com.apple/*" (custom /etc/pf.conf?), so block rules would not apply; nothing was changed`)
	}
	// Take a reference unless we hold one and pf is on (a reboot turns pf off and voids
	// the saved token).
	info, _ := runPfctl(ctx, nil, "-s", "info")
	enabled := bytes.Contains(info, []byte("Status: Enabled"))
	if b, err := os.ReadFile(blockTokenPath(env)); !enabled || err != nil || len(bytes.TrimSpace(b)) == 0 {
		out, err := runPfctl(ctx, nil, "-E")
		if err != nil {
			return backend, "", err
		}
		if tok := pfToken(out); tok != "" {
			if err := os.WriteFile(blockTokenPath(env), []byte(tok+"\n"), 0o600); err != nil && env.Log != nil {
				env.Log.Warn("host firewall: cannot save the pf token", "err", err)
			}
		}
	}
	return backend, fmt.Sprintf("pf anchor %s blocks %d address(es) or network(s); connections already open continue until they close", fwrules.PfAnchor, s.Len()), nil
}

// RemoveFirewall implements platform.HostFirewall.
func (*Platform) RemoveFirewall(ctx context.Context, env platform.Env) error {
	return removePfBlock(ctx, env)
}

func removePfBlock(ctx context.Context, env platform.Env) error {
	var errs []error
	if _, err := runPfctl(ctx, nil, "-a", fwrules.PfAnchor, "-F", "all"); err != nil {
		errs = append(errs, err)
	}
	if b, err := os.ReadFile(blockTokenPath(env)); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			// After a reboot the token is stale; pfctl then fails harmlessly.
			_, _ = runPfctl(ctx, nil, "-X", tok)
		}
		_ = os.Remove(blockTokenPath(env))
	}
	return errors.Join(errs...)
}
