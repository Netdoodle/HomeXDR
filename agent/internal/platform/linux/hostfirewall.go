//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/fwrules"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Host firewall control (CmdFirewall): its own nftables table, inet homexdr_block, next to
// (and independent of) the isolation table inet homexdr. The table is replaced in one
// atomic nft transaction. Like isolation it lives only in the kernel; the agent applies
// the last rule set again when it starts. There is no iptables fallback: without nft the
// command fails and says so.

const nftMissing = "host firewall blocking needs nftables, and the nft command is not installed (iptables alone is not supported)"

// ApplyFirewall implements platform.HostFirewall.
func (*Platform) ApplyFirewall(ctx context.Context, _ platform.Env, _ string, s hostfw.Set) (string, string, error) {
	bin, err := exec.LookPath("nft")
	if err != nil {
		if s.Empty() {
			return "nftables", "nothing to block", nil
		}
		return "nftables", "", errors.New(nftMissing)
	}
	cmd := exec.CommandContext(ctx, bin, "-f", "-")
	cmd.Stdin = strings.NewReader(fwrules.NftRuleset(s))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "nftables", "", fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if s.Empty() {
		return "nftables", "nothing to block: table inet " + fwrules.NftTable + " removed", nil
	}
	return "nftables", fmt.Sprintf("table inet %s blocks %d address(es) or network(s)", fwrules.NftTable, s.Len()), nil
}

// RemoveFirewall implements platform.HostFirewall.
func (*Platform) RemoveFirewall(ctx context.Context, _ platform.Env) error {
	bin, err := exec.LookPath("nft")
	if err != nil {
		return nil
	}
	if exec.CommandContext(ctx, bin, "list", "table", "inet", fwrules.NftTable).Run() != nil {
		return nil
	}
	if out, err := exec.CommandContext(ctx, bin, "delete", "table", "inet", fwrules.NftTable).CombinedOutput(); err != nil {
		return fmt.Errorf("nft delete table inet %s: %v: %s", fwrules.NftTable, err, strings.TrimSpace(string(out)))
	}
	return nil
}
