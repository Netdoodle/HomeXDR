//go:build windows

package windows

import (
	"context"

	"github.com/Netdoodle/homexdr/agent/internal/hardening"
	"github.com/Netdoodle/homexdr/shared/api"
)

// DefenderHarden applies HomeXDR's Defender hardening profile (ASR rules, Network
// Protection, Controlled Folder Access) through Defender's PowerShell module. The rule
// list is built in; what it replaced is kept in the data directory so "off" puts it back.
func (p *Platform) DefenderHarden(ctx context.Context, prm api.DefenderHardenParams) (api.DefenderHardenResult, error) {
	return hardening.Apply(ctx, prm, p.Paths().DataDir, runPowerShell)
}
