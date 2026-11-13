//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/Netdoodle/homexdr/agent/internal/hardening"
	"github.com/Netdoodle/homexdr/shared/api"
)

// TestDefenderHardeningLive runs audit, enforce and off against the real Defender and
// checks that off puts the preferences back. Needs an elevated prompt and
// HOMEXDR_LIVE_HARDENING=1; only run it on a test machine.
func TestDefenderHardeningLive(t *testing.T) {
	if os.Getenv("HOMEXDR_LIVE_HARDENING") != "1" {
		t.Skip("set HOMEXDR_LIVE_HARDENING=1 on a test machine")
	}
	ctx := context.Background()
	prefs := func() string {
		out, err := runPowerShell(ctx, `Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,EnableNetworkProtection,EnableControlledFolderAccess | ConvertTo-Json -Compress`)
		if err != nil {
			t.Fatalf("Get-MpPreference: %v: %s", err, out)
		}
		return string(out)
	}
	before := prefs()
	t.Logf("before: %s", before)
	dir := t.TempDir()
	for _, mode := range []string{api.HardeningAudit, api.HardeningEnforce, api.HardeningOff} {
		res, err := hardening.Apply(ctx, api.DefenderHardenParams{Mode: mode, Version: mode + "-p" + api.HardeningProfile}, dir, runPowerShell)
		b, _ := json.MarshalIndent(res, "", "  ")
		t.Logf("%s: err=%v\n%s", mode, err, b)
		if err != nil {
			t.Errorf("%s: %v", mode, err)
		}
		t.Logf("after %s: %s", mode, prefs())
	}
	if after := prefs(); after != before {
		t.Errorf("off did not restore the preferences:\nbefore %s\nafter  %s", before, after)
	}
}
