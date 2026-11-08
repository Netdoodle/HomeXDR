//go:build windows

package windows

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

func TestParseDefenderStatus(t *testing.T) {
	out := []byte(`{"status":{"antivirus_enabled":true,"real_time_protection_enabled":true,"behavior_monitor_enabled":true,"tamper_protected":true,` +
		`"running_mode":"Normal","signature_version":"1.441.22.0","signature_updated":"2026-11-07T06:24:18Z","signature_age_days":0,"quick_scan_end":"","full_scan_end":""},` +
		`"threats":[{"threat_id":2147694217,"name":"Virus:Win32/MpTest!amsi","severity_id":5,"active":false,"resources":["amsi:_C:\\x.ps1"],"action_code":6},` +
		`{"threat_id":2147519003,"name":"Virus:DOS/EICAR_Test_File","severity_id":5,"active":true,"resources":[""],"action_code":null},` +
		`{"threat_id":2147694217,"name":"Virus:Win32/MpTest!amsi","severity_id":5,"active":false,"resources":["amsi:_C:\\y.ps1"],"action_code":6}]}`)
	res, err := parseDefenderStatus(out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == nil || !res.Status.TamperProtected || res.Status.SignatureVersion != "1.441.22.0" {
		t.Fatalf("status = %+v", res.Status)
	}
	if len(res.Threats) != 2 || res.Threats[0].Action != "Allow" || res.Threats[1].Action != "" || !res.Threats[1].Active ||
		len(res.Threats[0].Resources) != 2 || len(res.Threats[1].Resources) != 0 {
		t.Fatalf("threats = %+v", res.Threats)
	}
	if res.Message != "Defender is on and up to date; 2 threats in history, 1 active" {
		t.Errorf("message = %q", res.Message)
	}
	res, _ = parseDefenderStatus([]byte(`{"status":{"antivirus_enabled":true,"real_time_protection_enabled":false},"threats":[]}`))
	if !strings.HasPrefix(res.Message, "Defender real-time protection is OFF") {
		t.Errorf("off message = %q", res.Message)
	}
}

func TestVersionLess(t *testing.T) {
	if !versionLess("4.18.24090.11-0", "4.18.25090.3009-0") || versionLess("4.18.25090.3009-0", "4.18.9.0") {
		t.Error("versionLess ordering")
	}
}

func TestDefenderParamChecks(t *testing.T) {
	p := &Platform{}
	ctx := context.Background()
	for _, bad := range []api.DefenderParams{
		{Action: "nuke"},
		{Action: api.DefenderAllowThreat},
		{Action: api.DefenderBlockThreat, ThreatID: -1},
		{Action: api.DefenderScan, ScanType: "everything"},
		{Action: api.DefenderScan, ScanType: "path", Path: `relative\file.exe`},
		{Action: api.DefenderScan, ScanType: "path", Path: `C:\x" -DisableRemediation`},
	} {
		if _, err := p.Defender(ctx, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// TestDefenderStatusLive reads the real status where Defender is installed. Reading it
// works unelevated on most PCs; it is skipped when it does not.
func TestDefenderStatusLive(t *testing.T) {
	if _, err := mpCmdRunPath(); err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := (&Platform{}).Defender(ctx, api.DefenderParams{Action: api.DefenderStatus})
	if err != nil {
		t.Skip("status not readable here:", err)
	}
	if res.Status == nil || res.Status.SignatureVersion == "" {
		t.Fatalf("status = %+v", res)
	}
	t.Log(res.Message)
}
