//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
)

// Defender drives Microsoft Defender Antivirus through its own local interfaces: the
// Defender PowerShell module (Get-MpComputerStatus, Get-MpThreat, Add-MpPreference,
// Remove-MpThreat) and MpCmdRun.exe. Each action is a fixed script; the only values from
// the command are a validated threat ID (a number) and, for a path scan, a file path
// passed as a separate process argument. Scripts go to PowerShell on stdin, so the
// command line stays plain ("-Command -").
func (*Platform) Defender(ctx context.Context, p api.DefenderParams) (api.DefenderResult, error) {
	switch p.Action {
	case api.DefenderStatus:
		return defenderStatus(ctx)
	case api.DefenderScan:
		return defenderScan(ctx, p)
	case api.DefenderUpdate:
		out, err := runMpCmdRun(ctx, "-SignatureUpdate")
		if err != nil {
			return api.DefenderResult{}, fmt.Errorf("signature update failed: %w", err)
		}
		return api.DefenderResult{Message: "signatures updated" + lastLine(out)}, nil
	case api.DefenderRemoveThreats:
		if _, err := runPowerShell(ctx, "$ErrorActionPreference='Stop'\nRemove-MpThreat\n"); err != nil {
			return api.DefenderResult{}, fmt.Errorf("remove threats: %w", err)
		}
		return api.DefenderResult{Message: "Defender cleaned all active threats"}, nil
	case api.DefenderAllowThreat:
		return defenderAllow(ctx, p.ThreatID)
	case api.DefenderBlockThreat:
		if p.ThreatID <= 0 {
			return api.DefenderResult{}, errors.New("threat_id is required")
		}
		script := fmt.Sprintf("$ErrorActionPreference='Stop'\nRemove-MpPreference -ThreatIDDefaultAction_Ids %d -ErrorAction SilentlyContinue\n"+
			"Add-MpPreference -ThreatIDDefaultAction_Ids %d -ThreatIDDefaultAction_Actions Quarantine\n", p.ThreatID, p.ThreatID)
		if _, err := runPowerShell(ctx, script); err != nil {
			return api.DefenderResult{}, fmt.Errorf("block threat %d: %w", p.ThreatID, err)
		}
		return api.DefenderResult{Message: fmt.Sprintf("threat %d is quarantined again when Defender finds it", p.ThreatID)}, nil
	}
	return api.DefenderResult{}, fmt.Errorf("unknown Defender action %q", p.Action)
}

const statusScript = `$ErrorActionPreference='Stop'
$s = Get-MpComputerStatus
$p = Get-MpPreference
$acts = @{}
if ($p.ThreatIDDefaultAction_Ids) {
  for ($i = 0; $i -lt $p.ThreatIDDefaultAction_Ids.Count; $i++) { $acts["$($p.ThreatIDDefaultAction_Ids[$i])"] = [int]$p.ThreatIDDefaultAction_Actions[$i] }
}
function T($d) { if ($d) { $d.ToUniversalTime().ToString('o') } else { '' } }
$threats = @(Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ threat_id = [int64]$_.ThreatID; name = "$($_.ThreatName)"; severity_id = [int]$_.SeverityID; active = [bool]$_.IsActive
    resources = @($_.Resources | ForEach-Object { "$_" }); action_code = $acts["$($_.ThreatID)"] }
})
[pscustomobject]@{
  status = [pscustomobject]@{
    antivirus_enabled = [bool]$s.AntivirusEnabled; real_time_protection_enabled = [bool]$s.RealTimeProtectionEnabled
    behavior_monitor_enabled = [bool]$s.BehaviorMonitorEnabled; tamper_protected = [bool]$s.IsTamperProtected
    running_mode = "$($s.AMRunningMode)"; signature_version = "$($s.AntivirusSignatureVersion)"
    signature_updated = (T $s.AntivirusSignatureLastUpdated); signature_age_days = [int]$s.AntivirusSignatureAge
    quick_scan_end = (T $s.QuickScanEndTime); full_scan_end = (T $s.FullScanEndTime)
  }
  threats = $threats
} | ConvertTo-Json -Depth 5 -Compress
`

// threatActions names ThreatIDDefaultAction values.
var threatActions = map[int]string{1: "Clean", 2: "Quarantine", 3: "Remove", 6: "Allow", 8: "UserDefined", 9: "NoAction", 10: "Block"}

func defenderStatus(ctx context.Context) (api.DefenderResult, error) {
	out, err := runPowerShell(ctx, statusScript)
	if err != nil {
		return api.DefenderResult{}, fmt.Errorf("read Defender status: %w", err)
	}
	return parseDefenderStatus(out)
}

func parseDefenderStatus(out []byte) (api.DefenderResult, error) {
	var raw struct {
		Status  api.DefenderStatusInfo `json:"status"`
		Threats []struct {
			api.DefenderThreatInfo
			ActionCode *int `json:"action_code"`
		} `json:"threats"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &raw); err != nil {
		return api.DefenderResult{}, fmt.Errorf("unexpected Defender status output: %w", err)
	}
	res := api.DefenderResult{Status: &raw.Status}
	// Get-MpThreat lists a threat once per detection: merge them by ID.
	byID := map[int64]int{}
	for _, t := range raw.Threats {
		info := t.DefenderThreatInfo
		if t.ActionCode != nil {
			info.Action = threatActions[*t.ActionCode]
		}
		var resources []string
		for _, r := range info.Resources {
			if strings.TrimSpace(r) != "" {
				resources = append(resources, r)
			}
		}
		info.Resources = resources
		if i, ok := byID[info.ThreatID]; ok {
			prev := &res.Threats[i]
			prev.Active = prev.Active || info.Active
			for _, r := range resources {
				if !slices.Contains(prev.Resources, r) {
					prev.Resources = append(prev.Resources, r)
				}
			}
			continue
		}
		byID[info.ThreatID] = len(res.Threats)
		res.Threats = append(res.Threats, info)
	}
	st := raw.Status
	switch {
	case !st.AntivirusEnabled || !st.RealTimeProtectionEnabled:
		res.Message = "Defender real-time protection is OFF"
	case st.SignatureAgeDays > 3:
		res.Message = fmt.Sprintf("Defender is on, but its signatures are %d days old", st.SignatureAgeDays)
	default:
		res.Message = "Defender is on and up to date"
	}
	active := 0
	for _, t := range res.Threats {
		if t.Active {
			active++
		}
	}
	res.Message += fmt.Sprintf("; %d threats in history, %d active", len(res.Threats), active)
	return res, nil
}

func defenderScan(ctx context.Context, p api.DefenderParams) (api.DefenderResult, error) {
	switch p.ScanType {
	case "quick", "full":
		// A full scan takes hours: start MpCmdRun and let it run on its own. Detections
		// arrive as Defender events (1116/1117) through the eventlog sensor.
		exe, err := mpCmdRunPath()
		if err != nil {
			return api.DefenderResult{}, err
		}
		typ := "1"
		if p.ScanType == "full" {
			typ = "2"
		}
		cmd := exec.Command(exe, "-Scan", "-ScanType", typ)
		if err := cmd.Start(); err != nil {
			return api.DefenderResult{}, fmt.Errorf("start %s scan: %w", p.ScanType, err)
		}
		_ = cmd.Process.Release()
		return api.DefenderResult{Message: p.ScanType + " scan started; detections show up as Defender alerts"}, nil
	case "path":
		if err := checkScanPath(p.Path); err != nil {
			return api.DefenderResult{}, err
		}
		out, err := runMpCmdRun(ctx, "-Scan", "-ScanType", "3", "-File", p.Path)
		found := false
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee) && ee.ExitCode() == 2:
			found = true
		default:
			return api.DefenderResult{}, fmt.Errorf("scan %s: %w", p.Path, err)
		}
		msg := "no threat found in " + p.Path
		if found {
			msg = "Defender found a threat in " + p.Path + " and handled it per its settings"
		}
		return api.DefenderResult{Message: msg + lastLine(out), Found: &found}, nil
	}
	return api.DefenderResult{}, fmt.Errorf("scan_type must be quick, full or path")
}

func checkScanPath(p string) error {
	if p == "" || !filepath.IsAbs(p) || strings.ContainsAny(p, "\"\r\n\x00") {
		return fmt.Errorf("path must be an absolute path: %q", p)
	}
	if _, err := os.Stat(p); err != nil {
		return err
	}
	return nil
}

func defenderAllow(ctx context.Context, id int64) (api.DefenderResult, error) {
	if id <= 0 {
		return api.DefenderResult{}, errors.New("threat_id is required")
	}
	script := fmt.Sprintf("$ErrorActionPreference='Stop'\nAdd-MpPreference -ThreatIDDefaultAction_Ids %d -ThreatIDDefaultAction_Actions Allow\n"+
		"$t = Get-MpThreat -ThreatID %d -ErrorAction SilentlyContinue | Select-Object -First 1\nif ($t) { \"$($t.ThreatName)\" }\n", id, id)
	out, err := runPowerShell(ctx, script)
	if err != nil {
		return api.DefenderResult{}, fmt.Errorf("allow threat %d: %w", id, err)
	}
	name := strings.TrimSpace(string(out))
	msg := fmt.Sprintf("threat %d is allowed on this host", id)
	if name == "" {
		return api.DefenderResult{Message: msg + "; Defender has no record of it, so nothing was restored"}, nil
	}
	if strings.ContainsAny(name, "\"\r\n\x00") {
		return api.DefenderResult{Message: msg + "; not restored (unexpected threat name)"}, nil
	}
	if rout, err := runMpCmdRun(ctx, "-Restore", "-Name", name, "-All"); err != nil {
		return api.DefenderResult{Message: fmt.Sprintf("%s (%s); restoring from quarantine failed: %v%s", msg, name, err, lastLine(rout))}, nil
	}
	return api.DefenderResult{Message: fmt.Sprintf("%s (%s) and restored from Defender's quarantine", msg, name)}, nil
}

// runPowerShell runs a script through Windows PowerShell, read from stdin.
func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-Command", "-")
	// With "-Command -" PowerShell reads stdin line by line and runs a multi-line
	// statement only after a blank line; one script block plus a blank line runs the
	// whole script, and a terminating error gives a non-zero exit code.
	cmd.Stdin = strings.NewReader("& {\n" + script + "\n}\n\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, trimOutput(stderr.String()))
	}
	return out, nil
}

func runMpCmdRun(ctx context.Context, args ...string) ([]byte, error) {
	exe, err := mpCmdRunPath()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, exe, args...).CombinedOutput()
}

// mpCmdRunPath prefers the newest Defender platform folder (updated outside Windows
// Update) over the copy in Program Files.
func mpCmdRunPath() (string, error) {
	var cands []string
	plat := filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows Defender\Platform`)
	if entries, err := os.ReadDir(plat); err == nil {
		var dirs []string
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, e.Name())
			}
		}
		sort.Slice(dirs, func(i, j int) bool { return versionLess(dirs[j], dirs[i]) })
		for _, d := range dirs {
			cands = append(cands, filepath.Join(plat, d, "MpCmdRun.exe"))
		}
	}
	cands = append(cands, filepath.Join(os.Getenv("ProgramFiles"), `Windows Defender\MpCmdRun.exe`))
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", errors.New("MpCmdRun.exe not found: is Microsoft Defender Antivirus installed?")
}

// versionLess compares dotted versions like 4.18.25090.3009-0 numerically.
func versionLess(a, b string) bool {
	pa := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' })
	pb := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' })
	for i := 0; i < len(pa) && i < len(pb); i++ {
		var x, y int
		fmt.Sscan(pa[i], &x)
		fmt.Sscan(pb[i], &y)
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if l := strings.TrimSpace(lines[len(lines)-1]); l != "" {
		return " (" + trimOutput(l) + ")"
	}
	return ""
}

func trimOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}
