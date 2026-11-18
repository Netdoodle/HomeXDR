//go:build windows

package windows

import (
	"context"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

// fakeSysmonHost simulates Sysmon and the Windows feature: commands change the install
// the way the real ones do.
type fakeSysmonHost struct {
	inst          *sysmonInstall
	feat          featureState
	enableRestart bool
	schemaV       string
	noBinary      bool
	failSysmon    map[string]error // by the command's first argument (-i, -c, -u)
	calls         []string
}

const fakeBin = `C:\Windows\System32\sysmon.exe`

func (f *fakeSysmonHost) probe() (*sysmonInstall, error) {
	if f.inst == nil {
		return nil, nil
	}
	c := *f.inst
	return &c, nil
}

func (f *fakeSysmonHost) feature(context.Context) (featureState, error) {
	f.calls = append(f.calls, "dism get")
	return f.feat, nil
}

func (f *fakeSysmonHost) setFeature(_ context.Context, on bool) (bool, error) {
	if on {
		f.calls = append(f.calls, "dism enable")
		f.feat = featureEnabled
		if f.enableRestart {
			f.feat = featurePending
		}
		return f.enableRestart, nil
	}
	f.calls = append(f.calls, "dism disable")
	f.feat = featureDisabled
	return false, nil
}

func (f *fakeSysmonHost) systemBinary() string { return fakeBin }
func (f *fakeSysmonHost) exists(string) bool   { return !f.noBinary }

func (f *fakeSysmonHost) schema(context.Context, string) (string, error) {
	f.calls = append(f.calls, "sysmon -s")
	return f.schemaV, nil
}

func (f *fakeSysmonHost) sysmon(_ context.Context, bin string, args ...string) error {
	f.calls = append(f.calls, "sysmon "+strings.Join(args, " "))
	if err := f.failSysmon[args[0]]; err != nil {
		return err
	}
	applied := func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		f.inst.ConfigHash, f.inst.ConfigFile, f.inst.HasRules = sysmonConfigHash("SHA256", b), path, true
	}
	switch args[0] {
	case "-i":
		f.inst = &sysmonInstall{Service: "Sysmon", Driver: "SysmonDrv", ImagePath: bin, Binary: bin}
		applied(args[1])
	case "-c":
		if args[1] == "--" {
			f.inst.ConfigHash, f.inst.ConfigFile, f.inst.HasRules = "", `C:\Windows\System32\Defaults`, false
		} else {
			applied(args[1])
		}
	case "-u":
		f.inst = nil
	}
	return nil
}

func resetSysmonGlobals(t *testing.T) {
	sysmonRestartPending.Store(false)
	sysmonFeatureMissing.Store(false)
	t.Cleanup(func() {
		sysmonRestartPending.Store(false)
		sysmonFeatureMissing.Store(false)
	})
}

func newTestSysmon(t *testing.T, h *fakeSysmonHost) *sysmonManager {
	t.Helper()
	resetSysmonGlobals(t)
	dir := t.TempDir()
	if h.schemaV == "" {
		h.schemaV = "4.91"
	}
	return &sysmonManager{
		host: h, configPath: filepath.Join(dir, "data", sysmonConfigName), backupPath: filepath.Join(dir, sysmonBackupName),
		agentExe: `C:\Program Files\HomeXDR\homexdr-agent.exe`, windir: `C:\WINDOWS`,
		programData: `C:\ProgramData`, programFiles: `C:\Program Files`,
		writeFile: func(p string, b []byte) error {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return err
			}
			return os.WriteFile(p, b, 0o600)
		},
	}
}

func (m *sysmonManager) testBackup(t *testing.T) *sysmonBackup {
	t.Helper()
	bk, err := m.loadBackup()
	if err != nil {
		t.Fatal(err)
	}
	return bk
}

func wantResult(t *testing.T, r sysmonResult, state, contains string) {
	t.Helper()
	text := r.msg + r.err
	if r.state != state || !strings.Contains(text, contains) {
		t.Fatalf("result = %+v, want state %s containing %q", r, state, contains)
	}
}

func wantCalls(t *testing.T, h *fakeSysmonHost, want ...string) {
	t.Helper()
	if !slices.Equal(h.calls, want) {
		t.Fatalf("calls = %q, want %q", h.calls, want)
	}
	h.calls = nil
}

func TestSysmonNotAvailable(t *testing.T) {
	h := &fakeSysmonHost{feat: featureMissing}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	wantResult(t, m.ensure(ctx), api.SensorRunning, sysmonNotAvailable)
	wantCalls(t, h, "dism get")
	// Remembered: DISM is not asked again.
	wantResult(t, m.ensure(ctx), api.SensorRunning, sysmonNotAvailable)
	wantCalls(t, h)
	if m.testBackup(t) != nil {
		t.Fatal("a backup was written although nothing changed")
	}
	r, did := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "has not changed Sysmon")
	if did != nil {
		t.Errorf("did = %q", did)
	}
}

func TestSysmonFeatureInstallAndUndo(t *testing.T) {
	h := &fakeSysmonHost{feat: featureDisabled}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	wantResult(t, m.ensure(ctx), api.SensorRunning, "installed and configured by HomeXDR")
	wantCalls(t, h, "dism get", "dism enable", "sysmon -s", "sysmon -i "+m.configPath)
	bk := m.testBackup(t)
	if bk == nil || bk.FeatureWasEnabled == nil || *bk.FeatureWasEnabled || bk.ServiceWasInstalled || bk.RulesBefore != rulesNone ||
		!bk.EnabledFeature || !bk.InstalledService || !bk.AppliedConfig || bk.ConfigHash != h.inst.ConfigHash || bk.ConfigPath != m.configPath {
		t.Fatalf("backup = %+v", bk)
	}
	// Nothing changed: only the registry is read (the schema is cached).
	wantResult(t, m.ensure(ctx), api.SensorRunning, "installed and configured by HomeXDR")
	wantCalls(t, h)

	r, did := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "uninstalled the Sysmon it had installed and turned the Windows Sysmon feature off")
	wantCalls(t, h, "sysmon -u", "dism disable")
	if len(did) != 2 || h.inst != nil || h.feat != featureDisabled || m.testBackup(t) != nil {
		t.Fatalf("after undo: did %q, install %+v, feature %d", did, h.inst, h.feat)
	}
	// Undone once: a later check has nothing to do.
	wantResult(t, func() sysmonResult { r, _ := m.undo(ctx); return r }(), api.SensorDisabled, "has not changed Sysmon")
	wantCalls(t, h)
}

func TestSysmonFeatureNeedsRestart(t *testing.T) {
	h := &fakeSysmonHost{feat: featureDisabled, enableRestart: true}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	wantResult(t, m.ensure(ctx), api.SensorDegraded, sysmonRestart)
	wantCalls(t, h, "dism get", "dism enable")
	wantResult(t, m.ensure(ctx), api.SensorDegraded, sysmonRestart)
	wantCalls(t, h) // waits for the restart without asking DISM again
	if bk := m.testBackup(t); bk == nil || !bk.EnabledFeature || bk.InstalledService {
		t.Fatalf("backup = %+v", bk)
	}
	// Turned off before the restart: the feature goes off again.
	r, _ := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "turned the Windows Sysmon feature off")
	wantCalls(t, h, "dism disable")
	if sysmonRestartPending.Load() {
		t.Error("restart still pending after the feature was turned off")
	}
}

// After a restart (a new agent process) the pending state shows in DISM's answer.
func TestSysmonFeaturePendingAfterRestart(t *testing.T) {
	h := &fakeSysmonHost{feat: featurePending}
	m := newTestSysmon(t, h)
	wantResult(t, m.ensure(context.Background()), api.SensorDegraded, sysmonRestart)
	wantCalls(t, h, "dism get")
}

func TestSysmonNoRulesConfiguredAndReset(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon", Driver: "SysmonDrv", ImagePath: fakeBin, Binary: fakeBin,
		ConfigFile: `C:\Users\admin\sysmon.exe -accepteula -i`}}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	wantResult(t, m.ensure(ctx), api.SensorRunning, "Sysmon configured by HomeXDR (events 1, 5, 8, 10 and 25)")
	wantCalls(t, h, "sysmon -s", "sysmon -c "+m.configPath)
	bk := m.testBackup(t)
	if bk == nil || bk.FeatureWasEnabled != nil || !bk.ServiceWasInstalled || bk.RulesBefore != rulesNone || bk.InstalledService || !bk.AppliedConfig {
		t.Fatalf("backup = %+v", bk)
	}
	wantResult(t, m.ensure(ctx), api.SensorRunning, "configured by HomeXDR")
	wantCalls(t, h)

	r, did := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "reset Sysmon to its default configuration")
	wantCalls(t, h, "sysmon -c --")
	if len(did) != 1 || h.inst == nil || h.inst.HasRules || m.testBackup(t) != nil {
		t.Fatalf("after undo: did %q install %+v", did, h.inst)
	}
}

func TestSysmonForeignRulesLeftAlone(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon64", Driver: "SysmonDrv", ImagePath: `C:\Windows\Sysmon64.exe`, Binary: `C:\Windows\Sysmon64.exe`,
		ConfigHash: "SHA256=0123ABCD", ConfigFile: `C:\Tools\sysmonconfig-export.xml`, HasRules: true}}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	r := m.ensure(ctx)
	wantResult(t, r, api.SensorRunning, "HomeXDR did not write, so HomeXDR left it unchanged")
	if !strings.Contains(r.msg, "8 (CreateRemoteThread), 10 (ProcessAccess) and 25 (ProcessTampering)") {
		t.Errorf("message does not say which events are needed: %q", r.msg)
	}
	wantCalls(t, h, "sysmon -s") // only to rule out HomeXDR's own configuration
	if m.testBackup(t) != nil {
		t.Fatal("backup written for a foreign configuration")
	}
	r, _ = m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "has not changed Sysmon")
	wantCalls(t, h)
}

// Someone replaced HomeXDR's configuration with their own: HomeXDR stops managing it and
// turning the setting off leaves it in place.
func TestSysmonReplacedByForeign(t *testing.T) {
	h := &fakeSysmonHost{feat: featureEnabled}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	m.ensure(ctx)
	wantCalls(t, h, "dism get", "sysmon -s", "sysmon -i "+m.configPath)
	if bk := m.testBackup(t); bk == nil || bk.FeatureWasEnabled == nil || !*bk.FeatureWasEnabled || bk.EnabledFeature {
		t.Fatalf("backup = %+v", bk)
	}
	h.inst.ConfigHash, h.inst.ConfigFile = "SHA256=FFFF", `C:\Tools\mine.xml`
	wantResult(t, m.ensure(ctx), api.SensorRunning, "did not write")
	wantCalls(t, h)
	r, did := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "left it installed and unchanged")
	wantCalls(t, h)
	if did != nil || h.inst == nil || m.testBackup(t) != nil {
		t.Fatalf("did %q install %+v", did, h.inst)
	}
}

func TestSysmonOutdatedHomeXDRConfig(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon", Driver: "SysmonDrv", ImagePath: fakeBin, Binary: fakeBin,
		ConfigHash: "SHA256=00AA", ConfigFile: `D:\elsewhere\old.xml`, HasRules: true}}
	m := newTestSysmon(t, h)
	// The record of an earlier HomeXDR configuration.
	if err := m.saveBackup(&sysmonBackup{ServiceWasInstalled: true, RulesBefore: rulesNone, AppliedConfig: true, ConfigHash: "sha256=00aa"}); err != nil {
		t.Fatal(err)
	}
	wantResult(t, m.ensure(context.Background()), api.SensorRunning, "configured by HomeXDR")
	wantCalls(t, h, "sysmon -s", "sysmon -c "+m.configPath)
	if bk := m.testBackup(t); bk.ConfigHash != h.inst.ConfigHash || bk.RulesBefore != rulesNone {
		t.Fatalf("backup = %+v", bk)
	}
}

// HomeXDR's current configuration without a backup (deleted) is recognised by its hash;
// turning the setting off then resets Sysmon.
func TestSysmonLostBackup(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon", Driver: "SysmonDrv", ImagePath: fakeBin, Binary: fakeBin}}
	m := newTestSysmon(t, h)
	ctx := context.Background()
	m.ensure(ctx)
	if err := m.removeBackup(); err != nil {
		t.Fatal(err)
	}
	h.inst.ConfigFile = `C:\Moved\sysmon-config.xml`
	h.calls = nil
	wantResult(t, m.ensure(ctx), api.SensorRunning, "configured by HomeXDR")
	wantCalls(t, h)
	if bk := m.testBackup(t); bk == nil || bk.RulesBefore != rulesHomeXDR || !bk.AppliedConfig {
		t.Fatalf("backup = %+v", bk)
	}
	r, _ := m.undo(ctx)
	wantResult(t, r, api.SensorDisabled, "reset Sysmon")
	wantCalls(t, h, "sysmon -c --")
}

func TestSysmonApplyFails(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon", Driver: "SysmonDrv", ImagePath: fakeBin, Binary: fakeBin},
		failSysmon: map[string]error{"-c": errors.New("sysmon.exe exit code 87: Error: Unknown element 'Bogus'")}}
	m := newTestSysmon(t, h)
	r := m.ensure(context.Background())
	wantResult(t, r, api.SensorDegraded, "Sysmon did not accept HomeXDR's configuration: sysmon.exe exit code 87")
	if bk := m.testBackup(t); bk == nil || bk.AppliedConfig {
		t.Fatalf("backup = %+v", bk)
	}
	// Nothing to undo: Sysmon still has no rules.
	r, did := m.undo(context.Background())
	wantResult(t, r, api.SensorDisabled, "nothing of HomeXDR's to undo")
	if did != nil {
		t.Errorf("did %q", did)
	}
}

func TestSysmonSchemaTooOld(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon64", Driver: "SysmonDrv", ImagePath: `C:\Windows\Sysmon64.exe`, Binary: `C:\Windows\Sysmon64.exe`},
		schemaV: "4.40"}
	m := newTestSysmon(t, h)
	wantResult(t, m.ensure(context.Background()), api.SensorDegraded, "too old for HomeXDR's configuration (schema 4.40, needs 4.50 or later)")
	wantCalls(t, h, "sysmon -s")
}

func TestSysmonBinaryNotRun(t *testing.T) {
	h := &fakeSysmonHost{inst: &sysmonInstall{Service: "Sysmon64", Driver: "SysmonDrv", ImagePath: `D:\Tools\Sysmon64.exe`}}
	m := newTestSysmon(t, h)
	wantResult(t, m.ensure(context.Background()), api.SensorRunning, `Sysmon runs from D:\Tools\Sysmon64.exe, which HomeXDR does not run`)
	wantCalls(t, h)
}

func TestRenderSysmonConfig(t *testing.T) {
	b := renderSysmonConfig("4.91", `C:\WINDOWS\`, `C:\ProgramData`, `C:\Program Files`, `C:\Agents & Tools\homexdr-agent.exe`)
	s := string(b)
	if strings.Contains(s, "{{") || strings.Contains(s, "\r") {
		t.Fatalf("placeholders or CR left:\n%s", s)
	}
	var doc struct {
		XMLName xml.Name `xml:"Sysmon"`
		Schema  string   `xml:"schemaversion,attr"`
		Hashes  string   `xml:"HashAlgorithms"`
		Groups  []struct {
			Inner string `xml:",innerxml"`
		} `xml:"EventFiltering>RuleGroup"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not XML: %v", err)
	}
	if doc.Schema != "4.91" || doc.Hashes != "SHA256,IMPHASH" {
		t.Errorf("schema %q hashes %q", doc.Schema, doc.Hashes)
	}
	// Exactly the five events, each in its own group; nothing else is turned on.
	var tags []string
	for _, g := range doc.Groups {
		m := regexp.MustCompile(`<(\w+) onmatch="(\w+)"`).FindAllStringSubmatch(g.Inner, -1)
		for _, x := range m {
			tags = append(tags, x[1]+"/"+x[2])
		}
	}
	want := []string{"ProcessCreate/exclude", "ProcessTerminate/exclude", "CreateRemoteThread/exclude",
		"ProcessAccess/include", "ProcessAccess/exclude", "ProcessTampering/exclude"}
	if !slices.Equal(tags, want) {
		t.Errorf("rule tags = %q, want %q", tags, want)
	}
	if !strings.Contains(s, `<TargetImage name="lsass" condition="is">C:\WINDOWS\System32\lsass.exe</TargetImage>`) {
		t.Error("no lsass rule with the Windows folder filled in")
	}
	if !strings.Contains(s, `<SourceImage condition="is">C:\Agents &amp; Tools\homexdr-agent.exe</SourceImage>`) {
		t.Error("agent path missing or not escaped")
	}
	// Sysmon writes access masks without leading zeros, so a rule with one never matches.
	if m := regexp.MustCompile(`<GrantedAccess[^>]*>0x0`).FindString(s); m != "" {
		t.Errorf("mask with a leading zero: %s", m)
	}
	if strings.Contains(strings.ToLower(s), ">0x1fffff<") {
		t.Error("PROCESS_ALL_ACCESS must not be included for every target")
	}
	// Deterministic: the same values give the same hash.
	again := renderSysmonConfig("4.91", `C:\WINDOWS\`, `C:\ProgramData`, `C:\Program Files`, `C:\Agents & Tools\homexdr-agent.exe`)
	if sysmonConfigHash("SHA256", b) != sysmonConfigHash("SHA256", again) {
		t.Error("rendering is not deterministic")
	}
}

func TestSysmonHelpers(t *testing.T) {
	if v, ok := parseSysmonSchema(`<manifest schemaversion="4.91" binaryversion="18">` + "\n  <configuration>"); !ok || v != "4.91" {
		t.Errorf("schema = %q %v", v, ok)
	}
	if _, ok := parseSysmonSchema("Usage: ..."); ok {
		t.Error("schema found in usage text")
	}
	for v, want := range map[string]bool{"4.91": true, "4.50": true, "5.0": true, "4.40": false, "3.99": false, "x": false, "4.": false} {
		if got := schemaAtLeast(v, sysmonMinSchema); got != want {
			t.Errorf("schemaAtLeast(%q) = %v", v, got)
		}
	}
	xmlB := []byte("<Sysmon/>")
	rec := sysmonConfigHash("SHA256", xmlB)
	if !strings.HasPrefix(rec, "SHA256=") || rec != strings.ToUpper(rec) {
		t.Errorf("hash format %q", rec)
	}
	if !sysmonHashMatches(rec, xmlB) || !sysmonHashMatches(strings.ToLower(rec), xmlB) || !sysmonHashMatches(sysmonConfigHash("SHA1", xmlB), xmlB) {
		t.Error("hash does not match its own config")
	}
	if sysmonHashMatches("", xmlB) || sysmonHashMatches("SHA256=00", xmlB) || sysmonHashMatches("CRC32=1", xmlB) {
		t.Error("hash matches the wrong config")
	}

	// `dism /English /Get-FeatureInfo` as Windows 11 prints it.
	info := "Deployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nFeature Information:\r\n\r\nFeature Name : Sysmon\r\nDisplay Name : Sysmon\r\nDescription : Enables the Sysmon tool\r\nRestart Required : Possible\r\nState : Enabled\r\n\r\nThe operation completed successfully.\r\n"
	for state, want := range map[string]featureState{"Enabled": featureEnabled, "Disabled": featureDisabled, "Enable Pending": featurePending,
		"Disable Pending": featurePending, "Disabled with Payload Removed": featureRemoved} {
		got, err := parseFeatureState(strings.Replace(info, "State : Enabled", "State : "+state, 1))
		if err != nil || got != want {
			t.Errorf("%s: %d %v", state, got, err)
		}
	}
	if _, err := parseFeatureState("Error: 87\r\n"); err == nil {
		t.Error("no state accepted")
	}

	out := "\r\nSystem Monitor v15.15 - System activity monitor\r\nBy Mark Russinovich and Thomas Garnier\r\nCopyright (C) 2014-2026 Microsoft Corporation\r\nUsing libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.\r\nSysinternals - www.sysinternals.com\r\n\r\nLoading configuration file with schema version 4.91\r\nError: Unknown element 'Bogus' found in EventFiltering section.\r\nConfiguration file rejected due to schema validation failure.\r\nUsage:\r\nInstall:                 sysmon.exe -i [<configfile>]\r\n"
	if got := sysmonError(out); !strings.Contains(got, "Unknown element 'Bogus'") || strings.Contains(got, "Install:") || strings.Contains(got, "Russinovich") {
		t.Errorf("sysmonError = %q", got)
	}
}

func TestSysmonImagePath(t *testing.T) {
	dir := t.TempDir()
	win := filepath.Join(dir, "Windows")
	sys := filepath.Join(win, "System32")
	if err := os.MkdirAll(sys, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(sys, "sysmon.exe"), filepath.Join(win, "Sysmon64.exe"), filepath.Join(win, "evil.exe")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := winSysmonHost{sysDir: sys, winDir: win}
	for in, want := range map[string]string{
		`"` + win + `\Sysmon64.exe"`:        filepath.Join(win, "Sysmon64.exe"),
		win + `\Sysmon64.exe`:               filepath.Join(win, "Sysmon64.exe"),
		`\SystemRoot\System32\sysmon.exe`:   filepath.Join(sys, "sysmon.exe"),
		`System32\sysmon.exe`:               filepath.Join(sys, "sysmon.exe"),
		`"` + win + `\Sysmon64.exe" -extra`: filepath.Join(win, "Sysmon64.exe"),
		win + `\Sysmon64.exe -service`:      filepath.Join(win, "Sysmon64.exe"),
		`\??\` + sys + `\sysmon.exe`:        filepath.Join(sys, "sysmon.exe"),
	} {
		if got := h.imagePath(in); !strings.EqualFold(got, want) {
			t.Errorf("imagePath(%q) = %q, want %q", in, got, want)
		}
	}
	for path, want := range map[string]bool{
		filepath.Join(sys, "sysmon.exe"):   true,
		filepath.Join(win, "Sysmon64.exe"): true,
		filepath.Join(win, "evil.exe"):     false, // not a Sysmon file name
		filepath.Join(win, "Sysmon.exe"):   false, // does not exist
		filepath.Join(dir, "sysmon.exe"):   false, // not a system folder
		"":                                 false,
	} {
		if got := h.runnable(path); got != want {
			t.Errorf("runnable(%q) = %v", path, got)
		}
	}
}
