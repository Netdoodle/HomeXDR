package hardening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

// fakeDefender stands in for PowerShell: it answers ReadScript and applies the lines of
// a Script to its preferences.
type fakeDefender struct {
	mode    string
	tamper  bool
	asr     map[string]int
	np, cfa int
	// policy pins settings like a Group Policy would: changes are accepted but ignored.
	policy map[string]bool
	// refuse makes the cmdlet fail for a setting.
	refuse  map[string]bool
	scripts []string
}

var (
	addRe = regexp.MustCompile(`^try \{ Add-MpPreference -AttackSurfaceReductionRules_Ids '([0-9a-f-]+)' -AttackSurfaceReductionRules_Actions (\w+) \}`)
	remRe = regexp.MustCompile(`^try \{ Remove-MpPreference -AttackSurfaceReductionRules_Ids '([0-9a-f-]+)' \}`)
	npRe  = regexp.MustCompile(`^try \{ Set-MpPreference -EnableNetworkProtection (\w+) \}`)
	cfaRe = regexp.MustCompile(`^try \{ Set-MpPreference -EnableControlledFolderAccess (\w+) \}`)
)

var asrEnum = map[string]int{"Disabled": 0, "Enabled": 1, "AuditMode": 2, "Warn": 6}
var optEnum = map[string]int{"Disabled": 0, "Enabled": 1, "AuditMode": 2, "BlockDiskModificationOnly": 3, "AuditDiskModificationOnly": 4}

func newFake() *fakeDefender {
	return &fakeDefender{mode: "Normal", asr: map[string]int{}, policy: map[string]bool{}, refuse: map[string]bool{}}
}

func (f *fakeDefender) run(_ context.Context, script string) ([]byte, error) {
	if script == ReadScript {
		ids, acts := []string{}, []int{}
		for id, a := range f.asr {
			ids = append(ids, strings.ToUpper(id)) // Defender may report upper case
			acts = append(acts, a)
		}
		return json.Marshal(map[string]any{"running_mode": f.mode, "tamper": f.tamper, "asr_ids": ids, "asr_actions": acts, "np": f.np, "cfa": f.cfa})
	}
	f.scripts = append(f.scripts, script)
	var out strings.Builder
	for _, l := range strings.Split(script, "\n") {
		var k string
		var apply func()
		switch {
		case addRe.MatchString(l):
			m := addRe.FindStringSubmatch(l)
			k = "asr:" + m[1]
			apply = func() { f.asr[m[1]] = asrEnum[m[2]] }
		case remRe.MatchString(l):
			m := remRe.FindStringSubmatch(l)
			k = "asr:" + m[1]
			apply = func() { delete(f.asr, m[1]) }
		case npRe.MatchString(l):
			m := npRe.FindStringSubmatch(l)
			k = KindNP
			apply = func() { f.np = optEnum[m[1]] }
		case cfaRe.MatchString(l):
			m := cfaRe.FindStringSubmatch(l)
			k = KindCFA
			apply = func() { f.cfa = optEnum[m[1]] }
		case strings.TrimSpace(l) == "" || l == "$ErrorActionPreference='Stop'":
			continue
		default:
			return nil, fmt.Errorf("unexpected script line %q", l)
		}
		if f.refuse[k] {
			fmt.Fprintf(&out, "ERR %s\tAccess denied\n", k)
			continue
		}
		if !f.policy[k] {
			apply()
		}
	}
	return []byte(out.String()), nil
}

const (
	lsass  = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
	psexec = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
	usb    = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
)

func TestRuleList(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if !guidRe.MatchString(r.ID) {
			t.Errorf("%s: not a lower-case GUID: %q", r.Name, r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
	}
	if len(Rules) != 14 {
		t.Errorf("rules: %d", len(Rules))
	}
	for _, r := range Rules {
		if r.AuditOnly != (r.ID == psexec) {
			t.Errorf("%s: audit only %v", r.Name, r.AuditOnly)
		}
	}
	// Rules with many false positives stay out of the list.
	for _, id := range []string{"01443614-cd74-433a-b99e-2ecdc07bfc25", "c1db55ab-c21a-4637-bb3f-a12568109d35", "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"} {
		if seen[id] {
			t.Errorf("rule %s should not be managed", id)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, p := range []api.DefenderHardenParams{{Mode: "off"}, {Mode: "audit", Version: "audit-p1"}, {Mode: "enforce", Version: "enforce-p1"}} {
		if err := Validate(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	for _, p := range []api.DefenderHardenParams{{Mode: ""}, {Mode: "block"}, {Mode: "audit", Version: "a b"}, {Mode: "audit", Version: "x'; Remove-Item"}, {Mode: "audit", Version: strings.Repeat("a", 65)}} {
		if err := Validate(p); err == nil {
			t.Errorf("%+v: accepted", p)
		}
	}
}

func TestParsePrefs(t *testing.T) {
	p, err := ParsePrefs([]byte(`{"running_mode":"Normal","tamper":true,"asr_ids":"{9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2}","asr_actions":1,"np":2,"cfa":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.asr(lsass) != 1 || p.NP != 2 || !p.Tamper || !p.Active() || p.asr(usb) != NotConfigured {
		t.Fatalf("%+v", p)
	}
	if p, err = ParsePrefs([]byte(`{"running_mode":"Passive Mode","asr_ids":[],"asr_actions":[]}`)); err != nil || p.Active() {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParsePrefs([]byte(`{"asr_ids":["a","b"],"asr_actions":[1]}`)); err == nil {
		t.Fatal("mismatched lists accepted")
	}
}

func TestScriptOnlyFixedValues(t *testing.T) {
	targets, _, _ := Plan(api.HardeningEnforce, Prefs{ASR: map[string]int{}}, State{})
	s := Script(targets, Prefs{ASR: map[string]int{}})
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if lines[0] != "$ErrorActionPreference='Stop'" || len(lines) != 1+len(Rules)+2 {
		t.Fatalf("script:\n%s", s)
	}
	for _, l := range lines[1:] {
		if !addRe.MatchString(l) && !npRe.MatchString(l) && !cfaRe.MatchString(l) {
			t.Errorf("unexpected line %q", l)
		}
	}
	if !strings.Contains(s, "'"+lsass+"' -AttackSurfaceReductionRules_Actions Enabled") ||
		!strings.Contains(s, "'"+psexec+"' -AttackSurfaceReductionRules_Actions AuditMode") ||
		!strings.Contains(s, "-EnableNetworkProtection Enabled") || !strings.Contains(s, "-EnableControlledFolderAccess AuditMode") {
		t.Errorf("script:\n%s", s)
	}
	// A bogus ID from a damaged state file never reaches a script.
	if s := Script([]Target{{Kind: KindASR, ID: "x'; Stop-Service WinDefend; '", Value: NotConfigured}}, Prefs{ASR: map[string]int{"x'; Stop-Service WinDefend; '": 1}}); s != "" {
		t.Errorf("script for a bad ID: %q", s)
	}
	// Nothing to change, no script.
	cur := Prefs{ASR: map[string]int{}, NP: 1, CFA: 2}
	for _, tg := range targets {
		if tg.Kind == KindASR {
			cur.ASR[tg.ID] = tg.Value
		}
	}
	if s := Script(targets, cur); s != "" {
		t.Errorf("script when in line: %q", s)
	}
}

func TestPlanKeepsStrongerSettings(t *testing.T) {
	cur := Prefs{ASR: map[string]int{lsass: asrBlock, usb: asrWarn}, NP: optEnabled, CFA: optEnabled}
	targets, next, _ := Plan(api.HardeningAudit, cur, State{})
	want := map[string]int{}
	for _, tg := range targets {
		want[key(tg)] = tg.Value
	}
	if want["asr:"+lsass] != asrBlock || want["asr:"+usb] != asrWarn || want["asr:"+psexec] != asrAudit {
		t.Errorf("asr targets %v", want)
	}
	if want[KindNP] != optEnabled || want[KindCFA] != optEnabled {
		t.Errorf("np/cfa targets %v", want)
	}
	if next.ASR[lsass].Prior != asrBlock || next.ASR[psexec].Prior != NotConfigured || next.NP.Prior != optEnabled {
		t.Errorf("state %+v", next)
	}
}

func TestApplyAndRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := newFake()
	f.asr[lsass] = asrAudit // set by the user before HomeXDR
	f.asr["01443614-cd74-433a-b99e-2ecdc07bfc25"] = asrBlock
	f.cfa = cfaAuditDiskModOnly

	res, err := Apply(ctx, api.DefenderHardenParams{Mode: "audit", Version: "audit-p1"}, dir, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failures) != 0 || f.np != optAudit || f.cfa != optAudit || f.asr[usb] != asrAudit || res.Version != "audit-p1" {
		t.Fatalf("audit: %+v, defender %+v", res, f)
	}
	if !strings.Contains(res.Message, "16 of 16 settings in effect") || !strings.Contains(res.Message, "14 audit") {
		t.Errorf("message %q", res.Message)
	}
	res, err = Apply(ctx, api.DefenderHardenParams{Mode: "enforce", Version: "enforce-p1"}, dir, f.run)
	if err != nil || len(res.Failures) != 0 {
		t.Fatal(res, err)
	}
	if f.asr[usb] != asrBlock || f.asr[lsass] != asrBlock || f.asr[psexec] != asrAudit || f.np != optEnabled || f.cfa != optAudit {
		t.Fatalf("enforce: defender %+v", f)
	}
	st, _ := LoadState(dir)
	if st.ASR[lsass].Prior != asrAudit || st.ASR[usb].Prior != NotConfigured || st.CFA.Prior != cfaAuditDiskModOnly || st.NP.Prior != optDisabled {
		t.Fatalf("recorded state %+v", st)
	}
	// Someone turns one rule off by hand: off leaves it alone.
	f.asr[usb] = asrDisabled
	res, err = Apply(ctx, api.DefenderHardenParams{Mode: "off", Version: "off"}, dir, f.run)
	if err != nil || len(res.Failures) != 0 {
		t.Fatal(res, err)
	}
	if f.asr[lsass] != asrAudit || f.asr[usb] != asrDisabled || f.np != optDisabled || f.cfa != cfaAuditDiskModOnly {
		t.Fatalf("off: defender %+v", f)
	}
	if _, ok := f.asr[psexec]; ok {
		t.Error("psexec rule not removed")
	}
	if f.asr["01443614-cd74-433a-b99e-2ecdc07bfc25"] != asrBlock {
		t.Error("a rule HomeXDR does not manage was changed")
	}
	if !strings.Contains(res.Message, "changed outside HomeXDR") {
		t.Errorf("message %q", res.Message)
	}
	if _, err := os.Stat(StatePath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file left behind: %v", err)
	}
	// Off again: nothing to do.
	n := len(f.scripts)
	res, err = Apply(ctx, api.DefenderHardenParams{Mode: "off", Version: "off"}, dir, f.run)
	if err != nil || len(f.scripts) != n || !strings.Contains(res.Message, "nothing to put back") {
		t.Fatal(res, err)
	}
}

func TestApplyReportsFailures(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := newFake()
	f.policy[KindNP] = true       // a Group Policy pins Network Protection
	f.refuse["asr:"+lsass] = true // the cmdlet fails for one rule
	f.tamper = true
	res, err := Apply(ctx, api.DefenderHardenParams{Mode: "enforce", Version: "enforce-p1"}, dir, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failures) != 2 || !strings.Contains(strings.Join(res.Failures, "\n"), "Access denied") ||
		!strings.Contains(strings.Join(res.Failures, "\n"), "Group Policy") {
		t.Fatalf("failures %q", res.Failures)
	}
	if !strings.Contains(res.Message, "2 not applied") || !strings.Contains(res.Message, "Tamper Protection is on") {
		t.Errorf("message %q", res.Message)
	}
	// Turning it off: the settings it could not set are simply not put back.
	f.refuse = map[string]bool{}
	f.policy = map[string]bool{}
	if _, err := Apply(ctx, api.DefenderHardenParams{Mode: "off", Version: "off"}, dir, f.run); err != nil {
		t.Fatal(err)
	}
	if len(f.asr) != 0 || f.np != 0 || f.cfa != 0 {
		t.Fatalf("after off: %+v", f)
	}
	// A refused revert stays recorded.
	if _, err := Apply(ctx, api.DefenderHardenParams{Mode: "audit", Version: "audit-p1"}, dir, f.run); err != nil {
		t.Fatal(err)
	}
	f.refuse[KindCFA] = true
	res, err = Apply(ctx, api.DefenderHardenParams{Mode: "off", Version: "off"}, dir, f.run)
	if err != nil || len(res.Failures) != 1 {
		t.Fatal(res, err)
	}
	st, _ := LoadState(dir)
	if st.CFA == nil || len(st.ASR) != 0 || st.NP != nil {
		t.Fatalf("state after a refused revert: %+v", st)
	}
}

func TestApplyPassiveMode(t *testing.T) {
	f := newFake()
	f.mode = "Passive Mode"
	if _, err := Apply(context.Background(), api.DefenderHardenParams{Mode: "audit", Version: "v"}, t.TempDir(), f.run); err == nil || !strings.Contains(err.Error(), "not the active antivirus") {
		t.Fatalf("passive mode: %v", err)
	}
	if len(f.scripts) != 0 {
		t.Error("changed settings in passive mode")
	}
}
