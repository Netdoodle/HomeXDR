// Package hardening applies HomeXDR's Microsoft Defender hardening profile: a fixed list
// of Attack Surface Reduction (ASR) rules, Network Protection and Controlled Folder
// Access. It has no Windows dependencies (PowerShell runs through a Runner), so the
// planning, the scripts and the restore logic are tested everywhere; the Windows platform
// passes its PowerShell runner.
//
// What HomeXDR changes is recorded in the agent's data directory the first time it
// touches each setting (the value from before), so "off" puts back exactly that, and only
// where the setting still has the value HomeXDR gave it.
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
)

// Rule is one ASR rule HomeXDR manages.
type Rule struct {
	ID   string // lower-case GUID, from Microsoft's ASR rules reference
	Name string
	// AuditOnly rules stay in audit mode under "enforce" (they break common tools).
	AuditOnly bool
}

// Rules is the curated list: well-known rules with few false positives on home and small
// office PCs. GUIDs are from Microsoft's "ASR rules reference"
// (learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference).
// Changing the list means bumping api.HardeningProfile.
var Rules = []Rule{
	{ID: "56a863a9-875e-4185-98a7-b882c64b5ce5", Name: "Block abuse of exploited vulnerable signed drivers"},
	{ID: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", Name: "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"},
	{ID: "e6db77e5-3df2-4cf1-b95a-636979351e5b", Name: "Block persistence through WMI event subscription"},
	{ID: "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", Name: "Block executable content from email client and webmail"},
	{ID: "d4f940ab-401b-4efc-aadc-ad5f3c50688a", Name: "Block all Office applications from creating child processes"},
	{ID: "3b576869-a4ec-4529-8536-b80a7769e899", Name: "Block Office applications from creating executable content"},
	{ID: "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", Name: "Block Office applications from injecting code into other processes"},
	{ID: "26190899-1602-49e8-8b27-eb1d0a1ce869", Name: "Block Office communication application from creating child processes"},
	{ID: "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", Name: "Block Win32 API calls from Office macros"},
	{ID: "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", Name: "Block Adobe Reader from creating child processes"},
	{ID: "d3e037e1-3eb8-44c8-a917-57927947596d", Name: "Block JavaScript or VBScript from launching downloaded executable content"},
	{ID: "5beb7efe-fd9a-4556-801d-275e5ffc04cc", Name: "Block execution of potentially obfuscated scripts"},
	{ID: "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", Name: "Block untrusted and unsigned processes that run from USB"},
	{ID: "d1e49aac-8f56-4280-b9ba-993a6d77406c", Name: "Block process creations originating from PSExec and WMI commands", AuditOnly: true},
}

// Setting kinds.
const (
	KindASR = "asr"
	KindNP  = "network_protection"
	KindCFA = "controlled_folder_access"
)

// NotConfigured is an ASR rule absent from Defender's list.
const NotConfigured = -1

// ASR rule actions (AttackSurfaceReductionRules_Actions).
const (
	asrDisabled = 0
	asrBlock    = 1
	asrAudit    = 2
	asrWarn     = 6
)

// Network Protection (EnableNetworkProtection) and Controlled Folder Access
// (EnableControlledFolderAccess) values.
const (
	optDisabled          = 0
	optEnabled           = 1
	optAudit             = 2
	cfaBlockDiskModOnly  = 3
	cfaAuditDiskModOnly  = 4
	stateFileName        = "defender-hardening.json"
	maxErrorMessageBytes = 300
)

var (
	guidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
)

// Validate checks a command's parameters before anything runs.
func Validate(p api.DefenderHardenParams) error {
	switch p.Mode {
	case api.HardeningOff, api.HardeningAudit, api.HardeningEnforce:
	default:
		return fmt.Errorf("unknown Defender hardening mode %q", p.Mode)
	}
	if !versionRe.MatchString(p.Version) {
		return fmt.Errorf("invalid version %q", p.Version)
	}
	return nil
}

// Prefs is what Defender reports (Get-MpComputerStatus and Get-MpPreference).
type Prefs struct {
	RunningMode string
	Tamper      bool
	ASR         map[string]int // lower-case GUID -> action
	NP          int
	CFA         int
}

// asr returns a rule's action, NotConfigured when absent.
func (p Prefs) asr(id string) int {
	if v, ok := p.ASR[id]; ok {
		return v
	}
	return NotConfigured
}

func (p Prefs) value(t Target) int {
	switch t.Kind {
	case KindNP:
		return p.NP
	case KindCFA:
		return p.CFA
	}
	return p.asr(t.ID)
}

// ReadScript prints Defender's state as one JSON object.
const ReadScript = `$ErrorActionPreference='Stop'
$s = Get-MpComputerStatus
$p = Get-MpPreference
[pscustomobject]@{
  running_mode = "$($s.AMRunningMode)"
  tamper = [bool]$s.IsTamperProtected
  asr_ids = @($p.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_" })
  asr_actions = @($p.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
  np = [int]$p.EnableNetworkProtection
  cfa = [int]$p.EnableControlledFolderAccess
} | ConvertTo-Json -Compress
`

// oneOrMany decodes a JSON array or a single value.
type oneOrMany[T any] []T

func (o *oneOrMany[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*o = nil
		return nil
	}
	if b[0] == '[' {
		var xs []T
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
		*o = xs
		return nil
	}
	var x T
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	*o = []T{x}
	return nil
}

// ParsePrefs reads ReadScript's output.
func ParsePrefs(out []byte) (Prefs, error) {
	var raw struct {
		RunningMode string            `json:"running_mode"`
		Tamper      bool              `json:"tamper"`
		IDs         oneOrMany[string] `json:"asr_ids"`
		Actions     oneOrMany[int]    `json:"asr_actions"`
		NP          int               `json:"np"`
		CFA         int               `json:"cfa"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &raw); err != nil {
		return Prefs{}, fmt.Errorf("unexpected Defender preferences output: %w", err)
	}
	if len(raw.IDs) != len(raw.Actions) {
		return Prefs{}, fmt.Errorf("Defender reports %d ASR rule IDs but %d actions", len(raw.IDs), len(raw.Actions))
	}
	p := Prefs{RunningMode: strings.TrimSpace(raw.RunningMode), Tamper: raw.Tamper, NP: raw.NP, CFA: raw.CFA, ASR: map[string]int{}}
	for i, id := range raw.IDs {
		p.ASR[strings.ToLower(strings.Trim(strings.TrimSpace(id), "{}"))] = raw.Actions[i]
	}
	return p, nil
}

// Active reports whether Defender runs as the active antivirus: ASR rules, Network
// Protection and Controlled Folder Access do nothing in passive mode.
func (p Prefs) Active() bool {
	return p.RunningMode == "" || strings.EqualFold(p.RunningMode, "Normal")
}

// Entry is one setting HomeXDR changed: the value before (Prior) and the value HomeXDR
// set (Set).
type Entry struct {
	Prior int `json:"prior"`
	Set   int `json:"set"`
}

// State is what HomeXDR changed on this host, kept in the agent's data directory.
type State struct {
	Mode    string           `json:"mode,omitempty"`
	Profile string           `json:"profile,omitempty"`
	ASR     map[string]Entry `json:"asr,omitempty"`
	NP      *Entry           `json:"network_protection,omitempty"`
	CFA     *Entry           `json:"controlled_folder_access,omitempty"`
}

func (s State) empty() bool { return len(s.ASR) == 0 && s.NP == nil && s.CFA == nil }

// Target is the value one setting should have.
type Target struct {
	Kind  string
	ID    string // ASR rule GUID
	Name  string
	Value int // NotConfigured: remove the ASR rule from Defender's list
}

// strength orders values from no protection (0) up, per kind.
func strength(kind string, v int) int {
	switch kind {
	case KindASR:
		switch v {
		case asrAudit:
			return 1
		case asrWarn:
			return 2
		case asrBlock:
			return 3
		}
		return 0
	case KindCFA:
		switch v {
		case cfaAuditDiskModOnly:
			return 1
		case optAudit:
			return 2
		case cfaBlockDiskModOnly:
			return 3
		case optEnabled:
			return 4
		}
		return 0
	}
	switch v { // network protection
	case optAudit:
		return 1
	case optEnabled:
		return 2
	}
	return 0
}

// Plan works out the value each managed setting should have for mode, and the state to
// record. Turning a mode on never weakens a setting that was stronger before HomeXDR
// touched it. "off" puts back the value from before, but only where the setting still
// has the value HomeXDR set; notes name the settings left alone.
func Plan(mode string, cur Prefs, st State) (targets []Target, next State, notes []string) {
	next = State{ASR: map[string]Entry{}}
	managed := map[string]bool{}
	if mode != api.HardeningOff {
		next.Mode, next.Profile = mode, api.HardeningProfile
		for _, r := range Rules {
			managed[r.ID] = true
			want := asrAudit
			if mode == api.HardeningEnforce && !r.AuditOnly {
				want = asrBlock
			}
			e, ok := st.ASR[r.ID]
			if !ok {
				e.Prior = cur.asr(r.ID)
			}
			if strength(KindASR, e.Prior) > strength(KindASR, want) {
				want = e.Prior
			}
			e.Set = want
			next.ASR[r.ID] = e
			targets = append(targets, Target{Kind: KindASR, ID: r.ID, Name: r.Name, Value: want})
		}
		npWant := optAudit
		if mode == api.HardeningEnforce {
			npWant = optEnabled
		}
		next.NP = planOpt(KindNP, st.NP, cur.NP, npWant)
		targets = append(targets, Target{Kind: KindNP, Name: "Network Protection", Value: next.NP.Set})
		// Controlled Folder Access stays in audit mode in both modes: blocking breaks
		// ordinary programs that save to Documents, Pictures or the Desktop.
		next.CFA = planOpt(KindCFA, st.CFA, cur.CFA, optAudit)
		targets = append(targets, Target{Kind: KindCFA, Name: "Controlled Folder Access", Value: next.CFA.Set})
	}
	// Put back what HomeXDR no longer manages (everything, for off).
	ids := make([]string, 0, len(st.ASR))
	for id := range st.ASR {
		if !managed[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !guidRe.MatchString(id) {
			continue // not a GUID: never put in a script
		}
		e := st.ASR[id]
		name := ruleName(id)
		if cur.asr(id) != e.Set {
			notes = append(notes, fmt.Sprintf("%s: left at %s (changed outside HomeXDR)", name, valueName(KindASR, cur.asr(id))))
			continue
		}
		targets = append(targets, Target{Kind: KindASR, ID: id, Name: name, Value: e.Prior})
	}
	if mode == api.HardeningOff {
		for _, o := range []struct {
			kind, name string
			e          *Entry
			cur        int
		}{{KindNP, "Network Protection", st.NP, cur.NP}, {KindCFA, "Controlled Folder Access", st.CFA, cur.CFA}} {
			if o.e == nil {
				continue
			}
			if o.cur != o.e.Set {
				notes = append(notes, fmt.Sprintf("%s: left at %s (changed outside HomeXDR)", o.name, valueName(o.kind, o.cur)))
				continue
			}
			targets = append(targets, Target{Kind: o.kind, Name: o.name, Value: o.e.Prior})
		}
	}
	return targets, next, notes
}

func planOpt(kind string, prev *Entry, cur, want int) *Entry {
	e := Entry{Prior: cur}
	if prev != nil {
		e = *prev
	}
	if strength(kind, e.Prior) > strength(kind, want) {
		want = e.Prior
	}
	e.Set = want
	return &e
}

func ruleName(id string) string {
	for _, r := range Rules {
		if r.ID == id {
			return r.Name
		}
	}
	return "ASR rule " + id
}

// valueName is how the console and the docs name a value.
func valueName(kind string, v int) string {
	if kind == KindASR {
		switch v {
		case NotConfigured:
			return "Not configured"
		case asrDisabled:
			return "Disabled"
		case asrBlock:
			return "Block"
		case asrAudit:
			return "Audit"
		case asrWarn:
			return "Warn"
		}
		return fmt.Sprintf("unknown (%d)", v)
	}
	switch v {
	case optDisabled:
		return "Disabled"
	case optEnabled:
		return "Enabled"
	case optAudit:
		return "Audit"
	case cfaBlockDiskModOnly:
		if kind == KindCFA {
			return "Block disk modification only"
		}
	case cfaAuditDiskModOnly:
		if kind == KindCFA {
			return "Audit disk modification only"
		}
	}
	return fmt.Sprintf("unknown (%d)", v)
}

// psValue is the Defender PowerShell enum name for a value, or "" if there is none.
func psValue(kind string, v int) string {
	if kind == KindASR {
		switch v {
		case asrDisabled:
			return "Disabled"
		case asrBlock:
			return "Enabled"
		case asrAudit:
			return "AuditMode"
		case asrWarn:
			return "Warn"
		}
		return ""
	}
	switch v {
	case optDisabled:
		return "Disabled"
	case optEnabled:
		return "Enabled"
	case optAudit:
		return "AuditMode"
	}
	if kind == KindCFA {
		switch v {
		case cfaBlockDiskModOnly:
			return "BlockDiskModificationOnly"
		case cfaAuditDiskModOnly:
			return "AuditDiskModificationOnly"
		}
	}
	return ""
}

func key(t Target) string {
	if t.Kind == KindASR {
		return KindASR + ":" + t.ID
	}
	return t.Kind
}

// Script sets every target that differs from cur. Each change runs on its own, so one
// refused setting does not stop the others; failures print "ERR <key>\t<message>". The
// only values in the script are GUIDs (checked against a strict pattern) and fixed enum
// names. It returns "" when nothing needs changing.
func Script(targets []Target, cur Prefs) string {
	var b strings.Builder
	for _, t := range targets {
		if cur.value(t) == t.Value || (t.Kind == KindASR && t.Value == NotConfigured && cur.value(t) == asrDisabled) {
			continue
		}
		var cmd string
		switch t.Kind {
		case KindASR:
			if !guidRe.MatchString(t.ID) {
				continue
			}
			if t.Value == NotConfigured {
				cmd = fmt.Sprintf("Remove-MpPreference -AttackSurfaceReductionRules_Ids '%s'", t.ID)
			} else if v := psValue(KindASR, t.Value); v != "" {
				cmd = fmt.Sprintf("Add-MpPreference -AttackSurfaceReductionRules_Ids '%s' -AttackSurfaceReductionRules_Actions %s", t.ID, v)
			}
		case KindNP:
			if v := psValue(KindNP, t.Value); v != "" {
				cmd = "Set-MpPreference -EnableNetworkProtection " + v
			}
		case KindCFA:
			if v := psValue(KindCFA, t.Value); v != "" {
				cmd = "Set-MpPreference -EnableControlledFolderAccess " + v
			}
		}
		if cmd == "" {
			continue
		}
		fmt.Fprintf(&b, "try { %s } catch { \"ERR %s`t$($_.Exception.Message -replace '\\s+', ' ')\" }\n", cmd, key(t))
	}
	if b.Len() == 0 {
		return ""
	}
	return "$ErrorActionPreference='Stop'\n" + b.String()
}

// parseErrors reads the "ERR key\tmessage" lines of Script's output.
func parseErrors(out []byte) map[string]string {
	errs := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "ERR ") {
			continue
		}
		k, msg, _ := strings.Cut(strings.TrimPrefix(l, "ERR "), "\t")
		if len(msg) > maxErrorMessageBytes {
			msg = msg[:maxErrorMessageBytes] + "..."
		}
		errs[strings.TrimSpace(k)] = strings.TrimSpace(msg)
	}
	return errs
}

// Runner runs a PowerShell script and returns its standard output.
type Runner func(ctx context.Context, script string) ([]byte, error)

// StatePath is where the record of HomeXDR's changes is kept.
func StatePath(dataDir string) string { return filepath.Join(dataDir, stateFileName) }

// LoadState reads the record; a missing file is an empty state.
func LoadState(dataDir string) (State, error) {
	b, err := os.ReadFile(StatePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("read %s: %w", StatePath(dataDir), err)
	}
	return s, nil
}

func saveState(dataDir string, s State) error {
	if s.empty() {
		if err := os.Remove(StatePath(dataDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := StatePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, StatePath(dataDir))
}

// Apply brings Defender in line with p.Mode, records what it changed and reports what
// Defender says afterwards.
func Apply(ctx context.Context, p api.DefenderHardenParams, dataDir string, run Runner) (api.DefenderHardenResult, error) {
	res := api.DefenderHardenResult{Mode: p.Mode, Version: p.Version, Profile: api.HardeningProfile}
	if err := Validate(p); err != nil {
		return res, err
	}
	out, err := run(ctx, ReadScript)
	if err != nil {
		return res, fmt.Errorf("read Defender preferences: %w", err)
	}
	cur, err := ParsePrefs(out)
	if err != nil {
		return res, err
	}
	if p.Mode != api.HardeningOff && !cur.Active() {
		return res, fmt.Errorf("Microsoft Defender Antivirus is not the active antivirus here (running mode %q): ASR rules, Network Protection and Controlled Folder Access only work when it is", cur.RunningMode)
	}
	st, err := LoadState(dataDir)
	if err != nil {
		return res, err
	}
	targets, next, notes := Plan(p.Mode, cur, st)
	if p.Mode == api.HardeningOff && st.empty() {
		res.Message = "HomeXDR has not changed Defender's settings on this host; nothing to put back"
		return res, nil
	}
	// Record the values from before first, so a crash halfway still knows them.
	if p.Mode != api.HardeningOff {
		if err := saveState(dataDir, next); err != nil {
			return res, fmt.Errorf("save the previous Defender settings: %w", err)
		}
	}
	errs := map[string]string{}
	if script := Script(targets, cur); script != "" {
		sout, serr := run(ctx, script)
		errs = parseErrors(sout)
		if serr != nil && len(errs) == 0 {
			errs["*"] = serr.Error()
		}
	}
	after := cur
	if out, err := run(ctx, ReadScript); err != nil {
		return res, fmt.Errorf("read back Defender preferences: %w", err)
	} else if after, err = ParsePrefs(out); err != nil {
		return res, err
	}
	inEffect := 0
	failed := map[string]bool{}
	for _, t := range targets {
		got := after.value(t)
		ok := got == t.Value || (t.Kind == KindASR && t.Value == NotConfigured && got == asrDisabled)
		res.Settings = append(res.Settings, api.HardeningSetting{Name: t.Name, Wanted: valueName(t.Kind, t.Value), Actual: valueName(t.Kind, got)})
		if ok {
			inEffect++
			continue
		}
		failed[key(t)] = true
		why := errs[key(t)]
		if why == "" {
			why = errs["*"]
		}
		if why == "" {
			why = "Defender kept the old value; a Group Policy or MDM setting, or Tamper Protection, may override local settings"
		}
		res.Failures = append(res.Failures, fmt.Sprintf("%s: wanted %s, Defender reports %s (%s)", t.Name, valueName(t.Kind, t.Value), valueName(t.Kind, got), why))
	}
	if p.Mode == api.HardeningOff {
		// What was put back (or was changed by someone else) is forgotten; settings
		// Defender refused to put back stay recorded for the next try.
		keep := State{ASR: map[string]Entry{}}
		for id, e := range st.ASR {
			if failed[KindASR+":"+id] {
				keep.ASR[id] = e
			}
		}
		if failed[KindNP] {
			keep.NP = st.NP
		}
		if failed[KindCFA] {
			keep.CFA = st.CFA
		}
		if err := saveState(dataDir, keep); err != nil {
			return res, fmt.Errorf("update the record of HomeXDR's Defender changes: %w", err)
		}
		res.Message = fmt.Sprintf("HomeXDR's Defender hardening removed: %d of %d settings put back", inEffect, len(targets))
	} else {
		blocking, auditing := 0, 0
		for _, r := range Rules {
			switch after.asr(r.ID) {
			case asrBlock, asrWarn:
				blocking++
			case asrAudit:
				auditing++
			}
		}
		res.Message = fmt.Sprintf("%s: %d of %d settings in effect; ASR rules: %d blocking, %d audit; Network Protection %s; Controlled Folder Access %s",
			p.Mode, inEffect, len(targets), blocking, auditing, valueName(KindNP, after.NP), valueName(KindCFA, after.CFA))
	}
	if len(notes) > 0 {
		res.Message += "; " + strings.Join(notes, "; ")
	}
	if len(res.Failures) > 0 {
		res.Message += fmt.Sprintf("; %d not applied", len(res.Failures))
	}
	if after.Tamper {
		res.Message += "; Tamper Protection is on"
	}
	return res, nil
}
