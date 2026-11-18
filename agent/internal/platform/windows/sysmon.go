//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Sysmon management (docs/sysmon.md). With the host's "Sysmon events" setting on, the
// agent makes sure Sysmon logs what the process sensor maps (procmap.go): process start
// and exit, remote threads, process access and process tampering.
//
//   - Sysmon not installed: where Windows has the Sysmon optional feature (Windows 11),
//     the agent turns it on with DISM (never downloading anything) and installs Sysmon
//     with HomeXDR's configuration. Elsewhere it only says so in its status.
//   - Sysmon installed with no rules, or with the configuration HomeXDR applied: the
//     agent applies HomeXDR's configuration when it differs from what Sysmon has.
//   - Sysmon with rules someone else wrote: left alone.
//
// What existed before HomeXDR first changed anything is recorded in a backup file next
// to the audit backup, and turning the setting off (or uninstalling the agent) undoes
// only what HomeXDR did. Sysmon, DISM and the config file are only ever used by absolute
// path; every command has a time limit and its exit code is checked.

const (
	// sysmonCheckInterval is how often the setting is enforced again. A check that finds
	// everything as it should be only reads the registry.
	sysmonCheckInterval = 10 * time.Minute
	sysmonConfigName    = "sysmon-config.xml"
	sysmonBackupName    = "sysmon-before-homexdr.json"
	sysmonCmdTimeout    = 2 * time.Minute
	// dismTimeout allows for a slow servicing stack when a feature is turned on or off.
	dismTimeout = 15 * time.Minute

	// sysmonFeature is the name of the Windows optional feature.
	sysmonFeature = "Sysmon"
	// dismUnknownFeature is DISM's exit code for a feature this Windows does not have
	// (CBS_E_UNKNOWN_UPDATE).
	dismUnknownFeature = 0x800F080C
	exitRestartNeeded  = 3010

	// Rules found in an installed Sysmon.
	rulesNone    = "none"    // no rules: Sysmon's defaults
	rulesHomeXDR = "homexdr" // the configuration HomeXDR applied
	rulesForeign = "foreign" // someone else's configuration
)

// sysmonEventsNote names what HomeXDR's configuration logs, for status messages.
const sysmonEventsNote = "events 1, 5, 8, 10 and 25"

// Status messages that are matched in tests.
const (
	sysmonNotAvailable = "Sysmon is not available on this Windows version; install it from Sysinternals for cross-process events"
	sysmonRestart      = "restart Windows to finish turning on the Sysmon feature; HomeXDR installs Sysmon after the restart"
)

// sysmonMinSchema is the oldest configuration schema with every event HomeXDR's
// configuration uses (ProcessTampering arrived with Sysmon 13, schema 4.50).
var sysmonMinSchema = [2]int{4, 50}

//go:embed sysmon_config.xml
var sysmonConfigTemplate string

// sysmonMu serialises all Sysmon changes in the agent process: a sensor that is being
// replaced may still be in the middle of a command when its successor starts.
var sysmonMu sync.Mutex

// Remembered for the life of the agent process (a restart of Windows restarts it too).
var (
	// sysmonRestartPending: the feature was turned on and needs a restart of Windows.
	sysmonRestartPending atomic.Bool
	// sysmonFeatureMissing: this Windows has no Sysmon feature.
	sysmonFeatureMissing atomic.Bool
)

// sysmonInstall is an installed Sysmon as the registry describes it.
type sysmonInstall struct {
	Service   string // service name: Sysmon (the Windows feature), Sysmon64, ...
	Driver    string
	ImagePath string // the service's executable
	// Binary is ImagePath when it is a Sysmon executable HomeXDR runs (in the Windows or
	// System32 folder), otherwise empty.
	Binary string
	// ConfigHash is the hash of the applied configuration file as Sysmon records it
	// ("SHA256=<hex>"); empty with no rules.
	ConfigHash string
	ConfigFile string // the file the configuration was applied from
	HasRules   bool
}

// featureState is the state of the Windows Sysmon optional feature.
type featureState int

const (
	featureMissing  featureState = iota + 1 // this Windows has no Sysmon feature
	featureDisabled                         // off, can be turned on
	featureEnabled
	featurePending // turning on or off waits for a restart
	featureRemoved // off, and its files were removed from Windows
)

// sysmonHost is what the manager needs from Windows; tests replace it.
type sysmonHost interface {
	// probe returns the installed Sysmon, nil when there is none.
	probe() (*sysmonInstall, error)
	feature(ctx context.Context) (featureState, error)
	// setFeature turns the optional feature on or off; restart reports exit code 3010.
	setFeature(ctx context.Context, on bool) (restart bool, err error)
	// systemBinary is %SystemRoot%\System32\sysmon.exe, which the feature provides.
	systemBinary() string
	exists(path string) bool
	// schema returns the newest configuration schema the binary accepts ("4.91").
	schema(ctx context.Context, bin string) (string, error)
	// sysmon runs the binary with -accepteula and args.
	sysmon(ctx context.Context, bin string, args ...string) error
}

// sysmonBackup is the backup file. The first part is the state before HomeXDR first
// changed Sysmon; the second what HomeXDR has done since, so that it is undone and
// nothing else.
type sysmonBackup struct {
	// FeatureWasEnabled is set when the Windows feature was checked: Sysmon was not
	// installed and the feature exists.
	FeatureWasEnabled   *bool  `json:"feature_was_enabled,omitempty"`
	ServiceWasInstalled bool   `json:"service_was_installed"`
	RulesBefore         string `json:"rules_before"` // rulesNone or rulesHomeXDR

	EnabledFeature   bool   `json:"enabled_feature,omitempty"`
	InstalledService bool   `json:"installed_service,omitempty"`
	AppliedConfig    bool   `json:"applied_config,omitempty"`
	ConfigHash       string `json:"config_hash,omitempty"` // as Sysmon records it
	ConfigPath       string `json:"config_path,omitempty"`
}

// sysmonResult is the outcome of a check, for the sensor status.
type sysmonResult struct {
	state string // api.Sensor*
	msg   string // informational (Message)
	err   string // what went wrong (Error)
}

func sysmonOK(msg string) sysmonResult  { return sysmonResult{state: api.SensorRunning, msg: msg} }
func sysmonBad(err string) sysmonResult { return sysmonResult{state: api.SensorDegraded, err: err} }
func sysmonOff(msg string) sysmonResult { return sysmonResult{state: api.SensorDisabled, msg: msg} }

// sysmonManager applies and undoes HomeXDR's Sysmon setup.
type sysmonManager struct {
	host       sysmonHost
	configPath string // where HomeXDR writes its configuration (the agent's data dir)
	backupPath string
	// Values for the configuration template.
	agentExe, windir, programData, programFiles string
	// writeFile writes a file only SYSTEM and Administrators can read.
	writeFile func(path string, b []byte) error

	schemaMu sync.Mutex
	schemas  map[string]schemaEntry // by binary path
}

type schemaEntry struct {
	mod     time.Time
	size    int64
	version string
}

func newSysmonManager(dataDir string) *sysmonManager {
	h := newWinSysmonHost()
	m := &sysmonManager{
		host:         h,
		configPath:   filepath.Join(dataDir, sysmonConfigName),
		backupPath:   sysmonBackupPath(),
		windir:       h.winDir,
		programData:  knownFolder(windows.FOLDERID_ProgramData, "ProgramData", `C:\ProgramData`),
		programFiles: knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", `C:\Program Files`),
		writeFile:    writeProtected,
	}
	if exe, err := os.Executable(); err == nil {
		m.agentExe = exe
	}
	return m
}

func sysmonBackupPath() string {
	return filepath.Join(filepath.Dir((&Platform{}).Paths().ConfigFile), sysmonBackupName)
}

// ensure makes Sysmon log what HomeXDR needs, where it may.
func (m *sysmonManager) ensure(ctx context.Context) sysmonResult {
	inst, err := m.host.probe()
	if err != nil {
		return sysmonBad("cannot read the Sysmon installation: " + err.Error())
	}
	bk, err := m.loadBackup()
	if err != nil {
		return sysmonBad(err.Error())
	}
	if inst == nil {
		return m.install(ctx, bk)
	}
	return m.configure(ctx, inst, bk)
}

// install turns on the Windows feature if needed and installs Sysmon with HomeXDR's
// configuration.
func (m *sysmonManager) install(ctx context.Context, bk *sysmonBackup) sysmonResult {
	if sysmonRestartPending.Load() {
		return sysmonBad(sysmonRestart)
	}
	if sysmonFeatureMissing.Load() {
		return sysmonOK(sysmonNotAvailable)
	}
	fs, err := m.host.feature(ctx)
	if err != nil {
		return sysmonBad("cannot read the state of the Windows Sysmon feature: " + err.Error())
	}
	switch fs {
	case featureMissing:
		sysmonFeatureMissing.Store(true)
		return sysmonOK(sysmonNotAvailable)
	case featureRemoved:
		return sysmonOK("the files of the Windows Sysmon feature were removed from this PC and HomeXDR does not download them; install Sysmon from Sysinternals for cross-process events")
	case featurePending:
		sysmonRestartPending.Store(true)
		return sysmonBad(sysmonRestart)
	case featureDisabled:
		if bk == nil {
			was := false
			bk = &sysmonBackup{FeatureWasEnabled: &was, RulesBefore: rulesNone}
		}
		// The earlier state is on disk before anything changes.
		if err := m.saveBackup(bk); err != nil {
			return sysmonBad(err.Error())
		}
		restart, err := m.host.setFeature(ctx, true)
		if err != nil {
			return sysmonBad("turning on the Windows Sysmon feature failed: " + err.Error())
		}
		bk.EnabledFeature = true
		if err := m.saveBackup(bk); err != nil {
			return sysmonBad(err.Error())
		}
		if restart {
			sysmonRestartPending.Store(true)
			return sysmonBad(sysmonRestart)
		}
	case featureEnabled:
		if bk == nil {
			was := true
			bk = &sysmonBackup{FeatureWasEnabled: &was, RulesBefore: rulesNone}
		}
	}
	bin := m.host.systemBinary()
	if !m.host.exists(bin) {
		return sysmonBad("the Windows Sysmon feature is on but " + bin + " is missing")
	}
	xml, res := m.render(ctx, bin)
	if res != nil {
		return *res
	}
	if err := m.writeFile(m.configPath, xml); err != nil {
		return sysmonBad("cannot write the Sysmon configuration: " + err.Error())
	}
	if err := m.saveBackup(bk); err != nil {
		return sysmonBad(err.Error())
	}
	if err := m.host.sysmon(ctx, bin, "-i", m.configPath); err != nil {
		// A failed install may still have left a service behind: it is HomeXDR's.
		if inst, perr := m.host.probe(); perr == nil && inst != nil {
			bk.InstalledService = true
			_ = m.saveBackup(bk)
		}
		return sysmonBad("installing Sysmon failed: " + err.Error())
	}
	bk.InstalledService, bk.AppliedConfig = true, true
	bk.ConfigHash, bk.ConfigPath = sysmonConfigHash("SHA256", xml), m.configPath
	if err := m.saveBackup(bk); err != nil {
		return sysmonBad(err.Error())
	}
	return sysmonOK("Sysmon installed and configured by HomeXDR (" + sysmonEventsNote + ")")
}

// configure applies HomeXDR's configuration to an installed Sysmon with no rules or with
// HomeXDR's rules, when it differs.
func (m *sysmonManager) configure(ctx context.Context, inst *sysmonInstall, bk *sysmonBackup) sysmonResult {
	const foreign = "Sysmon has a configuration HomeXDR did not write, so HomeXDR left it unchanged; " +
		"the storyline needs events 1 and 5 (process start and exit), 8 (CreateRemoteThread), 10 (ProcessAccess) and 25 (ProcessTampering)"
	rules := m.classify(inst, bk)
	if inst.Binary == "" {
		if rules == rulesForeign {
			return sysmonOK(foreign)
		}
		return sysmonOK("Sysmon runs from " + inst.ImagePath + ", which HomeXDR does not run, so HomeXDR left it unchanged")
	}
	xml, res := m.render(ctx, inst.Binary)
	if rules == rulesForeign {
		// HomeXDR's current configuration is recognised by its hash even without a
		// record of it (backup deleted, data folder moved).
		if res != nil || !sysmonHashMatches(inst.ConfigHash, xml) {
			return sysmonOK(foreign)
		}
		rules = rulesHomeXDR
	}
	if res != nil {
		return *res
	}
	if rules == rulesHomeXDR && sysmonHashMatches(inst.ConfigHash, xml) {
		if bk == nil {
			// HomeXDR's configuration without a record of it (the file was deleted):
			// turning the setting off resets Sysmon to its defaults.
			bk = &sysmonBackup{ServiceWasInstalled: true, RulesBefore: rulesHomeXDR, AppliedConfig: true,
				ConfigHash: inst.ConfigHash, ConfigPath: m.configPath}
			if err := m.saveBackup(bk); err != nil {
				return sysmonBad(err.Error())
			}
		}
		return sysmonOK(managedNote(bk))
	}
	if bk == nil {
		bk = &sysmonBackup{ServiceWasInstalled: true, RulesBefore: rules}
	}
	if err := m.writeFile(m.configPath, xml); err != nil {
		return sysmonBad("cannot write the Sysmon configuration: " + err.Error())
	}
	if err := m.saveBackup(bk); err != nil {
		return sysmonBad(err.Error())
	}
	if err := m.host.sysmon(ctx, inst.Binary, "-c", m.configPath); err != nil {
		return sysmonBad("Sysmon did not accept HomeXDR's configuration: " + err.Error())
	}
	bk.AppliedConfig = true
	bk.ConfigHash, bk.ConfigPath = sysmonConfigHash("SHA256", xml), m.configPath
	if err := m.saveBackup(bk); err != nil {
		return sysmonBad(err.Error())
	}
	return sysmonOK(managedNote(bk))
}

func managedNote(bk *sysmonBackup) string {
	if bk.InstalledService {
		return "Sysmon installed and configured by HomeXDR (" + sysmonEventsNote + ")"
	}
	return "Sysmon configured by HomeXDR (" + sysmonEventsNote + ")"
}

// classify tells what rules an installed Sysmon has. HomeXDR's are recognised by the
// configuration hash it recorded or by the file they were applied from.
func (m *sysmonManager) classify(inst *sysmonInstall, bk *sysmonBackup) string {
	if inst.ConfigHash == "" && !inst.HasRules {
		return rulesNone
	}
	if inst.ConfigHash != "" {
		if bk != nil && bk.ConfigHash != "" && strings.EqualFold(inst.ConfigHash, bk.ConfigHash) {
			return rulesHomeXDR
		}
		if samePath(inst.ConfigFile, m.configPath) || (bk != nil && samePath(inst.ConfigFile, bk.ConfigPath)) {
			return rulesHomeXDR
		}
	}
	return rulesForeign
}

// undo reverts what HomeXDR changed, as recorded in the backup file, and returns what it
// did. Sysmon that someone else has reconfigured since is left as it is.
func (m *sysmonManager) undo(ctx context.Context) (sysmonResult, []string) {
	bk, err := m.loadBackup()
	if err != nil {
		return sysmonBad(err.Error()), nil
	}
	if bk == nil {
		return sysmonOff("off for this host; HomeXDR has not changed Sysmon"), nil
	}
	inst, err := m.host.probe()
	if err != nil {
		return sysmonBad("cannot read the Sysmon installation: " + err.Error()), nil
	}
	var did []string
	if inst != nil {
		rules := m.classify(inst, bk)
		if rules == rulesForeign {
			if err := m.removeBackup(); err != nil {
				return sysmonBad(err.Error()), nil
			}
			return sysmonOff("off for this host; Sysmon now has a configuration HomeXDR did not write, so HomeXDR left it installed and unchanged"), nil
		}
		switch {
		case bk.InstalledService:
			if inst.Binary == "" {
				return sysmonBad("cannot uninstall the Sysmon HomeXDR installed: it now runs from " + inst.ImagePath), nil
			}
			if err := m.host.sysmon(ctx, inst.Binary, "-u"); err != nil {
				return sysmonBad("uninstalling the Sysmon HomeXDR installed failed: " + err.Error()), nil
			}
			did = append(did, "uninstalled the Sysmon it had installed")
		case bk.AppliedConfig && rules == rulesHomeXDR:
			if inst.Binary == "" {
				return sysmonBad("cannot reset Sysmon: it runs from " + inst.ImagePath), nil
			}
			if err := m.host.sysmon(ctx, inst.Binary, "-c", "--"); err != nil {
				return sysmonBad("resetting Sysmon to its default configuration failed: " + err.Error()), nil
			}
			did = append(did, "reset Sysmon to its default configuration")
		}
		bk.InstalledService, bk.AppliedConfig = false, false
		if err := m.saveBackup(bk); err != nil {
			return sysmonBad(err.Error()), did
		}
	}
	if bk.EnabledFeature {
		if now, err := m.host.probe(); err != nil || now != nil {
			// Sysmon is still installed (someone else's now): the feature stays on.
			did = append(did, "left the Windows Sysmon feature on because Sysmon is still installed")
		} else {
			restart, err := m.host.setFeature(ctx, false)
			if err != nil {
				return sysmonBad("turning the Windows Sysmon feature off failed: " + err.Error()), did
			}
			sysmonRestartPending.Store(false)
			if restart {
				did = append(did, "turned the Windows Sysmon feature off (finished at the next restart of Windows)")
			} else {
				did = append(did, "turned the Windows Sysmon feature off")
			}
		}
	}
	if err := m.removeBackup(); err != nil {
		return sysmonBad(err.Error()), did
	}
	if len(did) == 0 {
		return sysmonOff("off for this host; nothing of HomeXDR's to undo"), nil
	}
	return sysmonOff("off for this host; HomeXDR " + strings.Join(did, " and ")), did
}

// render fills in the configuration template for a binary, or says why it cannot be
// used.
func (m *sysmonManager) render(ctx context.Context, bin string) ([]byte, *sysmonResult) {
	v, err := m.schemaFor(ctx, bin)
	if err != nil {
		r := sysmonBad("cannot read the configuration schema of " + bin + ": " + err.Error())
		return nil, &r
	}
	if !schemaAtLeast(v, sysmonMinSchema) {
		r := sysmonBad(fmt.Sprintf("Sysmon at %s is too old for HomeXDR's configuration (schema %s, needs %d.%d or later); update Sysmon",
			bin, v, sysmonMinSchema[0], sysmonMinSchema[1]))
		return nil, &r
	}
	return renderSysmonConfig(v, m.windir, m.programData, m.programFiles, m.agentExe), nil
}

// schemaFor asks the binary for its schema version once per file version.
func (m *sysmonManager) schemaFor(ctx context.Context, bin string) (string, error) {
	fi, err := os.Stat(bin)
	var mod time.Time
	var size int64
	if err == nil {
		mod, size = fi.ModTime(), fi.Size()
	}
	m.schemaMu.Lock()
	if e, ok := m.schemas[bin]; ok && e.mod.Equal(mod) && e.size == size {
		m.schemaMu.Unlock()
		return e.version, nil
	}
	m.schemaMu.Unlock()
	v, err := m.host.schema(ctx, bin)
	if err != nil {
		return "", err
	}
	m.schemaMu.Lock()
	if m.schemas == nil {
		m.schemas = map[string]schemaEntry{}
	}
	m.schemas[bin] = schemaEntry{mod: mod, size: size, version: v}
	m.schemaMu.Unlock()
	return v, nil
}

func (m *sysmonManager) loadBackup() (*sysmonBackup, error) {
	b, err := os.ReadFile(m.backupPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.backupPath, err)
	}
	var bk sysmonBackup
	if err := json.Unmarshal(b, &bk); err != nil {
		return nil, fmt.Errorf("read %s: %w", m.backupPath, err)
	}
	return &bk, nil
}

func (m *sysmonManager) saveBackup(bk *sysmonBackup) error {
	b, _ := json.MarshalIndent(bk, "", "  ")
	if err := os.MkdirAll(filepath.Dir(m.backupPath), 0o700); err != nil {
		return fmt.Errorf("save the Sysmon backup: %w", err)
	}
	if err := m.writeFile(m.backupPath, b); err != nil {
		return fmt.Errorf("save the Sysmon backup: %w", err)
	}
	return nil
}

func (m *sysmonManager) removeBackup() error {
	if err := os.Remove(m.backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the Sysmon backup: %w", err)
	}
	return nil
}

// renderSysmonConfig fills in the embedded configuration. Line endings are normalised so
// every build produces the same file (and hash) for the same values.
func renderSysmonConfig(schema, windir, programData, programFiles, agentExe string) []byte {
	trim := func(p string) string { return strings.TrimRight(p, `\`) }
	s := strings.ReplaceAll(sysmonConfigTemplate, "\r\n", "\n")
	s = strings.NewReplacer(
		"{{schemaversion}}", xmlEscape(schema),
		"{{windir}}", xmlEscape(trim(windir)),
		"{{programdata}}", xmlEscape(trim(programData)),
		"{{programfiles}}", xmlEscape(trim(programFiles)),
		"{{agent}}", xmlEscape(agentExe),
	).Replace(s)
	return []byte(s)
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func xmlEscape(s string) string { return xmlEscaper.Replace(s) }

// sysmonConfigHash formats a configuration's hash the way Sysmon records it.
func sysmonConfigHash(alg string, xml []byte) string {
	var h hash.Hash
	switch strings.ToUpper(alg) {
	case "SHA256":
		h = sha256.New()
	case "SHA1":
		h = sha1.New()
	case "MD5":
		h = md5.New()
	default:
		return ""
	}
	h.Write(xml)
	return strings.ToUpper(alg) + "=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// sysmonHashMatches reports whether Sysmon's recorded hash ("SHA256=<hex>") is the hash
// of xml.
func sysmonHashMatches(recorded string, xml []byte) bool {
	alg, _, ok := strings.Cut(strings.TrimSpace(recorded), "=")
	if !ok {
		return false
	}
	want := sysmonConfigHash(alg, xml)
	return want != "" && strings.EqualFold(want, strings.TrimSpace(recorded))
}

var schemaRe = regexp.MustCompile(`schemaversion="([0-9]+)\.([0-9]+)"`)

// parseSysmonSchema finds the schema version in `sysmon -s` output.
func parseSysmonSchema(out string) (string, bool) {
	m := schemaRe.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1] + "." + m[2], true
}

func schemaAtLeast(v string, min [2]int) bool {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	major, err1 := strconv.Atoi(a)
	minor, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return major > min[0] || (major == min[0] && minor >= min[1])
}

func samePath(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// parseFeatureState reads the state from `dism /English /Get-FeatureInfo` output.
func parseFeatureState(out string) (featureState, error) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) != "State" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "enabled":
			return featureEnabled, nil
		case "disabled":
			return featureDisabled, nil
		case "enable pending", "disable pending":
			return featurePending, nil
		case "disabled with payload removed":
			return featureRemoved, nil
		default:
			return 0, fmt.Errorf("unknown feature state %q", strings.TrimSpace(v))
		}
	}
	return 0, errors.New("DISM did not report the feature state")
}

// sysmonError is the useful part of Sysmon's output for a failed command: the lines
// before the usage text it prints after an error.
func sysmonError(out string) string {
	if i := strings.Index(out, "Usage:"); i >= 0 {
		out = out[:i]
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "System Monitor") &&
			!strings.HasPrefix(l, "Copyright") && !strings.HasPrefix(l, "Sysinternals") && !strings.HasPrefix(l, "By ") {
			lines = append(lines, l)
		}
	}
	return trimOutput(strings.Join(lines, "; "))
}

// The sensor.

// sysmonSensor runs the manager: every sysmonCheckInterval, and at once when it starts
// (the core restarts it when the setting changes).
type sysmonSensor struct {
	enabled bool
	env     platform.Env
	mgr     *sysmonManager

	mu   sync.Mutex
	last sysmonResult
}

// SysmonSensor implements platform.SysmonManager.
func (*Platform) SysmonSensor(enabled bool, env platform.Env) platform.Sensor {
	return &sysmonSensor{enabled: enabled, env: env, mgr: newSysmonManager(env.DataDir)}
}

// Name returns "sysmon".
func (s *sysmonSensor) Name() string { return "sysmon" }

// Run checks now and then every sysmonCheckInterval until ctx is cancelled.
func (s *sysmonSensor) Run(ctx context.Context, _ platform.Emitter) error {
	s.setResult(sysmonOK("checking Sysmon"))
	if !windows.GetCurrentProcessToken().IsElevated() {
		r := sysmonBad("managing Sysmon needs the agent to run as SYSTEM or an administrator")
		if !s.enabled {
			r = sysmonOff("off for this host")
		}
		s.setResult(r)
		<-ctx.Done()
		return nil
	}
	for {
		s.check(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(sysmonCheckInterval):
		}
	}
}

func (s *sysmonSensor) check(ctx context.Context) {
	sysmonMu.Lock()
	defer sysmonMu.Unlock()
	if ctx.Err() != nil {
		return // replaced while waiting for the previous sensor's command
	}
	var r sysmonResult
	if s.enabled {
		r = s.mgr.ensure(ctx)
	} else {
		r, _ = s.mgr.undo(ctx)
	}
	s.mu.Lock()
	changed := r != s.last
	s.mu.Unlock()
	if changed {
		switch {
		case r.err != "":
			s.env.Log.Warn("sysmon: "+r.err, "enabled", s.enabled)
		default:
			s.env.Log.Info("sysmon: "+r.msg, "enabled", s.enabled)
		}
	}
	s.setResult(r)
}

func (s *sysmonSensor) setResult(r sysmonResult) {
	s.mu.Lock()
	s.last = r
	s.mu.Unlock()
}

// Status reports what the last check found.
func (s *sysmonSensor) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.last.state
	if st == "" {
		st = api.SensorRunning
	}
	return api.SensorStatus{Name: "sysmon", Impl: event.ModuleEventLog, State: st, Message: s.last.msg, Error: s.last.err}
}

// restoreSysmon undoes HomeXDR's Sysmon changes for `uninstall` (the service is already
// stopped).
func restoreSysmon() ([]string, error) {
	m := newSysmonManager((&Platform{}).Paths().DataDir)
	if bk, err := m.loadBackup(); err != nil || bk == nil {
		return nil, err
	}
	sysmonMu.Lock()
	defer sysmonMu.Unlock()
	r, did := m.undo(context.Background())
	var out []string
	for _, d := range did {
		out = append(out, "Sysmon: HomeXDR "+d)
	}
	if r.err != "" {
		return out, errors.New("Sysmon: " + r.err)
	}
	if len(did) == 0 && r.msg != "" {
		out = append(out, "Sysmon: "+strings.TrimPrefix(r.msg, "off for this host; "))
	}
	return out, nil
}

// The Windows side.

type winSysmonHost struct {
	sysDir, winDir string
}

func newWinSysmonHost() winSysmonHost {
	sys, err := windows.GetSystemDirectory()
	if err != nil || sys == "" {
		sys = filepath.Join(os.Getenv("SystemRoot"), "System32")
	}
	win, err := windows.GetSystemWindowsDirectory()
	if err != nil || win == "" {
		win = filepath.Dir(sys)
	}
	return winSysmonHost{sysDir: filepath.Clean(sys), winDir: filepath.Clean(win)}
}

func (h winSysmonHost) systemBinary() string { return filepath.Join(h.sysDir, "sysmon.exe") }

func (h winSysmonHost) exists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func (h winSysmonHost) dism() string { return filepath.Join(h.sysDir, "dism.exe") }

func (h winSysmonHost) feature(ctx context.Context) (featureState, error) {
	code, out, err := runSystemTool(ctx, sysmonCmdTimeout, h.dism(), "/English", "/Online", "/Get-FeatureInfo", "/FeatureName:"+sysmonFeature)
	if err != nil {
		return 0, err
	}
	if uint32(code) == dismUnknownFeature {
		return featureMissing, nil
	}
	if code != 0 {
		return 0, fmt.Errorf("DISM exit code 0x%X: %s", uint32(code), trimOutput(out))
	}
	return parseFeatureState(out)
}

func (h winSysmonHost) setFeature(ctx context.Context, on bool) (bool, error) {
	args := []string{"/English", "/Online", "/Disable-Feature", "/FeatureName:" + sysmonFeature, "/NoRestart"}
	if on {
		// LimitAccess: never fetch the feature's files from Windows Update.
		args = []string{"/English", "/Online", "/Enable-Feature", "/FeatureName:" + sysmonFeature, "/LimitAccess", "/NoRestart"}
	}
	code, out, err := runSystemTool(ctx, dismTimeout, h.dism(), args...)
	switch {
	case err != nil:
		return false, err
	case code == 0:
		return false, nil
	case code == exitRestartNeeded:
		return true, nil
	}
	return false, fmt.Errorf("DISM exit code 0x%X: %s", uint32(code), trimOutput(out))
}

func (h winSysmonHost) schema(ctx context.Context, bin string) (string, error) {
	_, out, err := runSystemTool(ctx, sysmonCmdTimeout, bin, "-accepteula", "-s")
	if err != nil {
		return "", err
	}
	// The exit code of -s is not reliable; the schema in the output is what counts.
	v, ok := parseSysmonSchema(out)
	if !ok {
		return "", fmt.Errorf("no schema version in the output of %s -s: %s", filepath.Base(bin), sysmonError(out))
	}
	return v, nil
}

func (h winSysmonHost) sysmon(ctx context.Context, bin string, args ...string) error {
	code, out, err := runSystemTool(ctx, sysmonCmdTimeout, bin, append([]string{"-accepteula"}, args...)...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s exit code %d: %s", filepath.Base(bin), code, sysmonError(out))
	}
	return nil
}

// probe finds Sysmon by its usual service names, then by its registry layout (a service
// whose Parameters name a driver that has Sysmon's ConfigHash value), so a renamed
// install is not mistaken for no install.
func (h winSysmonHost) probe() (*sysmonInstall, error) {
	for _, name := range []string{"Sysmon", "Sysmon64", "Sysmon64a"} {
		inst, err := h.probeService(name)
		if err != nil || inst != nil {
			return inst, err
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if inst, err := h.probeService(name); err == nil && inst != nil {
			return inst, nil
		}
	}
	return nil, nil
}

// probeService returns the Sysmon install behind a service, nil if the service is not
// Sysmon.
func (h winSysmonHost) probeService(name string) (*sysmonInstall, error) {
	const services = `SYSTEM\CurrentControlSet\Services\`
	pk, err := registry.OpenKey(registry.LOCAL_MACHINE, services+name+`\Parameters`, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, nil // a service key the agent cannot read is not Sysmon's
	}
	driver, _, err := pk.GetStringValue("DriverName")
	pk.Close()
	if err != nil || driver == "" || strings.ContainsAny(driver, `\/`) {
		return nil, nil
	}
	dk, err := registry.OpenKey(registry.LOCAL_MACHINE, services+driver+`\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil
	}
	defer dk.Close()
	hash, _, err := dk.GetStringValue("ConfigHash")
	if err != nil {
		return nil, nil // every Sysmon driver has the value, empty without rules
	}
	inst := &sysmonInstall{Service: name, Driver: driver, ConfigHash: strings.TrimSpace(hash)}
	inst.ConfigFile, _, _ = dk.GetStringValue("ConfigFile")
	if rules, _, err := dk.GetBinaryValue("Rules"); err == nil && len(rules) > 0 {
		inst.HasRules = true
	}
	if sk, err := registry.OpenKey(registry.LOCAL_MACHINE, services+name, registry.QUERY_VALUE); err == nil {
		img, _, _ := sk.GetStringValue("ImagePath")
		sk.Close()
		inst.ImagePath = h.imagePath(img)
	}
	if h.runnable(inst.ImagePath) {
		inst.Binary = inst.ImagePath
	}
	return inst, nil
}

// imagePath turns a service ImagePath into a plain path.
func (h winSysmonHost) imagePath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			s = s[1 : end+1]
		}
	} else if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		s = s[:i+4]
	}
	if exp, err := registry.ExpandString(s); err == nil {
		s = exp
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, `\systemroot\`):
		s = filepath.Join(h.winDir, s[len(`\systemroot\`):])
	case strings.HasPrefix(low, `\??\`):
		s = s[4:]
	case !filepath.IsAbs(s) && s != "":
		s = filepath.Join(h.winDir, s)
	}
	return filepath.Clean(s)
}

// runnable reports whether path is a Sysmon executable HomeXDR may run: one of Sysmon's
// own file names, in the Windows or System32 folder (only administrators can write
// there).
func (h winSysmonHost) runnable(path string) bool {
	if path == "" || !h.exists(path) {
		return false
	}
	dir := filepath.Dir(path)
	if !strings.EqualFold(dir, h.sysDir) && !strings.EqualFold(dir, h.winDir) {
		return false
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "sysmon.exe", "sysmon64.exe", "sysmon64a.exe":
		return true
	}
	return false
}

// runSystemTool runs a program by absolute path with a time limit and returns its exit
// code and output. Cancelling ctx does not stop it (a half-done DISM or Sysmon install is
// worse than waiting); the time limit does.
func runSystemTool(ctx context.Context, timeout time.Duration, exe string, args ...string) (int, string, error) {
	if !filepath.IsAbs(exe) {
		return -1, "", fmt.Errorf("%s is not an absolute path", exe)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = filepath.Dir(exe)
	out := &limitedBuffer{max: 256 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	err := cmd.Run()
	text := strings.ReplaceAll(out.String(), "\x00", "")
	if ctx.Err() == context.DeadlineExceeded {
		return -1, text, fmt.Errorf("%s did not finish within %s", filepath.Base(exe), timeout)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), text, nil
	}
	if err != nil {
		return -1, text, err
	}
	return 0, text, nil
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// writeProtected writes a file readable only by SYSTEM and Administrators.
func writeProtected(path string, b []byte) error {
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return (&Platform{}).ProtectPath(path)
}

func knownFolder(id *windows.KNOWNFOLDERID, env, def string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}
