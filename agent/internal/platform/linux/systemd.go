//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// ---- services.list ----

// parseSystemctlShow parses `systemctl show` output: Key=Value blocks separated by blank
// lines, one block per unit.
func parseSystemctlShow(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// execStartCommand extracts the command from systemctl's ExecStart property, e.g.
// "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; ... }".
func execStartCommand(v string) string {
	if i := strings.Index(v, "argv[]="); i >= 0 {
		rest := v[i+len("argv[]="):]
		if j := strings.Index(rest, " ;"); j >= 0 {
			rest = rest[:j]
		}
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(v)
}

func startType(unitFileState string) string {
	switch unitFileState {
	case "enabled", "enabled-runtime", "alias":
		return "auto"
	case "disabled", "masked", "masked-runtime", "bad":
		return "disabled"
	case "":
		return ""
	}
	return "manual" // static, indirect, generated, transient
}

func collectServices(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	sc, err := exec.LookPath("systemctl")
	if err != nil || !systemdRunning() {
		return collectInitd(emit)
	}
	// Unit files (installed services, including ones not loaded right now).
	files := map[string]string{}
	if out, err := exec.CommandContext(ctx, sc, "list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain").Output(); err == nil {
		s := bufio.NewScanner(bytes.NewReader(out))
		for s.Scan() {
			f := strings.Fields(s.Text())
			if len(f) >= 2 && !strings.Contains(f[0], "@.") {
				files[f[0]] = f[1]
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	// Loaded units (instances of templates show up here too).
	if out, err := exec.CommandContext(ctx, sc, "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain").Output(); err == nil {
		s := bufio.NewScanner(bytes.NewReader(out))
		for s.Scan() {
			f := strings.Fields(s.Text())
			if len(f) >= 1 && strings.HasSuffix(f[0], ".service") {
				if _, ok := files[f[0]]; !ok {
					files[f[0]] = ""
					names = append(names, f[0])
				}
			}
		}
	}
	sort.Strings(names)
	props := "Id,Description,ActiveState,SubState,UnitFileState,ExecStart,User,FragmentPath"
	for len(names) > 0 {
		batch := names[:min(len(names), 200)]
		names = names[len(batch):]
		out, err := exec.CommandContext(ctx, sc, append([]string{"show", "--no-pager", "-p", props, "--"}, batch...)...).Output()
		if err != nil {
			return fmt.Errorf("systemctl show: %w", err)
		}
		for _, u := range parseSystemctlShow(out) {
			state := u["ActiveState"]
			if sub := u["SubState"]; sub != "" && sub != state {
				state += " (" + sub + ")"
			}
			ufs := u["UnitFileState"]
			if ufs == "" {
				ufs = files[u["Id"]]
			}
			account := u["User"]
			if account == "" {
				account = "root"
			}
			row := platform.Row{
				"name": u["Id"], "display_name": u["Description"], "state": state,
				"start_type": startType(ufs), "path": execStartCommand(u["ExecStart"]), "account": account,
				"unit_file": u["FragmentPath"],
			}
			if err := emit(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectInitd(emit func(platform.Row) error) error {
	ents, err := os.ReadDir("/etc/init.d")
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "README" {
			continue
		}
		p := filepath.Join("/etc/init.d", e.Name())
		if err := emit(platform.Row{"name": e.Name(), "path": p, "start_type": "", "state": "", "account": "root"}); err != nil {
			return err
		}
	}
	return nil
}

func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// ---- service integration ----

const (
	unitName = "homexdr-agent.service"
	unitPath = "/etc/systemd/system/" + unitName
)

func unitFile(exe string) string {
	return fmt.Sprintf(`# Installed by homexdr-agent. Remove with: homexdr-agent uninstall
[Unit]
Description=HomeXDR Agent (endpoint telemetry and response)
Documentation=https://github.com/Netdoodle/homexdr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=5
# eBPF, fanotify and nftables need root.
User=root
# Kernels before 5.11 account BPF maps against RLIMIT_MEMLOCK.
LimitMEMLOCK=infinity
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
`, systemdQuote(exe))
}

// systemdQuote quotes a path for ExecStart if it contains spaces.
func systemdQuote(s string) string {
	if strings.ContainsAny(s, " \t\"'\\") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	return s
}

type systemdService struct{}

func systemctl(args ...string) error {
	sc, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("systemctl not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, sc, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Install writes the unit file and enables and starts it.
func (systemdService) Install(exe string) error {
	if !systemdRunning() {
		return fmt.Errorf("systemd is not running; start `%s run` from your init system instead: %w", exe, platform.ErrUnsupported)
	}
	if os.Geteuid() != 0 {
		return errors.New("installing the service requires root")
	}
	if err := os.WriteFile(unitPath, []byte(unitFile(exe)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", unitName)
}

// Uninstall stops, disables and removes the unit.
func (systemdService) Uninstall() error {
	if _, err := os.Stat(unitPath); errors.Is(err, os.ErrNotExist) {
		return platform.ErrUnsupported // nothing installed
	}
	if os.Geteuid() != 0 {
		return errors.New("removing the service requires root")
	}
	var errs []error
	if systemdRunning() {
		if err := systemctl("disable", "--now", unitName); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if systemdRunning() {
		if err := systemctl("daemon-reload"); err != nil {
			errs = append(errs, err)
		}
		_ = systemctl("reset-failed", unitName)
	}
	return errors.Join(errs...)
}

// Status reports the unit's active state.
func (systemdService) Status() (string, error) {
	if _, err := os.Stat(unitPath); err != nil {
		return "not installed", nil
	}
	sc, err := exec.LookPath("systemctl")
	if err != nil {
		return "installed (systemctl not found)", nil
	}
	out, _ := exec.Command(sc, "is-active", unitName).Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		s = "unknown"
	}
	return s, nil
}

// RunAsService: under systemd the agent is a plain foreground process (Type=simple) that
// stops on SIGTERM, so there is nothing special to do.
func (systemdService) RunAsService(func(context.Context) error) (bool, error) { return false, nil }
