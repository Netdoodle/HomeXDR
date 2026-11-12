//go:build darwin

package darwin

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/collect"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/communityid"
)

// collectors returns every macOS artifact in api.Artifacts.
func collectors(env platform.Env) map[string]platform.Collector {
	hc := newLRU[fileKey, string](4096)
	return map[string]platform.Collector{
		"system.info": collectSystemInfo,
		"process.list": func(ctx context.Context, p map[string]string, emit func(platform.Row) error) error {
			return collectProcesses(ctx, env, hc, p, emit)
		},
		"network.connections": collectConnections,
		"users.list":          collectUsers,
		"users.sessions":      collectSessions,
		"persistence.autoruns": func(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
			return collectAutoruns(ctx, hc, emit)
		},
		"services.list": collectServices,
		"software.list": collectSoftware,
		"file.find":     collect.FileFind,
	}
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func collectSystemInfo(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	h := hostInfo(ctx)
	row := platform.Row{
		"hostname": h.Hostname, "os_name": h.OS.Name, "os_version": h.OS.Version, "kernel": h.OS.Kernel,
		"arch": h.Arch, "cpus": h.CPUs, "memory_bytes": h.MemoryBytes, "domain": "",
		"family": h.OS.Family, "machine_id": h.MachineID, "timezone": h.Timezone, "ips": h.IPs,
	}
	if _, d, ok := strings.Cut(h.FQDN, "."); ok {
		row["domain"] = d
	}
	if h.BootTime != nil {
		row["boot_time"] = rfc3339(*h.BootTime)
	}
	if out, err := command(ctx, "/usr/sbin/sysctl", "-n", "hw.model"); err == nil {
		row["model"] = strings.TrimSpace(string(out))
	}
	if out, err := command(ctx, "/usr/bin/sw_vers", "-buildVersion"); err == nil {
		row["build"] = strings.TrimSpace(string(out))
	}
	return emit(row)
}

func collectProcesses(ctx context.Context, env platform.Env, hc *lru[fileKey, string], p map[string]string, emit func(platform.Row) error) error {
	hash := p["hash"] != "false"
	ps, err := listProcs()
	if err != nil {
		return err
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].PID < ps[j].PID })
	for _, k := range ps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row := platform.Row{
			"pid": k.PID, "ppid": k.PPID, "entity_id": env.EntityID(k.PID, k.Start), "name": k.Comm,
			"start": rfc3339(startTimeFromMicros(k.Start)), "user": users.name(k.RUID),
		}
		if exe, args, err := procArgs(k.PID); err == nil {
			if exe != "" {
				row["executable"] = exe
				row["name"] = baseName(exe)
				if hash {
					if h := fileHash(hc, exe); h != "" {
						row["sha256"] = h
					}
				}
			}
			if len(args) > 0 {
				row["command_line"] = joinArgs(args)
			}
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

func collectConnections(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	entries, err := readSockets(ctx)
	if err != nil {
		return err
	}
	for _, e := range entries {
		state := e.State
		if e.Transport == "udp" {
			state = "UNCONNECTED"
			if e.Remote.IsValid() {
				state = "CONNECTED"
			}
		}
		row := platform.Row{
			"transport": e.Transport, "state": state, "pid": e.PID, "process_name": e.Command,
			"local_ip": e.Local.Addr().String(), "local_port": e.Local.Port(),
		}
		if e.Remote.IsValid() {
			row["remote_ip"], row["remote_port"] = e.Remote.Addr().String(), e.Remote.Port()
			if e.Remote.Port() != 0 && !e.Remote.Addr().IsUnspecified() {
				proto := communityid.ProtoTCP
				if e.Transport == "udp" {
					proto = communityid.ProtoUDP
				}
				row["community_id"] = communityid.Compute(e.Local.Addr(), e.Remote.Addr(), proto, e.Local.Port(), e.Remote.Port())
			}
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// dsUser is a Directory Services account.
type dsUser struct {
	Name, UID, GID, Home, Shell, Gecos string
}

func directoryUsers(ctx context.Context) ([]dsUser, map[string][]string) {
	var us []dsUser
	seen := map[string]bool{}
	if out, err := command(ctx, "/usr/bin/dscacheutil", "-q", "user"); err == nil {
		for _, r := range parseDSCache(out) {
			if r["name"] == "" || seen[r["name"]] {
				continue
			}
			seen[r["name"]] = true
			us = append(us, dsUser{Name: r["name"], UID: r["uid"], GID: r["gid"], Home: r["dir"], Shell: r["shell"], Gecos: r["gecos"]})
		}
	}
	// group name -> members, plus "gid:<n>" -> group name for primary groups.
	groups := map[string][]string{}
	if out, err := command(ctx, "/usr/bin/dscacheutil", "-q", "group"); err == nil {
		for _, r := range parseDSCache(out) {
			if r["name"] == "" {
				continue
			}
			groups["gid:"+r["gid"]] = []string{r["name"]}
			if _, ok := groups[r["name"]]; !ok {
				groups[r["name"]] = nil
			}
			groups[r["name"]] = append(groups[r["name"]], strings.Fields(r["users"])...)
		}
	}
	return us, groups
}

func collectUsers(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	us, groups := directoryUsers(ctx)
	for _, u := range us {
		var gs []string
		if g := groups["gid:"+u.GID]; len(g) > 0 {
			gs = append(gs, g[0])
		}
		for name, members := range groups {
			if strings.HasPrefix(name, "gid:") {
				continue
			}
			for _, m := range members {
				if m == u.Name && (len(gs) == 0 || gs[0] != name) {
					gs = append(gs, name)
				}
			}
		}
		sort.Strings(gs[min(1, len(gs)):])
		admin := false
		for _, g := range gs {
			if g == "admin" {
				admin = true
			}
		}
		noLogin := strings.HasSuffix(u.Shell, "/false") || strings.HasSuffix(u.Shell, "/nologin")
		uid, err := strconv.Atoi(u.UID)
		row := platform.Row{
			"name": u.Name, "id": u.UID, "groups": gs, "shell": u.Shell, "home": u.Home,
			"admin": admin, "disabled": noLogin, "gid": u.GID, "gecos": u.Gecos,
			// Accounts below 500 and the _service accounts are macOS's own.
			"system": strings.HasPrefix(u.Name, "_") || err == nil && uid < 500,
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

func collectSessions(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	out, err := command(ctx, "/usr/bin/who")
	if err != nil {
		return err
	}
	for _, e := range parseWho(out, time.Now()) {
		typ := "tty"
		switch {
		case e.Line == "console":
			typ = "console"
		case e.Host != "":
			typ = "remote"
		}
		row := platform.Row{"user": e.User, "session": e.Line, "type": typ, "started": rfc3339(e.Time)}
		if e.Host != "" {
			row["source_ip"] = e.Host
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// homes returns the home directories under /Users plus root's.
func homes() map[string]string {
	out := map[string]string{"root": "/var/root"}
	ents, _ := os.ReadDir("/Users")
	for _, e := range ents {
		if e.IsDir() && e.Name() != "Shared" && !strings.HasPrefix(e.Name(), ".") {
			out[e.Name()] = filepath.Join("/Users", e.Name())
		}
	}
	return out
}

func plistFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.plist"))
	return m
}

func collectAutoruns(ctx context.Context, hc *lru[fileKey, string], emit func(platform.Row) error) error {
	var rows []platform.Row
	add := func(r platform.Row, hashPath string) {
		if hashPath != "" {
			if h := fileHash(hc, hashPath); h != "" {
				r["sha256"] = h
			}
		}
		rows = append(rows, r)
	}
	disabled := map[string]bool{}
	if out, err := command(ctx, "/bin/launchctl", "print-disabled", "system"); err == nil {
		disabled = parsePrintDisabled(out)
	}
	launchd := func(typ, dir, owner string) {
		for _, p := range plistFiles(dir) {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			j, err := parseLaunchdJob(b)
			if err != nil {
				add(autorunRow(typ, p, filepath.Base(p), "(unreadable: "+err.Error()+")", owner, true), "")
				continue
			}
			user := j.User
			if user == "" {
				user = owner
			}
			r := autorunRow(typ, p, j.Label, j.command(), user, !j.Disabled && !disabled[j.Label])
			r["run_at_load"], r["keep_alive"] = j.RunAtLoad, j.KeepAlive
			if len(j.Triggers) > 0 {
				r["triggers"] = j.Triggers
			}
			add(r, j.Program)
		}
	}
	launchd("launch_daemon", "/Library/LaunchDaemons", "root")
	launchd("launch_agent", "/Library/LaunchAgents", "")
	hs := homes()
	names := make([]string, 0, len(hs))
	for n := range hs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		launchd("launch_agent", filepath.Join(hs[n], "Library/LaunchAgents"), n)
	}
	// Legacy startup items (ignored since 10.10, but still a place malware drops files).
	if ents, err := os.ReadDir("/Library/StartupItems"); err == nil {
		for _, e := range ents {
			p := filepath.Join("/Library/StartupItems", e.Name())
			add(autorunRow("startup_item", p, e.Name(), filepath.Join(p, e.Name()), "root", true), filepath.Join(p, e.Name()))
		}
	}
	// cron: /etc/crontab and per-user crontabs.
	if b, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, e := range parseCrontab(b, true) {
			r := autorunRow("cron", "/etc/crontab", e.Schedule, e.Command, e.User, true)
			add(r, commandBinary(e.Command))
		}
	}
	if ents, err := os.ReadDir("/usr/lib/cron/tabs"); err == nil {
		for _, ent := range ents {
			p := filepath.Join("/usr/lib/cron/tabs", ent.Name())
			if b, err := os.ReadFile(p); err == nil {
				for _, e := range parseCrontab(b, false) {
					add(autorunRow("cron", p, e.Schedule, e.Command, ent.Name(), true), commandBinary(e.Command))
				}
			}
		}
	}
	// Shell start-up files and SSH keys.
	for _, p := range []string{"/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/profile", "/etc/bashrc"} {
		if _, err := os.Stat(p); err == nil {
			add(autorunRow("shell_profile", p, filepath.Base(p), p, "root", true), p)
		}
	}
	for _, n := range names {
		home := hs[n]
		for _, f := range []string{".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bashrc", ".profile"} {
			p := filepath.Join(home, f)
			if _, err := os.Stat(p); err == nil {
				add(autorunRow("shell_profile", p, f, p, n, true), p)
			}
		}
		for _, f := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			p := filepath.Join(home, f)
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(bytes.NewReader(b))
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				opts, typ, fp, comment, ok := authorizedKey(line)
				if !ok {
					continue
				}
				cmd := typ + " " + fp
				if opts != "" {
					cmd = opts + " " + cmd
				}
				add(autorunRow("authorized_keys", p, comment, cmd, n, true), "")
			}
		}
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func collectServices(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	out, err := command(ctx, "/bin/launchctl", "list")
	if err != nil {
		return err
	}
	running := parseLaunchctlList(out)
	jobs := map[string]launchdJob{}
	paths := map[string]string{}
	for _, dir := range []string{"/System/Library/LaunchDaemons", "/Library/LaunchDaemons"} {
		for _, p := range plistFiles(dir) {
			if b, err := os.ReadFile(p); err == nil {
				if j, err := parseLaunchdJob(b); err == nil && j.Label != "" {
					jobs[j.Label], paths[j.Label] = j, p
				}
			}
		}
	}
	labels := make([]string, 0, len(running))
	for l := range running {
		labels = append(labels, l)
	}
	for l := range jobs {
		if _, ok := running[l]; !ok {
			labels = append(labels, l)
		}
	}
	sort.Strings(labels)
	for _, l := range labels {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, loaded := running[l]
		state := "stopped"
		switch {
		case pid > 0:
			state = "running"
		case !loaded:
			state = "not loaded"
		}
		row := platform.Row{"name": l, "display_name": l, "state": state, "account": "root"}
		if pid > 0 {
			row["pid"] = pid
		}
		if j, ok := jobs[l]; ok {
			start := "manual"
			switch {
			case j.Disabled:
				start = "disabled"
			case j.RunAtLoad || j.KeepAlive:
				start = "auto"
			case len(j.Triggers) > 0:
				start = "on_demand"
			}
			row["start_type"], row["path"], row["plist"] = start, j.Program, paths[l]
			if j.User != "" {
				row["account"] = j.User
			}
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

func collectSoftware(ctx context.Context, _ map[string]string, emit func(platform.Row) error) error {
	var rows []platform.Row
	seen := map[string]bool{}
	app := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		b, err := os.ReadFile(filepath.Join(p, "Contents", "Info.plist"))
		if err != nil {
			return
		}
		v, err := decodePlist(b)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			return
		}
		name := plistString(m, "CFBundleDisplayName")
		if name == "" {
			name = plistString(m, "CFBundleName")
		}
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(p), ".app")
		}
		version := plistString(m, "CFBundleShortVersionString")
		if version == "" {
			version = plistString(m, "CFBundleVersion")
		}
		id := plistString(m, "CFBundleIdentifier")
		r := platform.Row{"name": name, "version": version, "vendor": bundleVendor(id), "type": "app", "bundle_id": id, "path": p}
		if fi, err := os.Stat(p); err == nil {
			r["install_date"] = rfc3339(fi.ModTime())
		}
		rows = append(rows, r)
	}
	dirs := []string{"/Applications", "/Applications/Utilities", "/System/Applications", "/System/Applications/Utilities"}
	for _, home := range homes() {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	for _, d := range dirs {
		apps, _ := filepath.Glob(filepath.Join(d, "*.app"))
		nested, _ := filepath.Glob(filepath.Join(d, "*", "*.app")) // vendor folders
		for _, p := range append(apps, nested...) {
			app(p)
		}
	}
	// Installer package receipts.
	receipts, _ := filepath.Glob("/var/db/receipts/*.plist")
	for _, p := range receipts {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := decodePlist(b)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			continue
		}
		id := plistString(m, "PackageIdentifier")
		if id == "" {
			continue
		}
		r := platform.Row{"name": id, "version": plistString(m, "PackageVersion"), "vendor": bundleVendor(id), "type": "pkg"}
		if t, ok := m["InstallDate"].(time.Time); ok {
			r["install_date"] = rfc3339(t)
		}
		rows = append(rows, r)
	}
	// Homebrew formulae and casks (Apple silicon and Intel prefixes).
	for _, base := range []string{"/opt/homebrew", "/usr/local"} {
		for _, kind := range []string{"Cellar", "Caskroom"} {
			vers, _ := filepath.Glob(filepath.Join(base, kind, "*", "*"))
			for _, p := range vers {
				if strings.HasPrefix(filepath.Base(p), ".") {
					continue
				}
				r := platform.Row{"name": filepath.Base(filepath.Dir(p)), "version": filepath.Base(p), "type": "brew"}
				if kind == "Caskroom" {
					r["type"] = "brew_cask"
				}
				if fi, err := os.Stat(p); err == nil {
					r["install_date"] = rfc3339(fi.ModTime())
				}
				rows = append(rows, r)
			}
		}
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}
