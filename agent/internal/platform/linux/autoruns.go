//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// autorunRow builds a persistence.autoruns row.
func autorunRow(typ, location, name, command, user string, enabled bool) platform.Row {
	return platform.Row{
		"type": typ, "location": location, "name": name, "command": command,
		"user": user, "enabled": enabled, "signed": false,
	}
}

// fileHash hashes a file with the shared cache (scripts and binaries named by entries).
func fileHash(hc *lru[fileKey, string], p string) string {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxHashBytes {
		return ""
	}
	key, ok := keyOf(fi)
	if ok {
		if h, hit := hc.get(key); hit {
			return h
		}
	}
	h, err := fsutil.SHA256File(p, maxHashBytes)
	if err == nil && ok {
		hc.put(key, h)
	}
	return h
}

// commandBinary returns the program of a command line, for hashing.
func commandBinary(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	b := strings.TrimLeft(f[0], "-@+!:") // systemd ExecStart prefixes
	if filepath.IsAbs(b) {
		return b
	}
	return ""
}

// parseCrontab returns (schedule, user, command) entries. System crontabs (/etc/crontab,
// /etc/cron.d) have a user column; user crontabs do not.
func parseCrontab(b []byte, hasUser bool, owner string) [][3]string {
	var out [][3]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "@") {
			continue // environment assignment
		}
		nSched := 5
		if strings.HasPrefix(line, "@") {
			nSched = 1
		}
		need := nSched + 1
		if hasUser {
			need++
		}
		if len(f) < need {
			continue
		}
		sched := strings.Join(f[:nSched], " ")
		user := owner
		rest := f[nSched:]
		if hasUser {
			user, rest = rest[0], rest[1:]
		}
		out = append(out, [3]string{sched, user, strings.Join(rest, " ")})
	}
	return out
}

// parseUnit extracts ExecStart and User from a systemd unit file.
func parseUnit(b []byte) (execStart, user string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok {
			switch strings.TrimSpace(k) {
			case "ExecStart":
				if execStart == "" {
					execStart = strings.TrimSpace(v)
				}
			case "User":
				user = strings.TrimSpace(v)
			}
		}
	}
	return
}

// parseDesktopExec returns the Exec= line of a .desktop file and whether it is hidden.
func parseDesktopExec(b []byte) (string, bool) {
	var exe string
	hidden := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Exec="):
			exe = strings.TrimPrefix(line, "Exec=")
		case line == "Hidden=true" || line == "X-GNOME-Autostart-enabled=false":
			hidden = true
		}
	}
	return exe, !hidden
}

// authorizedKey describes one authorized_keys line: options, key type, fingerprint and
// comment. The fingerprint is OpenSSH's "SHA256:<base64>".
func authorizedKey(line string) (opts, keyType, fp, comment string, ok bool) {
	f := strings.Fields(line)
	for i := 0; i < len(f); i++ {
		if strings.HasPrefix(f[i], "ssh-") || strings.HasPrefix(f[i], "ecdsa-") || strings.HasPrefix(f[i], "sk-") {
			if i+1 >= len(f) {
				return "", "", "", "", false
			}
			blob, err := base64.StdEncoding.DecodeString(f[i+1])
			if err != nil {
				return "", "", "", "", false
			}
			sum := sha256.Sum256(blob)
			return strings.Join(f[:i], " "), f[i], "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
				strings.Join(f[i+2:], " "), true
		}
	}
	return "", "", "", "", false
}

func listDir(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
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

	// cron
	if b, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, e := range parseCrontab(b, true, "") {
			add(autorunRow("cron", "/etc/crontab", e[0], e[2], e[1], true), commandBinary(e[2]))
		}
	}
	for _, p := range listDir("/etc/cron.d") {
		if b, err := os.ReadFile(p); err == nil {
			for _, e := range parseCrontab(b, true, "") {
				add(autorunRow("cron", p, e[0], e[2], e[1], true), commandBinary(e[2]))
			}
		}
	}
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		for _, p := range listDir(dir) {
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				continue
			}
			if b, err := os.ReadFile(p); err == nil {
				for _, e := range parseCrontab(b, false, filepath.Base(p)) {
					add(autorunRow("cron", p, e[0], e[2], e[1], true), commandBinary(e[2]))
				}
			}
		}
	}
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		for _, p := range listDir("/etc/cron." + period) {
			add(autorunRow("cron_script", "/etc/cron."+period, filepath.Base(p), p, "root", true), p)
		}
	}

	// systemd: units in /etc (admin-installed) and every enabled unit (.wants links).
	enabled := map[string]bool{}
	var wantsDirs []string
	for _, base := range []string{"/etc/systemd/system", "/etc/systemd/user"} {
		for _, p := range listDir(base) {
			if strings.HasSuffix(p, ".wants") {
				wantsDirs = append(wantsDirs, p)
			}
		}
	}
	for _, d := range wantsDirs {
		for _, l := range listDir(d) {
			enabled[filepath.Base(l)] = true
		}
	}
	seenUnit := map[string]bool{}
	addUnit := func(path, scope string) {
		link := filepath.Base(path)
		if !(strings.HasSuffix(link, ".service") || strings.HasSuffix(link, ".timer")) {
			return
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || real == "/dev/null" || seenUnit[real] {
			return // masked, dangling, or already listed (aliases and .wants links)
		}
		seenUnit[real] = true
		b, err := os.ReadFile(real)
		if err != nil {
			return
		}
		cmd, user := parseUnit(b)
		if user == "" {
			user = scope
		}
		name := filepath.Base(real)
		add(autorunRow("systemd", real, name, cmd, user, enabled[name] || enabled[link]), commandBinary(cmd))
	}
	for _, p := range listDir("/etc/systemd/system") {
		addUnit(p, "root")
	}
	for _, d := range wantsDirs {
		for _, l := range listDir(d) {
			addUnit(l, "root")
		}
	}

	// rc.local, init scripts, ld.so.preload, module autoload
	if _, err := os.Stat("/etc/rc.local"); err == nil {
		add(autorunRow("rc_local", "/etc/rc.local", "rc.local", "/etc/rc.local", "root", true), "/etc/rc.local")
	}
	for _, p := range listDir("/etc/init.d") {
		add(autorunRow("initd", "/etc/init.d", filepath.Base(p), p, "root", true), p)
	}
	if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		for _, lib := range strings.Fields(string(b)) {
			if !strings.HasPrefix(lib, "#") {
				add(autorunRow("ld_preload", "/etc/ld.so.preload", filepath.Base(lib), lib, "", true), lib)
			}
		}
	}
	for _, p := range append([]string{"/etc/modules"}, listDir("/etc/modules-load.d")...) {
		if b, err := os.ReadFile(p); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				m := strings.TrimSpace(sc.Text())
				if m != "" && !strings.HasPrefix(m, "#") && !strings.HasPrefix(m, ";") {
					add(autorunRow("kernel_module", p, m, "modprobe "+m, "root", true), "")
				}
			}
		}
	}

	// System-wide shell profiles and XDG autostart.
	for _, p := range append([]string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/environment"}, listDir("/etc/profile.d")...) {
		if _, err := os.Stat(p); err == nil {
			add(autorunRow("shell_profile", p, filepath.Base(p), p, "", true), p)
		}
	}
	for _, p := range listDir("/etc/xdg/autostart") {
		if b, err := os.ReadFile(p); err == nil && strings.HasSuffix(p, ".desktop") {
			cmd, on := parseDesktopExec(b)
			add(autorunRow("xdg_autostart", p, filepath.Base(p), cmd, "", on), commandBinary(cmd))
		}
	}

	// Per-user locations.
	if pb, err := os.ReadFile(passwdFile); err == nil {
		seenHome := map[string]bool{}
		for _, u := range parsePasswd(pb) {
			if u.Home == "" || u.Home == "/" || seenHome[u.Home] {
				continue
			}
			if st, err := os.Stat(u.Home); err != nil || !st.IsDir() {
				continue
			}
			seenHome[u.Home] = true
			for _, f := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".bash_logout"} {
				p := filepath.Join(u.Home, f)
				if _, err := os.Stat(p); err == nil {
					add(autorunRow("shell_profile", p, f, p, u.Name, true), p)
				}
			}
			for _, f := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
				p := filepath.Join(u.Home, f)
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
						cmd = opts + " " + cmd // e.g. a forced command="..."
					}
					add(autorunRow("authorized_keys", p, comment, cmd, u.Name, true), "")
				}
			}
			for _, p := range listDir(filepath.Join(u.Home, ".config/autostart")) {
				if b, err := os.ReadFile(p); err == nil && strings.HasSuffix(p, ".desktop") {
					cmd, on := parseDesktopExec(b)
					add(autorunRow("xdg_autostart", p, filepath.Base(p), cmd, u.Name, on), commandBinary(cmd))
				}
			}
			for _, p := range listDir(filepath.Join(u.Home, ".config/systemd/user")) {
				addUnit(p, u.Name)
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
