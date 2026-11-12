package darwin

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// autorunRow builds a persistence.autoruns row.
func autorunRow(typ, location, name, command, user string, enabled bool) platform.Row {
	return platform.Row{
		"type": typ, "location": location, "name": name, "command": command,
		"user": user, "enabled": enabled, "signed": false,
	}
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

// crontabEntry is one job line of a crontab.
type crontabEntry struct {
	Schedule, User, Command string
}

// parseCrontab returns the jobs of a crontab. System crontabs (/etc/crontab) have a
// user column; user crontabs (/usr/lib/cron/tabs/<user>) do not.
func parseCrontab(b []byte, system bool) []crontabEntry {
	var out []crontabEntry
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if strings.Contains(f[0], "=") {
			continue // VAR=value
		}
		n := 5
		if strings.HasPrefix(f[0], "@") {
			n = 1 // @reboot, @daily, ...
		}
		var e crontabEntry
		if system {
			if len(f) <= n+1 {
				continue
			}
			e = crontabEntry{Schedule: strings.Join(f[:n], " "), User: f[n], Command: strings.Join(f[n+1:], " ")}
		} else {
			if len(f) <= n {
				continue
			}
			e = crontabEntry{Schedule: strings.Join(f[:n], " "), Command: strings.Join(f[n:], " ")}
		}
		out = append(out, e)
	}
	return out
}

// parsePrintDisabled parses `launchctl print-disabled system`: lines like
// `"com.example.job" => disabled` (or `=> true` on older releases).
func parsePrintDisabled(b []byte) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok {
			continue
		}
		label := strings.Trim(strings.TrimSpace(k), `"`)
		v = strings.TrimSpace(v)
		out[label] = v == "disabled" || v == "true"
	}
	return out
}

// commandBinary returns the program of a command line, for hashing.
func commandBinary(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 || !strings.HasPrefix(f[0], "/") {
		return ""
	}
	return strings.Trim(f[0], `"`)
}

// bundleVendor guesses a vendor from a bundle identifier: com.apple.* is Apple; for
// others the second component ("com.google.Chrome" -> "google").
func bundleVendor(id string) string {
	if strings.HasPrefix(id, "com.apple.") {
		return "Apple"
	}
	parts := strings.Split(id, ".")
	if len(parts) >= 3 {
		return parts[1]
	}
	return ""
}
