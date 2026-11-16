package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DecoyConfig configures decoy (honeypot) files: plausible bait files the agent places
// in user folders and watches. Anything that changes, deletes, renames or (on Linux)
// opens one raises an event (event.module=decoy). See docs/decoys.md.
type DecoyConfig struct {
	// Enabled is the global switch. Host groups can override it per host; the server
	// sends a host's effective value in HeartbeatResponse.DecoysEnabled.
	Enabled bool `json:"enabled"`
	// CheckIntervalSec is how often every decoy is checked (minimum 15, default 60).
	CheckIntervalSec int `json:"check_interval_sec"`
	// Files lists where decoys go, per OS. Each agent uses the entries for its own OS.
	// A config without this field (saved before it existed) gets DefaultDecoyFiles plus
	// its old "extra" paths, see UnmarshalJSON.
	Files []DecoyFile `json:"files"`
}

// DecoyFile is one decoy location.
type DecoyFile struct {
	// OS is DecoyOSWindows, DecoyOSLinux or DecoyOSDarwin.
	OS string `json:"os"`
	// Path is an absolute file path, or one starting with DecoyHome followed by the OS's
	// separator ({home}\Documents\Passwords.xlsx): one decoy in each real user's home
	// folder. See DecoyPathProblem for the rules.
	Path string `json:"path"`
	// Hidden sets the hidden attribute (Windows) or flag (macOS). Linux has none: a file
	// name starting with a dot is how Linux hides files.
	Hidden bool `json:"hidden"`
}

// Decoy limits and names.
const (
	DecoyDefaultIntervalSec = 60
	DecoyMinIntervalSec     = 15
	DecoyMaxIntervalSec     = 24 * 3600
	DecoyMaxFiles           = 64
	DecoyMaxPathLen         = 260
	// DecoyHome at the start of a path stands for each real user's home folder.
	DecoyHome      = "{home}"
	DecoyOSWindows = "windows"
	DecoyOSLinux   = "linux"
	DecoyOSDarwin  = "darwin"
)

// DefaultDecoyFiles is where decoys go unless an administrator changes the list.
func DefaultDecoyFiles() []DecoyFile {
	return []DecoyFile{
		{OS: DecoyOSWindows, Path: `{home}\Documents\Passwords.xlsx`},
		{OS: DecoyOSWindows, Path: `C:\ProgramData\Backup\credentials.csv`},
		{OS: DecoyOSLinux, Path: "{home}/Documents/passwords.txt"},
		{OS: DecoyOSLinux, Path: "{home}/.aws/credentials.bak"},
		{OS: DecoyOSLinux, Path: "/var/backups/db-credentials.sql"},
		{OS: DecoyOSDarwin, Path: "{home}/Documents/Passwords.txt"},
	}
}

// DecoyFilesFromExtra converts the "extra" paths of configs saved before DecoyFile
// existed: a path with a drive letter is a Windows path, any other one is used on Linux
// and macOS.
func DecoyFilesFromExtra(extra []string) []DecoyFile {
	var out []DecoyFile
	for _, p := range extra {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case len(p) >= 2 && isDriveLetter(p[0]) && p[1] == ':':
			out = append(out, DecoyFile{OS: DecoyOSWindows, Path: p})
		default:
			out = append(out, DecoyFile{OS: DecoyOSLinux, Path: p}, DecoyFile{OS: DecoyOSDarwin, Path: p})
		}
	}
	return out
}

// UnmarshalJSON reads a decoy section, including those saved before Files existed: a
// missing (or null) "files" means the defaults, and the old "extra" paths are converted
// and added.
func (c *DecoyConfig) UnmarshalJSON(b []byte) error {
	var aux struct {
		Enabled          bool         `json:"enabled"`
		CheckIntervalSec int          `json:"check_interval_sec"`
		Files            *[]DecoyFile `json:"files"`
		Extra            []string     `json:"extra"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	c.Enabled, c.CheckIntervalSec = aux.Enabled, aux.CheckIntervalSec
	if aux.Files == nil {
		c.Files = DefaultDecoyFiles()
	} else {
		c.Files = append([]DecoyFile{}, (*aux.Files)...)
	}
	for _, f := range DecoyFilesFromExtra(aux.Extra) {
		if !c.HasFile(f.OS, f.Path) {
			c.Files = append(c.Files, f)
		}
	}
	return nil
}

// HasFile reports whether the list has an entry for os and path.
func (c DecoyConfig) HasFile(os, path string) bool {
	for _, f := range c.Files {
		if f.OS == os && f.Path == path {
			return true
		}
	}
	return false
}

// DecoySeparator is the path separator of a decoy entry's OS.
func DecoySeparator(os string) string {
	if os == DecoyOSWindows {
		return `\`
	}
	return "/"
}

func isDriveLetter(c byte) bool { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }

// DecoyPathProblem says what is wrong with a decoy path for an OS, or returns "" when it
// is usable. The console checks the same rules (web/src/lib/agentConfig.ts):
//
//   - absolute (/srv/x.txt, C:\Shares\x.csv) or starting with {home} and the OS's
//     separator ({home}/Documents/x.txt, {home}\Documents\x.xlsx);
//   - the OS's separator only (\ on Windows, / on Linux and macOS);
//   - no wildcards, no "." or ".." folders, no empty folder names, and a file name at the
//     end; on Windows nothing after the drive letter may contain a colon (no alternate
//     data streams) or < > " |;
//   - at most DecoyMaxPathLen characters.
func DecoyPathProblem(os, p string) string {
	if os != DecoyOSWindows && os != DecoyOSLinux && os != DecoyOSDarwin {
		return "unknown platform " + fmt.Sprintf("%q", os)
	}
	if p == "" {
		return "enter a path"
	}
	if len([]rune(p)) > DecoyMaxPathLen {
		return fmt.Sprintf("is longer than %d characters", DecoyMaxPathLen)
	}
	if strings.ContainsAny(p, "*?") {
		return "must not contain wildcards (* or ?)"
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "must not contain control characters"
		}
	}
	sep := DecoySeparator(os)
	var rest string
	if os == DecoyOSWindows {
		if strings.Contains(p, "/") {
			return `use \ as the separator on Windows`
		}
		if strings.ContainsAny(p, `<>"|`) {
			return `must not contain < > " or |`
		}
		switch {
		case strings.HasPrefix(p, DecoyHome+sep):
			rest = p[len(DecoyHome)+1:]
		case len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && p[2] == '\\':
			rest = p[3:]
		default:
			return `must start with {home}\ or a drive such as C:\`
		}
		if strings.Contains(rest, ":") {
			return "must not contain a colon after the drive letter"
		}
	} else {
		if strings.Contains(p, `\`) {
			return "use / as the separator on Linux and macOS"
		}
		switch {
		case strings.HasPrefix(p, DecoyHome+sep):
			rest = p[len(DecoyHome)+1:]
		case strings.HasPrefix(p, "/"):
			rest = p[1:]
		default:
			return "must start with {home}/ or /"
		}
	}
	if strings.Contains(rest, DecoyHome) {
		return "{home} can only be at the start"
	}
	segs := strings.Split(rest, sep)
	if segs[len(segs)-1] == "" {
		return "must end with a file name"
	}
	for _, s := range segs {
		switch s {
		case "":
			return "must not contain two separators in a row"
		case ".", "..":
			return `must not contain "." or ".." folders`
		}
	}
	return ""
}

// ValidateDecoyFiles trims the paths and checks every entry, rejecting duplicates and
// more than DecoyMaxFiles entries.
func ValidateDecoyFiles(files []DecoyFile) ([]DecoyFile, error) {
	if len(files) > DecoyMaxFiles {
		return nil, fmt.Errorf("at most %d decoy files", DecoyMaxFiles)
	}
	out := make([]DecoyFile, 0, len(files))
	seen := map[DecoyFile]bool{}
	for _, f := range files {
		f.Path = strings.TrimSpace(f.Path)
		if msg := DecoyPathProblem(f.OS, f.Path); msg != "" {
			return nil, fmt.Errorf("decoy file %q (%s): %s", f.Path, DecoyOSLabel(f.OS), msg)
		}
		key := DecoyFile{OS: f.OS, Path: f.Path}
		if seen[key] {
			return nil, fmt.Errorf("decoy file %q (%s) is listed twice", f.Path, DecoyOSLabel(f.OS))
		}
		seen[key] = true
		out = append(out, f)
	}
	return out, nil
}

// DecoyOSLabel names an OS for messages.
func DecoyOSLabel(os string) string {
	switch os {
	case DecoyOSWindows:
		return "Windows"
	case DecoyOSLinux:
		return "Linux"
	case DecoyOSDarwin:
		return "macOS"
	}
	return os
}
