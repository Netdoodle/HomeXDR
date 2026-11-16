package decoy

import (
	"os"
	"path/filepath"
	"strings"
)

// Content kinds: which fake text a decoy gets.
const (
	kindSheet  = "sheet" // a password list exported from a spreadsheet (CSV text)
	kindCodes  = "codes" // account backup / recovery codes
	kindCSV    = "csv"   // service credentials as CSV
	kindText   = "text"  // a personal password note
	kindAWS    = "aws"   // an AWS shared credentials file
	kindSQL    = "sql"   // a database dump with user grants
	maxUsers   = 200     // profile folders looked at per base folder
	maxDecoys  = 512     // decoys tracked per host
	maxDirScan = 5000    // entries looked at when searching a folder for a renamed decoy
)

// target is one place a decoy may be created. Base is a folder only an administrator
// controls; symlinks in it are followed. Every folder in Dirs is opened without following
// symlinks, because users control them (their home folder and what is in it).
type target struct {
	Base string
	Dirs []string
	Name string
	// MakeDir allows the last folder of Dirs to be created (~/.aws, ProgramData\Backup).
	MakeDir bool
	// Owner of the file (Unix). OwnerFromParent takes the parent folder's owner instead.
	User            string
	UID, GID        int
	HasOwner        bool
	OwnerFromParent bool
	Kind            string
}

func (t target) path() string {
	return filepath.Join(append(append([]string{t.Base}, t.Dirs...), t.Name)...)
}

// need is how many of Dirs must already exist for the decoy to be placed: all of them,
// except a folder the agent may create.
func (t target) need() int {
	if t.MakeDir && len(t.Dirs) > 0 {
		return len(t.Dirs) - 1
	}
	return len(t.Dirs)
}

// owner describes who owns a profile folder (Unix).
type owner struct {
	UID, GID int
	Name     string
}

// layout enumerates the default decoy locations of one OS below root. root is "" for
// the real file system; tests point it at a temporary folder.
type layout struct {
	goos string
	root string
	// lookupOwner returns the owner of a profile folder and whether it is a real user.
	lookupOwner func(path string, fi os.FileInfo) (owner, bool)
}

func (l layout) at(parts ...string) string {
	if l.root == "" {
		return filepath.Join(parts...)
	}
	return filepath.Join(append([]string{l.root}, parts...)...)
}

func (l layout) targets() []target {
	switch l.goos {
	case "windows":
		return l.windows()
	case "linux":
		return l.linux()
	case "darwin":
		return l.darwin()
	}
	return nil
}

// isRealDir reports whether fi (from Lstat) is a folder and not a link or junction.
func isRealDir(fi os.FileInfo) bool {
	return fi.IsDir() && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

// profiles lists the folders directly below dir (not links), at most maxUsers.
func profiles(dir string) []os.FileInfo {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []os.FileInfo
	for _, e := range ents {
		if len(out) >= maxUsers {
			break
		}
		fi, err := e.Info() // Lstat semantics
		if err != nil || !isRealDir(fi) {
			continue
		}
		out = append(out, fi)
	}
	return out
}

var windowsSkip = map[string]bool{"public": true, "default": true, "default user": true, "all users": true}

func (l layout) windows() []target {
	var users, pd string
	if l.root == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		users = drive + `\Users`
		pd = os.Getenv("ProgramData")
		if pd == "" {
			pd = drive + `\ProgramData`
		}
	} else {
		users, pd = l.at("Users"), l.at("ProgramData")
	}
	var out []target
	for _, fi := range profiles(users) {
		name := fi.Name()
		if windowsSkip[strings.ToLower(name)] {
			continue
		}
		// A real, used profile has a registry hive.
		if hive, err := os.Lstat(filepath.Join(users, name, "NTUSER.DAT")); err != nil || !hive.Mode().IsRegular() {
			continue
		}
		out = append(out,
			target{Base: users, Dirs: []string{name, "Documents"}, Name: "Passwords.xlsx", User: name, Kind: kindSheet},
			target{Base: users, Dirs: []string{name, "Desktop"}, Name: "backup-codes.txt", User: name, Kind: kindCodes},
		)
	}
	if fi, err := os.Stat(pd); err == nil && fi.IsDir() {
		out = append(out, target{Base: pd, Dirs: []string{"Backup"}, Name: "credentials.csv", MakeDir: true, Kind: kindCSV})
	}
	return out
}

func (l layout) linux() []target {
	var out []target
	home := l.at("/", "home")
	for _, fi := range profiles(home) {
		if fi.Name() == "lost+found" {
			continue
		}
		o, ok := l.lookupOwner(filepath.Join(home, fi.Name()), fi)
		if !ok || o.UID == 0 {
			continue
		}
		out = append(out, linuxHome(home, fi.Name(), o, true)...)
	}
	// /root: the agent runs as root, so these files are root's without a chown.
	if fi, err := os.Lstat(l.at("/", "root")); err == nil && isRealDir(fi) {
		out = append(out, linuxHome(l.at("/"), "root", owner{Name: "root"}, false)...)
	}
	if fi, err := os.Lstat(l.at("/", "var", "backups")); err == nil && isRealDir(fi) {
		out = append(out, target{Base: l.at("/", "var"), Dirs: []string{"backups"}, Name: "db-credentials.sql", User: "root", Kind: kindSQL})
	}
	return out
}

func linuxHome(base, dir string, o owner, chown bool) []target {
	t := target{Base: base, User: o.Name, UID: o.UID, GID: o.GID, HasOwner: chown}
	docs, aws := t, t
	docs.Dirs, docs.Name, docs.Kind = []string{dir, "Documents"}, "passwords.txt", kindText
	aws.Dirs, aws.Name, aws.Kind, aws.MakeDir = []string{dir, ".aws"}, "credentials.bak", kindAWS, true
	return []target{docs, aws}
}

func (l layout) darwin() []target {
	var out []target
	users := l.at("/", "Users")
	for _, fi := range profiles(users) {
		name := fi.Name()
		if name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		o, ok := l.lookupOwner(filepath.Join(users, name), fi)
		t := target{Base: users, User: name}
		if ok {
			t.User, t.UID, t.GID, t.HasOwner = o.Name, o.UID, o.GID, o.UID != 0
		}
		docs, desk := t, t
		docs.Dirs, docs.Name, docs.Kind = []string{name, "Documents"}, "Passwords.txt", kindText
		desk.Dirs, desk.Name, desk.Kind = []string{name, "Desktop"}, "backup-codes.txt", kindCodes
		out = append(out, docs, desk)
	}
	return out
}

// extraTarget turns an admin-configured path into a target, or returns false when the
// path is not usable (relative, a folder, inside the agent's data dir).
func extraTarget(p, dataDir string) (target, bool) {
	p = strings.TrimSpace(p)
	if p == "" || !filepath.IsAbs(p) || strings.ContainsAny(p, "*?\x00") {
		return target{}, false
	}
	p = filepath.Clean(p)
	name := filepath.Base(p)
	parent := filepath.Dir(p)
	if name == "." || name == ".." || name == string(filepath.Separator) || parent == p {
		return target{}, false
	}
	if dataDir != "" && under(p, filepath.Clean(dataDir)) {
		return target{}, false
	}
	t := target{Name: name, OwnerFromParent: true, Kind: kindForName(name)}
	if gp := filepath.Dir(parent); gp != parent {
		t.Base, t.Dirs = gp, []string{filepath.Base(parent)}
	} else {
		t.Base = parent // the parent is the root of the volume
	}
	return t, true
}

func under(p, dir string) bool {
	if strings.EqualFold(p, dir) {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(strings.TrimSuffix(dir, sep)+sep))
}

func kindForName(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".sql"):
		return kindSQL
	case strings.HasSuffix(n, ".csv"):
		return kindCSV
	case strings.HasSuffix(n, ".xlsx"), strings.HasSuffix(n, ".xls"):
		return kindSheet
	case strings.Contains(n, "aws") || strings.HasPrefix(n, "credentials"):
		return kindAWS
	case strings.Contains(n, "code"):
		return kindCodes
	}
	return kindText
}
