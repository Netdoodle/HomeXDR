package decoy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
)

// Content kinds: which fake text a decoy gets.
const (
	kindSheet  = "sheet" // a password list exported from a spreadsheet (CSV text)
	kindCodes  = "codes" // account backup / recovery codes
	kindCSV    = "csv"   // service credentials as CSV (decoys created before kinds came from the name)
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
	// MakeDir allows the last folder of Dirs to be created when its parent exists. It is
	// never set for a home folder itself.
	MakeDir bool
	// Owner of the file (Unix). OwnerFromParent takes the parent folder's owner instead.
	User            string
	UID, GID        int
	HasOwner        bool
	OwnerFromParent bool
	Kind            string
	// Entry is the configured path the target comes from; Home is set when it was
	// expanded from {home}.
	Entry  string
	Home   bool
	Hidden bool
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

// home is one real user's home folder: Dir below Base.
type home struct {
	Base, Dir string
	Owner     owner
	Chown     bool // chown files to Owner (Unix, not for root)
}

// layout expands the configured decoy paths for one OS below root. root is "" for the
// real file system; tests point it at a temporary folder, and absolute paths are then
// taken relative to it.
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

// targets expands the entries for this OS. Unusable entries are reported to bad.
func (l layout) targets(files []api.DecoyFile, dataDir string, bad func(path, msg string)) []target {
	var out []target
	var homes []home
	homesDone := false
	for _, f := range files {
		if f.OS != l.goos {
			continue
		}
		p := strings.TrimSpace(f.Path)
		if msg := api.DecoyPathProblem(f.OS, p); msg != "" {
			bad(p, msg)
			continue
		}
		sep := api.DecoySeparator(f.OS)
		hidden := f.Hidden && f.OS != api.DecoyOSLinux // Linux has no hidden attribute
		if rest, ok := strings.CutPrefix(p, api.DecoyHome+sep); ok {
			dirs, name := split(rest, sep)
			if !homesDone {
				homes, homesDone = l.homes(), true
			}
			for _, h := range homes {
				t := target{
					Base: h.Base, Dirs: append([]string{h.Dir}, dirs...), Name: name, MakeDir: len(dirs) > 0,
					User: h.Owner.Name, UID: h.Owner.UID, GID: h.Owner.GID, HasOwner: h.Chown,
					Kind: kindFor(dirs, name), Entry: p, Home: true, Hidden: hidden,
				}
				if l.allowed(t, dataDir, bad) {
					out = append(out, t)
				}
			}
			continue
		}
		vol, rest := l.volume(p)
		dirs, name := split(rest, sep)
		t := target{Base: vol, Name: name, OwnerFromParent: true, Kind: kindFor(dirs, name), Entry: p, Hidden: hidden}
		if n := len(dirs); n > 0 {
			t.Base = filepath.Join(append([]string{vol}, dirs[:n-1]...)...)
			t.Dirs, t.MakeDir = []string{dirs[n-1]}, true
		}
		if l.allowed(t, dataDir, bad) {
			out = append(out, t)
		}
	}
	return out
}

func (l layout) allowed(t target, dataDir string, bad func(path, msg string)) bool {
	if dataDir != "" && under(t.path(), filepath.Clean(dataDir)) {
		bad(t.path(), "inside the agent's data folder")
		return false
	}
	return true
}

// split cuts a checked relative path into its folders and file name.
func split(rest, sep string) ([]string, string) {
	parts := strings.Split(rest, sep)
	return parts[:len(parts)-1], parts[len(parts)-1]
}

// volume returns the root an absolute path starts at and the rest of the path.
func (l layout) volume(p string) (string, string) {
	if l.goos == api.DecoyOSWindows {
		if l.root != "" {
			return l.root, p[3:]
		}
		return p[:3], p[3:] // C:\
	}
	if l.root != "" {
		return l.root, p[1:]
	}
	return "/", p[1:]
}

// homes lists the real users' home folders of this OS.
func (l layout) homes() []home {
	switch l.goos {
	case api.DecoyOSWindows:
		return l.windowsHomes()
	case api.DecoyOSLinux:
		return l.linuxHomes()
	case api.DecoyOSDarwin:
		return l.darwinHomes()
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

// windowsHomes: each profile under C:\Users with a registry hive, except Public and the
// default profiles. Files inherit the folder's permissions, so there is no owner.
func (l layout) windowsHomes() []home {
	users := l.at("Users")
	if l.root == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		users = drive + `\Users`
	}
	var out []home
	for _, fi := range profiles(users) {
		name := fi.Name()
		if windowsSkip[strings.ToLower(name)] {
			continue
		}
		// A real, used profile has a registry hive.
		if hive, err := os.Lstat(filepath.Join(users, name, "NTUSER.DAT")); err != nil || !hive.Mode().IsRegular() {
			continue
		}
		out = append(out, home{Base: users, Dir: name, Owner: owner{Name: name}})
	}
	return out
}

// linuxHomes: each folder under /home owned by an existing user other than root, and
// /root (the agent runs as root, so files there are root's without a chown).
func (l layout) linuxHomes() []home {
	var out []home
	base := l.at("/", "home")
	for _, fi := range profiles(base) {
		if fi.Name() == "lost+found" {
			continue
		}
		o, ok := l.lookupOwner(filepath.Join(base, fi.Name()), fi)
		if !ok || o.UID == 0 {
			continue
		}
		out = append(out, home{Base: base, Dir: fi.Name(), Owner: o, Chown: true})
	}
	if fi, err := os.Lstat(l.at("/", "root")); err == nil && isRealDir(fi) {
		out = append(out, home{Base: l.at("/"), Dir: "root", Owner: owner{Name: "root"}})
	}
	return out
}

// darwinHomes: each folder under /Users except Shared and hidden folders.
func (l layout) darwinHomes() []home {
	var out []home
	base := l.at("/", "Users")
	for _, fi := range profiles(base) {
		name := fi.Name()
		if name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		h := home{Base: base, Dir: name, Owner: owner{Name: name}}
		if o, ok := l.lookupOwner(filepath.Join(base, name), fi); ok {
			h.Owner, h.Chown = o, o.UID != 0
		}
		out = append(out, h)
	}
	return out
}

func under(p, dir string) bool {
	if strings.EqualFold(p, dir) {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(strings.TrimSuffix(dir, sep)+sep))
}

// kindFor picks the fake content for a decoy from its name: spreadsheets and CSV files
// get a password list, .sql a database dump, credentials* in an .aws folder an AWS
// credentials file, names with "code" in them backup codes, anything else a password note.
func kindFor(dirs []string, name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".xlsx"), strings.HasSuffix(n, ".xls"), strings.HasSuffix(n, ".csv"):
		return kindSheet
	case strings.HasSuffix(n, ".sql"):
		return kindSQL
	case strings.HasPrefix(n, "credentials") && len(dirs) > 0 && strings.EqualFold(dirs[len(dirs)-1], ".aws"):
		return kindAWS
	case strings.Contains(n, "code"):
		return kindCodes
	}
	return kindText
}
