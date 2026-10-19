//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
	shadowFile = "/etc/shadow"
)

type passwdEntry struct {
	Name  string
	UID   uint32
	GID   uint32
	Gecos string
	Home  string
	Shell string
}

func parsePasswd(b []byte) []passwdEntry {
	var out []passwdEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{Name: f[0], UID: uint32(uid), GID: uint32(gid), Gecos: f[4], Home: f[5], Shell: f[6]})
	}
	return out
}

type groupEntry struct {
	Name    string
	GID     uint32
	Members []string
}

func parseGroup(b []byte) []groupEntry {
	var out []groupEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		g := groupEntry{Name: f[0], GID: uint32(gid)}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

// shadowLocked maps user names to whether the account's password is locked or unset
// ("!" or "*" prefix). Needs root to read /etc/shadow.
func shadowLocked(b []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		out[f[0]] = strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*")
	}
	return out
}

// userNames resolves UIDs to names from /etc/passwd, reloading when the file changes.
type userNames struct {
	mu    sync.Mutex
	mtime time.Time
	byUID map[uint32]string
}

var users = &userNames{}

func (u *userNames) name(uid uint32) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if fi, err := os.Stat(passwdFile); err == nil && (u.byUID == nil || !fi.ModTime().Equal(u.mtime)) {
		if b, err := os.ReadFile(passwdFile); err == nil {
			u.byUID = map[uint32]string{}
			for _, e := range parsePasswd(b) {
				if _, dup := u.byUID[e.UID]; !dup {
					u.byUID[e.UID] = e.Name
				}
			}
			u.mtime = fi.ModTime()
		}
	}
	if n, ok := u.byUID[uid]; ok {
		return n
	}
	return strconv.FormatUint(uint64(uid), 10)
}
