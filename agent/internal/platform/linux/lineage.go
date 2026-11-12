//go:build linux

package linux

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/authparse"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Lineage labels say where a process came from, so the server can tune maintenance work:
//
//   - ssh_session: the PID of the per-connection sshd process the process descends from.
//     It is the PID sshd logs "Accepted ..." under.
//   - ssh_key: the SHA256 fingerprint of the key that session logged in with.
//   - maintenance: "docker-update" when the process descends from Unraid's Docker update
//     scripts, "appdata-backup" when from the appdata backup plugin (which stops and
//     restarts every container).
//
// The ancestry is walked once per process and cached, so it costs a few /proc reads
// for processes HomeXDR has not seen start.

// origin is what a process inherits from its ancestors.
type origin struct {
	sshd        bool  // the process itself is sshd or sshd-session
	sshSession  int64 // per-connection sshd PID it descends from
	maintenance string
}

// maintenanceMarkers map a path in an ancestor's command line to a maintenance label.
var maintenanceMarkers = []struct{ path, label string }{
	{"/plugins/dynamix.docker.manager/", "docker-update"},
	{"/plugins/ca.update.applications/", "docker-update"},
	{"/plugins/appdata.backup/", "appdata-backup"},
}

func isSSHD(comm string) bool { return comm == "sshd" || comm == "sshd-session" }

// combine derives a process's origin from its parent's.
func combine(parent origin, parentKnown bool, pid int64, comm string, args []string) origin {
	o := origin{sshSession: parent.sshSession, maintenance: parent.maintenance}
	if isSSHD(comm) {
		o.sshd = true
		if parentKnown && parent.sshd && parent.sshSession == 0 {
			o.sshSession = pid // the first sshd below the listener: the session
		}
	}
	if o.maintenance == "" {
		cmd := strings.Join(args, " ")
		for _, m := range maintenanceMarkers {
			if strings.Contains(cmd, m.path) {
				o.maintenance = m.label
				break
			}
		}
	}
	return o
}

const maxLineage = 32

// procOrigin computes the origin of a running process from /proc, caching it.
func (en *enricher) procOrigin(pid int64, depth int) (origin, bool) {
	st, err := readStat(pid)
	if err != nil {
		return origin{}, false
	}
	key := en.env.EntityID(pid, st.StartTick)
	if o, ok := en.origins.get(key); ok {
		return o, true
	}
	var parent origin
	known := false
	if st.PPID > 1 && depth < maxLineage {
		parent, known = en.procOrigin(st.PPID, depth+1)
	}
	o := combine(parent, known, pid, st.Comm, readCmdline(pid))
	en.origins.put(key, o)
	return o, true
}

// labelLineage adds the lineage labels to a process start event.
func (en *enricher) labelLineage(ev *event.Event, pi *procInfo) {
	if en.origins == nil {
		return
	}
	var parent origin
	known := false
	if pi.PPID > 1 {
		if pi.HasParentKey {
			parent, known = en.origins.get(en.env.EntityID(pi.PPID, pi.ParentStartKey))
		}
		if !known {
			parent, known = en.procOrigin(pi.PPID, 1)
		}
	}
	o := combine(parent, known, pi.PID, pi.Comm, pi.Args)
	en.origins.put(ev.Process.EntityID, o)
	if o.sshSession == 0 && o.maintenance == "" {
		return
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	if o.sshSession > 0 {
		ev.Labels["ssh_session"] = strconv.FormatInt(o.sshSession, 10)
		if fp := sshLogins.lookup(o.sshSession, !o.sshd); fp != "" {
			ev.Labels["ssh_key"] = fp
		}
	}
	if o.maintenance != "" {
		ev.Labels["maintenance"] = o.maintenance
	}
}

// sshLoginRegistry maps the PID sshd logged a login under to the key it used ("" for a
// password or other non-key login).
type sshLoginRegistry struct {
	mu   sync.Mutex
	m    map[int64]sshLogin
	miss map[int64]time.Time // PIDs looked up in the logs and not found yet
}

type sshLogin struct {
	key string
	at  time.Time
}

var sshLogins = &sshLoginRegistry{m: map[int64]sshLogin{}, miss: map[int64]time.Time{}}

const sshLoginMax = 4096

func (r *sshLoginRegistry) note(pid int64, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) >= sshLoginMax {
		var oldest int64
		var t time.Time
		for p, l := range r.m {
			if t.IsZero() || l.at.Before(t) {
				oldest, t = p, l.at
			}
		}
		delete(r.m, oldest)
	}
	r.m[pid] = sshLogin{key: key, at: time.Now()}
	delete(r.miss, pid)
}

// lookup returns the key of a session. When the auth sensor has not reported the login
// yet (it reads the log on a timer, and the first command of a session can start
// sooner), it reads the end of the log files itself.
// A miss is remembered only when cacheMiss is set: sshd's own processes start before the
// login is logged, and the shell right after them must still look.
func (r *sshLoginRegistry) lookup(pid int64, cacheMiss bool) string {
	r.mu.Lock()
	l, ok := r.m[pid]
	missed, recently := r.miss[pid]
	r.mu.Unlock()
	if ok {
		return l.key
	}
	if recently && time.Since(missed) < 5*time.Second {
		return ""
	}
	if key, found := scanLoginInLogs(pid); found {
		r.note(pid, key)
		return key
	}
	if !cacheMiss {
		return ""
	}
	r.mu.Lock()
	if len(r.miss) > 1024 {
		r.miss = map[int64]time.Time{}
	}
	r.miss[pid] = time.Now()
	r.mu.Unlock()
	return ""
}

// noteSSHLogin records a successful sshd login event from the auth sensor.
func noteSSHLogin(e *event.Event) {
	if e == nil || e.Event.Action != "ssh_login" || e.Event.Outcome != event.OutcomeSuccess || e.Process == nil || e.Process.PID <= 0 {
		return
	}
	sshLogins.note(e.Process.PID, e.Labels["ssh_key"])
}

// sshLogFiles are read when a session's login was not reported yet. Unraid and some
// minimal systems log sshd only to syslog or messages.
var sshLogFiles = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"}

const sshLogTail = 512 << 10

func scanLoginInLogs(pid int64) (key string, found bool) {
	needle := []byte("[" + strconv.FormatInt(pid, 10) + "]: Accepted ")
	for _, f := range sshLogFiles {
		b := readTail(f, sshLogTail)
		for len(b) > 0 {
			i := bytes.LastIndex(b, needle)
			if i < 0 {
				break
			}
			start := bytes.LastIndexByte(b[:i], '\n') + 1
			end := i
			for end < len(b) && b[end] != '\n' {
				end++
			}
			line := string(b[start:end])
			b = b[:start]
			if !strings.Contains(line, "sshd") {
				continue
			}
			if g := authparse.SSHKeyTail.FindStringSubmatch(line); g != nil {
				return g[2], true
			}
			return "", true
		}
	}
	return "", false
}

func readTail(path string, n int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil
	}
	off := fi.Size() - n
	if off < 0 {
		off = 0
	}
	b := make([]byte, fi.Size()-off)
	k, _ := f.ReadAt(b, off)
	if k <= 0 {
		return nil
	}
	return b[:k]
}

func lastIndex(b, sep []byte) int { return strings.LastIndex(string(b), string(sep)) }

func lastNL(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			return i
		}
	}
	return -1
}
