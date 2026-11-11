//go:build windows

package windows

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Lineage labels, as on Linux: ssh_session is the PID of the per-connection sshd.exe
// ("sshd.exe -R") a process descends from, which is the PID OpenSSH logs "Accepted ..."
// under; ssh_key is the key that session used.

type origin struct {
	known      bool
	sshd       bool
	sshSession int64
}

func isSSHD(name string) bool { return strings.EqualFold(name, "sshd.exe") }

func combine(parent origin, pid int64, name string) origin {
	o := origin{known: true, sshSession: parent.sshSession}
	if isSSHD(name) {
		o.sshd = true
		if parent.known && parent.sshd && parent.sshSession == 0 {
			o.sshSession = pid // the first sshd.exe below the service: the session
		}
	}
	return o
}

const maxLineage = 32

// originOf computes an entry's origin from the table, caching it on the entry. Callers
// hold no table lock; entries are only read.
func (m *procMapper) originOf(e *procEntry, depth int) origin {
	if e == nil {
		return origin{}
	}
	m.lineMu.Lock()
	o, ok := m.origins[e.EntityID]
	m.lineMu.Unlock()
	if ok {
		return o
	}
	var parent origin
	if e.PPID > 4 && depth < maxLineage {
		if p := m.table.get(e.PPID, e.Start); p != nil && p != e {
			parent = m.originOf(p, depth+1)
		}
	}
	o = combine(parent, e.PID, e.Name)
	m.lineMu.Lock()
	if len(m.origins) > procTableMax {
		m.origins = map[string]origin{}
	}
	m.origins[e.EntityID] = o
	m.lineMu.Unlock()
	return o
}

// labelLineage adds the lineage labels to a process start event, once its process is in
// the table.
func (m *procMapper) labelLineage(ev *event.Event) {
	if ev == nil || ev.Process == nil || ev.Event.Action != "exec" {
		return
	}
	e := m.table.get(ev.Process.PID, time.Time{})
	if e == nil || e.EntityID != ev.Process.EntityID {
		return
	}
	o := m.originOf(e, 0)
	if o.sshSession == 0 {
		return
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	ev.Labels["ssh_session"] = strconv.FormatInt(o.sshSession, 10)
	if k := sshLogins.get(o.sshSession); k != "" {
		ev.Labels["ssh_key"] = k
	}
}

// sshLogins maps the PID OpenSSH logged a login under to the key it used, from the
// OpenSSH/Operational channel (eventlog sensor).
var sshLogins = &sshLoginRegistry{m: map[int64]string{}}

type sshLoginRegistry struct {
	mu sync.Mutex
	m  map[int64]string
}

func (r *sshLoginRegistry) note(pid int64, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) > 4096 {
		r.m = map[int64]string{}
	}
	r.m[pid] = key
}

func (r *sshLoginRegistry) get(pid int64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[pid]
}

var (
	reSSHAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHKey      = regexp.MustCompile(`ssh2: (\S+) (SHA256:[A-Za-z0-9+/=]+)`)
)

// mapOpenSSH turns OpenSSH/Operational's "Accepted ..." record into a login event.
func mapOpenSSH(e *event.Event, r *Record) {
	payload := r.Data["payload"]
	g := reSSHAccepted.FindStringSubmatch(payload)
	if g == nil {
		return
	}
	e.Event.Category = []string{event.CategoryAuthentication, event.CategorySession}
	e.Event.Type = []string{event.TypeStart}
	e.Event.Action = "ssh_login"
	e.Event.Outcome = event.OutcomeSuccess
	e.Message = "sshd: " + payload
	e.User = &event.User{Name: g[2]}
	port, _ := strconv.Atoi(g[4])
	e.Source = &event.Endpoint{IP: g[3], Port: port}
	if r.ProcessID != 0 {
		e.Process = &event.Process{PID: int64(r.ProcessID), Name: "sshd.exe"}
	}
	e.Data["auth_method"] = g[1]
	key := ""
	if k := reSSHKey.FindStringSubmatch(payload); k != nil {
		key = k[2]
		e.Data["ssh_key_type"] = k[1]
		e.Labels = map[string]string{"ssh_key": key}
	}
	if r.ProcessID != 0 {
		sshLogins.note(int64(r.ProcessID), key)
	}
}
