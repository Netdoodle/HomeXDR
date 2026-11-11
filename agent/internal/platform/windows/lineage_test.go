//go:build windows

package windows

import (
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestWindowsSSHLineage(t *testing.T) {
	m := newProcMapper(testEnv(t), nil, nil)
	at := time.Now()
	add := func(pid, ppid int64, name string) *procEntry {
		e := &procEntry{PID: pid, PPID: ppid, Name: name, EntityID: name + string(rune('a'+pid%26)) + time.Duration(pid).String(), Start: at}
		m.table.put(e)
		return e
	}
	add(924, 776, "services.exe")
	listener := add(3724, 924, "sshd.exe")
	// The VM case: the service started at boot reads as hours in the future after NTP
	// sets the clock back, so only the recorded parent links the session to it.
	listener.Start = at.Add(8 * time.Hour)
	r := add(2140, 3724, "sshd.exe")
	r.ParentEntityID = listener.EntityID
	add(4268, 2140, "sshd.exe") // -y, pre-auth
	add(6628, 2140, "sshd.exe") // -z
	ps := add(6344, 6628, "powershell.exe")
	other := add(100, 924, "svchost.exe")

	sshLogins.note(2140, "SHA256:CbPtkGqAGFaaH0z/4IqYEnoLzKAIbUcg7YUvw6haT+A")
	ev := &event.Event{Event: event.Meta{Action: "exec"}, Process: &event.Process{PID: ps.PID, EntityID: ps.EntityID}}
	m.labelLineage(ev)
	if ev.Labels["ssh_session"] != "2140" || ev.Labels["ssh_key"] != "SHA256:CbPtkGqAGFaaH0z/4IqYEnoLzKAIbUcg7YUvw6haT+A" {
		t.Fatalf("labels = %v", ev.Labels)
	}
	ev2 := &event.Event{Event: event.Meta{Action: "exec"}, Process: &event.Process{PID: other.PID, EntityID: other.EntityID}}
	m.labelLineage(ev2)
	if ev2.Labels != nil {
		t.Fatalf("svchost labels = %v", ev2.Labels)
	}
}

func TestOpenSSHLoginRecord(t *testing.T) {
	r := &Record{Channel: "OpenSSH/Operational", EventID: 4, ProcessID: 2140, Data: map[string]string{
		"process": "sshd",
		"payload": "Accepted publickey for hxadmin from 192.168.10.52 port 40941 ssh2: ED25519 SHA256:CbPtkGqAGFaaH0z/4IqYEnoLzKAIbUcg7YUvw6haT+A",
	}}
	e := &event.Event{Data: map[string]any{}}
	mapOpenSSH(e, r)
	if e.Event.Action != "ssh_login" || e.User.Name != "hxadmin" || e.Source.IP != "192.168.10.52" || e.Process.PID != 2140 ||
		e.Labels["ssh_key"] != "SHA256:CbPtkGqAGFaaH0z/4IqYEnoLzKAIbUcg7YUvw6haT+A" {
		t.Fatalf("event = %+v", e)
	}
}
