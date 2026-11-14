//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestLineageSSHSession(t *testing.T) {
	// OpenSSH 9.8+: listener sshd -> sshd-session (logs Accepted) -> forked sshd-session -> bash -> sed
	listener := combine(origin{}, true, 900, "sshd", []string{"/usr/sbin/sshd"})
	if listener.sshSession != 0 || !listener.sshd {
		t.Fatalf("listener = %+v", listener)
	}
	session := combine(listener, true, 1000, "sshd-session", []string{"sshd-session: root [priv]"})
	child := combine(session, true, 1001, "sshd-session", []string{"sshd-session: root@notty"})
	bash := combine(child, true, 1002, "bash", []string{"bash", "-c", "x"})
	sed := combine(bash, true, 1003, "sed", []string{"sed", "-i", "s/a/b/", "/etc/x"})
	if session.sshSession != 1000 || child.sshSession != 1000 || sed.sshSession != 1000 {
		t.Fatalf("session %+v child %+v sed %+v", session, child, sed)
	}
	// A process outside any session.
	if o := combine(origin{}, true, 50, "cron", nil); o.sshSession != 0 {
		t.Fatalf("cron = %+v", o)
	}
	// An sshd whose parent is unknown is not taken for a session.
	if o := combine(origin{}, false, 77, "sshd", nil); o.sshSession != 0 {
		t.Fatalf("orphan sshd = %+v", o)
	}
}

func TestLineageMaintenance(t *testing.T) {
	php := combine(origin{}, true, 10, "php", []string{"/usr/bin/php", "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/update_container", "frigate"})
	grep := combine(php, true, 11, "grep", []string{"grep", "x", "/boot/config/plugins/dockerMan/templates-user/my-frigate.xml"})
	if grep.maintenance != "docker-update" {
		t.Fatalf("grep = %+v", grep)
	}
	bk := combine(origin{}, true, 20, "php", []string{"php", "/usr/local/emhttp/plugins/appdata.backup/scripts/backup.php"})
	if bk.maintenance != "appdata-backup" {
		t.Fatalf("backup = %+v", bk)
	}
}

func TestSSHKeyFromLogs(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "syslog")
	log := "Nov 11 09:27:05 Tower2 sshd-session[3078858]: Accepted publickey for root from 192.168.10.52 port 12115 ssh2: ED25519 SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI\n" +
		"Nov 11 09:27:06 Tower2 sshd-session[3078900]: Accepted password for root from 192.168.10.52 port 12116 ssh2\n" +
		"Nov 11 09:27:07 Tower2 emhttpd: something [3078858]: Accepted nothing\n"
	if err := os.WriteFile(f, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	old := sshLogFiles
	sshLogFiles = []string{filepath.Join(dir, "missing"), f}
	defer func() { sshLogFiles = old }()

	r := &sshLoginRegistry{m: map[int64]sshLogin{}, miss: map[int64]time.Time{}}
	if k := r.lookup(3078858, true); k != "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI" {
		t.Fatalf("key = %q", k)
	}
	if k := r.lookup(3078900, true); k != "" {
		t.Fatalf("password login key = %q", k)
	}
	if _, ok := r.m[3078900]; !ok {
		t.Fatal("password login not remembered")
	}
	if k := r.lookup(42, true); k != "" || r.miss[42].IsZero() {
		t.Fatalf("unknown pid: key %q, miss %v", k, r.miss[42])
	}

	e := parseAuth(authMsg{App: "sshd-session", PID: 3078858, Msg: "Accepted publickey for root from 192.168.10.52 port 12115 ssh2: ED25519 SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI", Time: time.Now()})
	if e == nil || e.Labels["ssh_key"] != "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI" || e.Data["ssh_key_type"] != "ED25519" {
		t.Fatalf("auth event = %+v", e)
	}
}

// keyWaitSetup points the log scan at a temp file, gives every session a fresh start time
// and empties the login registry. It returns the log path.
func keyWaitSetup(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "syslog")
	if err := os.WriteFile(f, []byte("Nov 14 08:00:00 Tower2 emhttpd: unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldFiles, oldStart, oldReg := sshLogFiles, sessionStart, sshLogins
	sshLogFiles = []string{f}
	sessionStart = func(int64) time.Time { return time.Now().Add(-time.Second) }
	sshLogins = &sshLoginRegistry{m: map[int64]sshLogin{}, miss: map[int64]time.Time{}}
	t.Cleanup(func() { sshLogFiles, sessionStart, sshLogins = oldFiles, oldStart, oldReg })
	return f
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func sshEvent(name, session string) *event.Event {
	return &event.Event{Process: &event.Process{Name: name}, Labels: map[string]string{"ssh_session": session}}
}

func TestKeyWaitLateLoginLine(t *testing.T) {
	logf := keyWaitSetup(t)
	const fp = "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI"
	got := make(chan *event.Event, 8)
	out := platform.EmitterFunc(func(e *event.Event) { got <- e })
	slots := make(chan struct{}, 4)

	// Two commands of the same session, both started before the login line was logged.
	evs := []*event.Event{sshEvent("bash", "4242"), sshEvent("sqlite3", "4242")}
	for _, ev := range evs {
		sess := keyPending(ev, time.Now())
		if sess != 4242 {
			t.Fatalf("keyPending = %d", sess)
		}
		keyWaiter{out: out, sess: sess, slots: slots}.Emit(ev)
	}
	select {
	case e := <-got:
		t.Fatalf("emitted before the login line: %+v", e.Labels)
	case <-time.After(250 * time.Millisecond):
	}
	appendLine(t, logf, "Nov 14 08:00:01 Tower2 sshd-session[4242]: Accepted publickey for root from 192.168.10.52 port 50000 ssh2: ED25519 "+fp)
	for range evs {
		select {
		case e := <-got:
			if e.Labels["ssh_key"] != fp {
				t.Fatalf("ssh_key = %q", e.Labels["ssh_key"])
			}
		case <-time.After(keyWaitMax):
			t.Fatal("held event never emitted")
		}
	}
	if k, ok := sshLogins.known(4242); !ok || k != fp {
		t.Fatalf("registry = %q, %v", k, ok)
	}
	if len(slots) != 0 {
		t.Fatalf("%d slots still held", len(slots))
	}
	// Later commands of the session no longer wait.
	if sess := keyPending(sshEvent("ls", "4242"), time.Now()); sess != 0 {
		t.Fatalf("known session still pending: %d", sess)
	}
}

func TestKeyWaitTimesOut(t *testing.T) {
	keyWaitSetup(t)
	got := make(chan *event.Event, 1)
	start := time.Now()
	keyWaiter{out: platform.EmitterFunc(func(e *event.Event) { got <- e }), sess: 99, slots: make(chan struct{}, 1)}.Emit(sshEvent("bash", "99"))
	select {
	case e := <-got:
		if e.Labels["ssh_key"] != "" {
			t.Fatalf("ssh_key = %q", e.Labels["ssh_key"])
		}
		if d := time.Since(start); d < keyWaitMax-keyWaitStep || d > keyWaitMax+time.Second {
			t.Fatalf("waited %v", d)
		}
	case <-time.After(keyWaitMax + 2*time.Second):
		t.Fatal("event lost after the wait ran out")
	}
}

func TestKeyWaitSkips(t *testing.T) {
	keyWaitSetup(t)
	now := time.Now()
	if s := keyPending(sshEvent("sshd-session", "7"), now); s != 0 {
		t.Fatalf("sshd's own process waited: %d", s)
	}
	labelled := sshEvent("bash", "7")
	labelled.Labels["ssh_key"] = "SHA256:x"
	if s := keyPending(labelled, now); s != 0 {
		t.Fatalf("labelled event waited: %d", s)
	}
	if s := keyPending(&event.Event{Process: &event.Process{Name: "bash"}}, now); s != 0 {
		t.Fatalf("event outside SSH waited: %d", s)
	}
	sshLogins.note(8, "") // a password login
	if s := keyPending(sshEvent("bash", "8"), now); s != 0 {
		t.Fatalf("password session waited: %d", s)
	}
	sessionStart = func(int64) time.Time { return now.Add(-time.Minute) }
	if s := keyPending(sshEvent("bash", "9"), now); s != 0 {
		t.Fatalf("old session waited: %d", s)
	}
	sessionStart = func(int64) time.Time { return time.Time{} }
	if s := keyPending(sshEvent("bash", "9"), now); s != 0 {
		t.Fatalf("ended session waited: %d", s)
	}

	// With every slot taken the event goes out at once, unlabelled.
	var mu sync.Mutex
	var sent []*event.Event
	full := make(chan struct{}, 1)
	full <- struct{}{}
	keyWaiter{out: platform.EmitterFunc(func(e *event.Event) { mu.Lock(); sent = append(sent, e); mu.Unlock() }), sess: 10, slots: full}.Emit(sshEvent("bash", "10"))
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("full slots: %d events sent synchronously", len(sent))
	}
}
