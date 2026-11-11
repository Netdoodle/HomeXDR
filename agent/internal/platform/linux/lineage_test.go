//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if k := r.lookup(3078858); k != "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI" {
		t.Fatalf("key = %q", k)
	}
	if k := r.lookup(3078900); k != "" {
		t.Fatalf("password login key = %q", k)
	}
	if _, ok := r.m[3078900]; !ok {
		t.Fatal("password login not remembered")
	}
	if k := r.lookup(42); k != "" || r.miss[42].IsZero() {
		t.Fatalf("unknown pid: key %q, miss %v", k, r.miss[42])
	}

	e := parseAuth(authMsg{App: "sshd-session", PID: 3078858, Msg: "Accepted publickey for root from 192.168.10.52 port 12115 ssh2: ED25519 SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI", Time: time.Now()})
	if e == nil || e.Labels["ssh_key"] != "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI" || e.Data["ssh_key_type"] != "ED25519" {
		t.Fatalf("auth event = %+v", e)
	}
}
