package darwin

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/authparse"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/event"
)

func entity(pid int64, start uint64) string { return event.ProcessEntityID("agent", pid, start) }

func newTestMapper() *esMapper {
	return newESMapper(entity, nil, func(uid uint32) string {
		return map[uint32]string{0: "root", 501: "alex"}[uid]
	}, 4242)
}

// One exec line as eslogger prints it (abridged: stat blocks and some tokens removed).
const esExecLine = `{"schema_version":1,"mach_time":2016887962429,"event_type":9,"thread":{"thread_id":163353},"version":7,"seq_num":2,` +
	`"event":{"exec":{"dyld_exec_path":"\/usr\/bin\/curl","script":null,` +
	`"target":{"signing_id":"com.apple.curl","codesigning_flags":570522385,"executable":{"path":"\/usr\/bin\/curl","path_truncated":false},` +
	`"ppid":7187,"tty":{"path":"\/dev\/ttys004","path_truncated":false},"start_time":"2026-11-12T16:30:58.143318Z","is_platform_binary":true,` +
	`"audit_token":{"asid":100015,"pidversion":34839,"ruid":501,"euid":501,"rgid":20,"auid":501,"egid":20,"pid":15337},` +
	`"is_es_client":false,"session_id":7188,"original_ppid":7187,"cdhash":"0a1b2c","team_id":null},` +
	`"args":["curl","-fsSL","https:\/\/example.com\/x.sh"],"cwd":{"path":"\/Users\/alex","path_truncated":false},"last_fd":2,"env":["SECRET=1"]}},` +
	`"time":"2026-11-12T16:30:58.145040063Z","action":{"result":{"result":{"auth":0},"result_type":0}},` +
	`"process":{"audit_token":{"pid":15337,"euid":501,"ruid":501},"ppid":7187,"executable":{"path":"\/bin\/zsh"},"start_time":"2026-11-12T16:30:58.143318Z"},"action_type":1,"global_seq_num":5}`

func TestESExecAndExit(t *testing.T) {
	m := newTestMapper()
	msg, name, raw, err := parseESLine([]byte(esExecLine + "\n"))
	if err != nil || name != "exec" {
		t.Fatalf("parse: %v %q", err, name)
	}
	ev := m.mapProcess(msg, name, raw)
	if ev == nil {
		t.Fatal("no event")
	}
	p := ev.Process
	start := time.Date(2026, 11, 12, 16, 30, 58, 143318000, time.UTC)
	if p.PID != 15337 || p.Executable != "/usr/bin/curl" || p.Name != "curl" ||
		p.CommandLine != "curl -fsSL https://example.com/x.sh" || p.WorkingDirectory != "/Users/alex" ||
		p.TTY != "/dev/ttys004" || p.User.Name != "alex" || *p.Elevated || !p.Start.Equal(start) {
		t.Fatalf("process = %+v", p)
	}
	if p.EntityID != entity(15337, uint64(start.UnixMicro())) {
		t.Fatal("entity ID does not use the start time in microseconds")
	}
	if p.Parent == nil || p.Parent.PID != 7187 {
		t.Fatalf("parent = %+v", p.Parent)
	}
	cs := p.CodeSignature
	if cs == nil || !cs.Exists || cs.Status != "apple" || !*cs.Valid || !*cs.Trusted {
		t.Fatalf("code signature = %+v", cs)
	}
	if ev.Event.Module != event.ModuleESLogger || ev.Event.Action != "exec" || ev.Data["signing_id"] != "com.apple.curl" {
		t.Fatalf("event = %+v", ev.Event)
	}
	if strings.Contains(ev.Message, "SECRET") {
		t.Fatal("environment leaked into the event")
	}

	exit := `{"event":{"exit":{"stat":2304}},"time":"2026-11-12T16:30:59Z",` +
		`"process":{"audit_token":{"pid":15337,"ruid":501},"ppid":7187,"executable":{"path":"\/usr\/bin\/curl"},"start_time":"2026-11-12T16:30:58.143318Z"}}`
	msg, name, raw, _ = parseESLine([]byte(exit))
	ev = m.mapProcess(msg, name, raw)
	if ev == nil || ev.Process.EntityID != p.EntityID || *ev.Process.ExitCode != 9 || ev.Process.CommandLine != p.CommandLine {
		t.Fatalf("exit = %+v", ev)
	}
}

func TestESHardLinkedStub(t *testing.T) {
	m := newTestMapper()
	m.sameFile = func(a, b string) bool {
		stubs := map[string]bool{"/usr/bin/git": true, "/usr/bin/python3": true}
		return stubs[a] && stubs[b]
	}
	line := strings.NewReplacer(`"path":"\/usr\/bin\/curl","path_truncated":false},"ppid"`, `"path":"\/usr\/bin\/python3","path_truncated":false},"ppid"`,
		`"args":["curl","-fsSL","https:\/\/example.com\/x.sh"]`, `"args":["\/usr\/bin\/git","status"]`).Replace(esExecLine)
	msg, name, raw, _ := parseESLine([]byte(line))
	ev := m.mapProcess(msg, name, raw)
	if ev.Process.Executable != "/usr/bin/git" || ev.Process.Name != "git" {
		t.Fatalf("stub reported as %q", ev.Process.Executable)
	}
	// A relative argv[0] resolves against the reported directory; a different file stays.
	if got := m.execPath("/usr/bin/python3", []string{"git", "status"}); got != "/usr/bin/git" {
		t.Fatal(got)
	}
	if got := m.execPath("/usr/bin/python3", []string{"/opt/homebrew/bin/git"}); got != "/usr/bin/python3" {
		t.Fatal(got)
	}
	if got := m.execPath("/usr/bin/python3", []string{"python3", "-c", "1"}); got != "/usr/bin/python3" {
		t.Fatal(got)
	}
}

func TestESSkipsAgentChildren(t *testing.T) {
	m := newTestMapper()
	child := strings.Replace(esExecLine, `"ppid":7187,"tty"`, `"ppid":4242,"tty"`, 1)
	msg, name, raw, _ := parseESLine([]byte(child))
	if ev := m.mapProcess(msg, name, raw); ev != nil {
		t.Fatal("the agent's own child was reported")
	}
	exit := `{"event":{"exit":{"stat":0}},"time":"2026-11-12T16:30:59Z",` +
		`"process":{"audit_token":{"pid":15337},"ppid":1,"executable":{"path":"\/usr\/bin\/curl"},"start_time":"2026-11-12T16:30:58.143318Z"}}`
	msg, name, raw, _ = parseESLine([]byte(exit))
	if ev := m.mapProcess(msg, name, raw); ev != nil {
		t.Fatal("the agent's own child's exit was reported")
	}
}

func TestESSecurityEvents(t *testing.T) {
	m := newTestMapper()
	cases := []struct {
		line   string
		action string
		check  func(*event.Event) bool
	}{
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":300}},"event":{"btm_launch_item_add":{"instigator":{"audit_token":{"pid":812,"ruid":501},"executable":{"path":"\/Applications\/Evil.app\/Contents\/MacOS\/Evil"},"start_time":"2026-11-12T09:59:00Z"},"app":null,` +
			`"item":{"item_type":4,"legacy":true,"managed":false,"uid":0,"item_url":"file:\/\/\/Library\/LaunchDaemons\/com.evil.plist","app_url":null},"executable_path":"\/Library\/Evil\/evil"}}}`,
			"launch_item_added", func(e *event.Event) bool {
				return e.File.Path == "/Library/LaunchDaemons/com.evil.plist" && e.Data["item_type"] == "daemon" &&
					e.Process.Name == "Evil" && e.Event.Dataset == "persistence"
			}},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":1}},"event":{"xp_malware_detected":{"signature_version":"5281","malware_identifier":"OSX.Adload","incident_identifier":"ABC","detected_path":"\/Users\/alex\/Downloads\/x.app"}}}`,
			"malware_detected", func(e *event.Event) bool {
				return e.File.Path == "/Users/alex/Downloads/x.app" && e.Data["malware_identifier"] == "OSX.Adload" && e.Event.Category[0] == event.CategoryMalware
			}},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":500,"ruid":501},"executable":{"path":"\/usr\/libexec\/syspolicyd"},"start_time":"2026-11-12T09:00:00Z"},"event":{"gatekeeper_user_override":{"file_type":1,"file":{"path":"\/Users\/alex\/Downloads\/tool"},"sha256":"ab12","signing_info":{"team_id":"XYZ"}}}}`,
			"gatekeeper_override", func(e *event.Event) bool {
				return e.File.Path == "/Users/alex/Downloads/tool" && e.File.Hash.SHA256 == "ab12" && e.Data["team_id"] == "XYZ"
			}},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":1}},"event":{"tcc_modify":{"service":"kTCCServiceSystemPolicyAllFiles","identity":"com.evil.agent","right":"allowed","instigator":null}}}`,
			"tcc_modified", func(e *event.Event) bool {
				return e.Data["service"] == "SystemPolicyAllFiles" && e.Data["identity"] == "com.evil.agent"
			}},
	}
	for _, c := range cases {
		msg, name, raw, err := parseESLine([]byte(c.line))
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		ev := m.mapProcess(msg, name, raw)
		if ev == nil || ev.Event.Action != c.action || !c.check(ev) {
			t.Fatalf("%s: %+v", c.action, ev)
		}
	}
}

func TestESAuth(t *testing.T) {
	m := newTestMapper()
	cases := []struct {
		line, action, outcome, user string
		check                       func(*event.Event) bool
	}{
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":90}},"event":{"openssh_login":{"success":false,"result_type":4,"source_address_type":0,"source_address":"203.0.113.9","username":"admin","has_uid":false,"uid":null}}}`,
			"ssh_login", event.OutcomeFailure, "admin", func(e *event.Event) bool { return e.Source.IP == "203.0.113.9" && e.Data["result"] == "password" }},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":90}},"event":{"openssh_login":{"success":true,"result_type":2,"source_address":"192.168.1.5","username":"alex","has_uid":true,"uid":{"uid":501}}}}`,
			"ssh_login", event.OutcomeSuccess, "alex", func(e *event.Event) bool { return e.User.ID == "501" && len(e.Event.Category) == 2 }},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":91,"ruid":501},"executable":{"path":"\/usr\/bin\/sudo"},"start_time":"2026-11-12T09:59:59Z"},"event":{"sudo":{"success":false,"reject_info":{"plugin_name":"sudoers","plugin_type":1,"failure_message":"incorrect password"},"has_from_uid":true,"from_uid":{"uid":501},"from_username":"alex","has_to_uid":true,"to_uid":{"uid":0},"to_username":null,"command":"\/bin\/cat \/etc\/sudoers"}}}`,
			"sudo", event.OutcomeFailure, "alex", func(e *event.Event) bool {
				return e.User.Target.Name == "root" && e.Data["reason"] == "incorrect password" && e.Data["command"] == "/bin/cat /etc/sudoers"
			}},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":92}},"event":{"lw_session_unlock":{"username":"alex","graphical_session_id":257}}}`,
			"screen_unlock", event.OutcomeSuccess, "alex", nil},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":93}},"event":{"authentication":{"success":false,"type":0,"data":{"od":{"instigator":{"audit_token":{"pid":93,"ruid":501},"executable":{"path":"\/usr\/bin\/login"},"start_time":"2026-11-12T09:00:00Z"},"record_type":"user","record_name":"alex","node_name":"\/Local\/Default","db_path":null}}}}}`,
			"authentication", event.OutcomeFailure, "alex", func(e *event.Event) bool { return e.Data["auth_type"] == "opendirectory" && e.Process.Name == "login" }},
		{`{"time":"2026-11-12T10:00:00Z","process":{"audit_token":{"pid":94,"ruid":0},"executable":{"path":"\/usr\/sbin\/sysadminctl"},"start_time":"2026-11-12T09:00:00Z"},"event":{"od_group_add":{"instigator":null,"error_code":0,"group_name":"admin","member":{"member_type":0,"member_value":{"name":"backdoor"}},"node_name":"\/Local\/Default","db_path":null}}}`,
			"group_member_added", event.OutcomeSuccess, "root", func(e *event.Event) bool {
				return e.User.Target.Name == "backdoor" && e.Data["group"] == "admin" && e.Event.Category[0] == event.CategoryIAM
			}},
	}
	for _, c := range cases {
		msg, name, raw, err := parseESLine([]byte(c.line))
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		ev := m.mapAuth(msg, name, raw)
		if ev == nil || ev.Event.Action != c.action || ev.Event.Outcome != c.outcome || ev.User == nil || ev.User.Name != c.user ||
			ev.Event.Dataset != "macos.auth" || (c.check != nil && !c.check(ev)) {
			t.Fatalf("%s: %+v / %+v", c.action, ev, ev.User)
		}
	}
}

func TestESFileChange(t *testing.T) {
	cases := []struct {
		name, raw, path, old, action string
		ok                           bool
	}{
		{"create", `{"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/Users\/alex\/Library\/LaunchAgents"},"filename":"x.plist","mode":420}}}`,
			"/Users/alex/Library/LaunchAgents/x.plist", "", "created", true},
		{"create", `{"destination_type":0,"destination":{"existing_file":{"path":"\/tmp\/a"}}}`, "/tmp/a", "", "created", true},
		{"rename", `{"source":{"path":"\/tmp\/a"},"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/tmp"},"filename":"b"}}}`, "/tmp/b", "/tmp/a", "renamed", true},
		{"unlink", `{"target":{"path":"\/tmp\/b"},"parent_dir":{"path":"\/tmp"}}`, "/tmp/b", "", "deleted", true},
		{"close", `{"modified":true,"target":{"path":"\/etc\/hosts"}}`, "/etc/hosts", "", "modified", true},
		{"close", `{"modified":false,"target":{"path":"\/etc\/hosts"}}`, "", "", "", false},
	}
	for _, c := range cases {
		got, ok := fileChange(c.name, []byte(c.raw))
		if ok != c.ok || ok && (got.Path != c.path || got.OldPath != c.old || got.Action != c.action) {
			t.Fatalf("%s %s: %+v %v", c.name, c.raw, got, ok)
		}
	}
}

func TestUnifiedLogAuth(t *testing.T) {
	line := `{"traceID":1,"eventMessage":"Accepted publickey for alex from 192.168.1.20 port 51234 ssh2: ED25519 SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI","eventType":"logEvent","processImagePath":"\/usr\/libexec\/sshd-session","processID":812,"timestamp":"2026-11-12 10:00:00.123456-0600"}`
	m, ok := parseUnifiedLogLine([]byte(line))
	if !ok || m.App != "sshd-session" || m.PID != 812 || !m.Time.Equal(time.Date(2026, 11, 12, 16, 0, 0, 123456000, time.UTC)) {
		t.Fatalf("msg = %+v", m)
	}
	e := authparse.Parse(m)
	if e == nil || e.Event.Action != "ssh_login" || e.Source.IP != "192.168.1.20" || e.Labels["ssh_key"] == "" {
		t.Fatalf("event = %+v", e)
	}
}

func TestLsof(t *testing.T) {
	out := "p501\ncGoogle Chrome Helper\nu501\nf23\nPTCP\nn192.168.1.20:51515->142.250.72.14:443\nTST=ESTABLISHED\n" +
		"f24\nPUDP\nn*:5353\n" +
		"p88\ncsshd\nu0\nf3\nPTCP\nn*:22\nTST=LISTEN\nf4\nPTCP\nn[::1]:22\nTST=LISTEN\n" +
		"f5\nPTCP\nn192.168.1.20:22->192.168.1.5:60000\nTST=ESTABLISHED\n" +
		"f6\nPTCP\nn[fe80:4::1]:7000->[fe80:4::2]:51000\nTST=ESTABLISHED\n"
	es := parseLsof([]byte(out))
	if len(es) != 6 {
		t.Fatalf("entries = %+v", es)
	}
	if e := es[0]; e.PID != 501 || e.Command != "Google Chrome Helper" || e.UID != 501 || e.Transport != "tcp" || e.State != "ESTABLISHED" ||
		e.Remote != netip.MustParseAddrPort("142.250.72.14:443") {
		t.Fatalf("chrome = %+v", e)
	}
	if e := es[1]; e.Transport != "udp" || e.Remote.IsValid() || e.Local.Port() != 5353 {
		t.Fatalf("mdns = %+v", e)
	}
	if e := es[5]; e.Local != netip.MustParseAddrPort("[fe80::1]:7000") {
		t.Fatalf("zone not stripped: %+v", e)
	}
	cur, fresh := newConnections(nil, es)
	if len(cur) != 3 || len(fresh) != 3 {
		t.Fatalf("cur %d fresh %+v", len(cur), fresh)
	}
	for _, f := range fresh {
		if want := f.Local.Port() == 22; f.Inbound != want {
			t.Fatalf("direction of %+v", f)
		}
	}
	if _, again := newConnections(cur, es); len(again) != 0 {
		t.Fatal("known connections reported again")
	}
}

func TestProcArgs(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, 3)
	b = append(b, "/usr/bin/python3\x00\x00\x00\x00python3\x00-c\x00print(1)\x00PATH=/usr/bin\x00"...)
	exe, args, err := parseProcArgs(b)
	if err != nil || exe != "/usr/bin/python3" || strings.Join(args, "|") != "python3|-c|print(1)" {
		t.Fatalf("%q %q %v", exe, args, err)
	}
	if joinArgs([]string{"sh", "-c", "echo hi"}) != `sh -c "echo hi"` {
		t.Fatal(joinArgs([]string{"sh", "-c", "echo hi"}))
	}
}

func TestPlist(t *testing.T) {
	// The agent's own job definition round-trips through the XML decoder.
	j, err := parseLaunchdJob([]byte(launchdPlist("/usr/local/bin/homexdr-agent")))
	if err != nil || j.Label != serviceLabel || j.Program != "/usr/local/bin/homexdr-agent" || !j.RunAtLoad || !j.KeepAlive ||
		j.command() != "/usr/local/bin/homexdr-agent run" {
		t.Fatalf("job = %+v, %v", j, err)
	}
	x := `<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.x</string>
<key>Program</key><string>/opt/x/bin/x</string><key>StartCalendarInterval</key><dict><key>Hour</key><integer>3</integer></dict>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>Disabled</key><true/>
<key>Blob</key><data>AAEC</data><key>When</key><date>2026-01-02T03:04:05Z</date></dict></plist>`
	j, err = parseLaunchdJob([]byte(x))
	if err != nil || j.Program != "/opt/x/bin/x" || !j.Disabled || !j.KeepAlive || len(j.Triggers) != 1 {
		t.Fatalf("job = %+v, %v", j, err)
	}
	// bplist00 for {"Label": "x", "RunAtLoad": true, "Count": 300}.
	b := []byte("bplist00")
	b = append(b, 0xD3, 1, 2, 3, 4, 5, 6) // dict of 3: keys 1-3, values 4-6
	offs := []int{8}
	add := func(obj ...byte) { offs = append(offs, len(b)); b = append(b, obj...) }
	add(append([]byte{0x55}, "Label"...)...)
	add(append([]byte{0x59}, "RunAtLoad"...)...)
	add(append([]byte{0x55}, "Count"...)...)
	add(0x51, 'x')
	add(0x09)
	add(0x11, 0x01, 0x2C) // 2-byte int 300
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o))
	}
	tr := make([]byte, 32)
	tr[6], tr[7] = 1, 1
	binary.BigEndian.PutUint64(tr[8:], uint64(len(offs)))
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	b = append(b, tr...)
	v, err := decodePlist(b)
	m, _ := v.(map[string]any)
	if err != nil || m["Label"] != "x" || m["RunAtLoad"] != true || m["Count"] != int64(300) {
		t.Fatalf("bplist = %#v, %v", v, err)
	}
	if _, err := decodePlist(b[:len(b)-5]); err == nil {
		t.Fatal("truncated bplist decoded")
	}
}

func TestPfRules(t *testing.T) {
	iso := platform.Isolation{ServerIPs: []netip.Addr{netip.MustParseAddr("192.168.20.20")}, ServerPort: 8443,
		Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/24")}}
	r := pfRules(iso, []netip.Addr{netip.MustParseAddr("192.168.20.1"), netip.MustParseAddr("fd00::1")})
	for _, want := range []string{
		"pass out quick inet proto tcp from any to 192.168.20.20 port 8443",
		"pass out quick inet proto { udp, tcp } from any to 192.168.20.1 port 53",
		"pass out quick inet6 proto { udp, tcp } from any to fd00::1 port 53",
		"pass out quick inet from any to 10.0.0.0/24",
		"pass quick on lo0 all",
	} {
		if !strings.Contains(r, want+"\n") {
			t.Fatalf("missing %q in\n%s", want, r)
		}
	}
	if !strings.HasSuffix(r, "block drop quick all\n") {
		t.Fatalf("rules must end with the block:\n%s", r)
	}
	main := "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
	if !pfMainHasAppleAnchor([]byte(main)) || pfMainHasAppleAnchor([]byte("pass all\n")) {
		t.Fatal("anchor detection")
	}
	if pfToken([]byte("No ALTQ support in kernel\npf enabled\nToken : 13940349214532\n")) != "13940349214532" {
		t.Fatal("token")
	}
}

func TestCommandParsers(t *testing.T) {
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	ws := parseWho([]byte("alex     console  Jan  2 09:14 \nalex     ttys001  Dec 31 23:02 (192.168.1.20)\n"), now)
	if len(ws) != 2 || ws[0].Time.Year() != 2026 || ws[1].Time.Year() != 2025 || ws[1].Host != "192.168.1.20" {
		t.Fatalf("who = %+v", ws)
	}
	ds := parseDSCache([]byte("name: alex\nuid: 501\ngid: 20\ndir: /Users/alex\nshell: /bin/zsh\n\nname: _www\nuid: 70\n"))
	if len(ds) != 2 || ds[0]["dir"] != "/Users/alex" || ds[1]["uid"] != "70" {
		t.Fatalf("dscacheutil = %+v", ds)
	}
	l := parseLaunchctlList([]byte("PID\tStatus\tLabel\n412\t0\tcom.apple.sshd\n-\t0\tcom.homexdr.agent\n"))
	if l["com.apple.sshd"] != 412 || l["com.homexdr.agent"] != 0 || len(l) != 2 {
		t.Fatalf("launchctl list = %v", l)
	}
	d := parsePrintDisabled([]byte("disabled services = {\n\t\"com.apple.ftpd\" => disabled\n\t\"com.x\" => enabled\n}\n"))
	if !d["com.apple.ftpd"] || d["com.x"] {
		t.Fatalf("print-disabled = %v", d)
	}
	if s := parseLaunchctlState([]byte("system/com.homexdr.agent = {\n\tactive count = 1\n\tstate = running\n")); s != "running" {
		t.Fatal(s)
	}
	cr := parseCrontab([]byte("SHELL=/bin/sh\n*/5 * * * * root /usr/local/bin/x --y\n@reboot root /tmp/z\n"), true)
	if len(cr) != 2 || cr[0].User != "root" || cr[0].Command != "/usr/local/bin/x --y" || cr[1].Schedule != "@reboot" {
		t.Fatalf("crontab = %+v", cr)
	}
	if u := parseIOPlatformUUID([]byte(`    "IOPlatformUUID" = "A1B2C3D4-0000-1111-2222-333344445555"`)); u != "A1B2C3D4-0000-1111-2222-333344445555" {
		t.Fatal(u)
	}
	rs := parseResolvConf([]byte("#\nnameserver 192.168.20.1\nnameserver fe80::1%en0\n"))
	if len(rs) != 2 || rs[1].String() != "fe80::1" {
		t.Fatalf("resolvers = %v", rs)
	}
	if bundleVendor("com.google.Chrome") != "google" || bundleVendor("com.apple.Safari") != "Apple" {
		t.Fatal("vendor")
	}
}
