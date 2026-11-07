//go:build windows

package windows

import (
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/windows"
)

// Fixtures as EvtRender(EvtRenderEventXml) returns them.

const sysmonStartXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:15:30.1234567Z'/><EventRecordID>48211</EventRecordID><Correlation/><Execution ProcessID='3120' ThreadID='4412'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-HX01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-07 10:15:30.118</Data><Data Name='ProcessGuid'>{3f0a1c2e-d6a2-6728-5c03-000000002e00}</Data><Data Name='ProcessId'>7744</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>10.0.26100.1 (WinBuild.160101.0800)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=</Data><Data Name='CurrentDirectory'>C:\Users\alice\</Data><Data Name='User'>HX01\alice</Data><Data Name='LogonGuid'>{3f0a1c2e-d5f0-6728-1a2b-0c0000000000}</Data><Data Name='LogonId'>0xC2B1A</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>High</Data><Data Name='Hashes'>SHA1=3B8D30A4E8BF5E2F9B8C3D6A4B4F0E6C1D2A3B4C,MD5=9A7C2E1F0B3D4C5E6F708192A3B4C5D6,SHA256=0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0,IMPHASH=A1B2C3D4E5F60718293A4B5C6D7E8F90</Data><Data Name='ParentProcessGuid'>{3f0a1c2e-d6a0-6728-5a03-000000002e00}</Data><Data Name='ParentProcessId'>6620</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data><Data Name='ParentUser'>HX01\alice</Data></EventData></Event>`

const sysmonExitXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>5</EventID><Version>3</Version><Level>4</Level><Task>5</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:15:42.5012345Z'/><EventRecordID>48219</EventRecordID><Correlation/><Execution ProcessID='3120' ThreadID='4412'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-HX01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-07 10:15:42.497</Data><Data Name='ProcessGuid'>{3f0a1c2e-d6a2-6728-5c03-000000002e00}</Data><Data Name='ProcessId'>7744</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>HX01\alice</Data></EventData></Event>`

const securityStartXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:20:01.5550000Z'/><EventRecordID>912345</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='9876'/><Channel>Security</Channel><Computer>DESKTOP-HX01</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1111111111-2222222222-3333333333-1001</Data><Data Name='SubjectUserName'>alice</Data><Data Name='SubjectDomainName'>HX01</Data><Data Name='SubjectLogonId'>0xc2b1a</Data><Data Name='NewProcessId'>0x1f40</Data><Data Name='NewProcessName'>C:\Windows\System32\net.exe</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x19dc</Data><Data Name='CommandLine'>net localgroup administrators svc-backup /add</Data><Data Name='TargetUserSid'>S-1-5-21-1111111111-2222222222-3333333333-1002</Data><Data Name='TargetUserName'>svc-backup</Data><Data Name='TargetDomainName'>HX01</Data><Data Name='TargetLogonId'>0x5d3f10</Data><Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data><Data Name='MandatoryLabel'>S-1-16-12288</Data></EventData></Event>`

const securityExitXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4689</EventID><Version>0</Version><Level>0</Level><Task>13313</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:20:03.0000000Z'/><EventRecordID>912350</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='9876'/><Channel>Security</Channel><Computer>DESKTOP-HX01</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1111111111-2222222222-3333333333-1002</Data><Data Name='SubjectUserName'>svc-backup</Data><Data Name='SubjectDomainName'>HX01</Data><Data Name='SubjectLogonId'>0x5d3f10</Data><Data Name='Status'>0x2</Data><Data Name='ProcessId'>0x1f40</Data><Data Name='ProcessName'>C:\Windows\System32\net.exe</Data></EventData></Event>`

const (
	aliceSID  = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	backupSID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
)

// eventXML builds a record in the same shape as the fixtures, for variations.
func eventXML(provider, channel string, id, record int, created string, data [][2]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='%s'/>`+
		`<EventID>%d</EventID><Version>2</Version><Level>0</Level><TimeCreated SystemTime='%s'/>`+
		`<EventRecordID>%d</EventRecordID><Execution ProcessID='4' ThreadID='8'/><Channel>%s</Channel>`+
		`<Computer>DESKTOP-HX01</Computer><Security/></System><EventData>`, provider, id, created, record, channel)
	for _, kv := range data {
		fmt.Fprintf(&b, `<Data Name='%s'>%s</Data>`, kv[0], html.EscapeString(kv[1]))
	}
	b.WriteString(`</EventData></Event>`)
	return b.String()
}

func securityXML(id, record int, created string, data [][2]string) string {
	return eventXML("Microsoft-Windows-Security-Auditing", "Security", id, record, created, data)
}

func sysmonXML(id, record int, created string, data [][2]string) string {
	return eventXML("Microsoft-Windows-Sysmon", sysmonChannel, id, record, created, data)
}

// fakeProcs is a procSource with fixed processes.
type fakeProcs struct {
	pairs []procPair
	live  map[int64]*liveProc
}

func (f *fakeProcs) list() ([]procPair, error) { return f.pairs, nil }

func (f *fakeProcs) open(pid int64, want detailFlags) (*liveProc, bool) {
	lp, ok := f.live[pid]
	if !ok {
		return nil, false
	}
	c := *lp
	if want&(wantDetails|wantCwd) == 0 {
		c = liveProc{Created: lp.Created}
	}
	if want&wantCwd == 0 {
		c.WorkingDirectory = ""
	}
	return &c, true
}

func ft(t time.Time) windows.Filetime { return windows.NsecToFiletime(t.UnixNano()) }

func at(h, m, s, ns int) time.Time { return time.Date(2026, 11, 7, h, m, s, ns, time.UTC) }

func testEnv(t *testing.T) platform.Env {
	return platform.Env{AgentID: "agent-test", DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func mustParse(t *testing.T, x string) *Record {
	t.Helper()
	r, err := parseEventXML(x)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// newTestMapper returns a mapper whose snapshot holds explorer.exe (5000) and alice's
// cmd.exe (6620), which is the parent in the fixtures.
func newTestMapper(t *testing.T, extra map[int64]*liveProc, pe func(string) *event.PE) (*procMapper, *fakeProcs) {
	t.Helper()
	src := &fakeProcs{
		pairs: []procPair{{PID: 5000, PPID: 4800, Name: "explorer.exe"}, {PID: 6620, PPID: 5000, Name: "cmd.exe"}},
		live: map[int64]*liveProc{
			5000: {Created: ft(at(9, 0, 0, 0)), Executable: `C:\Windows\explorer.exe`, CommandLine: `C:\Windows\Explorer.EXE`, UserSID: aliceSID},
			6620: {Created: ft(at(10, 15, 0, 0)), Executable: `C:\Windows\System32\cmd.exe`, CommandLine: `"C:\Windows\system32\cmd.exe" `, UserSID: aliceSID},
		},
	}
	for pid, lp := range extra {
		src.live[pid] = lp
	}
	m := newProcMapper(testEnv(t), src, pe)
	// A fixed "now" after every fixture time, so no fixture looks like it started after
	// the clock was set back (clockSetBack) whatever the real date.
	m.now = func() time.Time { return at(23, 0, 0, 0) }
	m.users.m[aliceSID] = [2]string{"alice", "HX01"}
	m.users.m[backupSID] = [2]string{"svc-backup", "HX01"}
	if n, err := m.loadSnapshot(); err != nil || n != 2 {
		t.Fatalf("loadSnapshot = %d, %v", n, err)
	}
	return m, src
}

func checkMeta(t *testing.T, ev *event.Event, typ, action, provider, code string) {
	t.Helper()
	if ev == nil {
		t.Fatal("no event")
	}
	m := ev.Event
	if m.Kind != event.KindEvent || len(m.Category) != 1 || m.Category[0] != event.CategoryProcess ||
		len(m.Type) != 1 || m.Type[0] != typ || m.Action != action || m.Module != event.ModuleEventLog ||
		m.Dataset != "process" || m.Provider != provider || m.Code != code {
		t.Errorf("event meta = %+v", m)
	}
	if action == "exec" && m.Outcome != event.OutcomeSuccess {
		t.Errorf("outcome = %q", m.Outcome)
	}
}

func checkUser(t *testing.T, what string, u *event.User, id, name, domain string) {
	t.Helper()
	if u == nil {
		t.Errorf("%s: no user", what)
		return
	}
	if u.ID != id || u.Name != name || u.Domain != domain {
		t.Errorf("%s = %+v, want {%s %s %s}", what, *u, id, name, domain)
	}
}

func TestSysmonMapping(t *testing.T) {
	created := at(10, 15, 30, 118004200)
	m, _ := newTestMapper(t, map[int64]*liveProc{7744: {Created: ft(created), UserSID: aliceSID}}, nil)
	env := m.env

	ev := m.handle(mustParse(t, sysmonStartXML))
	checkMeta(t, ev, event.TypeStart, "exec", "Microsoft-Windows-Sysmon", "1")
	if !ev.Timestamp.Equal(at(10, 15, 30, 123456700)) {
		t.Errorf("@timestamp = %v", ev.Timestamp)
	}
	p := ev.Process
	childID := env.EntityID(7744, filetimeKey(ft(created)))
	if p.EntityID != childID {
		t.Errorf("entity ID uses %q, want the live creation time", p.EntityID)
	}
	if p.PID != 7744 || p.Name != "powershell.exe" || p.Executable != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Errorf("pid/name/executable: %d %q %q", p.PID, p.Name, p.Executable)
	}
	if p.CommandLine != "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=" {
		t.Errorf("command line = %q", p.CommandLine)
	}
	if p.WorkingDirectory != `C:\Users\alice\` {
		t.Errorf("working directory = %q", p.WorkingDirectory)
	}
	if p.Start == nil || !p.Start.Equal(created) {
		t.Errorf("start = %v, want %v", p.Start, created)
	}
	checkUser(t, "process.user", p.User, aliceSID, "alice", "HX01")
	if p.IntegrityLevel != "high" || p.Elevated == nil || !*p.Elevated || p.SessionID != 1 {
		t.Errorf("integrity/elevated/session: %q %v %d", p.IntegrityLevel, p.Elevated, p.SessionID)
	}
	if p.Hash == nil || p.Hash.SHA1 != "3b8d30a4e8bf5e2f9b8c3d6a4b4f0e6c1d2a3b4c" || p.Hash.MD5 != "9a7c2e1f0b3d4c5e6f708192a3b4c5d6" ||
		p.Hash.SHA256 != "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0" {
		t.Errorf("hash = %+v", p.Hash)
	}
	wantPE := event.PE{OriginalFileName: "PowerShell.EXE", Company: "Microsoft Corporation", Product: "Microsoft® Windows® Operating System",
		Description: "Windows PowerShell", FileVersion: "10.0.26100.1 (WinBuild.160101.0800)", Imphash: "a1b2c3d4e5f60718293a4b5c6d7e8f90"}
	if p.PE == nil || *p.PE != wantPE {
		t.Errorf("pe = %+v", p.PE)
	}
	par := p.Parent
	if par == nil {
		t.Fatal("no parent")
	}
	if par.PID != 6620 || par.EntityID != env.EntityID(6620, filetimeKey(ft(at(10, 15, 0, 0)))) {
		t.Errorf("parent pid/entity: %d %q", par.PID, par.EntityID)
	}
	if par.Executable != `C:\Windows\System32\cmd.exe` || par.Name != "cmd.exe" || par.CommandLine != `"C:\Windows\system32\cmd.exe" ` {
		t.Errorf("parent executable/name/command line: %q %q %q", par.Executable, par.Name, par.CommandLine)
	}
	checkUser(t, "process.parent.user", par.User, aliceSID, "alice", "HX01")
	if ev.Data["winlog.channel"] != sysmonChannel || ev.Data["winlog.record_id"] != uint64(48211) || ev.Data["winlog.logon_id"] != "0xc2b1a" {
		t.Errorf("data = %v", ev.Data)
	}
	if !strings.HasPrefix(ev.Message, "process started: powershell.exe -NoProfile") {
		t.Errorf("message = %q", ev.Message)
	}

	// A child of the PowerShell process: the parent resolves through Sysmon's
	// ProcessGuid, and the child (already gone) gets its key from UtcTime.
	child := m.handle(mustParse(t, sysmonXML(1, 48212, "2026-11-07T10:15:35.0100000Z", [][2]string{
		{"UtcTime", "2026-11-07 10:15:35.004"}, {"ProcessGuid", "{3f0a1c2e-d6a7-6728-6003-000000002e00}"},
		{"ProcessId", "8120"}, {"Image", `C:\Windows\System32\whoami.exe`}, {"FileVersion", "?"}, {"Description", "?"},
		{"Product", "?"}, {"Company", "?"}, {"OriginalFileName", "?"}, {"CommandLine", `"C:\Windows\system32\whoami.exe" /priv`},
		{"CurrentDirectory", `C:\Users\alice\`}, {"User", `HX01\alice`}, {"IntegrityLevel", "Medium"}, {"Hashes", "SHA256=ABCDEF"},
		{"ParentProcessGuid", "{3f0a1c2e-d6a2-6728-5c03-000000002e00}"}, {"ParentProcessId", "7744"},
		{"ParentImage", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"ParentCommandLine", "powershell.exe -NoProfile"}, {"ParentUser", `HX01\alice`},
	})))
	checkMeta(t, child, event.TypeStart, "exec", "Microsoft-Windows-Sysmon", "1")
	cp := child.Process
	if cp.EntityID != env.EntityID(8120, timeToFiletimeKey(at(10, 15, 35, 4000000))) {
		t.Errorf("exited child's entity ID should come from UtcTime")
	}
	if cp.Parent == nil || cp.Parent.EntityID != childID || cp.Parent.CommandLine != "powershell.exe -NoProfile" {
		t.Errorf("grandchild's parent = %+v, want entity %q", cp.Parent, childID)
	}
	if cp.PE != nil {
		t.Errorf("\"?\" version fields should be dropped, got %+v", cp.PE)
	}
	if cp.IntegrityLevel != "medium" || cp.Elevated == nil || *cp.Elevated {
		t.Errorf("integrity/elevated: %q %v", cp.IntegrityLevel, cp.Elevated)
	}

	// Event 5 for the PowerShell process reuses its entity ID.
	exit := m.handle(mustParse(t, sysmonExitXML))
	checkMeta(t, exit, event.TypeEnd, "exit", "Microsoft-Windows-Sysmon", "5")
	xp := exit.Process
	if xp.EntityID != childID || xp.PID != 7744 || xp.Name != "powershell.exe" {
		t.Errorf("exit process = %+v", xp)
	}
	if xp.End == nil || !xp.End.Equal(at(10, 15, 42, 497000000)) || xp.Start == nil || !xp.Start.Equal(created) {
		t.Errorf("exit start/end = %v %v", xp.Start, xp.End)
	}
	if xp.CommandLine == "" || xp.ExitCode != nil {
		t.Errorf("exit command line %q, exit code %v (Sysmon has none)", xp.CommandLine, xp.ExitCode)
	}
	checkUser(t, "exit user", xp.User, aliceSID, "alice", "HX01")
	if e := m.table.get(7744, at(10, 15, 42, 0)); e == nil || e.exited.IsZero() {
		t.Error("table entry not marked exited")
	}

	// An exit for a process the sensor never saw and that is gone has no reliable
	// entity ID and is dropped.
	unknown := sysmonXML(5, 48230, "2026-11-07T10:16:00Z", [][2]string{{"UtcTime", "2026-11-07 10:16:00.000"},
		{"ProcessGuid", "{00000000-0000-0000-0000-000000000001}"}, {"ProcessId", "9999"}, {"Image", `C:\x.exe`}})
	if ev := m.handle(mustParse(t, unknown)); ev != nil {
		t.Errorf("exit of an unknown process emitted: %+v", ev.Process)
	}
}

func TestSysmonPlaceholders(t *testing.T) {
	created := at(10, 15, 30, 118004200)
	m, _ := newTestMapper(t, map[int64]*liveProc{7744: {Created: ft(created), UserSID: "S-1-5-18"}}, nil)
	ev := m.handle(mustParse(t, sysmonXML(1, 1, "2026-11-07T10:15:30.1234567Z", [][2]string{
		{"UtcTime", "2026-11-07 10:15:30.118"}, {"ProcessId", "7744"}, {"Image", `C:\Windows\System32\svchost.exe`},
		{"CommandLine", `C:\Windows\system32\svchost.exe -k netsvcs `}, {"User", "-"}, {"IntegrityLevel", "System"},
		{"ParentProcessId", "6620"}, {"ParentImage", "-"}, {"ParentCommandLine", "-"}, {"ParentUser", "-"},
	})))
	p := ev.Process
	checkUser(t, "user from the live process", p.User, "S-1-5-18", "SYSTEM", "NT AUTHORITY")
	if p.CommandLine != `C:\Windows\system32\svchost.exe -k netsvcs ` {
		t.Errorf("command line = %q (must be kept exactly)", p.CommandLine)
	}
	if par := p.Parent; par == nil || par.Executable != `C:\Windows\System32\cmd.exe` || par.CommandLine != `"C:\Windows\system32\cmd.exe" ` {
		t.Errorf("placeholders should fall back to the table: %+v", par)
	}
}

func TestStartKeyPIDReuse(t *testing.T) {
	created := at(10, 15, 30, 118000000)
	for name, live := range map[string]time.Time{
		"reused after the event": created.Add(10 * time.Minute),
		"older than the window":  created.Add(-time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := newTestMapper(t, map[int64]*liveProc{7744: {Created: ft(live), CommandLine: "other process"}}, nil)
			ev := m.handle(mustParse(t, sysmonStartXML))
			if want := m.env.EntityID(7744, timeToFiletimeKey(created)); ev.Process.EntityID != want {
				t.Errorf("entity ID from the live process with a reused PID")
			}
			if !ev.Process.Start.Equal(created) {
				t.Errorf("start = %v", ev.Process.Start)
			}
		})
	}
	t.Run("parent created after the child", func(t *testing.T) {
		m, src := newTestMapper(t, nil, nil)
		// PID 6620 now belongs to a process created after the event, and the table
		// entry is gone: no parent entity.
		m.table = newProcTable(procTableMax)
		src.live[6620] = &liveProc{Created: ft(at(11, 0, 0, 0)), Executable: `C:\new.exe`}
		ev := m.handle(mustParse(t, sysmonStartXML))
		if par := ev.Process.Parent; par == nil || par.EntityID != "" || par.Executable != `C:\Windows\System32\cmd.exe` {
			t.Errorf("parent = %+v", par)
		}
	})
}

func TestSecurityMapping(t *testing.T) {
	created := at(10, 20, 1, 551234500)
	pe := &event.PE{OriginalFileName: "net.exe", Company: "Microsoft Corporation", Product: "Microsoft® Windows® Operating System",
		Description: "Net Command", FileVersion: "10.0.26100.1 (WinBuild.160101.0800)"}
	var peAsked string
	m, _ := newTestMapper(t, map[int64]*liveProc{8000: {
		Created: ft(created), Executable: `C:\Windows\System32\net.exe`, CommandLine: "live command line must not win",
		WorkingDirectory: `C:\Users\alice\`, UserSID: backupSID, SessionID: 1, HasSession: true,
	}}, func(path string) *event.PE { peAsked = path; return clonePE(pe) })
	env := m.env

	ev := m.handle(mustParse(t, securityStartXML))
	checkMeta(t, ev, event.TypeStart, "exec", "Microsoft-Windows-Security-Auditing", "4688")
	p := ev.Process
	id := env.EntityID(8000, filetimeKey(ft(created)))
	if p.EntityID != id || p.PID != 8000 || p.Name != "net.exe" || p.Executable != `C:\Windows\System32\net.exe` {
		t.Errorf("process = %+v", p)
	}
	if p.CommandLine != "net localgroup administrators svc-backup /add" {
		t.Errorf("command line = %q", p.CommandLine)
	}
	checkUser(t, "process.user (target account)", p.User, backupSID, "svc-backup", "HX01")
	if ev.Data["winlog.logon_id"] != "0x5d3f10" || ev.Data["winlog.record_id"] != uint64(912345) || ev.Data["winlog.channel"] != "Security" {
		t.Errorf("data = %v", ev.Data)
	}
	if p.IntegrityLevel != "high" || p.Elevated == nil || !*p.Elevated {
		t.Errorf("integrity/elevated = %q %v", p.IntegrityLevel, p.Elevated)
	}
	if p.WorkingDirectory != `C:\Users\alice\` || p.SessionID != 1 {
		t.Errorf("working directory/session from the live process = %q %d", p.WorkingDirectory, p.SessionID)
	}
	if peAsked != `C:\Windows\System32\net.exe` || p.PE == nil || *p.PE != *pe {
		t.Errorf("pe = %+v (asked for %q)", p.PE, peAsked)
	}
	if p.Start == nil || !p.Start.Equal(created) {
		t.Errorf("start = %v", p.Start)
	}
	par := p.Parent
	if par == nil || par.PID != 6620 || par.EntityID != env.EntityID(6620, filetimeKey(ft(at(10, 15, 0, 0)))) {
		t.Fatalf("parent = %+v", par)
	}
	if par.Executable != `C:\Windows\System32\cmd.exe` || par.Name != "cmd.exe" || par.CommandLine != `"C:\Windows\system32\cmd.exe" ` {
		t.Errorf("parent executable/name/command line (from the table) = %q %q %q", par.Executable, par.Name, par.CommandLine)
	}
	checkUser(t, "process.parent.user", par.User, aliceSID, "alice", "HX01")

	// 4689 reuses the entity ID and carries the exit status.
	exit := m.handle(mustParse(t, securityExitXML))
	checkMeta(t, exit, event.TypeEnd, "exit", "Microsoft-Windows-Security-Auditing", "4689")
	xp := exit.Process
	if xp.EntityID != id || xp.PID != 8000 || xp.Executable != `C:\Windows\System32\net.exe` || xp.CommandLine == "" {
		t.Errorf("exit process = %+v", xp)
	}
	if xp.ExitCode == nil || *xp.ExitCode != 2 {
		t.Errorf("exit code = %v", xp.ExitCode)
	}
	if xp.End == nil || !xp.End.Equal(at(10, 20, 3, 0)) {
		t.Errorf("end = %v", xp.End)
	}
	checkUser(t, "exit user", xp.User, backupSID, "svc-backup", "HX01")
	if exit.Message != "process exited: net.exe" {
		t.Errorf("message = %q", exit.Message)
	}
}

func securityNoCmdLine(pid string) string {
	return securityXML(4688, 912400, "2026-11-07T10:30:00.2500000Z", [][2]string{
		{"SubjectUserSid", "S-1-5-18"}, {"SubjectUserName", "DESKTOP-HX01$"}, {"SubjectDomainName", "WORKGROUP"},
		{"SubjectLogonId", "0x3e7"}, {"NewProcessId", pid}, {"NewProcessName", `C:\Windows\Temp\update.exe`},
		{"TokenElevationType", "%%1936"}, {"ProcessId", "0x19dc"}, {"CommandLine", ""},
		{"TargetUserSid", "S-1-0-0"}, {"TargetUserName", "-"}, {"TargetDomainName", "-"}, {"TargetLogonId", "0x0"},
		{"ParentProcessName", `C:\Windows\System32\cmd.exe`}, {"MandatoryLabel", "S-1-16-16384"},
	})
}

func TestSecurityMappingWithoutCommandLine(t *testing.T) {
	m, src := newTestMapper(t, nil, nil)
	ev := m.handle(mustParse(t, securityNoCmdLine("0x2328")))
	checkMeta(t, ev, event.TypeStart, "exec", "Microsoft-Windows-Security-Auditing", "4688")
	p := ev.Process
	if p.CommandLine != "" || ev.Message != `process started: C:\Windows\Temp\update.exe` {
		t.Errorf("command line %q, message %q", p.CommandLine, ev.Message)
	}
	// LocalSystem is named after the computer account in Security events.
	checkUser(t, "process.user", p.User, "S-1-5-18", "SYSTEM", "NT AUTHORITY")
	if ev.Data["winlog.logon_id"] != "0x3e7" {
		t.Errorf("logon id = %v", ev.Data["winlog.logon_id"])
	}
	if p.IntegrityLevel != "system" || p.Elevated == nil || !*p.Elevated {
		t.Errorf("integrity/elevated = %q %v", p.IntegrityLevel, p.Elevated)
	}
	created := at(10, 30, 0, 250000000)
	if p.EntityID != m.env.EntityID(9000, timeToFiletimeKey(created)) || !p.Start.Equal(created) {
		t.Error("a process that is gone should get its key from TimeCreated")
	}
	if p.WorkingDirectory != "" || p.PE != nil {
		t.Errorf("no live process, yet working directory %q, pe %+v", p.WorkingDirectory, p.PE)
	}

	// While the process is still running, its command line is read from it.
	src.live[9001] = &liveProc{Created: ft(created.Add(-2 * time.Millisecond)), CommandLine: `update.exe /quiet`}
	ev = m.handle(mustParse(t, securityNoCmdLine("0x2329")))
	if ev.Process.CommandLine != "update.exe /quiet" {
		t.Errorf("command line from the live process = %q", ev.Process.CommandLine)
	}
}

func TestSecurityExitStatus(t *testing.T) {
	m, src := newTestMapper(t, nil, nil)
	// A process from the snapshot that exits with STATUS_CONTROL_C_EXIT.
	src.live[6620].Created = ft(at(10, 15, 0, 0))
	ev := m.handle(mustParse(t, securityXML(4689, 1, "2026-11-07T10:40:00Z", [][2]string{
		{"SubjectUserSid", aliceSID}, {"SubjectUserName", "alice"}, {"SubjectDomainName", "HX01"},
		{"SubjectLogonId", "0xc2b1a"}, {"Status", "0xc000013a"}, {"ProcessId", "0x19dc"},
		{"ProcessName", `C:\Windows\System32\cmd.exe`},
	})))
	if ev == nil || ev.Process.ExitCode == nil || *ev.Process.ExitCode != 0xC000013A {
		t.Fatalf("exit = %+v", ev)
	}
	if ev.Process.EntityID != m.env.EntityID(6620, filetimeKey(ft(at(10, 15, 0, 0)))) {
		t.Error("exit of a snapshot process should reuse its entity ID")
	}
}

func TestIntegrityAndElevation(t *testing.T) {
	for in, want := range map[string]string{
		"S-1-16-0": "untrusted", "S-1-16-4096": "low", "S-1-16-8192": "medium", "S-1-16-8448": "medium",
		"S-1-16-12288": "high", "S-1-16-16384": "system", "S-1-16-20480": "system", "": "", "S-1-5-18": "",
	} {
		if got := integrityFromSID(in); got != want {
			t.Errorf("integrityFromSID(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"Low": "low", "Medium": "medium", "High": "high", "System": "system",
		"AppContainer": "low", "S-1-16-12288": "high", "-": ""} {
		if got := integrityFromName(in); got != want {
			t.Errorf("integrityFromName(%q) = %q, want %q", in, got, want)
		}
	}
	cases := []struct {
		typ, il string
		want    *bool
	}{
		{"%%1937", "high", ptr(true)}, {"%%1938", "medium", ptr(false)},
		{"%%1936", "medium", ptr(false)}, {"%%1936", "system", ptr(true)}, {"", "high", ptr(true)}, {"", "", nil},
	}
	for _, c := range cases {
		got := elevation(c.typ, c.il)
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("elevation(%q, %q) = %v, want %v", c.typ, c.il, got, c.want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestParseHelpers(t *testing.T) {
	for in, want := range map[string]int64{"0x1f40": 8000, "0X1F40": 8000, "7744": 7744, "": 0, "0x": 0, "-": 0, "-5": 0} {
		if got := parsePID(in); got != want {
			t.Errorf("parsePID(%q) = %d, want %d", in, got, want)
		}
	}
	if u := accountUser(`NT AUTHORITY\SYSTEM`); u == nil || u.Name != "SYSTEM" || u.Domain != "NT AUTHORITY" {
		t.Errorf("accountUser = %+v", u)
	}
	if u := accountUser("-"); u != nil {
		t.Errorf("accountUser(-) = %+v", u)
	}
	h, imp := parseHashes("MD5=AA,SHA256=BB,IMPHASH=CC")
	if h == nil || h.MD5 != "aa" || h.SHA256 != "bb" || h.SHA1 != "" || imp != "cc" {
		t.Errorf("parseHashes = %+v %q", h, imp)
	}
	if got := parseSysmonTime("2026-11-07 10:15:30.118"); !got.Equal(at(10, 15, 30, 118000000)) {
		t.Errorf("parseSysmonTime = %v", got)
	}
	if k := timeToFiletimeKey(time.Unix(0, 0)); k != filetimeEpochDelta {
		t.Errorf("timeToFiletimeKey(epoch) = %d", k)
	}
	now := time.Now().Truncate(100 * time.Nanosecond)
	if k := timeToFiletimeKey(now); k != filetimeKey(ft(now)) {
		t.Errorf("timeToFiletimeKey disagrees with NsecToFiletime: %d vs %d", k, filetimeKey(ft(now)))
	}
}

func TestProcTable(t *testing.T) {
	tb := newProcTable(4)
	clock := at(12, 0, 0, 0)
	tb.now = func() time.Time { return clock }
	a := &procEntry{PID: 10, Start: at(11, 0, 0, 0), EntityID: "a", SysmonGUID: "{a}"}
	tb.put(a)
	if tb.get(10, at(11, 30, 0, 0)) != a || tb.getGUID("{a}") != a {
		t.Fatal("lookup failed")
	}
	if tb.get(10, at(10, 0, 0, 0)) != nil {
		t.Error("an entry that started later matched an earlier time")
	}
	tb.exit(a, at(11, 59, 0, 0))
	if tb.get(10, at(11, 58, 30, 0)) == nil || tb.get(10, at(11, 59, 0, 500000000)) == nil {
		t.Error("exited entry should still match times before and just after its exit")
	}
	if tb.get(10, at(11, 59, 30, 0)) != nil {
		t.Error("exited entry matched a time after its exit")
	}
	clock = clock.Add(exitLinger - time.Second)
	tb.sweep()
	if tb.len() != 1 {
		t.Error("exited entry dropped before its linger time")
	}
	clock = clock.Add(2 * time.Second)
	tb.sweep()
	if tb.len() != 0 || tb.getGUID("{a}") != nil {
		t.Error("exited entry kept after its linger time")
	}
	// A reused PID replaces the old entry and its GUID.
	tb.put(&procEntry{PID: 20, Start: at(11, 0, 0, 0), SysmonGUID: "{old}"})
	tb.put(&procEntry{PID: 20, Start: at(11, 5, 0, 0), SysmonGUID: "{new}"})
	if tb.getGUID("{old}") != nil || tb.getGUID("{new}") == nil {
		t.Error("GUID index not updated on PID reuse")
	}
	// The table stays bounded; the oldest running entries go first.
	for i := range 10 {
		tb.put(&procEntry{PID: int64(100 + i), Start: at(11, 10+i, 0, 0)})
	}
	if tb.len() != 4 || tb.get(109, time.Time{}) == nil || tb.get(100, time.Time{}) != nil {
		t.Errorf("bounded table: len %d", tb.len())
	}
}

func TestReap(t *testing.T) {
	m, src := newTestMapper(t, nil, nil)
	// A process started from an event whose key is its (slightly late) record time.
	m.handle(mustParse(t, securityNoCmdLine("0x2328")))
	src.live[9000] = &liveProc{Created: ft(at(10, 30, 0, 248000000))}
	// explorer.exe exits unseen; cmd.exe's PID is reused by a new process.
	delete(src.live, 5000)
	src.live[6620] = &liveProc{Created: ft(at(10, 45, 0, 0))}
	m.reap(at(11, 0, 0, 0))
	if e := m.table.get(5000, time.Time{}); e == nil || e.exited.IsZero() {
		t.Error("vanished process not marked exited")
	}
	if e := m.table.get(6620, time.Time{}); e == nil || e.exited.IsZero() {
		t.Error("process whose PID was reused not marked exited")
	}
	if e := m.table.get(9000, time.Time{}); e == nil || !e.exited.IsZero() {
		t.Error("running process with an event-time key marked exited")
	}
}

func TestSecurityStatus(t *testing.T) {
	on := ProcessAudit{Creation: AuditSuccess, Termination: AuditSuccess, CommandLine: true, CommandLineSet: true}
	cases := []struct {
		name    string
		pol     ProcessAudit
		err     error
		saw     bool
		state   string
		contain string
	}{
		{"all on", on, nil, false, api.SensorRunning, ""},
		{"creation off", ProcessAudit{CommandLine: true}, nil, false, api.SensorDegraded, `"Audit Process Creation" is off`},
		{"no command lines", ProcessAudit{Creation: AuditSuccess, Termination: AuditSuccess}, nil, false, api.SensorDegraded, "ProcessCreationIncludeCmdLine_Enabled"},
		{"command lines seen", ProcessAudit{Creation: AuditSuccess}, nil, true, api.SensorRunning, ""},
		{"termination off", ProcessAudit{Creation: AuditSuccess}, nil, false, api.SensorDegraded, "process exits are not reported"},
		{"unreadable", ProcessAudit{}, errors.New("access denied"), false, api.SensorDegraded, "could not be read"},
		{"unreadable but working", ProcessAudit{}, errors.New("access denied"), true, api.SensorRunning, ""},
	}
	for _, c := range cases {
		state, msg := securityStatus(c.pol, c.err, c.saw)
		if state != c.state || (c.contain == "") != (msg == "") || !strings.Contains(msg, c.contain) {
			t.Errorf("%s: %s %q", c.name, state, msg)
		}
		if state == api.SensorDegraded && !strings.Contains(msg, "install Sysmon") {
			t.Errorf("%s: message should mention Sysmon: %q", c.name, msg)
		}
	}
}

// TestParentStartedInTheFuture covers a clock set back after boot: services.exe claims
// to have started hours after its child. It is still the parent when the event names its
// executable, and is rejected otherwise (a PID reused by another program).
func TestParentStartedInTheFuture(t *testing.T) {
	services := `C:\Windows\System32\services.exe`
	future := at(18, 30, 0, 0) // the child below starts at 10:30
	m, _ := newTestMapper(t, map[int64]*liveProc{
		940: {Created: ft(future), Executable: services, CommandLine: services},
	}, nil)
	child := func(pid, parentName string) *event.Event {
		return m.handle(mustParse(t, securityXML(4688, 1, "2026-11-07T10:30:00Z", [][2]string{
			{"SubjectUserSid", "S-1-5-18"}, {"NewProcessId", pid}, {"NewProcessName", `C:\Windows\System32\svchost.exe`},
			{"CommandLine", `svchost.exe -k test`}, {"ProcessId", "0x3ac"}, {"ParentProcessName", parentName},
			{"MandatoryLabel", "S-1-16-16384"},
		})))
	}
	// Now (23:00) is after the parent's start: a different program holding the PID is a
	// newer process that reused it.
	if ev := child("0x2400", `C:\Program Files\Other\other.exe`); ev.Process.Parent.EntityID != "" {
		t.Errorf("a different program with the parent's PID was accepted: %+v", ev.Process.Parent)
	}
	want := m.env.EntityID(940, filetimeKey(ft(future)))
	for i, pid := range []string{"0x2404", "0x2408"} { // live process, then table entry
		ev := child(pid, `C:\WINDOWS\system32\services.exe`)
		if p := ev.Process.Parent; p.EntityID != want || p.CommandLine != services {
			t.Errorf("event %d: parent = %+v, want entity %s", i, p, want)
		}
	}

	// Now (10:31) is before the parent's start, so the clock was set back since it
	// started: it is the parent even when the event names no image (Sysmon writes "-"
	// for parents it does not know).
	m2, _ := newTestMapper(t, map[int64]*liveProc{
		940: {Created: ft(future), Executable: services, CommandLine: services},
	}, nil)
	m2.now = func() time.Time { return at(10, 31, 0, 0) }
	ev := m2.handle(mustParse(t, securityXML(4688, 1, "2026-11-07T10:30:00Z", [][2]string{
		{"SubjectUserSid", "S-1-5-18"}, {"NewProcessId", "0x2410"}, {"NewProcessName", `C:\Windows\System32\whoami.exe`},
		{"ProcessId", "0x3ac"}, {"MandatoryLabel", "S-1-16-16384"},
	})))
	if p := ev.Process.Parent; p.EntityID != want {
		t.Errorf("parent started after now: %+v, want entity %s", p, want)
	}
}
