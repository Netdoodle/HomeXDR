package storyline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const host = "agent-1"

type fixture struct {
	t   *testing.T
	ctx context.Context
	src Sources
	t0  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &fixture{t: t, ctx: context.Background(), src: Sources{Events: ev, State: st},
		t0: time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)}
}

func (f *fixture) insert(evs ...*event.Event) {
	f.t.Helper()
	if err := f.src.Events.Insert(f.ctx, evs); err != nil {
		f.t.Fatal(err)
	}
}

func base(path string) string { return path[strings.LastIndexAny(path, `\/`)+1:] }

// start is a process start event at t0+minutes.
func (f *fixture) start(entity, parent, exe, cmd string, minutes int) *event.Event {
	at := f.t0.Add(time.Duration(minutes) * time.Minute)
	e := &event.Event{
		ID: event.NewID(), Timestamp: at,
		Host:  event.Host{ID: host, Name: "desk", OS: &event.OS{Platform: event.PlatformWindows}},
		Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}, Module: event.ModuleETW},
		Process: &event.Process{EntityID: entity, PID: int64(1000 + len(f.t.Name()) + minutes), Name: base(exe), Executable: exe,
			CommandLine: cmd, User: &event.User{Name: "alice"}, IntegrityLevel: "medium"},
	}
	if parent != "" {
		e.Process.Parent = &event.Process{EntityID: parent}
	}
	return e
}

// parentNamed adds the parent's name and command line, as the Windows agent sends them.
func parentNamed(e *event.Event, name, cmd string) *event.Event {
	e.Process.Parent.Name, e.Process.Parent.CommandLine = name, cmd
	return e
}

func (f *fixture) end(entity string, minutes int, code int64) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: f.t0.Add(time.Duration(minutes) * time.Minute),
		Host:    event.Host{ID: host, Name: "desk"},
		Event:   event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeEnd}},
		Process: &event.Process{EntityID: entity, ExitCode: &code},
	}
}

func (f *fixture) cross(actor, target, action string, minutes int) *event.Event {
	e := &event.Event{
		ID: event.NewID(), Timestamp: f.t0.Add(time.Duration(minutes) * time.Minute),
		Host: event.Host{ID: host, Name: "desk"},
		Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeAccess},
			Action: action, Provider: "Microsoft-Windows-Sysmon", Module: event.ModuleEventLog},
		Process: &event.Process{EntityID: actor},
	}
	if target != "" {
		e.Target = &event.Target{Process: &event.Process{EntityID: target}}
	}
	return e
}

func (f *fixture) alert(rule, entity, sev string, tactics ...string) *store.Alert {
	f.t.Helper()
	var mitre []store.Mitre
	for _, t := range tactics {
		mitre = append(mitre, store.Mitre{Tactic: t})
	}
	ev := &event.Event{ID: event.NewID(), Timestamp: time.Now().UTC(), Host: event.Host{ID: host, Name: "desk"},
		Process: &event.Process{EntityID: entity, Name: entity}}
	a, _, err := f.src.State.RecordAlert(f.ctx, store.AlertInput{Rule: store.AlertRule{ID: rule, Title: rule}, Severity: sev,
		Mitre: mitre, Event: ev})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func nodeMap(g *Graph) map[string]*Node {
	m := map[string]*Node{}
	for _, n := range g.Nodes {
		m[n.EntityID] = n
	}
	return m
}

func edgeKeys(g *Graph) []string {
	var out []string
	for _, e := range g.Edges {
		out = append(out, e.Kind+":"+e.From+">"+e.To)
	}
	slices.Sort(out)
	return out
}

func TestStorylineWindowsChain(t *testing.T) {
	f := newFixture(t)
	upd := `C:\Users\alice\AppData\Roaming\upd.exe`
	psStart := f.start("e-ps", "e-cmd", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -nop -enc SQBFAFgA", 3)
	f.insert(
		f.start("e-explorer", "e-userinit", `C:\Windows\explorer.exe`, "explorer.exe", 0),
		f.start("e-word", "e-explorer", `C:\Program Files\Microsoft Office\WINWORD.EXE`, "winword invoice.docm", 1),
		f.start("e-cmd", "e-word", `C:\Windows\System32\cmd.exe`, "cmd /c powershell -nop -enc SQBFAFgA", 2),
		psStart,
		f.start("e-who", "e-ps", `C:\Windows\System32\whoami.exe`, "whoami /all", 4),
		f.end("e-who", 5, 0),
		f.start("e-schtasks", "e-ps", `C:\Windows\System32\schtasks.exe`,
			`schtasks /create /tn Updater /sc minute /tr "`+upd+` -q"`, 6),
		// Explorer's other child, reached only through the remote thread.
		f.start("e-note", "e-explorer", `C:\Windows\System32\notepad.exe`, "notepad", 1),
		f.start("e-lsass", "e-wininit", `C:\Windows\System32\lsass.exe`, "lsass.exe", -60),
		// The Task Scheduler runs the payload an hour later, and other things.
		f.start("e-svch", "e-services", `C:\Windows\System32\svchost.exe`, "svchost.exe -k netsvcs -p -s Schedule", -50),
		parentNamed(f.start("e-upd", "e-svch", upd, `"`+upd+`" -q`, 66), "svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
		f.start("e-updkid", "e-upd", `C:\Windows\System32\net.exe`, "net user", 67),
		parentNamed(f.start("e-noise", "e-svch", `C:\Windows\System32\backgroundTaskHost.exe`, "backgroundTaskHost.exe -ServerName:x", 70), "svchost.exe", ""),
		// The same program from another service's svchost is not the task.
		parentNamed(f.start("e-bits", "e-svch2", upd, `"`+upd+`" -q`, 80), "svchost.exe", "svchost.exe -k netsvcs -p -s BITS"),
		// Nor is a run more than a day later.
		parentNamed(f.start("e-late", "e-svch", upd, `"`+upd+`" -q`, 6+25*60), "svchost.exe", ""),
	)
	thread := f.cross("e-ps", "e-note", event.ActionRemoteThread, 7)
	thread.Target.StartModule, thread.Target.StartFunction = `C:\Windows\System32\kernel32.dll`, "LoadLibraryW"
	access1 := f.cross("e-ps", "e-lsass", event.ActionProcessAccess, 8)
	access1.Target.GrantedAccess = "0x1010"
	access2 := f.cross("e-ps", "e-lsass", event.ActionProcessAccess, 9)
	access2.Target.GrantedAccess = "0x1fffff"
	tamper := f.cross("e-upd", "", "", 68)
	tamper.Event.Code = "25"
	tamper.Target = &event.Target{Tampering: "Image is replaced"}
	conn := &event.Event{ID: event.NewID(), Timestamp: f.t0.Add(10 * time.Minute), Host: event.Host{ID: host, Name: "desk"},
		Event:   event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryNetwork}, Type: []string{event.TypeConnection}},
		Process: &event.Process{EntityID: "e-ps"}, Destination: &event.Endpoint{IP: "203.0.113.9", Port: 443}}
	f.insert(thread, access1, access2, tamper, conn)
	a1 := f.alert("encoded-ps", "e-ps", store.SevHigh, "Execution")
	a2 := f.alert("lsass-access", "e-ps", store.SevCritical, "Defense Evasion", "Privilege Escalation")
	f.alert("task-payload", "e-upd", store.SevMedium, "Persistence")
	f.alert("other-proc", "e-elsewhere", store.SevLow, "Discovery")

	g, err := Build(f.ctx, f.src, host, "e-ps", 0+DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	if g.RootEntityID != "e-word" || g.FocusEntityID != "e-ps" || g.Hostname != "desk" || g.Truncated {
		t.Fatalf("graph header = root %s focus %s host %q truncated %v", g.RootEntityID, g.FocusEntityID, g.Hostname, g.Truncated)
	}
	nodes := nodeMap(g)
	var ids []string
	for id := range nodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	want := []string{"e-cmd", "e-explorer", "e-lsass", "e-note", "e-ps", "e-schtasks", "e-upd", "e-updkid", "e-who", "e-word"}
	if !slices.Equal(ids, want) {
		t.Fatalf("nodes = %v, want %v", ids, want)
	}
	check := func(id string, depth int, focus, root, ctx, outside bool) {
		t.Helper()
		n := nodes[id]
		if n.Depth != depth || n.Focus != focus || n.Root != root || n.Context != ctx || n.Outside != outside {
			t.Errorf("%s: depth %d focus %v root %v context %v outside %v", id, n.Depth, n.Focus, n.Root, n.Context, n.Outside)
		}
	}
	check("e-explorer", -1, false, false, true, false)
	check("e-word", 0, false, true, false, false)
	check("e-cmd", 1, false, false, false, false)
	check("e-ps", 2, true, false, false, false)
	check("e-who", 3, false, false, false, false)
	check("e-note", 2, false, false, false, true)
	check("e-lsass", 2, false, false, false, true)
	check("e-upd", 4, false, false, false, false)
	check("e-updkid", 5, false, false, false, false)
	if g.Nodes[0].EntityID != "e-explorer" || g.Nodes[1].EntityID != "e-word" {
		t.Errorf("nodes not ordered by depth: %s, %s", g.Nodes[0].EntityID, g.Nodes[1].EntityID)
	}

	wantEdges := []string{
		"parent:e-cmd>e-ps", "parent:e-explorer>e-word",
		"parent:e-explorer>e-note", // an outside node keeps its parent link when the parent is a node
		"parent:e-ps>e-schtasks", "parent:e-ps>e-who",
		"parent:e-upd>e-updkid", "parent:e-word>e-cmd",
		"process_access:e-ps>e-lsass", "process_tampering:e-upd>e-upd", "remote_thread:e-ps>e-note",
		"scheduled_task:e-schtasks>e-upd",
	}
	slices.Sort(wantEdges)
	if got := edgeKeys(g); !slices.Equal(got, wantEdges) {
		t.Fatalf("edges =\n%v\nwant\n%v", got, wantEdges)
	}
	for _, e := range g.Edges {
		switch e.Kind {
		case EdgeProcessAccess:
			if e.Detail != "0x1010" || e.EventID != access1.ID || !e.At.Equal(access1.Timestamp) {
				t.Errorf("collapsed access edge = %+v", e)
			}
		case EdgeRemoteThread:
			if e.Detail != `C:\Windows\System32\kernel32.dll!LoadLibraryW` || e.EventID != thread.ID {
				t.Errorf("remote thread edge = %+v", e)
			}
		case EdgeProcessTampering:
			if e.Detail != "Image is replaced" {
				t.Errorf("tampering edge = %+v", e)
			}
		case EdgeScheduledTask:
			if !strings.Contains(e.Detail, "schtasks /create") || e.At == nil {
				t.Errorf("launch edge = %+v", e)
			}
		case EdgeParent:
			if e.To == "e-ps" && e.EventID != psStart.ID {
				t.Errorf("parent edge evidence = %+v", e)
			}
		}
	}

	ps := nodes["e-ps"]
	if ps.AlertCount != 2 || ps.MaxSeverity != store.SevCritical ||
		!slices.Equal(ps.Tactics, []string{"execution", "privilege-escalation", "defense-evasion"}) {
		t.Errorf("focus alerts: count %d max %q tactics %v", ps.AlertCount, ps.MaxSeverity, ps.Tactics)
	}
	if ps.EventCounts["network"] != 1 || len(ps.EventCounts) != 5 {
		t.Errorf("event counts = %v", ps.EventCounts)
	}
	if n := nodes["e-word"]; n.AlertCount != 0 || n.MaxSeverity != "" || n.Tactics == nil || len(n.Tactics) != 0 {
		t.Errorf("quiet node = %+v", n)
	}
	if who := nodes["e-who"]; who.End == nil || who.ExitCode == nil || *who.ExitCode != 0 || who.Stub {
		t.Errorf("ended node = %+v", who)
	}
	if ps.User != "alice" || ps.IntegrityLevel != "medium" || ps.CommandLine == "" || ps.Start == nil || ps.ParentEntityID != "e-cmd" {
		t.Errorf("focus fields = %+v", ps)
	}
	if len(g.Alerts) != 3 {
		t.Fatalf("alerts = %+v", g.Alerts)
	}
	for _, a := range g.Alerts {
		if a.ID == a2.ID && (a.EntityID != "e-ps" || !slices.Equal(a.Tactics, []string{"privilege-escalation", "defense-evasion"})) {
			t.Errorf("alert = %+v", a)
		}
		if a.ID == a1.ID && a.Title != "encoded-ps" {
			t.Errorf("alert = %+v", a)
		}
	}

	// The JSON contract: every field present, arrays never null.
	raw, _ := json.Marshal(g)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"host_id", "hostname", "focus_entity_id", "root_entity_id", "truncated", "nodes", "edges", "alerts"} {
		if _, ok := m[k]; !ok {
			t.Errorf("graph JSON lacks %s", k)
		}
	}
	node := m["nodes"].([]any)[0].(map[string]any)
	for _, k := range []string{"entity_id", "pid", "name", "executable", "command_line", "user", "start", "end", "exit_code",
		"signed", "integrity_level", "parent_entity_id", "depth", "focus", "root", "context", "outside", "stub",
		"alert_count", "max_severity", "tactics", "event_counts"} {
		if _, ok := node[k]; !ok {
			t.Errorf("node JSON lacks %s", k)
		}
	}
	edge := m["edges"].([]any)[0].(map[string]any)
	for _, k := range []string{"from", "to", "kind", "at", "event_id", "detail"} {
		if _, ok := edge[k]; !ok {
			t.Errorf("edge JSON lacks %s", k)
		}
	}
	alert := m["alerts"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "title", "severity", "status", "first_seen", "last_seen", "entity_id", "tactics"} {
		if _, ok := alert[k]; !ok {
			t.Errorf("alert JSON lacks %s", k)
		}
	}

	// depth 0: the lineage only, with the focus's own children not walked either.
	g, err = Build(f.ctx, f.src, host, "e-ps", 0)
	if err != nil {
		t.Fatal(err)
	}
	nodes = nodeMap(g)
	for _, id := range []string{"e-who", "e-schtasks", "e-upd"} {
		if nodes[id] != nil {
			t.Errorf("depth 0 includes %s", id)
		}
	}
	if nodes["e-ps"] == nil || nodes["e-word"] == nil || nodes["e-explorer"] == nil {
		t.Error("depth 0 lost the lineage")
	}
}

func TestStorylineRoots(t *testing.T) {
	f := newFixture(t)
	lin := func(e *event.Event) *event.Event {
		e.Host.OS.Platform = event.PlatformLinux
		return e
	}
	f.insert(
		lin(f.start("l-systemd", "", "/usr/lib/systemd/systemd", "/sbin/init", 0)),
		lin(f.start("l-sshd", "l-systemd", "/usr/sbin/sshd", "sshd -D", 1)),
		lin(f.start("l-sshd2", "l-sshd", "/usr/sbin/sshd", "sshd: alice [priv]", 2)),
		lin(f.start("l-bash", "l-sshd2", "/usr/bin/bash", "-bash", 3)),
		lin(f.start("l-sh", "l-bash", "/usr/bin/sh", "sh -c curl", 4)),
		lin(f.start("l-curl", "l-sh", "/usr/bin/curl", "curl http://203.0.113.9/x", 5)),
		f.start("w-services", "w-wininit", `C:\Windows\System32\services.exe`, "services.exe", 0),
		f.start("w-svchost", "w-services", `C:\Windows\System32\svchost.exe`, "svchost.exe -k netsvcs", 1),
		f.start("w-child", "w-svchost", `C:\Windows\System32\wbem\WmiPrvSE.exe`, "wmiprvse.exe", 2),
		// A child whose parent never reported: the parent is a stub, and the root.
		f.start("w-orphan", "w-gone", `C:\Users\alice\x.exe`, "x.exe", 3),
		// A Windows service (started by services.exe) that runs for as long as the
		// machine: each session under it is its own storyline.
		f.start("w-sshd", "w-services", `C:\Windows\System32\OpenSSH\sshd.exe`, "sshd.exe", 1),
		f.start("w-sess1", "w-sshd", `C:\Windows\System32\OpenSSH\sshd.exe`, "sshd.exe -y", 2),
		f.start("w-ps", "w-sess1", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell", 3),
		f.start("w-sess2", "w-sshd", `C:\Windows\System32\OpenSSH\sshd.exe`, "sshd.exe -y", 4),
		f.start("w-cmd", "w-sess2", `C:\Windows\System32\cmd.exe`, "cmd", 5),
	)

	g, err := Build(f.ctx, f.src, host, "w-ps", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	nodes := nodeMap(g)
	if g.RootEntityID != "w-sess1" || !nodes["w-sshd"].Context || nodes["w-sess2"] != nil || nodes["w-cmd"] != nil {
		t.Errorf("service child root = %s, edges %v", g.RootEntityID, edgeKeys(g))
	}

	// More marks nodes whose children were not looked up.
	g, err = Build(f.ctx, f.src, host, "w-sess1", 1)
	if err != nil {
		t.Fatal(err)
	}
	nodes = nodeMap(g)
	if nodes["w-sess1"].More || !nodes["w-ps"].More || nodes["w-sshd"].More {
		t.Errorf("more: sess1 %v, ps %v, sshd (context) %v", nodes["w-sess1"].More, nodes["w-ps"].More, nodes["w-sshd"].More)
	}

	g, err = Build(f.ctx, f.src, host, "l-curl", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	nodes = nodeMap(g)
	if g.RootEntityID != "l-bash" || !nodes["l-sshd2"].Context || nodes["l-sshd2"].Depth != -1 || nodes["l-sshd"] != nil {
		t.Errorf("linux root = %s, nodes %v", g.RootEntityID, edgeKeys(g))
	}
	if nodes["l-curl"].Depth != 2 {
		t.Errorf("curl depth = %d", nodes["l-curl"].Depth)
	}

	// A system process as focus is its own root, with its parent as context.
	g, err = Build(f.ctx, f.src, host, "w-svchost", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	nodes = nodeMap(g)
	if g.RootEntityID != "w-svchost" || !nodes["w-svchost"].Root || !nodes["w-svchost"].Focus ||
		!nodes["w-services"].Context || nodes["w-child"] == nil {
		t.Errorf("boundary focus: root %s, edges %v", g.RootEntityID, edgeKeys(g))
	}

	g, err = Build(f.ctx, f.src, host, "w-orphan", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	nodes = nodeMap(g)
	if gone := nodes["w-gone"]; g.RootEntityID != "w-gone" || gone == nil || !gone.Stub || gone.Name != "(unknown parent)" || gone.Start != nil {
		t.Errorf("stub parent: root %s, %+v", g.RootEntityID, gone)
	}

	if _, err := Build(f.ctx, f.src, host, "nope", DefaultDepth); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing process: %v", err)
	}
	if _, err := Build(f.ctx, f.src, "other-host", "l-curl", DefaultDepth); !errors.Is(err, ErrNotFound) {
		t.Errorf("process on another host: %v", err)
	}
}

func TestStorylineFocusFromCrossProcessOnly(t *testing.T) {
	f := newFixture(t)
	f.insert(f.start("e-a", "", `C:\Users\alice\a.exe`, "a.exe", 0))
	e := f.cross("e-a", "e-victim", event.ActionProcessAccess, 1)
	e.Target.Process.Name = "victim.exe"
	f.insert(e)
	g, err := Build(f.ctx, f.src, host, "e-victim", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	nodes := nodeMap(g)
	if v := nodes["e-victim"]; v == nil || !v.Stub || !v.Focus || v.Name != "victim.exe" || nodes["e-a"] == nil || !nodes["e-a"].Outside {
		t.Fatalf("nodes = %+v", nodes)
	}
}

func TestStorylineTruncates(t *testing.T) {
	f := newFixture(t)
	evs := []*event.Event{f.start("e-root", "", `C:\Users\alice\fork.exe`, "fork.exe", 0)}
	for i := range MaxNodes + 50 {
		evs = append(evs, f.start(fmt.Sprintf("e-kid-%03d", i), "e-root", `C:\Users\alice\kid.exe`, "kid.exe", 1))
	}
	f.insert(evs...)
	g, err := Build(f.ctx, f.src, host, "e-root", DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Truncated || len(g.Nodes) != MaxNodes {
		t.Fatalf("truncated %v with %d nodes", g.Truncated, len(g.Nodes))
	}
}

func TestLaunchKind(t *testing.T) {
	cases := map[string]string{
		`schtasks /create /tn x /tr c:\x.exe /sc onlogon`:                 EdgeScheduledTask,
		`"C:\Windows\System32\schtasks.exe" -Create -TN x -TR "c:\x.exe"`: EdgeScheduledTask,
		`schtasks /query`:   "",
		`at 12:30 c:\x.exe`: EdgeScheduledTask,
		`powershell Register-ScheduledTask -TaskName x -Action $a`: EdgeScheduledTask,
		`sc.exe create evil binPath= "c:\x.exe"`:                   EdgeService,
		`sc \\server config evil binPath= c:\x.exe`:                EdgeService,
		`sc query`: "",
		`powershell New-Service -Name x -BinaryPathName c:\x.exe`:                              EdgeService,
		`wmic /node:pc process call create "c:\x.exe"`:                                         EdgeWMI,
		`powershell Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList c:\x.exe`: EdgeWMI,
		`powershell Invoke-CimMethod -MethodName Create -ClassName Win32_Process`:              EdgeWMI,
		`powershell Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{}`:            EdgeWMI,
		`cmd /c echo create a task`:                                                            "",
		`notepad c:\data\batch 12:30.txt`:                                                      "",
	}
	for cmd, want := range cases {
		if got := launchKind(cmd); got != want {
			t.Errorf("launchKind(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestPayloadMatch(t *testing.T) {
	creator := `schtasks /create /tn u /tr "C:\Users\alice\upd.exe -q" /sc minute`
	cases := []struct {
		exe, cmd string
		want     bool
	}{
		{`C:\Users\alice\upd.exe`, `"C:\Users\alice\upd.exe" -q`, true},
		{`C:\Users\alice\upd.exe`, `C:\Users\alice\upd.exe`, true},
		{`C:\Users\alice\other.exe`, `other.exe -q`, false},
		{`C:\Windows\System32\cmd.exe`, `cmd.exe /c whatever`, false},
	}
	for _, c := range cases {
		n := &Node{Executable: c.exe, Name: base(c.exe), CommandLine: c.cmd}
		if got := payloadMatch(creator, n); got != c.want {
			t.Errorf("payloadMatch(%s, %s) = %v", c.exe, c.cmd, got)
		}
	}
	// A system binary named in full still needs its arguments to match.
	sys := `schtasks /create /tn u /tr "C:\Windows\System32\cmd.exe /c c:\evil.bat"`
	if !payloadMatch(sys, &Node{Executable: `C:\Windows\System32\cmd.exe`, Name: "cmd.exe", CommandLine: `C:\Windows\system32\cmd.exe /c c:\evil.bat`}) {
		t.Error("system binary with matching arguments not linked")
	}
	if payloadMatch(sys, &Node{Executable: `C:\Windows\System32\cmd.exe`, Name: "cmd.exe", CommandLine: `C:\Windows\system32\cmd.exe /c cleanup.cmd`}) {
		t.Error("system binary with other arguments linked")
	}
	// WMI: the file name and arguments are enough.
	wmi := `wmic process call create "powershell.exe -nop -w hidden -c iex"`
	if !payloadMatch(wmi, &Node{Executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Name: "powershell.exe",
		CommandLine: `powershell.exe -nop -w hidden -c iex`}) {
		t.Error("wmi payload not linked")
	}
}

func TestTactics(t *testing.T) {
	got := unionTactics([]string{"defense-evasion", "custom"}, []string{tacticSlug("Command and Control"), tacticSlug("initial_access"), "defense-evasion"})
	want := []string{"initial-access", "defense-evasion", "command-and-control", "custom"}
	if !slices.Equal(got, want) {
		t.Errorf("unionTactics = %v, want %v", got, want)
	}
}

func TestIsBoundary(t *testing.T) {
	for _, n := range []string{"System", "SVCHOST.EXE", "explorer.exe", "systemd", "containerd-shim-runc-v2", "sshd"} {
		if !isBoundary(n) {
			t.Errorf("%s should be a boundary", n)
		}
	}
	for _, n := range []string{"bash", "powershell.exe", "cmd.exe", "python3", ""} {
		if isBoundary(n) {
			t.Errorf("%s should not be a boundary", n)
		}
	}
}
