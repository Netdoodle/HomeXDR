//go:build windows

package windows

import (
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Records logged on a Windows 11 test machine with HomeXDR's Sysmon configuration (one
// PowerShell opening another and starting a thread in it, and a cmd.exe whose image was
// changed while suspended), moved to the fixtures' date.
const (
	sysmonAccessXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>10</EventID><Version>3</Version><Level>4</Level><Task>10</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:30:18.4017274Z'/><EventRecordID>26237</EventRecordID><Correlation/><Execution ProcessID='3744' ThreadID='4556'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-EXAMPLE01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>write access</Data><Data Name='UtcTime'>2026-11-07 10:30:18.390</Data><Data Name='SourceProcessGUID'>{504dde96-3c95-6afd-470c-000000000500}</Data><Data Name='SourceProcessId'>8692</Data><Data Name='SourceThreadId'>3300</Data><Data Name='SourceImage'>C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetProcessGUID'>{504dde96-3c98-6afd-4b0c-000000000500}</Data><Data Name='TargetProcessId'>3956</Data><Data Name='TargetImage'>C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='GrantedAccess'>0x1f3fff</Data><Data Name='CallTrace'>C:\WINDOWS\SYSTEM32\ntdll.dll+161f54|C:\WINDOWS\System32\KERNELBASE.dll+42e76|UNKNOWN(00007FFBBB515C78)</Data><Data Name='SourceUser'>WIN-EXAMPLE01\hxadmin</Data><Data Name='TargetUser'>WIN-EXAMPLE01\hxadmin</Data></EventData></Event>`

	sysmonThreadXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>8</EventID><Version>2</Version><Level>4</Level><Task>8</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:30:18.4028502Z'/><EventRecordID>26238</EventRecordID><Correlation/><Execution ProcessID='3744' ThreadID='4556'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-EXAMPLE01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-07 10:30:18.390</Data><Data Name='SourceProcessGuid'>{504dde96-3c95-6afd-470c-000000000500}</Data><Data Name='SourceProcessId'>8692</Data><Data Name='SourceImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetProcessGuid'>{504dde96-3c98-6afd-4b0c-000000000500}</Data><Data Name='TargetProcessId'>3956</Data><Data Name='TargetImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='NewThreadId'>1896</Data><Data Name='StartAddress'>0x00007FFC6D42C4D0</Data><Data Name='StartModule'>C:\WINDOWS\SYSTEM32\ntdll.dll</Data><Data Name='StartFunction'>RtlExitUserThread</Data><Data Name='SourceUser'>WIN-EXAMPLE01\hxadmin</Data><Data Name='TargetUser'>WIN-EXAMPLE01\hxadmin</Data></EventData></Event>`

	sysmonTamperXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>25</EventID><Version>5</Version><Level>4</Level><Task>25</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T10:30:18.4312015Z'/><EventRecordID>26240</EventRecordID><Correlation/><Execution ProcessID='3744' ThreadID='4556'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-EXAMPLE01</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-11-07 10:30:18.421</Data><Data Name='ProcessGuid'>{504dde96-3c9a-6afd-4d0c-000000000500}</Data><Data Name='ProcessId'>6108</Data><Data Name='Image'>C:\Windows\System32\cmd.exe</Data><Data Name='Type'>Image is replaced</Data><Data Name='User'>WIN-EXAMPLE01\hxadmin</Data></EventData></Event>`
)

const (
	psExe  = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	cmdExe = `C:\Windows\System32\cmd.exe`
)

// crossMapper is the test mapper after Sysmon reported the start of the processes in the
// records: PowerShell 8692 (child of cmd.exe 6620), its child PowerShell 3956, and
// cmd.exe 6108 (child of 8692).
func crossMapper(t *testing.T) (*procMapper, map[int64]string) {
	t.Helper()
	m, _ := newTestMapper(t, map[int64]*liveProc{
		8692: {Created: ft(at(10, 30, 10, 0)), UserSID: aliceSID},
		3956: {Created: ft(at(10, 30, 16, 0)), UserSID: aliceSID},
		6108: {Created: ft(at(10, 30, 18, 300000000)), UserSID: aliceSID},
	}, nil)
	m.selfPID, m.selfExe = 1, `C:\Program Files\HomeXDR\homexdr-agent.exe`
	starts := []struct {
		pid, ppid, guid, pguid, image, utc string
	}{
		{"8692", "6620", "{504dde96-3c95-6afd-470c-000000000500}", "", psExe, "2026-11-07 10:30:10.000"},
		{"3956", "8692", "{504dde96-3c98-6afd-4b0c-000000000500}", "{504dde96-3c95-6afd-470c-000000000500}", psExe, "2026-11-07 10:30:16.000"},
		{"6108", "8692", "{504dde96-3c9a-6afd-4d0c-000000000500}", "{504dde96-3c95-6afd-470c-000000000500}", cmdExe, "2026-11-07 10:30:18.300"},
	}
	ids := map[int64]string{}
	for i, s := range starts {
		ev := m.handle(mustParse(t, sysmonXML(1, 100+i, strings.Replace(s.utc, " ", "T", 1)+"Z", [][2]string{
			{"UtcTime", s.utc}, {"ProcessGuid", s.guid}, {"ProcessId", s.pid}, {"Image", s.image},
			{"CommandLine", s.image}, {"User", `WIN-EXAMPLE01\hxadmin`},
			{"ParentProcessGuid", s.pguid}, {"ParentProcessId", s.ppid},
		})))
		if ev == nil || ev.Process.EntityID == "" {
			t.Fatalf("start %s: %+v", s.pid, ev)
		}
		ids[ev.Process.PID] = ev.Process.EntityID
	}
	return m, ids
}

func TestSysmonProcessAccess(t *testing.T) {
	m, ids := crossMapper(t)
	ev := m.handle(mustParse(t, sysmonAccessXML))
	checkMeta(t, ev, event.TypeAccess, event.ActionProcessAccess, "Microsoft-Windows-Sysmon", "10")
	if !ev.Timestamp.Equal(at(10, 30, 18, 401727400)) {
		t.Errorf("@timestamp = %v", ev.Timestamp)
	}
	p := ev.Process
	if p.PID != 8692 || p.EntityID != ids[8692] || p.Name != "powershell.exe" || p.Executable != `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Errorf("source = %+v", p)
	}
	if p.Parent == nil || p.Parent.PID != 6620 || p.Parent.EntityID == "" {
		t.Errorf("source parent = %+v", p.Parent)
	}
	checkUser(t, "source user", p.User, aliceSID, "hxadmin", "WIN-EXAMPLE01")
	tg := ev.Target
	if tg == nil || tg.Process == nil {
		t.Fatalf("target = %+v", tg)
	}
	if tg.Process.PID != 3956 || tg.Process.EntityID != ids[3956] || tg.Process.Name != "powershell.exe" {
		t.Errorf("target process = %+v", tg.Process)
	}
	if tg.Process.Parent == nil || tg.Process.Parent.EntityID != ids[8692] {
		t.Errorf("target parent = %+v", tg.Process.Parent)
	}
	checkUser(t, "target user", tg.Process.User, aliceSID, "hxadmin", "WIN-EXAMPLE01")
	if tg.GrantedAccess != "0x1f3fff" || !strings.HasPrefix(tg.CallTrace, `C:\WINDOWS\SYSTEM32\ntdll.dll+161f54|`) || tg.StartAddress != "" || tg.Tampering != "" {
		t.Errorf("target details = %+v", tg)
	}
	if ev.Message != "process accessed: powershell.exe -> powershell.exe (0x1f3fff)" {
		t.Errorf("message = %q", ev.Message)
	}
	if ev.Data["winlog.record_id"] != uint64(26237) || ev.Data["winlog.channel"] != sysmonChannel {
		t.Errorf("data = %v", ev.Data)
	}
}

func TestSysmonRemoteThread(t *testing.T) {
	m, ids := crossMapper(t)
	ev := m.handle(mustParse(t, sysmonThreadXML))
	checkMeta(t, ev, event.TypeChange, event.ActionRemoteThread, "Microsoft-Windows-Sysmon", "8")
	if ev.Process.EntityID != ids[8692] || ev.Target == nil || ev.Target.Process == nil || ev.Target.Process.EntityID != ids[3956] {
		t.Fatalf("source %+v target %+v", ev.Process, ev.Target)
	}
	tg := ev.Target
	if tg.StartAddress != "0x00007FFC6D42C4D0" || tg.StartModule != `C:\WINDOWS\SYSTEM32\ntdll.dll` || tg.StartFunction != "RtlExitUserThread" || tg.GrantedAccess != "" {
		t.Errorf("thread details = %+v", tg)
	}
	if ev.Message != "remote thread created: powershell.exe -> powershell.exe" {
		t.Errorf("message = %q", ev.Message)
	}
}

func TestSysmonTampering(t *testing.T) {
	m, ids := crossMapper(t)
	ev := m.handle(mustParse(t, sysmonTamperXML))
	checkMeta(t, ev, event.TypeChange, event.ActionProcessTampering, "Microsoft-Windows-Sysmon", "25")
	p := ev.Process
	if p.PID != 6108 || p.EntityID != ids[6108] || p.Executable != cmdExe || p.Name != "cmd.exe" {
		t.Errorf("process = %+v", p)
	}
	if p.Parent == nil || p.Parent.EntityID != ids[8692] {
		t.Errorf("parent = %+v", p.Parent)
	}
	if ev.Target == nil || ev.Target.Process != nil || ev.Target.Tampering != "Image is replaced" {
		t.Errorf("target = %+v", ev.Target)
	}
	if ev.Message != "process tampering: cmd.exe: Image is replaced" {
		t.Errorf("message = %q", ev.Message)
	}
}

// The agent opens every process to read its details; those accesses are not reported.
func TestSysmonCrossFromAgentDropped(t *testing.T) {
	m, _ := crossMapper(t)
	m.selfPID = 8692
	if ev := m.handle(mustParse(t, sysmonAccessXML)); ev != nil {
		t.Errorf("event from the agent's PID: %+v", ev)
	}
	m.selfPID, m.selfExe = 1, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	if ev := m.handle(mustParse(t, sysmonThreadXML)); ev != nil {
		t.Errorf("event from the agent's executable: %+v", ev)
	}
}

// A target the agent cannot place (gone, never seen) keeps its PID and image without an
// entity ID.
func TestSysmonCrossUnknownTarget(t *testing.T) {
	m, ids := crossMapper(t)
	x := strings.NewReplacer("<Data Name='TargetProcessId'>3956<", "<Data Name='TargetProcessId'>7777<",
		"{504dde96-3c98-6afd-4b0c-000000000500}", "{504dde96-0000-6afd-ffff-000000000500}").Replace(sysmonAccessXML)
	ev := m.handle(mustParse(t, x))
	if ev == nil || ev.Process.EntityID != ids[8692] {
		t.Fatalf("event = %+v", ev)
	}
	if tp := ev.Target.Process; tp.PID != 7777 || tp.EntityID != "" || tp.Name != "powershell.exe" {
		t.Errorf("target = %+v", tp)
	}
}

func TestSysmonQueryHasCrossEvents(t *testing.T) {
	for _, id := range []string{"EventID=1 ", "EventID=5 ", "EventID=8 ", "EventID=10 ", "EventID=25)"} {
		if !strings.Contains(sysmonQuery, id) {
			t.Errorf("sysmonQuery %q lacks %s", sysmonQuery, id)
		}
	}
}
