package detect

import (
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// sysmonCross is a cross-process event as the Windows agent maps Sysmon 8, 10 and 25:
// Process is the source, Target the process acted on, no raw EventData.
func sysmonCross(code, action, srcImage, dstImage string) *event.Event {
	base := func(p string) string {
		for i := len(p) - 1; i >= 0; i-- {
			if p[i] == '\\' {
				return p[i+1:]
			}
		}
		return p
	}
	e := &event.Event{
		ID:   event.NewID(),
		Host: event.Host{ID: "h", Name: "desk", OS: &event.OS{Platform: event.PlatformWindows}},
		Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeAccess},
			Action: action, Code: code, Provider: "Microsoft-Windows-Sysmon", Module: event.ModuleEventLog},
		Process: &event.Process{EntityID: "e-src", PID: 4242, Name: base(srcImage), Executable: srcImage,
			User: &event.User{Domain: "DESK", Name: "alice"}},
	}
	if dstImage != "" {
		e.Target = &event.Target{Process: &event.Process{EntityID: "e-dst", PID: 700, Name: base(dstImage), Executable: dstImage,
			User: &event.User{Domain: "NT AUTHORITY", Name: "SYSTEM"}}}
	}
	return e
}

func TestCrossProcessSigmaRules(t *testing.T) {
	// Adapted from SigmaHQ proc_access_win_lsass_susp_access_flag.yml (filters trimmed).
	lsassFlags := mustRule(t, `
title: Suspicious GrantedAccess Flags on LSASS
id: a18dd26b-6450-46de-8c91-9659150cf088
status: test
level: medium
tags: [attack.credential-access, attack.t1003.001]
logsource:
  category: process_access
  product: windows
detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'
  selection_access:
    - GrantedAccess:
        - '0x1FFFFF'
        - '0x1010'
        - '0x1038'
        - '0x40'
        - '0x1400'
        - '0x1410'
        - '0x143a'
        - '0x1438'
        - '0x1000'
    - GrantedAccess|endswith:
        - '30'
        - '50'
        - '70'
        - '90'
        - 'B0'
        - 'D0'
        - 'F0'
        - '18'
        - '38'
        - '58'
        - '78'
        - '98'
        - 'B8'
        - 'D8'
        - 'F8'
        - '1A'
        - '3A'
        - '5A'
        - '7A'
        - '9A'
        - 'BA'
        - 'DA'
        - 'FA'
        - '0x14C2'
        - 'FF'
  filter_main_generic:
    SourceImage|contains:
      - ':\Program Files\'
      - ':\Program Files (x86)\'
      - ':\Windows\System32\'
      - ':\Windows\SysWOW64\'
  condition: all of selection_* and not 1 of filter_main_*
`)
	// SigmaHQ proc_access_win_lsass_dump_comsvcs_dll.yml.
	comsvcs := mustRule(t, `
title: Lsass Memory Dump via Comsvcs DLL
id: a49fa4d5-11db-418c-8473-1e014a8dd462
status: test
level: high
tags: [attack.credential-access, attack.t1003.001]
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    SourceImage|endswith: '\rundll32.exe'
    CallTrace|contains: 'comsvcs.dll'
  condition: selection
`)
	// SigmaHQ create_remote_thread_win_powershell_lsass.yml: a remote thread into a system
	// process from PowerShell.
	psRemote := mustRule(t, `
title: Potential Credential Dumping Attempt Via PowerShell Remote Thread
id: fb656378-f909-47c1-8747-278bf09f4f4f
status: test
level: high
tags: [attack.credential-access, attack.t1003.001]
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    SourceImage|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    TargetImage|endswith: '\lsass.exe'
  condition: selection
`)
	// SigmaHQ create_remote_thread_win_loadlibrary.yml.
	loadLib := mustRule(t, `
title: CreateRemoteThread API and LoadLibrary
id: 052ec6f6-1adc-41e6-907a-f1c813478bee
status: test
level: high
tags: [attack.defense-evasion, attack.t1055.001]
logsource:
  product: windows
  category: create_remote_thread
detection:
  selection:
    StartModule|endswith: '\kernel32.dll'
    StartFunction: 'LoadLibraryA'
  condition: selection
`)
	// SigmaHQ proc_tamper_win_susp_process_hollowing.yml (filters trimmed).
	hollow := mustRule(t, `
title: Potential Process Hollowing Activity
id: c4b890e5-8d8c-4496-8c66-c805753817cd
status: test
level: medium
tags: [attack.defense-evasion, attack.privilege-escalation, attack.t1055.012]
logsource:
  product: windows
  category: process_tampering
detection:
  selection:
    Type: 'Image is replaced'
  filter_main_generic:
    Image|contains:
      - ':\Program Files (x86)'
      - ':\Program Files\'
      - ':\Windows\System32\wbem\WMIADAP.exe'
      - ':\Windows\SysWOW64\wbem\WMIADAP.exe'
  condition: selection and not 1 of filter_main_*
`)
	// Field mapping beyond images: GUIDs, PIDs and users on both sides.
	ids := mustRule(t, `
title: Cross-process identity fields
id: 3d0f0f0e-0000-4000-8000-00000000c0de
level: low
logsource: {product: windows, category: process_access}
detection:
  selection:
    SourceProcessGUID: e-src
    SourceProcessGuid: e-src
    TargetProcessGUID: e-dst
    SourceProcessId: 4242
    TargetProcessId: 700
    SourceUser|endswith: '\alice'
    TargetUser|contains: 'AUTHORI'
  condition: selection
`)

	access := func(src, granted, trace string) *event.Event {
		e := sysmonCross("10", event.ActionProcessAccess, src, `C:\Windows\System32\lsass.exe`)
		e.Target.GrantedAccess = granted
		e.Target.CallTrace = trace
		return e
	}
	thread := func(src, dst, module, fn string) *event.Event {
		e := sysmonCross("8", event.ActionRemoteThread, src, dst)
		e.Event.Type = []string{event.TypeChange}
		e.Target.StartModule, e.Target.StartFunction, e.Target.StartAddress = module, fn, "0x7FFB12340000"
		return e
	}
	tamper := func(img, typ string) *event.Event {
		e := sysmonCross("25", event.ActionProcessTampering, img, "")
		e.Event.Type = []string{event.TypeChange}
		e.Target = &event.Target{Tampering: typ}
		return e
	}
	trace := `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|C:\Windows\System32\comsvcs.dll+1aaa`
	cases := []struct {
		name string
		rule *Rule
		ev   *event.Event
		want bool
	}{
		{"lsass flags", lsassFlags, access(`C:\Users\alice\mimikatz.exe`, "0x1010", ""), true},
		{"lsass flags lowercase mask", lsassFlags, access(`C:\Users\alice\mimikatz.exe`, "0x1fffff", ""), true},
		{"lsass flags suffix", lsassFlags, access(`C:\Users\alice\dump.exe`, "0x1438", ""), true},
		{"lsass flags system source filtered", lsassFlags, access(`C:\Windows\System32\taskmgr.exe`, "0x1010", ""), false},
		{"lsass flags benign mask", lsassFlags, access(`C:\Users\alice\tool.exe`, "0x1001", ""), false},
		{"comsvcs", comsvcs, access(`C:\Windows\System32\rundll32.exe`, "0x1fffff", trace), true},
		{"comsvcs other trace", comsvcs, access(`C:\Windows\System32\rundll32.exe`, "0x1fffff", `C:\Windows\SYSTEM32\ntdll.dll+9d4c4`), false},
		{"powershell thread into lsass", psRemote, thread(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\lsass.exe`, "", ""), true},
		{"powershell thread into notepad", psRemote, thread(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\notepad.exe`, "", ""), false},
		{"loadlibrary", loadLib, thread(`C:\Users\alice\inject.exe`, `C:\Windows\System32\notepad.exe`, `C:\Windows\System32\KERNEL32.DLL`, "LoadLibraryA"), true},
		{"loadlibrary other function", loadLib, thread(`C:\Users\alice\inject.exe`, `C:\Windows\System32\notepad.exe`, `C:\Windows\System32\kernel32.dll`, "CreateFileW"), false},
		{"hollowing", hollow, tamper(`C:\Users\alice\AppData\Local\Temp\svchost.exe`, "Image is replaced"), true},
		{"hollowing program files", hollow, tamper(`C:\Program Files\App\app.exe`, "Image is replaced"), false},
		{"hollowing other type", hollow, tamper(`C:\Users\alice\x.exe`, "Image is locked for access"), false},
		{"identity fields", ids, access(`C:\Users\alice\x.exe`, "0x1000", ""), true},
		// Logsource: the categories only take their own kind of event.
		{"access rule on a thread", lsassFlags, func() *event.Event {
			e := thread(`C:\Users\alice\mimikatz.exe`, `C:\Windows\System32\lsass.exe`, "", "")
			e.Target.GrantedAccess = "0x1010"
			return e
		}(), false},
	}
	for _, c := range cases {
		if got := c.rule.Match(NewDoc(c.ev)); got != c.want {
			t.Errorf("%s: match = %v, want %v", c.name, got, c.want)
		}
	}

	// Without event.action, the Sysmon code decides; without either it is not
	// cross-process at all.
	ev := access(`C:\Users\alice\mimikatz.exe`, "0x1010", "")
	ev.Event.Action = ""
	if !lsassFlags.Match(NewDoc(ev)) {
		t.Error("Sysmon event 10 without an action did not match process_access")
	}
	ev.Event.Provider = "Some-Other-Provider"
	if lsassFlags.Match(NewDoc(ev)) {
		t.Error("code 10 from another provider matched process_access")
	}

	// Raw EventData from the event log is used when it is there.
	raw := access(`C:\Users\alice\mimikatz.exe`, "", "")
	raw.Target = nil
	raw.Data = map[string]any{"TargetImage": `C:\Windows\system32\lsass.exe`, "GrantedAccess": "0x1410",
		"SourceImage": `C:\Users\alice\mimikatz.exe`}
	if !lsassFlags.Match(NewDoc(raw)) {
		t.Error("raw EventData did not match")
	}
}

func TestCrossProcessNotProcessCreation(t *testing.T) {
	r := mustRule(t, `
title: Any process start
id: 3d0f0f0e-0000-4000-8000-00000000c0df
level: low
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
`)
	ev := sysmonCross("8", event.ActionRemoteThread, `C:\x\inject.exe`, `C:\Windows\System32\notepad.exe`)
	ev.Event.Type = []string{event.TypeStart} // even if a producer calls the thread a start
	if r.Match(NewDoc(ev)) {
		t.Error("a remote thread event matched process_creation")
	}
	ev.Event.Action, ev.Event.Provider = "", ""
	if !r.Match(NewDoc(ev)) {
		t.Error("a plain process start no longer matches process_creation")
	}
}

func TestCrossProcessCoverage(t *testing.T) {
	r := mustRule(t, `
title: LSASS access
id: 3d0f0f0e-0000-4000-8000-00000000c0e0
level: high
logsource: {product: windows, category: process_access}
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1010'
  condition: selection
`)
	cov := NewCoverage()
	cov.Add(winProc(`C:\Windows\System32\cmd.exe`, "cmd", `C:\Windows\explorer.exe`))
	if got := cov.Check(r); got.SourceSeen {
		t.Fatalf("process starts alone should not cover process_access: %+v", got)
	}
	ev := sysmonCross("10", event.ActionProcessAccess, `C:\x\a.exe`, `C:\Windows\System32\lsass.exe`)
	ev.Target.GrantedAccess = "0x1fffff"
	cov.Add(ev)
	if got := cov.Check(r); !got.CanFire {
		t.Fatalf("mapped Sysmon 10 events should let the rule fire: %+v", got)
	}
	if _, err := Synthesize(r); err != nil {
		t.Fatal(err)
	}
}
