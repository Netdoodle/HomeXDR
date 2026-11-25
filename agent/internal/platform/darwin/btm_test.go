package darwin

import (
	"strconv"
	"testing"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// Abridged `sfltool dumpbtm` output (macOS 15+ layout), with made-up apps.
const btmSample = `========================
 Records for UID -2 : FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE
========================

 ServiceManagement migrated: true
 LaunchServices registered: false

 Items:

 #1:
                 UUID: 476B7540-D3EA-4689-92D1-F818D6DECC10
                 Name: (null)
       Developer Name: (null)
                 Type: developer (0x20)
                Flags: [  ] (0)
          Disposition: [disabled, allowed, not notified] (0x2)
           Identifier: Unknown Developer
                  URL: (null)
           Generation: 0
  Embedded Item Identifiers:
    #1: 16.com.example.daemon

 #2:
                 UUID: 57B93C7C-BB94-408A-A2AD-01FC5702B0F5
                 Name: exampled
       Developer Name: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.com.example.daemon
                  URL: /Library/LaunchDaemons/com.example.daemon.plist
      Executable Path: /usr/local/bin/exampled
           Generation: 6
             Last Use: 2026-11-24 21:11:27-06:00
    Parent Identifier: Unknown Developer

========================
 Records for UID 501 : 3D0E8083-66DC-4701-8A0D-C34B509C685E
========================

 Items:

 #1:
                 UUID: FFDD39B5-7F7D-42CF-BF01-49381493E189
                 Name: Example
       Developer Name: Example Inc
      Team Identifier: ABCDE12345
                 Type: app (0x2)
                Flags: [  ] (0)
          Disposition: [disabled, allowed, not notified] (0x2)
           Identifier: 2.com.example.app
                  URL: /Applications/Example.app
           Generation: 0
    Bundle Identifier: com.example.app

 #2:
                 UUID: 5E2F7868-7DFF-4AE1-970D-CB00B9A470B7
                 Name: ExampleHelper
       Developer Name: Example Inc
      Team Identifier: ABCDE12345
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 4.com.example.helper
                  URL: Contents/Library/LoginItems/ExampleHelper.app
           Generation: 1
    Bundle Identifier: com.example.helper
    Parent Identifier: 2.com.example.app

 #3:
                 UUID: DCCF647A-C087-45E0-9457-ACDBBB43B48D
                 Name: Example - background tasks
       Developer Name: Example Inc
                 Type: background tasks (0x2000)
                Flags: [  ] (0)
          Disposition: [disabled, allowed, notified] (0xa)
           Identifier: 8192.com.example.app
                  URL: (null)
           Generation: 2
             Last Use: 2026-11-24 16:51:30-06:00
    Parent Identifier: 2.com.example.app

 #4:
                 UUID: 1A2B3C4D-0000-0000-0000-000000000004
                 Name: Updater
       Developer Name: Example Inc
      Team Identifier: ABCDE12345
                 Type: agent (0x8)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 8.com.example.updater
                  URL: Contents/Library/LaunchAgents/com.example.updater.plist
      Executable Path: /Applications/Example.app/Contents/MacOS/Updater
           Generation: 1
    Parent Identifier: 2.com.example.app

 #5:
                 UUID: 1A2B3C4D-0000-0000-0000-000000000005
                 Name: Other
       Developer Name: Other Ltd
                 Type: legacy agent (0x10008)
                Flags: [ legacy ] (0x1)
          Disposition: [disabled, allowed, notified] (0xa)
           Identifier: 8.com.other.agent
                  URL: /Users/501/Library/LaunchAgents/com.other.agent.plist
      Executable Path: /Applications/Other.app/Contents/MacOS/Other
           Generation: 2
             Last Use: 2026-11-24 20:07:19-06:00
`

func TestParseBTM(t *testing.T) {
	items := parseBTM([]byte(btmSample))
	if len(items) != 7 {
		t.Fatalf("got %d items, want 7: %+v", len(items), items)
	}
	d := items[1]
	if d.UID != -2 || d.Type != btmDaemon|btmLegacy || d.Disposition != 0xb || d.label() != "com.example.daemon" ||
		d.ExecPath != "/usr/local/bin/exampled" || d.Used != "2026-11-24 21:11:27-06:00" || d.Name != "exampled" {
		t.Errorf("legacy daemon: %+v", d)
	}
	if items[0].Identifier != "Unknown Developer" || items[0].Name != "" {
		t.Errorf("developer record: %+v", items[0])
	}
	if items[3].UID != 501 || items[3].Type != btmLoginItem || !items[3].enabled() || items[3].TeamID != "ABCDE12345" {
		t.Errorf("login item: %+v", items[3])
	}
	if items[4].enabled() {
		t.Errorf("background task with disposition 0xa should be disabled")
	}
}

func TestBTMAutoruns(t *testing.T) {
	launchd := []platform.Row{
		autorunRow("launch_daemon", "/Library/LaunchDaemons/com.example.daemon.plist", "com.example.daemon", "/usr/local/bin/exampled", "root", true),
		autorunRow("launch_agent", "/Users/alex/Library/LaunchAgents/com.other.agent.plist", "com.other.agent", "/Applications/Other.app/Contents/MacOS/Other", "alex", true),
	}
	names := map[int]string{0: "root", 501: "alex"}
	rows := btmAutoruns(parseBTM([]byte(btmSample)), launchd, func(uid int) string {
		if n, ok := names[uid]; ok {
			return n
		}
		return strconv.Itoa(uid)
	})
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 (login item, background task, bundled agent): %v", len(rows), rows)
	}
	li := rows[0]
	if li["type"] != "login_item" || li["location"] != "/Applications/Example.app/Contents/Library/LoginItems/ExampleHelper.app" ||
		li["user"] != "alex" || li["enabled"] != true || li["parent"] != "com.example.app" || li["team_id"] != "ABCDE12345" ||
		li["source"] != "btm" {
		t.Errorf("login item row: %v", li)
	}
	bt := rows[1]
	if bt["type"] != "background_task" || bt["location"] != "/Applications/Example.app" || bt["enabled"] != false ||
		bt["last_used"] != "2026-11-24 16:51:30-06:00" {
		t.Errorf("background task row: %v", bt)
	}
	ag := rows[2]
	if ag["type"] != "launch_agent" || ag["command"] != "/Applications/Example.app/Contents/MacOS/Updater" ||
		ag["location"] != "/Applications/Example.app/Contents/Library/LaunchAgents/com.example.updater.plist" {
		t.Errorf("bundled agent row: %v", ag)
	}
	// Legacy jobs annotate the plist rows instead of duplicating them.
	if launchd[0]["enabled"] != true || launchd[0]["login_items_allowed"] != true {
		t.Errorf("legacy daemon row: %v", launchd[0])
	}
	if launchd[1]["enabled"] != false || launchd[1]["login_items_allowed"] != false {
		t.Errorf("legacy agent switched off in Login Items should be disabled: %v", launchd[1])
	}
}

func TestParseBTMGarbage(t *testing.T) {
	for _, in := range []string{"", "#1:\n", "Records for UID x\n#1:\nType: app\n", "Identifier: x\n"} {
		_ = parseBTM([]byte(in))
	}
	if got := parseBTM([]byte(" #1:\n Identifier: 4.a\n Type: login item (0xZZ)\n")); len(got) != 1 || got[0].Type != 0 {
		t.Errorf("bad hex: %+v", got)
	}
}
