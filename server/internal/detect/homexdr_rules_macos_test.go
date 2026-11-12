package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// The macOS rules against events shaped like the agent's eslogger mapping.
func TestShippedRulesMacOS(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	e := NewEngine()
	e.SetRules(rules)
	titles := map[string]string{}
	for _, r := range rules {
		titles[r.ID] = r.Title
	}
	mac := &event.OS{Platform: event.PlatformDarwin}
	es := func(cat, typ, action string, data map[string]any) *event.Event {
		return &event.Event{
			Host:  event.Host{OS: mac},
			Event: event.Meta{Kind: event.KindEvent, Category: []string{cat}, Type: []string{typ}, Action: action, Module: event.ModuleESLogger},
			Data:  data,
		}
	}
	proc := func(cmd string) *event.Event {
		ev := es(event.CategoryProcess, event.TypeStart, "exec", nil)
		ev.Process = &event.Process{Executable: "/bin/launchctl", CommandLine: cmd}
		return ev
	}
	onLinux := proc("launchctl bootout system/com.homexdr.agent")
	onLinux.Host.OS = &event.OS{Platform: event.PlatformLinux}

	cases := []struct {
		name string
		ev   *event.Event
		want string
	}{
		{"xprotect", es(event.CategoryMalware, event.TypeInfo, "malware_detected", map[string]any{"malware_identifier": "OSX.Adload"}), "XProtect Detected Malware On macOS"},
		{"xprotect remediated", es(event.CategoryMalware, event.TypeInfo, "malware_remediated", nil), ""},
		{"launch daemon", es(event.CategoryConfiguration, event.TypeCreation, "launch_item_added", map[string]any{"item_type": "daemon", "managed": false}), "Launch Daemon Or Agent Added On macOS"},
		{"managed launch daemon", es(event.CategoryConfiguration, event.TypeCreation, "launch_item_added", map[string]any{"item_type": "daemon", "managed": true}), ""},
		{"login item", es(event.CategoryConfiguration, event.TypeCreation, "launch_item_added", map[string]any{"item_type": "login_item", "managed": false}), ""},
		{"full disk access", es(event.CategoryConfiguration, event.TypeChange, "tcc_modified", map[string]any{"service": "SystemPolicyAllFiles", "identity": "com.x", "right": "allowed"}), "Sensitive Privacy Permission Granted On macOS"},
		{"full disk access denied", es(event.CategoryConfiguration, event.TypeChange, "tcc_modified", map[string]any{"service": "SystemPolicyAllFiles", "right": "denied"}), ""},
		{"camera", es(event.CategoryConfiguration, event.TypeChange, "tcc_modified", map[string]any{"service": "Camera", "right": "allowed"}), ""},
		{"gatekeeper", es(event.CategoryConfiguration, event.TypeChange, "gatekeeper_override", nil), "Gatekeeper Overridden On macOS"},
		{"admin group", es(event.CategoryIAM, event.TypeChange, "group_member_added", map[string]any{"group": "admin"}), "User Added To The Admin Group On macOS"},
		{"staff group", es(event.CategoryIAM, event.TypeChange, "group_member_added", map[string]any{"group": "staff"}), ""},
		{"bootout agent", proc("launchctl bootout system/com.homexdr.agent"), "HomeXDR Agent Stopped Or Removed On macOS"},
		{"uninstall agent", proc("/usr/local/bin/homexdr-agent uninstall"), "HomeXDR Agent Stopped Or Removed On macOS"},
		{"kickstart agent", proc("launchctl kickstart -k system/com.homexdr.agent"), ""},
		{"agent status", proc("/usr/local/bin/homexdr-agent status"), ""},
		{"linux host", onLinux, ""},
	}
	for _, c := range cases {
		var got []string
		for _, r := range e.Evaluate(c.ev) {
			if t, ok := titles[r.ID]; ok {
				got = append(got, t)
			}
		}
		switch {
		case c.want == "" && len(got) > 0:
			t.Errorf("%s: unexpected hits %v", c.name, got)
		case c.want != "" && (len(got) != 1 || got[0] != c.want):
			t.Errorf("%s: hits %v, want %q", c.name, got, c.want)
		}
	}
}
