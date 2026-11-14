package detect

import (
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// The third set of shipped rules: firewall logs, SSH user guessing from inside, and
// two more DNS categories. Matched by title.
func TestShippedRulesNetwork(t *testing.T) {
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

	// An OPNsense filterlog record as syslog.decodeFilterlog builds it.
	fw := func(action, proto, src, dst string, dport int) *event.Event {
		types := []string{event.TypeConnection, event.TypeAllowed}
		if action != "pass" {
			types = []string{event.TypeConnection, event.TypeDenied}
		}
		return &event.Event{
			Event:       event.Meta{Module: event.ModuleOPNsense, Dataset: "opnsense.filterlog", Category: []string{event.CategoryNetwork}, Type: types, Action: action},
			Observer:    &event.Observer{Type: "firewall", Vendor: "OPNsense", Product: "OPNsense"},
			Network:     &event.Network{Transport: proto, Direction: event.DirectionInbound},
			Source:      &event.Endpoint{IP: src, Port: 51515},
			Destination: &event.Endpoint{IP: dst, Port: dport},
		}
	}
	dns := func(name string) *event.Event {
		return &event.Event{
			Host:  event.Host{OS: &event.OS{Platform: "linux"}},
			Event: event.Meta{Category: []string{event.CategoryNetwork}, Module: event.ModuleDNS, Dataset: "dns.adguard"},
			DNS:   &event.DNS{Question: event.DNSQuestion{Name: name, Type: "A"}},
		}
	}
	// sshd failures as the syslog decoder and the agent's log parser report them.
	sshFail := func(action, msg, ip string) *event.Event {
		return &event.Event{
			Event:   event.Meta{Module: event.ModuleSyslog, Dataset: "syslog.sshd", Category: []string{event.CategoryAuthentication}, Action: action, Outcome: event.OutcomeFailure},
			User:    &event.User{Name: "admin"},
			Source:  &event.Endpoint{IP: ip},
			Message: msg,
		}
	}

	const (
		inbound = "Remote Admin Or Database Port Allowed In From The Internet"
		smb     = "Windows File Sharing Connection To The Internet"
		telnet  = "Telnet Connection To The Internet"
		guess   = "SSH Login Tried For A User That Does Not Exist From Inside The Network"
		mining  = "DNS Lookup Of A Cryptocurrency Mining Pool"
		remote  = "DNS Lookup Of A Remote Desktop Service"
	)
	cases := []struct {
		name string
		ev   *event.Event
		want string
	}{
		{"rdp from the internet", fw("pass", "tcp", "203.0.113.50", "192.168.20.15", 3389), inbound},
		{"ssh from the internet", fw("pass", "tcp", "2001:db8::7", "192.168.20.10", 22), inbound},
		{"rdp blocked", fw("block", "tcp", "203.0.113.50", "192.168.20.15", 3389), ""},
		{"https from the internet", fw("pass", "tcp", "203.0.113.50", "192.168.20.10", 443), ""},
		{"rdp inside", fw("pass", "tcp", "192.168.10.52", "192.168.20.15", 3389), ""},
		{"rdp over tailscale", fw("pass", "tcp", "100.101.102.103", "192.168.20.15", 3389), ""},
		{"udp 3389", fw("pass", "udp", "203.0.113.50", "192.168.20.15", 3389), ""},
		{"smb out", fw("pass", "tcp", "192.168.10.52", "198.51.100.9", 445), smb},
		{"smb out blocked", fw("block", "tcp", "192.168.10.52", "198.51.100.9", 445), ""},
		{"smb to the nas", fw("pass", "tcp", "192.168.10.52", "192.168.20.10", 445), ""},
		{"telnet out", fw("pass", "tcp", "192.168.30.77", "198.51.100.9", 23), telnet},
		{"telnet out alt port", fw("pass", "tcp", "192.168.30.77", "198.51.100.9", 2323), telnet},
		{"telnet inside", fw("pass", "tcp", "192.168.10.52", "192.168.1.1", 23), ""},
		{"https out", fw("pass", "tcp", "192.168.10.52", "198.51.100.9", 443), ""},

		{"invalid user inside, syslog", sshFail("ssh-login-failed", "Invalid user admin from 192.168.30.77 port 40022", "192.168.30.77"), guess},
		{"invalid user inside, agent", sshFail("ssh_login", "Failed password for invalid user admin from 192.168.30.77 port 40022 ssh2", "192.168.30.77"), guess},
		{"invalid user inside, agent preauth", sshFail("ssh_invalid_user", "Invalid user oracle from 10.0.0.9 port 5555", "10.0.0.9"), guess},
		{"invalid user from the internet", sshFail("ssh-login-failed", "Invalid user admin from 203.0.113.50 port 40022", "203.0.113.50"), ""},
		{"wrong password inside", sshFail("ssh-login-failed", "Failed password for root from 192.168.30.77 port 40022 ssh2", "192.168.30.77"), ""},

		{"nanopool", dns("xmr-eu1.nanopool.org"), mining},
		{"moneroocean", dns("gulf.moneroocean.stream"), mining},
		{"xmrig donate", dns("donate.v2.xmrig.com"), mining},
		{"not a pool", dns("plantpool.com"), ""},
		{"anydesk", dns("relay-1a2b3c.net.anydesk.com"), remote},
		{"teamviewer", dns("router4.teamviewer.com"), remote},
		{"zoho assist", dns("assist.zoho.com"), remote},
		{"zoho mail", dns("mail.zoho.com"), ""},
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
