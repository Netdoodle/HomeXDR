package syslog

import (
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

var now = time.Date(2026, 10, 19, 18, 0, 0, 0, time.UTC)

func TestParse5424(t *testing.T) {
	m, err := Parse(`<134>1 2026-10-19T12:00:00-05:00 OPNsense.localdomain filterlog 61234 - [meta sequenceId="5" x="a\]b"] 77,,,abc,igb0`, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.Facility != 16 || m.Severity != 6 || m.Hostname != "OPNsense.localdomain" || m.AppName != "filterlog" ||
		m.ProcID != "61234" || m.Msg != "77,,,abc,igb0" || !m.Timestamp.Equal(time.Date(2026, 10, 19, 17, 0, 0, 0, time.UTC)) {
		t.Fatalf("parsed %+v", m)
	}
}

func TestParse3164(t *testing.T) {
	cases := []struct {
		raw, host, app, pid, msg string
	}{
		{`<134>Oct 19 12:00:00 filterlog[61234]: 77,,,abc`, "", "filterlog", "61234", "77,,,abc"},
		{`<38>Oct  9 12:00:00 nas sshd[999]: Failed password for root`, "nas", "sshd", "999", "Failed password for root"},
		{`<13>Oct 19 12:00:00 router kernel: link up`, "router", "kernel", "", "link up"},
		{`<13>Oct 19 12:00:00 router just text`, "router", "", "", "just text"},
	}
	for _, c := range cases {
		m, err := Parse(c.raw, now)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if m.Hostname != c.host || m.AppName != c.app || m.ProcID != c.pid || m.Msg != c.msg {
			t.Errorf("%s:\n got host=%q app=%q pid=%q msg=%q", c.raw, m.Hostname, m.AppName, m.ProcID, m.Msg)
		}
	}
	if _, err := Parse("no pri here", now); err == nil {
		t.Error("expected error without PRI")
	}
}

func TestFilterlog(t *testing.T) {
	raw := `<134>1 2026-10-19T12:00:00-05:00 fw filterlog 1 - - 77,,,02f4bab0,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,203.0.113.50,192.168.1.10,51515,22,0,S,1234567,,64240,,mss`
	m, _ := Parse(raw, now)
	ev, kind := Decode(m)
	if kind != "opnsense" {
		t.Fatalf("kind = %s", kind)
	}
	if ev.Event.Action != "block" || ev.Event.Outcome != event.OutcomeFailure || ev.Network.Transport != "tcp" ||
		ev.Source.IP != "203.0.113.50" || ev.Source.Port != 51515 || ev.Destination.IP != "192.168.1.10" ||
		ev.Destination.Port != 22 || ev.Network.Direction != event.DirectionInbound || ev.Network.CommunityID == "" ||
		ev.Data["interface"] != "igb0" || ev.Data["tcp_flags"] != "S" {
		t.Fatalf("decoded %+v / %+v / %+v / %+v", ev.Event, ev.Network, ev.Source, ev.Data)
	}

	v6 := `<134>Oct 19 12:00:00 filterlog[1]: 5,,,abc,igb1,match,pass,out,6,0x00,0x00000,64,udp,17,72,2001:db8::1,2001:db8::53,5353,53,72`
	m, _ = Parse(v6, now)
	ev, _ = Decode(m)
	if ev.Network.Type != "ipv6" || ev.Network.Transport != "udp" || ev.Destination.Port != 53 || ev.Event.Outcome != event.OutcomeSuccess {
		t.Fatalf("v6 decoded %+v %+v", ev.Network, ev.Destination)
	}
}

func TestEVE(t *testing.T) {
	raw := `<14>1 2026-10-19T17:00:00Z opnsense suricata 999 - - {"timestamp":"2026-10-19T12:00:00.123456-0500","flow_id":1234,"in_iface":"igb1","event_type":"alert","src_ip":"192.168.1.10","src_port":50000,"dest_ip":"198.51.100.9","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2027865,"rev":3,"signature":"ET POLICY curl User-Agent Outbound","category":"Attempted Information Leak","severity":2,"metadata":{"mitre_technique_id":["T1105"]}}}`
	m, _ := Parse(raw, now)
	ev, kind := Decode(m)
	if kind != "suricata" || ev.Event.Kind != event.KindAlert || ev.Rule.ID != "2027865" || ev.Event.Severity != 47 ||
		ev.Network.CommunityID == "" || ev.Threat == nil || ev.Threat.Techniques[0].ID != "T1105" ||
		!ev.Timestamp.Equal(time.Date(2026, 10, 19, 17, 0, 0, 123456000, time.UTC)) {
		t.Fatalf("decoded %+v %+v %+v ts=%v", ev.Event, ev.Rule, ev.Network, ev.Timestamp)
	}

	dns := `<14>1 2026-10-19T17:00:00Z opnsense suricata 999 - - {"timestamp":"2026-10-19T12:00:00.000000-0500","event_type":"dns","src_ip":"192.168.1.10","src_port":5353,"dest_ip":"192.168.1.1","dest_port":53,"proto":"UDP","dns":{"version":3,"type":"response","queries":[{"rrname":"example.com","rrtype":"A"}],"rcode":"NOERROR","answers":[{"rrname":"example.com","rrtype":"A","ttl":60,"rdata":"93.184.215.14"}]}}`
	m, _ = Parse(dns, now)
	ev, _ = Decode(m)
	if ev.DNS == nil || ev.DNS.Question.Name != "example.com" || ev.DNS.Type != "answer" || len(ev.DNS.ResolvedIP) != 1 {
		t.Fatalf("dns decoded %+v", ev.DNS)
	}
}

func TestSSHD(t *testing.T) {
	m, _ := Parse(`<38>Oct 19 12:00:00 nas sshd[999]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2`, now)
	ev, _ := Decode(m)
	if ev.Event.Outcome != event.OutcomeFailure || ev.User.Name != "admin" || ev.Source.IP != "203.0.113.9" ||
		ev.Event.Category[0] != event.CategoryAuthentication {
		t.Fatalf("sshd decoded %+v %+v %+v", ev.Event, ev.User, ev.Source)
	}
	m, _ = Parse(`<38>Oct 19 12:00:00 nas sshd[999]: Accepted publickey for bob from 192.168.1.20 port 40000 ssh2`, now)
	ev, _ = Decode(m)
	if ev.Event.Outcome != event.OutcomeSuccess || ev.User.Name != "bob" {
		t.Fatalf("accepted decoded %+v %+v", ev.Event, ev.User)
	}
	m, _ = Parse(`<38>Oct 19 12:00:00 nas sshd[999]: Connection closed by 1.2.3.4`, now)
	ev, kind := Decode(m)
	if kind != "syslog" || ev.Event.Module != event.ModuleSyslog || ev.Message == "" {
		t.Fatalf("generic fallback %+v", ev.Event)
	}
}
