package syslog

import (
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestUnbound(t *testing.T) {
	cases := []struct {
		name, raw                           string
		ip, question, qtype, dnsType, rcode string
	}{
		{"query 3164", `<30>Nov  5 12:00:00 fw unbound[4242]: [4242:0] info: 192.168.20.5 example.com. A IN`, "192.168.20.5", "example.com", "A", "query", ""},
		{"query 5424", `<30>1 2026-11-05T12:00:00+00:00 fw.lan unbound 4242 - - [4242:0] info: 192.168.20.5 WWW.Example.COM. AAAA IN`, "192.168.20.5", "www.example.com", "AAAA", "query", ""},
		{"no brackets", `<30>Nov  5 12:00:00 fw unbound: info: 10.0.0.2 example.org. TXT IN`, "10.0.0.2", "example.org", "TXT", "query", ""},
		{"reply", `<30>1 2026-11-05T12:00:00Z fw unbound 4242 - - [4242:1] info: 192.168.20.5 example.com. A IN NOERROR 0.012500 0 86`, "192.168.20.5", "example.com", "A", "answer", "NOERROR"},
		{"reply without timing", `<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: 192.168.20.5 nope.example. A IN NXDOMAIN`, "192.168.20.5", "nope.example", "A", "answer", "NXDOMAIN"},
		{"tagged reply", `<30>Nov  5 12:00:00 fw unbound[1]: [1:0] reply: 192.168.20.5 example.com. A IN SERVFAIL 1.500000 0 40`, "192.168.20.5", "example.com", "A", "answer", "SERVFAIL"},
		{"ipv6 client", `<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: fd00::5 example.com. A IN`, "fd00::5", "example.com", "A", "query", ""},
		{"local zone", `<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: ads.example. always_nxdomain 192.168.20.5@53124 ads.example. A IN`, "192.168.20.5", "ads.example", "A", "query", ""},
		{"root", `<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: 192.168.20.5 . NS IN`, "192.168.20.5", ".", "NS", "query", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(c.raw, now)
			if err != nil {
				t.Fatal(err)
			}
			ev, kind := Decode(m)
			if kind != "unbound" {
				t.Fatalf("kind %q, event %+v", kind, ev)
			}
			if ev.Event.Module != event.ModuleDNS || ev.Source.IP != c.ip || ev.DNS.Question.Name != c.question ||
				ev.DNS.Question.Type != c.qtype || ev.DNS.Type != c.dnsType || ev.DNS.ResponseCode != c.rcode {
				t.Fatalf("decoded %+v dns %+v source %+v", ev.Event, ev.DNS, ev.Source)
			}
		})
	}
	m, _ := Parse(`<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: 192.168.20.5 example.com. A IN NOERROR 0.012500 1 86`, now)
	ev, _ := Decode(m)
	if ev.Data["cached"] != true || ev.Data["response_bytes"] != 86 || ev.Data["response_time_ms"].(float64) != 12.5 {
		t.Fatalf("reply data %+v", ev.Data)
	}
	m, _ = Parse(`<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: ads.example. always_nxdomain 192.168.20.5@53124 ads.example. A IN`, now)
	ev, _ = Decode(m)
	if ev.Event.Action != "dns-local-zone" || ev.Data["local_action"] != "always_nxdomain" {
		t.Fatalf("local zone %+v %+v", ev.Event, ev.Data)
	}
	// Other Unbound lines stay generic.
	for _, raw := range []string{
		`<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: start of service (unbound 1.22.0).`,
		`<30>Nov  5 12:00:00 fw unbound[1]: [1:0] info: generate keytag query _ta-4f66. NULL IN`,
		`<27>Nov  5 12:00:00 fw unbound[1]: [1:0] error: SERVFAIL <example.com. A IN>: all the configured stub servers failed`,
		`<30>Nov  5 12:00:00 fw unbound[1]: [1:0] notice: init module 0: validator`,
		`<30>Nov  5 12:00:00 fw unbound[1]: `,
	} {
		m, err := Parse(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		if ev, kind := Decode(m); kind != "syslog" || ev.DNS != nil {
			t.Errorf("%s: kind %q", raw, kind)
		}
	}
}

func TestDHCP(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	cases := []struct {
		name, raw                              string
		backend, msg, ip, wantMAC, host, iface string
	}{
		{"isc ack", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPACK on 192.168.20.50 to aa:bb:cc:dd:ee:ff (phone) via vlan0.20`, "isc", "ACK", "192.168.20.50", mac, "phone", "vlan0.20"},
		{"isc ack 5424", `<30>1 2026-11-05T12:00:00Z fw dhcpd 99 - - DHCPACK on 192.168.20.50 to AA:BB:CC:DD:EE:FF via igb1`, "isc", "ACK", "192.168.20.50", mac, "", "igb1"},
		{"isc ack relay", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPACK on 192.168.20.50 to aa:bb:cc:dd:ee:ff (my phone) via 192.168.20.2 relay 192.168.20.2 lease-duration 7200`, "isc", "ACK", "192.168.20.50", mac, "my phone", "192.168.20.2"},
		{"isc inform ack", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPACK to 192.168.20.50 (aa:bb:cc:dd:ee:ff) via igb1`, "isc", "ACK", "192.168.20.50", mac, "", "igb1"},
		{"isc offer", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPOFFER on 192.168.20.50 to aa:bb:cc:dd:ee:ff (phone) via igb1`, "isc", "OFFER", "192.168.20.50", mac, "phone", "igb1"},
		{"isc request", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPREQUEST for 192.168.20.50 (192.168.20.1) from aa:bb:cc:dd:ee:ff (phone) via igb1`, "isc", "REQUEST", "192.168.20.50", mac, "phone", "igb1"},
		{"isc release", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPRELEASE of 192.168.20.50 from aa:bb:cc:dd:ee:ff (phone) via igb1 (found)`, "isc", "RELEASE", "192.168.20.50", mac, "phone", "igb1"},
		{"isc expire", `<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPEXPIRE on 192.168.20.50 to aa:bb:cc:dd:ee:ff`, "isc", "EXPIRE", "192.168.20.50", mac, "", ""},
		{"kea alloc", `<30>Nov  5 12:00:00 fw kea-dhcp4[12]: INFO  [kea-dhcp4.leases/12.1405] DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[01:aa:bb:cc:dd:ee:ff], tid=0x1a2b3c4d: lease 192.168.20.50 has been allocated for 3600 seconds`, "kea", "ACK", "192.168.20.50", mac, "", ""},
		{"kea no severity", `<30>1 2026-11-05T12:00:00Z fw kea-dhcp4 12 - - DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: lease 192.168.20.50 has been allocated for 3600 seconds`, "kea", "ACK", "192.168.20.50", mac, "", ""},
		{"kea advert", `<30>Nov  5 12:00:00 fw kea-dhcp4[12]: INFO  [kea-dhcp4.leases/12.1] DHCP4_LEASE_ADVERT [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: lease 192.168.20.50 will be advertised`, "kea", "OFFER", "192.168.20.50", mac, "", ""},
		{"kea release", `<30>Nov  5 12:00:00 fw kea-dhcp4[12]: INFO  [kea-dhcp4.release/12.1] DHCP4_RELEASE [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: address 192.168.20.50 was released properly.`, "kea", "RELEASE", "192.168.20.50", mac, "", ""},
		{"kea hostname", `<31>Nov  5 12:00:00 fw kea-dhcp4[12]: DEBUG [kea-dhcp4.ddns/12.1] DHCP4_CLIENT_HOSTNAME_DATA [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: client sent Hostname option: phone`, "kea", "NAME", "", mac, "phone", ""},
		{"dnsmasq ack", `<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: DHCPACK(vlan0.20) 192.168.20.50 aa:bb:cc:dd:ee:ff phone`, "dnsmasq", "ACK", "192.168.20.50", mac, "phone", "vlan0.20"},
		{"dnsmasq ack no name", `<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: DHCPACK(br0) 192.168.20.50 aa:bb:cc:dd:ee:ff`, "dnsmasq", "ACK", "192.168.20.50", mac, "", "br0"},
		{"dnsmasq log-dhcp tag", `<30>1 2026-11-05T12:00:00Z fw dnsmasq-dhcp 7 - - 1234567 DHCPACK(br0) 192.168.20.50 aa:bb:cc:dd:ee:ff phone`, "dnsmasq", "ACK", "192.168.20.50", mac, "phone", "br0"},
		{"dnsmasq plain tag", `<30>Nov  5 12:00:00 fw dnsmasq[7]: DHCPRELEASE(br0) 192.168.20.50 aa:bb:cc:dd:ee:ff`, "dnsmasq", "RELEASE", "192.168.20.50", mac, "", "br0"},
		{"dnsmasq nak reason", `<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: DHCPNAK(br0) 192.168.20.50 aa:bb:cc:dd:ee:ff wrong address`, "dnsmasq", "NAK", "192.168.20.50", mac, "", "br0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(c.raw, now)
			if err != nil {
				t.Fatal(err)
			}
			ev, kind := Decode(m)
			if kind != "dhcp" {
				t.Fatalf("kind %q, event %+v", kind, ev)
			}
			if ev.Event.Module != event.ModuleDHCP || ev.Event.Dataset != "dhcp."+c.backend || ev.Data["dhcp_message"] != c.msg ||
				ev.Source.IP != c.ip || ev.Source.MAC != c.wantMAC || ev.Source.Domain != c.host {
				t.Fatalf("decoded %+v source %+v data %+v", ev.Event, ev.Source, ev.Data)
			}
			if got, _ := ev.Data["interface"].(string); got != c.iface {
				t.Fatalf("interface %q", got)
			}
		})
	}
	// Other messages from these daemons stay generic.
	for _, raw := range []string{
		`<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPDISCOVER from aa:bb:cc:dd:ee:ff via igb1`,
		`<30>Nov  5 12:00:00 fw dhcpd[99]: Listening on BPF/igb1/aa:bb:cc:dd:ee:ff/192.168.20.0/24`,
		`<30>Nov  5 12:00:00 fw dhcpd[99]: DHCPACK on not-an-ip to aa:bb:cc:dd:ee:ff via igb1`,
		`<30>Nov  5 12:00:00 fw kea-dhcp4[12]: INFO  [kea-dhcp4.dhcp4/12.1] DHCP4_STARTED Kea DHCPv4 server version 2.6.1 started`,
		`<30>Nov  5 12:00:00 fw kea-dhcp4[12]: INFO  [kea-dhcp4.leases/12.1] DHCP4_LEASE_ALLOC [no hwaddr info], cid=[01:02], tid=0x1: lease 192.168.20.50 has been allocated for 3600 seconds`,
		`<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff`,
		`<30>Nov  5 12:00:00 fw dnsmasq[7]: query[A] example.com from 192.168.20.5`,
		`<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: 1234567 tags: lan, br0`,
	} {
		m, err := Parse(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		if ev, kind := Decode(m); kind != "syslog" || ev.Event.Module != event.ModuleSyslog {
			t.Errorf("%s: kind %q module %q", raw, kind, ev.Event.Module)
		}
	}
	// A client-supplied name stays short and printable.
	m, _ := Parse("<30>Nov  5 12:00:00 fw dnsmasq-dhcp[7]: DHCPACK(br0) 192.168.20.50 aa:bb:cc:dd:ee:ff a\x01b", now)
	if ev, _ := Decode(m); ev.Source.Domain != "ab" {
		t.Errorf("hostname %q", ev.Source.Domain)
	}
}
