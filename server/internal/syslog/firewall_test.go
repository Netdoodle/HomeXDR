package syslog

import (
	"testing"

	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Every line below is written from the vendor's documented format with documentation
// addresses (RFC 5737, RFC 1918), not copied from a device.
func TestFirewallVendors(t *testing.T) {
	cases := []struct {
		name, raw, kind, vendor string
		src, dst, proto         string
		sport, dport            int
		action, dir, iface      string
	}{
		{
			name: "fortigate accept outbound",
			raw:  `<189>date=2026-03-01 time=10:00:00 devname="FGT-A" devid="FGT60F0000000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1772359200000000000 srcip=192.168.1.10 srcport=51234 srcintf="lan" srcintfrole="lan" dstip=203.0.113.5 dstport=443 dstintf="wan1" dstintfrole="wan" proto=6 action="accept" policyid=1 service="HTTPS" sentbyte=1234 rcvdbyte=5678`,
			kind: "fortigate", vendor: "Fortinet", src: "192.168.1.10", dst: "203.0.113.5", proto: "tcp", sport: 51234, dport: 443,
			action: "pass", dir: event.DirectionOutbound, iface: "lan",
		},
		{
			name: "fortigate deny inbound",
			raw:  `<189>date=2026-03-01 time=10:00:01 devname="FGT-A" devid="FGT60F0000000000" logid="0000000013" type="traffic" subtype="forward" level="warning" srcip=198.51.100.7 srcport=40000 srcintf="wan1" srcintfrole="wan" dstip=192.168.1.20 dstport=22 dstintf="lan" dstintfrole="lan" proto=6 action="deny" policyid=0`,
			kind: "fortigate", vendor: "Fortinet", src: "198.51.100.7", dst: "192.168.1.20", proto: "tcp", sport: 40000, dport: 22,
			action: "block", dir: event.DirectionInbound, iface: "wan1",
		},
		{
			name: "palo alto traffic allow",
			raw:  `<14>Mar  1 10:00:00 PA-FW 1,2026/03/01 10:00:00,001234567890,TRAFFIC,end,2561,2026/03/01 10:00:00,192.168.1.10,203.0.113.5,0.0.0.0,0.0.0.0,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,fwd,2026/03/01 10:00:00,12345,1,51234,443,0,0,0x19,tcp,allow,6000,1000,5000,12,2026/03/01 09:59:00,5,web-browsing`,
			kind: "paloalto", vendor: "Palo Alto Networks", src: "192.168.1.10", dst: "203.0.113.5", proto: "tcp", sport: 51234, dport: 443,
			action: "pass", dir: event.DirectionOutbound, iface: "ethernet1/2",
		},
		{
			name: "palo alto traffic drop",
			raw:  `<14>Mar  1 10:00:00 PA-FW 1,2026/03/01 10:00:00,001234567890,TRAFFIC,drop,2561,2026/03/01 10:00:00,198.51.100.7,192.168.1.20,0.0.0.0,0.0.0.0,deny-all,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,fwd,2026/03/01 10:00:00,0,1,40000,3389,0,0,0x0,tcp,drop,60,60,0,1,2026/03/01 10:00:00,0,any`,
			kind: "paloalto", vendor: "Palo Alto Networks", src: "198.51.100.7", dst: "192.168.1.20", proto: "tcp", sport: 40000, dport: 3389,
			action: "block", dir: event.DirectionInbound, iface: "ethernet1/1",
		},
		{
			name: "sophos allow",
			raw:  `<30>device_name="SFW" timestamp="2026-03-01T10:00:00" log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" fw_rule_id=3 in_interface="Port2" out_interface="Port1" src_mac=AA:BB:CC:DD:EE:FF src_ip=192.168.1.10 dst_ip=203.0.113.5 protocol="TCP" src_port=51234 dst_port=443 sent_bytes=100 recv_bytes=900`,
			kind: "sophos", vendor: "Sophos", src: "192.168.1.10", dst: "203.0.113.5", proto: "tcp", sport: 51234, dport: 443,
			action: "pass", dir: event.DirectionOutbound, iface: "Port2",
		},
		{
			name: "mikrotik drop with prefix",
			raw:  `<134>Mar  1 10:00:00 rb4011 firewall,info DROP-WAN forward: in:ether1 out:bridge, src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 198.51.100.7:40000->192.168.88.10:22, len 60`,
			kind: "mikrotik", vendor: "MikroTik", src: "198.51.100.7", dst: "192.168.88.10", proto: "tcp", sport: 40000, dport: 22,
			action: "block", dir: event.DirectionInbound, iface: "ether1",
		},
		{
			name: "mikrotik icmp accept",
			raw:  `<134>Mar  1 10:00:00 rb4011 firewall,info forward: in:bridge out:ether1, proto ICMP (type 8, code 0), 192.168.88.10->203.0.113.5, len 84`,
			kind: "mikrotik", vendor: "MikroTik", src: "192.168.88.10", dst: "203.0.113.5", proto: "icmp",
			action: "pass", dir: event.DirectionOutbound, iface: "bridge",
		},
		{
			name: "unifi drop",
			raw:  `<4>Mar  1 10:00:00 udm kernel: [WAN_IN-3000-D]IN=eth8 OUT=br0 MAC=00:00:5e:00:53:01:aa:bb:cc:dd:ee:ff:08:00 SRC=198.51.100.7 DST=192.168.1.10 LEN=44 TOS=0x00 PREC=0x00 TTL=240 ID=54321 PROTO=TCP SPT=40000 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0`,
			kind: "ubiquiti", vendor: "Ubiquiti", src: "198.51.100.7", dst: "192.168.1.10", proto: "tcp", sport: 40000, dport: 23,
			action: "block", dir: event.DirectionInbound, iface: "eth8",
		},
		{
			name: "edgerouter accept",
			raw:  `<4>Mar  1 10:00:00 er-x kernel: [LAN_IN-10-A]IN=eth1 OUT=eth0 SRC=192.168.1.10 DST=203.0.113.5 LEN=60 PROTO=UDP SPT=5353 DPT=53`,
			kind: "ubiquiti", vendor: "Ubiquiti", src: "192.168.1.10", dst: "203.0.113.5", proto: "udp", sport: 5353, dport: 53,
			action: "pass", dir: event.DirectionOutbound, iface: "eth1",
		},
		{
			name: "plain netfilter is not Ubiquiti",
			raw:  `<4>Mar  1 10:00:00 gw kernel: DROPPED: IN=eth0 OUT= SRC=198.51.100.7 DST=192.168.1.10 LEN=40 PROTO=TCP SPT=1 DPT=2`,
			kind: "ubiquiti", vendor: "Linux", src: "198.51.100.7", dst: "192.168.1.10", proto: "tcp", sport: 1, dport: 2,
			action: "block", dir: event.DirectionInbound, iface: "eth0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse(c.raw, now)
			if err != nil {
				t.Fatal(err)
			}
			ev, kind := Decode(m)
			if kind != c.kind {
				t.Fatalf("kind %q, want %q (event %+v)", kind, c.kind, ev.Event)
			}
			if ev.Event.Module != event.ModuleFirewall || ev.Observer == nil || ev.Observer.Type != "firewall" || ev.Observer.Vendor != c.vendor {
				t.Fatalf("module %q observer %+v", ev.Event.Module, ev.Observer)
			}
			if ev.Source.IP != c.src || ev.Destination.IP != c.dst || ev.Network.Transport != c.proto ||
				ev.Source.Port != c.sport || ev.Destination.Port != c.dport {
				t.Fatalf("5-tuple %+v -> %+v %s", ev.Source, ev.Destination, ev.Network.Transport)
			}
			if ev.Event.Action != c.action || ev.Network.Direction != c.dir || ev.Data["interface"] != c.iface {
				t.Fatalf("action %q direction %q data %v", ev.Event.Action, ev.Network.Direction, ev.Data)
			}
			want := communityid.ComputeStrings(c.src, c.dst, c.proto, c.sport, c.dport)
			if want == "" || ev.Network.CommunityID != want {
				t.Fatalf("community id %q, want %q", ev.Network.CommunityID, want)
			}
			if (c.action == "pass") != (ev.Event.Outcome == event.OutcomeSuccess) {
				t.Fatalf("outcome %q for action %q", ev.Event.Outcome, c.action)
			}
		})
	}
}

func TestFortiGateSkipsOtherLogTypes(t *testing.T) {
	m, _ := Parse(`<189>date=2026-03-01 time=10:00:00 devname="FGT-A" devid="FGT60F0000000000" logid="0100032001" type="event" subtype="system" level="information" msg="Admin login"`, now)
	if _, kind := Decode(m); kind != "syslog" {
		t.Fatalf("kind %q", kind)
	}
}

func TestParseKV(t *testing.T) {
	kv := parseKV(`a=1 b="two words" bare c= d="x\"y" a=dup`)
	if kv["a"] != "1" || kv["b"] != "two words" || kv["c"] != "" || kv["d"] != `x\"y` || len(kv) != 4 {
		t.Fatalf("%v", kv)
	}
}
