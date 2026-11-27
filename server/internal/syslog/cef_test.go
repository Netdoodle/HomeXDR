package syslog

import (
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Sample lines follow the published CEF and LEEF specifications, with documentation
// addresses; they are not captured from any product.
func TestCEFFirewall(t *testing.T) {
	raw := `<134>Mar  1 10:00:00 fw01 CEF:0|Example Corp|Edge FW|2.1|4001|Connection denied|7|rt=1772359200000 src=198.51.100.7 spt=40000 dst=192.168.1.10 dpt=22 proto=TCP act=blocked deviceInboundInterface=wan0 suser=alice msg=SSH from outside \= not allowed`
	m, err := Parse(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	ev, kind := Decode(m)
	if kind != "cef" || ev.Event.Module != event.ModuleFirewall || ev.Event.Dataset != "firewall.cef.example_corp" {
		t.Fatalf("kind %q event %+v", kind, ev.Event)
	}
	if ev.Event.Action != "block" || ev.Network.Direction != event.DirectionInbound || ev.Data["interface"] != "wan0" ||
		ev.Source.Port != 40000 || ev.Destination.IP != "192.168.1.10" || ev.Network.CommunityID == "" {
		t.Fatalf("event %+v net %+v data %v", ev.Event, ev.Network, ev.Data)
	}
	if ev.Event.Severity != 70 || ev.User == nil || ev.User.Name != "alice" || ev.Timestamp.Unix() != 1772359200 {
		t.Fatalf("severity %d user %+v ts %v", ev.Event.Severity, ev.User, ev.Timestamp)
	}
	if f := ev.Data["fields"].(map[string]string); f["msg"] != "SSH from outside = not allowed" {
		t.Fatalf("msg %q", f["msg"])
	}
	if ev.Observer.Vendor != "Example Corp" || ev.Observer.Product != "Edge FW" {
		t.Fatalf("observer %+v", ev.Observer)
	}
}

func TestCEFNonFirewall(t *testing.T) {
	// No verdict: an IDS-style alert keeps its fields as a syslog event. The header has an
	// escaped pipe, and the line has no syslog hostname.
	raw := `<134>CEF:0|Example Corp|Sensor\|IDS|1.0|900|Port scan detected|High|src=198.51.100.7 dst=192.168.1.10 cat=recon`
	m, _ := Parse(raw, now)
	ev, kind := Decode(m)
	if kind != "cef" || ev.Event.Module != event.ModuleSyslog || ev.Event.Dataset != "cef.example_corp" {
		t.Fatalf("kind %q event %+v", kind, ev.Event)
	}
	if ev.Observer.Product != "Sensor|IDS" || ev.Message != "Port scan detected" || ev.Event.Severity != 75 ||
		ev.Source.IP != "198.51.100.7" || ev.Network.Direction != event.DirectionInbound || ev.Data["category"] != "recon" {
		t.Fatalf("observer %+v msg %q sev %d data %v", ev.Observer, ev.Message, ev.Event.Severity, ev.Data)
	}
}

func TestLEEF1(t *testing.T) {
	raw := "<13>Mar  1 10:00:00 gw LEEF:1.0|Example Corp|Gateway|3.0|traffic|src=192.168.1.10\tdst=203.0.113.5\tsrcPort=51234\tdstPort=443\tproto=6\taction=allow\tsrcBytes=100\tdstBytes=900\tusrName=bob"
	m, _ := Parse(raw, now)
	ev, kind := Decode(m)
	if kind != "leef" || ev.Event.Module != event.ModuleFirewall || ev.Event.Action != "pass" {
		t.Fatalf("kind %q event %+v", kind, ev.Event)
	}
	if ev.Network.Transport != "tcp" || ev.Network.Bytes != 1000 || ev.Network.Direction != event.DirectionOutbound ||
		ev.Destination.Port != 443 || ev.User.Name != "bob" {
		t.Fatalf("net %+v dst %+v", ev.Network, ev.Destination)
	}
}

func TestLEEF2Delimiter(t *testing.T) {
	for _, d := range []string{"^", "x5E", "0x5E"} {
		raw := "<13>LEEF:2.0|Example Corp|Gateway|3.0|deny|" + d + "|src=198.51.100.7^dst=192.168.1.10^srcPort=1^dstPort=3389^proto=TCP^action=drop"
		m, _ := Parse(raw, now)
		ev, kind := Decode(m)
		if kind != "leef" || ev.Event.Action != "block" || ev.Destination.Port != 3389 {
			t.Fatalf("delimiter %q: kind %q event %+v", d, kind, ev.Event)
		}
	}
}

func TestParseCEFExt(t *testing.T) {
	ext := parseCEFExt(`a=1 b=two words c=x\=y url=http://h/?q=1 d=`)
	if ext["a"] != "1" || ext["b"] != "two words" || ext["c"] != "x=y" || ext["url"] != "http://h/?q=1" || ext["d"] != "" {
		t.Fatalf("%q", ext)
	}
}
