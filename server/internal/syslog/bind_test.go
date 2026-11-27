package syslog

import (
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestDecodeAs(t *testing.T) {
	filterlog := `<134>1 2026-10-19T12:00:00-05:00 fw filterlog 61234 - - 77,,,abc,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.7,192.168.1.10,40000,22,0,S,1,,64240,,mss`
	m, _ := Parse(filterlog, now)
	if ev, kind := DecodeAs(m, ""); kind != "opnsense" || ev.Observer.Product != "OPNsense" {
		t.Fatalf("auto: %q %+v", kind, ev.Observer)
	}
	ev, kind := DecodeAs(m, "pfsense")
	if kind != "pfsense" || ev.Observer.Product != "pfSense" || ev.Event.Module != event.ModuleOPNsense || ev.Event.Action != "block" {
		t.Fatalf("pfsense: %q %+v %+v", kind, ev.Observer, ev.Event)
	}
	if vendorFor("pfsense") == "" {
		t.Fatal("pfsense has no vendor")
	}
	if ev, kind := DecodeAs(m, PlainParser); kind != "syslog" || ev.Event.Module != event.ModuleSyslog {
		t.Fatalf("plain: %q %+v", kind, ev.Event)
	}
	// A line the bound parser cannot read falls back to auto-detection.
	if _, kind := DecodeAs(m, "fortigate"); kind != "opnsense" {
		t.Fatalf("fallback: %q", kind)
	}
	if !IsParser("ubiquiti") || IsParser("syslog") || IsParser("nope") {
		t.Fatal("IsParser")
	}
}
