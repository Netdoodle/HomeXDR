package syslog

import (
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// decoder recognizes one kind of message and turns it into an event. match is cheap and
// looks at the parsed message only; decode may still return nil when the line turns out
// not to be what match guessed, and the next decoder is tried.
type decoder struct {
	kind   string // what Decode reports, and what the sender is remembered as
	vendor string // shown as the device's vendor when the kind is a network appliance
	match  func(*Message) bool
	decode func(*Message) *event.Event
}

// decoders is tried in order. Vendors that send no syslog tag (FortiGate, Palo Alto,
// Sophos) are matched on the message content, so they come after the tag-based ones.
var decoders = []decoder{
	{kind: "opnsense", vendor: "OPNsense", match: func(m *Message) bool { return m.AppName == "filterlog" }, decode: decodeFilterlog},
	{kind: "suricata", vendor: "Suricata", match: func(m *Message) bool {
		return strings.HasPrefix(strings.TrimSpace(m.Msg), "{") && strings.Contains(m.Msg, `"event_type"`)
	}, decode: decodeEVE},
	{kind: "syslog", match: func(m *Message) bool { return m.AppName == "sshd" || strings.HasPrefix(m.AppName, "sshd-") }, decode: decodeSSHD},
	{kind: "unbound", match: func(m *Message) bool { return m.AppName == "unbound" }, decode: decodeUnbound},
	{kind: "dhcp", match: func(m *Message) bool { return isDHCPApp(m.AppName) }, decode: decodeDHCP},
	{kind: "fortigate", vendor: "Fortinet", match: matchFortiGate, decode: decodeFortiGate},
	{kind: "paloalto", vendor: "Palo Alto Networks", match: matchPaloAlto, decode: decodePaloAlto},
	{kind: "sophos", vendor: "Sophos", match: matchSophos, decode: decodeSophos},
	{kind: "mikrotik", vendor: "MikroTik", match: matchMikroTik, decode: decodeMikroTik},
	{kind: "ubiquiti", vendor: "Ubiquiti", match: matchUbiquiti, decode: decodeUbiquiti},
}

// Decode turns a syslog message into an event. kind reports what was recognized, for
// example "opnsense", "fortigate", "unbound" or, when nothing matched, "syslog".
func Decode(m *Message) (ev *event.Event, kind string) {
	for _, d := range decoders {
		if !d.match(m) {
			continue
		}
		if ev := d.decode(m); ev != nil {
			return ev, d.kind
		}
	}
	return decodeGeneric(m), "syslog"
}

// vendorFor names the appliance vendor for a kind, or "" for kinds that are not devices.
func vendorFor(kind string) string {
	for _, d := range decoders {
		if d.kind == kind {
			return d.vendor
		}
	}
	return ""
}
