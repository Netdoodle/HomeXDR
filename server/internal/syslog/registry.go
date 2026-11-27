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
	label  string // offered as a parser an admin can bind a sender to; "" = not offered
	match  func(*Message) bool
	decode func(*Message) *event.Event
}

// decoders is tried in order. Vendors that send no syslog tag (FortiGate, Palo Alto,
// Sophos) are matched on the message content, so they come after the tag-based ones.
var decoders = []decoder{
	{kind: "opnsense", vendor: "OPNsense", label: "OPNsense filterlog", match: func(m *Message) bool { return m.AppName == "filterlog" }, decode: decodeFilterlog},
	// pfSense sends the same lines as OPNsense, so it is never auto-detected; binding a
	// sender to it only changes the vendor shown.
	{kind: "pfsense", vendor: "Netgate", label: "pfSense filterlog", match: func(*Message) bool { return false }, decode: decodePfSense},
	{kind: "suricata", vendor: "Suricata", label: "Suricata EVE JSON", match: func(m *Message) bool {
		return strings.HasPrefix(strings.TrimSpace(m.Msg), "{") && strings.Contains(m.Msg, `"event_type"`)
	}, decode: decodeEVE},
	{kind: "syslog", match: func(m *Message) bool { return m.AppName == "sshd" || strings.HasPrefix(m.AppName, "sshd-") }, decode: decodeSSHD},
	{kind: "unbound", label: "Unbound DNS", match: func(m *Message) bool { return m.AppName == "unbound" }, decode: decodeUnbound},
	{kind: "dhcp", label: "DHCP server", match: func(m *Message) bool { return isDHCPApp(m.AppName) }, decode: decodeDHCP},
	// CEF and LEEF name their vendor in the header, so they come before content guesses.
	{kind: "cef", label: "CEF", match: matchCEF, decode: decodeCEF},
	{kind: "leef", label: "LEEF", match: matchLEEF, decode: decodeLEEF},
	{kind: "fortigate", vendor: "Fortinet", label: "Fortinet FortiGate", match: matchFortiGate, decode: decodeFortiGate},
	{kind: "paloalto", vendor: "Palo Alto Networks", label: "Palo Alto PAN-OS", match: matchPaloAlto, decode: decodePaloAlto},
	{kind: "sophos", vendor: "Sophos", label: "Sophos Firewall", match: matchSophos, decode: decodeSophos},
	{kind: "mikrotik", vendor: "MikroTik", label: "MikroTik RouterOS", match: matchMikroTik, decode: decodeMikroTik},
	{kind: "ubiquiti", vendor: "Ubiquiti", label: "Ubiquiti UniFi / EdgeOS (netfilter)", match: matchUbiquiti, decode: decodeUbiquiti},
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

// PlainParser is the binding that turns decoding off: every line is kept as plain syslog.
const PlainParser = "plain"

// Parser is one choice for binding a sender.
type Parser struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// Parsers lists what a sender can be bound to, in the order decoders are tried.
func Parsers() []Parser {
	out := []Parser{}
	for _, d := range decoders {
		if d.label != "" {
			out = append(out, Parser{d.kind, d.label})
		}
	}
	return append(out, Parser{PlainParser, "Plain syslog (no decoding)"})
}

// IsParser reports whether kind can be bound.
func IsParser(kind string) bool {
	for _, p := range Parsers() {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

// DecodeAs decodes with the parser a sender is bound to. A line that parser does not
// understand goes through auto-detection, since one device often sends several formats
// (a FortiGate's system events next to its traffic log, for example).
func DecodeAs(m *Message, parser string) (ev *event.Event, kind string) {
	switch parser {
	case "":
		return Decode(m)
	case PlainParser:
		return decodeGeneric(m), "syslog"
	}
	for _, d := range decoders {
		if d.kind == parser && d.label != "" {
			if ev := d.decode(m); ev != nil {
				return ev, d.kind
			}
			break
		}
	}
	return Decode(m)
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
