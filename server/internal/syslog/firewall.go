package syslog

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

// fwRecord is what every firewall decoder fills in. newFirewallEvent turns it into an
// event the same way for every vendor, so detections and the inbound/exposure views work
// without knowing which firewall sent the line.
type fwRecord struct {
	Vendor, Product string
	Dataset         string // short vendor id, becomes firewall.<Dataset>
	RawAction       string // the vendor's own word, kept in Data["vendor_action"]
	Denied          bool
	Direction       string // event.Direction*; empty means work it out from the addresses
	Proto           string // tcp, udp, icmp ... or a protocol number
	SrcIP, DstIP    string
	SrcPort         int
	DstPort         int
	SrcMAC          string
	Bytes, Packets  int64
	Interface       string // the interface the packet came in on
	Rule            string
	Data            map[string]any
}

// newFirewallEvent returns nil when the record has no usable source and destination.
func newFirewallEvent(m *Message, r fwRecord) *event.Event {
	src, err1 := netip.ParseAddr(r.SrcIP)
	dst, err2 := netip.ParseAddr(r.DstIP)
	if err1 != nil || err2 != nil {
		return nil
	}
	proto := protoName(r.Proto)
	ev := base(m, event.ModuleFirewall, "firewall."+sanitizeDataset(r.Dataset))
	ev.Observer = &event.Observer{Type: "firewall", Vendor: r.Vendor, Product: r.Product, Hostname: m.Hostname}
	ev.Event.Category = []string{event.CategoryNetwork}
	// Every vendor's allow/deny wording is folded into pass/block, which is what OPNsense
	// logs and what the queries elsewhere look for.
	if r.Denied {
		ev.Event.Action = "block"
		ev.Event.Type = []string{event.TypeConnection, event.TypeDenied}
		ev.Event.Outcome = event.OutcomeFailure
	} else {
		ev.Event.Action = "pass"
		ev.Event.Type = []string{event.TypeConnection, event.TypeAllowed}
		ev.Event.Outcome = event.OutcomeSuccess
	}
	dir := r.Direction
	if dir == "" {
		dir = inferDirection(src, dst)
	}
	ev.Network = &event.Network{Direction: dir, Transport: proto, Bytes: r.Bytes, Packets: r.Packets}
	if src.Is4() || src.Is4In6() {
		ev.Network.Type = "ipv4"
	} else {
		ev.Network.Type = "ipv6"
	}
	ev.Source = &event.Endpoint{IP: src.Unmap().String(), Port: r.SrcPort, MAC: r.SrcMAC}
	ev.Destination = &event.Endpoint{IP: dst.Unmap().String(), Port: r.DstPort}
	ev.Data = map[string]any{}
	for k, v := range r.Data {
		if v != "" && v != nil {
			ev.Data[k] = v
		}
	}
	if r.Interface != "" {
		ev.Data["interface"] = r.Interface
	}
	if r.Rule != "" {
		ev.Data["rule_number"] = r.Rule
	}
	if r.RawAction != "" {
		ev.Data["vendor_action"] = r.RawAction
	}
	ev.Network.CommunityID = communityid.ComputeStrings(ev.Source.IP, ev.Destination.IP, proto, r.SrcPort, r.DstPort)
	verdict := "pass"
	if r.Denied {
		verdict = "block"
	}
	ev.Message = verdict + " " + proto + " " + joinHostPort(ev.Source.IP, r.SrcPort) + " -> " +
		joinHostPort(ev.Destination.IP, r.DstPort)
	if r.Interface != "" {
		ev.Message += " on " + r.Interface
	}
	return ev
}

// protoName gives the lower-case transport name for a name or an IP protocol number.
func protoName(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "1", "icmp":
		return "icmp"
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "47", "gre":
		return "gre"
	case "50", "esp":
		return "esp"
	case "58", "icmp6", "ipv6-icmp", "icmpv6":
		return "ipv6-icmp"
	case "":
		return "unknown"
	}
	return p
}

// isDeniedAction reports whether a vendor's action word means the traffic was stopped.
// Anything else (allow, accept, close, start, timeout ...) means it went through.
func isDeniedAction(a string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	for _, p := range []string{"deny", "denied", "drop", "block", "reject", "reset", "discard", "refuse", "client-rst", "server-rst", "ip-conn", "failed"} {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

// inferDirection is for vendors that log zones or interface names but not a direction.
// A public source reaching a private address is inbound, the reverse is outbound.
func inferDirection(src, dst netip.Addr) string {
	switch sp, dp := isPublicAddr(src), isPublicAddr(dst); {
	case sp && !dp:
		return event.DirectionInbound
	case !sp && dp:
		return event.DirectionOutbound
	}
	return event.DirectionUnknown
}

func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1]&0xc0 == 0x40 { // carrier-grade NAT, also Tailscale
			return false
		}
	}
	return true
}

// parseKV reads key=value pairs separated by spaces. Values may be double-quoted and then
// may hold spaces. Tokens without "=" are skipped. Keys are lower-cased.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			continue // a bare word
		}
		key := strings.ToLower(s[start:i])
		i++
		var val string
		if i < len(s) && s[i] == '"' {
			i++
			vs := i
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
			val = s[vs:min(i, len(s))]
			if i < len(s) {
				i++
			}
		} else {
			vs := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			val = s[vs:i]
		}
		if _, dup := out[key]; !dup && key != "" {
			out[key] = val
		}
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
