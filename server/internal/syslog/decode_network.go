package syslog

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Formats in this file come from each daemon's documentation and source, since no live
// sample was available when they were written. A line that does not fit falls through to
// the generic decoder, so nothing is lost.

// decodeUnbound decodes Unbound's query and reply log lines (log-queries, log-replies,
// log-local-actions), which name the client, so each DNS lookup belongs to one device:
//
//	[pid:0] info: 192.168.20.5 example.com. A IN
//	[pid:0] info: 192.168.20.5 example.com. A IN NOERROR 0.001234 0 86
//	[pid:0] info: ads.example.com. always_nxdomain 192.168.20.5@53124 ads.example.com. A IN
//	[pid:0] reply: 192.168.20.5 example.com. A IN NOERROR 0.001234 1 86   (log-tag-queryreply)
func decodeUnbound(m *Message) *event.Event {
	s := strings.TrimSpace(m.Msg)
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			s = strings.TrimLeft(s[i+1:], " ")
		}
	}
	tag, rest, ok := strings.Cut(s, ": ")
	if !ok || (tag != "info" && tag != "query" && tag != "reply") {
		return nil
	}
	f := strings.Fields(rest)
	var client, name, qtype string
	var rcode, zone, zoneAction string
	var timing, cached, size string
	switch {
	case len(f) == 4 && isDNSClass(f[3]):
		client, name, qtype = f[0], f[1], f[2]
	case len(f) == 6 && isDNSClass(f[5]) && strings.Contains(f[2], "@"):
		zone, zoneAction, name, qtype = f[0], f[1], f[3], f[4]
		client, _, _ = strings.Cut(f[2], "@")
	case len(f) >= 5 && isDNSClass(f[3]):
		client, name, qtype, rcode = f[0], f[1], f[2], f[4]
		if len(f) >= 8 {
			timing, cached, size = f[5], f[6], f[7]
		}
	default:
		return nil
	}
	client, _, _ = strings.Cut(client, "@")
	addr, err := netip.ParseAddr(client)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	ev := base(m, event.ModuleDNS, "dns.unbound")
	ev.Observer = &event.Observer{Type: "dns", Vendor: "NLnet Labs", Product: "Unbound", Hostname: m.Hostname}
	ev.Event.Category = []string{event.CategoryNetwork}
	ev.Event.Type = []string{event.TypeProtocol}
	ev.Source = &event.Endpoint{IP: addr.String()}
	ev.Network = &event.Network{Protocol: "dns", Type: ipType(addr)}
	name = cleanDNSName(name)
	ev.DNS = &event.DNS{Type: "query", Question: event.DNSQuestion{Name: name, Type: strings.ToUpper(qtype)}}
	ev.Event.Action = "dns-query"
	ev.Message = "dns query " + name + " " + ev.DNS.Question.Type + " from " + ev.Source.IP
	if rcode != "" {
		ev.DNS.Type = "answer"
		ev.DNS.ResponseCode = rcode
		ev.Event.Action = "dns-answer"
		ev.Message = "dns answer " + name + " " + ev.DNS.Question.Type + " " + rcode + " to " + ev.Source.IP
		if d := unboundData(timing, cached, size); d != nil {
			ev.Data = d
		}
	}
	if zoneAction != "" {
		ev.Event.Action = "dns-local-zone"
		ev.Data = map[string]any{"local_zone": cleanDNSName(zone), "local_action": zoneAction}
		ev.Message = "dns " + zoneAction + " " + name + " " + ev.DNS.Question.Type + " from " + ev.Source.IP
	}
	return ev
}

func unboundData(timing, cached, size string) map[string]any {
	if timing == "" {
		return nil
	}
	d := map[string]any{}
	if t, err := strconv.ParseFloat(timing, 64); err == nil {
		d["response_time_ms"] = t * 1000
	}
	if cached == "1" {
		d["cached"] = true
	} else if cached == "0" {
		d["cached"] = false
	}
	if n, err := strconv.Atoi(size); err == nil {
		d["response_bytes"] = n
	}
	return d
}

func isDNSClass(s string) bool {
	switch s {
	case "IN", "CH", "HS", "ANY", "NONE":
		return true
	}
	return strings.HasPrefix(s, "CLASS")
}

// cleanDNSName drops the trailing dot and lowers case; the root stays ".".
func cleanDNSName(s string) string {
	if s == "<root>" || s == "." {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func ipType(a netip.Addr) string {
	if a.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// isDHCPApp reports the syslog tags of the DHCP servers OPNsense can run.
func isDHCPApp(app string) bool {
	switch app {
	case "dhcpd", "kea-dhcp4", "dnsmasq-dhcp", "dnsmasq":
		return true
	}
	return false
}

// dhcpLine is what the three DHCP servers' log lines have in common.
type dhcpLine struct {
	backend, msgType, ip, mac, hostname, iface string
}

// decodeDHCP decodes lease messages from ISC dhcpd, Kea and dnsmasq. Event fields:
// source.ip is the client's address, source.mac its MAC, source.domain the name it gave.
func decodeDHCP(m *Message) *event.Event {
	s := strings.TrimSpace(m.Msg)
	var d *dhcpLine
	switch m.AppName {
	case "dhcpd":
		d = parseISC(s)
	case "kea-dhcp4":
		d = parseKea(s)
	case "dnsmasq-dhcp", "dnsmasq":
		d = parseDnsmasq(s)
	}
	if d == nil {
		return nil
	}
	ev := base(m, event.ModuleDHCP, "dhcp."+d.backend)
	ev.Observer = &event.Observer{Type: "dhcp", Product: d.backend, Hostname: m.Hostname}
	ev.Event.Category = []string{event.CategoryNetwork}
	ev.Event.Type = []string{event.TypeProtocol}
	ev.Event.Action = "dhcp-" + strings.ToLower(d.msgType)
	ev.Network = &event.Network{Protocol: "dhcp", Transport: "udp"}
	ev.Source = &event.Endpoint{IP: d.ip, MAC: d.mac, Domain: d.hostname}
	ev.Data = map[string]any{"dhcp_message": d.msgType, "dhcp_backend": d.backend}
	if d.iface != "" {
		ev.Data["interface"] = d.iface
	}
	if d.hostname != "" {
		ev.Data["hostname"] = d.hostname
	}
	var sb strings.Builder
	sb.WriteString("DHCP" + d.msgType)
	if d.ip != "" {
		sb.WriteString(" " + d.ip)
	}
	sb.WriteString(" " + d.mac)
	if d.hostname != "" {
		sb.WriteString(" (" + d.hostname + ")")
	}
	if d.iface != "" {
		sb.WriteString(" via " + d.iface)
	}
	ev.Message = sb.String()
	return ev
}

// ISC dhcpd message shapes. Group order is message, address, MAC, name, interface.
var iscLines = []*regexp.Regexp{
	regexp.MustCompile(`^DHCP(ACK|OFFER|NAK) on (\S+) to ([0-9A-Fa-f:]+)(?: \(([^)]*)\))? via (\S+)`),
	regexp.MustCompile(`^DHCP(RELEASE|DECLINE) of (\S+) from ([0-9A-Fa-f:]+)(?: \(([^)]*)\))? via (\S+)`),
	regexp.MustCompile(`^DHCP(REQUEST) for (\S+)(?: \([^)]*\))? from ([0-9A-Fa-f:]+)(?: \(([^)]*)\))? via (\S+)`),
	regexp.MustCompile(`^DHCP(ACK) to (\S+) \(([0-9A-Fa-f:]+)\)()(?: via (\S+))?`),
	regexp.MustCompile(`^DHCP(EXPIRE) on (\S+) to ([0-9A-Fa-f:]+)(?: \(([^)]*)\))?()`),
}

func parseISC(s string) *dhcpLine {
	if !strings.HasPrefix(s, "DHCP") {
		return nil
	}
	for _, re := range iscLines {
		g := re.FindStringSubmatch(s)
		if g == nil {
			continue
		}
		ip, mac := cleanIP(g[2]), cleanMAC(g[3])
		if ip == "" || mac == "" {
			return nil
		}
		return &dhcpLine{backend: "isc", msgType: g[1], ip: ip, mac: mac, hostname: cleanHostname(g[4]), iface: cleanIface(g[5])}
	}
	return nil
}

// Kea logs lease events with a code, the client as [hwtype=1 <mac>], and no hostname at
// the default log level; the *_HOSTNAME_DATA and *_FQDN_DATA debug lines carry the name.
var (
	keaLine  = regexp.MustCompile(`\b(DHCP4_[A-Z0-9_]+)\s+\[hwtype=\d+ ([0-9A-Fa-f:]+)\]`)
	keaLease = regexp.MustCompile(`(?:lease|address|requests address) (\d+\.\d+\.\d+\.\d+)`)
	keaName  = regexp.MustCompile(`(?:Hostname|FQDN) option: (.+)$`)
)

// keaCodes maps Kea log codes to the matching DHCP message.
var keaCodes = map[string]string{
	"DHCP4_LEASE_ALLOC":            "ACK",
	"DHCP4_LEASE_REUSE":            "ACK",
	"DHCP4_LEASE_ADVERT":           "OFFER",
	"DHCP4_INIT_REBOOT":            "REQUEST",
	"DHCP4_RELEASE":                "RELEASE",
	"DHCP4_RELEASE_EXPIRED":        "RELEASE",
	"DHCP4_DECLINE_LEASE":          "DECLINE",
	"DHCP4_CLIENT_HOSTNAME_DATA":   "NAME",
	"DHCP4_CLIENT_FQDN_DATA":       "NAME",
	"DHCP4_RESPONSE_HOSTNAME_DATA": "NAME",
	"DHCP4_RESPONSE_FQDN_DATA":     "NAME",
}

func parseKea(s string) *dhcpLine {
	g := keaLine.FindStringSubmatch(s)
	if g == nil {
		return nil
	}
	mt, ok := keaCodes[g[1]]
	mac := cleanMAC(g[2])
	if !ok || mac == "" {
		return nil
	}
	d := &dhcpLine{backend: "kea", msgType: mt, mac: mac}
	if mt == "NAME" {
		n := keaName.FindStringSubmatch(s)
		if n == nil {
			return nil
		}
		d.hostname = cleanHostname(n[1])
		if d.hostname == "" {
			return nil
		}
		return d
	}
	l := keaLease.FindStringSubmatch(s)
	if l == nil {
		return nil
	}
	if d.ip = cleanIP(l[1]); d.ip == "" {
		return nil
	}
	return d
}

// dnsmasq: [<tag> ]DHCPACK(<if>) <ip> <mac> [<hostname>]. A <tag> number appears with
// log-dhcp. DHCPNAK's last field is a reason rather than a name.
var dnsmasqLine = regexp.MustCompile(`^(?:\d+ )?DHCP(ACK|OFFER|REQUEST|RELEASE|DECLINE|NAK)\(([^)]*)\) (\S+) ([0-9A-Fa-f:]+)(?: (.*))?$`)

func parseDnsmasq(s string) *dhcpLine {
	g := dnsmasqLine.FindStringSubmatch(s)
	if g == nil {
		return nil
	}
	ip, mac := cleanIP(g[3]), cleanMAC(g[4])
	if ip == "" || mac == "" {
		return nil
	}
	d := &dhcpLine{backend: "dnsmasq", msgType: g[1], ip: ip, mac: mac, iface: cleanIface(g[2])}
	if g[1] == "ACK" {
		d.hostname = cleanHostname(g[5])
	}
	return d
}

func cleanIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// cleanMAC returns a 6-octet MAC in lower case with colons, or "".
func cleanMAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

func cleanIface(s string) string { return truncate(strings.TrimSpace(s), 32) }

// cleanHostname trims a client-supplied name. It is whatever the device claims, so it
// stays short and printable; ISC's "(none)"-style placeholders count as no name.
func cleanHostname(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" || s == "*" || s == "-" {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
