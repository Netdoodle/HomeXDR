package syslog

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

// CEF (ArcSight Common Event Format) and LEEF (IBM QRadar Log Event Extended Format) are
// the two formats most security products can send when they have no syslog format of
// their own:
//
//	CEF:0|Vendor|Product|1.0|100|Connection blocked|5|src=198.51.100.7 dst=192.168.1.10 spt=40000 dpt=22 proto=TCP act=blocked
//	LEEF:1.0|Vendor|Product|1.0|42|src=198.51.100.7<TAB>dst=192.168.1.10<TAB>srcPort=40000
//	LEEF:2.0|Vendor|Product|1.0|42|^|src=198.51.100.7^dst=192.168.1.10
//
// A line with source, destination and an allow/deny verdict is a firewall log and is
// decoded like the other firewalls (event.module:firewall). Anything else keeps its
// fields but stays a syslog event, dataset cef.<vendor> or leef.<vendor>.

// maxExtFields caps how many extension fields are kept in Data, so a hostile sender cannot
// make one row arbitrarily wide.
const maxExtFields = 64

// common holds the fields both formats share once their names are mapped.
type common struct {
	format                          string // cef or leef
	vendor, product, version, sigID string
	name, severity                  string
	ext                             map[string]string
	src, dst, proto, action, srcMAC string
	sport, dport                    int
	bytesIn, bytesOut               int64
	user, iface, msg, category, dir string
	ts                              time.Time
}

func matchCEF(m *Message) bool  { return strings.Contains(m.Raw, "CEF:") }
func matchLEEF(m *Message) bool { return strings.Contains(m.Raw, "LEEF:") }

func decodeCEF(m *Message) *event.Event {
	i := strings.Index(m.Raw, "CEF:")
	if i < 0 {
		return nil
	}
	h, rest, ok := splitHeader(m.Raw[i+4:], 7)
	if !ok {
		return nil
	}
	ext := parseCEFExt(rest)
	c := common{
		format: "cef", version: h[3], vendor: h[1], product: h[2], sigID: h[4], name: h[5], severity: h[6], ext: ext,
		src: firstNonEmpty(ext["src"], ext["c6a2"]), dst: firstNonEmpty(ext["dst"], ext["c6a3"]),
		sport: atoi(ext["spt"]), dport: atoi(ext["dpt"]), proto: ext["proto"],
		action: firstNonEmpty(ext["act"], ext["outcome"]), srcMAC: ext["smac"],
		bytesIn: atoi64(ext["in"]), bytesOut: atoi64(ext["out"]),
		user: firstNonEmpty(ext["suser"], ext["duser"]), iface: ext["deviceinboundinterface"],
		msg: ext["msg"], category: ext["cat"], ts: cefTime(ext["rt"]),
	}
	switch ext["devicedirection"] {
	case "0":
		c.dir = event.DirectionInbound
	case "1":
		c.dir = event.DirectionOutbound
	}
	return c.event(m)
}

func decodeLEEF(m *Message) *event.Event {
	i := strings.Index(m.Raw, "LEEF:")
	if i < 0 {
		return nil
	}
	s := m.Raw[i+5:]
	n := 5 // version, vendor, product, product version, event ID
	if strings.HasPrefix(s, "2.0|") {
		n = 6 // LEEF 2.0 adds the delimiter
	}
	h, rest, ok := splitHeader(s, n)
	if !ok {
		return nil
	}
	delim := "\t"
	if n == 6 {
		delim = leefDelim(h[5])
	}
	ext := map[string]string{}
	for _, kv := range strings.Split(rest, delim) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || len(ext) >= maxExtFields {
			continue
		}
		ext[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	c := common{
		format: "leef", version: h[3], vendor: h[1], product: h[2], sigID: h[4], name: h[4], ext: ext,
		src: ext["src"], dst: ext["dst"], sport: atoi(ext["srcport"]), dport: atoi(ext["dstport"]),
		proto: ext["proto"], action: firstNonEmpty(ext["action"], ext["act"]), srcMAC: ext["srcmac"],
		bytesIn: atoi64(ext["dstbytes"]), bytesOut: atoi64(ext["srcbytes"]), severity: ext["sev"],
		user: ext["usrname"], msg: firstNonEmpty(ext["msg"], ext["reason"]), category: ext["cat"],
		ts: cefTime(ext["devtime"]),
	}
	return c.event(m)
}

func (c *common) event(m *Message) *event.Event {
	src, err1 := netip.ParseAddr(c.src)
	dst, err2 := netip.ParseAddr(c.dst)
	tuple := err1 == nil && err2 == nil
	vendor := strings.ToLower(firstNonEmpty(c.vendor, "unknown"))
	var ev *event.Event
	if tuple && c.action != "" {
		ev = newFirewallEvent(m, fwRecord{
			Vendor: c.vendor, Product: c.product, Dataset: c.format + "." + vendor,
			RawAction: c.action, Denied: isDeniedAction(c.action), Direction: c.dir,
			Proto: c.proto, SrcIP: c.src, DstIP: c.dst, SrcPort: c.sport, DstPort: c.dport,
			SrcMAC: strings.ToLower(c.srcMAC), Bytes: c.bytesIn + c.bytesOut, Interface: c.iface,
			Rule: c.sigID,
		})
	}
	if ev == nil {
		ev = base(m, event.ModuleSyslog, c.format+"."+sanitizeDataset(vendor))
		ev.Event.Category = []string{event.CategoryHost}
		ev.Event.Type = []string{event.TypeInfo}
		ev.Observer = &event.Observer{Vendor: c.vendor, Product: c.product, Hostname: m.Hostname}
		ev.Data = map[string]any{}
		if tuple {
			ev.Event.Category = []string{event.CategoryNetwork}
			proto := protoName(c.proto)
			ev.Source = &event.Endpoint{IP: src.Unmap().String(), Port: c.sport, MAC: strings.ToLower(c.srcMAC)}
			ev.Destination = &event.Endpoint{IP: dst.Unmap().String(), Port: c.dport}
			dir := c.dir
			if dir == "" {
				dir = inferDirection(src, dst)
			}
			ev.Network = &event.Network{Direction: dir, Transport: proto, Bytes: c.bytesIn + c.bytesOut,
				CommunityID: communityid.ComputeStrings(ev.Source.IP, ev.Destination.IP, proto, c.sport, c.dport)}
		} else if err1 == nil {
			ev.Source = &event.Endpoint{IP: src.Unmap().String(), Port: c.sport}
		}
		if c.action != "" {
			ev.Event.Action = c.action
		}
	}
	ev.Event.Code = c.sigID
	ev.Event.Severity = cefSeverity(c.severity)
	ev.Event.Original = truncate(m.Raw, 16<<10)
	if c.user != "" {
		ev.User = &event.User{Name: c.user}
	}
	if ev.Observer != nil && ev.Observer.Hostname == "" {
		ev.Observer.Hostname = c.ext["dvchost"]
	}
	if !c.ts.IsZero() {
		ev.Timestamp = c.ts
	}
	ev.Data["format"] = c.format
	ev.Data["signature_id"] = c.sigID
	if c.category != "" {
		ev.Data["category"] = c.category
	}
	ext := map[string]string{}
	for k, v := range c.ext {
		if len(ext) >= maxExtFields {
			break
		}
		ext[k] = truncate(v, 1024)
	}
	ev.Data["fields"] = ext
	msg := firstNonEmpty(c.name, c.msg)
	if c.msg != "" && c.msg != msg {
		msg += ": " + c.msg
	}
	switch {
	case ev.Event.Module != event.ModuleFirewall:
		ev.Message = truncate(msg, 4096)
	case msg != "":
		ev.Message = truncate(msg, 4096) + " (" + ev.Message + ")"
	}
	return ev
}

// splitHeader splits the first n pipe-separated header fields (version included). A
// backslash escapes a pipe or a backslash inside a field.
func splitHeader(s string, n int) (h []string, rest string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\'):
			b.WriteByte(s[i+1])
			i++
		case ch == '|':
			h = append(h, b.String())
			b.Reset()
			if len(h) == n {
				return h, s[i+1:], true
			}
		default:
			b.WriteByte(ch)
		}
	}
	return nil, "", false
}

// parseCEFExt reads CEF's extension: key=value pairs where a value runs until the next
// " key=" and may hold spaces. "\=" and "\\" are escapes, "\n" a newline. Keys are lower-cased.
func parseCEFExt(s string) map[string]string {
	type pos struct {
		key    string
		ks, vs int
	}
	var keys []pos
	for i := 0; i < len(s); i++ {
		if s[i] != '=' || (i > 0 && s[i-1] == '\\') {
			continue
		}
		j := i
		for j > 0 && isKeyChar(s[j-1]) {
			j--
		}
		if j == i || (j > 0 && s[j-1] != ' ') {
			continue // "=" inside a value
		}
		keys = append(keys, pos{s[j:i], j, i + 1})
	}
	out := map[string]string{}
	for k, p := range keys {
		end := len(s)
		if k+1 < len(keys) {
			end = keys[k+1].ks
		}
		v := strings.TrimRight(s[p.vs:end], " ")
		v = strings.NewReplacer(`\=`, "=", `\\`, `\`, `\n`, "\n", `\r`, "").Replace(v)
		if len(out) < maxExtFields {
			out[strings.ToLower(p.key)] = v
		}
	}
	return out
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// leefDelim reads LEEF 2.0's delimiter field: one character, or its hex code as x5E or 0x5E.
func leefDelim(s string) string {
	if t := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(s), "0"), "x"); len(s) > 1 && t != "" {
		if n, err := strconv.ParseUint(t, 16, 8); err == nil && n > 0 {
			return string(rune(n))
		}
	}
	if s == "" {
		return "\t"
	}
	return s[:1]
}

// cefTime reads epoch milliseconds or the "MMM dd yyyy HH:mm:ss" form both formats allow.
func cefTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 1e11 {
		return time.UnixMilli(n).UTC()
	}
	for _, f := range []string{"Jan 02 2006 15:04:05", "Jan 2 2006 15:04:05", "Jan 02 2006 15:04:05.000", time.RFC3339} {
		if t, err := time.ParseInLocation(f, s, time.Local); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// cefSeverity maps 0-10 or Low/Medium/High/Very-High to HomeXDR's 0-100.
func cefSeverity(s string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 && n <= 10 {
		return n * 10
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return 20
	case "medium":
		return 50
	case "high":
		return 75
	case "very-high", "very high", "critical":
		return 95
	}
	return 0
}
