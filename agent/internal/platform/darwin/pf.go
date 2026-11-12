package darwin

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// pfAnchor holds the isolation rules. The stock /etc/pf.conf evaluates every anchor
// under com.apple/ (`anchor "com.apple/*"`), so rules loaded here take effect without
// editing pf.conf; "000." sorts it before Apple's own sub-anchors.
const pfAnchor = "com.apple/000.HomeXDR"

// pfRules renders the isolation ruleset: loopback, DHCP, IPv6 neighbour discovery, DNS
// to the resolvers, the server and the allow list pass; everything else is dropped.
// pf keeps state for pass rules, so replies to allowed traffic come back in.
func pfRules(iso platform.Isolation, resolvers []netip.Addr) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# HomeXDR network isolation. Removed when the host is released.")
	w("pass quick on lo0 all")
	w("pass out quick inet proto udp from any port 68 to any port 67")
	w("pass in quick inet proto udp from any port 67 to any port 68")
	w("pass out quick inet6 proto udp from any port 546 to any port 547")
	w("pass in quick inet6 proto udp from any port 547 to any port 546")
	w("pass quick inet6 proto ipv6-icmp all icmp6-type { neighbrsol, neighbradv, routersol, routeradv }")
	for _, r := range resolvers {
		w("pass out quick %s proto { udp, tcp } from any to %s port 53", family(r), r)
	}
	port := iso.ServerPort
	if port == 0 {
		port = 443
	}
	for _, s := range iso.ServerIPs {
		w("pass out quick %s proto tcp from any to %s port %d", family(s), s.Unmap(), port)
	}
	for _, p := range iso.Allow {
		p = p.Masked()
		w("pass out quick %s from any to %s", family(p.Addr()), p)
		w("pass in quick %s from %s to any", family(p.Addr()), p)
	}
	w("block drop quick all")
	return b.String()
}

func family(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "inet"
	}
	return "inet6"
}

// pfMainHasAppleAnchor reports whether the main ruleset (`pfctl -s rules`) evaluates the
// com.apple sub-anchors, without which the isolation rules would never be consulted.
func pfMainHasAppleAnchor(rules []byte) bool {
	for _, line := range strings.Split(string(rules), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), `anchor "com.apple/*"`) {
			return true
		}
	}
	return false
}

// pfToken extracts the reference token `pfctl -E` prints ("Token : 1234").
func pfToken(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Token" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
