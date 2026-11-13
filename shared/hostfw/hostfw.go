// Package hostfw validates host firewall block rules (api.CmdFirewall). The server checks
// every address when someone adds it and again before sending a rule set; the agent
// checks the whole set once more before touching the firewall, with its own idea of the
// server's addresses, so a bad or hostile rule set cannot cut it off from HomeXDR.
package hostfw

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
)

// reserved ranges are never blocked: blocking them breaks the host itself (loopback,
// link-local, multicast) or means nothing (unspecified, broadcast).
var reserved = []struct {
	p    netip.Prefix
	what string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "the unspecified network 0.0.0.0/8"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback (127.0.0.0/8)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local (169.254.0.0/16)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast (224.0.0.0/4)"},
	{netip.MustParsePrefix("255.255.255.255/32"), "broadcast"},
	{netip.MustParsePrefix("::/128"), "the unspecified address ::"},
	{netip.MustParsePrefix("::1/128"), "loopback (::1)"},
	{netip.MustParsePrefix("fe80::/10"), "link-local (fe80::/10)"},
	{netip.MustParsePrefix("ff00::/8"), "multicast (ff00::/8)"},
}

// ParseCIDR reads an IP address or CIDR (IPv4 or IPv6) and returns it as a masked prefix,
// or says why it cannot be blocked: too broad, a reserved range, or not an address.
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return p, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return p, fmt.Errorf("%s is too broad", s)
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if p.Addr().Is4() && p.Bits() < api.FirewallMinPrefixV4 {
		return p, fmt.Errorf("%s is too broad: IPv4 blocks are /%d or narrower", s, api.FirewallMinPrefixV4)
	}
	if p.Addr().Is6() && p.Bits() < api.FirewallMinPrefixV6 {
		return p, fmt.Errorf("%s is too broad: IPv6 blocks are /%d or narrower", s, api.FirewallMinPrefixV6)
	}
	for _, r := range reserved {
		if p.Overlaps(r.p) {
			return p, fmt.Errorf("%s covers %s, which is never blocked", s, r.what)
		}
	}
	return p, nil
}

// Format writes a prefix the way people write it: a single address without its /32 or
// /128, a network as a CIDR.
func Format(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// CheckProtected refuses a prefix that covers one of the protected addresses (the
// HomeXDR server's own addresses).
func CheckProtected(p netip.Prefix, protected []netip.Addr) error {
	for _, a := range protected {
		if a = a.Unmap().WithZone(""); a.IsValid() && p.Contains(a) {
			return fmt.Errorf("%s covers %s, an address of the HomeXDR server: blocking it would cut hosts off from HomeXDR", Format(p), a)
		}
	}
	return nil
}

// CheckDirection validates a rule direction.
func CheckDirection(d string) error {
	switch d {
	case "", api.FirewallBoth, api.FirewallIn, api.FirewallOut:
		return nil
	}
	return fmt.Errorf("direction %q is not both, in or out", d)
}

var versionRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// CheckVersion validates a rule set version; it is used in rule names on the host.
func CheckVersion(v string) error {
	if !versionRe.MatchString(v) {
		return fmt.Errorf("version %q must be 1 to 64 letters, digits, dots, dashes or underscores", v)
	}
	return nil
}

// Set is a validated rule set: the networks blocked inbound and outbound, with duplicates
// and networks inside other networks removed, IPv4 before IPv6, sorted.
type Set struct {
	In  []netip.Prefix
	Out []netip.Prefix
}

// Normalize validates a rule set (every address, the count, the directions) and refuses
// it if any rule covers a protected address.
func Normalize(rules []api.FirewallRule, protected []netip.Addr) (Set, error) {
	if len(rules) > api.FirewallMaxRules {
		return Set{}, fmt.Errorf("%d rules: at most %d addresses can be blocked on a host", len(rules), api.FirewallMaxRules)
	}
	var in, out []netip.Prefix
	for _, r := range rules {
		p, err := ParseCIDR(r.CIDR)
		if err != nil {
			return Set{}, err
		}
		if err := CheckDirection(r.Direction); err != nil {
			return Set{}, err
		}
		if err := CheckProtected(p, protected); err != nil {
			return Set{}, err
		}
		if r.Direction != api.FirewallOut {
			in = append(in, p)
		}
		if r.Direction != api.FirewallIn {
			out = append(out, p)
		}
	}
	return Set{In: Merge(in), Out: Merge(out)}, nil
}

// Merge removes duplicates and prefixes contained in another prefix, so no two remain
// overlapping (nftables interval sets refuse overlaps), and sorts the rest.
func Merge(ps []netip.Prefix) []netip.Prefix {
	sorted := slices.Clone(ps)
	// Broadest first, so a network is kept before the addresses inside it.
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(a.Bits(), b.Bits()), a.Addr().Compare(b.Addr()))
	})
	var out []netip.Prefix
	for _, p := range sorted {
		covered := false
		for _, k := range out {
			if k.Addr().BitLen() == p.Addr().BitLen() && k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, comparePrefix)
	return out
}

func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// Empty reports whether nothing is blocked.
func (s Set) Empty() bool { return len(s.In) == 0 && len(s.Out) == 0 }

// Len counts the distinct networks blocked in either direction.
func (s Set) Len() int {
	seen := map[netip.Prefix]bool{}
	for _, p := range slices.Concat(s.In, s.Out) {
		seen[p] = true
	}
	return len(seen)
}

// Split returns the IPv4 and IPv6 prefixes of a list.
func Split(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}
