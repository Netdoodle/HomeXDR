// Package netscope decides which addresses belong to the home network. The flow receiver,
// the device inventory and the behaviour detectors all use it, so they agree on what
// counts as a device and what counts as the internet.
package netscope

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10") // Tailscale and carrier NAT
	bridgeRange = netip.MustParsePrefix("172.16.0.0/12") // Docker's default bridge networks
)

// IsInternal reports addresses that are not on the public internet: private ranges,
// unique-local and link-local IPv6, loopback, and the shared range Tailscale uses.
func IsInternal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || cgnat.Contains(a)
}

// IsPublic reports a routable unicast address on the internet.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || IsInternal(a) {
		return false
	}
	return a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Direction infers a flow's direction from its addresses: outbound leaves the home
// network, inbound enters it, internal stays inside and external touches neither side.
func Direction(src, dst netip.Addr) string {
	srcIn, dstIn := !IsPublic(src), !IsPublic(dst)
	switch {
	case srcIn && dstIn:
		return event.DirectionInternal
	case srcIn:
		return event.DirectionOutbound
	case dstIn:
		return event.DirectionInbound
	}
	return event.DirectionExternal
}

// Config is what the owner can set about the home network.
type Config struct {
	// Subnets are the home subnets. Empty means automatic: every private IPv4 address
	// outside 172.16.0.0/12, which is where container bridges live.
	Subnets []netip.Prefix
	// Exclude is never part of the home network, whatever Subnets says.
	Exclude []netip.Prefix
	// Firewall lists the firewall's own addresses.
	Firewall []netip.Addr
}

// ParseConfig reads subnets, exclusions and firewall addresses as text.
func ParseConfig(subnets, exclude, firewall []string) (Config, error) {
	var c Config
	var err error
	if c.Subnets, err = parsePrefixes(subnets); err != nil {
		return c, err
	}
	if c.Exclude, err = parsePrefixes(exclude); err != nil {
		return c, err
	}
	for _, s := range firewall {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return c, fmt.Errorf("%q is not an IP address", s)
		}
		c.Firewall = append(c.Firewall, a.Unmap())
	}
	return c, nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%q is not a subnet such as 192.168.20.0/24", s)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Scope is an immutable view of the home network.
type Scope struct {
	cfg      Config
	firewall map[netip.Addr]bool
	// gatewayOctets are the last octets of the firewall's IPv4 addresses per /16: a firewall
	// on 192.168.20.1 is taken to be 192.168.10.1 on the next VLAN as well.
	gatewayOctets map[[3]byte]bool
}

// New builds a scope. observed adds firewall addresses learned from its logs.
func New(cfg Config, observed []netip.Addr) *Scope {
	s := &Scope{cfg: cfg, firewall: map[netip.Addr]bool{}, gatewayOctets: map[[3]byte]bool{}}
	for _, a := range cfg.Firewall {
		s.firewall[a.Unmap()] = true
	}
	for _, a := range observed {
		a = a.Unmap()
		s.firewall[a] = true
		if a.Is4() && a.IsPrivate() {
			b := a.As4()
			s.gatewayOctets[[3]byte{b[0], b[1], b[3]}] = true
		}
	}
	return s
}

// IsFirewall reports the firewall's own addresses, configured or learned.
func (s *Scope) IsFirewall(a netip.Addr) bool {
	a = a.Unmap()
	if s.firewall[a] {
		return true
	}
	if a.Is4() && len(s.cfg.Subnets) == 0 {
		b := a.As4()
		return s.gatewayOctets[[3]byte{b[0], b[1], b[3]}]
	}
	return false
}

// Home reports whether an address can be a device on the home network. Multicast,
// broadcast, the firewall's own addresses and container bridges cannot.
func (s *Scope) Home(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range s.cfg.Exclude {
		if p.Contains(a) {
			return false
		}
	}
	if s.IsFirewall(a) {
		return false
	}
	if len(s.cfg.Subnets) > 0 {
		for _, p := range s.cfg.Subnets {
			if p.Contains(a) {
				return !isEdgeAddress(p, a)
			}
		}
		return false
	}
	if !a.Is4() || !a.IsPrivate() || bridgeRange.Contains(a) {
		return false
	}
	b := a.As4()
	return b[3] != 0 && b[3] != 255
}

// Public reports an address on the internet, other than the firewall's own.
func (s *Scope) Public(a netip.Addr) bool { return IsPublic(a) && !s.IsFirewall(a) }

// SubnetOf names the subnet a home address belongs to.
func (s *Scope) SubnetOf(a netip.Addr) string {
	a = a.Unmap()
	for _, p := range s.cfg.Subnets {
		if p.Contains(a) {
			return p.String()
		}
	}
	if a.Is4() {
		return netip.PrefixFrom(a, 24).Masked().String()
	}
	if p, err := a.Prefix(64); err == nil {
		return p.String()
	}
	return ""
}

// isEdgeAddress reports an IPv4 subnet's network and broadcast addresses.
func isEdgeAddress(p netip.Prefix, a netip.Addr) bool {
	if !a.Is4() || p.Bits() >= 31 {
		return false
	}
	if a == p.Masked().Addr() {
		return true
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return v|(1<<(32-p.Bits())-1) == v
}
