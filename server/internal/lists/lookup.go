package lists

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
)

var _ enrich.Lookup = (*Service)(nil)

// Domain answers from the lists. The registrable domain needs no download: the public suffix
// list is built into the program.
func (s *Service) Domain(name string) enrich.DomainInfo {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return enrich.DomainInfo{}
	}
	var info enrich.DomainInfo
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err == nil {
		info.Registered = reg
	}
	if t := s.tables.ranks.Load(); t != nil {
		if r, ok := t.get(name); ok {
			info.Rank = int(r)
		} else if reg != "" && reg != name {
			if r, ok := t.get(reg); ok {
				info.Rank = int(r)
			}
		}
	}
	if t := s.tables.categories.Load(); t != nil {
		// The domain itself, then each parent down to the registrable domain.
		for d := name; d != ""; {
			if c, ok := t.get(d); ok && int(c) < len(ut1Categories) {
				info.Category = ut1Categories[c].label
				break
			}
			if d == reg || reg == "" {
				break
			}
			_, parent, found := strings.Cut(d, ".")
			if !found {
				break
			}
			d = parent
		}
	}
	if t := s.tables.newDomains.Load(); t != nil && reg != "" {
		_, info.NewlyRegistered = t.get(reg)
	}
	return info
}

// IP answers from the IP network list.
func (s *Service) IP(ip string) enrich.IPInfo {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return enrich.IPInfo{}
	}
	t := s.tables.asn.Load()
	e, ok := t.find(addr)
	if !ok {
		return enrich.IPInfo{}
	}
	info := enrich.IPInfo{ASN: int(e.asn), ASName: t.name(e)}
	if e.cc != [2]byte{} {
		info.Country = string(e.cc[:])
	}
	return info
}

// MAC answers from the vendor list. A locally administered address, which phones use for
// privacy, has no vendor to find.
func (s *Service) MAC(mac string) enrich.MACInfo {
	first, ok := macPrefix(mac)
	if !ok {
		return enrich.MACInfo{}
	}
	var info enrich.MACInfo
	if first>>16&0x02 != 0 {
		info.Randomized = true
		return info
	}
	if v, ok := s.tables.oui.Load().get(first); ok {
		info.Vendor = v
	}
	return info
}

// macPrefix reads the first three bytes of a MAC address, in any common format.
func macPrefix(mac string) (uint32, bool) {
	var p uint32
	digits := 0
	for i := 0; i < len(mac); i++ {
		c := mac[i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		case c == ':' || c == '-' || c == '.':
			continue
		default:
			return 0, false
		}
		if digits < 6 {
			p = p<<4 | uint32(d)
		}
		digits++
	}
	return p, digits == 12
}
