//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"golang.org/x/sys/windows"
)

// Host isolation on Windows: persistent Windows Filtering Platform filters in HomeXDR's own
// sublayer, weighted above Windows Firewall's. Permits (loopback, the server, DNS to the
// configured resolvers, DHCP, the allow list) are "hard" permits that a firewall rule in a
// lower sublayer cannot block; everything else is blocked at the ALE connect and
// receive/accept layers, which Windows Firewall rules cannot permit back. ALE
// re-authorises existing connections when filters change, so connections opened before
// isolation to anything not allowed stop working.
//
// The filters are persistent: they survive an agent restart and a reboot until the agent
// releases the host. The core still re-applies them on start while its saved state says
// the host is isolated, and removes leftovers when it says not.

// wfpMaxFilters caps the filters HomeXDR adds (and how far release looks for them).
const wfpMaxFilters = 2048

// wfpRule is one isolation filter: a permit or block on one ALE layer.
type wfpRule struct {
	name       string
	layer      windows.GUID
	permit     bool
	loopback   bool
	remote     netip.Prefix
	proto      uint8
	remotePort uint16
	localPort  uint16
}

const (
	protoTCP = 6
	protoUDP = 17
)

// isolationRules renders the isolation filters. Permits come first; the four block-all
// filters are last.
func isolationRules(iso platform.Isolation, dns []netip.Addr) ([]wfpRule, error) {
	if len(iso.ServerIPs) == 0 || iso.ServerPort <= 0 || iso.ServerPort > 65535 {
		return nil, errors.New("isolation needs the server address")
	}
	type layers struct{ connect, accept windows.GUID }
	v4 := layers{layerConnectV4, layerAcceptV4}
	v6 := layers{layerConnectV6, layerAcceptV6}
	fam := func(a netip.Addr) layers {
		if a.Unmap().Is4() {
			return v4
		}
		return v6
	}
	host := func(a netip.Addr) netip.Prefix {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen())
	}
	var out []wfpRule
	for _, l := range []layers{v4, v6} {
		out = append(out,
			wfpRule{name: "loopback out", layer: l.connect, permit: true, loopback: true},
			wfpRule{name: "loopback in", layer: l.accept, permit: true, loopback: true})
	}
	for _, s := range iso.ServerIPs {
		out = append(out, wfpRule{name: "HomeXDR server " + s.Unmap().String(), layer: fam(s).connect, permit: true,
			remote: host(s), proto: protoTCP, remotePort: uint16(iso.ServerPort)})
	}
	for _, d := range dns {
		for _, p := range []uint8{protoUDP, protoTCP} {
			out = append(out, wfpRule{name: "DNS " + d.Unmap().String(), layer: fam(d).connect, permit: true,
				remote: host(d), proto: p, remotePort: 53})
		}
	}
	out = append(out,
		wfpRule{name: "DHCP out", layer: v4.connect, permit: true, proto: protoUDP, localPort: 68, remotePort: 67},
		wfpRule{name: "DHCP in", layer: v4.accept, permit: true, proto: protoUDP, localPort: 68, remotePort: 67},
		wfpRule{name: "DHCPv6 out", layer: v6.connect, permit: true, proto: protoUDP, localPort: 546, remotePort: 547},
		wfpRule{name: "DHCPv6 in", layer: v6.accept, permit: true, proto: protoUDP, localPort: 546, remotePort: 547})
	for _, p := range iso.Allow {
		if a := p.Addr(); a.Is4In6() {
			p = netip.PrefixFrom(a.Unmap(), max(p.Bits()-96, 0))
		}
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		l := fam(p.Addr())
		out = append(out,
			wfpRule{name: "allow " + p.String() + " out", layer: l.connect, permit: true, remote: p},
			wfpRule{name: "allow " + p.String() + " in", layer: l.accept, permit: true, remote: p})
	}
	out = append(out,
		wfpRule{name: "block IPv4 out", layer: v4.connect},
		wfpRule{name: "block IPv4 in", layer: v4.accept},
		wfpRule{name: "block IPv6 out", layer: v6.connect},
		wfpRule{name: "block IPv6 in", layer: v6.accept})
	if len(out) > wfpMaxFilters {
		return nil, fmt.Errorf("isolation needs %d filters, more than %d: shorten the allow list", len(out), wfpMaxFilters)
	}
	return out, nil
}

// Isolate replaces HomeXDR's isolation filters in one transaction.
func (r responder) Isolate(_ context.Context, iso platform.Isolation) error {
	rules, err := isolationRules(iso, dnsServers())
	if err != nil {
		return err
	}
	e, err := openWFP()
	if err != nil {
		return err
	}
	defer e.close()
	return e.tx(func() error {
		if err := e.deleteAll(); err != nil {
			return err
		}
		if err := e.addProviderAndSubLayer(); err != nil {
			return err
		}
		for i, f := range rules {
			if err := e.addFilter(i, f); err != nil {
				return err
			}
		}
		return nil
	})
}

// Release removes the isolation filters.
func (r responder) Release(context.Context) error {
	e, err := openWFP()
	if err != nil {
		return err
	}
	defer e.close()
	return e.tx(e.deleteAll)
}

// Isolated reports whether HomeXDR's isolation sublayer exists.
func (r responder) Isolated() bool {
	e, err := openWFP()
	if err != nil {
		return false
	}
	defer e.close()
	return e.subLayerExists()
}

// dnsServers returns the DNS servers of the adapters that are up (not loopback ones).
func dnsServers() []netip.Addr {
	size := uint32(16 << 10)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	var out []netip.Addr
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			ip, ok := netip.AddrFromSlice(d.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap().WithZone("")
			if ip.IsLoopback() || !ip.IsValid() || slices.Contains(out, ip) {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}
