//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// Host isolation: a dedicated nftables table (inet homexdr), or dedicated iptables chains
// when nft is not installed. Both allow loopback, the server's IPs and port, DNS to the
// configured resolvers, DHCP (v4 and v6), IPv6 neighbour discovery and the allow list;
// everything else is dropped, including forwarded traffic (containers, VMs).
//
// Inbound, established/related packets are accepted so replies to allowed outbound
// traffic arrive. Outbound there is no blanket established rule, so connections that
// existed before isolation (to anything not allowed) stop working immediately.
//
// The rules live only in the kernel. They do not survive a reboot on their own; the agent
// re-applies them on start while its saved state says the host is isolated.

const nftTable = "homexdr"

type firewall interface {
	name() string
	apply(ctx context.Context, iso platform.Isolation, dns []netip.Addr) error
	release(ctx context.Context) error
	active(ctx context.Context) bool
}

func availableFirewalls() []firewall {
	var out []firewall
	if p, err := exec.LookPath("nft"); err == nil {
		out = append(out, nftFirewall{bin: p})
	}
	if p, err := exec.LookPath("iptables"); err == nil {
		ip6, _ := exec.LookPath("ip6tables")
		out = append(out, iptFirewall{v4: p, v6: ip6})
	}
	return out
}

// parseResolvConf returns the nameserver addresses of a resolv.conf.
func parseResolvConf(b []byte) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			// Strip an IPv6 zone ("fe80::1%eth0") for the firewall rule.
			s, _, _ := strings.Cut(f[1], "%")
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

// resolvers returns the DNS servers to keep reachable. With systemd-resolved,
// /etc/resolv.conf points at the local stub (covered by the loopback rule) and the real
// upstream servers are in /run/systemd/resolve/resolv.conf.
func resolvers() []netip.Addr {
	var out []netip.Addr
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		if b, err := os.ReadFile(f); err == nil {
			for _, a := range parseResolvConf(b) {
				if !a.IsLoopback() && !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func splitAddrs(as []netip.Addr) (v4, v6 []string) {
	for _, a := range as {
		a = a.Unmap()
		if a.Is4() {
			v4 = append(v4, a.String())
		} else if a.IsValid() {
			v6 = append(v6, a.String())
		}
	}
	return
}

func splitPrefixes(ps []netip.Prefix) (v4, v6 []string) {
	for _, p := range ps {
		p = p.Masked()
		if p.Addr().Is4() || p.Addr().Is4In6() {
			v4 = append(v4, netip.PrefixFrom(p.Addr().Unmap(), min(p.Bits(), 32)).String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	return
}

func nftSet(items []string) string { return "{ " + strings.Join(items, ", ") + " }" }

// nftRuleset renders the isolation table. It begins by creating and deleting the table so
// the whole script is one atomic, idempotent replace.
func nftRuleset(iso platform.Isolation, dns []netip.Addr) string {
	srv4, srv6 := splitAddrs(iso.ServerIPs)
	dns4, dns6 := splitAddrs(dns)
	allow4, allow6 := splitPrefixes(iso.Allow)
	port := strconv.Itoa(iso.ServerPort)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("table inet %s", nftTable)
	w("delete table inet %s", nftTable)
	w("table inet %s {", nftTable)
	w("\tchain input {")
	w("\t\ttype filter hook input priority -10; policy drop;")
	w("\t\tiif \"lo\" accept")
	w("\t\tct state established,related accept")
	w("\t\tudp sport 67 udp dport 68 accept")
	w("\t\tudp sport 547 udp dport 546 accept")
	w("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-redirect } accept")
	if len(allow4) > 0 {
		w("\t\tip saddr %s accept", nftSet(allow4))
	}
	if len(allow6) > 0 {
		w("\t\tip6 saddr %s accept", nftSet(allow6))
	}
	w("\t}")
	w("\tchain output {")
	w("\t\ttype filter hook output priority -10; policy drop;")
	w("\t\toif \"lo\" accept")
	if len(srv4) > 0 {
		w("\t\tip daddr %s tcp dport %s accept", nftSet(srv4), port)
	}
	if len(srv6) > 0 {
		w("\t\tip6 daddr %s tcp dport %s accept", nftSet(srv6), port)
	}
	if len(dns4) > 0 {
		w("\t\tip daddr %s meta l4proto { tcp, udp } th dport 53 accept", nftSet(dns4))
	}
	if len(dns6) > 0 {
		w("\t\tip6 daddr %s meta l4proto { tcp, udp } th dport 53 accept", nftSet(dns6))
	}
	w("\t\tudp sport 68 udp dport 67 accept")
	w("\t\tudp sport 546 udp dport 547 accept")
	w("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	if len(allow4) > 0 {
		w("\t\tip daddr %s accept", nftSet(allow4))
	}
	if len(allow6) > 0 {
		w("\t\tip6 daddr %s accept", nftSet(allow6))
	}
	w("\t}")
	w("\tchain forward {")
	w("\t\ttype filter hook forward priority -10; policy drop;")
	w("\t}")
	w("}")
	return b.String()
}

type nftFirewall struct{ bin string }

func (nftFirewall) name() string { return "nftables" }

func (f nftFirewall) apply(ctx context.Context, iso platform.Isolation, dns []netip.Addr) error {
	if len(iso.ServerIPs) == 0 || iso.ServerPort == 0 {
		return fmt.Errorf("isolation needs the server address")
	}
	cmd := exec.CommandContext(ctx, f.bin, "-f", "-")
	cmd.Stdin = strings.NewReader(nftRuleset(iso, dns))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f nftFirewall) release(ctx context.Context) error {
	if !f.active(ctx) {
		return nil
	}
	out, err := exec.CommandContext(ctx, f.bin, "delete", "table", "inet", nftTable).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft delete table: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f nftFirewall) active(ctx context.Context) bool {
	return exec.CommandContext(ctx, f.bin, "list", "table", "inet", nftTable).Run() == nil
}

// iptables fallback: chains HOMEXDR-IN/OUT/FWD jumped to from the top of the built-in
// chains.
const (
	iptIn  = "HOMEXDR-IN"
	iptOut = "HOMEXDR-OUT"
	iptFwd = "HOMEXDR-FWD"
)

type iptFirewall struct{ v4, v6 string }

func (iptFirewall) name() string { return "iptables" }

// iptRules returns the chain contents for one address family.
func iptRules(v6 bool, iso platform.Isolation, dns []netip.Addr) [][]string {
	srv4, srv6 := splitAddrs(iso.ServerIPs)
	dns4, dns6 := splitAddrs(dns)
	allow4, allow6 := splitPrefixes(iso.Allow)
	srv, dnsA, allow := srv4, dns4, allow4
	dhcpIn, dhcpOut := []string{"--sport", "67", "--dport", "68"}, []string{"--sport", "68", "--dport", "67"}
	if v6 {
		srv, dnsA, allow = srv6, dns6, allow6
		dhcpIn, dhcpOut = []string{"--sport", "547", "--dport", "546"}, []string{"--sport", "546", "--dport", "547"}
	}
	port := strconv.Itoa(iso.ServerPort)
	var r [][]string
	add := func(args ...string) { r = append(r, args) }
	add("-A", iptIn, "-i", "lo", "-j", "ACCEPT")
	add("-A", iptIn, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	add(append(append([]string{"-A", iptIn, "-p", "udp"}, dhcpIn...), "-j", "ACCEPT")...)
	if v6 {
		for _, t := range []string{"neighbour-solicitation", "neighbour-advertisement", "router-advertisement", "redirect"} {
			add("-A", iptIn, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "ACCEPT")
		}
	}
	for _, a := range allow {
		add("-A", iptIn, "-s", a, "-j", "ACCEPT")
	}
	add("-A", iptIn, "-j", "DROP")

	add("-A", iptOut, "-o", "lo", "-j", "ACCEPT")
	for _, s := range srv {
		add("-A", iptOut, "-d", s, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
	}
	for _, d := range dnsA {
		add("-A", iptOut, "-d", d, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
		add("-A", iptOut, "-d", d, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	}
	add(append(append([]string{"-A", iptOut, "-p", "udp"}, dhcpOut...), "-j", "ACCEPT")...)
	if v6 {
		for _, t := range []string{"neighbour-solicitation", "neighbour-advertisement", "router-solicitation"} {
			add("-A", iptOut, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "ACCEPT")
		}
	}
	for _, a := range allow {
		add("-A", iptOut, "-d", a, "-j", "ACCEPT")
	}
	add("-A", iptOut, "-j", "DROP")
	add("-A", iptFwd, "-j", "DROP")
	return r
}

func run(ctx context.Context, bin string, args ...string) error {
	out, err := exec.CommandContext(ctx, bin, append([]string{"-w"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

var iptJumps = [][2]string{{"INPUT", iptIn}, {"OUTPUT", iptOut}, {"FORWARD", iptFwd}}

func (f iptFirewall) apply(ctx context.Context, iso platform.Isolation, dns []netip.Addr) error {
	if len(iso.ServerIPs) == 0 || iso.ServerPort == 0 {
		return fmt.Errorf("isolation needs the server address")
	}
	for _, fam := range []struct {
		bin string
		v6  bool
	}{{f.v4, false}, {f.v6, true}} {
		if fam.bin == "" {
			continue
		}
		// Fill the chains completely before (re)inserting the jumps.
		for _, c := range []string{iptIn, iptOut, iptFwd} {
			_ = run(ctx, fam.bin, "-N", c) // exists already: fine
			if err := run(ctx, fam.bin, "-F", c); err != nil {
				return err
			}
		}
		for _, r := range iptRules(fam.v6, iso, dns) {
			if err := run(ctx, fam.bin, r...); err != nil {
				return err
			}
		}
		for _, j := range iptJumps {
			if run(ctx, fam.bin, "-C", j[0], "-j", j[1]) != nil {
				if err := run(ctx, fam.bin, "-I", j[0], "1", "-j", j[1]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (f iptFirewall) release(ctx context.Context) error {
	for _, bin := range []string{f.v4, f.v6} {
		if bin == "" {
			continue
		}
		for _, j := range iptJumps {
			for i := 0; i < 10 && run(ctx, bin, "-C", j[0], "-j", j[1]) == nil; i++ {
				_ = run(ctx, bin, "-D", j[0], "-j", j[1])
			}
		}
		for _, c := range []string{iptIn, iptOut, iptFwd} {
			if run(ctx, bin, "-F", c) == nil {
				_ = run(ctx, bin, "-X", c)
			}
		}
	}
	return nil
}

func (f iptFirewall) active(ctx context.Context) bool {
	return run(ctx, f.v4, "-C", "INPUT", "-j", iptIn) == nil
}
