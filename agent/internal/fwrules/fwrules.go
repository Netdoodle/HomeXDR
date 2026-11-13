// Package fwrules renders HomeXDR's host firewall block rules (api.CmdFirewall) for each
// OS: an nftables table for Linux, a PowerShell script for Windows Firewall and a pf
// anchor for macOS. It has no OS dependencies, so the rendering is tested everywhere; the
// platform packages run the result. Input is always a hostfw.Set, whose addresses were
// parsed with net/netip, so the output only ever holds digits, dots, colons and slashes
// from the addresses, plus the validated version.
//
// Directions follow connections, as both Windows Firewall and pf do: "in" blocks
// connections the address opens to the host, "out" blocks connections the host opens to
// the address, and an address blocked both ways is dropped outright.
package fwrules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// Names of HomeXDR's own firewall objects. None is shared with host isolation.
const (
	// NftTable is the nftables table (family inet), separate from isolation's inet homexdr.
	NftTable = "homexdr_block"
	// PfAnchor sorts after isolation's com.apple/000.HomeXDR; the stock pf.conf
	// evaluates every com.apple/* anchor.
	PfAnchor = "com.apple/001.HomeXDR-block"
	// WindowsGroup is the Windows Firewall rule group.
	WindowsGroup = api.FirewallWindowsGroup
	// WindowsBatch is the most addresses in one Windows Firewall rule. RemoteAddress
	// takes a list; a few long rules load faster than hundreds of short ones and stay
	// readable in the Windows Firewall console.
	WindowsBatch = 100
)

// Parts splits a set into addresses blocked both ways, inbound only and outbound only.
type Parts struct {
	Both, In, Out []netip.Prefix
}

// Split works out the parts of a set.
func Split(s hostfw.Set) Parts {
	var p Parts
	for _, x := range s.In {
		if slices.Contains(s.Out, x) {
			p.Both = append(p.Both, x)
		} else {
			p.In = append(p.In, x)
		}
	}
	for _, x := range s.Out {
		if !slices.Contains(s.In, x) {
			p.Out = append(p.Out, x)
		}
	}
	return p
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = hostfw.Format(p)
	}
	return out
}

// --- nftables (Linux) ---

// NftRuleset renders the table. Like isolation's ruleset it starts by creating and
// deleting the table, so `nft -f` replaces it in one atomic transaction. An empty set
// renders only the deletion.
func NftRuleset(s hostfw.Set) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("table inet %s", NftTable)
	w("delete table inet %s", NftTable)
	if s.Empty() {
		return b.String()
	}
	p := Split(s)
	w("table inet %s {", NftTable)
	sets := []struct {
		name string
		ps   []netip.Prefix
	}{{"both", p.Both}, {"in", p.In}, {"out", p.Out}}
	for _, st := range sets {
		v4, v6 := hostfw.Split(st.ps)
		for _, fam := range []struct {
			suffix, typ string
			ps          []netip.Prefix
		}{{"4", "ipv4_addr", v4}, {"6", "ipv6_addr", v6}} {
			w("\tset %s%s {", st.name, fam.suffix)
			w("\t\ttype %s; flags interval;", fam.typ)
			if len(fam.ps) > 0 {
				w("\t\telements = { %s }", strings.Join(strs(fam.ps), ", "))
			}
			w("\t}")
		}
	}
	// Address blocked both ways: every packet. Inbound only: packets of connections the
	// address opened (ct direction original). Outbound only: connections to it.
	chain := func(name, hook string, rules ...string) {
		w("\tchain %s {", name)
		w("\t\ttype filter hook %s priority -5; policy accept;", hook)
		for _, r := range rules {
			w("\t\t%s", r)
		}
		w("\t}")
	}
	in := []string{"ip saddr @both4 drop", "ip6 saddr @both6 drop",
		"ip saddr @in4 ct direction original drop", "ip6 saddr @in6 ct direction original drop"}
	out := []string{"ip daddr @both4 drop", "ip6 daddr @both6 drop",
		"ip daddr @out4 ct direction original drop", "ip6 daddr @out6 ct direction original drop"}
	chain("input", "input", in...)
	chain("forward", "forward", slices.Concat(in, out)...)
	chain("output", "output", out...)
	w("}")
	return b.String()
}

// --- Windows Firewall ---

// WindowsRule is one Windows Firewall rule of the rendered set.
type WindowsRule struct {
	Name        string // unique rule name: HomeXDR-<version>-<in|out>-<n>
	DisplayName string
	Direction   string // Inbound or Outbound
	Addresses   []string
}

// WindowsRules batches a set into rules: inbound rules block everything the set blocks
// inbound (both and in), outbound rules everything blocked outbound.
func WindowsRules(s hostfw.Set, version string) []WindowsRule {
	var out []WindowsRule
	for _, d := range []struct {
		short, dir, label string
		ps                []netip.Prefix
	}{{"in", "Inbound", "inbound", s.In}, {"out", "Outbound", "outbound", s.Out}} {
		addrs := strs(d.ps)
		n := (len(addrs) + WindowsBatch - 1) / WindowsBatch
		for i := range n {
			chunk := addrs[i*WindowsBatch : min((i+1)*WindowsBatch, len(addrs))]
			out = append(out, WindowsRule{
				Name:        fmt.Sprintf("HomeXDR-%s-%s-%d", version, d.short, i+1),
				DisplayName: fmt.Sprintf("HomeXDR block %s (%d of %d)", d.label, i+1, n),
				Direction:   d.dir,
				Addresses:   chunk,
			})
		}
	}
	return out
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func psArray(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = psQuote(s)
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// WindowsDescription is set on every rule, so whoever finds one knows where it comes from.
const WindowsDescription = "Managed by HomeXDR host firewall control. Remove them all with: Remove-NetFirewallRule -Group HomeXDR"

// WindowsScript renders the PowerShell that makes the HomeXDR group hold exactly the
// set's rules. Rule names carry the version, so the new rules are added before the old
// ones are removed (no moment without blocks), and a set already in place is left
// alone. It prints one JSON line: {changed, rules, profiles_off}.
func WindowsScript(s hostfw.Set, version string) string {
	rules := WindowsRules(s, version)
	names := make([]string, len(rules))
	for i, r := range rules {
		names[i] = r.Name
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("$ErrorActionPreference = 'Stop'")
	w("$group = %s", psQuote(WindowsGroup))
	w("$want = %s", psArray(names))
	w("$have = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })")
	w("$missing = @($want | Where-Object { $have -notcontains $_ })")
	w("if ($missing.Count -gt 0) {")
	// A half-applied earlier attempt of this version: start this version over.
	w("  $have | Where-Object { $want -contains $_ } | ForEach-Object { Remove-NetFirewallRule -Name $_ }")
	for _, r := range rules {
		w("  New-NetFirewallRule -Name %s -DisplayName %s -Group $group -Description %s -Direction %s -Action Block -Profile Any -Enabled True -RemoteAddress %s | Out-Null",
			psQuote(r.Name), psQuote(r.DisplayName), psQuote(WindowsDescription), r.Direction, psArray(r.Addresses))
	}
	w("}")
	w("$have | Where-Object { $want -notcontains $_ } | ForEach-Object { Remove-NetFirewallRule -Name $_ }")
	w("$off = @(Get-NetFirewallProfile | Where-Object { \"$($_.Enabled)\" -eq 'False' } | ForEach-Object { \"$($_.Name)\" })")
	w("[pscustomobject]@{ changed = ($missing.Count -gt 0 -or @($have | Where-Object { $want -notcontains $_ }).Count -gt 0); rules = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count; profiles_off = $off } | ConvertTo-Json -Compress")
	return b.String()
}

// WindowsRemoveScript removes every rule in the HomeXDR group (uninstall).
const WindowsRemoveScript = "$ErrorActionPreference = 'Stop'\nRemove-NetFirewallRule -Group 'HomeXDR' -ErrorAction SilentlyContinue\n"

// --- pf (macOS) ---

// PfRules renders the anchor. pf keeps state, so a block rule only stops connections
// that start after it is loaded in that direction.
func PfRules(s hostfw.Set) string {
	p := Split(s)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# HomeXDR host firewall control. Remove with: pfctl -a '%s' -F all", PfAnchor)
	table := func(name string, ps []netip.Prefix) bool {
		if len(ps) == 0 {
			return false
		}
		w("table <%s> persist { %s }", name, strings.Join(strs(ps), ", "))
		return true
	}
	both := table("homexdr_block", p.Both)
	in := table("homexdr_block_in", p.In)
	out := table("homexdr_block_out", p.Out)
	if both {
		w("block drop in quick from <homexdr_block> to any")
		w("block drop out quick from any to <homexdr_block>")
	}
	if in {
		w("block drop in quick from <homexdr_block_in> to any")
	}
	if out {
		w("block drop out quick from any to <homexdr_block_out>")
	}
	return b.String()
}
