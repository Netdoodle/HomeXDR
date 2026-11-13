package fwrules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

func set(t *testing.T, rules ...api.FirewallRule) hostfw.Set {
	t.Helper()
	s, err := hostfw.Normalize(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNftRuleset(t *testing.T) {
	s := set(t,
		api.FirewallRule{CIDR: "203.0.113.7"},
		api.FirewallRule{CIDR: "198.51.100.0/24"},
		api.FirewallRule{CIDR: "2001:db8::/48"},
		api.FirewallRule{CIDR: "192.0.2.1", Direction: api.FirewallIn},
		api.FirewallRule{CIDR: "2001:db8:1::1", Direction: api.FirewallOut},
	)
	got := NftRuleset(s)
	for _, want := range []string{
		"table inet homexdr_block\ndelete table inet homexdr_block\ntable inet homexdr_block {\n",
		"\tset both4 {\n\t\ttype ipv4_addr; flags interval;\n\t\telements = { 198.51.100.0/24, 203.0.113.7 }\n\t}\n",
		"\tset both6 {\n\t\ttype ipv6_addr; flags interval;\n\t\telements = { 2001:db8::/48 }\n\t}\n",
		"\tset in4 {\n\t\ttype ipv4_addr; flags interval;\n\t\telements = { 192.0.2.1 }\n\t}\n",
		"\tset in6 {\n\t\ttype ipv6_addr; flags interval;\n\t}\n",
		"\tset out6 {\n\t\ttype ipv6_addr; flags interval;\n\t\telements = { 2001:db8:1::1 }\n\t}\n",
		"\tchain input {\n\t\ttype filter hook input priority -5; policy accept;\n\t\tip saddr @both4 drop\n\t\tip6 saddr @both6 drop\n\t\tip saddr @in4 ct direction original drop\n",
		"\tchain output {\n\t\ttype filter hook output priority -5; policy accept;\n\t\tip daddr @both4 drop\n",
		"\t\tip6 daddr @out6 ct direction original drop\n\t}\n}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "inet homexdr ") || strings.Contains(got, "inet homexdr\n") {
		t.Error("the block table must not touch the isolation table")
	}
	if strings.Count(got, "chain forward") != 1 || !strings.Contains(got, "\tchain forward {\n\t\ttype filter hook forward priority -5; policy accept;\n\t\tip saddr @both4 drop\n") {
		t.Errorf("forward chain:\n%s", got)
	}
	// Empty: only the deletion.
	if e := NftRuleset(hostfw.Set{}); e != "table inet homexdr_block\ndelete table inet homexdr_block\n" {
		t.Errorf("empty ruleset = %q", e)
	}
}

func TestWindowsScript(t *testing.T) {
	var rules []api.FirewallRule
	for i := range 150 {
		rules = append(rules, api.FirewallRule{CIDR: fmt.Sprintf("203.0.%d.%d", 100+i/100, i%100+1)})
	}
	rules = append(rules, api.FirewallRule{CIDR: "2001:db8::/48", Direction: api.FirewallOut})
	s := set(t, rules...)
	wr := WindowsRules(s, "fw-abc")
	// 150 inbound → 2 rules; 151 outbound → 2 rules.
	if len(wr) != 4 || wr[0].Name != "HomeXDR-fw-abc-in-1" || len(wr[0].Addresses) != WindowsBatch || len(wr[1].Addresses) != 50 ||
		wr[2].Direction != "Outbound" || wr[3].Name != "HomeXDR-fw-abc-out-2" || wr[3].Addresses[len(wr[3].Addresses)-1] != "2001:db8::/48" {
		t.Fatalf("rules = %+v", wr)
	}
	sc := WindowsScript(s, "fw-abc")
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'\n",
		"$group = 'HomeXDR'\n",
		"$want = @('HomeXDR-fw-abc-in-1','HomeXDR-fw-abc-in-2','HomeXDR-fw-abc-out-1','HomeXDR-fw-abc-out-2')\n",
		"New-NetFirewallRule -Name 'HomeXDR-fw-abc-in-1' -DisplayName 'HomeXDR block inbound (1 of 2)' -Group $group -Description '" + WindowsDescription +
			"' -Direction Inbound -Action Block -Profile Any -Enabled True -RemoteAddress @('203.0.100.1','203.0.100.2',",
		"-Direction Outbound -Action Block -Profile Any -Enabled True -RemoteAddress @('203.0.100.1',",
		"$have | Where-Object { $want -notcontains $_ } | ForEach-Object { Remove-NetFirewallRule -Name $_ }\n",
		"ConvertTo-Json -Compress",
	} {
		if !strings.Contains(sc, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// New rules are created before the old version's are removed.
	if strings.Index(sc, "New-NetFirewallRule") > strings.LastIndex(sc, "$want -notcontains") {
		t.Error("old rules removed before the new ones exist")
	}
	// Empty: no rules wanted, everything in the group goes.
	e := WindowsScript(hostfw.Set{}, "none")
	if !strings.Contains(e, "$want = @()\n") || strings.Contains(e, "New-NetFirewallRule") {
		t.Errorf("empty script:\n%s", e)
	}
	// Nothing outside single quotes comes from the addresses: each is a quoted literal.
	for _, line := range strings.Split(sc, "\n") {
		if strings.Contains(line, "RemoteAddress") && strings.Count(line, "'")%2 != 0 {
			t.Errorf("unbalanced quotes: %s", line)
		}
	}
}

func TestPfRules(t *testing.T) {
	s := set(t,
		api.FirewallRule{CIDR: "203.0.113.7"},
		api.FirewallRule{CIDR: "2001:db8::/48"},
		api.FirewallRule{CIDR: "192.0.2.1", Direction: api.FirewallIn},
	)
	got := PfRules(s)
	for _, want := range []string{
		"table <homexdr_block> persist { 203.0.113.7, 2001:db8::/48 }\n",
		"table <homexdr_block_in> persist { 192.0.2.1 }\n",
		"block drop in quick from <homexdr_block> to any\nblock drop out quick from any to <homexdr_block>\n",
		"block drop in quick from <homexdr_block_in> to any\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pf rules lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "homexdr_block_out") {
		t.Errorf("empty out table rendered:\n%s", got)
	}
	if strings.Contains(PfRules(hostfw.Set{}), "block drop") {
		t.Error("empty set blocks something")
	}
}
