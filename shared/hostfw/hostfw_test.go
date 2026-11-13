package hostfw

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

func TestParseCIDR(t *testing.T) {
	ok := map[string]string{
		"203.0.113.7":             "203.0.113.7/32",
		" 203.0.113.0/24 ":        "203.0.113.0/24",
		"203.0.113.9/24":          "203.0.113.0/24", // host bits are masked
		"10.0.0.0/8":              "10.0.0.0/8",
		"2001:db8::1":             "2001:db8::1/128",
		"2001:db8::/32":           "2001:db8::/32",
		"::ffff:198.51.100.4":     "198.51.100.4/32",
		"::ffff:198.51.100.0/120": "198.51.100.0/24",
	}
	for in, want := range ok {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseCIDR(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	bad := map[string]string{
		"0.0.0.0/0":         "too broad",
		"::/0":              "too broad",
		"8.0.0.0/7":         "too broad",
		"2001:db8::/31":     "too broad",
		"::ffff:0.0.0.0/96": "too broad",
		"127.0.0.1":         "loopback",
		"127.0.0.0/8":       "loopback",
		"::1":               "loopback",
		"169.254.10.1":      "link-local",
		"fe80::1":           "link-local",
		"fe80::1%eth0":      "not an IP",
		"224.0.0.251":       "multicast",
		"ff02::fb":          "multicast",
		"255.255.255.255":   "broadcast",
		"0.1.2.3":           "unspecified",
		"::":                "unspecified",
		"example.com":       "not an IP",
		"203.0.113.0/33":    "not an IP",
		"":                  "not an IP",
		"1.2.3.4; rm -rf /": "not an IP",
		"1.2.3.4'+'x":       "not an IP",
	}
	for in, want := range bad {
		if _, err := ParseCIDR(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseCIDR(%q) error = %v; want %q", in, err, want)
		}
	}
}

func TestNormalizeRefusesServerAddresses(t *testing.T) {
	server := []netip.Addr{netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("2001:db8:5::10")}
	for _, cidr := range []string{"198.51.100.20", "198.51.100.0/24", "198.0.0.0/8", "2001:db8::/32", "::ffff:198.51.100.20"} {
		_, err := Normalize([]api.FirewallRule{{CIDR: "203.0.113.1"}, {CIDR: cidr}}, server)
		if err == nil || !strings.Contains(err.Error(), "HomeXDR server") {
			t.Errorf("%s: err = %v", cidr, err)
		}
	}
	if _, err := Normalize([]api.FirewallRule{{CIDR: "198.51.100.21"}}, server); err != nil {
		t.Errorf("neighbour of the server refused: %v", err)
	}
}

func TestNormalizeMergesAndSplits(t *testing.T) {
	s, err := Normalize([]api.FirewallRule{
		{CIDR: "203.0.113.5"},
		{CIDR: "203.0.113.0/24"},                    // swallows .5
		{CIDR: "203.0.113.0/24", Direction: "both"}, // duplicate
		{CIDR: "198.51.100.1", Direction: api.FirewallIn},
		{CIDR: "2001:db8::/48", Direction: api.FirewallOut},
		{CIDR: "2001:db8::1", Direction: api.FirewallOut},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in, out := fmtList(s.In), fmtList(s.Out)
	if in != "198.51.100.1/32 203.0.113.0/24" || out != "203.0.113.0/24 2001:db8::/48" {
		t.Fatalf("in = %s; out = %s", in, out)
	}
	if s.Len() != 3 || s.Empty() {
		t.Fatalf("len = %d", s.Len())
	}
	if _, err := Normalize([]api.FirewallRule{{CIDR: "203.0.113.1", Direction: "sideways"}}, nil); err == nil {
		t.Fatal("bad direction accepted")
	}
	many := make([]api.FirewallRule, api.FirewallMaxRules+1)
	for i := range many {
		many[i] = api.FirewallRule{CIDR: "203.0.113.1"}
	}
	if _, err := Normalize(many, nil); err == nil {
		t.Fatal("over the cap accepted")
	}
	if s, err := Normalize(nil, nil); err != nil || !s.Empty() {
		t.Fatalf("empty set: %v %v", s, err)
	}
}

func TestCheckVersion(t *testing.T) {
	for _, v := range []string{"none", "fw-0123abcd", "v1.2_3"} {
		if CheckVersion(v) != nil {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", "a b", "x'y", "a;b", strings.Repeat("a", 65), "$(x)"} {
		if CheckVersion(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestFormat(t *testing.T) {
	if Format(netip.MustParsePrefix("203.0.113.1/32")) != "203.0.113.1" || Format(netip.MustParsePrefix("203.0.113.0/24")) != "203.0.113.0/24" {
		t.Fatal("format")
	}
}

func fmtList(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}
