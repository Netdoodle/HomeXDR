package netscope

import (
	"net/netip"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDirection(t *testing.T) {
	cases := []struct{ src, dst, want string }{
		{"192.168.20.5", "1.1.1.1", event.DirectionOutbound},
		{"1.1.1.1", "192.168.20.5", event.DirectionInbound},
		{"192.168.20.5", "192.168.10.5", event.DirectionInternal},
		{"100.100.1.1", "192.168.10.5", event.DirectionInternal},
		{"1.1.1.1", "8.8.8.8", event.DirectionExternal},
		{"192.168.20.5", "239.255.255.250", event.DirectionInternal},
		{"192.168.20.5", "255.255.255.255", event.DirectionInternal},
		{"2001:4860:4860::8888", "fd00::1", event.DirectionInbound},
	}
	for _, c := range cases {
		if got := Direction(addr(c.src), addr(c.dst)); got != c.want {
			t.Errorf("%s -> %s = %s, want %s", c.src, c.dst, got, c.want)
		}
	}
}

func TestScopeAutomatic(t *testing.T) {
	s := New(Config{}, []netip.Addr{addr("192.168.20.1"), addr("203.0.113.9")})
	home := map[string]bool{
		"192.168.20.5":    true,
		"192.168.10.77":   true,
		"10.1.2.3":        true,
		"192.168.20.1":    false, // the firewall
		"192.168.10.1":    false, // the firewall on another VLAN
		"192.168.20.255":  false, // broadcast
		"192.168.20.0":    false,
		"172.17.0.2":      false, // container bridge
		"239.255.255.250": false,
		"224.0.0.251":     false,
		"255.255.255.255": false,
		"169.254.1.1":     false,
		"127.0.0.1":       false,
		"8.8.8.8":         false,
		"100.100.1.1":     false,
		"fe80::1":         false,
		"fd00::1":         false,
	}
	for ip, want := range home {
		if got := s.Home(addr(ip)); got != want {
			t.Errorf("Home(%s) = %v", ip, got)
		}
	}
	if s.Public(addr("203.0.113.9")) {
		t.Error("the firewall's WAN address is not an internet destination")
	}
	if !s.Public(addr("8.8.8.8")) || s.Public(addr("192.168.20.5")) || s.Public(addr("100.100.1.1")) {
		t.Error("Public")
	}
	if got := s.SubnetOf(addr("192.168.20.5")); got != "192.168.20.0/24" {
		t.Errorf("subnet %s", got)
	}
}

func TestScopeConfigured(t *testing.T) {
	cfg, err := ParseConfig([]string{"192.168.20.0/24", "172.20.0.0/16", "fd00::/64"}, []string{"192.168.20.128/25"}, []string{"192.168.20.254"})
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, []netip.Addr{addr("192.168.20.1")})
	home := map[string]bool{
		"192.168.20.5":   true,
		"172.20.3.4":     true, // listed, so a bridge range is fine
		"fd00::1":        true,
		"192.168.10.5":   false, // not listed
		"192.168.20.200": false, // excluded
		"192.168.20.254": false, // firewall
		"192.168.20.1":   false, // firewall, learned
		"172.20.255.255": false, // broadcast of the /16
		"172.20.0.0":     false,
	}
	for ip, want := range home {
		if got := s.Home(addr(ip)); got != want {
			t.Errorf("Home(%s) = %v", ip, got)
		}
	}
	if got := s.SubnetOf(addr("172.20.3.4")); got != "172.20.0.0/16" {
		t.Errorf("subnet %s", got)
	}
	if _, err := ParseConfig([]string{"nope"}, nil, nil); err == nil {
		t.Error("bad subnet accepted")
	}
	if _, err := ParseConfig(nil, nil, []string{"192.168.0.0/24"}); err == nil {
		t.Error("bad firewall address accepted")
	}
}
