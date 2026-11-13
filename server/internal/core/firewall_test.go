package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestServerAddrs(t *testing.T) {
	oldLookup, oldIfs := firewallLookup, firewallInterfaceAddrs
	t.Cleanup(func() { firewallLookup, firewallInterfaceAddrs = oldLookup, oldIfs })
	firewallLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "xdr.home.example" {
			return []netip.Addr{netip.MustParseAddr("198.51.100.30"), netip.MustParseAddr("::ffff:198.51.100.31")}, nil
		}
		return nil, errors.New("no such host")
	}
	firewallInterfaceAddrs = func() ([]net.Addr, error) {
		_, n1, _ := net.ParseCIDR("192.0.2.5/24")
		n1.IP = net.ParseIP("192.0.2.5")
		_, lo, _ := net.ParseCIDR("127.0.0.1/8")
		lo.IP = net.ParseIP("127.0.0.1")
		return []net.Addr{n1, lo}, nil
	}
	c := &Core{Cfg: config.Config{
		ServerNames: []string{"xdr.home.example", "198.51.100.40", "localhost", "unknown.invalid"},
		AgentURL:    "https://[2001:db8::40]:8443",
		AgentAddr:   ":8443",
	}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var got []string
	for _, a := range c.ServerAddrs(context.Background()) {
		got = append(got, a.String())
	}
	want := "192.0.2.5 198.51.100.30 198.51.100.31 198.51.100.40 2001:db8::40"
	if strings.Join(got, " ") != want {
		t.Fatalf("server addrs = %v, want %s", got, want)
	}
}

func TestFirewallVersion(t *testing.T) {
	a := []api.FirewallRule{{CIDR: "203.0.113.1", Direction: "both"}}
	b := []api.FirewallRule{{CIDR: "203.0.113.1", Direction: "in"}}
	if firewallVersion(nil) != "none" || firewallVersion(a) == firewallVersion(b) || !strings.HasPrefix(firewallVersion(a), "fw-") ||
		firewallVersion(a) != firewallVersion([]api.FirewallRule{{CIDR: "203.0.113.1", Direction: "both"}}) {
		t.Fatal("versions")
	}
}

func TestValidateFirewallParams(t *testing.T) {
	win := &store.Host{Kind: store.HostEndpoint, OS: event.OS{Platform: "windows"}}
	other := &store.Host{Kind: store.HostEndpoint, OS: event.OS{Platform: "freebsd"}}
	got, err := validateParams(win, api.CmdFirewall, json.RawMessage(`{"version":"none"}`))
	if err != nil || string(got) != `{"version":"none","rules":[]}` {
		t.Fatalf("empty set: %s %v", got, err)
	}
	for _, in := range []string{
		`{"version":"v","rules":[{"cidr":"0.0.0.0/0"}]}`,
		`{"version":"v","rules":[{"cidr":"::/0"}]}`,
		`{"version":"v","rules":[{"cidr":"10.0.0.0/7"}]}`,
		`{"version":"v","rules":[{"cidr":"127.0.0.1"}]}`,
		`{"version":"v","rules":[{"cidr":"fe80::1"}]}`,
		`{"version":"v;x","rules":[]}`,
		`{"version":"v","rules":[],"script":"x"}`,
	} {
		if _, err := validateParams(win, api.CmdFirewall, json.RawMessage(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	if _, err := validateParams(other, api.CmdFirewall, json.RawMessage(`{"version":"v"}`)); err == nil {
		t.Error("unsupported platform accepted")
	}
}
