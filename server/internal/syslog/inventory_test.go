package syslog

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// TestDecodedLogsFillTheInventory follows real log lines through ingest to the device
// inventory and the event store.
func TestDecodedLogsFillTheInventory(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	c, err := core.New(context.Background(), config.Config{DataDir: dir, RulesDir: dir}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	l := New(c, nil)
	var items []item
	for _, raw := range []string{
		`<134>1 2026-11-05T12:00:00Z fw filterlog 1 - - 77,,,abc,igb1,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,192.168.20.77,192.168.10.5,51515,22,0,S,1,,64240,,mss`,
		`<134>1 2026-11-05T12:00:00Z fw filterlog 1 - - 77,,,abc,igb0,match,pass,out,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.9,1.1.1.1,51515,443,0,S,1,,64240,,mss`,
		`<30>1 2026-11-05T12:00:00Z fw dhcpd 99 - - DHCPACK on 192.168.20.50 to 00:11:22:33:44:55 (printer) via igb1`,
		`<30>1 2026-11-05T12:00:00Z fw kea-dhcp4 12 - - DHCP4_LEASE_ALLOC [hwtype=1 00:11:22:33:44:66], cid=[no info], tid=0x1: lease 192.168.20.51 has been allocated for 3600 seconds`,
		`<30>1 2026-11-05T12:00:00Z fw dnsmasq-dhcp 7 - - DHCPACK(br0) 192.168.20.77 00:11:22:33:44:77 laptop`,
		`<30>1 2026-11-05T12:00:00Z fw unbound 4242 - - [4242:0] info: 192.168.20.60 example.com. A IN NOERROR 0.012500 0 86`,
	} {
		m, err := Parse(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		e, kind := Decode(m)
		items = append(items, item{src: "192.168.20.1", name: m.Hostname, kind: kind, ev: e})
	}
	ctx := context.Background()
	l.flush(ctx, "192.168.20.1", items)

	got := map[string]core.DeviceView{}
	for _, d := range c.Inventory.List().Devices {
		got[d.ID] = d
	}
	if len(got) != 4 {
		t.Fatalf("devices %+v", got)
	}
	if d := got["00:11:22:33:44:55"]; d.IP != "192.168.20.50" || d.Hostname != "printer" || d.Interface != "igb1" {
		t.Errorf("ISC lease %+v", d)
	}
	if d := got["00:11:22:33:44:66"]; d.IP != "192.168.20.51" {
		t.Errorf("Kea lease %+v", d)
	}
	if d := got["00:11:22:33:44:77"]; d.IP != "192.168.20.77" || d.Hostname != "laptop" || len(d.Sources) != 2 {
		t.Errorf("dnsmasq lease merged with the firewall's sighting %+v", d)
	}
	if d := got["ip:192.168.20.60"]; d.Sources[0] != "dns" {
		t.Errorf("Unbound client %+v", d)
	}
	scope := c.Inventory.Scope()
	for _, a := range []string{"192.168.20.1", "203.0.113.9"} {
		if !scope.IsFirewall(netip.MustParseAddr(a)) {
			t.Errorf("%s was not learned as the firewall", a)
		}
	}
	for q, want := range map[string]int64{
		"event.module:dhcp":                                     3,
		"event.module:dhcp source.mac:00:11*":                   3,
		"event.dataset:dhcp.isc hostname:printer":               1,
		"dns.question.name:example.com source.ip:192.168.20.60": 1,
	} {
		res, err := c.Events.Search(ctx, events.SearchQuery{Query: q})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if res.Total != want {
			t.Errorf("%s: %d events, want %d", q, res.Total, want)
		}
	}
}
