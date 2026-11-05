package core

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	realMAC  = "00:11:22:33:44:55"
	realMAC2 = "00:11:22:33:44:66"
	randMAC  = "02:aa:bb:cc:dd:01" // locally administered
	randMAC2 = "06:aa:bb:cc:dd:02"
)

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newInventoryTest(t *testing.T) (*Core, *clock) {
	t.Helper()
	c := newRepoTestCore(t)
	ck := &clock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	c.Inventory.now = ck.now
	c.Inventory.started = ck.t
	return c, ck
}

var fwHost = &store.Host{ID: "fw", Kind: store.HostNetwork, Hostname: "fw", IPs: []string{"192.168.20.1"}}

func dhcpAck(mac, ip, name string) *event.Event {
	return &event.Event{
		Event:  event.Meta{Module: event.ModuleDHCP},
		Source: &event.Endpoint{IP: ip, MAC: mac, Domain: name},
		Data:   map[string]any{"dhcp_message": "ACK", "interface": "vlan0.20"},
	}
}

func filterRow(action, dir, iface, src, dst string) *event.Event {
	return &event.Event{
		Event:       event.Meta{Module: event.ModuleOPNsense, Action: action},
		Source:      &event.Endpoint{IP: src},
		Destination: &event.Endpoint{IP: dst},
		Network:     &event.Network{Direction: dir},
		Data:        map[string]any{"interface": iface},
	}
}

func flowRow(src, dst string) *event.Event {
	return &event.Event{Event: event.Meta{Module: event.ModuleNetFlow}, Source: &event.Endpoint{IP: src}, Destination: &event.Endpoint{IP: dst}}
}

func dnsRow(src string) *event.Event {
	return &event.Event{Event: event.Meta{Module: event.ModuleDNS}, Source: &event.Endpoint{IP: src}}
}

func deviceByID(c *Core, id string) *DeviceView {
	for _, d := range c.Inventory.List().Devices {
		if d.ID == id {
			return &d
		}
	}
	return nil
}

func TestInventoryProvisionalMergesIntoMAC(t *testing.T) {
	c, ck := newInventoryTest(t)
	inv := c.Inventory
	inv.Observe(fwHost, []*event.Event{filterRow("block", event.DirectionInbound, "igb1", "192.168.20.50", "192.168.10.5")})
	if err := func() error {
		_, err := inv.Patch(context.Background(), "ip:192.168.20.50", DevicePatch{Name: ptr("Kitchen")})
		return err
	}(); err != nil {
		t.Fatal(err)
	}
	first := ck.t
	ck.t = ck.t.Add(time.Hour)
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.50", "printer")})

	list := inv.List()
	if deviceByID(c, "ip:192.168.20.50") != nil {
		t.Fatalf("provisional record is still there: %+v", list.Devices)
	}
	d := deviceByID(c, realMAC)
	if d == nil || d.IP != "192.168.20.50" || d.Hostname != "printer" || d.Name != "Kitchen" || !d.FirstSeen.Equal(first) ||
		!contains(d.Sources, sourceFirewall) || !contains(d.Sources, sourceDHCP) || d.Subnet != "192.168.20.0/24" || d.Randomized {
		t.Fatalf("merged device %+v", d)
	}
	// Traffic from the address now belongs to the MAC's record.
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.50", "1.1.1.1")})
	if got := len(inv.List().Devices); got != 1 {
		t.Fatalf("%d devices", got)
	}
	// A new lease moves the device; the old address no longer points at it.
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.51", "printer")})
	d = deviceByID(c, realMAC)
	if d.IP != "192.168.20.51" || len(d.IPs) != 2 {
		t.Fatalf("after new lease %+v", d)
	}
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.50", "1.1.1.1")})
	if deviceByID(c, "ip:192.168.20.50") == nil {
		t.Fatal("the freed address is a new provisional record")
	}
	// A lease taken over by another MAC moves it off the old device.
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC2, "192.168.20.51", "other")})
	if d = deviceByID(c, realMAC); d.IP != "" {
		t.Fatalf("old holder keeps the address: %+v", d)
	}
	if d = deviceByID(c, realMAC2); d.IP != "192.168.20.51" {
		t.Fatalf("new holder %+v", d)
	}
}

func ptr[T any](v T) *T { return &v }

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestInventoryRandomizedMACFollowsName(t *testing.T) {
	c, _ := newInventoryTest(t)
	inv := c.Inventory
	inv.Observe(fwHost, []*event.Event{dhcpAck(randMAC, "192.168.20.60", "pixel-of-sam")})
	inv.Observe(fwHost, []*event.Event{dhcpAck(randMAC2, "192.168.20.61", "pixel-of-sam")})
	list := inv.List().Devices
	if len(list) != 1 || list[0].ID != randMAC || len(list[0].MACs) != 2 || !list[0].Randomized || list[0].IP != "192.168.20.61" {
		t.Fatalf("devices %+v", list)
	}
	// With no name, or a name many devices share, a randomized MAC is its own device.
	inv.Observe(fwHost, []*event.Event{dhcpAck("0a:00:00:00:00:01", "192.168.20.62", "")})
	inv.Observe(fwHost, []*event.Event{dhcpAck("0a:00:00:00:00:02", "192.168.20.63", "iPhone")})
	inv.Observe(fwHost, []*event.Event{dhcpAck("0a:00:00:00:00:03", "192.168.20.64", "iPhone")})
	if got := len(inv.List().Devices); got != 4 {
		t.Fatalf("%d devices", got)
	}
	// Two real MACs with one name stay two devices.
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.70", "nas"), dhcpAck(realMAC2, "192.168.20.71", "nas")})
	if deviceByID(c, realMAC) == nil || deviceByID(c, realMAC2) == nil {
		t.Fatalf("devices %+v", inv.List().Devices)
	}
	// The offline lists can also flag a MAC and name its vendor.
	c.Enrich = fakeMAC{}
	inv.Observe(fwHost, []*event.Event{dhcpAck("00:aa:00:00:00:01", "192.168.20.72", "tv-room")})
	d := deviceByID(c, "00:aa:00:00:00:01")
	if d.Vendor != "Acme" || !d.Randomized {
		t.Fatalf("enriched %+v", d)
	}
}

type fakeMAC struct{ enrich.Nop }

func (fakeMAC) MAC(string) enrich.MACInfo { return enrich.MACInfo{Vendor: "Acme", Randomized: true} }

func TestInventoryIgnoresWhatIsNotADevice(t *testing.T) {
	c, _ := newInventoryTest(t)
	inv := c.Inventory
	inv.Observe(fwHost, []*event.Event{
		flowRow("172.17.0.2", "1.1.1.1"),          // a container bridge
		flowRow("8.8.8.8", "239.255.255.250"),     // public and multicast
		flowRow("192.168.20.1", "1.1.1.1"),        // the firewall, once learned below
		flowRow("192.168.20.255", "1.1.1.1"),      // broadcast
		dnsRow("127.0.0.1"),                       // loopback
		dnsRow("fe80::1"),                         // link-local
		dhcpAck(realMAC, "172.17.0.9", "dockery"), // a lease outside the home subnets
	})
	if d := inv.List().Devices; len(d) != 1 || d[0].ID != "ip:192.168.20.1" {
		t.Fatalf("devices %+v", d)
	}
	// Firewall logs teach it its own address, here and on the next VLAN, and its WAN.
	inv.Observe(fwHost, []*event.Event{
		filterRow("pass", event.DirectionOutbound, "igb0", "203.0.113.9", "1.1.1.1"),
		filterRow("block", event.DirectionInbound, "igb0", "192.168.100.1", "203.0.113.9"), // a modem's address on WAN
		filterRow("pass", event.DirectionInbound, "igb1", "192.168.10.1", "192.168.20.5"),
		filterRow("block", event.DirectionInbound, "igb1", "192.168.20.5", "192.168.10.1"),
	})
	if !inv.Scope().IsFirewall(addrOf("192.168.20.1")) || !inv.Scope().IsFirewall(addrOf("203.0.113.9")) || !inv.Scope().IsFirewall(addrOf("192.168.10.1")) {
		t.Error("firewall addresses were not learned")
	}
	if deviceByID(c, "ip:192.168.20.1") != nil {
		t.Error("the record of the firewall's address stayed once it was known to be the firewall")
	}
	if deviceByID(c, "ip:192.168.100.1") != nil {
		t.Error("a private address on the WAN interface became a device")
	}
	if deviceByID(c, "ip:192.168.10.1") != nil {
		t.Error("the firewall on another VLAN became a device")
	}
	if d := deviceByID(c, "ip:192.168.20.5"); d == nil || d.DestOnly || d.Interface != "igb1" {
		t.Errorf("real device %+v", d)
	}
	// A blocked packet's target is not evidence of anything.
	inv.Observe(fwHost, []*event.Event{filterRow("block", event.DirectionInbound, "igb1", "192.168.20.5", "192.168.20.99")})
	if deviceByID(c, "ip:192.168.20.99") != nil {
		t.Error("a blocked destination became a device")
	}
}

func TestInventoryConfiguredSubnets(t *testing.T) {
	c, _ := newInventoryTest(t)
	inv := c.Inventory
	ctx := context.Background()
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.5", "1.1.1.1"), flowRow("10.9.0.5", "1.1.1.1")})
	if _, err := inv.SetSettings(ctx, NetworkSettings{Subnets: []string{"nope"}, NewDeviceAlerts: true}); err == nil {
		t.Fatal("bad subnet accepted")
	}
	if _, err := inv.SetSettings(ctx, NetworkSettings{NewDeviceAlerts: true, LearningDays: 500}); err == nil {
		t.Fatal("bad learning period accepted")
	}
	if _, err := inv.SetSettings(ctx, NetworkSettings{Subnets: []string{"192.168.20.0/24", "172.20.0.0/16"}, NewDeviceAlerts: true}); err != nil {
		t.Fatal(err)
	}
	if deviceByID(c, "ip:10.9.0.5") != nil {
		t.Error("a device outside the new subnets stayed")
	}
	if deviceByID(c, "ip:192.168.20.5") == nil {
		t.Error("a device inside the new subnets went")
	}
	inv.Observe(fwHost, []*event.Event{flowRow("172.20.1.1", "1.1.1.1"), flowRow("10.9.0.5", "1.1.1.1")})
	if deviceByID(c, "ip:172.20.1.1") == nil || deviceByID(c, "ip:10.9.0.5") != nil {
		t.Errorf("devices %+v", inv.List().Devices)
	}
	list := inv.List().Subnets
	if len(list) != 2 || list[0].Subnet != "172.20.0.0/16" || list[1].Devices != 1 {
		t.Errorf("subnets %+v", list)
	}
}

func TestInventoryLinksAgents(t *testing.T) {
	c, ck := newInventoryTest(t)
	inv := c.Inventory
	agent := &store.Host{ID: "tower", Kind: store.HostEndpoint, Hostname: "Tower", IPs: []string{"192.168.20.20", "172.17.0.1", "10.253.0.1"}}
	// No subnet seen on the wire yet, so nothing counts.
	inv.Observe(agent, []*event.Event{{}})
	if got := len(inv.List().Devices); got != 0 {
		t.Fatalf("%d devices", got)
	}
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.5", "1.1.1.1")})
	ck.t = ck.t.Add(agentLinkInterval + time.Second)
	inv.Observe(agent, []*event.Event{{}})
	d := deviceByID(c, "ip:192.168.20.20")
	if d == nil || d.HostID != "tower" || d.HostName != "Tower" || !contains(d.Sources, sourceAgent) {
		t.Fatalf("agent device %+v", d)
	}
	if deviceByID(c, "ip:172.17.0.1") != nil || deviceByID(c, "ip:10.253.0.1") != nil {
		t.Errorf("host-only addresses became devices: %+v", inv.List().Devices)
	}
	// The link survives DHCP revealing the MAC.
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.20", "tower")})
	if d = deviceByID(c, realMAC); d == nil || d.HostID != "tower" {
		t.Fatalf("merged agent device %+v", d)
	}
}

func TestInventoryPersists(t *testing.T) {
	c, ck := newInventoryTest(t)
	inv := c.Inventory
	ctx := context.Background()
	inv.Observe(fwHost, []*event.Event{dhcpAck(randMAC, "192.168.20.60", "pixel"), flowRow("192.168.20.70", "1.1.1.1")})
	inv.flush(ctx)
	if _, err := inv.Patch(ctx, randMAC, DevicePatch{Name: ptr("Sam's phone"), Note: ptr("  note "), Known: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Patch(ctx, "nope", DevicePatch{Known: ptr(true)}); err != store.ErrNotFound {
		t.Errorf("missing device: %v", err)
	}
	if _, err := inv.Patch(ctx, randMAC, DevicePatch{}); err == nil {
		t.Error("empty patch accepted")
	}
	// A merge deletes the provisional row.
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.70", "nas")})
	inv.flush(ctx)

	fresh := newInventory(c)
	fresh.now = ck.now
	if err := fresh.load(ctx); err != nil {
		t.Fatal(err)
	}
	if fresh.started.IsZero() {
		t.Error("the start of learning was not kept")
	}
	stored, err := c.State.ListDevices(ctx)
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %d: %v", len(stored), err)
	}
	c.Inventory = fresh
	d := deviceByID(c, randMAC)
	if d == nil || d.Name != "Sam's phone" || d.Note != "note" || !d.Known || d.IP != "192.168.20.60" || !d.Randomized || len(d.IPs) != 1 {
		t.Fatalf("reloaded %+v", d)
	}
	// The indexes came back: same address, same device.
	fresh.Observe(fwHost, []*event.Event{flowRow("192.168.20.60", "1.1.1.1"), dhcpAck(randMAC, "192.168.20.60", "pixel")})
	if got := len(fresh.List().Devices); got != 2 {
		t.Fatalf("%d devices after reload", got)
	}
}

func alertsFor(t *testing.T, c *Core) []*store.Alert {
	t.Helper()
	alerts, _, err := c.State.ListAlerts(context.Background(), store.AlertFilter{RuleID: RuleNewDevice})
	if err != nil {
		t.Fatal(err)
	}
	return alerts
}

func TestNewDeviceAlerts(t *testing.T) {
	c, ck := newInventoryTest(t)
	inv := c.Inventory
	ctx := context.Background()

	// Seen during learning: never new, however late learning ends.
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.5", "1.1.1.1")})
	ck.t = ck.t.Add(time.Hour)
	inv.raiseNewDevices(ctx)
	if len(alertsFor(t, c)) != 0 {
		t.Fatal("alert during learning")
	}

	ck.t = ck.t.AddDate(0, 0, defaultLearningDays)
	if inv.List().Learning {
		t.Fatal("still learning")
	}
	inv.Observe(fwHost, []*event.Event{
		flowRow("192.168.20.5", "1.1.1.1"),
		flowRow("192.168.20.77", "1.1.1.1"),
		dhcpAck(realMAC, "192.168.20.80", "laptop"),
		dhcpAck(randMAC, "192.168.20.81", "pixel"),
		flowRow("192.168.20.6", "192.168.20.90"), // only a destination
	})
	if d := deviceByID(c, "ip:192.168.20.90"); d == nil || !d.DestOnly || d.New {
		t.Fatalf("destination-only record %+v", d)
	}
	if d := deviceByID(c, "ip:192.168.20.77"); d == nil || !d.New {
		t.Fatalf("new record %+v", d)
	}
	// Not yet: DHCP gets a moment to name it.
	inv.raiseNewDevices(ctx)
	if len(alertsFor(t, c)) != 0 {
		t.Fatal("alert before the holdoff")
	}
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	alerts := alertsFor(t, c)
	if len(alerts) != 4 { // 77, 80, 81 and 6 (a source first seen after learning)
		t.Fatalf("%d alerts: %+v", len(alerts), alerts)
	}
	byEntity := map[string]*store.Alert{}
	for _, a := range alerts {
		if a.Severity != store.SevLow {
			t.Errorf("severity %s", a.Severity)
		}
		byEntity[a.Rule.Description] = a
	}
	var bare, withMAC, random string
	for desc := range byEntity {
		switch {
		case strings.Contains(desc, "192.168.20.77"):
			bare = desc
		case strings.Contains(desc, realMAC):
			withMAC = desc
		case strings.Contains(desc, randMAC):
			random = desc
		}
	}
	if !strings.Contains(bare, "not proof of a new device") {
		t.Errorf("bare IP text: %s", bare)
	}
	if !strings.Contains(withMAC, `"laptop"`) || strings.Contains(withMAC, "randomized") {
		t.Errorf("MAC text: %s", withMAC)
	}
	if !strings.Contains(random, "randomized") {
		t.Errorf("randomized text: %s", random)
	}
	// Once only, also after a provisional record merges into its MAC.
	inv.raiseNewDevices(ctx)
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC2, "192.168.20.77", "found-it")})
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != 4 {
		t.Fatalf("%d alerts after repeat", got)
	}

	// A known device stays quiet, and so does one with an agent.
	if _, err := inv.Patch(ctx, "ip:192.168.20.6", DevicePatch{Known: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if deviceByID(c, "ip:192.168.20.6").New {
		t.Error("a known device is new")
	}

	// The toggle: nothing while off, and what appeared meanwhile is not raised afterwards.
	set := inv.Settings()
	set.NewDeviceAlerts = false
	if _, err := inv.SetSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.91", "1.1.1.1")})
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != 4 {
		t.Fatalf("%d alerts while off", got)
	}
	set.NewDeviceAlerts = true
	if _, err := inv.SetSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != 4 {
		t.Fatalf("%d alerts after turning back on", got)
	}
	inv.Observe(fwHost, []*event.Event{flowRow("192.168.20.92", "1.1.1.1")})
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != 5 {
		t.Fatalf("%d alerts for a device after turning back on", got)
	}
}

func TestNewDeviceAlertBurstIsCapped(t *testing.T) {
	c, ck := newInventoryTest(t)
	inv := c.Inventory
	ctx := context.Background()
	ck.t = ck.t.AddDate(0, 0, defaultLearningDays+1)
	var evs []*event.Event
	for i := range maxNewDeviceAlerts + 3 {
		evs = append(evs, flowRow(fmt.Sprintf("192.168.30.%d", i+2), "1.1.1.1"))
	}
	inv.Observe(fwHost, evs)
	ck.t = ck.t.Add(newDeviceHoldoff + time.Second)
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != maxNewDeviceAlerts {
		t.Fatalf("%d alerts in a pass", got)
	}
	inv.raiseNewDevices(ctx)
	if got := len(alertsFor(t, c)); got != maxNewDeviceAlerts+3 {
		t.Fatalf("%d alerts after the next pass", got)
	}
}

func TestDeviceLabel(t *testing.T) {
	c, _ := newInventoryTest(t)
	inv := c.Inventory
	inv.Observe(fwHost, []*event.Event{dhcpAck(realMAC, "192.168.20.50", "printer"), flowRow("192.168.20.51", "1.1.1.1")})
	if key, label := inv.DeviceLabel("192.168.20.50"); key != realMAC || label != "printer (192.168.20.50)" {
		t.Errorf("%s %s", key, label)
	}
	if key, label := inv.DeviceLabel("192.168.20.51"); key != "ip:192.168.20.51" || label != "192.168.20.51" {
		t.Errorf("%s %s", key, label)
	}
	if key, label := inv.DeviceLabel("192.168.20.52"); key != "ip:192.168.20.52" || label != "192.168.20.52" {
		t.Errorf("%s %s", key, label)
	}
}

func addrOf(s string) netip.Addr { return netip.MustParseAddr(s) }
