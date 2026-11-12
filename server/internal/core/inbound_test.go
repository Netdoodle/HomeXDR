package core

import (
	"context"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

type fakeGeo struct{ enrich.Nop }

func (fakeGeo) IP(ip string) enrich.IPInfo {
	switch ip {
	case "45.141.233.145", "45.141.233.146":
		return enrich.IPInfo{Country: "NL", ASN: 51396, ASName: "PFCLOUD"}
	case "198.51.100.7":
		return enrich.IPInfo{Country: "US", ASN: 14061, ASName: "DIGITALOCEAN-ASN"}
	}
	return enrich.IPInfo{}
}

func TestInboundThreats(t *testing.T) {
	c := newRepoTestCore(t)
	c.Enrich = fakeGeo{}
	ctx := context.Background()
	fw := &store.Host{ID: "fw", Kind: store.HostNetwork, Hostname: "fw"}
	now := time.Now().UTC()
	row := func(action, src string, port int, ago time.Duration) *event.Event {
		return &event.Event{
			Timestamp:   now.Add(-ago),
			Event:       event.Meta{Module: event.ModuleOPNsense, Dataset: "opnsense.filterlog", Action: action, Category: []string{event.CategoryNetwork}},
			Source:      &event.Endpoint{IP: src, Port: 40000},
			Destination: &event.Endpoint{IP: "72.179.145.86", Port: port},
			Network:     &event.Network{Direction: "inbound", Transport: "tcp"},
		}
	}
	var evs []*event.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, row("block", "45.141.233.145", 22+i, time.Duration(i)*time.Minute))
	}
	evs = append(evs,
		row("block", "45.141.233.146", 3389, 2*time.Hour),
		row("block", "198.51.100.7", 22, 3*time.Hour),
		row("rdr", "198.51.100.7", 443, 3*time.Hour),
		row("block", "192.168.20.151", 445, time.Hour), // a LAN device: not the internet
		row("block", "100.81.93.1", 22, time.Hour),     // Tailscale
		row("block", "203.0.113.9", 80, 60*time.Hour),  // outside both windows
		row("block", "203.0.113.10", 80, 30*time.Hour), // the window before: the trend
		row("block", "203.0.113.11", 80, 31*time.Hour),
	)
	if err := c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	_ = fw

	v, err := c.InboundThreats(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	if v.Attempts != 13 || v.Allowed != 1 || v.Blocked != 12 || v.Sources != 3 || v.NoGeo {
		t.Fatalf("totals: attempts %d allowed %d blocked %d sources %d nogeo %v", v.Attempts, v.Allowed, v.Blocked, v.Sources, v.NoGeo)
	}
	if len(v.Countries) != 2 || v.Countries[0].Code != "NL" || v.Countries[0].Attempts != 11 || v.Countries[0].Sources != 2 {
		t.Fatalf("countries: %+v", v.Countries)
	}
	top := v.TopSources[0]
	if top.IP != "45.141.233.145" || top.Ports != 10 || top.ASName != "PFCLOUD" || top.Attempts != 10 {
		t.Fatalf("top source: %+v", top)
	}
	if len(v.AllowedIn) != 1 || v.AllowedIn[0].IP != "198.51.100.7" {
		t.Fatalf("allowed: %+v", v.AllowedIn)
	}
	if len(v.Networks) != 2 || v.Networks[0].ASN != 51396 {
		t.Fatalf("networks: %+v", v.Networks)
	}
	ports := map[int]int64{}
	for _, p := range v.Ports {
		ports[p.Port] = p.Attempts
	}
	if ports[22] != 2 || ports[445] != 0 || ports[3389] != 1 {
		t.Fatalf("ports (LAN and Tailscale sources must not count): %+v", v.Ports)
	}
	var tl int64
	for _, p := range v.Timeline {
		tl += p.Blocked + p.Allowed
	}
	var srcs int64
	for _, p := range v.Timeline {
		srcs += p.Sources
	}
	if srcs < 3 {
		t.Fatalf("timeline sources %d: %+v", srcs, v.Timeline)
	}
	if v.PrevAttempts != 2 || v.PrevBlocked != 2 || v.PrevSources != 2 {
		t.Fatalf("previous window: %d attempts, %d blocked, %d sources", v.PrevAttempts, v.PrevBlocked, v.PrevSources)
	}
	// The events behind the numbers.
	ev, err := c.InboundEvents(ctx, 24, "US", "allowed", 0)
	if err != nil || ev.Total != 1 || ev.Sources != 1 || ev.Query == "" {
		t.Fatalf("US let in: %+v, %v", ev, err)
	}
	ev, _ = c.InboundEvents(ctx, 24, "NL", "blocked", 0)
	if ev.Total != 11 || ev.Sources != 2 || len(ev.Events) != 11 {
		t.Fatalf("NL blocked: total %d sources %d events %d", ev.Total, ev.Sources, len(ev.Events))
	}
	ev, _ = c.InboundEvents(ctx, 24, "NL", "allowed", 0)
	if ev.Total != 0 || ev.Sources != 0 {
		t.Fatalf("NL let in: %+v", ev)
	}
	if tl != 13 {
		t.Fatalf("timeline total %d, want 13: %+v", tl, v.Timeline)
	}
}
