package core

import (
	"context"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestInboundIDS(t *testing.T) {
	c := newRepoTestCore(t)
	c.Enrich = fakeGeo{}
	ctx := context.Background()
	now := time.Now().UTC()
	alert := func(sig, cat string, sev int, src, dst string, ago time.Duration) *event.Event {
		return &event.Event{
			Timestamp:   now.Add(-ago),
			Event:       event.Meta{Kind: event.KindAlert, Module: event.ModuleSuricata, Dataset: "suricata.alert", Severity: sev},
			Rule:        &event.Rule{Name: sig, Category: cat},
			Source:      &event.Endpoint{IP: src},
			Destination: &event.Endpoint{IP: dst},
		}
	}
	wan := "72.179.145.86"
	evs := []*event.Event{
		alert("ET CINS Active Threat Intelligence Poor Reputation IP group 121", "Misc Attack", 47, "45.141.233.145", wan, time.Minute),
		alert("ET CINS Active Threat Intelligence Poor Reputation IP group 212", "Misc Attack", 47, "45.141.233.146", wan, 2*time.Minute),
		alert("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 47, "198.51.100.7", wan, 3*time.Minute),
		alert("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 47, "198.51.100.7", wan, 4*time.Minute),
		// Outbound from the firewall's address: the remote side is the destination.
		alert("ET MALWARE Known C2 Beacon", "A Network Trojan was detected", 80, wan, "45.141.233.145", 5*time.Minute),
	}
	if err := c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	// Teach the inventory the firewall's own WAN address.
	set := c.Inventory.Settings()
	set.FirewallIPs = []string{wan}
	if _, err := c.Inventory.SetSettings(ctx, set); err != nil {
		t.Fatal(err)
	}

	v, err := c.InboundIDS(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	if v.Total != 5 || len(v.Threats) != 3 {
		t.Fatalf("total %d threats %+v", v.Total, v.Threats)
	}
	byName := map[string]IDSThreat{}
	for _, th := range v.Threats {
		byName[th.Name] = th
	}
	cins := byName["ET CINS Active Threat Intelligence Poor Reputation IP"]
	if cins.Count != 2 || cins.Sources != 2 || cins.TopCountry != "NL" || cins.Severity != "medium" {
		t.Fatalf("groups not joined: %+v", cins)
	}
	c2 := byName["ET MALWARE Known C2 Beacon"]
	if c2.Severity != "high" || c2.TopCountry != "NL" {
		t.Fatalf("outbound alert placed on the wrong side: %+v", c2)
	}
	var nl IDSCountry
	for _, cc := range v.Countries {
		if cc.Code == "NL" {
			nl = cc
		}
	}
	if nl.MaxSeverity != "high" {
		t.Fatalf("NL worst severity = %q", nl.MaxSeverity)
	}
	if nl.Total != 3 || nl.ByCategory["Misc Attack"] != 2 || nl.ByCategory["A Network Trojan was detected"] != 1 {
		t.Fatalf("NL = %+v", nl)
	}
	if len(v.Categories) != 3 || v.Categories[0] != "Misc Attack" && v.Categories[0] != "Potentially Bad Traffic" {
		t.Fatalf("categories = %v", v.Categories)
	}
	var spark int64
	for _, n := range byName["ET SCAN Suspicious inbound to mySQL port 3306"].Spark {
		spark += n
	}
	if spark != 2 {
		t.Fatalf("sparkline sums to %d: %+v", spark, byName["ET SCAN Suspicious inbound to mySQL port 3306"])
	}

	// The logs behind a country's category.
	ev, err := c.InboundEvents(ctx, 24, "NL", "ids", "Misc Attack", 0)
	if err != nil || ev.Total != 2 || ev.Query == "" {
		t.Fatalf("NL misc attack logs: %+v, %v", ev, err)
	}
	ev, _ = c.InboundEvents(ctx, 24, "NL", "ids", "", 0)
	if ev.Total != 3 {
		t.Fatalf("NL all IDS logs: %d", ev.Total)
	}
	ev, _ = c.InboundEvents(ctx, 24, "US", "ids", "Misc Attack", 0)
	if ev.Total != 0 {
		t.Fatalf("US misc attack logs: %d", ev.Total)
	}
}
