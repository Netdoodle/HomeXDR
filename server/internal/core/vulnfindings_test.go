package core

import (
	"context"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestOldVulnAlertsAreRetired(t *testing.T) {
	c := healthCore(t, nil)
	ctx := context.Background()
	for _, cve := range []string{"CVE-2010-4344", "CVE-2021-3156"} {
		if err := c.RaiseFinding(ctx, Finding{RuleID: RuleVulnKEV, Severity: store.SevHigh, Title: "Known-exploited vulnerability: " + cve,
			Entity: "h1/" + cve, HostID: "h1", Hostname: "tower", Dataset: "homexdr.vulnerability", Data: map[string]any{"entity": "h1/" + cve}}); err != nil {
			t.Fatal(err)
		}
	}
	c.retireVulnAlerts(ctx)
	list, _, err := c.State.ListAlerts(ctx, store.AlertFilter{RuleID: RuleVulnKEV, Limit: 10})
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
	for _, a := range list {
		got, err := c.State.GetAlert(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != store.AlertResolved || len(got.Notes) != 1 || got.Notes[0].Text != vulnRetiredNote {
			t.Fatalf("%+v", got)
		}
	}
}

func TestVulnExposureFromFirewallLog(t *testing.T) {
	c := newRepoTestCore(t)
	ctx := context.Background()
	web, err := c.State.CreateEndpoint(ctx, "web", api.HostInfo{Hostname: "web", IPs: []string{"192.168.120.22"}, OS: event.OS{Platform: "linux"}}, nil, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.State.CreateEndpoint(ctx, "nas", api.HostInfo{Hostname: "nas", IPs: []string{"192.168.120.30"}, OS: event.OS{Platform: "linux"}}, nil, "s2"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	row := func(action, src, dst string, port int, ago time.Duration) *event.Event {
		return &event.Event{
			Timestamp:   now.Add(-ago),
			Event:       event.Meta{Module: event.ModuleOPNsense, Dataset: "opnsense.filterlog", Action: action, Category: []string{event.CategoryNetwork}},
			Source:      &event.Endpoint{IP: src, Port: 40000},
			Destination: &event.Endpoint{IP: dst, Port: port},
			Network:     &event.Network{Direction: "inbound", Transport: "tcp"},
		}
	}
	evs := []*event.Event{
		row("pass", "198.51.100.7", "192.168.120.22", 443, time.Hour),        // a port forward to web
		row("pass", "198.51.100.8", "192.168.120.22", 443, 2*time.Hour),      // same port again
		row("block", "198.51.100.7", "192.168.120.30", 445, time.Hour),       // blocked: not exposure
		row("pass", "192.168.120.151", "192.168.120.30", 22, time.Hour),       // from the LAN: not the internet
		row("pass", "198.51.100.7", "192.168.120.22", 8080, 10*24*time.Hour), // too old
	}
	if err := c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	got, err := vulnExposure{c}.InternetExposure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[web.ID]) != 1 || got[web.ID][0] != 443 {
		t.Fatalf("%v", got)
	}
}
