package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const corrRules = `title: SSH failure
id: 00000000-0000-4000-8000-0000000000c1
name: test_ssh_failure
level: low
logsource: {category: authentication}
detection:
  sel: {event.action: ssh_login, event.outcome: failure}
  condition: sel
---
title: SSH brute force
id: 00000000-0000-4000-8000-0000000000c2
description: Many failures.
tags: [attack.credential-access, attack.t1110]
level: high
correlation:
  type: event_count
  rules: [test_ssh_failure]
  group-by: [source.ip]
  timespan: 5m
  condition: {gte: 5}
`

// Ingested events that cross a correlation's threshold raise exactly one alert, through
// the same path as a rule hit; the base rule raises none; a correlation whose base rule is
// missing is reported, not loaded.
func TestCorrelationAlertEndToEnd(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	os.WriteFile(filepath.Join(c.Cfg.RulesDir, "corr.yml"), []byte(corrRules), 0o644)
	os.WriteFile(filepath.Join(c.Cfg.RulesDir, "broken.yml"), []byte(`title: Broken correlation
id: 00000000-0000-4000-8000-0000000000c3
correlation: {type: event_count, rules: [no_such_rule], timespan: 5m, condition: {gte: 5}}
`), 0o644)
	if err := c.Rules.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, e := range c.Rules.LoadErrors() {
		if strings.HasSuffix(e.Path, "broken.yml") && strings.Contains(e.Err, "Broken correlation: correlation: rule \"no_such_rule\" is not loaded") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("unresolved correlation not reported: %+v", c.Rules.LoadErrors())
	}
	if _, err := c.Rules.Get(ctx, "00000000-0000-4000-8000-0000000000c3"); err == nil {
		t.Fatal("the unresolved correlation was loaded")
	}
	if _, err := c.Rules.Get(ctx, "00000000-0000-4000-8000-0000000000c2"); err != nil {
		t.Fatalf("correlation rule not loaded: %v", err)
	}
	// A custom correlation is checked against the loaded rules before it is saved.
	if _, err := c.Rules.Validate("title: c\nid: c\ncorrelation: {type: event_count, rules: [nope], timespan: 1m, condition: {gte: 2}}\n"); err == nil {
		t.Fatal("a custom correlation with a missing base rule validated")
	}
	if _, err := c.Rules.Validate("title: c\nid: c\ncorrelation: {type: event_count, rules: [test_ssh_failure], timespan: 1m, condition: {gte: 2}}\n"); err != nil {
		t.Fatalf("a custom correlation of a loaded rule: %v", err)
	}

	h, err := c.State.CreateEndpoint(ctx, "a", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux"}}, nil, "s1")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	fail := func(ip string, i int) *event.Event {
		return &event.Event{
			Timestamp: start.Add(time.Duration(i) * time.Second),
			Event: event.Meta{Category: []string{event.CategoryAuthentication}, Type: []string{event.TypeStart},
				Action: "ssh_login", Outcome: event.OutcomeFailure, Module: event.ModuleAuthLog},
			Process: &event.Process{PID: 900, Name: "sshd"},
			User:    &event.User{Name: "root"},
			Source:  &event.Endpoint{IP: ip, Port: 40000 + i},
		}
	}
	// Twelve failures from one address, in two batches, and four from another.
	var batch []*event.Event
	for i := 0; i < 6; i++ {
		batch = append(batch, fail("203.0.113.7", i))
	}
	batch = append(batch, fail("198.51.100.2", 0), fail("198.51.100.2", 1))
	if err := c.Ingest(ctx, h, batch); err != nil {
		t.Fatal(err)
	}
	fifth := batch[4]
	batch = nil
	for i := 6; i < 12; i++ {
		batch = append(batch, fail("203.0.113.7", i))
	}
	batch = append(batch, fail("198.51.100.2", 2), fail("198.51.100.2", 3))
	if err := c.Ingest(ctx, h, batch); err != nil {
		t.Fatal(err)
	}

	alerts, _, err := c.State.ListAlerts(ctx, store.AlertFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		titles := []string{}
		for _, a := range alerts {
			titles = append(titles, a.Rule.Title)
		}
		t.Fatalf("alerts = %d %v, want 1", len(alerts), titles)
	}
	a := alerts[0]
	if a.Rule.ID != "00000000-0000-4000-8000-0000000000c2" || a.Rule.Title != "SSH brute force" || a.Severity != store.SevHigh ||
		a.Count != 1 || a.Hostname != "tower" || len(a.Mitre) == 0 {
		t.Fatalf("alert = %+v", a)
	}
	if !strings.HasPrefix(a.Rule.Description, `5 events matching "SSH failure" within 5m (threshold >= 5) for source.ip=203.0.113.7.`) ||
		!strings.HasSuffix(a.Rule.Description, "Many failures.") {
		t.Fatalf("description = %q", a.Rule.Description)
	}
	// The alert's event is the one that crossed the threshold (the fifth failure).
	full, err := c.State.GetAlert(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.EventIDs) != 1 || full.EventIDs[0] != fifth.ID {
		t.Fatalf("event ids = %v", full.EventIDs)
	}
}
