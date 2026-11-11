package core

import (
	"context"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestDefenderHealth(t *testing.T) {
	c := newRepoTestCore(t)
	ctx := context.Background()
	host := &store.Host{ID: "win1", Hostname: "DESK", Kind: store.HostEndpoint}
	report := func(rtp, age string) *event.Event {
		return &event.Event{Event: event.Meta{Module: event.ModuleEventLog, Provider: "Microsoft-Windows-Windows Defender", Code: "1151"},
			Data: map[string]any{"RTP state": rtp, "BM state": "Enabled", "Last AV security intelligence age": age, "AV security intelligence version": "1.463.233.0"}}
	}
	// Healthy, and "never" (4294967295) ages: nothing.
	c.observeDefender(ctx, host, []*event.Event{report("Enabled", "0"), report("Enabled", "4294967295")})
	if _, n, _ := c.State.ListAlerts(ctx, store.AlertFilter{}); n != 0 {
		t.Fatalf("healthy reports raised %d alerts", n)
	}
	// Protection off twice (one alert), stale signatures (another).
	c.observeDefender(ctx, host, []*event.Event{report("Disabled", "0"), report("Disabled", "5")})
	alerts, n, err := c.State.ListAlerts(ctx, store.AlertFilter{})
	if err != nil || n != 2 {
		t.Fatalf("alerts = %d, %v", n, err)
	}
	rules := map[string]string{}
	for _, a := range alerts {
		rules[a.Rule.ID] = a.Severity
	}
	if rules[RuleDefenderOff] != store.SevHigh || rules[RuleDefenderStale] != store.SevMedium {
		t.Fatalf("rules = %v", rules)
	}
	// Linux hosts and other providers are ignored.
	other := &event.Event{Event: event.Meta{Module: event.ModuleEventLog, Provider: "Something", Code: "5001"}}
	c.observeDefender(ctx, host, []*event.Event{other})
	if _, n, _ := c.State.ListAlerts(ctx, store.AlertFilter{}); n != 2 {
		t.Fatalf("unrelated event raised an alert")
	}
}
