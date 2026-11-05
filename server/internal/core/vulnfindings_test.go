package core

import (
	"context"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

func TestVulnFindingsBecomeOneAlertPerHostAndCVE(t *testing.T) {
	c := healthCore(t, nil)
	ctx := context.Background()
	n := vulnNotifier{c}
	m := store.VulnMatch{
		HostID: "h1", Hostname: "tower", Package: "exim", Version: "4.69", CVE: "CVE-2010-4344",
		Title: "Exim Heap-Based Buffer Overflow Vulnerability", Reason: "Version 4.69 is affected.", Ransomware: true,
	}
	for range 2 {
		if err := n.RaiseVuln(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	other := m
	other.CVE = "CVE-2021-0001"
	if err := n.RaiseVuln(ctx, other); err != nil {
		t.Fatal(err)
	}
	list, _, err := c.State.ListAlerts(ctx, store.AlertFilter{RuleID: RuleVulnKEV, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d alerts", len(list))
	}
	var first *store.Alert
	for _, a := range list {
		if strings.Contains(a.Rule.Title, "CVE-2010-4344") {
			first = a
		}
	}
	if first == nil || first.Count != 2 || first.Severity != store.SevHigh || first.HostID != "h1" {
		t.Fatalf("%+v", first)
	}
	if err := n.ResolveVuln(ctx, "h1", "CVE-2010-4344", "patched"); err != nil {
		t.Fatal(err)
	}
	got, err := c.State.GetAlert(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.AlertResolved || len(got.Notes) != 1 || got.Notes[0].Text != "patched" {
		t.Fatalf("%+v", got)
	}
	// The other CVE's alert is untouched.
	open, _, err := c.State.ListAlerts(ctx, store.AlertFilter{RuleID: RuleVulnKEV, Statuses: []string{store.AlertNew}, Limit: 10})
	if err != nil || len(open) != 1 {
		t.Fatalf("%v %v", open, err)
	}
}
