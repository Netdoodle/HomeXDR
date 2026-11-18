package core

import (
	"context"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/behavior"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Network findings stay under the server's host ID, so suppressions keep matching, but
// show the home device's address as the host name.
func TestNetworkFindingsNameTheDevice(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)

	beacon := func(src, dst string) behavior.Finding {
		return behavior.Finding{
			Rule: "net:beaconing", Title: "Possible beaconing from " + src, Severity: store.SevMedium,
			Entity: "beaconing|" + src + "|" + dst,
			Source: &event.Endpoint{IP: src}, Destination: &event.Endpoint{IP: dst, Port: 443},
		}
	}
	for _, f := range []behavior.Finding{
		beacon("192.168.20.62", "35.82.195.206"),
		beacon("192.168.20.62", "35.82.195.207"),
		beacon("192.168.20.89", "172.67.162.106"),
		// Inbound exposure: the home device is the destination.
		{Rule: "net:exposure", Title: "Exposed", Severity: store.SevMedium, Entity: "exposure|1",
			Source: &event.Endpoint{IP: "198.51.100.7"}, Destination: &event.Endpoint{IP: "192.168.20.20", Port: 18444}},
	} {
		if err := c.raiseBehavior(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.RaiseFinding(ctx, Finding{RuleID: "health:feed-silent", Title: "Feed silent",
		Severity: store.SevLow, Entity: "feed", Dataset: "homexdr.health"}); err != nil {
		t.Fatal(err)
	}

	list, _, err := c.State.ListAlerts(ctx, store.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, a := range list {
		if a.HostID != ServerHostID {
			t.Fatalf("%s filed under %q, want %q", a.Rule.Title, a.HostID, ServerHostID)
		}
		names[a.Rule.Title] = a.Hostname
	}
	want := map[string]string{
		"Possible beaconing from 192.168.20.62": "192.168.20.62",
		"Possible beaconing from 192.168.20.89": "192.168.20.89",
		"Exposed":                               "192.168.20.20",
		"Feed silent":                           ServerHostname,
	}
	for title, host := range want {
		if names[title] != host {
			t.Errorf("%s: host name %q, want %q", title, names[title], host)
		}
	}

	top, err := c.State.TopHosts(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, h := range top {
		counts[h.Hostname] = h.Alerts
	}
	if counts["192.168.20.62"] != 2 || counts["192.168.20.89"] != 1 || counts[ServerHostname] != 1 || len(top) != 4 {
		t.Fatalf("top hosts: %+v", top)
	}
}
