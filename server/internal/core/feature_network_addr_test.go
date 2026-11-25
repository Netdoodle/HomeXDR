package core

import (
	"context"
	"testing"
)

func TestAdGuardAddr(t *testing.T) {
	c := &Core{}
	ctx := context.Background()
	if a, err := c.adguardAddr(ctx, "192.168.120.1"); err != nil || a != "192.168.120.1" {
		t.Fatalf("ip: %q %v", a, err)
	}
	// A name that never resolved is an error, never a host named after the hostname.
	if a, err := c.adguardAddr(ctx, "resolver.invalid"); err == nil {
		t.Fatalf("unresolvable name gave %q", a)
	}
	// A name that resolved before falls back to its last address.
	adguardIPs.Store("ads.example.invalid", "192.168.120.1")
	defer adguardIPs.Delete("ads.example.invalid")
	if a, err := c.adguardAddr(ctx, "ads.example.invalid"); err != nil || a != "192.168.120.1" {
		t.Fatalf("fallback: %q %v", a, err)
	}
	if got := c.pulledSources(); len(got) != 0 {
		t.Fatalf("no poller: %v", got)
	}
}
