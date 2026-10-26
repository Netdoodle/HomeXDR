package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestDecommissionInactive(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info := func(name string) api.HostInfo { return api.HostInfo{Hostname: name, OS: event.OS{Platform: "linux"}} }
	for _, id := range []string{"stale", "recent", "revoked"} {
		if _, err := s.CreateEndpoint(ctx, id, info(id), nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.EnsureNetworkHost(ctx, "192.168.120.1", "fw", "opnsense"); err != nil {
		t.Fatal(err)
	}
	old := ts(time.Now().AddDate(0, 0, -40))
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET last_seen = ? WHERE id IN ('stale', 'revoked') OR kind = 'network'`, old); err != nil {
		t.Fatal(err)
	}
	s.RevokeHost(ctx, "revoked")

	got, err := s.DecommissionInactive(ctx, time.Now().AddDate(0, 0, -30))
	if err != nil || len(got) != 1 || got[0].ID != "stale" {
		t.Fatalf("decommissioned %v, %v", got, err)
	}
	if again, _ := s.DecommissionInactive(ctx, time.Now().AddDate(0, 0, -30)); len(again) != 0 {
		t.Fatalf("decommissioned twice: %v", again)
	}
	h, _ := s.GetHost(ctx, "stale")
	if h.Status != "decommissioned" || h.DecommissionedAt == nil {
		t.Fatalf("stale host: %+v", h)
	}
	if n, _, _, _ := s.HostCounts(ctx); n != 2 { // recent + the network device
		t.Fatalf("host count %d", n)
	}
	if was, _ := s.RecommissionHost(ctx, "stale"); !was {
		t.Fatal("not recommissioned")
	}
	if h, _ := s.GetHost(ctx, "stale"); h.DecommissionedAt != nil || h.Status == "decommissioned" {
		t.Fatalf("after restore: %+v", h)
	}
}
