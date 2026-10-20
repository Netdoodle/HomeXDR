package events

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// spread returns n events for host spread evenly over the last `days` days, oldest first,
// each carrying padding so the store grows quickly.
func spread(host string, n, days int) []*event.Event {
	now := time.Now().UTC()
	pad := strings.Repeat("x", 2000)
	out := make([]*event.Event, n)
	for i := range out {
		at := now.Add(-time.Duration(days*24) * time.Hour * time.Duration(n-i) / time.Duration(n))
		ev := sample(host, "e", "", "p.exe", pad, []string{"process"}, "start", at)
		ev.ID = event.NewID()
		out[i] = ev
	}
	return out
}

func TestSQLiteTrimToSize(t *testing.T) {
	ctx := context.Background()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	evs := spread("h", 3000, 10)
	if err := s.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	before, err := s.Size(ctx)
	if err != nil || before < 3000*2000 {
		t.Fatalf("Size = %d, %v", before, err)
	}
	// Nothing to do under the cap.
	if cutoff, err := s.TrimToSize(ctx, before*2); err != nil || !cutoff.IsZero() {
		t.Fatalf("TrimToSize above size: cutoff %v, err %v", cutoff, err)
	}
	limit := before / 2
	cutoff, err := s.TrimToSize(ctx, limit)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.Size(ctx)
	if after > limit {
		t.Fatalf("size %d still over the cap %d", after, limit)
	}
	if cutoff.IsZero() {
		t.Fatal("no cutoff reported")
	}
	if _, err := s.Get(ctx, evs[0].ID); err != ErrNotFound {
		t.Fatalf("oldest event survived: %v", err)
	}
	if _, err := s.Get(ctx, evs[len(evs)-1].ID); err != nil {
		t.Fatalf("newest event was deleted: %v", err)
	}
	// It removes the oldest events only: roughly half should remain.
	res, err := s.Search(ctx, SearchQuery{HostID: "h", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total < 1000 || res.Total > 2000 {
		t.Fatalf("%d events left of 3000 after trimming to half the size", res.Total)
	}
}

// TestClickHouseRetention checks the size cap and the no-time-limit TTL against a real
// server (HOMEXDR_TEST_CLICKHOUSE_DSN), in a throwaway database.
func TestClickHouseRetention(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := "homexdr_retention_" + strings.ToLower(event.NewID())
	u.Path = "/" + db
	ctx := context.Background()

	s, err := OpenClickHouse(ctx, u.String(), 30)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = s.conn.Exec(ctx, "DROP DATABASE IF EXISTS `"+db+"`")
		s.Close()
	}()
	createQuery := func() string {
		var q string
		if err := s.conn.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE database = ? AND name = 'events'", db).Scan(&q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	if !strings.Contains(createQuery(), " TTL ") {
		t.Fatal("30-day retention should set a TTL")
	}
	// Reopening with no time limit removes the TTL from the existing table.
	s2, err := OpenClickHouse(ctx, u.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if strings.Contains(createQuery(), " TTL ") {
		t.Fatal("TTL still set with retention 0")
	}

	evs := spread("h", 300, 5) // six daily partitions
	if err := s.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	size, err := s.Size(ctx)
	if err != nil || size == 0 {
		t.Fatalf("Size = %d, %v", size, err)
	}
	if cutoff, err := s.TrimToSize(ctx, size); err != nil || !cutoff.IsZero() {
		t.Fatalf("TrimToSize at size: %v, %v", cutoff, err)
	}
	// A cap smaller than one day keeps only the newest partition and says so.
	cutoff, err := s.TrimToSize(ctx, 1)
	if err == nil || cutoff.IsZero() {
		t.Fatalf("TrimToSize(1): cutoff %v, err %v", cutoff, err)
	}
	if _, err := s.Get(ctx, evs[0].ID); err != ErrNotFound {
		t.Fatalf("oldest event survived: %v", err)
	}
	if _, err := s.Get(ctx, evs[len(evs)-1].ID); err != nil {
		t.Fatalf("newest event was dropped: %v", err)
	}
}
