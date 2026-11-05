package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func testSources(t *testing.T, s Store, host string) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	mk := func(at time.Time, module, dataset string) *event.Event {
		return &event.Event{
			ID: event.NewID(), Timestamp: at, Host: event.Host{ID: host, Name: "h"},
			Event:   event.Meta{Kind: event.KindEvent, Module: module, Dataset: dataset},
			Message: dataset,
		}
	}
	if err := s.Insert(ctx, []*event.Event{
		mk(base.Add(time.Minute), "m1", "m1.a"),
		mk(base.Add(2*time.Minute), "m1", "m1.a"),
		mk(base.Add(2*time.Hour), "m1", "m1.a"),
		mk(base.Add(time.Minute), "m2", "m2.b"),
	}); err != nil {
		t.Fatal(err)
	}
	if f, ok := s.(interface{ Flush(context.Context) error }); ok {
		_ = f.Flush(ctx)
	}

	buckets, err := SourceActivity(ctx, s, base.Add(-time.Hour), base.Add(5*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, b := range buckets {
		if b.HostID == host {
			got[b.Module+"/"+b.Dataset+"@"+b.Start.Format("15:04")] = b.Count
		}
	}
	h0, h2 := base.Format("15:04"), base.Add(2*time.Hour).Format("15:04")
	want := map[string]int64{"m1/m1.a@" + h0: 2, "m1/m1.a@" + h2: 1, "m2/m2.b@" + h0: 1}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}

	evs, err := SampleSource(ctx, s, host, "m1", "m1.a", base.Add(-time.Hour), base.Add(5*time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || !evs[0].Timestamp.After(evs[1].Timestamp) || evs[0].Event.Dataset != "m1.a" {
		t.Fatalf("sample: %+v", evs)
	}
	evs, err = SampleSource(ctx, s, host, "m3", "none", base.Add(-time.Hour), base.Add(5*time.Hour), 2)
	if err != nil || len(evs) != 0 {
		t.Fatalf("no rows: %v %v", evs, err)
	}
}

func TestSourcesSQLite(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testSources(t, s, "h1")
}

func TestSourcesClickHouse(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	s, err := OpenClickHouse(context.Background(), dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testSources(t, s, "h1-"+event.NewID())
}

type notABackend struct{ Store }

func TestSourcesUnsupportedStore(t *testing.T) {
	if _, err := SourceActivity(context.Background(), notABackend{}, time.Time{}, time.Time{}, time.Hour); err != ErrUnsupportedStore {
		t.Fatalf("got %v", err)
	}
}
