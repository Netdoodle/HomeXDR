package events

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestConnTimesSQLite(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testConnTimes(t, s, "192.168.77.")
}

func TestConnTimesClickHouse(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	s, err := OpenClickHouse(context.Background(), dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A subnet per run keeps repeated runs apart.
	testConnTimes(t, s, "10."+strconv.Itoa(int(time.Now().Unix()%250))+"."+strconv.Itoa(time.Now().Nanosecond()%250)+".")
}

func testConnTimes(t *testing.T, s Store, prefix string) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	conn := func(ts time.Time, module, src string, sport int, dst string, dport int) *event.Event {
		return &event.Event{
			ID: event.NewID(), Timestamp: ts, Host: event.Host{ID: "fw"}, Event: event.Meta{Module: module},
			Source: &event.Endpoint{IP: src, Port: sport}, Destination: &event.Endpoint{IP: dst, Port: dport},
			Network: &event.Network{Transport: "tcp"},
		}
	}
	a, b := prefix+"5", prefix+"6"
	var evs []*event.Event
	for i := range 10 {
		evs = append(evs, conn(now.Add(-time.Duration(i+1)*time.Minute), event.ModuleNetFlow, a, 40000+i, "198.51.100.1", 8443))
	}
	evs = append(evs,
		conn(now.Add(-time.Minute), event.ModuleNetFlow, b, 40000, "198.51.100.2", 8443), // too few
		conn(now.Add(-time.Minute), event.ModuleNetFlow, b, 40000, "198.51.100.3", 8443), // a second pair...
		conn(now.Add(-2*time.Minute), event.ModuleNetFlow, b, 40000, "198.51.100.3", 8443),
		conn(now.Add(-time.Minute), event.ModuleOPNsense, b, 40000, "198.51.100.3", 8443), // ...one row from another module
		conn(now.Add(-time.Minute), event.ModuleEBPF, b, 40000, "198.51.100.4", 8443),     // not asked for
		conn(now.Add(-48*time.Hour), event.ModuleNetFlow, b, 40000, "198.51.100.5", 8443), // too old
		conn(now.Add(-time.Minute), event.ModuleNetFlow, a, 40000, prefix+"9", 8443),      // private destination when prefix is
		conn(now.Add(-time.Minute), event.ModuleNetFlow, a, 40000, "198.51.100.6", 0),     // no port
	)
	for range 3 {
		evs = append(evs, conn(now.Add(-time.Minute), event.ModuleNetFlow, "203.0.113.9", 40000, "198.51.100.7", 8443)) // public source
	}
	if err := s.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConnTimes(ctx, ConnTimesQuery{
		From: now.Add(-24 * time.Hour), To: now.Add(time.Minute), Modules: []string{event.ModuleNetFlow, event.ModuleOPNsense},
		MinCount: 2, MaxSeries: 100, MaxTimes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	mine := map[string]ConnSeries{}
	for _, c := range got {
		if c.Source == a || c.Source == b {
			mine[c.Source+">"+c.Destination] = c
		}
		if c.Source == "203.0.113.9" {
			t.Errorf("public source returned: %+v", c)
		}
	}
	if len(mine) != 2 {
		t.Fatalf("series %+v", mine)
	}
	c := mine[a+">198.51.100.1"]
	if c.Count != 10 || c.SourcePorts != 10 || c.Port != 8443 || c.Transport != "tcp" || len(c.Times) != 4 {
		t.Fatalf("series %+v", c)
	}
	// The newest times, oldest first.
	if !c.Times[0].Equal(now.Add(-4*time.Minute)) || !c.Times[3].Equal(now.Add(-time.Minute)) {
		t.Fatalf("times %v", c.Times)
	}
	if c := mine[b+">198.51.100.3"]; c.Count != 3 || c.SourcePorts != 1 || len(c.Times) != 3 {
		t.Fatalf("series %+v", c)
	}
	if got, err := s.ConnTimes(ctx, ConnTimesQuery{From: now.Add(-time.Hour), To: now}); err != nil || got != nil {
		t.Fatalf("no modules: %v %v", got, err)
	}
}
