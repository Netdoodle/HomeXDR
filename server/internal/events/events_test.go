package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestParseQuery(t *testing.T) {
	good := []string{
		``,
		`powershell`,
		`process.name:powershell.exe`,
		`process.name:power* AND NOT user.name:SYSTEM`,
		`(destination.port:443 OR destination.port:80) host.name:"desk top"`,
		`destination.port:>=1024 -process.name:svchost.exe`,
		`data.LogonType:10`,
		`file.path:*\\Temp\\*`,
		`process.command_line:*`,
	}
	for _, q := range good {
		if _, err := ParseQuery(q); err != nil {
			t.Errorf("ParseQuery(%q): %v", q, err)
		}
	}
	bad := []string{`(a`, `a)`, `"unterminated`, `bad;field:1`, `destination.port:>abc`, `AND`}
	for _, q := range bad {
		if _, err := ParseQuery(q); err == nil {
			t.Errorf("ParseQuery(%q): want error", q)
		}
	}
}

func TestLikePattern(t *testing.T) {
	cases := map[string]string{
		`power*`:     `power%`,
		`a?c`:        `a_c`,
		`100%`:       `100\%`,
		`snake_case`: `snake\_case`,
		`lit\*eral*`: `lit*eral%`,
	}
	for in, want := range cases {
		if got := likePattern(in); got != want {
			t.Errorf("likePattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func sample(host, entity, parentEntity, name, cmd string, cats []string, typ string, at time.Time) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: at,
		Host:  event.Host{ID: host, Name: host, OS: &event.OS{Platform: "windows"}},
		Event: event.Meta{Kind: event.KindEvent, Category: cats, Type: []string{typ}, Module: "etw"},
		Process: &event.Process{
			EntityID: entity, PID: 100, Name: name, CommandLine: cmd, Executable: `C:\Windows\` + name,
			Parent: &event.Process{EntityID: parentEntity, Name: "explorer.exe"},
		},
		Data: map[string]any{"LogonType": "10"},
	}
}

func TestSQLiteStore(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testStore(t, s, "h1", "h2", true)
}

// TestClickHouseStore runs against a real server when HOMEXDR_TEST_CLICKHOUSE_DSN is set,
// e.g. clickhouse://default:@localhost:9000/homexdr_test
func TestClickHouseStore(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	ctx := context.Background()
	s, err := OpenClickHouse(ctx, dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Unique host IDs keep repeated runs independent.
	suffix := event.NewID()
	testStore(t, s, "h1-"+suffix, "h2-"+suffix, false)
}

func testStore(t *testing.T, s Store, h1, h2 string, purges bool) {
	ctx := context.Background()
	now := time.Now().UTC()
	root := sample(h1, "e-root", "", "explorer.exe", "explorer.exe", []string{"process"}, "start", now.Add(-time.Hour))
	ps := sample(h1, "e-ps", "e-root", "powershell.exe", "powershell -nop -enc SQBFAFgA", []string{"process"}, "start", now.Add(-30*time.Minute))
	conn := sample(h1, "e-ps", "e-root", "powershell.exe", "", []string{"network"}, "connection", now.Add(-29*time.Minute))
	conn.Destination = &event.Endpoint{IP: "203.0.113.7", Port: 443}
	conn.Network = &event.Network{Transport: "tcp", CommunityID: "1:abc"}
	who := sample(h1, "e-who", "e-ps", "whoami.exe", "whoami /all", []string{"process"}, "start", now.Add(-28*time.Minute))
	other := sample(h2, "e-x", "", "bash", "bash -c id", []string{"process"}, "start", now.Add(-10*time.Minute))
	other.Host.OS.Platform = "linux"
	old := sample(h1, "e-old", "", "old.exe", "", []string{"process"}, "start", now.Add(-48*time.Hour))
	if err := s.Insert(ctx, []*event.Event{root, ps, conn, who, other, old}); err != nil {
		t.Fatal(err)
	}

	search := func(q string) int64 {
		t.Helper()
		res, err := s.Search(ctx, SearchQuery{Query: q, From: now.Add(-24 * time.Hour), HostIDs: []string{h1, h2}})
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if int64(len(res.Events)) != res.Total {
			t.Fatalf("Search(%q): %d events but total %d", q, len(res.Events), res.Total)
		}
		return res.Total
	}
	cases := map[string]int64{
		``:                              5,
		`process.name:POWERSHELL.EXE`:   2,
		`process.name:power*`:           2,
		`event.category:network`:        1,
		`event.category:process`:        4,
		`NOT event.category:process`:    1,
		`destination.port:443`:          1,
		`destination.port:>400`:         1,
		`destination.port:<400`:         0,
		`whoami`:                        1,
		`-enc`:                          4,
		`"-enc"`:                        1,
		`host.os.platform:linux`:        1,
		`data.LogonType:10`:             5,
		`process.parent.entity_id:e-ps`: 1,
		`network.community_id:*`:        1,
		`(process.name:bash OR process.name:whoami.exe) AND host.name:` + h1: 1,
	}
	for q, want := range cases {
		if got := search(q); got != want {
			t.Errorf("Search(%q) = %d, want %d", q, got, want)
		}
	}

	got, err := s.Get(ctx, ps.ID)
	if err != nil || got.Process.CommandLine != ps.Process.CommandLine {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	kids, err := s.Children(ctx, h1, []string{"e-root"}, 10)
	if err != nil || len(kids) != 1 || kids[0].Process.EntityID != "e-ps" {
		t.Fatalf("Children = %v, %v", kids, err)
	}
	counts, err := s.EntityCounts(ctx, h1, []string{"e-ps"})
	if err != nil || counts["e-ps"]["network"] != 1 {
		t.Fatalf("EntityCounts = %v, %v", counts, err)
	}
	st, err := s.Stats(ctx, now.Add(-24*time.Hour), now.Add(time.Minute))
	if err != nil || st.Total < 5 || len(st.Categories) < 2 {
		t.Fatalf("Stats = %+v, %v", st, err)
	}
	var scanned int
	if err := s.Scan(ctx, now.Add(-72*time.Hour), now.Add(time.Minute), 100000, func(e *event.Event) bool {
		if e.Host.ID == h1 || e.Host.ID == h2 {
			scanned++
		}
		return true
	}); err != nil || scanned != 6 {
		t.Fatalf("Scan visited %d, err %v", scanned, err)
	}
	if !purges {
		return
	}
	if err := s.Purge(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, old.ID); err != ErrNotFound {
		t.Fatalf("old event should be purged, got %v", err)
	}
}
