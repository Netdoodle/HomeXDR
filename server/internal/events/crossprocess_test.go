package events

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// crossEvent is a cross-process event: actor acting on target (no target when empty).
func crossEvent(host, actor, actorName, target, targetName, action string, at time.Time) *event.Event {
	e := sample(host, actor, "", actorName, "", []string{"process"}, event.TypeAccess, at)
	e.Event.Action = action
	e.Event.Module = event.ModuleEventLog
	e.Event.Provider = "Microsoft-Windows-Sysmon"
	e.Process.Parent = nil
	if target != "" {
		e.Target = &event.Target{Process: &event.Process{EntityID: target, PID: 700, Name: targetName,
			Executable: `C:\Windows\System32\` + targetName}}
	}
	return e
}

// testCrossProcess checks CrossProcess, the target column and the query language's
// target.* fields on host h (which must have no other events).
func testCrossProcess(t *testing.T, s Store, h string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	start := sample(h, "e-inj", "e-explorer", "powershell.exe", "powershell -c inject", []string{"process"}, "start", now.Add(-10*time.Minute))
	thread := crossEvent(h, "e-inj", "powershell.exe", "e-note", "notepad.exe", event.ActionRemoteThread, now.Add(-9*time.Minute))
	thread.Target.StartModule = `C:\Windows\System32\kernel32.dll`
	thread.Target.StartFunction = "LoadLibraryW"
	access := crossEvent(h, "e-mimi", "mimikatz.exe", "e-lsass", "lsass.exe", event.ActionProcessAccess, now.Add(-8*time.Minute))
	access.Target.GrantedAccess = "0x1010"
	// A Sysmon process tampering record without event.action is still cross-process.
	tamper := crossEvent(h, "e-hollow", "hollow.exe", "", "", "", now.Add(-7*time.Minute))
	tamper.Event.Code = "25"
	conn := sample(h, "e-inj", "e-explorer", "powershell.exe", "", []string{"network"}, "connection", now.Add(-6*time.Minute))
	if err := s.Insert(ctx, []*event.Event{start, thread, access, tamper, conn}); err != nil {
		t.Fatal(err)
	}

	ids := func(evs []*event.Event) string {
		var out []string
		for _, e := range evs {
			out = append(out, e.ID)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name     string
		entities []string
		limit    int
		want     []*event.Event
	}{
		{"by target", []string{"e-note"}, 10, []*event.Event{thread}},
		{"by actor", []string{"e-inj", "e-lsass"}, 10, []*event.Event{thread, access}},
		{"both sides once", []string{"e-inj", "e-note"}, 10, []*event.Event{thread}},
		{"sysmon code", []string{"e-hollow"}, 10, []*event.Event{tamper}},
		{"limit keeps the oldest", []string{"e-inj", "e-lsass", "e-hollow"}, 1, []*event.Event{thread}},
		{"no match", []string{"e-nobody"}, 10, nil},
		{"empty", nil, 10, nil},
	}
	for _, c := range cases {
		got, err := s.CrossProcess(ctx, h, c.entities, c.limit)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got == nil {
			t.Fatalf("%s: nil slice", c.name)
		}
		if ids(got) != ids(c.want) {
			t.Errorf("%s: CrossProcess = %s, want %s", c.name, ids(got), ids(c.want))
		}
	}
	if got, err := s.CrossProcess(ctx, h+"-other", []string{"e-inj"}, 10); err != nil || len(got) != 0 {
		t.Errorf("other host: %v, %v", got, err)
	}
	got, err := s.CrossProcess(ctx, h, []string{"e-lsass"}, 10)
	if err != nil || len(got) != 1 || got[0].Target == nil || got[0].Target.GrantedAccess != "0x1010" {
		t.Fatalf("target fields lost: %+v, %v", got, err)
	}

	// Lifecycle lookups skip cross-process events, which are category process too.
	life, err := s.ProcessEvents(ctx, h, []string{"e-inj", "e-mimi", "e-hollow"})
	if err != nil || ids(life) != start.ID {
		t.Fatalf("ProcessEvents = %s, %v (want only %s)", ids(life), err, start.ID)
	}

	for q, want := range map[string]int64{
		`target.process.entity_id:e-lsass`:     1,
		`target.process.name:LSASS.EXE`:        1,
		`target.granted_access:0x1010`:         1,
		`target.process.entity_id:*`:           2,
		`event.action:remote-thread-created`:   1,
		`target.start_function:LoadLibrary*`:   1,
		`NOT target.process.entity_id:e-lsass`: 4,
	} {
		res, err := s.Search(ctx, SearchQuery{Query: q, HostID: h, From: now.Add(-time.Hour)})
		if err != nil || res.Total != want {
			t.Errorf("Search(%q) = %v, %v; want %d", q, res, err, want)
		}
	}
}

func TestSQLiteCrossProcess(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testCrossProcess(t, s, "h-xp")
}

func TestClickHouseCrossProcess(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	s, err := OpenClickHouse(context.Background(), dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testCrossProcess(t, s, "h-xp-"+event.NewID())
}

// oldColumns is the table as it was before target_entity_id was added.
func oldColumns() []Column {
	var out []Column
	for _, c := range Columns {
		if c.Name != "target_entity_id" {
			out = append(out, c)
		}
	}
	return out
}

// TestSQLiteMigratesOldTable opens a database made before target_entity_id existed.
func TestSQLiteMigratesOldTable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for _, c := range oldColumns() {
		cols = append(cols, c.Name+" "+sqliteType(&c))
	}
	old := sample("h-old", "e-old", "", "old.exe", "old.exe", []string{"process"}, "start", time.Now().UTC().Add(-time.Hour))
	stmts := []string{
		`CREATE TABLE events (` + strings.Join(cols, ", ") + `, raw TEXT NOT NULL)`,
		`INSERT INTO events (id, ts, host_id, process_entity_id, category, type, raw) VALUES ('` + old.ID + `', ` +
			strconv.FormatInt(old.Timestamp.UnixMilli(), 10) + `, 'h-old', 'e-old', '["process"]', '["start"]', '{"id":"` + old.ID + `"}')`,
	}
	for _, st := range stmts {
		if _, err := db.Exec(st); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, old.ID); err != nil || got.ID != old.ID {
		t.Fatalf("old row: %+v, %v", got, err)
	}
	if res, err := s.Search(ctx, SearchQuery{Query: `NOT target.process.entity_id:*`, HostID: "h-old"}); err != nil || res.Total != 1 {
		t.Fatalf("old row has no target: %+v, %v", res, err)
	}
	testCrossProcess(t, s, "h-xp")
	s.Close()
	// Opening again finds nothing to add.
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

// TestClickHouseMigratesOldTable adds target_entity_id to a table made before it existed.
func TestClickHouseMigratesOldTable(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Create the current table first, then rebuild it in the old shape.
	db := "homexdr_migrate_" + strings.ToLower(event.NewID())
	u.Path = "/" + db
	s, err := OpenClickHouse(ctx, u.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = s.conn.Exec(ctx, "DROP DATABASE IF EXISTS `"+db+"`")
		s.Close()
	}()
	var cols []string
	for _, c := range oldColumns() {
		cols = append(cols, "`"+c.Name+"` "+chType(&c))
	}
	for _, st := range []string{
		"DROP TABLE " + s.table,
		"CREATE TABLE " + s.table + " (" + strings.Join(cols, ", ") + ", `raw` String) ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (host_id, ts)",
	} {
		if err := s.conn.Exec(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := OpenClickHouse(ctx, u.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var create string
	if err := s2.conn.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE database = ? AND name = 'events'", db).Scan(&create); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(create, "`target_entity_id` String, `raw` String") || !strings.Contains(create, "idx_target") {
		t.Fatalf("column or index not added where expected:\n%s", create)
	}
	testCrossProcess(t, s2, "h-xp")
}
