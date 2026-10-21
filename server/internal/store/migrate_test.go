package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigrateTriageEngine opens a database whose alert_triage table predates engines.
func TestMigrateTriageEngine(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate alert_triage as an older version had it, with a queued row.
	for _, q := range []string{
		`DROP TABLE alert_triage`,
		`CREATE TABLE alert_triage (alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, trigger TEXT NOT NULL,
			requested_by TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
			verdict TEXT NOT NULL DEFAULT '', confidence TEXT NOT NULL DEFAULT '', report TEXT NOT NULL DEFAULT '',
			transcript TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', tool_calls INTEGER NOT NULL DEFAULT 0,
			usage TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)`,
		`INSERT INTO alert_triage(alert_id, status, trigger, created_at) VALUES('a1', 'queued', 'auto', '2026-10-20T00:00:00.000000Z')`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tr, err := s.GetTriage(ctx, "a1")
	if err != nil || tr.Engine != EngineAPI {
		t.Fatalf("old row after migration: %+v %v", tr, err)
	}
	if n, _ := s.CountQueuedTriages(ctx, EngineAPI); n != 1 {
		t.Fatalf("queued api: %d", n)
	}
	var tokens sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE name = 'mcp_tokens'`).Scan(&tokens); err != nil {
		t.Fatalf("mcp_tokens table: %v", err)
	}
}
