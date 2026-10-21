// Package store is the server's state database (SQLite): users, sessions, hosts,
// enrollment tokens, alerts, commands, hunts, rule settings and the audit log.
// Telemetry lives in package events, not here.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a uniqueness or state rule is violated.
var ErrConflict = errors.New("conflict")

// Store is the state database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY between our own
	// goroutines. State traffic is small enough that this is not a bottleneck.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	hostname TEXT NOT NULL,
	platform TEXT NOT NULL DEFAULT '',
	info TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL DEFAULT '{}',
	labels TEXT NOT NULL DEFAULT '[]',
	enrolled_at TEXT NOT NULL,
	last_seen TEXT,
	revoked INTEGER NOT NULL DEFAULT 0,
	isolated INTEGER NOT NULL DEFAULT 0,
	cert_serial TEXT NOT NULL DEFAULT '',
	source_ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS hosts_source_ip ON hosts(source_ip);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	expires_at TEXT,
	max_uses INTEGER,
	uses INTEGER NOT NULL DEFAULT 0,
	labels TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS alerts (
	id TEXT PRIMARY KEY,
	dedup_key TEXT NOT NULL,
	rule_id TEXT NOT NULL,
	rule TEXT NOT NULL,
	mitre TEXT NOT NULL DEFAULT '[]',
	severity TEXT NOT NULL,
	risk_score INTEGER NOT NULL,
	status TEXT NOT NULL,
	assignee TEXT NOT NULL DEFAULT '',
	host_id TEXT NOT NULL,
	hostname TEXT NOT NULL DEFAULT '',
	process_entity_id TEXT NOT NULL DEFAULT '',
	process_name TEXT NOT NULL DEFAULT '',
	command_line TEXT NOT NULL DEFAULT '',
	user_name TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	count INTEGER NOT NULL DEFAULT 1,
	event_ids TEXT NOT NULL DEFAULT '[]',
	event TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_dedup ON alerts(dedup_key, status);
CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS alerts_host ON alerts(host_id, status);
CREATE INDEX IF NOT EXISTS alerts_entity ON alerts(process_entity_id);
CREATE TABLE IF NOT EXISTS commands (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	type TEXT NOT NULL,
	params TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL,
	issued_by TEXT NOT NULL,
	issued_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	delivered_at TEXT,
	completed_at TEXT,
	error TEXT NOT NULL DEFAULT '',
	output TEXT NOT NULL DEFAULT '',
	row_count INTEGER NOT NULL DEFAULT 0,
	hunt_id TEXT NOT NULL DEFAULT '',
	upload_path TEXT NOT NULL DEFAULT '',
	upload_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS commands_host ON commands(host_id, status);
CREATE INDEX IF NOT EXISTS commands_hunt ON commands(hunt_id);
CREATE TABLE IF NOT EXISTS command_rows (
	command_id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	host_id TEXT NOT NULL,
	hunt_id TEXT NOT NULL DEFAULT '',
	row TEXT NOT NULL,
	PRIMARY KEY (command_id, seq)
);
CREATE INDEX IF NOT EXISTS command_rows_hunt ON command_rows(hunt_id);
CREATE TABLE IF NOT EXISTS hunts (
	id TEXT PRIMARY KEY,
	artifact TEXT NOT NULL,
	params TEXT NOT NULL DEFAULT '{}',
	description TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL,
	created_by TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
	id TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	yaml TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id TEXT PRIMARY KEY,
	at TEXT NOT NULL,
	user TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
CREATE TABLE IF NOT EXISTS kv (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema+triageSchema+mcpTokenSchema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	for _, m := range triageMigrations {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('alert_triage') WHERE name = ?`, m.column).Scan(&n); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
		if n == 0 {
			if _, err := s.db.ExecContext(ctx, m.ddl); err != nil {
				return fmt.Errorf("store: migrate %s: %w", m.column, err)
			}
		}
	}
	return nil
}

// tsLayout is fixed-width so timestamps sort lexically.
const tsLayout = "2006-01-02T15:04:05.000000Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func nullTS(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return ts(*t)
}

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, s)
	}
	return t
}

func parseNullTS(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := parseTS(ns.String)
	return &t
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func unmarshalJSON(s string, v any) {
	if s == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}

// GetKV reads a value from the key/value table into v. It returns ErrNotFound if absent.
func (s *Store) GetKV(ctx context.Context, key string, v any) error {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM kv WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), v)
}

// SetKV stores v as JSON under key.
func (s *Store) SetKV(ctx context.Context, key string, v any) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, mustJSON(v))
	return err
}

// clampLimit applies the API's default and maximum page sizes.
func clampLimit(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
