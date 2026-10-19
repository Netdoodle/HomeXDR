package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
	_ "modernc.org/sqlite"
)

// SQLite is the lite-mode event store. Times are stored as Unix milliseconds and array
// columns as JSON arrays.
type SQLite struct {
	w *sql.DB // single writer connection
	r *sql.DB // reader pool
}

// OpenSQLite opens or creates an event database at path.
func OpenSQLite(path string) (*SQLite, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "auto_vacuum(INCREMENTAL)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + path + "?" + q.Encode()
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	s := &SQLite{w: w}
	if err := s.migrate(); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	s.r = r
	return s, nil
}

func (s *SQLite) migrate() error {
	var cols []string
	for _, c := range Columns {
		typ := "TEXT NOT NULL DEFAULT ''"
		switch c.Kind {
		case KInt, KTime:
			typ = "INTEGER NOT NULL DEFAULT 0"
		case KArray:
			typ = "TEXT NOT NULL DEFAULT '[]'"
		}
		cols = append(cols, c.Name+" "+typ)
	}
	cols = append(cols, "raw TEXT NOT NULL")
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS events (` + strings.Join(cols, ", ") + `)`,
		`CREATE INDEX IF NOT EXISTS events_ts ON events(ts)`,
		`CREATE INDEX IF NOT EXISTS events_host_ts ON events(host_id, ts)`,
		`CREATE INDEX IF NOT EXISTS events_id ON events(id)`,
		`CREATE INDEX IF NOT EXISTS events_entity ON events(process_entity_id)`,
		`CREATE INDEX IF NOT EXISTS events_parent ON events(parent_entity_id)`,
		`CREATE INDEX IF NOT EXISTS events_cid ON events(community_id) WHERE community_id != ''`,
	}
	for _, st := range stmts {
		if _, err := s.w.Exec(st); err != nil {
			return fmt.Errorf("events: sqlite migrate: %w", err)
		}
	}
	return nil
}

// Close closes the database.
func (s *SQLite) Close() error {
	s.r.Close()
	return s.w.Close()
}

// Ping checks the database.
func (s *SQLite) Ping(ctx context.Context) error { return s.r.PingContext(ctx) }

var sqliteInsert = func() string {
	names := make([]string, 0, len(Columns)+1)
	for _, c := range Columns {
		names = append(names, c.Name)
	}
	names = append(names, "raw")
	return `INSERT INTO events (` + strings.Join(names, ", ") + `) VALUES (` +
		strings.TrimSuffix(strings.Repeat("?,", len(names)), ",") + `)`
}()

func sqliteValue(c *Column, e *event.Event) any {
	v := c.Get(e)
	switch c.Kind {
	case KTime:
		return v.(time.Time).UnixMilli()
	case KArray:
		b, _ := json.Marshal(v)
		return string(b)
	}
	return v
}

// Insert stores events in one transaction.
func (s *SQLite) Insert(ctx context.Context, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, sqliteInsert)
	if err != nil {
		return err
	}
	defer stmt.Close()
	args := make([]any, len(Columns)+1)
	for _, e := range evs {
		for i := range Columns {
			args[i] = sqliteValue(&Columns[i], e)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		args[len(Columns)] = string(raw)
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type sqliteDialect struct{}

func (sqliteDialect) column(c *Column) string { return c.Name }

func (sqliteDialect) jsonPath(path []string) string {
	var b strings.Builder
	b.WriteString("$")
	for _, p := range path {
		b.WriteString(`."`)
		b.WriteString(strings.ReplaceAll(p, `"`, ``))
		b.WriteString(`"`)
	}
	return b.String()
}

func (d sqliteDialect) jsonString(path []string) (string, []any) {
	return "COALESCE(CAST(json_extract(raw, ?) AS TEXT), '')", []any{d.jsonPath(path)}
}

func (d sqliteDialect) jsonNumber(path []string) (string, []any) {
	return "CAST(json_extract(raw, ?) AS REAL)", []any{d.jsonPath(path)}
}

func (sqliteDialect) arrayEq(col, value string) (string, []any) {
	return "EXISTS (SELECT 1 FROM json_each(events." + col + ") WHERE lower(value) = lower(?))", []any{value}
}

func (sqliteDialect) arrayLike(col, pattern string) (string, []any) {
	return "EXISTS (SELECT 1 FROM json_each(events." + col + ") WHERE value LIKE ? ESCAPE '\\')", []any{pattern}
}

func (sqliteDialect) like(expr string) string { return expr + " LIKE ? ESCAPE '\\'" }

func (s *SQLite) where(q SearchQuery) (string, []any, error) {
	n, err := ParseQuery(q.Query)
	if err != nil {
		return "", nil, err
	}
	cond, args, err := compile(n, sqliteDialect{})
	if err != nil {
		return "", nil, err
	}
	parts := []string{"(" + cond + ")"}
	if !q.From.IsZero() {
		parts = append(parts, "ts >= ?")
		args = append(args, q.From.UnixMilli())
	}
	if !q.To.IsZero() {
		parts = append(parts, "ts < ?")
		args = append(args, q.To.UnixMilli())
	}
	if q.HostID != "" {
		parts = append(parts, "host_id = ?")
		args = append(args, q.HostID)
	}
	if len(q.HostIDs) > 0 {
		parts = append(parts, "host_id IN ("+marks(len(q.HostIDs))+")")
		args = append(args, anys(q.HostIDs)...)
	}
	if q.EntityID != "" {
		parts = append(parts, "process_entity_id = ?")
		args = append(args, q.EntityID)
	}
	if len(q.Categories) > 0 {
		var ors []string
		for _, c := range q.Categories {
			if c == CategoryDNS {
				ors = append(ors, "dns_question != ''")
				continue
			}
			e, a := sqliteDialect{}.arrayEq("category", c)
			ors = append(ors, e)
			args = append(args, a...)
		}
		parts = append(parts, "("+strings.Join(ors, " OR ")+")")
	}
	return strings.Join(parts, " AND "), args, nil
}

// Search runs a query.
func (s *SQLite) Search(ctx context.Context, q SearchQuery) (*SearchResult, error) {
	start := time.Now()
	where, args, err := s.where(q)
	if err != nil {
		return nil, &QueryError{Err: err}
	}
	limit, offset := clamp(q.Limit, q.Offset)
	order := "DESC"
	if q.Asc {
		order = "ASC"
	}
	res := &SearchResult{Events: []*event.Event{}}
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&res.Total); err != nil {
		return nil, err
	}
	evs, err := s.queryRaw(ctx, `SELECT raw FROM events WHERE `+where+` ORDER BY ts `+order+`, id `+order+` LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	res.Events = evs
	res.TookMs = time.Since(start).Milliseconds()
	return res, nil
}

func (s *SQLite) queryRaw(ctx context.Context, query string, args ...any) ([]*event.Event, error) {
	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*event.Event{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e event.Event
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			continue
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// Get returns one event.
func (s *SQLite) Get(ctx context.Context, id string) (*event.Event, error) {
	evs, err := s.queryRaw(ctx, `SELECT raw FROM events WHERE id = ? LIMIT 1`, id)
	if err != nil {
		return nil, err
	}
	if len(evs) == 0 {
		return nil, ErrNotFound
	}
	return evs[0], nil
}

// GetMany returns events by ID.
func (s *SQLite) GetMany(ctx context.Context, ids []string) ([]*event.Event, error) {
	if len(ids) == 0 {
		return []*event.Event{}, nil
	}
	return s.queryRaw(ctx, `SELECT raw FROM events WHERE id IN (`+marks(len(ids))+`) ORDER BY ts`, anys(ids)...)
}

// ProcessEvents returns process lifecycle events for entities.
func (s *SQLite) ProcessEvents(ctx context.Context, hostID string, entityIDs []string) ([]*event.Event, error) {
	if len(entityIDs) == 0 {
		return []*event.Event{}, nil
	}
	return s.queryRaw(ctx,
		`SELECT raw FROM events WHERE host_id = ? AND process_entity_id IN (`+marks(len(entityIDs))+`)
		 AND EXISTS (SELECT 1 FROM json_each(events.category) WHERE value = 'process') ORDER BY ts`,
		append([]any{hostID}, anys(entityIDs)...)...)
}

// Children returns child process start events.
func (s *SQLite) Children(ctx context.Context, hostID string, parentIDs []string, limit int) ([]*event.Event, error) {
	if len(parentIDs) == 0 {
		return []*event.Event{}, nil
	}
	args := append([]any{hostID}, anys(parentIDs)...)
	return s.queryRaw(ctx,
		`SELECT raw FROM events WHERE host_id = ? AND parent_entity_id IN (`+marks(len(parentIDs))+`)
		 AND EXISTS (SELECT 1 FROM json_each(events.category) WHERE value = 'process')
		 AND EXISTS (SELECT 1 FROM json_each(events.type) WHERE value = 'start') ORDER BY ts LIMIT ?`,
		append(args, limit)...)
}

// EntityCounts returns per-entity category counts.
func (s *SQLite) EntityCounts(ctx context.Context, hostID string, entityIDs []string) (map[string]map[string]int64, error) {
	out := map[string]map[string]int64{}
	if len(entityIDs) == 0 {
		return out, nil
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT e.process_entity_id, CASE WHEN e.dns_question != '' THEN 'dns' ELSE j.value END, COUNT(DISTINCT e.id)
		 FROM events e, json_each(e.category) j
		 WHERE e.host_id = ? AND e.process_entity_id IN (`+marks(len(entityIDs))+`) AND j.value != 'process'
		 GROUP BY 1, 2`, append([]any{hostID}, anys(entityIDs)...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, cat string
		var n int64
		if err := rows.Scan(&id, &cat, &n); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]int64{}
		}
		out[id][cat] = n
	}
	return out, rows.Err()
}

// Stats returns dashboard counts.
func (s *SQLite) Stats(ctx context.Context, from, to time.Time) (*Stats, error) {
	st := &Stats{Timeline: []TimeCount{}, Categories: []CategoryCount{}}
	f, t := from.UnixMilli(), to.UnixMilli()
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ?`, f, t).Scan(&st.Total); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT (ts / 3600000) * 3600000 AS h, COUNT(*) FROM events WHERE ts >= ? AND ts < ? GROUP BY h ORDER BY h`, f, t)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h, n int64
		if err := rows.Scan(&h, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.Timeline = append(st.Timeline, TimeCount{T: time.UnixMilli(h).UTC(), Count: n})
	}
	rows.Close()
	rows, err = s.r.QueryContext(ctx,
		`SELECT j.value, COUNT(*) AS n FROM events e, json_each(e.category) j WHERE e.ts >= ? AND e.ts < ?
		 GROUP BY j.value ORDER BY n DESC`, f, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		st.Categories = append(st.Categories, c)
	}
	return st, rows.Err()
}

// Scan visits events newest first.
func (s *SQLite) Scan(ctx context.Context, from, to time.Time, limit int, fn func(*event.Event) bool) error {
	const page = 1000
	cursor := to.UnixMilli()
	seen := 0
	lastID := "~"
	for seen < limit {
		n := page
		if limit-seen < n {
			n = limit - seen
		}
		rows, err := s.r.QueryContext(ctx,
			`SELECT ts, id, raw FROM events WHERE ts >= ? AND (ts < ? OR (ts = ? AND id < ?))
			 ORDER BY ts DESC, id DESC LIMIT ?`, from.UnixMilli(), cursor, cursor, lastID, n)
		if err != nil {
			return err
		}
		got := 0
		stop := false
		for rows.Next() {
			var tsv int64
			var id, raw string
			if err := rows.Scan(&tsv, &id, &raw); err != nil {
				rows.Close()
				return err
			}
			got++
			seen++
			cursor, lastID = tsv, id
			var e event.Event
			if json.Unmarshal([]byte(raw), &e) == nil && !fn(&e) {
				stop = true
				break
			}
		}
		rows.Close()
		if stop || got < n {
			return nil
		}
	}
	return nil
}

// Purge deletes events older than before, in chunks.
func (s *SQLite) Purge(ctx context.Context, before time.Time) error {
	for {
		res, err := s.w.ExecContext(ctx,
			`DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE ts < ? LIMIT 5000)`, before.UnixMilli())
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	_, err := s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	return err
}

// QueryError wraps an invalid user query so handlers can return 400.
type QueryError struct{ Err error }

func (e *QueryError) Error() string { return "invalid query: " + e.Err.Error() }
func (e *QueryError) Unwrap() error { return e.Err }

// IsQueryError reports whether err is a user query error.
func IsQueryError(err error) bool {
	var qe *QueryError
	return errors.As(err, &qe)
}

func marks(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

func anys(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
