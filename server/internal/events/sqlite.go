package events

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
	"modernc.org/sqlite"
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

// column qualifies names: pipelines join json_each, whose id and type columns would
// otherwise clash with the events table's.
func (sqliteDialect) column(c *Column) string { return "events." + c.Name }

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
	return "EXISTS (SELECT 1 FROM json_each(" + col + ") WHERE lower(value) = lower(?))", []any{value}
}

func (sqliteDialect) arrayLike(col, pattern string) (string, []any) {
	return "EXISTS (SELECT 1 FROM json_each(" + col + ") WHERE value LIKE ? ESCAPE '\\')", []any{pattern}
}

func (sqliteDialect) like(expr string) string { return expr + " LIKE ? ESCAPE '\\'" }

var sqlitePlainRefs = func() map[string]bool {
	m := map[string]bool{"raw": true}
	for i := range Columns {
		m[sqliteDialect{}.column(&Columns[i])] = true
	}
	return m
}()

// hx_num, hx_rex and hx_match are Go functions registered with SQLite (see init).
func (sqliteDialect) num(x string) string     { return "hx_num(" + x + ")" }
func (sqliteDialect) float(x string) string   { return x }
func (sqliteDialect) str(x string) string     { return "CAST(" + x + " AS TEXT)" }
func (sqliteDialect) integer(x string) string { return "CAST(" + x + " AS INTEGER)" }
func (sqliteDialect) epoch(ts string) string  { return "(" + ts + " / 1000.0)" }
func (sqliteDialect) bucket(ts string, ms int64) string {
	m := strconv.FormatInt(ms, 10)
	return "((" + ts + " / " + m + ") * " + m + ")"
}
func (sqliteDialect) concat(a, b string) string { return "(" + a + " || " + b + ")" }
func (sqliteDialect) div(a, b string) string {
	return "(CAST(" + a + " AS REAL) / nullif(" + b + ", 0))"
}
func (sqliteDialect) mod(a, b string) string { return "(" + a + " % nullif(" + b + ", 0))" }
func (sqliteDialect) strLen(x string) string { return "length(" + x + ")" }
func (sqliteDialect) substr(s, start, n string) string {
	if n == "" {
		return "substr(" + s + ", " + start + ")"
	}
	return "substr(" + s + ", " + start + ", " + n + ")"
}
func (sqliteDialect) rexGroup(s string, g int) string {
	return "hx_rex(" + s + ", ?, " + strconv.Itoa(g) + ")"
}
func (sqliteDialect) rexMatch(s string) string { return "hx_match(" + s + ", ?)" }
func (sqliteDialect) ilike(a, b string) string { return "(" + a + " LIKE " + b + " ESCAPE '\\')" }
func (sqliteDialect) arrayStr(a string) string {
	return "(SELECT group_concat(value, ',') FROM json_each(" + a + "))"
}
func (sqliteDialect) arrayHas(arr, v string) string {
	return "EXISTS (SELECT 1 FROM json_each(" + arr + ") WHERE lower(value) = lower(" + v + "))"
}
func (sqliteDialect) arrayNonEmpty(a string) string { return "(json_array_length(" + a + ") > 0)" }
func (sqliteDialect) explode(arr, alias string) (string, string) {
	if aliasRe.MatchString(arr) {
		arr = "events." + arr
	}
	return alias + ".value", ", json_each(" + arr + ") AS " + alias
}
func (sqliteDialect) values(x string) string { return "json_group_array(DISTINCT " + x + ")" }
func (sqliteDialect) boolean(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
func (sqliteDialect) plainRef(s string) bool { return sqlitePlainRefs[s] }

func init() {
	sqlite.MustRegisterDeterministicScalarFunction("hx_num", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		switch v := args[0].(type) {
		case int64, float64:
			return v, nil
		case string:
			return parseNumber(v), nil
		case []byte:
			return parseNumber(string(v)), nil
		}
		return nil, nil
	})
	sqlite.MustRegisterDeterministicScalarFunction("hx_rex", 3, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		re, err := cachedRegexp(args[1])
		if err != nil {
			return nil, err
		}
		g, _ := args[2].(int64)
		m := re.FindStringSubmatch(textArg(args[0]))
		if int(g) >= len(m) || g < 0 {
			return "", nil
		}
		return m[g], nil
	})
	sqlite.MustRegisterDeterministicScalarFunction("hx_match", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		re, err := cachedRegexp(args[1])
		if err != nil {
			return nil, err
		}
		if re.MatchString(textArg(args[0])) {
			return int64(1), nil
		}
		return int64(0), nil
	})
}

func parseNumber(s string) driver.Value {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return f
}

func textArg(v driver.Value) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

var rexCache struct {
	sync.Mutex
	m map[string]*regexp.Regexp
}

func cachedRegexp(p driver.Value) (*regexp.Regexp, error) {
	pattern := textArg(p)
	rexCache.Lock()
	defer rexCache.Unlock()
	if re, ok := rexCache.m[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	if rexCache.m == nil || len(rexCache.m) >= 64 {
		rexCache.m = map[string]*regexp.Regexp{}
	}
	rexCache.m[pattern] = re
	return re, nil
}

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
			e, a := sqliteDialect{}.arrayEq("events.category", c)
			ors = append(ors, e)
			args = append(args, a...)
		}
		parts = append(parts, "("+strings.Join(ors, " OR ")+")")
	}
	return strings.Join(parts, " AND "), args, nil
}

// Search runs a search.
func (s *SQLite) Search(ctx context.Context, q SearchQuery) (*SearchResult, error) {
	return search(ctx, s, q)
}

func (s *SQLite) pd() pipeDialect   { return sqliteDialect{} }
func (s *SQLite) tableName() string { return "events" }

func (s *SQLite) userError(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() & 0xff {
	case 1, 20, 25: // SQLITE_ERROR, SQLITE_MISMATCH, SQLITE_RANGE
		return true
	}
	return false
}

func (s *SQLite) rows(ctx context.Context, query string, args ...any) ([][]any, error) {
	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			vals[i] = normalize(v)
		}
		out = append(out, vals)
	}
	return out, rows.Err()
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

// Size returns the bytes of the database pages in use (free pages excluded).
func (s *SQLite) Size(ctx context.Context) (int64, error) {
	var pages, free, pageSize int64
	for _, q := range []struct {
		pragma string
		dst    *int64
	}{{"page_count", &pages}, {"freelist_count", &free}, {"page_size", &pageSize}} {
		if err := s.w.QueryRowContext(ctx, "PRAGMA "+q.pragma).Scan(q.dst); err != nil {
			return 0, err
		}
	}
	return (pages - free) * pageSize, nil
}

// TrimToSize deletes the oldest events in steps until the pages in use fit in maxBytes,
// then returns the freed pages to the file system.
func (s *SQLite) TrimToSize(ctx context.Context, maxBytes int64) (time.Time, error) {
	var cutoff time.Time
	for range 1000 {
		size, err := s.Size(ctx)
		if err != nil || size <= maxBytes {
			break
		}
		var count int64
		if err := s.w.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&count); err != nil {
			return cutoff, err
		}
		if count == 0 {
			break
		}
		// Delete roughly the share of rows that is over the cap (at least 1%).
		n := max(count*(size-maxBytes)/size, count/100, 1)
		var ts int64
		if err := s.w.QueryRowContext(ctx, `SELECT ts FROM events ORDER BY ts LIMIT 1 OFFSET ?`, min(n, count)-1).Scan(&ts); err != nil {
			return cutoff, err
		}
		if err := s.Purge(ctx, time.UnixMilli(ts+1)); err != nil {
			return cutoff, err
		}
		cutoff = time.UnixMilli(ts + 1).UTC()
	}
	return cutoff, nil
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
