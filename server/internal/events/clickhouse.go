package events

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/Netdoodle/homexdr/shared/event"
)

// ClickHouse is the default event store. Time-based retention uses a table TTL; the
// size cap drops whole daily partitions, oldest first.
type ClickHouse struct {
	conn  driver.Conn
	db    string
	table string // `db`.`events`
}

var identRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// lowCardinality columns repeat a small set of values.
var lowCardinality = map[string]bool{
	"host_id": true, "host_name": true, "platform": true, "kind": true, "action": true, "module": true,
	"dataset": true, "provider": true, "code": true, "outcome": true, "process_name": true,
	"parent_name": true, "user_name": true, "transport": true, "direction": true,
}

// OpenClickHouse connects using a DSN such as
// clickhouse://user:pass@clickhouse:9000/homexdr, creating the database and table.
// retentionDays 0 means no time limit.
func OpenClickHouse(ctx context.Context, dsn string, retentionDays int) (*ClickHouse, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("events: clickhouse dsn: %w", err)
	}
	db := opts.Auth.Database
	if db == "" {
		db = "homexdr"
	}
	if !identRe.MatchString(db) {
		return nil, fmt.Errorf("events: invalid clickhouse database name %q", db)
	}
	opts.Auth.Database = ""
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for i := 0; i < 30; i++ { // ClickHouse may still be starting
		if lastErr = conn.Ping(ctx); lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("events: clickhouse ping: %w", lastErr)
	}
	c := &ClickHouse{conn: conn, db: db, table: "`" + db + "`.`events`"}
	if err := c.migrate(ctx, db, retentionDays); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *ClickHouse) migrate(ctx context.Context, db string, days int) error {
	var cols []string
	for _, col := range Columns {
		typ := "String"
		switch col.Kind {
		case KInt:
			typ = "Int64"
		case KTime:
			typ = "DateTime64(3, 'UTC')"
		case KArray:
			typ = "Array(LowCardinality(String))"
		default:
			if lowCardinality[col.Name] {
				typ = "LowCardinality(String)"
			}
		}
		cols = append(cols, "`"+col.Name+"` "+typ)
	}
	cols = append(cols, "`raw` String CODEC(ZSTD(3))",
		"INDEX idx_id id TYPE bloom_filter GRANULARITY 4",
		"INDEX idx_entity process_entity_id TYPE bloom_filter GRANULARITY 4",
		"INDEX idx_parent parent_entity_id TYPE bloom_filter GRANULARITY 4",
		"INDEX idx_cid community_id TYPE bloom_filter GRANULARITY 4")
	ttl, ttlClause := "", ""
	if days > 0 {
		ttl = fmt.Sprintf("toDateTime(ts) + INTERVAL %d DAY", days)
		ttlClause = "TTL " + ttl + " "
	}
	stmts := []string{
		"CREATE DATABASE IF NOT EXISTS `" + db + "`",
		"CREATE TABLE IF NOT EXISTS " + c.table + " (" + strings.Join(cols, ", ") + `)
		 ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (host_id, ts)
		 ` + ttlClause + `SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,
	}
	for _, st := range stmts {
		if err := c.conn.Exec(ctx, st); err != nil {
			return fmt.Errorf("events: clickhouse migrate: %w", err)
		}
	}
	// Bring an existing table's TTL in line with the current setting.
	var create string
	if err := c.conn.QueryRow(ctx, "SELECT create_table_query FROM system.tables WHERE database = ? AND name = 'events'", db).Scan(&create); err != nil {
		return fmt.Errorf("events: clickhouse migrate: %w", err)
	}
	var alter string
	switch hasTTL := strings.Contains(create, " TTL "); {
	case ttl != "":
		alter = "ALTER TABLE " + c.table + " MODIFY TTL " + ttl + " SETTINGS materialize_ttl_after_modify = 0"
	case hasTTL:
		alter = "ALTER TABLE " + c.table + " REMOVE TTL"
	}
	if alter != "" {
		if err := c.conn.Exec(ctx, alter); err != nil {
			return fmt.Errorf("events: clickhouse migrate: %w", err)
		}
	}
	return nil
}

// Close closes the connection.
func (c *ClickHouse) Close() error { return c.conn.Close() }

// Ping checks the connection.
func (c *ClickHouse) Ping(ctx context.Context) error { return c.conn.Ping(ctx) }

// Insert sends one batch.
func (c *ClickHouse) Insert(ctx context.Context, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO "+c.table)
	if err != nil {
		return err
	}
	vals := make([]any, len(Columns)+1)
	for _, e := range evs {
		for i := range Columns {
			vals[i] = Columns[i].Get(e)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			batch.Abort()
			return err
		}
		vals[len(Columns)] = string(raw)
		if err := batch.Append(vals...); err != nil {
			batch.Abort()
			return err
		}
	}
	return batch.Send()
}

type chDialect struct{}

func (chDialect) column(c *Column) string { return "`" + c.Name + "`" }

func chPath(path []string) (string, []any) {
	args := make([]any, len(path))
	for i, p := range path {
		args[i] = p
	}
	return strings.TrimSuffix(strings.Repeat("?, ", len(path)), ", "), args
}

func (chDialect) jsonString(path []string) (string, []any) {
	p, a := chPath(path)
	expr := "if(JSONType(raw, " + p + ") = 'String', JSONExtractString(raw, " + p + "), JSONExtractRaw(raw, " + p + "))"
	args := append(append(append([]any{}, a...), a...), a...)
	return expr, args
}

func (chDialect) jsonNumber(path []string) (string, []any) {
	p, a := chPath(path)
	return "toFloat64OrNull(trim(BOTH '\"' FROM JSONExtractRaw(raw, " + p + ")))", a
}

func (chDialect) arrayEq(col, value string) (string, []any) {
	return "has(arrayMap(x -> lower(x), " + col + "), lower(?))", []any{value}
}

func (chDialect) arrayLike(col, pattern string) (string, []any) {
	return "arrayExists(x -> x ILIKE ?, " + col + ")", []any{pattern}
}

func (chDialect) like(expr string) string { return expr + " ILIKE ?" }

func (c *ClickHouse) where(q SearchQuery) (string, []any, error) {
	n, err := ParseQuery(q.Query)
	if err != nil {
		return "", nil, err
	}
	cond, args, err := compile(n, chDialect{})
	if err != nil {
		return "", nil, err
	}
	parts := []string{"(" + cond + ")"}
	if !q.From.IsZero() {
		parts = append(parts, "ts >= ?")
		args = append(args, q.From.UTC())
	}
	if !q.To.IsZero() {
		parts = append(parts, "ts < ?")
		args = append(args, q.To.UTC())
	}
	if q.HostID != "" {
		parts = append(parts, "host_id = ?")
		args = append(args, q.HostID)
	}
	if len(q.HostIDs) > 0 {
		parts = append(parts, "host_id IN ?")
		args = append(args, q.HostIDs)
	}
	if q.EntityID != "" {
		parts = append(parts, "process_entity_id = ?")
		args = append(args, q.EntityID)
	}
	if len(q.Categories) > 0 {
		var cats []string
		dns := false
		for _, c := range q.Categories {
			if c == CategoryDNS {
				dns = true
			} else {
				cats = append(cats, c)
			}
		}
		var ors []string
		if len(cats) > 0 {
			ors = append(ors, "hasAny(category, ?)")
			args = append(args, cats)
		}
		if dns {
			ors = append(ors, "dns_question != ''")
		}
		parts = append(parts, "("+strings.Join(ors, " OR ")+")")
	}
	return strings.Join(parts, " AND "), args, nil
}

// Search runs a query.
func (c *ClickHouse) Search(ctx context.Context, q SearchQuery) (*SearchResult, error) {
	start := time.Now()
	where, args, err := c.where(q)
	if err != nil {
		return nil, &QueryError{Err: err}
	}
	limit, offset := clamp(q.Limit, q.Offset)
	order := "DESC"
	if q.Asc {
		order = "ASC"
	}
	res := &SearchResult{Events: []*event.Event{}}
	var total uint64
	if err := c.conn.QueryRow(ctx, "SELECT count() FROM "+c.table+" WHERE "+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	res.Total = int64(total)
	evs, err := c.queryRaw(ctx, "SELECT raw FROM "+c.table+" WHERE "+where+
		" ORDER BY ts "+order+", id "+order+" LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	res.Events = evs
	res.TookMs = time.Since(start).Milliseconds()
	return res, nil
}

func (c *ClickHouse) queryRaw(ctx context.Context, query string, args ...any) ([]*event.Event, error) {
	rows, err := c.conn.Query(ctx, query, args...)
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
		if json.Unmarshal([]byte(raw), &e) == nil {
			out = append(out, &e)
		}
	}
	return out, rows.Err()
}

// Get returns one event.
func (c *ClickHouse) Get(ctx context.Context, id string) (*event.Event, error) {
	evs, err := c.queryRaw(ctx, "SELECT raw FROM "+c.table+" WHERE id = ? LIMIT 1", id)
	if err != nil {
		return nil, err
	}
	if len(evs) == 0 {
		return nil, ErrNotFound
	}
	return evs[0], nil
}

// GetMany returns events by ID.
func (c *ClickHouse) GetMany(ctx context.Context, ids []string) ([]*event.Event, error) {
	if len(ids) == 0 {
		return []*event.Event{}, nil
	}
	return c.queryRaw(ctx, "SELECT raw FROM "+c.table+" WHERE id IN ? ORDER BY ts", ids)
}

// ProcessEvents returns process lifecycle events for entities.
func (c *ClickHouse) ProcessEvents(ctx context.Context, hostID string, entityIDs []string) ([]*event.Event, error) {
	if len(entityIDs) == 0 {
		return []*event.Event{}, nil
	}
	return c.queryRaw(ctx, "SELECT raw FROM "+c.table+
		" WHERE host_id = ? AND process_entity_id IN ? AND has(category, 'process') ORDER BY ts", hostID, entityIDs)
}

// Children returns child process start events.
func (c *ClickHouse) Children(ctx context.Context, hostID string, parentIDs []string, limit int) ([]*event.Event, error) {
	if len(parentIDs) == 0 {
		return []*event.Event{}, nil
	}
	return c.queryRaw(ctx, "SELECT raw FROM "+c.table+
		" WHERE host_id = ? AND parent_entity_id IN ? AND has(category, 'process') AND has(type, 'start') ORDER BY ts LIMIT ?",
		hostID, parentIDs, limit)
}

// EntityCounts returns per-entity category counts.
func (c *ClickHouse) EntityCounts(ctx context.Context, hostID string, entityIDs []string) (map[string]map[string]int64, error) {
	out := map[string]map[string]int64{}
	if len(entityIDs) == 0 {
		return out, nil
	}
	rows, err := c.conn.Query(ctx, "SELECT process_entity_id, arrayJoin(if(dns_question != '', ['dns'], category)) AS cat, count() FROM "+c.table+
		" WHERE host_id = ? AND process_entity_id IN ? GROUP BY process_entity_id, cat HAVING cat != 'process'",
		hostID, entityIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, cat string
		var n uint64
		if err := rows.Scan(&id, &cat, &n); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]int64{}
		}
		out[id][cat] = int64(n)
	}
	return out, rows.Err()
}

// Stats returns dashboard counts.
func (c *ClickHouse) Stats(ctx context.Context, from, to time.Time) (*Stats, error) {
	st := &Stats{Timeline: []TimeCount{}, Categories: []CategoryCount{}}
	var total uint64
	if err := c.conn.QueryRow(ctx, "SELECT count() FROM "+c.table+" WHERE ts >= ? AND ts < ?", from.UTC(), to.UTC()).Scan(&total); err != nil {
		return nil, err
	}
	st.Total = int64(total)
	rows, err := c.conn.Query(ctx, "SELECT toStartOfHour(ts) AS h, count() FROM "+c.table+
		" WHERE ts >= ? AND ts < ? GROUP BY h ORDER BY h", from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h time.Time
		var n uint64
		if err := rows.Scan(&h, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.Timeline = append(st.Timeline, TimeCount{T: h.UTC(), Count: int64(n)})
	}
	rows.Close()
	rows, err = c.conn.Query(ctx, "SELECT arrayJoin(category) AS cat, count() AS n FROM "+c.table+
		" WHERE ts >= ? AND ts < ? GROUP BY cat ORDER BY n DESC", from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cc CategoryCount
		var n uint64
		if err := rows.Scan(&cc.Category, &n); err != nil {
			return nil, err
		}
		cc.Count = int64(n)
		st.Categories = append(st.Categories, cc)
	}
	return st, rows.Err()
}

// Scan visits events newest first.
func (c *ClickHouse) Scan(ctx context.Context, from, to time.Time, limit int, fn func(*event.Event) bool) error {
	const page = 2000
	cursor := to.UTC()
	lastID := "~"
	seen := 0
	for seen < limit {
		n := page
		if limit-seen < n {
			n = limit - seen
		}
		rows, err := c.conn.Query(ctx, "SELECT ts, id, raw FROM "+c.table+
			" WHERE ts >= ? AND (ts < ? OR (ts = ? AND id < ?)) ORDER BY ts DESC, id DESC LIMIT ?",
			from.UTC(), cursor, cursor, lastID, n)
		if err != nil {
			return err
		}
		got := 0
		stop := false
		for rows.Next() {
			var tsv time.Time
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

// Purge is a no-op: the table TTL drops old partitions.
func (c *ClickHouse) Purge(ctx context.Context, before time.Time) error { return nil }

// Size returns the compressed size of the events table's active parts.
func (c *ClickHouse) Size(ctx context.Context) (int64, error) {
	var n uint64
	err := c.conn.QueryRow(ctx,
		"SELECT sum(bytes_on_disk) FROM system.parts WHERE database = ? AND table = 'events' AND active", c.db).Scan(&n)
	return int64(n), err
}

var partitionIDRe = regexp.MustCompile(`^[0-9]{8}$`) // toYYYYMMDD(ts)

// TrimToSize drops daily partitions, oldest first, until the table fits in maxBytes.
// The newest partition (today) is never dropped.
func (c *ClickHouse) TrimToSize(ctx context.Context, maxBytes int64) (time.Time, error) {
	rows, err := c.conn.Query(ctx, `SELECT partition_id, sum(bytes_on_disk) FROM system.parts
		WHERE database = ? AND table = 'events' AND active GROUP BY partition_id ORDER BY partition_id`, c.db)
	if err != nil {
		return time.Time{}, err
	}
	type partition struct {
		id    string
		bytes uint64
	}
	var parts []partition
	var total int64
	for rows.Next() {
		var p partition
		if err := rows.Scan(&p.id, &p.bytes); err != nil {
			rows.Close()
			return time.Time{}, err
		}
		parts = append(parts, p)
		total += int64(p.bytes)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return time.Time{}, err
	}
	var cutoff time.Time
	for i := 0; i < len(parts)-1 && total > maxBytes; i++ {
		p := parts[i]
		if !partitionIDRe.MatchString(p.id) {
			return cutoff, fmt.Errorf("events: unexpected partition id %q", p.id)
		}
		day, err := time.Parse("20060102", p.id)
		if err != nil {
			return cutoff, fmt.Errorf("events: unexpected partition id %q", p.id)
		}
		// Large partitions need the drop-size guard lifted (default 50 GB).
		if err := c.conn.Exec(ctx, "ALTER TABLE "+c.table+" DROP PARTITION ID '"+p.id+"' SETTINGS max_partition_size_to_drop = 0"); err != nil {
			return cutoff, fmt.Errorf("events: drop partition %s: %w", p.id, err)
		}
		total -= int64(p.bytes)
		cutoff = day.AddDate(0, 0, 1)
	}
	if total > maxBytes && len(parts) > 0 {
		return cutoff, fmt.Errorf("events: today's events alone (%d bytes) exceed the size cap (%d bytes)", total, maxBytes)
	}
	return cutoff, nil
}
