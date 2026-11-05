package events

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// ConnTimesQuery asks for the connection times of devices talking to the internet.
type ConnTimesQuery struct {
	From, To time.Time
	Modules  []string // event.module any-of
	// MinCount skips pairs with fewer connections.
	MinCount int
	// MaxSeries caps the pairs returned, busiest first; MaxTimes caps the times per pair.
	MaxSeries, MaxTimes int
}

// ConnSeries is one source's connections to one destination and port.
type ConnSeries struct {
	Source, Destination, Transport string
	Port                           int
	// Count is all the connections in the range; Times holds the newest MaxTimes, oldest first.
	Count int64
	// SourcePorts is how many different source ports were used. A connection reported in
	// parts by an exporter's timers keeps its one port; new connections get new ones.
	SourcePorts int64
	Times       []time.Time
}

const (
	maxConnSeries = 5000
	maxConnTimes  = 240
)

func (q ConnTimesQuery) limits() (series, times, minCount int) {
	series, times, minCount = q.MaxSeries, q.MaxTimes, q.MinCount
	if series <= 0 || series > maxConnSeries {
		series = maxConnSeries
	}
	if times <= 0 || times > maxConnTimes {
		times = maxConnTimes
	}
	if minCount < 1 {
		minCount = 1
	}
	return series, times, minCount
}

// connWhere picks private sources talking to destinations outside the common private
// ranges. Callers check addresses precisely; this keeps the firewall's own WAN rows, which
// are most of its log, out of the grouping.
const connWhere = `ts >= ? AND ts < ? AND module IN %s
	AND (source_ip LIKE '10.%%' OR source_ip LIKE '192.168.%%' OR source_ip LIKE '172.%%' OR source_ip LIKE 'fd%%')
	AND destination_ip != '' AND destination_ip NOT LIKE '10.%%' AND destination_ip NOT LIKE '192.168.%%'
	AND destination_port > 0`

// ConnTimes returns connection times per source, destination, port and transport.
func (s *SQLite) ConnTimes(ctx context.Context, q ConnTimesQuery) ([]ConnSeries, error) {
	if len(q.Modules) == 0 {
		return nil, nil
	}
	maxSeries, maxTimes, minCount := q.limits()
	marks := "("
	args := []any{q.From.UTC().UnixMilli(), q.To.UTC().UnixMilli()}
	for i, m := range q.Modules {
		if i > 0 {
			marks += ","
		}
		marks += "?"
		args = append(args, m)
	}
	marks += ")"
	where := fmt.Sprintf(connWhere, marks)
	rows, err := s.r.QueryContext(ctx, `SELECT source_ip, destination_ip, destination_port, transport, count(*) AS n, count(DISTINCT source_port) AS sp FROM events
		WHERE `+where+` GROUP BY source_ip, destination_ip, destination_port, transport HAVING n >= ? ORDER BY n DESC LIMIT ?`,
		append(args, minCount, maxSeries)...)
	if err != nil {
		return nil, err
	}
	var out []ConnSeries
	for rows.Next() {
		var c ConnSeries
		if err := rows.Scan(&c.Source, &c.Destination, &c.Port, &c.Transport, &c.Count, &c.SourcePorts); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		c := &out[i]
		trows, err := s.r.QueryContext(ctx, `SELECT ts FROM events WHERE source_ip = ? AND destination_ip = ? AND destination_port = ?
			AND transport = ? AND ts >= ? AND ts < ? ORDER BY ts DESC LIMIT ?`,
			c.Source, c.Destination, c.Port, c.Transport, q.From.UTC().UnixMilli(), q.To.UTC().UnixMilli(), maxTimes)
		if err != nil {
			return nil, err
		}
		for trows.Next() {
			var ms int64
			if err := trows.Scan(&ms); err != nil {
				trows.Close()
				return nil, err
			}
			c.Times = append(c.Times, time.UnixMilli(ms).UTC())
		}
		trows.Close()
		if err := trows.Err(); err != nil {
			return nil, err
		}
		sort.Slice(c.Times, func(a, b int) bool { return c.Times[a].Before(c.Times[b]) })
	}
	return out, nil
}

// ConnTimes returns connection times per source, destination, port and transport. It runs
// under the same memory cap as a search; groupArraySorted holds at most MaxTimes per pair.
func (c *ClickHouse) ConnTimes(ctx context.Context, q ConnTimesQuery) ([]ConnSeries, error) {
	if len(q.Modules) == 0 {
		return nil, nil
	}
	maxSeries, maxTimes, minCount := q.limits()
	query := `SELECT source_ip, destination_ip, destination_port, transport, count() AS n, uniqExact(source_port) AS sp,
		groupArraySorted(` + strconv.Itoa(maxTimes) + `)(-toUnixTimestamp64Milli(ts)) AS t FROM ` + c.table + `
		WHERE ` + fmt.Sprintf(connWhere, "?") + `
		GROUP BY source_ip, destination_ip, destination_port, transport HAVING n >= ? ORDER BY n DESC LIMIT ?`
	rows, err := c.conn.Query(clickhouse.Context(ctx, clickhouse.WithSettings(searchSettings)), query,
		q.From.UTC(), q.To.UTC(), q.Modules, uint64(minCount), maxSeries)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnSeries
	for rows.Next() {
		var cs ConnSeries
		var port int64
		var n, sp uint64
		var times []int64
		if err := rows.Scan(&cs.Source, &cs.Destination, &port, &cs.Transport, &n, &sp, &times); err != nil {
			return nil, err
		}
		cs.Port, cs.Count, cs.SourcePorts = int(port), int64(n), int64(sp)
		cs.Times = make([]time.Time, len(times))
		for i, neg := range times { // newest first, negated: reverse into oldest first
			cs.Times[len(times)-1-i] = time.UnixMilli(-neg).UTC()
		}
		out = append(out, cs)
	}
	return out, rows.Err()
}
