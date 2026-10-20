package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Result limits.
const (
	maxTableRows     = 10000  // rows returned by a table result
	maxTimechartRows = 100000 // (bucket, series) rows read for a timechart
	maxBuckets       = 10000  // timechart buckets
	maxCell          = 8192   // characters of a string cell
	defaultSeries    = 8      // timechart series before OTHER (8 chart colors)
)

// backend is what the shared search code needs from a store.
type backend interface {
	pd() pipeDialect
	tableName() string
	where(q SearchQuery) (string, []any, error)
	// rows runs a query and returns its rows with values normalized to nil, int64,
	// float64, bool, string, time.Time, []string or []any.
	rows(ctx context.Context, query string, args ...any) ([][]any, error)
	// userError reports whether err is the database rejecting a query (a type error,
	// a bad regex, a resource limit), which is reported as an invalid query.
	userError(err error) bool
}

// search runs a search: a filter, optionally followed by pipeline commands.
func search(ctx context.Context, b backend, q SearchQuery) (*SearchResult, error) {
	start := time.Now()
	pl, err := ParsePipeline(q.Query)
	if err != nil {
		return nil, &QueryError{Err: err}
	}
	bq := q
	bq.Query = pl.Filter
	ws, wa, err := b.where(bq)
	if err != nil {
		return nil, &QueryError{Err: err}
	}
	where := frag{"(" + ws + ")", wa}
	p := &planner{d: b.pd()}
	r := p.base(b.tableName(), where, q.Asc)
	cmds := pl.Commands
	var tc *timechartCmd
	if n := len(cmds); n > 0 {
		if c, ok := cmds[n-1].(timechartCmd); ok {
			tc, cmds = &c, cmds[:n-1]
		}
	}
	for _, c := range cmds {
		if err := p.apply(r, c); err != nil {
			return nil, &QueryError{Err: err}
		}
	}
	res := &SearchResult{Events: []*event.Event{}, Mode: "events"}
	var rng timeRange
	if tc != nil || q.Timeline {
		if rng, err = p.findRange(ctx, b, q, where); err != nil {
			return nil, dbErr(b, err)
		}
	}
	switch {
	case tc != nil:
		err = p.timechart(ctx, b, r, *tc, rng, res)
	case r.events:
		err = p.runEvents(ctx, b, r, q, res)
	default:
		err = p.runTable(ctx, b, r, res)
	}
	if err == nil && q.Timeline {
		err = p.timeline(ctx, b, where, rng, res)
	}
	if err != nil {
		return nil, dbErr(b, err)
	}
	res.TookMs = time.Since(start).Milliseconds()
	return res, nil
}

func dbErr(b backend, err error) error {
	var qe *QueryError
	if errors.As(err, &qe) || !b.userError(err) {
		return err
	}
	return &QueryError{Err: err}
}

func (p *planner) runEvents(ctx context.Context, b backend, r *rel, q SearchQuery, res *SearchResult) error {
	limit, offset := clamp(q.Limit, q.Offset)
	cq := cat(fr("SELECT count(*) FROM "), r.from, p.whereClause(r.conds))
	rows, err := b.rows(ctx, cq.s, cq.a...)
	if err != nil {
		return err
	}
	var total int64
	if len(rows) > 0 {
		total, _ = rows[0][0].(int64)
	}
	if r.limit > 0 {
		total = min(total, int64(r.limit))
		limit = min(limit, r.limit-offset)
	}
	res.Total = total
	if limit <= 0 {
		return nil
	}
	items := []frag{fr("raw")}
	for i, c := range r.cols {
		items = append(items, cat(c.v.frag, fr(" AS _x"+strconv.Itoa(i))))
	}
	sq := cat(fr("SELECT "), joinf(items, ", "), fr(" FROM "), r.from, p.whereClause(r.conds), p.orderBy(r.order),
		fr(fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)))
	if rows, err = b.rows(ctx, sq.s, sq.a...); err != nil {
		return err
	}
	for _, row := range rows {
		raw, _ := row[0].(string)
		var e event.Event
		if json.Unmarshal([]byte(raw), &e) != nil {
			continue
		}
		res.Events = append(res.Events, &e)
		if len(r.cols) > 0 {
			m := make(map[string]any, len(r.cols))
			for i, c := range r.cols {
				m[c.name] = convert(row[i+1], c.v.typ)
			}
			res.Extra = append(res.Extra, m)
		}
	}
	return nil
}

func (p *planner) runTable(ctx context.Context, b backend, r *rel, res *SearchResult) error {
	items := make([]frag, len(r.cols))
	for i, c := range r.cols {
		items[i] = cat(c.v.frag, fr(" AS _r"+strconv.Itoa(i)))
	}
	n := maxTableRows + 1
	if r.limit > 0 && r.limit < n {
		n = r.limit
	}
	q := cat(fr("SELECT "), joinf(items, ", "), fr(" FROM "), r.from, p.whereClause(r.conds), p.orderBy(r.order), limitClause(n))
	rows, err := b.rows(ctx, q.s, q.a...)
	if err != nil {
		return err
	}
	if len(rows) > maxTableRows {
		rows, res.Truncated = rows[:maxTableRows], true
	}
	res.Mode = "table"
	for _, c := range r.cols {
		res.Columns = append(res.Columns, ResultColumn{Name: c.name, Type: c.v.typ.String()})
	}
	res.Rows = make([][]any, len(rows))
	for i, row := range rows {
		out := make([]any, len(row))
		for j, v := range row {
			out[j] = convert(v, r.cols[j].v.typ)
		}
		res.Rows[i] = out
	}
	res.Total = int64(len(rows))
	return nil
}

// timeRange is the span of a search, for timecharts and the timeline.
type timeRange struct {
	from, to time.Time
	span     time.Duration
}

var spans = []time.Duration{
	time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute,
	10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour,
	12 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour,
}

// pickSpan returns the smallest bucket size giving at most 100 buckets.
func pickSpan(d time.Duration) time.Duration {
	for _, s := range spans {
		if d/s <= 100 {
			return s
		}
	}
	return spans[len(spans)-1]
}

// findRange is the query's time range; an open start is the oldest matching event.
func (p *planner) findRange(ctx context.Context, b backend, q SearchQuery, where frag) (timeRange, error) {
	to, from := q.To, q.From
	if to.IsZero() {
		to = time.Now()
	}
	if from.IsZero() {
		ts := p.d.column(columnByField["@timestamp"])
		rows, err := b.rows(ctx, "SELECT min("+ts+") FROM "+b.tableName()+" WHERE "+where.s, where.a...)
		if err != nil {
			return timeRange{}, err
		}
		if len(rows) > 0 {
			from = toTime(rows[0][0])
		}
		if from.Unix() <= 0 {
			from = to.Add(-24 * time.Hour)
		}
	}
	if !from.Before(to) {
		to = from.Add(time.Second)
	}
	return timeRange{from: from, to: to, span: pickSpan(to.Sub(from))}, nil
}

func floorMs(t time.Time, ms int64) int64 {
	v := t.UnixMilli()
	return v - ((v%ms)+ms)%ms
}

func (p *planner) timeline(ctx context.Context, b backend, where frag, rng timeRange, res *SearchResult) error {
	ms := rng.span.Milliseconds()
	ts := p.d.column(columnByField["@timestamp"])
	rows, err := b.rows(ctx, "SELECT "+p.d.bucket(ts, ms)+" AS _b, count(*) FROM "+b.tableName()+
		" WHERE "+where.s+" GROUP BY _b", where.a...)
	if err != nil {
		return err
	}
	counts := make(map[int64]int64, len(rows))
	for _, row := range rows {
		n, _ := row[1].(int64)
		counts[toTime(row[0]).UnixMilli()] = n
	}
	res.Timeline = []TimeCount{}
	for t := floorMs(rng.from, ms); t < rng.to.UnixMilli(); t += ms {
		res.Timeline = append(res.Timeline, TimeCount{T: time.UnixMilli(t).UTC(), Count: counts[t]})
	}
	res.TimelineSpan = int64(rng.span / time.Second)
	return nil
}

func (p *planner) timechart(ctx context.Context, b backend, r *rel, c timechartCmd, rng timeRange, res *SearchResult) error {
	p.settle(r)
	tv, err := p.resolve(r, "_time")
	if err != nil || tv.typ != fTime {
		return &QueryError{Err: errors.New("timechart needs event times (_time): put it before stats, top or table")}
	}
	if c.Agg.Fn == "values" {
		return &QueryError{Err: errors.New("timechart: use count, dc, sum, avg, min or max")}
	}
	span := c.Span
	if span == 0 {
		span = rng.span
	}
	ms := span.Milliseconds()
	start, end := floorMs(rng.from, ms), rng.to.UnixMilli()
	if (end-start)/ms > maxBuckets {
		return &QueryError{Err: fmt.Errorf("timechart: span=%s gives more than %d buckets for this time range; use a larger span", span, maxBuckets)}
	}
	g := &grouped{}
	tb := p.alias("c")
	g.items = append(g.items, cat(one(func(s string) string { return p.d.bucket(s, ms) }, tv.frag), fr(" AS "+tb)))
	g.groups = append(g.groups, tb)
	if c.By != "" {
		if err := p.groupBy(r, g, []string{c.By}); err != nil {
			return &QueryError{Err: fmt.Errorf("timechart: %w", err)}
		}
	}
	f, typ, err := p.aggregate(r, c.Agg)
	if err != nil {
		return &QueryError{Err: fmt.Errorf("timechart: %w", err)}
	}
	p.add(g, c.Agg.As, f, typ)
	q := cat(p.groupSQL(r, g), limitClause(maxTimechartRows+1))
	rows, err := b.rows(ctx, q.s, q.a...)
	if err != nil {
		return err
	}
	if len(rows) > maxTimechartRows {
		rows, res.Truncated = rows[:maxTimechartRows], true
	}

	// Pivot (bucket, series, value) rows into one column per series.
	cells := map[string]map[int64]any{}
	totals := map[string]float64{}
	if c.By == "" {
		cells[c.Agg.As] = map[int64]any{}
	}
	for _, row := range rows {
		s := c.Agg.As
		if c.By != "" {
			s = fmt.Sprint(convert(row[1], fStr))
		}
		v := convert(row[len(row)-1], typ)
		if cells[s] == nil {
			cells[s] = map[int64]any{}
		}
		cells[s][toTime(row[0]).UnixMilli()] = v
		if f, ok := toFloat(v); ok {
			totals[s] += f
		}
	}
	series := make([]string, 0, len(cells))
	for s := range cells {
		series = append(series, s)
	}
	sort.Slice(series, func(i, j int) bool {
		if totals[series[i]] != totals[series[j]] {
			return totals[series[i]] > totals[series[j]]
		}
		return series[i] < series[j]
	})
	limit := c.Limit
	if limit == 0 {
		limit = defaultSeries
	}
	additive := c.Agg.Fn == "count" || c.Agg.Fn == "sum"
	zeroFill := additive || c.Agg.Fn == "dc"
	var rest []string
	if len(series) > limit {
		series, rest = series[:limit], series[limit:]
	}
	res.Mode, res.Chart = "table", "timechart"
	res.Columns = []ResultColumn{{Name: "_time", Type: "time"}}
	for _, s := range series {
		res.Columns = append(res.Columns, ResultColumn{Name: s, Type: "number"})
	}
	other := additive && len(rest) > 0
	if other {
		res.Columns = append(res.Columns, ResultColumn{Name: "OTHER", Type: "number"})
	}
	res.Rows = [][]any{}
	for t := start; t < end; t += ms {
		row := []any{time.UnixMilli(t).UTC().Format(time.RFC3339Nano)}
		for _, s := range series {
			v := cells[s][t]
			if v == nil && zeroFill {
				v = int64(0)
			}
			row = append(row, v)
		}
		if other {
			var sum float64
			for _, s := range rest {
				f, _ := toFloat(cells[s][t])
				sum += f
			}
			row = append(row, sum)
		}
		res.Rows = append(res.Rows, row)
	}
	res.Total = int64(len(res.Rows))
	res.TimelineSpan = int64(span / time.Second)
	return nil
}

// --- values ---

// normalize converts a scanned database value to nil, int64, float64, bool, string,
// time.Time, []string or []any.
func normalize(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string, bool, time.Time, []string:
		return x
	case []byte:
		return string(x)
	case int:
		return int64(x)
	case int8:
		return int64(x)
	case int16:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint8:
		return int64(x)
	case uint16:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		if x > math.MaxInt64 {
			return float64(x)
		}
		return int64(x)
	case float32:
		return normalize(float64(x))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil
		}
		return x
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return normalize(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	}
	return fmt.Sprint(v)
}

func toTime(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case int64:
		return time.UnixMilli(x).UTC()
	case float64:
		return time.UnixMilli(int64(x)).UTC()
	}
	return time.Time{}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

func clip(s string) string {
	if len(s) <= maxCell {
		return s
	}
	cut := maxCell
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// convert formats a normalized value for a result of type t.
func convert(v any, t ftype) any {
	if v == nil {
		return nil
	}
	switch t {
	case fTime:
		tt := toTime(v)
		if tt.IsZero() {
			return nil
		}
		return tt.Format(time.RFC3339Nano)
	case fBool:
		switch x := v.(type) {
		case bool:
			return x
		case int64:
			return x != 0
		case float64:
			return x != 0
		}
		return v
	case fArr:
		var items []any
		switch x := v.(type) {
		case []string:
			for _, s := range x {
				items = append(items, s)
			}
		case []any:
			items = x
		case string: // SQLite: a JSON array
			_ = json.Unmarshal([]byte(x), &items)
		}
		list := []string{}
		for _, it := range items {
			if it == nil {
				continue
			}
			s := fmt.Sprint(it)
			if s != "" {
				list = append(list, clip(s))
			}
		}
		sort.Strings(list)
		list = dedupSorted(list)
		if len(list) > maxValues {
			list = list[:maxValues]
		}
		return list
	case fNum:
		switch x := v.(type) {
		case int64, float64:
			return x
		case bool:
			if x {
				return int64(1)
			}
			return int64(0)
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
				return f
			}
			return nil
		}
		return v
	}
	switch x := v.(type) {
	case string:
		return clip(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []string:
		return clip(strings.Join(x, ","))
	}
	return clip(fmt.Sprint(v))
}

func dedupSorted(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
