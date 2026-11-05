package events

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// ErrUnsupportedStore is returned by the helpers below for a store that is not one of the
// two SQL backends (test doubles).
var ErrUnsupportedStore = errors.New("this event store cannot answer that")

// SourceBucket says a data source (host, module, dataset) had rows in a time bucket.
type SourceBucket struct {
	HostID  string
	Module  string
	Dataset string
	Start   time.Time
	Count   int64
}

// SourceActivity counts rows per source and time bucket in [from, to). It is one
// aggregated query over a few columns, under the same memory caps as a search.
func SourceActivity(ctx context.Context, s Store, from, to time.Time, bucket time.Duration) ([]SourceBucket, error) {
	b, ok := s.(backend)
	if !ok {
		return nil, ErrUnsupportedStore
	}
	ws, wa, err := b.where(SearchQuery{From: from, To: to})
	if err != nil {
		return nil, err
	}
	d := b.pd()
	ts := d.column(columnByField["@timestamp"])
	host, module, dataset := d.column(columnByField["host.id"]), d.column(columnByField["event.module"]), d.column(columnByField["event.dataset"])
	q := "SELECT " + host + ", " + module + ", " + dataset + ", " + d.bucket(ts, bucket.Milliseconds()) + " AS _b, count(*) FROM " +
		b.tableName() + " WHERE " + ws + " GROUP BY " + host + ", " + module + ", " + dataset + ", _b"
	rows, err := b.rows(ctx, q, wa...)
	if err != nil {
		return nil, err
	}
	out := make([]SourceBucket, 0, len(rows))
	for _, r := range rows {
		n, _ := r[4].(int64)
		sb := SourceBucket{Start: toTime(r[3]).UTC(), Count: n}
		sb.HostID, _ = r[0].(string)
		sb.Module, _ = r[1].(string)
		sb.Dataset, _ = r[2].(string)
		out = append(out, sb)
	}
	return out, nil
}

// SampleSource returns up to limit of a source's newest events in [from, to), newest
// first. Giving the host keeps ClickHouse on its primary key.
func SampleSource(ctx context.Context, s Store, hostID, module, dataset string, from, to time.Time, limit int) ([]*event.Event, error) {
	b, ok := s.(backend)
	if !ok {
		return nil, ErrUnsupportedStore
	}
	ws, wa, err := b.where(SearchQuery{From: from, To: to, HostID: hostID})
	if err != nil {
		return nil, err
	}
	d := b.pd()
	wa = append(wa, module, dataset)
	q := "SELECT raw FROM " + b.tableName() + " WHERE " + ws +
		" AND " + d.column(columnByField["event.module"]) + " = ? AND " + d.column(columnByField["event.dataset"]) + " = ?" +
		" ORDER BY " + d.column(columnByField["@timestamp"]) + " DESC LIMIT " + strconv.Itoa(limit)
	rows, err := b.rows(ctx, q, wa...)
	if err != nil {
		return nil, err
	}
	out := make([]*event.Event, 0, len(rows))
	for _, r := range rows {
		raw, _ := r[0].(string)
		var e event.Event
		if json.Unmarshal([]byte(raw), &e) == nil {
			out = append(out, &e)
		}
	}
	return out, nil
}
