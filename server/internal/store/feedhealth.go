package store

import (
	"context"
	"database/sql"
	"time"
)

func init() { featureSchemas = append(featureSchemas, feedSourceSchema) }

const feedSourceSchema = `
CREATE TABLE IF NOT EXISTS feed_sources (
	host_id TEXT NOT NULL,
	module TEXT NOT NULL,
	dataset TEXT NOT NULL,
	first_seen TEXT,
	last_seen TEXT,
	clock TEXT,
	silent_since TEXT,
	expected_since TEXT,
	arrivals INTEGER NOT NULL DEFAULT 0,
	gaps TEXT NOT NULL DEFAULT '[]',
	muted INTEGER NOT NULL DEFAULT 0,
	expected INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (host_id, module, dataset)
);
`

// FeedGap is the longest gap between a source's rows on one UTC day.
type FeedGap struct {
	Day int64 `json:"d"` // days since 1970
	Sec int64 `json:"s"`
}

// FeedSource is what feed health remembers about one data source between restarts. The
// host's own row has an empty module and dataset. Zero times mean not set.
type FeedSource struct {
	HostID, Module, Dataset string
	FirstSeen, LastSeen     time.Time
	// Clock is when the source's silence started counting. It is the last arrival, moved
	// forward by any time the server or the host was away.
	Clock         time.Time
	SilentSince   time.Time // an alert about this source is open or was raised
	ExpectedSince time.Time // when the owner marked it expected
	Arrivals      int64     // separate minutes with rows, at least
	Gaps          []FeedGap
	Muted         bool
	Expected      bool
}

func zeroToNil(t time.Time) any { return nullTS(&t) }

func nullToZero(s sql.NullString) time.Time {
	if t := parseNullTS(s); t != nil {
		return *t
	}
	return time.Time{}
}

// ListFeedSources returns every remembered source.
func (s *Store) ListFeedSources(ctx context.Context) ([]FeedSource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, module, dataset, first_seen, last_seen, clock, silent_since,
		expected_since, arrivals, gaps, muted, expected FROM feed_sources`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedSource
	for rows.Next() {
		var f FeedSource
		var first, last, clock, silent, exp sql.NullString
		var gaps string
		var muted, expected int
		if err := rows.Scan(&f.HostID, &f.Module, &f.Dataset, &first, &last, &clock, &silent, &exp, &f.Arrivals, &gaps, &muted, &expected); err != nil {
			return nil, err
		}
		f.FirstSeen, f.LastSeen, f.Clock = nullToZero(first), nullToZero(last), nullToZero(clock)
		f.SilentSince, f.ExpectedSince = nullToZero(silent), nullToZero(exp)
		f.Muted, f.Expected = muted != 0, expected != 0
		unmarshalJSON(gaps, &f.Gaps)
		out = append(out, f)
	}
	return out, rows.Err()
}

// PutFeedSources saves sources in one transaction, so a flush is one write however many
// sources changed.
func (s *Store) PutFeedSources(ctx context.Context, list []FeedSource) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := range list {
		f := &list[i]
		gaps := f.Gaps
		if gaps == nil {
			gaps = []FeedGap{}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feed_sources(host_id, module, dataset, first_seen, last_seen, clock,
			silent_since, expected_since, arrivals, gaps, muted, expected) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(host_id, module, dataset) DO UPDATE SET first_seen = excluded.first_seen, last_seen = excluded.last_seen,
			clock = excluded.clock, silent_since = excluded.silent_since, expected_since = excluded.expected_since,
			arrivals = excluded.arrivals, gaps = excluded.gaps, muted = excluded.muted, expected = excluded.expected`,
			f.HostID, f.Module, f.Dataset, zeroToNil(f.FirstSeen), zeroToNil(f.LastSeen), zeroToNil(f.Clock),
			zeroToNil(f.SilentSince), zeroToNil(f.ExpectedSince), f.Arrivals, mustJSON(gaps), boolInt(f.Muted), boolInt(f.Expected)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteFeedSources forgets sources.
func (s *Store) DeleteFeedSources(ctx context.Context, list []FeedSource) error {
	for i := range list {
		f := &list[i]
		if _, err := s.db.ExecContext(ctx, `DELETE FROM feed_sources WHERE host_id = ? AND module = ? AND dataset = ?`, f.HostID, f.Module, f.Dataset); err != nil {
			return err
		}
	}
	return nil
}

// ResolveFinding resolves the open alerts of one server finding, with a note saying why.
// Findings keep their entity in the event's data.entity, so this needs nothing from how
// alerts are grouped. It returns how many alerts it resolved.
func (s *Store) ResolveFinding(ctx context.Context, ruleID, hostID, entity, author, note string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM alerts WHERE rule_id = ? AND host_id = ?
		AND status IN ('new','in_progress') AND json_extract(event, '$.data.entity') = ?`, ruleID, hostID, entity)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	resolved := AlertResolved
	for _, id := range ids {
		if _, err := s.AddAlertNote(ctx, id, author, note); err != nil {
			return 0, err
		}
		if _, err := s.UpdateAlert(ctx, id, &resolved, nil); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
