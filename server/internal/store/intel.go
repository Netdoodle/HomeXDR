package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// IntelLookup is what the threat intelligence services last said about an indicator.
type IntelLookup struct {
	Indicator string          `json:"indicator"`
	Kind      string          `json:"kind"`
	Score     *int            `json:"score,omitempty"`
	Verdict   string          `json:"verdict"`
	Results   json.RawMessage `json:"-"` // one result per source
	FirstAt   time.Time       `json:"first_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	UpdatedBy string          `json:"updated_by"`
	Lookups   int             `json:"lookups"`
}

const intelSchema = `
CREATE TABLE IF NOT EXISTS intel_lookups (
	indicator TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	score INTEGER,
	verdict TEXT NOT NULL DEFAULT '',
	results TEXT NOT NULL DEFAULT '[]',
	first_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL DEFAULT '',
	lookups INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS intel_lookups_updated ON intel_lookups(updated_at);
`

// maxIntelLookups is how many indicators are remembered, newest first.
const maxIntelLookups = 2000

const intelCols = `indicator, kind, score, verdict, results, first_at, updated_at, updated_by, lookups`

func scanIntelLookup(row interface{ Scan(...any) error }) (*IntelLookup, error) {
	var l IntelLookup
	var score sql.NullInt64
	var results, first, updated string
	err := row.Scan(&l.Indicator, &l.Kind, &score, &l.Verdict, &results, &first, &updated, &l.UpdatedBy, &l.Lookups)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if score.Valid {
		v := int(score.Int64)
		l.Score = &v
	}
	l.Results = json.RawMessage(results)
	l.FirstAt, l.UpdatedAt = parseTS(first), parseTS(updated)
	return &l, nil
}

// GetIntelLookup returns what is stored for an indicator.
func (s *Store) GetIntelLookup(ctx context.Context, indicator string) (*IntelLookup, error) {
	return scanIntelLookup(s.db.QueryRowContext(ctx, `SELECT `+intelCols+` FROM intel_lookups WHERE indicator = ?`, indicator))
}

// PutIntelLookup stores a lookup's results, counting it, and forgets the oldest
// indicators beyond the limit.
func (s *Store) PutIntelLookup(ctx context.Context, l *IntelLookup) error {
	now := ts(time.Now())
	var score any
	if l.Score != nil {
		score = *l.Score
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO intel_lookups(indicator, kind, score, verdict, results, first_at, updated_at, updated_by)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(indicator) DO UPDATE SET kind = excluded.kind, score = excluded.score, verdict = excluded.verdict,
		   results = excluded.results, updated_at = excluded.updated_at, updated_by = excluded.updated_by, lookups = lookups + 1`,
		l.Indicator, l.Kind, score, l.Verdict, string(l.Results), now, now, l.UpdatedBy)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM intel_lookups WHERE indicator NOT IN
		(SELECT indicator FROM intel_lookups ORDER BY updated_at DESC LIMIT ?)`, maxIntelLookups)
	return err
}

// ListIntelLookups returns the most recently looked up indicators, without their results.
func (s *Store) ListIntelLookups(ctx context.Context, limit int) ([]*IntelLookup, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT indicator, kind, score, verdict, '[]', first_at, updated_at, updated_by, lookups
		FROM intel_lookups ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IntelLookup{}
	for rows.Next() {
		l, err := scanIntelLookup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// AlertsForEvents returns alerts raised by any of the given events, newest first.
func (s *Store) AlertsForEvents(ctx context.Context, eventIDs []string, limit int) ([]*Alert, error) {
	if len(eventIDs) == 0 {
		return []*Alert{}, nil
	}
	args := make([]any, 0, len(eventIDs)+1)
	for _, id := range eventIDs {
		args = append(args, id)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE EXISTS
		(SELECT 1 FROM json_each(alerts.event_ids) j WHERE j.value IN (`+placeholders(len(eventIDs))+`))
		ORDER BY last_seen DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
