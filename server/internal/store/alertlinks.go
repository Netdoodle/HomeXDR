package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// foldLinked folds a hit into an open alert from another rule that has the same link
// key (within DedupWindow). It reports whether it did.
func (s *Store) foldLinked(ctx context.Context, tx *sql.Tx, in AlertInput, at, now time.Time) (*Alert, bool, error) {
	var id, idsJSON, linkedJSON, sev string
	err := tx.QueryRowContext(ctx,
		`SELECT id, event_ids, linked, severity FROM alerts
		 WHERE link_key = ? AND status IN ('new','in_progress') AND last_seen >= ?
		 ORDER BY first_seen LIMIT 1`, in.LinkKey, ts(now.Add(-DedupWindow))).Scan(&id, &idsJSON, &linkedJSON, &sev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var ids []string
	var linked []AlertLink
	unmarshalJSON(idsJSON, &ids)
	unmarshalJSON(linkedJSON, &linked)
	if len(ids) < maxAlertEventIDs {
		ids = append(ids, in.Event.ID)
	}
	found := false
	for i := range linked {
		if linked[i].RuleID == in.Rule.ID {
			l := &linked[i]
			l.Count++
			if at.After(l.LastSeen) {
				l.LastSeen = at
			}
			found = true
			break
		}
	}
	if !found && len(linked) < 20 {
		linked = append(linked, AlertLink{RuleID: in.Rule.ID, Title: in.Rule.Title, Source: in.LinkSource,
			Severity: in.Severity, FirstSeen: at, LastSeen: at, Count: 1, EventID: in.Event.ID})
	}
	// The alert takes the more serious severity of the two.
	if RiskScore(in.Severity) > RiskScore(sev) {
		sev = in.Severity
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE alerts SET count = count + 1, last_seen = MAX(last_seen, ?), event_ids = ?, linked = ?,
		   severity = ?, risk_score = ?, updated_at = ? WHERE id = ?`,
		ts(at), mustJSON(ids), mustJSON(linked), sev, RiskScore(sev), ts(now), id); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	a, err := s.GetAlert(ctx, id)
	return a, true, err
}
