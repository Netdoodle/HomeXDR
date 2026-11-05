package store

import (
	"context"
	"time"
)

const behaviorSchema = `
CREATE TABLE IF NOT EXISTS behavior_state (
	detector TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (detector, key)
);
`

func init() { featureSchemas = append(featureSchemas, behaviorSchema) }

// BehaviorState returns what a behaviour detector has learned: its baselines and what it
// has already reported.
func (s *Store) BehaviorState(ctx context.Context, detector string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM behavior_state WHERE detector = ?`, detector)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SaveBehaviorState writes changed keys and removes deleted ones in one transaction.
func (s *Store) SaveBehaviorState(ctx context.Context, detector string, changed map[string]string, deleted []string) error {
	if len(changed) == 0 && len(deleted) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := ts(time.Now())
	for _, k := range deleted {
		if _, err := tx.ExecContext(ctx, `DELETE FROM behavior_state WHERE detector = ? AND key = ?`, detector, k); err != nil {
			return err
		}
	}
	for k, v := range changed {
		if _, err := tx.ExecContext(ctx, `INSERT INTO behavior_state(detector, key, value, updated_at) VALUES(?,?,?,?)
			ON CONFLICT(detector, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, detector, k, v, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
