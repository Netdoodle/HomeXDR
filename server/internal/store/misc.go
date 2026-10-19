package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// RuleRow is the stored state of a rule: an enabled override for built-in rules, or the
// full YAML for custom rules.
type RuleRow struct {
	ID        string
	Source    string // builtin | custom
	YAML      string
	Enabled   bool
	UpdatedAt time.Time
}

// ListRuleRows returns all stored rule rows.
func (s *Store) ListRuleRows(ctx context.Context) ([]RuleRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source, yaml, enabled, updated_at FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleRow
	for rows.Next() {
		var r RuleRow
		var en int
		var upd string
		if err := rows.Scan(&r.ID, &r.Source, &r.YAML, &en, &upd); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		r.UpdatedAt = parseTS(upd)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRuleRow returns one stored rule row.
func (s *Store) GetRuleRow(ctx context.Context, id string) (*RuleRow, error) {
	var r RuleRow
	var en int
	var upd string
	err := s.db.QueryRowContext(ctx, `SELECT id, source, yaml, enabled, updated_at FROM rules WHERE id = ?`, id).
		Scan(&r.ID, &r.Source, &r.YAML, &en, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Enabled = en != 0
	r.UpdatedAt = parseTS(upd)
	return &r, nil
}

// PutRuleRow inserts or replaces a rule row.
func (s *Store) PutRuleRow(ctx context.Context, r RuleRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rules(id, source, yaml, enabled, updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET source = excluded.source, yaml = excluded.yaml,
		   enabled = excluded.enabled, updated_at = excluded.updated_at`,
		r.ID, r.Source, r.YAML, boolInt(r.Enabled), ts(time.Now()))
	return err
}

// DeleteRuleRow removes a rule row.
func (s *Store) DeleteRuleRow(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	return err
}

// AuditEntry is one audit log record.
type AuditEntry struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	User    string    `json:"user"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Details string    `json:"details"`
}

// Audit appends an audit record. Errors are returned but callers usually log and continue.
func (s *Store) Audit(ctx context.Context, user, action, target, details string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit(id, at, user, action, target, details) VALUES(?,?,?,?,?,?)`,
		event.NewID(), ts(time.Now()), user, action, target, truncate(details, 4000))
	return err
}

// ListAudit returns audit records newest first.
func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]AuditEntry, int, error) {
	limit, offset = clampLimit(limit, offset)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, user, action, target, details FROM audit ORDER BY at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.User, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, 0, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, total, rows.Err()
}
