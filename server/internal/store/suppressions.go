package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

const suppressionSchema = `
CREATE TABLE IF NOT EXISTS suppressions (
	id TEXT PRIMARY KEY,
	rule_id TEXT NOT NULL DEFAULT '',
	rule_title TEXT NOT NULL DEFAULT '',
	host_id TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	conditions TEXT NOT NULL DEFAULT '[]',
	reason TEXT NOT NULL,
	created_by TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT,
	enabled INTEGER NOT NULL DEFAULT 1,
	hit_count INTEGER NOT NULL DEFAULT 0,
	last_hit_at TEXT,
	override_count INTEGER NOT NULL DEFAULT 0,
	last_override_at TEXT
);
`

func init() {
	featureSchemas = append(featureSchemas, suppressionSchema)
	columnMigrations = append(columnMigrations, struct{ table, column, def string }{"alerts", "suppression", `TEXT NOT NULL DEFAULT ''`})
}

// SuppressionCondition compares one event field with a value. Field is a Sigma or ECS
// name, as detect.Doc.Get takes it.
type SuppressionCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"` // equals | contains | startswith | endswith
	Value string `json:"value"`
}

// Suppression closes matching hits on arrival. It has a scope, a reason and usually an
// expiry. HitCount counts hits it closed; OverrideCount counts hits it matched that were
// kept as alerts anyway (must-alert).
type Suppression struct {
	ID             string                 `json:"id"`
	RuleID         string                 `json:"rule_id,omitempty"`
	RuleTitle      string                 `json:"rule_title,omitempty"`
	HostID         string                 `json:"host_id,omitempty"`
	Hostname       string                 `json:"hostname,omitempty"`
	Conditions     []SuppressionCondition `json:"conditions"`
	Reason         string                 `json:"reason"`
	CreatedBy      string                 `json:"created_by"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      *time.Time             `json:"expires_at"` // nil: never
	Enabled        bool                   `json:"enabled"`
	HitCount       int64                  `json:"hit_count"`
	LastHitAt      *time.Time             `json:"last_hit_at"`
	OverrideCount  int64                  `json:"override_count"`
	LastOverrideAt *time.Time             `json:"last_override_at"`
}

// Active reports whether the suppression matches anything at time t.
func (s *Suppression) Active(t time.Time) bool {
	return s.Enabled && (s.ExpiresAt == nil || s.ExpiresAt.After(t))
}

const suppressionCols = `id, rule_id, rule_title, host_id, hostname, conditions, reason, created_by, created_at,
	expires_at, enabled, hit_count, last_hit_at, override_count, last_override_at`

func scanSuppression(row interface{ Scan(...any) error }) (*Suppression, error) {
	var sp Suppression
	var conditions, created string
	var expires, lastHit, lastOverride sql.NullString
	var enabled int
	err := row.Scan(&sp.ID, &sp.RuleID, &sp.RuleTitle, &sp.HostID, &sp.Hostname, &conditions, &sp.Reason, &sp.CreatedBy,
		&created, &expires, &enabled, &sp.HitCount, &lastHit, &sp.OverrideCount, &lastOverride)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	unmarshalJSON(conditions, &sp.Conditions)
	if sp.Conditions == nil {
		sp.Conditions = []SuppressionCondition{}
	}
	sp.CreatedAt = parseTS(created)
	sp.ExpiresAt = parseNullTS(expires)
	sp.LastHitAt = parseNullTS(lastHit)
	sp.LastOverrideAt = parseNullTS(lastOverride)
	sp.Enabled = enabled != 0
	return &sp, nil
}

// CreateSuppression stores a suppression (already validated), setting its ID and creation
// time.
func (s *Store) CreateSuppression(ctx context.Context, sp *Suppression) error {
	sp.ID = event.NewID()
	sp.CreatedAt = time.Now().UTC()
	if sp.Conditions == nil {
		sp.Conditions = []SuppressionCondition{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO suppressions(id, rule_id, rule_title, host_id, hostname, conditions, reason,
		created_by, created_at, expires_at, enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		sp.ID, sp.RuleID, sp.RuleTitle, sp.HostID, sp.Hostname, mustJSON(sp.Conditions), sp.Reason,
		sp.CreatedBy, ts(sp.CreatedAt), nullTS(sp.ExpiresAt), boolInt(sp.Enabled))
	return err
}

// GetSuppression returns one suppression.
func (s *Store) GetSuppression(ctx context.Context, id string) (*Suppression, error) {
	return scanSuppression(s.db.QueryRowContext(ctx, `SELECT `+suppressionCols+` FROM suppressions WHERE id = ?`, id))
}

// ListSuppressions returns all suppressions, oldest first.
func (s *Store) ListSuppressions(ctx context.Context) ([]*Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+suppressionCols+` FROM suppressions ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Suppression{}
	for rows.Next() {
		sp, err := scanSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// UpdateSuppression saves a suppression's editable fields. Its counters are left alone.
func (s *Store) UpdateSuppression(ctx context.Context, sp *Suppression) error {
	res, err := s.db.ExecContext(ctx, `UPDATE suppressions SET rule_id = ?, rule_title = ?, host_id = ?, hostname = ?,
		conditions = ?, reason = ?, expires_at = ?, enabled = ? WHERE id = ?`,
		sp.RuleID, sp.RuleTitle, sp.HostID, sp.Hostname, mustJSON(sp.Conditions), sp.Reason, nullTS(sp.ExpiresAt),
		boolInt(sp.Enabled), sp.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSuppression removes a suppression.
func (s *Store) DeleteSuppression(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordSuppressionHit counts a hit the suppression closed, or matched but had to keep.
func (s *Store) RecordSuppressionHit(ctx context.Context, id string, overridden bool) error {
	q := `UPDATE suppressions SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?`
	if overridden {
		q = `UPDATE suppressions SET override_count = override_count + 1, last_override_at = ? WHERE id = ?`
	}
	_, err := s.db.ExecContext(ctx, q, ts(time.Now()), id)
	return err
}

// SuppressionNames finds a display title for a rule and a name for a host from what has
// been seen of them. Either is empty when unknown.
func (s *Store) SuppressionNames(ctx context.Context, ruleID, hostID string) (ruleTitle, hostname string) {
	if ruleID != "" {
		var title sql.NullString
		_ = s.db.QueryRowContext(ctx, `SELECT json_extract(rule, '$.title') FROM alerts WHERE rule_id = ? LIMIT 1`, ruleID).Scan(&title)
		ruleTitle = title.String
	}
	if hostID != "" {
		_ = s.db.QueryRowContext(ctx, `SELECT hostname FROM hosts WHERE id = ?`, hostID).Scan(&hostname)
		if hostname == "" {
			_ = s.db.QueryRowContext(ctx, `SELECT hostname FROM alerts WHERE host_id = ? LIMIT 1`, hostID).Scan(&hostname)
		}
	}
	return ruleTitle, hostname
}

// OpenAlertsPage returns up to limit open alerts with IDs after afterID, in ID order,
// narrowed to a rule and host when those are set. Pass the last ID back to page on. The
// rows are read and closed before it returns, so the caller can write between pages.
func (s *Store) OpenAlertsPage(ctx context.Context, ruleID, hostID, afterID string, limit int) ([]*Alert, error) {
	where := ` WHERE status IN ('new','in_progress') AND id > ?`
	args := []any{afterID}
	if ruleID != "" {
		where += ` AND rule_id = ?`
		args = append(args, ruleID)
	}
	if hostID != "" {
		where += ` AND host_id = ?`
		args = append(args, hostID)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+alertCols+` FROM alerts`+where+` ORDER BY id LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Alert, 0, limit)
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// closeBatch is how many alerts one transaction closes, so a big cleanup never holds the
// write lock long enough to get in the way of a running server.
const closeBatch = 200

// CloseAlertsAsSuppressed sets open alerts to suppressed with a note, and cancels their
// waiting AI investigations. It returns how many it closed.
func (s *Store) CloseAlertsAsSuppressed(ctx context.Context, ids []string, ref AlertSuppression, author, note string) (int, error) {
	closed := 0
	for len(ids) > 0 {
		batch := ids
		if len(batch) > closeBatch {
			batch = batch[:closeBatch]
		}
		ids = ids[len(batch):]
		n, err := s.closeSuppressedBatch(ctx, batch, ref, author, note)
		if err != nil {
			return closed, err
		}
		closed += n
	}
	return closed, nil
}

func (s *Store) closeSuppressedBatch(ctx context.Context, ids []string, ref AlertSuppression, author, note string) (int, error) {
	now := time.Now().UTC()
	in := placeholders(len(ids))
	idArgs := make([]any, len(ids))
	for i, id := range ids {
		idArgs[i] = id
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE alerts SET status = ?, suppression = ?, updated_at = ?,
		notes = json_insert(notes, '$[#]', json(?))
		WHERE status IN ('new','in_progress') AND id IN (`+in+`)`,
		append([]any{AlertSuppressed, mustJSON(ref), ts(now), mustJSON(Note{Author: author, Text: truncate(note, 8000), At: now})}, idArgs...)...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE alert_triage SET status = 'skipped', error = 'the alert was closed by a suppression', finished_at = ?
		WHERE status = 'queued' AND alert_id IN (`+in+`)`, append([]any{ts(now)}, idArgs...)...); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// RepeatingShape is a group of open alerts that are the same thing happening again: one
// rule, one host, one process shape. It works on alerts stored before grouping by shape
// too, because it reads the shape from each alert's event.
type RepeatingShape struct {
	RuleID      string    `json:"rule_id"`
	RuleTitle   string    `json:"rule_title"`
	Severity    string    `json:"severity"`
	HostID      string    `json:"host_id"`
	Hostname    string    `json:"hostname"`
	Process     string    `json:"process,omitempty"`
	Parent      string    `json:"parent,omitempty"`
	Alerts      int       `json:"alerts"`
	Hits        int64     `json:"hits"`
	LastSeen    time.Time `json:"last_seen"`
	SampleAlert string    `json:"sample_alert_id"`
}

// TopRepeating returns the noisiest shapes among open alerts seen since `since`.
func (s *Store) TopRepeating(ctx context.Context, since time.Time, limit int) ([]RepeatingShape, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT rule_id, MAX(json_extract(rule, '$.title')), MAX(severity), host_id, MAX(hostname), exe, parent,
			COUNT(*), SUM(count), MAX(last_seen), MAX(id)
		FROM (SELECT id, rule_id, rule, severity, host_id, hostname, count, last_seen,
				COALESCE(NULLIF(json_extract(event, '$.process.executable'), ''), process_name) AS exe,
				COALESCE(NULLIF(json_extract(event, '$.process.parent.executable'), ''),
					json_extract(event, '$.process.parent.name'), '') AS parent
			FROM alerts WHERE status IN ('new','in_progress') AND last_seen >= ?)
		GROUP BY rule_id, host_id, exe, parent
		HAVING SUM(count) > 1
		ORDER BY SUM(count) DESC, MAX(last_seen) DESC LIMIT ?`, ts(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RepeatingShape{}
	for rows.Next() {
		var r RepeatingShape
		var title sql.NullString
		var last string
		if err := rows.Scan(&r.RuleID, &title, &r.Severity, &r.HostID, &r.Hostname, &r.Process, &r.Parent,
			&r.Alerts, &r.Hits, &last, &r.SampleAlert); err != nil {
			return nil, err
		}
		r.RuleTitle, r.LastSeen = title.String, parseTS(last)
		out = append(out, r)
	}
	return out, rows.Err()
}
