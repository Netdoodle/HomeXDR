package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

const notificationSchema = `
CREATE TABLE IF NOT EXISTS notify_outbox (
	id TEXT PRIMARY KEY,
	channel_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	alert_id TEXT NOT NULL DEFAULT '',
	payload TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	next_attempt_at TEXT NOT NULL,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	finished_at TEXT
);
CREATE INDEX IF NOT EXISTS notify_outbox_due ON notify_outbox(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS notify_outbox_created ON notify_outbox(created_at);
`

func init() { featureSchemas = append(featureSchemas, notificationSchema) }

// Outbox statuses.
const (
	NotifyPending  = "pending"
	NotifySent     = "sent"
	NotifyFailed   = "failed"   // gave up after retries
	NotifyDropped  = "dropped"  // no longer worth sending
	NotifyOverflow = "overflow" // over the hourly cap: a record for the digest, never sent
)

// Outbox row kinds.
const (
	NotifyKindAlert  = "alert"
	NotifyKindDigest = "digest"
	NotifyKindNotice = "notice" // about notifications themselves
)

// OutboxItem is one message on its way to one channel.
type OutboxItem struct {
	ID        string          `json:"id"`
	ChannelID string          `json:"channel_id"`
	Kind      string          `json:"kind"`
	AlertID   string          `json:"alert_id,omitempty"`
	Payload   json.RawMessage `json:"-"`
	Status    string          `json:"status"`
	Attempts  int             `json:"attempts"`
	NextAt    time.Time       `json:"next_attempt_at"`
	LastError string          `json:"last_error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	// Title is read from the payload for delivery status.
	Title string `json:"title,omitempty"`
}

// EnqueueNotifications stores messages to send as of now, in one transaction.
func (s *Store) EnqueueNotifications(ctx context.Context, at time.Time, items []OutboxItem) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := ts(at)
	for _, it := range items {
		status := it.Status
		if status == "" {
			status = NotifyPending
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_outbox(id, channel_id, kind, alert_id, payload, status, next_attempt_at, created_at)
			VALUES(?,?,?,?,?,?,?,?)`, event.NewID(), it.ChannelID, it.Kind, it.AlertID, string(it.Payload), status, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const outboxCols = `id, channel_id, kind, alert_id, payload, status, attempts, next_attempt_at, last_error, created_at`

func scanOutbox(rows *sql.Rows) (OutboxItem, error) {
	var it OutboxItem
	var payload, next, created string
	if err := rows.Scan(&it.ID, &it.ChannelID, &it.Kind, &it.AlertID, &payload, &it.Status, &it.Attempts, &next, &it.LastError, &created); err != nil {
		return it, err
	}
	it.Payload = json.RawMessage(payload)
	it.NextAt, it.CreatedAt = parseTS(next), parseTS(created)
	var head struct {
		Title string `json:"title"`
	}
	unmarshalJSON(payload, &head)
	it.Title = head.Title
	return it, nil
}

// DueNotifications returns pending messages whose time has come, oldest first.
func (s *Store) DueNotifications(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+outboxCols+` FROM notify_outbox
		WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY created_at, id LIMIT ?`, ts(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		it, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// FinishNotification marks a message sent, failed or dropped.
func (s *Store) FinishNotification(ctx context.Context, id, status, lastError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_outbox SET status = ?, last_error = ?, finished_at = ?,
		attempts = attempts + CASE WHEN ? = 'dropped' THEN 0 ELSE 1 END WHERE id = ?`,
		status, lastError, ts(time.Now()), status, id)
	return err
}

// RetryNotification records a failed attempt and when to try again.
func (s *Store) RetryNotification(ctx context.Context, id, lastError string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?`,
		lastError, ts(next), id)
	return err
}

// ImmediateAlertsSince counts distinct alerts sent or on their way since t, for the cap.
func (s *Store) ImmediateAlertsSince(ctx context.Context, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT alert_id) FROM notify_outbox
		WHERE kind = 'alert' AND status != 'overflow' AND created_at >= ?`, ts(t)).Scan(&n)
	return n, err
}

// OverflowSince counts alerts held back by the cap since t.
func (s *Store) OverflowSince(ctx context.Context, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_outbox WHERE status = 'overflow' AND created_at >= ?`, ts(t)).Scan(&n)
	return n, err
}

// PurgeNotifications removes finished messages created before t, and returns how many.
func (s *Store) PurgeNotifications(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notify_outbox WHERE status != 'pending' AND created_at < ?`, ts(before))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// NotificationStats is delivery status for the settings page.
type NotificationStats struct {
	Pending    int          `json:"pending"`
	Sent24h    int          `json:"sent_24h"`
	Failed24h  int          `json:"failed_24h"`
	Overflow1h int          `json:"overflow_1h"`
	LastSentAt *time.Time   `json:"last_sent_at"`
	Failures   []OutboxItem `json:"recent_failures"`
}

// GetNotificationStats returns delivery counts and the most recent failures, including
// messages that are still being retried.
func (s *Store) GetNotificationStats(ctx context.Context, now time.Time) (*NotificationStats, error) {
	st := &NotificationStats{Failures: []OutboxItem{}}
	var last sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT
			COALESCE(SUM(status = 'pending'), 0),
			COALESCE(SUM(status = 'sent' AND created_at >= ?), 0),
			COALESCE(SUM(status = 'failed' AND created_at >= ?), 0),
			COALESCE(SUM(status = 'overflow' AND created_at >= ?), 0),
			MAX(CASE WHEN status = 'sent' THEN finished_at END)
		FROM notify_outbox`, ts(now.Add(-24*time.Hour)), ts(now.Add(-24*time.Hour)), ts(now.Add(-time.Hour))).
		Scan(&st.Pending, &st.Sent24h, &st.Failed24h, &st.Overflow1h, &last); err != nil {
		return nil, err
	}
	st.LastSentAt = parseNullTS(last)
	rows, err := s.db.QueryContext(ctx, `SELECT `+outboxCols+` FROM notify_outbox
		WHERE last_error != '' AND status IN ('pending', 'failed') ORDER BY created_at DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		it, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		st.Failures = append(st.Failures, it)
	}
	return st, rows.Err()
}

// DigestRuleCount is one rule's activity for the daily digest.
type DigestRuleCount struct {
	RuleID   string
	Title    string
	Severity string
	Alerts   int
	Hits     int64
}

// DigestRuleCounts returns activity per rule and severity since t, busiest first.
// Suppressed alerts are counted separately.
func (s *Store) DigestRuleCounts(ctx context.Context, since time.Time) ([]DigestRuleCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule_id, MAX(json_extract(rule, '$.title')), severity, COUNT(*), SUM(count)
		FROM alerts WHERE last_seen >= ? AND status != 'suppressed'
		GROUP BY rule_id, severity ORDER BY SUM(count) DESC`, ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DigestRuleCount
	for rows.Next() {
		var r DigestRuleCount
		var title sql.NullString
		if err := rows.Scan(&r.RuleID, &title, &r.Severity, &r.Alerts, &r.Hits); err != nil {
			return nil, err
		}
		r.Title = title.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// SuppressedHitsSince returns how many hits were suppressed on rows seen since t.
func (s *Store) SuppressedHitsSince(ctx context.Context, since time.Time) (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT SUM(count) FROM alerts WHERE status = 'suppressed' AND last_seen >= ?`, ts(since)).Scan(&n)
	return n.Int64, err
}

// DigestVerdict is an alert the AI analyst did not call benign.
type DigestVerdict struct {
	AlertID  string
	Title    string
	Hostname string
	Verdict  string
}

// DigestVerdicts returns AI verdict counts for alerts seen since t, and up to limit
// alerts it called something other than benign, worst first.
func (s *Store) DigestVerdicts(ctx context.Context, since time.Time, limit int) (map[string]int, []DigestVerdict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.verdict, COUNT(*) FROM alert_triage t JOIN alerts a ON a.id = t.alert_id
		WHERE t.status = 'done' AND t.verdict != '' AND a.last_seen >= ? AND a.status != 'suppressed' GROUP BY t.verdict`, ts(since))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, nil, err
		}
		counts[v] = n
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()
	top, err := s.db.QueryContext(ctx, `SELECT a.id, json_extract(a.rule, '$.title'), a.hostname, t.verdict
		FROM alert_triage t JOIN alerts a ON a.id = t.alert_id
		WHERE t.status = 'done' AND t.verdict IN ('malicious', 'suspicious', 'inconclusive') AND a.last_seen >= ? AND a.status != 'suppressed'
		ORDER BY CASE t.verdict WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 ELSE 2 END, a.last_seen DESC LIMIT ?`, ts(since), limit)
	if err != nil {
		return nil, nil, err
	}
	defer top.Close()
	var list []DigestVerdict
	for top.Next() {
		var d DigestVerdict
		var title sql.NullString
		if err := top.Scan(&d.AlertID, &title, &d.Hostname, &d.Verdict); err != nil {
			return nil, nil, err
		}
		d.Title = title.String
		list = append(list, d)
	}
	return counts, list, top.Err()
}

// AlertStatus returns an alert's status.
func (s *Store) AlertStatus(ctx context.Context, id string) (string, error) {
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM alerts WHERE id = ?`, id).Scan(&st)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return st, err
}
