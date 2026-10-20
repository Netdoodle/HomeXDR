package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Alert statuses.
const (
	AlertNew           = "new"
	AlertInProgress    = "in_progress"
	AlertResolved      = "resolved"
	AlertFalsePositive = "false_positive"
)

// ValidAlertStatus reports whether s is a known alert status.
func ValidAlertStatus(s string) bool {
	switch s {
	case AlertNew, AlertInProgress, AlertResolved, AlertFalsePositive:
		return true
	}
	return false
}

// Severities, in Sigma level names.
const (
	SevCritical      = "critical"
	SevHigh          = "high"
	SevMedium        = "medium"
	SevLow           = "low"
	SevInformational = "informational"
)

// RiskScore maps a severity to a 0-100 score.
func RiskScore(sev string) int {
	switch sev {
	case SevCritical:
		return 99
	case SevHigh:
		return 73
	case SevMedium:
		return 47
	case SevLow:
		return 21
	}
	return 10
}

// AlertRule is the rule snapshot stored with an alert.
type AlertRule struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description,omitempty"`
	Level          string   `json:"level"`
	Tags           []string `json:"tags"`
	References     []string `json:"references,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty"`
}

// Mitre is one ATT&CK mapping.
type Mitre struct {
	Tactic      string `json:"tactic,omitempty"`
	TechniqueID string `json:"technique_id,omitempty"`
	Technique   string `json:"technique,omitempty"`
}

// Note is an analyst note on an alert.
type Note struct {
	Author string    `json:"author"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

// Alert is an alert in API shape.
type Alert struct {
	ID              string         `json:"id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	Count           int            `json:"count"`
	Status          string         `json:"status"`
	Severity        string         `json:"severity"`
	RiskScore       int            `json:"risk_score"`
	Assignee        string         `json:"assignee,omitempty"`
	Rule            AlertRule      `json:"rule"`
	Mitre           []Mitre        `json:"mitre"`
	HostID          string         `json:"host_id"`
	Hostname        string         `json:"hostname"`
	ProcessEntityID string         `json:"process_entity_id,omitempty"`
	ProcessName     string         `json:"process_name,omitempty"`
	CommandLine     string         `json:"command_line,omitempty"`
	User            string         `json:"user,omitempty"`
	EventIDs        []string       `json:"event_ids"`
	Event           *event.Event   `json:"event,omitempty"`
	Events          []*event.Event `json:"events,omitempty"`
	Notes           []Note         `json:"notes"`
	// AITriage summarizes the AI analyst's investigation, if there is one.
	AITriage *TriageSummary `json:"ai_triage,omitempty"`
}

// AlertInput describes a detection hit.
type AlertInput struct {
	Rule     AlertRule
	Mitre    []Mitre
	Severity string
	Event    *event.Event
}

// DedupWindow is how long an open alert keeps absorbing repeat hits.
const DedupWindow = 24 * time.Hour

// maxAlertEventIDs caps the event IDs kept on one alert.
const maxAlertEventIDs = 50

// RecordAlert creates an alert for a hit, or folds it into an open alert with the same
// rule, host and process within DedupWindow. It returns the alert and whether it is new.
func (s *Store) RecordAlert(ctx context.Context, in AlertInput) (*Alert, bool, error) {
	ev := in.Event
	var entity, pname, cmdline, user string
	if ev.Process != nil {
		entity, pname, cmdline = ev.Process.EntityID, ev.Process.Name, ev.Process.CommandLine
		if ev.Process.User != nil {
			user = ev.Process.User.Name
		}
	}
	if user == "" && ev.User != nil {
		user = ev.User.Name
	}
	key := in.Rule.ID + "|" + ev.Host.ID + "|" + entity
	now := time.Now().UTC()
	at := ev.Timestamp.UTC()
	if at.IsZero() {
		at = now
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	var id, idsJSON string
	err = tx.QueryRowContext(ctx,
		`SELECT id, event_ids FROM alerts
		 WHERE dedup_key = ? AND status IN ('new','in_progress') AND last_seen >= ?
		 ORDER BY last_seen DESC LIMIT 1`, key, ts(now.Add(-DedupWindow))).Scan(&id, &idsJSON)
	switch {
	case err == nil:
		var ids []string
		unmarshalJSON(idsJSON, &ids)
		if len(ids) < maxAlertEventIDs {
			ids = append(ids, ev.ID)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE alerts SET count = count + 1, last_seen = MAX(last_seen, ?), event_ids = ?, updated_at = ? WHERE id = ?`,
			ts(at), mustJSON(ids), ts(now), id); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		a, err := s.GetAlert(ctx, id)
		return a, false, err
	case !errors.Is(err, sql.ErrNoRows):
		return nil, false, err
	}

	if in.Mitre == nil {
		in.Mitre = []Mitre{}
	}
	if in.Rule.Tags == nil {
		in.Rule.Tags = []string{}
	}
	id = event.NewID()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO alerts(id, dedup_key, rule_id, rule, mitre, severity, risk_score, status, host_id, hostname,
		   process_entity_id, process_name, command_line, user_name, first_seen, last_seen, count, event_ids, event,
		   created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)`,
		id, key, in.Rule.ID, mustJSON(in.Rule), mustJSON(in.Mitre), in.Severity, RiskScore(in.Severity), AlertNew,
		ev.Host.ID, ev.Host.Name, entity, pname, truncate(cmdline, 4096), user, ts(at), ts(at),
		mustJSON([]string{ev.ID}), mustJSON(ev), ts(now), ts(now)); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	a, err := s.GetAlert(ctx, id)
	return a, true, err
}

const alertCols = `id, created_at, updated_at, first_seen, last_seen, count, status, severity, risk_score,
	assignee, rule, mitre, host_id, hostname, process_entity_id, process_name, command_line, user_name,
	event_ids, event, notes`

func scanAlert(row interface{ Scan(...any) error }) (*Alert, error) {
	var a Alert
	var created, updated, first, last, rule, mitre, ids, ev, notes string
	if err := row.Scan(&a.ID, &created, &updated, &first, &last, &a.Count, &a.Status, &a.Severity, &a.RiskScore,
		&a.Assignee, &rule, &mitre, &a.HostID, &a.Hostname, &a.ProcessEntityID, &a.ProcessName, &a.CommandLine,
		&a.User, &ids, &ev, &notes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.CreatedAt, a.UpdatedAt = parseTS(created), parseTS(updated)
	a.FirstSeen, a.LastSeen = parseTS(first), parseTS(last)
	unmarshalJSON(rule, &a.Rule)
	unmarshalJSON(mitre, &a.Mitre)
	unmarshalJSON(ids, &a.EventIDs)
	unmarshalJSON(notes, &a.Notes)
	if ev != "" {
		a.Event = &event.Event{}
		unmarshalJSON(ev, a.Event)
	}
	if a.Mitre == nil {
		a.Mitre = []Mitre{}
	}
	if a.EventIDs == nil {
		a.EventIDs = []string{}
	}
	if a.Notes == nil {
		a.Notes = []Note{}
	}
	if a.Rule.Tags == nil {
		a.Rule.Tags = []string{}
	}
	return &a, nil
}

// GetAlert returns one alert.
func (s *Store) GetAlert(ctx context.Context, id string) (*Alert, error) {
	a, err := scanAlert(s.db.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	s.attachTriage(ctx, []*Alert{a})
	return a, nil
}

// AlertFilter selects alerts.
type AlertFilter struct {
	Statuses   []string
	Severities []string
	HostID     string
	RuleID     string
	EntityIDs  []string
	Q          string
	Since      *time.Time
	Limit      int
	Offset     int
}

// ListAlerts returns alerts newest-last_seen first, and the total matching count.
func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]*Alert, int, error) {
	where := ` WHERE 1=1`
	var args []any
	if len(f.Statuses) > 0 {
		where += ` AND status IN (` + placeholders(len(f.Statuses)) + `)`
		for _, v := range f.Statuses {
			args = append(args, v)
		}
	}
	if len(f.Severities) > 0 {
		where += ` AND severity IN (` + placeholders(len(f.Severities)) + `)`
		for _, v := range f.Severities {
			args = append(args, v)
		}
	}
	if f.HostID != "" {
		where += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if f.RuleID != "" {
		where += ` AND rule_id = ?`
		args = append(args, f.RuleID)
	}
	if len(f.EntityIDs) > 0 {
		where += ` AND process_entity_id IN (` + placeholders(len(f.EntityIDs)) + `)`
		for _, v := range f.EntityIDs {
			args = append(args, v)
		}
	}
	if f.Since != nil {
		where += ` AND last_seen >= ?`
		args = append(args, ts(*f.Since))
	}
	if f.Q != "" {
		like := "%" + escapeLike(f.Q) + "%"
		where += ` AND (rule LIKE ? ESCAPE '\' OR hostname LIKE ? ESCAPE '\' OR process_name LIKE ? ESCAPE '\' OR command_line LIKE ? ESCAPE '\' OR user_name LIKE ? ESCAPE '\')`
		args = append(args, like, like, like, like, like)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := clampLimit(f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+alertCols+` FROM alerts`+where+` ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	rows.Close()
	s.attachTriage(ctx, out)
	return out, total, nil
}

// UpdateAlert sets status and/or assignee (nil leaves a field unchanged).
func (s *Store) UpdateAlert(ctx context.Context, id string, status, assignee *string) (*Alert, error) {
	n, err := s.updateAlerts(ctx, []string{id}, status, assignee)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.GetAlert(ctx, id)
}

// BulkUpdateAlerts updates many alerts and returns how many changed.
func (s *Store) BulkUpdateAlerts(ctx context.Context, ids []string, status, assignee *string) (int, error) {
	return s.updateAlerts(ctx, ids, status, assignee)
}

func (s *Store) updateAlerts(ctx context.Context, ids []string, status, assignee *string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if status != nil && !ValidAlertStatus(*status) {
		return 0, errors.New("invalid status")
	}
	set := []string{"updated_at = ?"}
	args := []any{ts(time.Now())}
	if status != nil {
		set = append(set, "status = ?")
		args = append(args, *status)
	}
	if assignee != nil {
		set = append(set, "assignee = ?")
		args = append(args, strings.TrimSpace(*assignee))
	}
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET `+strings.Join(set, ", ")+` WHERE id IN (`+placeholders(len(ids))+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// AddAlertNote appends a note.
func (s *Store) AddAlertNote(ctx context.Context, id, author, text string) (*Alert, error) {
	a, err := s.GetAlert(ctx, id)
	if err != nil {
		return nil, err
	}
	a.Notes = append(a.Notes, Note{Author: author, Text: truncate(text, 8000), At: time.Now().UTC()})
	if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET notes = ?, updated_at = ? WHERE id = ?`,
		mustJSON(a.Notes), ts(time.Now()), id); err != nil {
		return nil, err
	}
	return s.GetAlert(ctx, id)
}

// SeverityCounts is open alerts by severity.
type SeverityCounts struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// OpenAlertCounts returns the open alert total and per-severity counts.
func (s *Store) OpenAlertCounts(ctx context.Context) (int, SeverityCounts, error) {
	var c SeverityCounts
	rows, err := s.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM alerts WHERE status IN ('new','in_progress') GROUP BY severity`)
	if err != nil {
		return 0, c, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return 0, c, err
		}
		total += n
		switch sev {
		case SevCritical:
			c.Critical = n
		case SevHigh:
			c.High = n
		case SevMedium:
			c.Medium = n
		case SevLow:
			c.Low = n
		default:
			c.Informational += n
		}
	}
	return total, c, rows.Err()
}

// TimeCount is one bucket of a timeline.
type TimeCount struct {
	T     time.Time `json:"t"`
	Count int64     `json:"count"`
}

// AlertTimeline returns hourly counts of alerts first seen since `since`.
func (s *Store) AlertTimeline(ctx context.Context, since time.Time) ([]TimeCount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT substr(first_seen, 1, 13), COUNT(*) FROM alerts WHERE first_seen >= ? GROUP BY 1 ORDER BY 1`, ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TimeCount{}
	for rows.Next() {
		var hour string
		var n int64
		if err := rows.Scan(&hour, &n); err != nil {
			return nil, err
		}
		t, err := time.Parse("2006-01-02T15", hour)
		if err != nil {
			continue
		}
		out = append(out, TimeCount{T: t, Count: n})
	}
	return out, rows.Err()
}

// RuleCount is alerts per rule.
type RuleCount struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// TopRules returns the rules with the most hits since `since`.
func (s *Store) TopRules(ctx context.Context, since time.Time, limit int) ([]RuleCount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, json_extract(rule, '$.title'), severity, SUM(count) AS n FROM alerts
		 WHERE last_seen >= ? GROUP BY rule_id ORDER BY n DESC LIMIT ?`, ts(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleCount{}
	for rows.Next() {
		var r RuleCount
		var title sql.NullString
		if err := rows.Scan(&r.RuleID, &title, &r.Severity, &r.Count); err != nil {
			return nil, err
		}
		r.Title = title.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// HostCount is alerts per host.
type HostCount struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Alerts   int    `json:"alerts"`
}

// TopHosts returns the hosts with the most alerts since `since`.
func (s *Store) TopHosts(ctx context.Context, since time.Time, limit int) ([]HostCount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT host_id, MAX(hostname), COUNT(*) AS n FROM alerts WHERE last_seen >= ?
		 GROUP BY host_id ORDER BY n DESC LIMIT ?`, ts(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostCount{}
	for rows.Next() {
		var h HostCount
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.Alerts); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RuleHits returns SUM(count) per rule for alerts seen since `since`.
func (s *Store) RuleHits(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, SUM(count) FROM alerts WHERE last_seen >= ? GROUP BY rule_id`, ts(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// AlertCountsByEntity returns alert counts keyed by process entity ID.
func (s *Store) AlertCountsByEntity(ctx context.Context, entityIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if len(entityIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(entityIDs))
	for i, v := range entityIDs {
		args[i] = v
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT process_entity_id, COUNT(*) FROM alerts WHERE process_entity_id IN (`+placeholders(len(entityIDs))+`)
		 GROUP BY process_entity_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
