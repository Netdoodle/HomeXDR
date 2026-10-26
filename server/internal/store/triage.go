package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// AI triage statuses.
const (
	TriageQueued  = "queued"
	TriageRunning = "running"
	TriageDone    = "done"
	TriageFailed  = "failed"
	TriageRefused = "refused" // the model declined (safety classifier)
	TriageSkipped = "skipped" // e.g. the daily limit was reached
)

// Triage engines: who runs a queued investigation.
const (
	EngineAPI = "api" // the server's own worker, through an AI provider's API
	EngineMCP = "mcp" // an MCP client (e.g. Claude Code) claims it with next_investigation
)

// Triage is the AI analyst's investigation of one alert. It is stored next to the
// alert, never in it: the AI annotates and does not change the alert.
type Triage struct {
	AlertID     string          `json:"alert_id"`
	Status      string          `json:"status"`
	Trigger     string          `json:"trigger"` // auto | manual
	Engine      string          `json:"engine"`  // api | mcp
	RequestedBy string          `json:"requested_by,omitempty"`
	Provider    string          `json:"provider,omitempty"`
	Model       string          `json:"model,omitempty"`
	Verdict     string          `json:"verdict,omitempty"`
	Confidence  string          `json:"confidence,omitempty"`
	Report      json.RawMessage `json:"report,omitempty"`
	Transcript  json.RawMessage `json:"transcript,omitempty"`
	Error       string          `json:"error,omitempty"`
	ToolCalls   int             `json:"tool_calls"`
	Usage       TriageUsage     `json:"usage"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
}

// TriageUsage is the token usage of one investigation.
type TriageUsage struct {
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	CacheReadTokens int64 `json:"cache_read_tokens"`
}

// TriageSummary is shown with alerts in lists.
type TriageSummary struct {
	Status     string `json:"status"`
	Verdict    string `json:"verdict,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

const triageSchema = `
CREATE TABLE IF NOT EXISTS alert_triage (
	alert_id TEXT PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
	status TEXT NOT NULL,
	trigger TEXT NOT NULL,
	requested_by TEXT NOT NULL DEFAULT '',
	provider TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	verdict TEXT NOT NULL DEFAULT '',
	confidence TEXT NOT NULL DEFAULT '',
	report TEXT NOT NULL DEFAULT '',
	transcript TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	tool_calls INTEGER NOT NULL DEFAULT 0,
	usage TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL,
	started_at TEXT,
	finished_at TEXT
);
CREATE INDEX IF NOT EXISTS alert_triage_status ON alert_triage(status, created_at);
`

const triageCols = `alert_id, status, trigger, engine, requested_by, provider, model, verdict, confidence,
	report, transcript, error, tool_calls, usage, created_at, started_at, finished_at`

func scanTriage(row interface{ Scan(...any) error }) (*Triage, error) {
	var t Triage
	var report, transcript, usage, created string
	var started, finished sql.NullString
	err := row.Scan(&t.AlertID, &t.Status, &t.Trigger, &t.Engine, &t.RequestedBy, &t.Provider, &t.Model, &t.Verdict,
		&t.Confidence, &report, &transcript, &t.Error, &t.ToolCalls, &usage, &created, &started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if report != "" {
		t.Report = json.RawMessage(report)
	}
	if transcript != "" {
		t.Transcript = json.RawMessage(transcript)
	}
	unmarshalJSON(usage, &t.Usage)
	t.CreatedAt = parseTS(created)
	t.StartedAt = parseNullTS(started)
	t.FinishedAt = parseNullTS(finished)
	return &t, nil
}

// QueueTriage queues an investigation of an alert for an engine, replacing a finished
// one. It returns ErrConflict while one is already queued or running.
func (s *Store) QueueTriage(ctx context.Context, alertID, trigger, requestedBy, engine string) (*Triage, error) {
	return s.putTriage(ctx, alertID, TriageQueued, trigger, requestedBy, engine, "")
}

// StartTriage records an investigation that is already under way (an MCP client
// investigating an alert it chose), replacing a finished one. ErrConflict as QueueTriage.
func (s *Store) StartTriage(ctx context.Context, alertID, trigger, requestedBy, engine string) (*Triage, error) {
	return s.putTriage(ctx, alertID, TriageRunning, trigger, requestedBy, engine, "")
}

// SkipTriage records that an alert was not investigated, and why.
func (s *Store) SkipTriage(ctx context.Context, alertID, trigger, engine, reason string) (*Triage, error) {
	return s.putTriage(ctx, alertID, TriageSkipped, trigger, "", engine, reason)
}

func (s *Store) putTriage(ctx context.Context, alertID, status, trigger, requestedBy, engine, reason string) (*Triage, error) {
	if engine == "" {
		engine = EngineAPI
	}
	now := ts(time.Now())
	var started any
	if status == TriageRunning {
		started = now
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alert_triage(alert_id, status, trigger, engine, requested_by, error, created_at, started_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(alert_id) DO UPDATE SET status = excluded.status, trigger = excluded.trigger, engine = excluded.engine,
			requested_by = excluded.requested_by, provider = '', model = '', verdict = '', confidence = '',
			report = '', transcript = '', error = excluded.error, tool_calls = 0, usage = '{}',
			created_at = excluded.created_at, started_at = excluded.started_at, finished_at = NULL
		WHERE alert_triage.status NOT IN ('queued', 'running')`,
		alertID, status, trigger, engine, requestedBy, reason, now, started)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrConflict
	}
	return s.GetTriage(ctx, alertID)
}

// GetTriage returns an alert's triage record.
func (s *Store) GetTriage(ctx context.Context, alertID string) (*Triage, error) {
	return scanTriage(s.db.QueryRowContext(ctx, `SELECT `+triageCols+` FROM alert_triage WHERE alert_id = ?`, alertID))
}

// ClaimTriage marks the oldest investigation queued for an engine as running and
// returns it, or ErrNotFound when there is none.
func (s *Store) ClaimTriage(ctx context.Context, engine string) (*Triage, error) {
	for {
		var id string
		err := s.db.QueryRowContext(ctx,
			`SELECT alert_id FROM alert_triage WHERE status = 'queued' AND engine = ? ORDER BY created_at LIMIT 1`, engine).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		claimed, err := s.ClaimQueuedTriage(ctx, id, engine)
		if errors.Is(err, ErrConflict) {
			continue // someone else claimed it first
		}
		return claimed, err
	}
}

// ClaimQueuedTriage marks one alert's investigation, queued for engine, as running.
// ErrConflict when it is not queued for that engine.
func (s *Store) ClaimQueuedTriage(ctx context.Context, alertID, engine string) (*Triage, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE alert_triage SET status = 'running', started_at = ?
		WHERE alert_id = ? AND status = 'queued' AND engine = ?`, ts(time.Now()), alertID, engine)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrConflict
	}
	return s.GetTriage(ctx, alertID)
}

// CountQueuedTriages counts investigations waiting for an engine.
func (s *Store) CountQueuedTriages(ctx context.Context, engine string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_triage WHERE status = 'queued' AND engine = ?`, engine).Scan(&n)
	return n, err
}

// FailStaleTriages marks an engine's investigations that have been running since before
// t as failed with reason (an MCP client that stopped without reporting). They are not
// requeued, so a client that keeps failing cannot loop.
func (s *Store) FailStaleTriages(ctx context.Context, engine string, before time.Time, reason string) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE alert_triage SET status = 'failed', error = ?, finished_at = ?
		WHERE status = 'running' AND engine = ? AND started_at < ?`, reason, ts(time.Now()), engine, ts(before))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// FinishTriage stores the outcome of a running investigation.
func (s *Store) FinishTriage(ctx context.Context, t *Triage) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alert_triage SET status = ?, provider = ?, model = ?, verdict = ?,
		confidence = ?, report = ?, transcript = ?, error = ?, tool_calls = ?, usage = ?, finished_at = ?
		WHERE alert_id = ?`,
		t.Status, t.Provider, t.Model, t.Verdict, t.Confidence, string(t.Report), string(t.Transcript),
		t.Error, t.ToolCalls, mustJSON(t.Usage), ts(time.Now()), t.AlertID)
	return err
}

// RequeueRunningTriages puts the server's own (API engine) investigations interrupted
// by a restart back in the queue.
func (s *Store) RequeueRunningTriages(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE alert_triage SET status = 'queued', started_at = NULL WHERE status = 'running' AND engine = 'api'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// CountTriages counts investigations of a trigger kind created since t (skipped ones
// excluded), for the daily limit.
func (s *Store) CountTriages(ctx context.Context, trigger string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_triage
		WHERE trigger = ? AND created_at >= ? AND status != 'skipped'`, trigger, ts(since)).Scan(&n)
	return n, err
}

// TriageSummaries returns the triage status and verdict of the given alerts.
func (s *Store) TriageSummaries(ctx context.Context, alertIDs []string) (map[string]*TriageSummary, error) {
	out := map[string]*TriageSummary{}
	if len(alertIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(alertIDs))
	for i, id := range alertIDs {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT alert_id, status, verdict, confidence FROM alert_triage
		WHERE alert_id IN (`+placeholders(len(alertIDs))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var t TriageSummary
		if err := rows.Scan(&id, &t.Status, &t.Verdict, &t.Confidence); err != nil {
			return nil, err
		}
		out[id] = &t
	}
	return out, rows.Err()
}

// attachTriage fills Alert.AITriage for a page of alerts.
func (s *Store) attachTriage(ctx context.Context, alerts []*Alert) {
	ids := make([]string, len(alerts))
	for i, a := range alerts {
		ids[i] = a.ID
	}
	m, err := s.TriageSummaries(ctx, ids)
	if err != nil {
		return
	}
	for _, a := range alerts {
		a.AITriage = m[a.ID]
	}
}
