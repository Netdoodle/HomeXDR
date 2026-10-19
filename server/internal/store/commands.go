package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// CommandRecord is a command in API shape.
type CommandRecord struct {
	ID          string          `json:"id"`
	HostID      string          `json:"host_id"`
	Hostname    string          `json:"hostname"`
	Type        string          `json:"type"`
	Params      json.RawMessage `json:"params"`
	Status      string          `json:"status"`
	IssuedBy    string          `json:"issued_by"`
	IssuedAt    time.Time       `json:"issued_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Error       string          `json:"error,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	RowCount    int             `json:"row_count,omitempty"`
	HuntID      string          `json:"hunt_id,omitempty"`
	HasUpload   bool            `json:"has_upload,omitempty"`

	UploadPath string `json:"-"`
	UploadName string `json:"-"`
}

// Command returns the wire form of the record.
func (c *CommandRecord) Command() api.Command {
	return api.Command{
		ID: c.ID, AgentID: c.HostID, Type: c.Type, Params: c.Params,
		IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, IssuedBy: c.IssuedBy, HuntID: c.HuntID,
	}
}

// DefaultCommandTTL is how long a queued command waits for its agent.
const DefaultCommandTTL = 24 * time.Hour

// CreateCommand queues a command for a host.
func (s *Store) CreateCommand(ctx context.Context, hostID, typ string, params json.RawMessage, issuedBy, huntID string, ttl time.Duration) (*CommandRecord, error) {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if ttl <= 0 {
		ttl = DefaultCommandTTL
	}
	now := time.Now().UTC()
	id := event.NewID()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO commands(id, host_id, type, params, status, issued_by, issued_at, expires_at, hunt_id)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, hostID, typ, string(params), api.StatusQueued, issuedBy, ts(now), ts(now.Add(ttl)), huntID)
	if err != nil {
		return nil, err
	}
	return s.GetCommand(ctx, id)
}

const commandCols = `c.id, c.host_id, COALESCE(h.hostname, ''), c.type, c.params, c.status, c.issued_by, c.issued_at,
	c.expires_at, c.delivered_at, c.completed_at, c.error, c.output, c.row_count, c.hunt_id, c.upload_path, c.upload_name`

const commandFrom = ` FROM commands c LEFT JOIN hosts h ON h.id = c.host_id`

func scanCommand(row interface{ Scan(...any) error }) (*CommandRecord, error) {
	var c CommandRecord
	var params, issued, expires, output string
	var delivered, completed sql.NullString
	if err := row.Scan(&c.ID, &c.HostID, &c.Hostname, &c.Type, &params, &c.Status, &c.IssuedBy, &issued,
		&expires, &delivered, &completed, &c.Error, &output, &c.RowCount, &c.HuntID, &c.UploadPath, &c.UploadName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.Params = json.RawMessage(params)
	if output != "" {
		c.Output = json.RawMessage(output)
	}
	c.IssuedAt, c.ExpiresAt = parseTS(issued), parseTS(expires)
	c.DeliveredAt, c.CompletedAt = parseNullTS(delivered), parseNullTS(completed)
	c.HasUpload = c.UploadPath != ""
	return &c, nil
}

// GetCommand returns one command.
func (s *Store) GetCommand(ctx context.Context, id string) (*CommandRecord, error) {
	return scanCommand(s.db.QueryRowContext(ctx, `SELECT `+commandCols+commandFrom+` WHERE c.id = ?`, id))
}

// ListHostCommands returns a host's commands, newest first.
func (s *Store) ListHostCommands(ctx context.Context, hostID string, limit int) ([]*CommandRecord, error) {
	limit, _ = clampLimit(limit, 0)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+commandCols+commandFrom+` WHERE c.host_id = ? ORDER BY c.issued_at DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CommandRecord{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasPendingCommands reports whether a host has queued, unexpired commands.
func (s *Store) HasPendingCommands(ctx context.Context, hostID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM commands WHERE host_id = ? AND status = 'queued' AND expires_at > ?`,
		hostID, ts(time.Now())).Scan(&n)
	return n > 0, err
}

// TakePendingCommands returns up to limit queued, unexpired commands for a host and marks
// them delivered.
func (s *Store) TakePendingCommands(ctx context.Context, hostID string, limit int) ([]*CommandRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	rows, err := tx.QueryContext(ctx,
		`SELECT `+commandCols+commandFrom+` WHERE c.host_id = ? AND c.status = 'queued' AND c.expires_at > ?
		 ORDER BY c.issued_at LIMIT ?`, hostID, ts(now), limit)
	if err != nil {
		return nil, err
	}
	var out []*CommandRecord
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	for _, c := range out {
		if _, err := tx.ExecContext(ctx,
			`UPDATE commands SET status = 'delivered', delivered_at = ? WHERE id = ?`, ts(now), c.ID); err != nil {
			return nil, err
		}
		c.Status = api.StatusDelivered
		c.DeliveredAt = &now
	}
	return out, tx.Commit()
}

// FinalStatus reports whether a command status is terminal.
func FinalStatus(s string) bool {
	switch s {
	case api.StatusCompleted, api.StatusFailed, api.StatusRejected, api.StatusExpired:
		return true
	}
	return false
}

// RecordResult applies an agent's result to its command. It returns ErrNotFound if the
// command does not exist or belongs to another host, and ErrConflict if it is already
// final.
func (s *Store) RecordResult(ctx context.Context, hostID string, r api.CommandResult) (*CommandRecord, error) {
	c, err := s.GetCommand(ctx, r.CommandID)
	if err != nil {
		return nil, err
	}
	if c.HostID != hostID {
		return nil, ErrNotFound
	}
	if FinalStatus(c.Status) {
		return nil, ErrConflict
	}
	switch r.Status {
	case api.StatusRunning, api.StatusCompleted, api.StatusFailed, api.StatusRejected:
	default:
		return nil, errors.New("invalid result status")
	}
	var completed any
	if FinalStatus(r.Status) {
		completed = ts(time.Now())
	}
	output := ""
	if len(r.Output) > 0 && json.Valid(r.Output) {
		output = truncate(string(r.Output), 1<<20)
	}
	rowCount := c.RowCount
	if r.RowCount > rowCount {
		rowCount = r.RowCount
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE commands SET status = ?, error = ?, output = CASE WHEN ? = '' THEN output ELSE ? END,
		   row_count = ?, completed_at = COALESCE(?, completed_at) WHERE id = ?`,
		r.Status, truncate(r.Error, 4000), output, output, rowCount, completed, c.ID); err != nil {
		return nil, err
	}
	return s.GetCommand(ctx, c.ID)
}

// MaxRowsPerCommand caps stored artifact rows per command.
const MaxRowsPerCommand = 100000

// AddRows stores artifact rows for a command and returns how many were stored.
func (s *Store) AddRows(ctx context.Context, c *CommandRecord, rows []json.RawMessage) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM command_rows WHERE command_id = ?`, c.ID).Scan(&next); err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO command_rows(command_id, seq, host_id, hunt_id, row) VALUES(?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	stored := 0
	for _, r := range rows {
		if next >= MaxRowsPerCommand {
			break
		}
		if !json.Valid(r) {
			continue
		}
		if _, err := stmt.ExecContext(ctx, c.ID, next, c.HostID, c.HuntID, string(r)); err != nil {
			return 0, err
		}
		next++
		stored++
	}
	if _, err := tx.ExecContext(ctx, `UPDATE commands SET row_count = ? WHERE id = ?`, next, c.ID); err != nil {
		return 0, err
	}
	return stored, tx.Commit()
}

// ListRows returns a command's artifact rows.
func (s *Store) ListRows(ctx context.Context, commandID string, limit, offset int) ([]json.RawMessage, int, error) {
	limit, offset = clampLimit(limit, offset)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM command_rows WHERE command_id = ?`, commandID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT row FROM command_rows WHERE command_id = ? ORDER BY seq LIMIT ? OFFSET ?`, commandID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, 0, err
		}
		out = append(out, json.RawMessage(r))
	}
	return out, total, rows.Err()
}

// SetUpload records the stored path of a file uploaded for a command.
func (s *Store) SetUpload(ctx context.Context, id, path, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE commands SET upload_path = ?, upload_name = ? WHERE id = ?`, path, name, id)
	return err
}

// StaleResultGrace is how long after expiry a delivered or running command may go
// without a final result before it is marked failed.
const StaleResultGrace = 24 * time.Hour

// ExpireCommands marks queued commands past their expiry as expired, and delivered or
// running commands that never reported a final result as failed.
func (s *Store) ExpireCommands(ctx context.Context) (int, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE commands SET status = 'expired', completed_at = ? WHERE status = 'queued' AND expires_at <= ?`,
		ts(now), ts(now))
	if err != nil {
		return 0, err
	}
	expired, _ := res.RowsAffected()
	res, err = s.db.ExecContext(ctx,
		`UPDATE commands SET status = 'failed', error = 'no result from agent', completed_at = ?
		 WHERE status IN ('delivered', 'running') AND expires_at <= ?`,
		ts(now), ts(now.Add(-StaleResultGrace)))
	if err != nil {
		return 0, err
	}
	stale, _ := res.RowsAffected()
	return int(expired + stale), nil
}
