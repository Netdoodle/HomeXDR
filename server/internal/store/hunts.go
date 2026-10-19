package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Hunt statuses.
const (
	HuntRunning   = "running"
	HuntStopped   = "stopped"
	HuntCompleted = "completed"
)

// HuntTarget selects the hosts a hunt runs on.
type HuntTarget struct {
	All      bool     `json:"all,omitempty"`
	Labels   []string `json:"labels,omitempty"`
	HostIDs  []string `json:"host_ids,omitempty"`
	Platform string   `json:"platform,omitempty"`
}

// Matches reports whether an endpoint host is in the target.
func (t HuntTarget) Matches(h *Host) bool {
	if h.Kind != HostEndpoint || h.Revoked {
		return false
	}
	if t.Platform != "" && h.OS.Platform != t.Platform {
		return false
	}
	if t.All {
		return true
	}
	for _, id := range t.HostIDs {
		if id == h.ID {
			return true
		}
	}
	return len(t.Labels) > 0 && anyFold(h.Labels, t.Labels)
}

// HuntStats summarizes a hunt's commands.
type HuntStats struct {
	Scheduled int `json:"scheduled"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Rows      int `json:"rows"`
}

// Hunt is a hunt in API shape.
type Hunt struct {
	ID          string            `json:"id"`
	Artifact    string            `json:"artifact"`
	Params      map[string]string `json:"params"`
	Description string            `json:"description,omitempty"`
	Target      HuntTarget        `json:"target"`
	Status      string            `json:"status"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Stats       HuntStats         `json:"stats"`
}

// CreateHunt stores a hunt. Commands are queued by the caller.
func (s *Store) CreateHunt(ctx context.Context, artifact string, params map[string]string, desc string, target HuntTarget, createdBy string, ttl time.Duration) (*Hunt, error) {
	if params == nil {
		params = map[string]string{}
	}
	now := time.Now().UTC()
	h := &Hunt{
		ID: event.NewID(), Artifact: artifact, Params: params, Description: desc, Target: target,
		Status: HuntRunning, CreatedBy: createdBy, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hunts(id, artifact, params, description, target, status, created_by, created_at, expires_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		h.ID, artifact, mustJSON(params), desc, mustJSON(target), h.Status, createdBy, ts(now), ts(h.ExpiresAt))
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Store) scanHunt(ctx context.Context, row interface{ Scan(...any) error }) (*Hunt, error) {
	var h Hunt
	var params, target, created, expires string
	if err := row.Scan(&h.ID, &h.Artifact, &params, &h.Description, &target, &h.Status, &h.CreatedBy, &created, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	unmarshalJSON(params, &h.Params)
	unmarshalJSON(target, &h.Target)
	h.CreatedAt, h.ExpiresAt = parseTS(created), parseTS(expires)
	if h.Status == HuntRunning && time.Now().After(h.ExpiresAt) {
		h.Status = HuntCompleted
	}
	return &h, nil
}

const huntCols = `id, artifact, params, description, target, status, created_by, created_at, expires_at`

func (s *Store) fillHuntStats(ctx context.Context, h *Hunt) error {
	return s.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		   COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN status IN ('failed','rejected','expired') THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(row_count), 0)
		 FROM commands WHERE hunt_id = ?`, h.ID).Scan(&h.Stats.Scheduled, &h.Stats.Completed, &h.Stats.Failed, &h.Stats.Rows)
}

// GetHunt returns a hunt with stats.
func (s *Store) GetHunt(ctx context.Context, id string) (*Hunt, error) {
	h, err := s.scanHunt(ctx, s.db.QueryRowContext(ctx, `SELECT `+huntCols+` FROM hunts WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return h, s.fillHuntStats(ctx, h)
}

// ListHunts returns hunts newest first, with stats.
func (s *Store) ListHunts(ctx context.Context) ([]*Hunt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+huntCols+` FROM hunts ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	var out []*Hunt
	for rows.Next() {
		h, err := s.scanHunt(ctx, rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, h := range out {
		if err := s.fillHuntStats(ctx, h); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []*Hunt{}
	}
	return out, nil
}

// ActiveHunts returns running, unexpired hunts.
func (s *Store) ActiveHunts(ctx context.Context) ([]*Hunt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+huntCols+` FROM hunts WHERE status = 'running' AND expires_at > ?`, ts(time.Now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Hunt
	for rows.Next() {
		h, err := s.scanHunt(ctx, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// StopHunt stops a hunt and expires its undelivered commands.
func (s *Store) StopHunt(ctx context.Context, id string) (*Hunt, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE hunts SET status = 'stopped' WHERE id = ? AND status = 'running'`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.GetHunt(ctx, id); err != nil {
			return nil, err
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE commands SET status = 'expired', completed_at = ? WHERE hunt_id = ? AND status = 'queued'`,
		ts(time.Now()), id); err != nil {
		return nil, err
	}
	return s.GetHunt(ctx, id)
}

// HuntHasHost reports whether a hunt already has a command for a host.
func (s *Store) HuntHasHost(ctx context.Context, huntID, hostID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands WHERE hunt_id = ? AND host_id = ?`, huntID, hostID).Scan(&n)
	return n > 0, err
}

// HuntRow is one artifact row from a hunt.
type HuntRow struct {
	HostID   string          `json:"host_id"`
	Hostname string          `json:"hostname"`
	Row      json.RawMessage `json:"row"`
}

// HuntResults returns a hunt's rows, optionally for one host.
func (s *Store) HuntResults(ctx context.Context, huntID, hostID string, limit, offset int) ([]HuntRow, int, error) {
	limit, offset = clampLimit(limit, offset)
	where := ` WHERE r.hunt_id = ?`
	args := []any{huntID}
	if hostID != "" {
		where += ` AND r.host_id = ?`
		args = append(args, hostID)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM command_rows r`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.host_id, COALESCE(h.hostname, ''), r.row FROM command_rows r LEFT JOIN hosts h ON h.id = r.host_id`+
			where+` ORDER BY r.host_id, r.command_id, r.seq LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []HuntRow{}
	for rows.Next() {
		var hr HuntRow
		var row string
		if err := rows.Scan(&hr.HostID, &hr.Hostname, &row); err != nil {
			return nil, 0, err
		}
		hr.Row = json.RawMessage(row)
		out = append(out, hr)
	}
	return out, total, rows.Err()
}
