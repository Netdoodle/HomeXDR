package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// MCPToken lets an MCP client (Claude Code, Claude Desktop) use the MCP endpoint: read
// telemetry and alerts, and record AI triage reports. Token is only set when created.
type MCPToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Token      string     `json:"token,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

const mcpTokenSchema = `
CREATE TABLE IF NOT EXISTS mcp_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	last_used_at TEXT
);
`

// mcpTokenPrefix marks MCP tokens so they are recognizable in config files.
const mcpTokenPrefix = "hxm_"

// CreateMCPToken creates an MCP token. The plaintext token is returned once.
func (s *Store) CreateMCPToken(ctx context.Context, name, createdBy string) (*MCPToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "mcp"
	}
	t := &MCPToken{ID: event.NewID(), Name: name, Token: mcpTokenPrefix + RandomToken(32), CreatedAt: time.Now().UTC(), CreatedBy: createdBy}
	_, err := s.db.ExecContext(ctx, `INSERT INTO mcp_tokens(id, name, token_hash, created_at, created_by) VALUES(?,?,?,?,?)`,
		t.ID, t.Name, hashToken(t.Token), ts(t.CreatedAt), createdBy)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func scanMCPToken(row interface{ Scan(...any) error }) (*MCPToken, error) {
	var t MCPToken
	var created string
	var used sql.NullString
	if err := row.Scan(&t.ID, &t.Name, &created, &t.CreatedBy, &used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = parseTS(created)
	t.LastUsedAt = parseNullTS(used)
	return &t, nil
}

// ListMCPTokens returns all MCP tokens, newest first.
func (s *Store) ListMCPTokens(ctx context.Context) ([]*MCPToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, created_by, last_used_at FROM mcp_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MCPToken{}
	for rows.Next() {
		t, err := scanMCPToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteMCPToken revokes an MCP token.
func (s *Store) DeleteMCPToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mcp_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateMCPToken returns the token record for a plaintext MCP token and notes
// its use (at most once a minute). ErrNotFound when it is unknown.
func (s *Store) AuthenticateMCPToken(ctx context.Context, token string) (*MCPToken, error) {
	if !strings.HasPrefix(token, mcpTokenPrefix) {
		return nil, ErrNotFound
	}
	h := hashToken(token)
	t, err := scanMCPToken(s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at, created_by, last_used_at FROM mcp_tokens WHERE token_hash = ?`, h))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?`, ts(now), t.ID)
		t.LastUsedAt = &now
	}
	return t, nil
}
