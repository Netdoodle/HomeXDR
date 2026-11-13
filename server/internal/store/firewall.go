package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Host firewall block policies: addresses blocked in the hosts' own firewalls, each for
// every host (Global, group_id '') or for one group and its child groups. The core
// validates them (shared/hostfw) and turns them into each host's rule set.

const firewallSchema = `
CREATE TABLE IF NOT EXISTS firewall_blocks (
	id TEXT PRIMARY KEY,
	cidr TEXT NOT NULL,
	direction TEXT NOT NULL DEFAULT 'both',
	group_id TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	alert_id TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS firewall_blocks_scope ON firewall_blocks(cidr, group_id);
`

func init() { featureSchemas = append(featureSchemas, firewallSchema) }

// FirewallBlock is one blocked address or network.
type FirewallBlock struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`      // canonical: an address, or a masked CIDR
	Direction string    `json:"direction"` // both, in, out
	GroupID   string    `json:"group_id"`  // "" for every host (Global)
	Note      string    `json:"note"`
	AlertID   string    `json:"alert_id,omitempty"` // the alert it was blocked from
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

const firewallCols = `id, cidr, direction, group_id, note, alert_id, created_by, created_at`

func scanFirewallBlock(row interface{ Scan(...any) error }) (*FirewallBlock, error) {
	var b FirewallBlock
	var created string
	if err := row.Scan(&b.ID, &b.CIDR, &b.Direction, &b.GroupID, &b.Note, &b.AlertID, &b.CreatedBy, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	b.CreatedAt = parseTS(created)
	return &b, nil
}

// ListFirewallBlocks returns every block, newest first.
func (s *Store) ListFirewallBlocks(ctx context.Context) ([]*FirewallBlock, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+firewallCols+` FROM firewall_blocks ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FirewallBlock{}
	for rows.Next() {
		b, err := scanFirewallBlock(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetFirewallBlock returns one block.
func (s *Store) GetFirewallBlock(ctx context.Context, id string) (*FirewallBlock, error) {
	return scanFirewallBlock(s.db.QueryRowContext(ctx, `SELECT `+firewallCols+` FROM firewall_blocks WHERE id = ?`, id))
}

// CountFirewallBlocks counts the blocks.
func (s *Store) CountFirewallBlocks(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM firewall_blocks`).Scan(&n)
	return n, err
}

// CreateFirewallBlock stores a block (already validated), setting its ID and time. The
// same address twice in one scope is ErrConflict.
func (s *Store) CreateFirewallBlock(ctx context.Context, b *FirewallBlock) error {
	b.ID = event.NewID()
	b.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO firewall_blocks(`+firewallCols+`) VALUES(?,?,?,?,?,?,?,?)`,
		b.ID, b.CIDR, b.Direction, b.GroupID, b.Note, b.AlertID, b.CreatedBy, ts(b.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrConflict
	}
	return err
}

// DeleteFirewallBlock removes a block.
func (s *Store) DeleteFirewallBlock(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM firewall_blocks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
