package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Host groups: the organisation (Global) at the top, parent groups under it and child
// groups under those. A host is in at most one group. A group's policy overrides
// settings for its hosts and its child groups; what it leaves unset comes from its parent
// group, then from the global settings.

const groupSchema = `
CREATE TABLE IF NOT EXISTS host_groups (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	parent_id TEXT NOT NULL DEFAULT '',
	policy TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS host_groups_parent ON host_groups(parent_id);
`

func init() { featureSchemas = append(featureSchemas, groupSchema) }

// MaxGroupDepth: parent groups and their child groups.
const MaxGroupDepth = 2

// GroupPolicy holds a group's overrides. A nil field inherits.
type GroupPolicy struct {
	AV AVGroupPolicy `json:"av"`
	AI AIGroupPolicy `json:"ai"`
}

// AVGroupPolicy switches the antivirus' file scanners and response for a group.
type AVGroupPolicy struct {
	ClamAV *bool `json:"clamav,omitempty"`
	YARA   *bool `json:"yara,omitempty"`
	// Action is the response to malware: "quarantine" or "alert".
	Action *string `json:"action,omitempty"`
	// AppControl is the Windows App Control mode: "off", "audit" or "enforce".
	AppControl *string `json:"app_control,omitempty"`
}

// AIGroupPolicy: whether the AI analyst investigates the group's alerts on its own
// (when the AI analyst is set up and automatic investigations are on).
type AIGroupPolicy struct {
	Auto *bool `json:"auto,omitempty"`
}

// Validate checks the policy's values.
func (p GroupPolicy) Validate() error {
	if a := p.AV.Action; a != nil && *a != "quarantine" && *a != "alert" {
		return &GroupError{"the antivirus response is quarantine or alert"}
	}
	if a := p.AV.AppControl; a != nil && *a != "off" && *a != "audit" && *a != "enforce" {
		return &GroupError{"App Control is off, audit or enforce"}
	}
	return nil
}

// HostGroup is one group.
type HostGroup struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	ParentID  string      `json:"parent_id"`
	Policy    GroupPolicy `json:"policy"`
	CreatedAt time.Time   `json:"created_at"`
	Hosts     int         `json:"hosts"` // hosts directly in the group
}

// GroupError is a request the group tree cannot take.
type GroupError struct{ Msg string }

func (e *GroupError) Error() string { return e.Msg }

func scanGroup(row interface{ Scan(...any) error }) (*HostGroup, error) {
	var g HostGroup
	var policy, created string
	if err := row.Scan(&g.ID, &g.Name, &g.ParentID, &policy, &created, &g.Hosts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	unmarshalJSON(policy, &g.Policy)
	g.CreatedAt = parseTS(created)
	return &g, nil
}

const groupCols = `g.id, g.name, g.parent_id, g.policy, g.created_at,
	(SELECT COUNT(*) FROM hosts h WHERE h.group_id = g.id AND h.decommissioned_at IS NULL)`

// ListGroups returns every group in tree order: each parent group followed by its
// child groups, by name.
func (s *Store) ListGroups(ctx context.Context) ([]*HostGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupCols+` FROM host_groups g ORDER BY g.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []*HostGroup
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		all = append(all, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	byParent := map[string][]*HostGroup{}
	for _, g := range all {
		byParent[g.ParentID] = append(byParent[g.ParentID], g)
	}
	out := make([]*HostGroup, 0, len(all))
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		if depth > MaxGroupDepth+1 {
			return
		}
		for _, g := range byParent[parent] {
			out = append(out, g)
			walk(g.ID, depth+1)
		}
	}
	walk("", 1)
	return out, nil
}

// GetGroup returns one group.
func (s *Store) GetGroup(ctx context.Context, id string) (*HostGroup, error) {
	return scanGroup(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM host_groups g WHERE g.id = ?`, id))
}

// groupDepth returns how deep a group is (1 for a parent group).
func (s *Store) groupDepth(ctx context.Context, id string) (int, error) {
	d := 0
	for id != "" {
		d++
		if d > 10 {
			return 0, errors.New("group tree has a loop")
		}
		if err := s.db.QueryRowContext(ctx, `SELECT parent_id FROM host_groups WHERE id = ?`, id).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, ErrNotFound
			}
			return 0, err
		}
	}
	return d, nil
}

func (s *Store) checkGroupName(ctx context.Context, name, parentID, self string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return "", &GroupError{"a group name is 1 to 80 characters"}
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM host_groups WHERE parent_id = ? AND name = ? COLLATE NOCASE AND id != ?`,
		parentID, name, self).Scan(&n); err != nil {
		return "", err
	}
	if n > 0 {
		return "", &GroupError{fmt.Sprintf("there already is a group named %q here", name)}
	}
	return name, nil
}

func (s *Store) parentDepth(ctx context.Context, parentID string) (int, error) {
	if parentID == "" {
		return 0, nil
	}
	d, err := s.groupDepth(ctx, parentID)
	if errors.Is(err, ErrNotFound) {
		return 0, &GroupError{"the parent group does not exist"}
	}
	return d, err
}

// CreateGroup adds a group under parentID ("" for a parent group).
func (s *Store) CreateGroup(ctx context.Context, name, parentID string) (*HostGroup, error) {
	d, err := s.parentDepth(ctx, parentID)
	if err != nil {
		return nil, err
	}
	if d >= MaxGroupDepth {
		return nil, &GroupError{"groups go two levels deep: parent groups and their child groups"}
	}
	if name, err = s.checkGroupName(ctx, name, parentID, ""); err != nil {
		return nil, err
	}
	id := event.NewID()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO host_groups(id, name, parent_id, policy, created_at) VALUES(?,?,?,?,?)`,
		id, name, parentID, mustJSON(GroupPolicy{}), ts(time.Now())); err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

// GroupUpdate changes a group; nil fields stay as they are.
type GroupUpdate struct {
	Name     *string      `json:"name"`
	ParentID *string      `json:"parent_id"`
	Policy   *GroupPolicy `json:"policy"`
}

// UpdateGroup renames, moves or changes the policy of a group.
func (s *Store) UpdateGroup(ctx context.Context, id string, u GroupUpdate) (*HostGroup, error) {
	g, err := s.GetGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	parent := g.ParentID
	if u.ParentID != nil && *u.ParentID != g.ParentID {
		parent = *u.ParentID
		if parent == id {
			return nil, &GroupError{"a group cannot be its own parent"}
		}
		depth, err := s.parentDepth(ctx, parent)
		if err != nil {
			return nil, err
		}
		var children int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_groups WHERE parent_id = ?`, id).Scan(&children); err != nil {
			return nil, err
		}
		height := 1
		if children > 0 {
			height = 2
		}
		if depth+height > MaxGroupDepth {
			return nil, &GroupError{"groups go two levels deep: a group with child groups can only be a parent group"}
		}
	}
	name := g.Name
	if u.Name != nil || parent != g.ParentID {
		if u.Name != nil {
			name = *u.Name
		}
		if name, err = s.checkGroupName(ctx, name, parent, id); err != nil {
			return nil, err
		}
	}
	policy := g.Policy
	if u.Policy != nil {
		if err := u.Policy.Validate(); err != nil {
			return nil, err
		}
		policy = *u.Policy
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE host_groups SET name = ?, parent_id = ?, policy = ? WHERE id = ?`,
		name, parent, mustJSON(policy), id); err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

// DeleteGroup removes a group without child groups; its hosts move to its parent group.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	g, err := s.GetGroup(ctx, id)
	if err != nil {
		return err
	}
	var children int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_groups WHERE parent_id = ?`, id).Scan(&children); err != nil {
		return err
	}
	if children > 0 {
		return &GroupError{"delete or move its child groups first"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET group_id = ? WHERE group_id = ?`, g.ParentID, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET group_id = ? WHERE group_id = ?`, g.ParentID, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_groups WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetHostsGroup moves hosts into a group ("" for none). It returns how many moved.
func (s *Store) SetHostsGroup(ctx context.Context, hostIDs []string, groupID string) (int, error) {
	if groupID != "" {
		if _, err := s.GetGroup(ctx, groupID); errors.Is(err, ErrNotFound) {
			return 0, &GroupError{"the group does not exist"}
		} else if err != nil {
			return 0, err
		}
	}
	if len(hostIDs) == 0 {
		return 0, nil
	}
	args := []any{groupID}
	for _, id := range hostIDs {
		args = append(args, id)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE hosts SET group_id = ? WHERE id IN (`+placeholders(len(hostIDs))+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
