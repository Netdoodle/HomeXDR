package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// RuleRepoSettings are the admin's choices for a rule repository.
type RuleRepoSettings struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Ref  string `json:"ref"` // branch, tag or commit; "" = the default branch
	// Paths are the folders whose rules are loaded; empty = the whole repository.
	Paths []string `json:"paths"`
	// MinLevel skips rules below this level ("" = all levels).
	MinLevel string `json:"min_level"`
	// Statuses are the Sigma statuses to load; empty = all but deprecated and unsupported.
	Statuses []string `json:"statuses"`
	// EnableRules is whether rules from this repository start enabled. Rules an admin
	// enabled or disabled by hand keep that choice across updates.
	EnableRules bool `json:"enable_rules"`
	// AutoUpdate installs new versions as they are found. Without it new versions are
	// only reported, and an admin installs them.
	AutoUpdate    bool `json:"auto_update"`
	IntervalHours int  `json:"interval_hours"` // how often to check for a new version
	Enabled       bool `json:"enabled"`        // load this repository's rules at all
}

// RuleRepoState is what the server last saw and installed.
type RuleRepoState struct {
	Version       string     `json:"version,omitempty"`        // installed commit or archive hash
	LatestVersion string     `json:"latest_version,omitempty"` // newest version found by the last check
	ETag          string     `json:"-"`
	LastModified  string     `json:"-"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
	InstalledAt   *time.Time `json:"installed_at,omitempty"`
	Error         string     `json:"error,omitempty"` // last check or update failure
	Files         int        `json:"files"`           // rule files on disk
	Folders       []Folder   `json:"folders"`         // folders in the download, for choosing Paths
	// Added and Removed count rule IDs the last installed update added and removed.
	Added   int `json:"added"`
	Removed int `json:"removed"`
}

// Folder is a folder in a downloaded repository and how many rule files it holds.
type Folder struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
}

// RuleRepo is a repository of Sigma rules the server downloads and keeps up to date.
type RuleRepo struct {
	ID string `json:"id"`
	RuleRepoSettings
	RuleRepoState
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

const ruleRepoSchema = `
CREATE TABLE IF NOT EXISTS rule_repos (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	url TEXT NOT NULL,
	ref TEXT NOT NULL DEFAULT '',
	paths TEXT NOT NULL DEFAULT '[]',
	min_level TEXT NOT NULL DEFAULT '',
	statuses TEXT NOT NULL DEFAULT '[]',
	enable_rules INTEGER NOT NULL DEFAULT 1,
	auto_update INTEGER NOT NULL DEFAULT 1,
	interval_hours INTEGER NOT NULL DEFAULT 24,
	enabled INTEGER NOT NULL DEFAULT 1,
	version TEXT NOT NULL DEFAULT '',
	latest_version TEXT NOT NULL DEFAULT '',
	etag TEXT NOT NULL DEFAULT '',
	last_modified TEXT NOT NULL DEFAULT '',
	checked_at TEXT,
	installed_at TEXT,
	error TEXT NOT NULL DEFAULT '',
	files INTEGER NOT NULL DEFAULT 0,
	folders TEXT NOT NULL DEFAULT '[]',
	added INTEGER NOT NULL DEFAULT 0,
	removed INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL
);
`

const ruleRepoCols = `id, name, url, ref, paths, min_level, statuses, enable_rules, auto_update, interval_hours,
	enabled, version, latest_version, etag, last_modified, checked_at, installed_at, error, files, folders,
	added, removed, created_at, created_by`

func scanRuleRepo(row interface{ Scan(...any) error }) (*RuleRepo, error) {
	var r RuleRepo
	var paths, statuses, folders, created string
	var enableRules, auto, enabled int
	var checked, installed sql.NullString
	err := row.Scan(&r.ID, &r.Name, &r.URL, &r.Ref, &paths, &r.MinLevel, &statuses, &enableRules, &auto, &r.IntervalHours,
		&enabled, &r.Version, &r.LatestVersion, &r.ETag, &r.LastModified, &checked, &installed, &r.Error, &r.Files, &folders,
		&r.Added, &r.Removed, &created, &r.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Paths, r.Statuses, r.Folders = []string{}, []string{}, []Folder{}
	unmarshalJSON(paths, &r.Paths)
	unmarshalJSON(statuses, &r.Statuses)
	unmarshalJSON(folders, &r.Folders)
	r.EnableRules, r.AutoUpdate, r.Enabled = enableRules != 0, auto != 0, enabled != 0
	r.CheckedAt, r.InstalledAt = parseNullTS(checked), parseNullTS(installed)
	r.CreatedAt = parseTS(created)
	return &r, nil
}

// ListRuleRepos returns rule repositories in the order they were added, which is also
// their precedence when two repositories hold a rule with the same ID.
func (s *Store) ListRuleRepos(ctx context.Context) ([]*RuleRepo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleRepoCols+` FROM rule_repos ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RuleRepo{}
	for rows.Next() {
		r, err := scanRuleRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRuleRepo returns one rule repository.
func (s *Store) GetRuleRepo(ctx context.Context, id string) (*RuleRepo, error) {
	return scanRuleRepo(s.db.QueryRowContext(ctx, `SELECT `+ruleRepoCols+` FROM rule_repos WHERE id = ?`, id))
}

// CreateRuleRepo adds a rule repository. Nothing is downloaded yet.
func (s *Store) CreateRuleRepo(ctx context.Context, set RuleRepoSettings, createdBy string) (*RuleRepo, error) {
	id := event.NewID()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rule_repos(id, name, url, ref, paths, min_level, statuses, enable_rules, auto_update, interval_hours,
		   enabled, created_at, created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, set.Name, set.URL, set.Ref, mustJSON(nonNil(set.Paths)), set.MinLevel, mustJSON(nonNil(set.Statuses)),
		boolInt(set.EnableRules), boolInt(set.AutoUpdate), set.IntervalHours, boolInt(set.Enabled), ts(time.Now()), createdBy)
	if err != nil {
		return nil, err
	}
	return s.GetRuleRepo(ctx, id)
}

// UpdateRuleRepoSettings replaces a repository's settings, leaving its state alone.
func (s *Store) UpdateRuleRepoSettings(ctx context.Context, id string, set RuleRepoSettings) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE rule_repos SET name = ?, url = ?, ref = ?, paths = ?, min_level = ?, statuses = ?, enable_rules = ?,
		   auto_update = ?, interval_hours = ?, enabled = ? WHERE id = ?`,
		set.Name, set.URL, set.Ref, mustJSON(nonNil(set.Paths)), set.MinLevel, mustJSON(nonNil(set.Statuses)),
		boolInt(set.EnableRules), boolInt(set.AutoUpdate), set.IntervalHours, boolInt(set.Enabled), id)
	return affected(res, err)
}

// UpdateRuleRepoState replaces what the server knows about a repository's versions.
func (s *Store) UpdateRuleRepoState(ctx context.Context, id string, st RuleRepoState) error {
	folders := st.Folders
	if folders == nil {
		folders = []Folder{}
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE rule_repos SET version = ?, latest_version = ?, etag = ?, last_modified = ?, checked_at = ?, installed_at = ?,
		   error = ?, files = ?, folders = ?, added = ?, removed = ? WHERE id = ?`,
		st.Version, st.LatestVersion, st.ETag, st.LastModified, nullTS(st.CheckedAt), nullTS(st.InstalledAt),
		truncate(st.Error, 2000), st.Files, mustJSON(folders), st.Added, st.Removed, id)
	return affected(res, err)
}

// DeleteRuleRepo removes a rule repository. Enabled/disabled choices for its rules are
// kept, so adding it back restores them.
func (s *Store) DeleteRuleRepo(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rule_repos WHERE id = ?`, id)
	return affected(res, err)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
