package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/rulerepo"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/version"
)

// Rule repositories are downloaded into <data>/rule-repos/<id>. Downloads go to a
// sibling folder first and are swapped in once complete, so a failed or partial update
// never replaces the installed rules.

// ErrRepoBusy is returned while a repository is being checked or updated.
var ErrRepoBusy = errors.New("this repository is being updated; try again when it finishes")

const (
	maxRuleRepos         = 50
	defaultRepoInterval  = 24
	maxRepoIntervalHours = 24 * 30
	// repoRetry is how soon a failed check or update is retried, when the interval is longer.
	repoRetry = time.Hour
)

var sigmaStatuses = []string{"stable", "test", "experimental", "deprecated", "unsupported"}

// RepoDir is where a rule repository's files are kept.
func (c *Core) RepoDir(id string) string {
	return filepath.Join(c.Cfg.DataDir, "rule-repos", id)
}

// RuleRepos downloads rule repositories and keeps them current: on their schedule
// (Run), and when an admin asks.
type RuleRepos struct {
	c       *Core
	fetcher *rulerepo.Fetcher

	mu      sync.Mutex
	running map[string]bool
	ctx     context.Context // set by Run; background updates stop with it
}

// NewRuleRepos returns the repository updater.
func NewRuleRepos(c *Core) *RuleRepos {
	return &RuleRepos{
		c:       c,
		fetcher: &rulerepo.Fetcher{UserAgent: "homexdr/" + version.Version},
		running: map[string]bool{},
		ctx:     context.Background(),
	}
}

// RuleRepoView is a rule repository as the console shows it.
type RuleRepoView struct {
	*store.RuleRepo
	RepoRuleStats
	Kind            string     `json:"kind"`                 // git | archive
	BrowseURL       string     `json:"browse_url,omitempty"` // the installed version upstream
	UpdateAvailable bool       `json:"update_available"`
	Syncing         bool       `json:"syncing"`
	NextCheckAt     *time.Time `json:"next_check_at,omitempty"`
}

func (m *RuleRepos) view(r *store.RuleRepo) RuleRepoView {
	v := RuleRepoView{RuleRepo: r, RepoRuleStats: m.c.Rules.RepoStats(r.ID)}
	if src, err := rulerepo.Parse(r.URL); err == nil {
		v.Kind = src.Kind
		v.BrowseURL = src.FileURL(r.Version, "")
	}
	v.UpdateAvailable = r.Version != "" && r.LatestVersion != "" && r.LatestVersion != r.Version
	m.mu.Lock()
	v.Syncing = m.running[r.ID]
	m.mu.Unlock()
	if r.Enabled {
		next := m.nextCheck(r)
		v.NextCheckAt = &next
	}
	return v
}

// List returns every rule repository.
func (m *RuleRepos) List(ctx context.Context) ([]RuleRepoView, error) {
	repos, err := m.c.State.ListRuleRepos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RuleRepoView, len(repos))
	for i, r := range repos {
		out[i] = m.view(r)
	}
	return out, nil
}

// Get returns one rule repository.
func (m *RuleRepos) Get(ctx context.Context, id string) (*RuleRepoView, error) {
	r, err := m.c.State.GetRuleRepo(ctx, id)
	if err != nil {
		return nil, err
	}
	v := m.view(r)
	return &v, nil
}

// normalize validates settings. A URL that points into a repository
// (…/tree/<branch>/<folder>) fills in the branch and folder when they are not set.
func (m *RuleRepos) normalize(ctx context.Context, s store.RuleRepoSettings, selfID string) (store.RuleRepoSettings, error) {
	src, err := rulerepo.Parse(s.URL)
	if err != nil {
		return s, invalid("%v", err)
	}
	s.URL = src.URL
	s.Ref = strings.TrimSpace(s.Ref)
	if src.Kind == rulerepo.KindArchive {
		s.Ref = ""
	} else if s.Ref == "" {
		s.Ref = src.Ref
	}
	if len(s.Ref) > 200 || strings.ContainsAny(s.Ref, " \t\r\n\x00~^:?*[\\") {
		return s, invalid("%q is not a valid branch, tag or commit", s.Ref)
	}
	if s.Name = strings.TrimSpace(s.Name); s.Name == "" {
		s.Name = src.Name()
	}
	if len(s.Name) > 100 {
		return s, invalid("the name is longer than 100 characters")
	}
	if len(s.Paths) == 0 && src.Path != "" {
		s.Paths = []string{src.Path}
	}
	var paths []string
	for _, p := range s.Paths {
		f, err := rulerepo.CleanFolder(p)
		if err != nil {
			return s, invalid("%v", err)
		}
		if f == "" {
			paths = nil // the whole repository
			break
		}
		if !slices.Contains(paths, f) {
			paths = append(paths, f)
		}
	}
	if len(paths) > 100 {
		return s, invalid("choose at most 100 folders")
	}
	s.Paths = paths
	if s.MinLevel = strings.ToLower(strings.TrimSpace(s.MinLevel)); s.MinLevel != "" && levelRank[s.MinLevel] == 0 {
		return s, invalid("unknown level %q", s.MinLevel)
	}
	var statuses []string
	for _, st := range s.Statuses {
		st = strings.ToLower(strings.TrimSpace(st))
		if !slices.Contains(sigmaStatuses, st) {
			return s, invalid("unknown rule status %q (use %s)", st, strings.Join(sigmaStatuses, ", "))
		}
		if !slices.Contains(statuses, st) {
			statuses = append(statuses, st)
		}
	}
	s.Statuses = statuses
	if s.IntervalHours == 0 {
		s.IntervalHours = defaultRepoInterval
	}
	if s.IntervalHours < 1 || s.IntervalHours > maxRepoIntervalHours {
		return s, invalid("check for updates between every hour and every 30 days")
	}
	repos, err := m.c.State.ListRuleRepos(ctx)
	if err != nil {
		return s, err
	}
	for _, r := range repos {
		if r.ID != selfID && strings.EqualFold(r.URL, s.URL) && r.Ref == s.Ref {
			return s, invalid("%s is already added as %q; edit its folders instead", s.URL, r.Name)
		}
	}
	if selfID == "" && len(repos) >= maxRuleRepos {
		return s, invalid("at most %d rule repositories can be added", maxRuleRepos)
	}
	return s, nil
}

// Add adds a repository and starts downloading it.
func (m *RuleRepos) Add(ctx context.Context, s store.RuleRepoSettings, user string) (*RuleRepoView, error) {
	s, err := m.normalize(ctx, s, "")
	if err != nil {
		return nil, err
	}
	r, err := m.c.State.CreateRuleRepo(ctx, s, user)
	if err != nil {
		return nil, err
	}
	m.c.Audit(ctx, user, "rule_repo.add", r.ID, r.Name+" "+r.URL)
	m.Start(r.ID, true, user)
	return m.Get(ctx, r.ID)
}

// Update changes a repository's settings. A new URL or branch downloads it again;
// other changes only reload the rules already downloaded.
func (m *RuleRepos) Update(ctx context.Context, id string, s store.RuleRepoSettings, user string) (*RuleRepoView, error) {
	cur, err := m.c.State.GetRuleRepo(ctx, id)
	if err != nil {
		return nil, err
	}
	if s, err = m.normalize(ctx, s, id); err != nil {
		return nil, err
	}
	moved := !strings.EqualFold(cur.URL, s.URL) || cur.Ref != s.Ref
	if moved {
		// A running update would record the old source's state over the reset below.
		if !m.claim(id) {
			return nil, ErrRepoBusy
		}
	}
	err = m.c.State.UpdateRuleRepoSettings(ctx, id, s)
	if err == nil && moved {
		// Forget the old source's validators and pending version; the files stay
		// installed until the new download replaces them.
		st := cur.RuleRepoState
		st.LatestVersion, st.ETag, st.LastModified, st.CheckedAt = "", "", "", nil
		err = m.c.State.UpdateRuleRepoState(ctx, id, st)
	}
	if moved {
		m.release(id)
	}
	if err != nil {
		return nil, err
	}
	m.c.Audit(ctx, user, "rule_repo.update", id, s.Name)
	if err := m.c.Rules.Reload(ctx); err != nil {
		return nil, err
	}
	if moved && s.Enabled {
		m.Start(id, true, user)
	}
	return m.Get(ctx, id)
}

// Delete removes a repository, its files and its rules.
func (m *RuleRepos) Delete(ctx context.Context, id, user string) error {
	if !m.claim(id) {
		return ErrRepoBusy
	}
	defer m.release(id)
	r, err := m.c.State.GetRuleRepo(ctx, id)
	if err != nil {
		return err
	}
	if err := m.c.State.DeleteRuleRepo(ctx, id); err != nil {
		return err
	}
	m.c.Rules.loadMu.Lock()
	err = os.RemoveAll(m.c.RepoDir(id))
	m.c.Rules.loadMu.Unlock()
	if err != nil {
		m.c.Log.Warn("remove rule repository files", "id", id, "err", err)
	}
	m.c.Audit(ctx, user, "rule_repo.delete", id, r.Name)
	return m.c.Rules.Reload(ctx)
}

// Check looks for a new version without installing it.
func (m *RuleRepos) Check(ctx context.Context, id, user string) (*RuleRepoView, error) {
	if !m.claim(id) {
		return nil, ErrRepoBusy
	}
	err := m.sync(ctx, id, false, user)
	m.release(id)
	if err != nil && !errors.Is(err, errSyncFailed) {
		return nil, err
	}
	return m.Get(ctx, id)
}

// Start installs the newest version (install) or only checks for one, in the background.
// It reports false when the repository is already busy.
func (m *RuleRepos) Start(id string, install bool, user string) bool {
	if !m.claim(id) {
		return false
	}
	m.mu.Lock()
	ctx := m.ctx
	m.mu.Unlock()
	go func() {
		defer m.release(id)
		_ = m.sync(ctx, id, install, user)
	}()
	return true
}

func (m *RuleRepos) claim(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

func (m *RuleRepos) release(id string) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}

// errSyncFailed marks failures that were recorded on the repository (network, archive
// problems) as opposed to database errors.
var errSyncFailed = errors.New("rule repository update failed")

// sync checks a repository for a new version and, with install, downloads and loads
// it. The outcome, including errors, is recorded in the repository's state. Callers
// hold the repository's claim.
func (m *RuleRepos) sync(ctx context.Context, id string, install bool, user string) error {
	r, err := m.c.State.GetRuleRepo(ctx, id)
	if err != nil {
		return err
	}
	st := r.RuleRepoState
	now := time.Now().UTC()
	st.CheckedAt = &now
	fail := func(err error) error {
		st.Error = err.Error()
		m.c.Log.Warn("rule repository update failed", "repo", r.Name, "url", r.URL, "err", err)
		if serr := m.c.State.UpdateRuleRepoState(ctx, id, st); serr != nil {
			return serr
		}
		return fmt.Errorf("%w: %v", errSyncFailed, err)
	}
	src, err := rulerepo.Parse(r.URL)
	if err != nil {
		return fail(err)
	}
	dir := m.c.RepoDir(id)
	have := rulerepo.Remote{Version: r.Version, ETag: r.ETag, LastModified: r.LastModified}
	if _, err := os.Stat(dir); err != nil {
		have = rulerepo.Remote{} // the files are gone (data restored without them): download again
	}

	if !install {
		rem, err := m.fetcher.Latest(ctx, src, r.Ref, have)
		if err != nil {
			return fail(err)
		}
		st.LatestVersion, st.Error = rem.Version, ""
		if rem.Version == r.Version {
			// Keep the archive validators fresh so later checks can skip the download.
			st.ETag, st.LastModified = rem.ETag, rem.LastModified
		}
		return m.c.State.UpdateRuleRepoState(ctx, id, st)
	}

	staging := fmt.Sprintf("%s.new-%d", dir, now.UnixNano())
	defer os.RemoveAll(staging)
	rem, stats, changed, err := m.fetcher.Fetch(ctx, src, r.Ref, have, staging)
	if err != nil {
		return fail(err)
	}
	st.LatestVersion, st.ETag, st.LastModified, st.Error = rem.Version, rem.ETag, rem.LastModified, ""
	if !changed {
		return m.c.State.UpdateRuleRepoState(ctx, id, st)
	}

	before := m.c.Rules.repoRuleIDs(id)
	old := fmt.Sprintf("%s.old-%d", dir, now.UnixNano())
	m.c.Rules.loadMu.Lock()
	err = os.Rename(dir, old)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		err = os.Rename(staging, dir)
	}
	if err == nil {
		prev := r.Version
		st.Version, st.InstalledAt = rem.Version, &now
		st.Files, st.Folders = stats.Files, toStoreFolders(rulerepo.Folders(dir))
		err = m.c.State.UpdateRuleRepoState(ctx, id, st)
		if err != nil {
			st.Version = prev
		}
	}
	m.c.Rules.loadMu.Unlock()
	os.RemoveAll(old)
	if err != nil {
		return fail(err)
	}
	if err := m.c.Rules.Reload(ctx); err != nil {
		return err
	}
	after := m.c.Rules.repoRuleIDs(id)
	st.Added, st.Removed = 0, 0
	for rid := range after {
		if !before[rid] {
			st.Added++
		}
	}
	for rid := range before {
		if !after[rid] {
			st.Removed++
		}
	}
	if err := m.c.State.UpdateRuleRepoState(ctx, id, st); err != nil {
		return err
	}
	details := fmt.Sprintf("%s: installed %s, %d rules (+%d, -%d)", r.Name, shortVersion(rem.Version), len(after), st.Added, st.Removed)
	if stats.Skipped > 0 {
		details += fmt.Sprintf(", %d files over 1 MB skipped", stats.Skipped)
	}
	m.c.Audit(ctx, user, "rule_repo.install", id, details)
	m.c.Log.Info("rule repository installed", "repo", r.Name, "version", shortVersion(rem.Version), "rules", len(after),
		"added", st.Added, "removed", st.Removed)
	return nil
}

func toStoreFolders(in []rulerepo.Folder) []store.Folder {
	out := make([]store.Folder, len(in))
	for i, f := range in {
		out[i] = store.Folder{Path: f.Path, Files: f.Files}
	}
	return out
}

func shortVersion(v string) string {
	v = strings.TrimPrefix(v, "sha256:")
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

// nextCheck is when the schedule next looks at a repository.
func (m *RuleRepos) nextCheck(r *store.RuleRepo) time.Time {
	if r.CheckedAt == nil {
		return time.Now().UTC()
	}
	wait := time.Duration(r.IntervalHours) * time.Hour
	if r.Error != "" && wait > repoRetry {
		wait = repoRetry
	}
	return r.CheckedAt.Add(wait)
}

// Run keeps repositories current until ctx ends: once a minute it checks each enabled
// repository whose interval has passed. Repositories set to update automatically get the
// new version installed; the others only record that one is available.
func (m *RuleRepos) Run(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	m.cleanup()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		m.runDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (m *RuleRepos) runDue(ctx context.Context) {
	repos, err := m.c.State.ListRuleRepos(ctx)
	if err != nil {
		m.c.Log.Warn("list rule repositories", "err", err)
		return
	}
	now := time.Now()
	for _, r := range repos {
		if ctx.Err() != nil {
			return
		}
		if !r.Enabled || now.Before(m.nextCheck(r)) || !m.claim(r.ID) {
			continue
		}
		// Manual repositories are only checked, unless nothing is installed (the first
		// download failed, or the files were lost with a data restore).
		_, statErr := os.Stat(m.c.RepoDir(r.ID))
		_ = m.sync(ctx, r.ID, r.AutoUpdate || r.Version == "" || statErr != nil, "system")
		m.release(r.ID)
	}
}

// cleanup removes folders left by updates that were interrupted, and folders of
// repositories that no longer exist.
func (m *RuleRepos) cleanup() {
	root := filepath.Join(m.c.Cfg.DataDir, "rule-repos")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	repos, err := m.c.State.ListRuleRepos(m.ctx)
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, r := range repos {
		live[r.ID] = true
	}
	for _, e := range entries {
		if !live[e.Name()] {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}
