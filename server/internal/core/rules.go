package core

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/rulerepo"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Rule sources. When two sources hold a rule with the same ID, the rules folder wins over
// custom rules, custom rules over rule repositories, and an earlier repository over a
// later one.
const (
	SourceBuiltin = "builtin"
	SourceCustom  = "custom"
	SourceRepo    = "repo"
)

// RuleInfo is a rule in API shape.
type RuleInfo struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	Status      string           `json:"status,omitempty"`
	Level       string           `json:"level"`
	Enabled     bool             `json:"enabled"`
	Source      string           `json:"source"`
	Tags        []string         `json:"tags"`
	Author      string           `json:"author,omitempty"`
	References  []string         `json:"references,omitempty"`
	LogSource   detect.LogSource `json:"logsource"`
	Mitre       []detect.Mitre   `json:"mitre"`
	Hits24h     int              `json:"hits_24h"`
	UpdatedAt   time.Time        `json:"updated_at"`
	YAML        string           `json:"yaml,omitempty"`
	// Repo is set for rules from a rule repository.
	Repo *RuleRepoRef `json:"repo,omitempty"`
}

// RuleRepoRef says which rule repository a rule came from.
type RuleRepoRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`          // file in the repository
	URL  string `json:"url,omitempty"` // the file upstream, for git repositories
}

type ruleEntry struct {
	rule      *detect.Rule
	source    string
	enabled   bool
	updatedAt time.Time
	repo      *RuleRepoRef
}

// RepoRuleStats counts what a rule repository contributed at the last load.
type RepoRuleStats struct {
	Rules        int `json:"rules"`         // loaded
	RulesEnabled int `json:"rules_enabled"` // loaded and enabled
	Filtered     int `json:"filtered"`      // skipped by the level or status filter
	Duplicates   int `json:"duplicates"`    // skipped because another source has the ID
	Errors       int `json:"load_errors"`   // files that failed to load
}

// repoLoad caches a repository's parsed rules; parsing SigmaHQ takes about a second and
// Reload runs on every rule change.
type repoLoad struct {
	key   string // version and folders the rules were read with
	rules []detect.FileRule
	errs  []detect.LoadError
}

// RuleSet manages built-in, custom and repository rules and keeps the engine in sync.
type RuleSet struct {
	c *Core
	// loadMu serializes Reload, so an older load never replaces a newer one, and lets the
	// repository updater swap folders without a load reading them halfway.
	loadMu     sync.Mutex
	mu         sync.RWMutex
	entries    map[string]*ruleEntry
	loadErrors []detect.LoadError
	repoStats  map[string]RepoRuleStats
	repoSkips  map[string][]RepoSkip   // rules a repository's folders hold that are not loaded
	repoCache  map[string]*repoLoad    // by repository ID; guarded by loadMu
	repoDocs   map[string]*repoCatalog // by repository ID; guarded by loadMu
	dirPrint   string                  // detect.DirFingerprint of the rules folder at the last load
}

// RepoSkip is a rule in a repository's chosen folders that is not loaded, and why.
type RepoSkip struct {
	Path  string `json:"path"`
	Title string `json:"title,omitempty"`
	Error string `json:"error"`
}

// NewRuleSet returns an empty rule set.
func NewRuleSet(c *Core) *RuleSet {
	return &RuleSet{c: c, entries: map[string]*ruleEntry{}, repoStats: map[string]RepoRuleStats{},
		repoSkips: map[string][]RepoSkip{}, repoCache: map[string]*repoLoad{}, repoDocs: map[string]*repoCatalog{}}
}

// ReloadIfChanged reloads when files in the rules folder were added, removed or modified
// since the last load. It reports whether a reload happened.
func (rs *RuleSet) ReloadIfChanged(ctx context.Context) (bool, error) {
	fp := detect.DirFingerprint(rs.c.Cfg.RulesDir)
	rs.mu.RLock()
	same := fp == rs.dirPrint
	rs.mu.RUnlock()
	if same {
		return false, nil
	}
	rs.c.Log.Info("rules folder changed; reloading", "dir", rs.c.Cfg.RulesDir)
	return true, rs.Reload(ctx)
}

// Stats returns the number of loaded and enabled rules.
func (rs *RuleSet) Stats() (total, enabled int) {
	rs.mu.RLock()
	total = len(rs.entries)
	rs.mu.RUnlock()
	return total, len(rs.c.Engine.Rules())
}

// Reload reads built-in rules from disk, custom rules and overrides from the database,
// and rules from installed rule repositories.
func (rs *RuleSet) Reload(ctx context.Context) error {
	rs.loadMu.Lock()
	defer rs.loadMu.Unlock()
	fp := detect.DirFingerprint(rs.c.Cfg.RulesDir)
	builtin, errs := detect.LoadDir(rs.c.Cfg.RulesDir)
	// Large community rule sets contain rules this engine cannot run (aggregations,
	// unsupported modifiers); log a few and keep the rest at debug level.
	for i, e := range errs {
		if i < 10 {
			rs.c.Log.Warn("rule failed to load", "path", e.Path, "err", e.Err)
		} else {
			rs.c.Log.Debug("rule failed to load", "path", e.Path, "err", e.Err)
		}
	}
	if len(errs) > 10 {
		rs.c.Log.Warn("more rules failed to load; see the Rules page or set HOMEXDR_LOG_LEVEL=debug", "count", len(errs)-10)
	}
	rows, err := rs.c.State.ListRuleRows(ctx)
	if err != nil {
		return err
	}
	repos, err := rs.c.State.ListRuleRepos(ctx)
	if err != nil {
		return err
	}
	entries := map[string]*ruleEntry{}
	for _, r := range builtin {
		entries[r.ID] = &ruleEntry{rule: r, source: SourceBuiltin, enabled: true}
	}
	for _, row := range rows {
		if row.Source != SourceCustom {
			continue
		}
		r, err := detect.ParseRule([]byte(row.YAML))
		if err != nil {
			errs = append(errs, detect.LoadError{Path: "custom:" + row.ID, Err: err.Error()})
			rs.c.Log.Warn("custom rule failed to load", "id", row.ID, "err", err)
			continue
		}
		if _, clash := entries[r.ID]; clash {
			continue
		}
		entries[r.ID] = &ruleEntry{rule: r, source: SourceCustom, enabled: row.Enabled, updatedAt: row.UpdatedAt}
	}
	stats := map[string]RepoRuleStats{}
	skips := map[string][]RepoSkip{}
	live := map[string]bool{}
	for _, repo := range repos {
		live[repo.ID] = true
		var st RepoRuleStats
		if repo.Enabled && repo.Version != "" {
			ld := rs.loadRepo(repo)
			st.Errors = len(ld.errs)
			for _, e := range ld.errs {
				errs = append(errs, detect.LoadError{Path: repo.Name + ": " + e.Path, Err: e.Err})
				skips[repo.ID] = append(skips[repo.ID], RepoSkip{Path: e.Path, Error: e.Err})
			}
			src, _ := rulerepo.Parse(repo.URL)
			var installed time.Time
			if repo.InstalledAt != nil {
				installed = *repo.InstalledAt
			}
			for _, fr := range ld.rules {
				r := fr.Rule
				if !levelAtLeast(r.Level, repo.MinLevel) || !statusAllowed(r.Status, repo.Statuses) {
					st.Filtered++
					continue
				}
				if other, clash := entries[r.ID]; clash {
					st.Duplicates++
					skips[repo.ID] = append(skips[repo.ID], RepoSkip{Path: fr.Path, Title: r.Title, Error: "same id as " + other.describe()})
					continue
				}
				entries[r.ID] = &ruleEntry{rule: r, source: SourceRepo, enabled: repo.EnableRules, updatedAt: installed,
					repo: &RuleRepoRef{ID: repo.ID, Name: repo.Name, Path: fr.Path, URL: src.FileURL(repo.Version, fr.Path)}}
				st.Rules++
			}
		}
		stats[repo.ID] = st
	}
	for id := range rs.repoCache {
		if !live[id] {
			delete(rs.repoCache, id)
		}
	}
	for id := range rs.repoDocs {
		if !live[id] {
			delete(rs.repoDocs, id)
		}
	}
	// Enabled/disabled choices for rules from the rules folder and from repositories are
	// stored by rule ID, so they survive reloads, updates and rules moving between sources.
	for _, row := range rows {
		if row.Source == SourceCustom {
			continue
		}
		if e, ok := entries[row.ID]; ok && e.source != SourceCustom {
			e.enabled = row.Enabled
			e.updatedAt = row.UpdatedAt
		}
	}
	for _, e := range entries {
		if e.repo != nil && e.enabled {
			st := stats[e.repo.ID]
			st.RulesEnabled++
			stats[e.repo.ID] = st
		}
	}
	rs.mu.Lock()
	rs.entries = entries
	rs.loadErrors = errs
	rs.repoStats = stats
	rs.repoSkips = skips
	rs.dirPrint = fp
	rs.mu.Unlock()
	rs.sync()
	rs.c.Log.Info("rules loaded", "total", len(entries), "enabled", len(rs.c.Engine.Rules()), "errors", len(errs))
	return nil
}

// loadRepo returns a repository's parsed rules, from the cache while the installed
// version and folders are unchanged. Callers hold loadMu.
func (rs *RuleSet) loadRepo(repo *store.RuleRepo) *repoLoad {
	key := repo.Version + "\x00" + strings.Join(repo.Paths, "\x00")
	if ld := rs.repoCache[repo.ID]; ld != nil && ld.key == key {
		return ld
	}
	paths := repo.Paths
	rules, errs := detect.LoadTree(rs.c.RepoDir(repo.ID), func(rel string) bool { return rulerepo.InFolders(rel, paths) })
	ld := &repoLoad{key: key, rules: rules, errs: errs}
	rs.repoCache[repo.ID] = ld
	return ld
}

var levelRank = map[string]int{"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func levelAtLeast(level, min string) bool {
	return min == "" || levelRank[level] >= levelRank[min]
}

// statusAllowed applies a repository's status filter. With no filter, deprecated and
// unsupported rules are left out. Rules without a status always pass.
func statusAllowed(status string, allowed []string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return true
	}
	if len(allowed) == 0 {
		return status != "deprecated" && status != "unsupported"
	}
	return slices.Contains(allowed, status)
}

// RepoStats returns what each rule repository contributed at the last load.
func (rs *RuleSet) RepoStats(id string) RepoRuleStats {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.repoStats[id]
}

// describe names where a rule comes from, for duplicate-id messages.
func (e *ruleEntry) describe() string {
	switch {
	case e.repo != nil:
		return "a rule from " + e.repo.Name + " (" + e.repo.Path + ")"
	case e.source == SourceCustom:
		return "a custom rule"
	}
	return "a rule in the rules folder"
}

// repoCatalog is every rule document in a repository's installed version, for choosing
// folders: parsed once per version.
type repoCatalog struct {
	version string
	files   []RepoFile
}

// RepoFile describes one rule document in a downloaded repository.
type RepoFile struct {
	Path    string `json:"path"`
	Status  string `json:"status,omitempty"`
	Level   string `json:"level"`
	Product string `json:"product,omitempty"`
	Error   string `json:"error,omitempty"` // why the engine cannot run it
}

// RepoFiles lists every rule document in a repository's installed version, whichever
// folders are chosen, and the rules in its chosen folders that are not loaded.
func (rs *RuleSet) RepoFiles(repo *store.RuleRepo) ([]RepoFile, []RepoSkip) {
	files := []RepoFile{}
	if repo.Version != "" {
		rs.loadMu.Lock()
		cat := rs.repoDocs[repo.ID]
		if cat == nil || cat.version != repo.Version {
			cat = &repoCatalog{version: repo.Version, files: []RepoFile{}}
			for _, d := range detect.LoadDocuments(rs.c.RepoDir(repo.ID)) {
				f := RepoFile{Path: d.Path, Status: d.Status, Level: d.Level, Product: strings.ToLower(d.LogSource.Product)}
				if d.Err != nil {
					f.Error = d.Err.Error()
				}
				cat.files = append(cat.files, f)
			}
			rs.repoDocs[repo.ID] = cat
		}
		rs.loadMu.Unlock()
		files = cat.files
	}
	rs.mu.RLock()
	skipped := append([]RepoSkip{}, rs.repoSkips[repo.ID]...)
	rs.mu.RUnlock()
	return files, skipped
}

// SetRepoEnabled enables or disables every loaded rule of a repository, returning how
// many changed. The choice is stored per rule, like enabling one by hand.
func (rs *RuleSet) SetRepoEnabled(ctx context.Context, repoID string, enabled bool) (int, error) {
	rs.mu.RLock()
	var rows []store.RuleRow
	for id, e := range rs.entries {
		if e.repo != nil && e.repo.ID == repoID && e.enabled != enabled {
			rows = append(rows, store.RuleRow{ID: id, Source: SourceRepo, Enabled: enabled})
		}
	}
	rs.mu.RUnlock()
	if len(rows) == 0 {
		return 0, nil
	}
	if err := rs.c.State.PutRuleRows(ctx, rows); err != nil {
		return 0, err
	}
	return len(rows), rs.Reload(ctx)
}

// repoRuleIDs returns the IDs of the loaded rules from one repository.
func (rs *RuleSet) repoRuleIDs(repoID string) map[string]bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := map[string]bool{}
	for id, e := range rs.entries {
		if e.repo != nil && e.repo.ID == repoID {
			out[id] = true
		}
	}
	return out
}

func (rs *RuleSet) sync() {
	rs.mu.RLock()
	var enabled []*detect.Rule
	for _, e := range rs.entries {
		if e.enabled {
			enabled = append(enabled, e.rule)
		}
	}
	rs.mu.RUnlock()
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })
	rs.c.Engine.SetRules(enabled)
}

// LoadErrors returns rules that failed to load.
func (rs *RuleSet) LoadErrors() []detect.LoadError {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return append([]detect.LoadError(nil), rs.loadErrors...)
}

func (rs *RuleSet) info(e *ruleEntry, hits map[string]int, withYAML bool) RuleInfo {
	r := e.rule
	ri := RuleInfo{
		ID: r.ID, Title: r.Title, Description: r.Description, Status: r.Status, Level: r.Level,
		Enabled: e.enabled, Source: e.source, Tags: r.Tags, Author: r.Author, References: r.References,
		LogSource: r.LogSource, Mitre: detect.MitreFromTags(r.Tags), Hits24h: hits[r.ID], UpdatedAt: e.updatedAt,
		Repo: e.repo,
	}
	if ri.Tags == nil {
		ri.Tags = []string{}
	}
	if withYAML {
		ri.YAML = r.YAML
	}
	return ri
}

// RuleFilter selects rules.
type RuleFilter struct {
	Q       string
	Enabled *bool
	Level   string
	Source  string
	Repo    string // rule repository ID
}

// List returns rules sorted by title.
func (rs *RuleSet) List(ctx context.Context, f RuleFilter) ([]RuleInfo, error) {
	hits, err := rs.c.State.RuleHits(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	q := strings.ToLower(f.Q)
	out := []RuleInfo{}
	for _, e := range rs.entries {
		if f.Enabled != nil && e.enabled != *f.Enabled {
			continue
		}
		if f.Level != "" && e.rule.Level != f.Level {
			continue
		}
		if f.Source != "" && e.source != f.Source {
			continue
		}
		if f.Repo != "" && (e.repo == nil || e.repo.ID != f.Repo) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.rule.Title+" "+e.rule.Description+" "+strings.Join(e.rule.Tags, " ")), q) {
			continue
		}
		out = append(out, rs.info(e, hits, false))
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title) })
	return out, nil
}

// Get returns one rule with YAML.
func (rs *RuleSet) Get(ctx context.Context, id string) (*RuleInfo, error) {
	hits, err := rs.c.State.RuleHits(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	e, ok := rs.entries[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	ri := rs.info(e, hits, true)
	return &ri, nil
}

// Validate parses rule YAML without saving it.
func (rs *RuleSet) Validate(yamlSrc string) (*detect.Rule, error) {
	if len(yamlSrc) > 256<<10 {
		return nil, invalid("rule is larger than 256 KiB")
	}
	r, err := detect.ParseRule([]byte(yamlSrc))
	if err != nil {
		return nil, invalid("%v", err)
	}
	return r, nil
}

// SaveCustom creates or replaces a custom rule. If id is set, the YAML must keep that id.
func (rs *RuleSet) SaveCustom(ctx context.Context, id, yamlSrc string) (*RuleInfo, error) {
	r, err := rs.Validate(yamlSrc)
	if err != nil {
		return nil, err
	}
	rs.mu.RLock()
	existing, exists := rs.entries[r.ID]
	var target *ruleEntry
	if id != "" {
		target = rs.entries[id]
	}
	rs.mu.RUnlock()
	switch {
	case id == "" && exists && existing.repo != nil:
		return nil, invalid("id %s belongs to a rule from %s; give the copy a new id", r.ID, existing.repo.Name)
	case id == "" && exists:
		return nil, invalid("a rule with id %s already exists", r.ID)
	case id != "" && target == nil:
		return nil, store.ErrNotFound
	case id != "" && target.source != SourceCustom:
		return nil, invalid("%s rules cannot be edited; copy it into a new custom rule", sourceLabel(target))
	case id != "" && r.ID != id:
		return nil, invalid("the rule id cannot change (was %s)", id)
	case exists && existing.source != SourceCustom:
		return nil, invalid("id %s belongs to a %s rule", r.ID, sourceLabel(existing))
	}
	enabled := true
	if target != nil {
		enabled = target.enabled
	}
	if err := rs.c.State.PutRuleRow(ctx, store.RuleRow{ID: r.ID, Source: SourceCustom, YAML: yamlSrc, Enabled: enabled}); err != nil {
		return nil, err
	}
	if err := rs.Reload(ctx); err != nil {
		return nil, err
	}
	return rs.Get(ctx, r.ID)
}

// SetEnabled enables or disables any rule.
func (rs *RuleSet) SetEnabled(ctx context.Context, id string, enabled bool) (*RuleInfo, error) {
	rs.mu.RLock()
	e, ok := rs.entries[id]
	rs.mu.RUnlock()
	if !ok {
		return nil, store.ErrNotFound
	}
	row := store.RuleRow{ID: id, Source: e.source, Enabled: enabled}
	if e.source == SourceCustom {
		row.YAML = e.rule.YAML
	}
	if err := rs.c.State.PutRuleRow(ctx, row); err != nil {
		return nil, err
	}
	if err := rs.Reload(ctx); err != nil {
		return nil, err
	}
	return rs.Get(ctx, id)
}

// DeleteCustom removes a custom rule.
func (rs *RuleSet) DeleteCustom(ctx context.Context, id string) error {
	rs.mu.RLock()
	e, ok := rs.entries[id]
	rs.mu.RUnlock()
	if !ok {
		return store.ErrNotFound
	}
	if e.source != SourceCustom {
		return fmt.Errorf("%s rules cannot be deleted; disable them instead", sourceLabel(e))
	}
	if err := rs.c.State.DeleteRuleRow(ctx, id); err != nil {
		return err
	}
	return rs.Reload(ctx)
}

func sourceLabel(e *ruleEntry) string {
	if e.repo != nil {
		return "repository"
	}
	return "built-in"
}
