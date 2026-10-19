package core

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Rule sources.
const (
	SourceBuiltin = "builtin"
	SourceCustom  = "custom"
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
}

type ruleEntry struct {
	rule      *detect.Rule
	source    string
	enabled   bool
	updatedAt time.Time
}

// RuleSet manages built-in and custom rules and keeps the engine in sync.
type RuleSet struct {
	c          *Core
	mu         sync.RWMutex
	entries    map[string]*ruleEntry
	loadErrors []detect.LoadError
}

// NewRuleSet returns an empty rule set.
func NewRuleSet(c *Core) *RuleSet {
	return &RuleSet{c: c, entries: map[string]*ruleEntry{}}
}

// Reload reads built-in rules from disk and custom rules and overrides from the database.
func (rs *RuleSet) Reload(ctx context.Context) error {
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
	entries := map[string]*ruleEntry{}
	for _, r := range builtin {
		entries[r.ID] = &ruleEntry{rule: r, source: SourceBuiltin, enabled: true}
	}
	for _, row := range rows {
		switch row.Source {
		case SourceBuiltin:
			if e, ok := entries[row.ID]; ok {
				e.enabled = row.Enabled
				e.updatedAt = row.UpdatedAt
			}
		case SourceCustom:
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
	}
	rs.mu.Lock()
	rs.entries = entries
	rs.loadErrors = errs
	rs.mu.Unlock()
	rs.sync()
	rs.c.Log.Info("rules loaded", "total", len(entries), "enabled", len(rs.c.Engine.Rules()), "errors", len(errs))
	return nil
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
	case id == "" && exists:
		return nil, invalid("a rule with id %s already exists", r.ID)
	case id != "" && target == nil:
		return nil, store.ErrNotFound
	case id != "" && target.source != SourceCustom:
		return nil, invalid("built-in rules cannot be edited; copy it into a new custom rule")
	case id != "" && r.ID != id:
		return nil, invalid("the rule id cannot change (was %s)", id)
	case exists && existing.source != SourceCustom:
		return nil, invalid("id %s belongs to a built-in rule", r.ID)
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
		return errors.New("built-in rules cannot be deleted; disable them instead")
	}
	if err := rs.c.State.DeleteRuleRow(ctx, id); err != nil {
		return err
	}
	return rs.Reload(ctx)
}
