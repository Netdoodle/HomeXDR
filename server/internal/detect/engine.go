package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Engine evaluates events against the enabled rule set. SetRules swaps the set
// atomically, so evaluation never blocks on rule changes.
type Engine struct {
	rules atomic.Pointer[[]*Rule]
}

// NewEngine returns an engine with no rules.
func NewEngine() *Engine {
	e := &Engine{}
	empty := []*Rule{}
	e.rules.Store(&empty)
	return e
}

// SetRules replaces the enabled rules.
func (e *Engine) SetRules(rules []*Rule) {
	cp := append([]*Rule(nil), rules...)
	e.rules.Store(&cp)
}

// Rules returns the enabled rules.
func (e *Engine) Rules() []*Rule { return *e.rules.Load() }

// Evaluate returns the rules that match ev.
func (e *Engine) Evaluate(ev *event.Event) []*Rule {
	rules := *e.rules.Load()
	if len(rules) == 0 {
		return nil
	}
	d := NewDoc(ev)
	var hits []*Rule
	for _, r := range rules {
		if r.Match(d) {
			hits = append(hits, r)
		}
	}
	return hits
}

// LoadError records a rule file that failed to load.
type LoadError struct {
	Path string `json:"path"`
	Err  string `json:"error"`
}

// ruleFiles returns the .yml/.yaml files under dir in path order.
func ruleFiles(dir string) []string {
	var paths []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if !d.IsDir() && (ext == ".yml" || ext == ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	return paths
}

// DirFingerprint summarizes the rule files under dir (names, sizes, modification times)
// so callers can cheaply tell whether anything changed since the last load.
func DirFingerprint(dir string) string {
	h := sha256.New()
	for _, p := range ruleFiles(dir) {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(h, "%s|%d|%d\n", p, st.Size(), st.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LoadDir parses every .yml/.yaml file under dir. Files that fail are reported, not
// fatal. Rules with duplicate IDs keep the first one found (in path order).
func LoadDir(dir string) ([]*Rule, []LoadError) {
	files, errs := LoadTree(dir, nil)
	rules := make([]*Rule, len(files))
	for i, f := range files {
		rules[i] = f.Rule
	}
	for i := range errs {
		errs[i].Path = filepath.Join(dir, filepath.FromSlash(errs[i].Path))
	}
	return rules, errs
}

// FileRule is a rule and the file it came from.
type FileRule struct {
	Rule *Rule
	Path string // slash-separated, relative to the loaded folder
}

// LoadTree is LoadDir for the files whose path relative to dir (slash-separated) passes
// include, or all files when include is nil. Paths in the result and in errors are
// relative to dir.
func LoadTree(dir string, include func(rel string) bool) ([]FileRule, []LoadError) {
	var rules []FileRule
	var errs []LoadError
	seen := map[string]bool{}
	for _, p := range ruleFiles(dir) {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if include != nil && !include(rel) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, LoadError{Path: rel, Err: err.Error()})
			continue
		}
		rs, err := ParseRules(b)
		if err != nil {
			errs = append(errs, LoadError{Path: rel, Err: err.Error()})
			continue
		}
		for _, r := range rs {
			if seen[r.ID] {
				errs = append(errs, LoadError{Path: rel, Err: fmt.Sprintf("duplicate rule id %s", r.ID)})
				continue
			}
			seen[r.ID] = true
			rules = append(rules, FileRule{Rule: r, Path: rel})
		}
	}
	return rules, errs
}
