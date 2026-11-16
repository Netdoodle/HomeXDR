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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Engine evaluates events against the enabled rule set. SetRules swaps the set
// atomically, so evaluation never blocks on rule changes. Correlation and threshold rules
// keep their windows in memory (correlation_state.go); a reload that leaves such a rule
// unchanged keeps its windows.
type Engine struct {
	plan  atomic.Pointer[plan]
	calls atomic.Uint64

	mu     sync.Mutex // serializes SetRuleSet
	states map[string]*corrState
}

// plan is what Evaluate runs.
type plan struct {
	enabled []*Rule
	eval    []evalRule
	states  []*corrState
}

// evalRule is a rule evaluated on every event: whether a match alerts on its own, and
// which correlations it feeds.
type evalRule struct {
	rule  *Rule
	alert bool
	feeds []corrFeed
}

type corrFeed struct {
	st   *corrState
	base int // index in the correlation's rules
}

// corrSweepCalls is how many evaluations pass between checks for expired correlation
// groups, so idle correlation rules release memory too.
const corrSweepCalls = 4096

// NewEngine returns an engine with no rules.
func NewEngine() *Engine {
	e := &Engine{states: map[string]*corrState{}}
	e.plan.Store(&plan{enabled: []*Rule{}})
	return e
}

// SetRules replaces the enabled rules. Correlation rules find their base rules among them.
func (e *Engine) SetRules(rules []*Rule) { e.SetRuleSet(rules, rules) }

// SetRuleSet replaces the enabled rules. all holds every loaded rule, enabled or not:
// correlation rules find their base rules there, so a correlation runs whether or not its
// base rules are enabled. A base rule referenced by any loaded correlation rule only
// feeds it, and raises no alert of its own, unless one of those correlations sets
// generate. Correlation rules whose base rules cannot be found are skipped
// (ResolveCorrelations reports them).
func (e *Engine) SetRuleSet(enabled, all []*Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rv := newResolver(all, enabled)
	referenced := map[*Rule]bool{}
	generates := map[*Rule]bool{}
	for _, r := range rv.rules {
		c := corrOf(r)
		if c == nil {
			continue
		}
		bases, err := rv.bases(r)
		if err != nil {
			continue
		}
		for _, b := range bases {
			referenced[b] = true
			if c.Generate {
				generates[b] = true
			}
		}
	}

	p := &plan{enabled: append([]*Rule{}, enabled...)}
	at := map[*Rule]int{}
	add := func(r *Rule, alert bool) int {
		i, ok := at[r]
		if !ok {
			i = len(p.eval)
			at[r] = i
			p.eval = append(p.eval, evalRule{rule: r})
		}
		p.eval[i].alert = p.eval[i].alert || alert
		return i
	}
	states := map[string]*corrState{}
	state := func(r *Rule, bases []*Rule) *corrState {
		key := corrKey(r, bases)
		st := states[key]
		if st == nil {
			st = e.states[key]
		}
		if st == nil {
			st = newCorrState(newCorrDef(r, bases))
		}
		if states[key] == nil {
			states[key] = st
			p.states = append(p.states, st)
		}
		return st
	}
	for _, r := range p.enabled {
		if r.Correlation == nil {
			add(r, !referenced[r] || generates[r])
			continue
		}
		bases, err := rv.bases(r)
		if err != nil {
			continue
		}
		st := state(r, bases)
		for i, b := range bases {
			j := add(b, false)
			p.eval[j].feeds = append(p.eval[j].feeds, corrFeed{st: st, base: i})
		}
	}
	e.states = states
	e.plan.Store(p)
}

// Rules returns the enabled rules.
func (e *Engine) Rules() []*Rule { return e.plan.Load().enabled }

// Result is what an event set off.
type Result struct {
	// Rules are the rules that matched and raise their own alert.
	Rules []*Rule
	// Correlations are the correlation and threshold rules whose condition the event met.
	Correlations []CorrelationMatch
}

// Evaluate returns the rules that match ev and raise their own alert. It also feeds
// correlation rules, but drops their matches; ingest uses Detect.
func (e *Engine) Evaluate(ev *event.Event) []*Rule { return e.Detect(ev).Rules }

// Detect evaluates ev: the rules it matches and the correlations it completes. Correlation
// windows use the event's timestamp (now when it has none).
func (e *Engine) Detect(ev *event.Event) Result {
	p := e.plan.Load()
	var res Result
	if len(p.eval) == 0 {
		return res
	}
	d := NewDoc(ev)
	var fed []*corrState
	var ts time.Time
	for i := range p.eval {
		er := &p.eval[i]
		if !er.rule.Match(d) {
			continue
		}
		if er.alert {
			res.Rules = append(res.Rules, er.rule)
		}
		for _, f := range er.feeds {
			// An event that matches several base rules of a count correlation counts once.
			if f.st.def.c.Type != CorrTemporal {
				if containsState(fed, f.st) {
					continue
				}
				fed = append(fed, f.st)
			}
			if ts.IsZero() {
				ts = eventTime(ev)
			}
			if m := f.st.feed(f.base, d, ts); m != nil {
				res.Correlations = append(res.Correlations, *m)
			}
		}
	}
	if len(p.states) > 0 && e.calls.Add(1)%corrSweepCalls == 0 {
		for _, st := range p.states {
			st.sweep(eventTime(ev))
		}
	}
	return res
}

func eventTime(ev *event.Event) time.Time {
	if ev.Timestamp.IsZero() {
		return time.Now().UTC()
	}
	return ev.Timestamp
}

func containsState(list []*corrState, s *corrState) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
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
		docs, err := ParseDocuments(b)
		if err != nil {
			errs = append(errs, LoadError{Path: rel, Err: err.Error()})
		}
		// Each rule in a file stands alone: one the engine cannot run is reported, and the
		// others still load.
		for _, d := range docs {
			switch {
			case d.Err != nil:
				errs = append(errs, LoadError{Path: rel, Err: docError(d, len(docs))})
			case seen[d.Rule.ID]:
				errs = append(errs, LoadError{Path: rel, Err: fmt.Sprintf("duplicate rule id %s", d.Rule.ID)})
			default:
				seen[d.Rule.ID] = true
				rules = append(rules, FileRule{Rule: d.Rule, Path: rel})
			}
		}
	}
	return rules, errs
}

// docError describes a rule that failed, naming it when its file holds several.
func docError(d Document, inFile int) string {
	if inFile > 1 && d.Title != "" {
		return d.Title + ": " + d.Err.Error()
	}
	return d.Err.Error()
}

// FileDocument is a rule document and the file it came from.
type FileDocument struct {
	Path string // slash-separated, relative to the loaded folder
	Document
}

// LoadDocuments reads every rule document under dir with its metadata and result,
// including those that cannot run, for listing what a folder holds. Files the YAML decoder
// cannot read are returned as documents with only Err set.
func LoadDocuments(dir string) []FileDocument {
	var out []FileDocument
	for _, p := range ruleFiles(dir) {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err == nil {
			var docs []Document
			docs, err = ParseDocuments(b)
			for _, d := range docs {
				out = append(out, FileDocument{Path: rel, Document: d})
			}
		}
		if err != nil {
			out = append(out, FileDocument{Path: rel, Document: Document{Level: "medium", Err: err}})
		}
	}
	return out
}
