package core

// Self-check: can the loaded rules actually fire? It writes nothing to the event store and
// creates no real alerts. See docs/health.md.
//
//  1. Detection rate. For each enabled rule, build an event from the rule's own selection and
//     evaluate it through the engine. A rule that misses cannot fire on anything.
//  2. Field coverage. Sample recent real events and work out which rules could fire on the
//     data this install has. Rules for Windows on a Linux-and-firewall install show up here.
//  3. Pipeline. Push a hit through a real ingest into a temporary store, and check that it
//     makes an alert and that a repeat folds into it.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	selfCheckKey       = "selfcheck_last"
	selfCheckMaxFails  = 200
	coverageDays       = 7
	coverageSample     = 200 // events read per source
	coverageMaxSources = 200
	coverageTimeout    = 2 * time.Minute
	rateDropRegression = 0.05 // percentage points; below this is rounding
)

// selfCheckRule runs the pipeline check when no rule is loaded. It matches only a marker field.
const selfCheckRule = `title: HomeXDR self-check
id: 6f0c4e0a-6c1b-4a51-9c44-3a2f7f1d0b11
logsource:
  product: homexdr-selfcheck
detection:
  selection:
    selfcheck_marker: homexdr
  condition: selection
level: low
`

// SelfCheckFailure is a rule that did not fire on an event built from its own selection.
type SelfCheckFailure struct {
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// SelfCheckPipeline is the end-to-end check's result.
type SelfCheckPipeline struct {
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// FieldCount is a field and how many rules need it.
type FieldCount struct {
	Field string `json:"field"`
	Rules int    `json:"rules"`
}

// CoverageGroup is one logsource's rules.
type CoverageGroup struct {
	Logsource string `json:"logsource"`
	Rules     int    `json:"rules"`
	CanFire   int    `json:"can_fire"`
	// NoEvents rules have no event of this kind in the sample; MissingField rules have events
	// of the right kind, without a field they need.
	NoEvents     int          `json:"no_events"`
	MissingField int          `json:"missing_field"`
	Missing      []FieldCount `json:"missing,omitempty"`
}

// SelfCheckCoverage is how much of the rule set can fire on this install's data.
type SelfCheckCoverage struct {
	Days       int             `json:"days"`
	Events     int             `json:"events"`  // sampled
	Sources    int             `json:"sources"` // sampled
	Rules      int             `json:"rules"`
	CanFire    int             `json:"can_fire"`
	CannotFire int             `json:"cannot_fire"`
	Groups     []CoverageGroup `json:"groups"`
	// Missing are the fields most often keeping rules from firing, across all logsources.
	Missing []FieldCount `json:"missing"`
	Note    string       `json:"note,omitempty"`
}

// SelfCheckSummary is the part of a run kept for comparing with the next one.
type SelfCheckSummary struct {
	At         time.Time `json:"at"`
	Rules      int       `json:"rules"`
	Fired      int       `json:"fired"`
	Rate       float64   `json:"rate"`
	CannotFire int       `json:"cannot_fire"`
	Pipeline   bool      `json:"pipeline"`
}

// SelfCheckResult is one run.
type SelfCheckResult struct {
	At     time.Time `json:"at"`
	TookMs int64     `json:"took_ms"`
	Rules  int       `json:"rules"`
	Fired  int       `json:"fired"`
	// Rate is the detection rate, 0 to 100.
	Rate     float64            `json:"rate"`
	Failed   int                `json:"failed"`
	Failures []SelfCheckFailure `json:"failures"`
	Pipeline SelfCheckPipeline  `json:"pipeline"`
	Coverage *SelfCheckCoverage `json:"coverage,omitempty"`
	Previous *SelfCheckSummary  `json:"previous,omitempty"`
	// Regression says this run is worse than the one before, and why.
	Regression bool   `json:"regression"`
	Reason     string `json:"reason,omitempty"`
}

func (r *SelfCheckResult) summary() *SelfCheckSummary {
	s := &SelfCheckSummary{At: r.At, Rules: r.Rules, Fired: r.Fired, Rate: r.Rate, Pipeline: r.Pipeline.Passed}
	if r.Coverage != nil {
		s.CannotFire = r.Coverage.CannotFire
	}
	return s
}

// LastSelfCheck returns the last saved run, or nil.
func (c *Core) LastSelfCheck(ctx context.Context) *SelfCheckResult {
	var r SelfCheckResult
	if err := c.State.GetKV(ctx, selfCheckKey, &r); err != nil || r.At.IsZero() {
		return nil
	}
	return &r
}

// RunSelfCheck runs the self-check and saves the result in the settings database.
func (c *Core) RunSelfCheck(ctx context.Context) *SelfCheckResult {
	start := time.Now()
	rules := c.Engine.Rules()
	res := &SelfCheckResult{At: start.UTC(), Rules: len(rules), Failures: []SelfCheckFailure{}, Rate: 100}
	var pipeRule *detect.Rule
	var pipeEvent *event.Event
	for _, r := range rules {
		ev, err := detect.Synthesize(r)
		if err == nil {
			// Evaluate through an engine, the way ingest does.
			eng := detect.NewEngine()
			eng.SetRules([]*detect.Rule{r})
			if len(eng.Evaluate(ev)) == 0 {
				err = fmt.Errorf("the engine did not fire on the event built from it")
			}
		}
		if err != nil {
			res.Failed++
			if len(res.Failures) < selfCheckMaxFails {
				res.Failures = append(res.Failures, SelfCheckFailure{RuleID: r.ID, Title: r.Title, Reason: err.Error()})
			}
			continue
		}
		res.Fired++
		if pipeRule == nil {
			pipeRule, pipeEvent = r, ev
		}
	}
	if res.Rules > 0 {
		res.Rate = 100 * float64(res.Fired) / float64(res.Rules)
	}
	res.Pipeline = c.selfCheckPipeline(ctx, pipeRule, pipeEvent)
	res.Coverage = c.selfCheckCoverage(ctx, rules)

	if prev := c.LastSelfCheck(ctx); prev != nil {
		res.Previous = prev.summary()
		switch {
		case prev.Pipeline.Passed && !res.Pipeline.Passed:
			res.Regression, res.Reason = true, "The pipeline check passed last time and fails now."
		case prev.Rate-res.Rate > rateDropRegression:
			res.Regression, res.Reason = true, fmt.Sprintf("The detection rate fell from %.1f%% to %.1f%%.", prev.Rate, res.Rate)
		}
	}
	if !res.Pipeline.Passed && !res.Regression {
		res.Reason = "The pipeline check fails."
	}
	res.TookMs = time.Since(start).Milliseconds()
	if err := c.State.SetKV(ctx, selfCheckKey, res); err != nil {
		c.Log.Warn("self-check: save result", "err", err)
	}
	return res
}

// Bad reports whether a command-line run should exit non-zero.
func (r *SelfCheckResult) Bad() bool { return r.Regression || !r.Pipeline.Passed }

// selfCheckPipeline pushes a hit through a real Core on a throwaway store: nothing reaches
// the real event store, alerts, notifications or the AI analyst, since all of their settings
// and data live in the stores being replaced.
func (c *Core) selfCheckPipeline(ctx context.Context, rule *detect.Rule, ev *event.Event) SelfCheckPipeline {
	fail := func(format string, a ...any) SelfCheckPipeline {
		return SelfCheckPipeline{Message: fmt.Sprintf(format, a...)}
	}
	if rule == nil {
		r, err := detect.ParseRule([]byte(selfCheckRule))
		if err != nil {
			return fail("The built-in test rule did not compile: %v", err)
		}
		if ev, err = detect.Synthesize(r); err != nil {
			return fail("No event could be built for the built-in test rule: %v", err)
		}
		rule = r
	}
	base := c.Cfg.DataDir
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		base = ""
	}
	dir, err := os.MkdirTemp(base, "selfcheck-*")
	if err != nil {
		return fail("Could not make a temporary folder: %v", err)
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		return fail("Could not open a temporary settings database: %v", err)
	}
	defer st.Close()
	evs, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		return fail("Could not open a temporary event store: %v", err)
	}
	defer evs.Close()

	cfg := c.Cfg
	cfg.DataDir, cfg.EventStore, cfg.SyslogAddr = dir, "sqlite", ""
	cfg.RulesDir, cfg.DownloadsDir, cfg.SignaturesDir, cfg.ReleasesDir = filepath.Join(dir, "rules"), filepath.Join(dir, "dl"), filepath.Join(dir, "sig"), ""
	scratch, err := New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, evs, nil)
	if err != nil {
		return fail("Could not start a temporary pipeline: %v", err)
	}
	scratch.Engine.SetRules([]*detect.Rule{rule})

	info := api.HostInfo{Hostname: "selfcheck"}
	if ev.Host.OS != nil {
		info.OS = *ev.Host.OS
	}
	host, err := st.CreateEndpoint(ctx, "selfcheck", info, nil, "selfcheck")
	if err != nil {
		return fail("Could not register a temporary host: %v", err)
	}
	send := func() error {
		cp := *ev
		cp.ID = event.NewID()
		cp.Timestamp = time.Now().UTC()
		return scratch.Ingest(ctx, host, []*event.Event{&cp})
	}
	if err := send(); err != nil {
		return fail("The event could not be stored: %v", err)
	}
	alerts, _, err := st.ListAlerts(ctx, store.AlertFilter{Limit: 10})
	if err != nil {
		return fail("Could not read alerts back: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Rule.ID != rule.ID {
		return fail("A hit on %q should make one alert, and made %d.", rule.Title, len(alerts))
	}
	if err := send(); err != nil {
		return fail("The repeat event could not be stored: %v", err)
	}
	alerts, _, err = st.ListAlerts(ctx, store.AlertFilter{Limit: 10})
	if err != nil {
		return fail("Could not read alerts back: %v", err)
	}
	if len(alerts) != 1 {
		return fail("A repeat of the same hit should fold into one alert, and there are %d.", len(alerts))
	}
	if alerts[0].Count != 2 {
		return fail("A repeat should raise the alert's count to 2, and it is %d.", alerts[0].Count)
	}
	return SelfCheckPipeline{Passed: true, Message: "A hit on a temporary store made an alert, and a repeat folded into it."}
}

// selfCheckCoverage samples each source's newest events from the last week. Reading a sample
// instead of every event keeps this cheap on a large store, so a rare field can be missed.
func (c *Core) selfCheckCoverage(ctx context.Context, rules []*detect.Rule) *SelfCheckCoverage {
	cctx, cancel := context.WithTimeout(ctx, coverageTimeout)
	defer cancel()
	now := time.Now().UTC()
	cov := &SelfCheckCoverage{Days: coverageDays, Groups: []CoverageGroup{}, Missing: []FieldCount{}, Rules: len(rules)}
	buckets, err := events.SourceActivity(cctx, c.Events, now.AddDate(0, 0, -coverageDays), now.Add(time.Minute), 24*time.Hour)
	if err != nil {
		cov.Note = "Could not read the event store, so field coverage was not measured: " + c.scrub(err.Error())
		return cov
	}
	type sourceKey struct{ host, module, dataset string }
	newest := map[sourceKey]time.Time{}
	for _, b := range buckets {
		if b.Module == event.ModuleHomeXDR {
			continue
		}
		k := sourceKey{b.HostID, b.Module, b.Dataset}
		if b.Start.After(newest[k]) {
			newest[k] = b.Start
		}
	}
	keys := make([]sourceKey, 0, len(newest))
	for k := range newest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return newest[keys[i]].After(newest[keys[j]]) })
	if len(keys) > coverageMaxSources {
		keys = keys[:coverageMaxSources]
	}
	sample := detect.NewCoverage()
	for _, k := range keys {
		list, err := events.SampleSource(cctx, c.Events, k.host, k.module, k.dataset, newest[k], newest[k].Add(24*time.Hour), coverageSample)
		if err != nil {
			cov.Note = "Stopped early while reading events, so this may miss some sources: " + c.scrub(err.Error())
			break
		}
		cov.Sources++
		for _, e := range list {
			sample.Add(e)
		}
	}
	cov.Events = sample.Size()
	if cov.Events == 0 {
		if cov.Note == "" {
			cov.Note = "No events in the last week, so field coverage could not be measured."
		}
		return cov
	}
	groups := map[string]*CoverageGroup{}
	groupFields := map[string]map[string]int{}
	allFields := map[string]int{}
	for _, r := range rules {
		label := logsourceLabel(r.LogSource)
		g := groups[label]
		if g == nil {
			g = &CoverageGroup{Logsource: label}
			groups[label] = g
			groupFields[label] = map[string]int{}
		}
		g.Rules++
		v := sample.Check(r)
		switch {
		case v.CanFire:
			g.CanFire++
			cov.CanFire++
		case !v.SourceSeen:
			g.NoEvents++
			cov.CannotFire++
		default:
			g.MissingField++
			cov.CannotFire++
			for _, f := range v.Missing {
				groupFields[label][f]++
				allFields[f]++
			}
		}
	}
	for label, g := range groups {
		g.Missing = topFields(groupFields[label], 5)
		cov.Groups = append(cov.Groups, *g)
	}
	sort.Slice(cov.Groups, func(i, j int) bool {
		a, b := &cov.Groups[i], &cov.Groups[j]
		if ac, bc := a.Rules-a.CanFire, b.Rules-b.CanFire; ac != bc {
			return ac > bc
		}
		return a.Logsource < b.Logsource
	})
	cov.Missing = topFields(allFields, 30)
	return cov
}

func topFields(m map[string]int, n int) []FieldCount {
	out := make([]FieldCount, 0, len(m))
	for f, c := range m {
		out = append(out, FieldCount{f, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rules != out[j].Rules {
			return out[i].Rules > out[j].Rules
		}
		return out[i].Field < out[j].Field
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func logsourceLabel(ls detect.LogSource) string {
	var parts []string
	for _, p := range []string{ls.Product, ls.Category, ls.Service} {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " / ")
}

// StartSelfCheck runs the self-check in the background, unless one is already running.
func (h *Health) StartSelfCheck(c *Core) bool {
	if !h.selfCheckRunning.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer h.selfCheckRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		res := c.RunSelfCheck(ctx)
		c.Log.Info("self-check finished", "rules", res.Rules, "fired", res.Fired, "pipeline", res.Pipeline.Passed, "regression", res.Regression)
	}()
	return true
}

// SelfCheckRunning reports whether a background self-check is running.
func (h *Health) SelfCheckRunning() bool { return h.selfCheckRunning.Load() }
