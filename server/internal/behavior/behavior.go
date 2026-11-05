// Package behavior looks for patterns across many events that no single-event rule can
// see: a device checking in on a timer, a sudden upload, a port sweep. Detectors run one at
// a time on a schedule, against the event store, with bounded windows, so a slow one holds
// up the next detector and never ingest.
package behavior

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/netscope"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	settingsKey = "behavior_settings"
	statusKey   = "behavior_status"

	// Each detector runs at most this often, unless its Spec says less often.
	defaultEvery = 15 * time.Minute
	// tickEvery spaces out detectors, so they never pile up on the event store.
	tickEvery  = 90 * time.Second
	runTimeout = 3 * time.Minute
	// maxFindingsPerRun: more stay unreported until the next run.
	maxFindingsPerRun = 20
	// maxStateKeys bounds what one detector remembers.
	maxStateKeys = 20000
	dataWindow   = 24 * time.Hour
)

// Status values.
const (
	StatusPending  = "pending"
	StatusOK       = "ok"
	StatusLimited  = "limited"
	StatusLearning = "learning"
	StatusNeedData = "needs_data"
	StatusDisabled = "disabled"
	StatusError    = "error"
)

// Finding is something a detector found.
type Finding struct {
	Rule, Title, Description string
	Severity                 string
	Entity                   string
	Source, Destination      *event.Endpoint
	Data                     map[string]any
}

// Deps is what the runner needs from the rest of the server.
type Deps struct {
	Events events.Store
	State  *store.Store
	Enrich func() enrich.Lookup
	Log    *slog.Logger
	// Scope is the current view of the home network, shared with the device inventory.
	Scope func() *netscope.Scope
	// Label names the device behind an address: a key that survives address changes, and
	// text for people.
	Label func(ip string) (key, label string)
	Raise func(ctx context.Context, f Finding) error
	Now   func() time.Time
}

// Threshold describes one number a detector uses.
type Threshold struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Help    string  `json:"help"`
	Default float64 `json:"default"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
}

// ListDef describes one list a detector uses.
type ListDef struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Help  string `json:"help"`
	// Kind says what each entry must be: ip, domain, port or endpoint.
	Kind    string   `json:"kind"`
	Default []string `json:"default,omitempty"`
}

type dataNeed int

const (
	needTraffic  dataNeed = iota // NetFlow; firewall rows only give a partial view
	needFlows                    // NetFlow alone
	needDNS                      // DNS logs naming the client
	needFirewall                 // firewall rows or NetFlow, either is enough
)

// Spec describes a detector.
type Spec struct {
	ID         string
	Rule       string
	Title      string
	About      string
	Need       dataNeed
	Every      time.Duration
	Thresholds []Threshold
	Lists      []ListDef
	run        func(*runCtx) error
}

// DetectorSetting is what the owner sets for one detector. A nil Enabled and a missing
// value mean the default.
type DetectorSetting struct {
	Enabled *bool               `json:"enabled,omitempty"`
	Values  map[string]float64  `json:"values,omitempty"`
	Lists   map[string][]string `json:"lists,omitempty"`
}

// Settings holds every detector's settings by ID.
type Settings struct {
	Detectors map[string]DetectorSetting `json:"detectors"`
}

// Status is how a detector is doing.
type Status struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	About string `json:"about"`
	// Enabled mirrors the setting; State is one of the Status* values.
	Enabled bool   `json:"enabled"`
	State   string `json:"status"`
	// DataNeeded says what to turn on, when input is missing or partial.
	DataNeeded     string     `json:"data_needed,omitempty"`
	LastRun        *time.Time `json:"last_run,omitempty"`
	LastDurationMs int64      `json:"last_duration_ms,omitempty"`
	LastFindings   int        `json:"last_finding_count"`
	TotalFindings  int        `json:"total_finding_count"`
	LearningUntil  *time.Time `json:"learning_until,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// DetectorView is a detector's settings for the console.
type DetectorView struct {
	ID         string              `json:"id"`
	Title      string              `json:"title"`
	About      string              `json:"about"`
	Enabled    bool                `json:"enabled"`
	Values     map[string]float64  `json:"values"`
	Lists      map[string][]string `json:"lists"`
	Thresholds []Threshold         `json:"thresholds"`
	ListDefs   []ListDef           `json:"list_defs"`
}

// Runner schedules and runs the detectors.
type Runner struct {
	d     Deps
	specs []*Spec

	mu       sync.Mutex
	settings Settings
	status   map[string]*Status
	next     int
}

// New returns a runner over all detectors.
func New(d Deps) *Runner {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Enrich == nil {
		d.Enrich = func() enrich.Lookup { return enrich.Nop{} }
	}
	return &Runner{d: d, specs: catalog(), status: map[string]*Status{}, settings: Settings{Detectors: map[string]DetectorSetting{}}}
}

// Load reads settings and the last known status.
func (r *Runner) Load(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var set Settings
	switch err := r.d.State.GetKV(ctx, settingsKey, &set); {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	default:
		if set.Detectors != nil {
			r.settings = set
		}
	}
	var st map[string]*Status
	if err := r.d.State.GetKV(ctx, statusKey, &st); err == nil && st != nil {
		r.status = st
	}
	return nil
}

// Run runs detectors until ctx ends, one per tick, each when it is due.
func (r *Runner) Run(ctx context.Context) {
	tick := time.NewTicker(tickEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s := r.nextDue()
			if s == nil {
				continue
			}
			r.runOne(ctx, s)
		}
	}
}

// nextDue picks the next detector in turn whose time has come.
func (r *Runner) nextDue() *Spec {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.d.Now()
	for range r.specs {
		s := r.specs[r.next%len(r.specs)]
		r.next++
		every := s.Every
		if every == 0 {
			every = defaultEvery
		}
		st := r.status[s.ID]
		if st == nil || st.LastRun == nil || now.Sub(*st.LastRun) >= every {
			return s
		}
	}
	return nil
}

// RunAll runs every detector now, one after another.
func (r *Runner) RunAll(ctx context.Context) {
	for _, s := range r.specs {
		r.runOne(ctx, s)
	}
}

func (r *Runner) setting(id string) DetectorSetting {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settings.Detectors[id]
}

func enabled(ds DetectorSetting) bool { return ds.Enabled == nil || *ds.Enabled }

func (r *Runner) runOne(parent context.Context, s *Spec) {
	ds := r.setting(s.ID)
	if !enabled(ds) {
		return
	}
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()
	now := r.d.Now().UTC()
	start := time.Now()
	st := Status{ID: s.ID, State: StatusOK}
	r.mu.Lock()
	if prev := r.status[s.ID]; prev != nil {
		st.TotalFindings = prev.TotalFindings
	}
	r.mu.Unlock()

	level, needed := r.checkData(ctx, s, now)
	st.DataNeeded = needed
	var found int
	var runErr error
	switch level {
	case levelNone:
		st.State = StatusNeedData
	default:
		if level == levelPartial {
			st.State = StatusLimited
		}
		var rc *runCtx
		if rc, runErr = r.newRunCtx(ctx, s, ds, level, now); runErr == nil {
			runErr = s.run(rc)
			if until := rc.learningUntil(); rc.learning() {
				st.State, st.LearningUntil = StatusLearning, &until
			}
			found = rc.raised
			if err := rc.save(); err != nil && runErr == nil {
				runErr = err
			}
		}
	}
	if runErr != nil && parent.Err() != nil {
		return // shutting down; keep the last real status
	}
	if runErr != nil {
		st.State, st.Error = StatusError, runErr.Error()
		r.d.Log.Warn("behaviour detector failed", "detector", s.ID, "err", runErr)
	}
	st.LastRun = &now
	st.LastDurationMs = time.Since(start).Milliseconds()
	st.LastFindings = found
	st.TotalFindings += found
	r.mu.Lock()
	r.status[s.ID] = &st
	snapshot, err := json.Marshal(r.status)
	r.mu.Unlock()
	if err == nil {
		_ = r.d.State.SetKV(context.WithoutCancel(parent), statusKey, json.RawMessage(snapshot))
	}
}

type dataLevel int

const (
	levelNone dataLevel = iota
	levelPartial
	levelFull
)

// Text for what a detector is missing.
const (
	wantNetFlow = "NetFlow from the firewall. See docs/network-visibility.md."
	partialText = "Running on firewall rows only, which rarely name the device behind NAT. NetFlow gives it the full picture. See docs/network-visibility.md."
	wantDNS     = "Unbound query logs, or Suricata DNS events. See docs/network-visibility.md."
	wantRows    = "Firewall logs or NetFlow. See docs/network-visibility.md."
)

// checkData reports how much of a detector's input exists.
func (r *Runner) checkData(ctx context.Context, s *Spec, now time.Time) (dataLevel, string) {
	has := func(q string) bool {
		res, err := r.d.Events.Search(ctx, events.SearchQuery{Query: q + " | stats count as n", From: now.Add(-dataWindow), To: now.Add(time.Minute)})
		if err != nil || len(res.Rows) == 0 {
			return false
		}
		return toFloat(res.Rows[0][0]) > 0
	}
	flows := func() bool { return has("event.module:netflow") }
	rows := func() bool { return has("event.module:opnsense") || has("event.dataset:suricata.flow") }
	switch s.Need {
	case needFlows:
		if flows() {
			return levelFull, ""
		}
		return levelNone, wantNetFlow
	case needDNS:
		if has("dns.question.name:*") {
			return levelFull, ""
		}
		return levelNone, wantDNS
	case needFirewall:
		if flows() || rows() {
			return levelFull, ""
		}
		return levelNone, wantRows
	}
	if flows() {
		return levelFull, ""
	}
	if rows() {
		return levelPartial, partialText
	}
	return levelNone, wantNetFlow
}

// Statuses returns every detector's status, in catalog order.
func (r *Runner) Statuses() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Status, 0, len(r.specs))
	for _, s := range r.specs {
		st := Status{ID: s.ID, State: StatusPending}
		if prev := r.status[s.ID]; prev != nil {
			st = *prev
		}
		st.Title, st.About = s.Title, s.About
		st.Enabled = enabled(r.settings.Detectors[s.ID])
		if !st.Enabled {
			st.State = StatusDisabled
		}
		out = append(out, st)
	}
	return out
}

// DetectorViews returns every detector's settings, with defaults filled in.
func (r *Runner) DetectorViews() []DetectorView {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DetectorView, 0, len(r.specs))
	for _, s := range r.specs {
		ds := r.settings.Detectors[s.ID]
		v := DetectorView{
			ID: s.ID, Title: s.Title, About: s.About, Enabled: enabled(ds),
			Values: map[string]float64{}, Lists: map[string][]string{},
			Thresholds: s.Thresholds, ListDefs: s.Lists,
		}
		if v.ListDefs == nil {
			v.ListDefs = []ListDef{}
		}
		for _, t := range s.Thresholds {
			v.Values[t.Key] = t.Default
			if x, ok := ds.Values[t.Key]; ok {
				v.Values[t.Key] = x
			}
		}
		for _, l := range s.Lists {
			v.Lists[l.Key] = []string{}
			if l.Default != nil {
				v.Lists[l.Key] = l.Default
			}
			if x, ok := ds.Lists[l.Key]; ok {
				v.Lists[l.Key] = x
			}
		}
		out = append(out, v)
	}
	return out
}

// InputError is a problem with settings the owner entered.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// SetSettings validates and stores new settings.
func (r *Runner) SetSettings(ctx context.Context, set Settings) error {
	if set.Detectors == nil {
		set.Detectors = map[string]DetectorSetting{}
	}
	for id, ds := range set.Detectors {
		s := r.spec(id)
		if s == nil {
			return &InputError{fmt.Sprintf("unknown detector %q", id)}
		}
		for k, v := range ds.Values {
			t := s.threshold(k)
			if t == nil {
				return &InputError{fmt.Sprintf("%s has no setting %q", s.Title, k)}
			}
			if v < t.Min || v > t.Max {
				return &InputError{fmt.Sprintf("%s: %s must be between %g and %g", s.Title, t.Label, t.Min, t.Max)}
			}
		}
		for k, items := range ds.Lists {
			l := s.list(k)
			if l == nil {
				return &InputError{fmt.Sprintf("%s has no list %q", s.Title, k)}
			}
			if len(items) > 500 {
				return &InputError{fmt.Sprintf("%s: %s is too long", s.Title, l.Label)}
			}
			for i, item := range items {
				if !validListItem(l.Kind, item) {
					return &InputError{fmt.Sprintf("%s: %q does not belong in %s", s.Title, item, l.Label)}
				}
				items[i] = normalListItem(l.Kind, item)
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.d.State.SetKV(ctx, settingsKey, set); err != nil {
		return err
	}
	r.settings = set
	return nil
}

func validListItem(kind, item string) bool {
	if item == "" || len(item) > 253 || strings.ContainsAny(item, " \t\r\n") {
		return false
	}
	switch kind {
	case "ip":
		_, err := netip.ParseAddr(item)
		return err == nil
	case "domain":
		return strings.Contains(strings.Trim(item, "."), ".")
	case "port", "endpoint":
		_, _, _, ok := parsePortItem(item)
		return ok
	}
	return true
}

// normalListItem writes an entry the way detectors compare it.
func normalListItem(kind, item string) string {
	switch kind {
	case "ip":
		if a, err := netip.ParseAddr(item); err == nil {
			return a.Unmap().String()
		}
	case "domain":
		return strings.ToLower(strings.Trim(item, "."))
	}
	return item
}

func (r *Runner) spec(id string) *Spec {
	for _, s := range r.specs {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func (s *Spec) threshold(key string) *Threshold {
	for i := range s.Thresholds {
		if s.Thresholds[i].Key == key {
			return &s.Thresholds[i]
		}
	}
	return nil
}

func (s *Spec) list(key string) *ListDef {
	for i := range s.Lists {
		if s.Lists[i].Key == key {
			return &s.Lists[i]
		}
	}
	return nil
}

// runCtx is one detector's run: its settings, memory and what it has raised.
type runCtx struct {
	context.Context
	r     *Runner
	s     *Spec
	ds    DetectorSetting
	level dataLevel
	now   time.Time
	scope *netscope.Scope

	state   map[string]string
	changed map[string]string
	removed map[string]bool
	raised  int
	started time.Time
}

func (r *Runner) newRunCtx(ctx context.Context, s *Spec, ds DetectorSetting, level dataLevel, now time.Time) (*runCtx, error) {
	state, err := r.d.State.BehaviorState(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	rc := &runCtx{
		Context: ctx, r: r, s: s, ds: ds, level: level, now: now, scope: r.d.Scope(),
		state: state, changed: map[string]string{}, removed: map[string]bool{},
	}
	// Learning starts when a detector first has this level of input. NetFlow arriving later
	// is a far wider view than firewall rows, so it starts learning again.
	key := "started|partial"
	if level == levelFull {
		key = "started|full"
	}
	if t, err := time.Parse(time.RFC3339, state[key]); err == nil {
		rc.started = t
	} else {
		rc.started = now
		rc.put(key, now.Format(time.RFC3339))
	}
	return rc, nil
}

func (rc *runCtx) value(key string) float64 {
	if v, ok := rc.ds.Values[key]; ok {
		return v
	}
	if t := rc.s.threshold(key); t != nil {
		return t.Default
	}
	return 0
}

func (rc *runCtx) listOf(key string) []string {
	if v, ok := rc.ds.Lists[key]; ok {
		return v
	}
	if l := rc.s.list(key); l != nil {
		return l.Default
	}
	return nil
}

func (rc *runCtx) learningUntil() time.Time {
	return rc.started.Add(time.Duration(rc.value("learning_days") * float64(24*time.Hour)))
}

// learning reports the learning period of a detector that has one.
func (rc *runCtx) learning() bool {
	return rc.s.threshold("learning_days") != nil && rc.now.Before(rc.learningUntil())
}

func (rc *runCtx) get(key string) (string, bool) {
	v, ok := rc.state[key]
	return v, ok
}

func (rc *runCtx) put(key, val string) {
	if _, exists := rc.state[key]; !exists && len(rc.state) >= maxStateKeys {
		return
	}
	rc.state[key] = val
	rc.changed[key] = val
	delete(rc.removed, key)
}

func (rc *runCtx) del(key string) {
	delete(rc.state, key)
	delete(rc.changed, key)
	rc.removed[key] = true
}

func (rc *runCtx) save() error {
	removed := make([]string, 0, len(rc.removed))
	for k := range rc.removed {
		removed = append(removed, k)
	}
	return rc.r.d.State.SaveBehaviorState(context.WithoutCancel(rc.Context), rc.s.ID, rc.changed, removed)
}

// reportedWithin says an entity was reported in the last n days, and forgets old reports.
func (rc *runCtx) reportedWithin(entity string, days float64) bool {
	key := "r|" + entity
	v, ok := rc.get(key)
	if !ok {
		return false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil || rc.now.Sub(t) >= time.Duration(days*float64(24*time.Hour)) {
		rc.del(key)
		return false
	}
	return true
}

// raise reports a finding once per reported_days per entity. It returns whether it did.
func (rc *runCtx) raise(f Finding) bool {
	if rc.raised >= maxFindingsPerRun {
		return false
	}
	if rc.reportedWithin(f.Entity, rc.value("reported_days")) {
		return false
	}
	f.Rule = rc.s.Rule
	if f.Data == nil {
		f.Data = map[string]any{}
	}
	f.Data["detector"] = rc.s.ID
	entity := f.Entity
	f.Entity = rc.s.ID + "|" + entity
	if err := rc.r.d.Raise(rc.Context, f); err != nil {
		rc.r.d.Log.Warn("behaviour finding", "detector", rc.s.ID, "err", err)
		return false
	}
	rc.put("r|"+entity, rc.now.Format(time.RFC3339))
	rc.raised++
	return true
}

// row is one result row by column name.
type row map[string]any

func (x row) str(k string) string {
	if s, ok := x[k].(string); ok {
		return s
	}
	return ""
}

func (x row) num(k string) float64 { return toFloat(x[k]) }

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case string:
		var f float64
		_, _ = fmt.Sscan(n, &f)
		return f
	}
	return 0
}

// table runs a transforming search over a time range and returns its rows.
func (rc *runCtx) table(query string, from, to time.Time) ([]row, error) {
	res, err := rc.r.d.Events.Search(rc.Context, events.SearchQuery{Query: query, From: from, To: to})
	if err != nil {
		return nil, err
	}
	out := make([]row, 0, len(res.Rows))
	for _, r := range res.Rows {
		m := make(row, len(r))
		for i, c := range res.Columns {
			if i < len(r) {
				m[c.Name] = r[i]
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// window is the last n hours up to a minute from now, since clocks differ a little.
func (rc *runCtx) window(hours float64) (time.Time, time.Time) {
	return rc.now.Add(-time.Duration(hours * float64(time.Hour))), rc.now.Add(time.Minute)
}

func (rc *runCtx) addr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// home parses an address that belongs to a device on the home network.
func (rc *runCtx) home(s string) (netip.Addr, bool) {
	a, ok := rc.addr(s)
	return a, ok && rc.scope.Home(a)
}

func (rc *runCtx) label(ip string) (key, label string) { return rc.r.d.Label(ip) }

func (rc *runCtx) enrich() enrich.Lookup { return rc.r.d.Enrich() }

// asName adds the network owner of a public address, when the offline lists know it.
func (rc *runCtx) asName(ip string) string {
	if info := rc.enrich().IP(ip); info.ASName != "" {
		return info.ASName
	}
	return ""
}

// sortRows orders rows by a text key so runs are repeatable.
func sortRows(rows []row, key func(row) string) {
	sort.Slice(rows, func(i, j int) bool { return key(rows[i]) < key(rows[j]) })
}
