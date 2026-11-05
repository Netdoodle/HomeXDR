package core

// Feed health: notice when a data source that used to send data has stopped, and say so
// plainly. A source is (host, module, dataset). Every ingested batch updates an in-memory
// record, and a flush saves changed records once a minute so baselines survive restarts.
//
// The allowance (the longest allowed silence) comes from each source's own history: three
// times its usual longest gap, at least 15 minutes and at most 7 days. Time the server or
// the host was away does not count as silence. See docs/health.md.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	// RuleFeedSilent is the alert raised when a data source or a host goes quiet.
	RuleFeedSilent = "health:feed-silent"

	feedFloor       = 15 * time.Minute
	feedCap         = 7 * 24 * time.Hour
	feedGapFactor   = 3
	feedMinAge      = 24 * time.Hour // seen this long before it can alert
	feedMinArrivals = 20             // and with this many separate arrivals
	feedGrace       = 15 * time.Minute
	feedTick        = time.Minute
	feedAwayGap     = 2 * time.Minute // ticks further apart than this: the server was away
	feedMinGap      = time.Minute     // shorter gaps are not worth recording
	feedGapDays     = 14              // days of longest gaps kept per source
	feedDefault     = 24 * time.Hour  // allowance of an expected source with no history
	feedMaxSources  = 2000            // syslog app names are free text; don't grow without limit

	feedBootstrapDays = 30
	feedBootstrapKey  = "feed_health_bootstrapped"
	feedLastTickKey   = "feed_health_last_tick"
	feedNoteAuthor    = "HomeXDR"
)

// Feed statuses.
const (
	FeedOK          = "ok"
	FeedSilent      = "silent"
	FeedLearning    = "learning"
	FeedNeverSeen   = "never_seen"
	FeedQuiet       = "quiet"
	FeedMuted       = "muted"
	FeedHostOffline = "host_offline"
)

type feedKey struct{ host, module, dataset string }

type feedState struct {
	store.FeedSource
	dirty    bool
	returned bool // an arrival came in while reported silent
}

// knownFeed is a feed a collector should produce, shown as "never seen" until it does.
type knownFeed struct {
	module, dataset, explain string
	endpoint                 bool // for endpoint agents; otherwise OPNsense syslog hosts
}

var knownFeeds = []knownFeed{
	{event.ModuleInventory, "inventory.software.list", "This host has never sent a list of installed software. The agent reads it every few hours. Agents older than this server cannot read Unraid or Slackware packages, so update the agent first. Known-exploited software matching needs this data.", true},
	{event.ModuleInventory, "inventory.services.list", "This host has never sent a list of services. The agent reads it every few hours. Agents older than this server cannot read Unraid or Slackware services, so update the agent first.", true},
	{event.ModuleSuricata, "suricata.alert", "OPNsense is sending logs, but no Suricata alert has ever arrived. A quiet IDS may just mean nothing matched. If you expected alerts, check that Intrusion Detection is on in OPNsense and that it logs alerts to syslog.", false},
}

// quietFeed reports a feed that only has rows when something happened, so silence means
// nothing by itself. It alerts only if the owner marks it expected.
func quietFeed(module string) bool { return module == event.ModuleSuricata }

// FeedHealth tracks every data source.
type FeedHealth struct {
	c   *Core
	now func() time.Time
	// listHosts reads the hosts (tests replace it to control last-seen times).
	listHosts func(ctx context.Context, f store.HostFilter) ([]*store.Host, error)

	mu         sync.Mutex
	src        map[feedKey]*feedState
	graceUntil time.Time
	lastTick   time.Time
	bootDone   bool
	full       bool // feedMaxSources reached
}

func newFeedHealth(c *Core, now func() time.Time) *FeedHealth {
	return &FeedHealth{c: c, now: now, listHosts: c.State.ListHosts, src: map[feedKey]*feedState{}}
}

// load restores saved sources. Time since the last saved tick was server downtime, so every
// clock moves forward by it; a source that was already silent stays as silent as it was,
// and one reported silent stays reported. No saved tick: the clocks start now.
func (f *FeedHealth) load(ctx context.Context) error {
	list, err := f.c.State.ListFeedSources(ctx)
	if err != nil {
		return err
	}
	now := f.now()
	var last time.Time
	_ = f.c.State.GetKV(ctx, feedLastTickKey, &last)
	var done bool
	_ = f.c.State.GetKV(ctx, feedBootstrapKey, &done)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bootDone = done
	f.graceUntil = now.Add(feedGrace)
	f.lastTick = now
	for i := range list {
		st := &feedState{FeedSource: list[i]}
		switch {
		case st.Clock.IsZero():
		case last.IsZero() || last.After(now):
			st.Clock = now
		default:
			st.Clock = minTime(st.Clock.Add(now.Sub(last)), now)
		}
		f.src[feedKey{st.HostID, st.Module, st.Dataset}] = st
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.After(b) {
		return b
	}
	return a
}

// observe notes one batch of events. It takes the lock once per batch and only touches a
// source when the (module, dataset) changes, so it adds very little to ingest.
func (f *FeedHealth) observe(host *store.Host, evs []*event.Event) {
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	var prevModule, prevDataset string
	for i, e := range evs {
		m, d := e.Event.Module, e.Event.Dataset
		if i > 0 && m == prevModule && d == prevDataset {
			continue
		}
		prevModule, prevDataset = m, d
		st := f.src[feedKey{host.ID, m, d}]
		if st == nil {
			if len(f.src) >= feedMaxSources {
				f.full = true
				continue
			}
			st = &feedState{FeedSource: store.FeedSource{HostID: host.ID, Module: m, Dataset: d}}
			f.src[feedKey{host.ID, m, d}] = st
		}
		st.arrive(now)
	}
}

// arrive records rows arriving now. A gap the source was reported silent for was an outage,
// not its usual rhythm, so it stays out of the history.
func (st *feedState) arrive(now time.Time) {
	if st.FirstSeen.IsZero() {
		st.FirstSeen = now
	}
	if st.LastSeen.IsZero() || now.Sub(st.LastSeen) >= feedMinGap {
		st.Arrivals++
	}
	if !st.Clock.IsZero() && st.SilentSince.IsZero() {
		if gap := now.Sub(st.Clock); gap >= feedMinGap {
			st.Gaps = addGap(st.Gaps, now, gap)
		}
	}
	if !st.SilentSince.IsZero() {
		st.returned = true
	}
	st.LastSeen, st.Clock, st.dirty = now, now, true
}

// addGap keeps each day's longest gap, for the last feedGapDays days.
func addGap(gaps []store.FeedGap, at time.Time, gap time.Duration) []store.FeedGap {
	day := at.Unix() / 86400
	sec := int64(gap / time.Second)
	if n := len(gaps); n > 0 && gaps[n-1].Day == day {
		if sec > gaps[n-1].Sec {
			gaps[n-1].Sec = sec
		}
		return gaps
	}
	gaps = append(gaps, store.FeedGap{Day: day, Sec: sec})
	drop := 0
	for drop < len(gaps) && gaps[drop].Day <= day-feedGapDays {
		drop++
	}
	return gaps[drop:]
}

// usualGap is the source's usual longest gap: the second longest of its recent daily longest
// gaps, so one reboot does not set the baseline. With under five days of gaps, the longest.
func usualGap(gaps []store.FeedGap, now time.Time) time.Duration {
	day := now.Unix() / 86400
	var recent []int64
	for _, g := range gaps {
		if g.Day > day-feedGapDays {
			recent = append(recent, g.Sec)
		}
	}
	if len(recent) == 0 {
		return 0
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i] > recent[j] })
	if len(recent) >= 5 {
		return time.Duration(recent[1]) * time.Second
	}
	return time.Duration(recent[0]) * time.Second
}

// allowance is the longest allowed silence.
func allowance(gaps []store.FeedGap, now time.Time) time.Duration {
	a := feedGapFactor * usualGap(gaps, now)
	if a < feedFloor {
		return feedFloor
	}
	if a > feedCap {
		return feedCap
	}
	return a
}

func (st *feedState) eligible(now time.Time) bool {
	return !st.FirstSeen.IsZero() && now.Sub(st.FirstSeen) >= feedMinAge && st.Arrivals >= feedMinArrivals
}

// limit is the source's allowance, allowing for an expected source without enough history.
func (st *feedState) limit(now time.Time) time.Duration {
	switch {
	case quietFeed(st.Module):
		return feedCap
	case st.eligible(now):
		return allowance(st.Gaps, now)
	case st.Expected:
		return feedDefault
	}
	return allowance(st.Gaps, now)
}

// canAlert reports whether this source raises an alert when it goes quiet.
func (st *feedState) canAlert(now time.Time) bool {
	if st.Muted {
		return false
	}
	if st.Expected {
		return true
	}
	return !quietFeed(st.Module) && !st.FirstSeen.IsZero() && st.eligible(now)
}

func feedEntity(k feedKey) string {
	if k.module == "" && k.dataset == "" {
		return k.host + "/host"
	}
	return k.host + "/" + k.module + "/" + k.dataset
}

func hostOffline(h *store.Host, now time.Time) bool {
	window := store.EndpointOnlineWindow
	if h.Kind == store.HostNetwork {
		window = store.NetworkOnlineWindow
	}
	return h.LastSeen == nil || now.Sub(*h.LastSeen) >= window
}

type feedAction struct {
	key   feedKey
	raise *Finding
	note  string // resolve with this note when raise is nil
}

// Tick checks every source once.
func (f *FeedHealth) Tick(ctx context.Context) {
	now := f.now()
	f.mu.Lock()
	elapsed := now.Sub(f.lastTick)
	f.lastTick = now
	f.mu.Unlock()
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > feedAwayGap {
		// The machine slept or the process was paused.
		f.shift(elapsed, now, "")
		f.mu.Lock()
		f.graceUntil = now.Add(feedGrace)
		f.mu.Unlock()
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := f.c.Events.Ping(pingCtx)
	cancel()
	if err != nil {
		// Nothing can be stored, so everything looks silent and no alert could be raised.
		f.shift(elapsed, now, "")
		return
	}
	hosts, err := f.listHosts(ctx, store.HostFilter{IncludeDecommissioned: true})
	if err != nil {
		f.c.Log.Warn("feed health: list hosts", "err", err)
		return
	}
	for _, a := range f.evaluate(hosts, now, elapsed) {
		f.apply(ctx, a)
	}
}

// shift moves silence clocks forward by d, for one host or (host "") for all.
func (f *FeedHealth) shift(d time.Duration, now time.Time, host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, st := range f.src {
		f.shiftOne(st, d, now, host)
	}
}

func (f *FeedHealth) shiftOne(st *feedState, d time.Duration, now time.Time, host string) {
	if (host != "" && st.HostID != host) || st.Clock.IsZero() {
		return
	}
	st.Clock = minTime(st.Clock.Add(d), now)
	st.dirty = true
}

// evaluate works out what to raise and resolve. Only changing state is done here; storing
// alerts happens in apply, outside the lock.
func (f *FeedHealth) evaluate(hosts []*store.Host, now time.Time, elapsed time.Duration) []feedAction {
	byID := make(map[string]*store.Host, len(hosts))
	for _, h := range hosts {
		byID[h.ID] = h
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	inGrace := now.Before(f.graceUntil)
	var out []feedAction
	resolve := func(k feedKey, st *feedState, note string) {
		st.SilentSince, st.returned, st.dirty = time.Time{}, false, true
		out = append(out, feedAction{key: k, note: note})
	}

	// Hosts first: an offline host gets one finding, and its sources' clocks stand still.
	offline := map[string]bool{}
	for _, h := range hosts {
		if h.Revoked || h.DecommissionedAt != nil || h.LastSeen == nil {
			continue
		}
		k := feedKey{host: h.ID}
		st := f.src[k]
		if st == nil {
			st = &feedState{FeedSource: store.FeedSource{HostID: h.ID, FirstSeen: h.EnrolledAt, LastSeen: *h.LastSeen, Clock: *h.LastSeen}, dirty: true}
			f.src[k] = st
		} else if h.LastSeen.After(st.LastSeen) {
			at := *h.LastSeen
			if st.SilentSince.IsZero() && !st.Clock.IsZero() {
				if gap := at.Sub(st.Clock); gap >= feedMinGap*5 {
					st.Gaps = addGap(st.Gaps, at, gap)
				}
			}
			st.Arrivals++
			st.LastSeen, st.Clock, st.dirty = at, maxTime(st.Clock, at), true
		}
		off := hostOffline(h, now)
		offline[h.ID] = off
		switch {
		case !off && !st.SilentSince.IsZero():
			resolve(k, st, fmt.Sprintf("%s is sending data again, after %s. HomeXDR resolved this alert itself.", h.Hostname, plainDuration(now.Sub(st.SilentSince))))
		case off && st.SilentSince.IsZero() && !inGrace && st.canAlert(now) && now.Sub(st.Clock) > st.limit(now):
			st.SilentSince, st.dirty = now, true
			out = append(out, feedAction{key: k, raise: hostFinding(h, st, now)})
		}
	}

	for k, st := range f.src {
		h := byID[k.host]
		switch {
		case h == nil:
			if !st.SilentSince.IsZero() {
				resolve(k, st, "This host was removed from HomeXDR. HomeXDR resolved this alert itself.")
			}
			continue
		case h.Revoked || h.DecommissionedAt != nil:
			if !st.SilentSince.IsZero() {
				resolve(k, st, h.Hostname+" was decommissioned. HomeXDR resolved this alert itself.")
			}
			continue
		}
		if k.module == "" && k.dataset == "" {
			continue // handled above
		}
		if st.returned {
			resolve(k, st, fmt.Sprintf("Data is arriving again from %s on %s. HomeXDR resolved this alert itself.", k.dataset, h.Hostname))
			continue
		}
		if offline[k.host] || h.LastSeen == nil {
			f.shiftOne(st, elapsed, now, "")
			continue
		}
		if !st.SilentSince.IsZero() || inGrace || !st.canAlert(now) {
			continue
		}
		start := st.Clock
		if st.FirstSeen.IsZero() {
			start = st.ExpectedSince
		}
		if start.IsZero() || now.Sub(start) <= st.limit(now) {
			continue
		}
		st.SilentSince, st.dirty = now, true
		out = append(out, feedAction{key: k, raise: feedFinding(h, k, st, now)})
	}
	return out
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func feedFinding(h *store.Host, k feedKey, st *feedState, now time.Time) *Finding {
	entity := feedEntity(k)
	last := "It has never sent any data."
	if !st.LastSeen.IsZero() {
		last = "Last seen " + st.LastSeen.UTC().Format(time.RFC1123) + "."
	}
	return &Finding{
		RuleID: RuleFeedSilent, Severity: store.SevMedium, Tags: []string{"homexdr", "health"},
		Title:       "Data source went silent: " + k.dataset + " on " + h.Hostname,
		Description: "A data source that used to send data has stopped. Detection rules that read it cannot fire until it comes back.",
		Message: fmt.Sprintf("%s on %s has sent nothing for over %s, longer than its usual pattern allows. %s",
			k.dataset, h.Hostname, plainDuration(st.limit(now)), last),
		Entity: entity, HostID: h.ID, Hostname: h.Hostname, Dataset: "homexdr.health",
		Data: map[string]any{"entity": entity, "module": k.module, "dataset": k.dataset, "allowance_sec": int64(st.limit(now) / time.Second)},
	}
}

func hostFinding(h *store.Host, st *feedState, now time.Time) *Finding {
	entity := feedEntity(feedKey{host: h.ID})
	return &Finding{
		RuleID: RuleFeedSilent, Severity: store.SevMedium, Tags: []string{"homexdr", "health"},
		Title:       h.Hostname + " stopped sending data",
		Description: "A host that used to send data has gone quiet, so nothing on it is being watched.",
		Message: fmt.Sprintf("%s has not been heard from for over %s, longer than its usual pattern allows. Last seen %s.",
			h.Hostname, plainDuration(st.limit(now)), st.LastSeen.UTC().Format(time.RFC1123)),
		Entity: entity, HostID: h.ID, Hostname: h.Hostname, Dataset: "homexdr.health",
		Data: map[string]any{"entity": entity, "allowance_sec": int64(st.limit(now) / time.Second)},
	}
}

// apply stores one decision. A finding that could not be stored is retried next tick.
func (f *FeedHealth) apply(ctx context.Context, a feedAction) {
	if a.raise != nil {
		if err := f.c.RaiseFinding(ctx, *a.raise); err != nil {
			f.c.Log.Warn("feed health: raise finding", "err", err, "entity", a.raise.Entity)
			f.mu.Lock()
			if st := f.src[a.key]; st != nil {
				st.SilentSince = time.Time{}
			}
			f.mu.Unlock()
		}
		return
	}
	if _, err := f.c.State.ResolveFinding(ctx, RuleFeedSilent, a.key.host, feedEntity(a.key), feedNoteAuthor, a.note); err != nil {
		f.c.Log.Warn("feed health: resolve finding", "err", err, "entity", feedEntity(a.key))
	}
}

// Flush saves changed sources and the time of the last tick.
func (f *FeedHealth) Flush(ctx context.Context) {
	f.mu.Lock()
	var list []store.FeedSource
	for _, st := range f.src {
		if st.dirty {
			c := st.FeedSource
			c.Gaps = append([]store.FeedGap(nil), st.Gaps...)
			list = append(list, c)
			st.dirty = false
		}
	}
	last := f.lastTick
	f.mu.Unlock()
	if err := f.c.State.PutFeedSources(ctx, list); err != nil {
		f.c.Log.Warn("feed health: save", "err", err)
		f.mu.Lock()
		for i := range list {
			if st := f.src[feedKey{list[i].HostID, list[i].Module, list[i].Dataset}]; st != nil {
				st.dirty = true
			}
		}
		f.mu.Unlock()
		return
	}
	if !last.IsZero() {
		if err := f.c.State.SetKV(ctx, feedLastTickKey, last); err != nil {
			f.c.Log.Warn("feed health: save", "err", err)
		}
	}
}

// Bootstrap fills baselines from stored events on the first run, once. It is one
// aggregated query (rows per source per hour), so gaps start at hour resolution and get
// finer as data arrives. It returns false to be tried again later.
func (f *FeedHealth) Bootstrap(ctx context.Context) bool {
	f.mu.Lock()
	done := f.bootDone
	f.mu.Unlock()
	if done {
		return true
	}
	now := f.now()
	qctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	buckets, err := events.SourceActivity(qctx, f.c.Events, now.AddDate(0, 0, -feedBootstrapDays), now, time.Hour)
	if err != nil {
		f.c.Log.Warn("feed health: reading history failed; will try again", "err", err)
		return false
	}
	hosts, err := f.listHosts(ctx, store.HostFilter{IncludeDecommissioned: true})
	if err != nil {
		return false
	}
	known := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		known[h.ID] = true
	}
	perSource := map[feedKey][]time.Time{}
	perHost := map[string]map[int64]bool{}
	for _, b := range buckets {
		if !known[b.HostID] || b.Module == event.ModuleHomeXDR {
			continue
		}
		k := feedKey{b.HostID, b.Module, b.Dataset}
		perSource[k] = append(perSource[k], b.Start)
		if perHost[b.HostID] == nil {
			perHost[b.HostID] = map[int64]bool{}
		}
		perHost[b.HostID][b.Start.Unix()] = true
	}
	for id, hours := range perHost {
		list := make([]time.Time, 0, len(hours))
		for h := range hours {
			list = append(list, time.Unix(h, 0).UTC())
		}
		perSource[feedKey{host: id}] = list
	}
	f.mu.Lock()
	for k, times := range perSource {
		st := f.src[k]
		if st == nil {
			if len(f.src) >= feedMaxSources {
				continue
			}
			st = &feedState{FeedSource: store.FeedSource{HostID: k.host, Module: k.module, Dataset: k.dataset}}
			f.src[k] = st
		}
		st.mergeHistory(times, now)
	}
	f.bootDone = true
	f.mu.Unlock()
	if err := f.c.State.SetKV(ctx, feedBootstrapKey, true); err != nil {
		f.c.Log.Warn("feed health: save", "err", err)
	}
	f.c.Log.Info("feed health: baselines read from history", "sources", len(perSource))
	return true
}

// mergeHistory folds hourly history into a source that may already have live data.
func (st *feedState) mergeHistory(hours []time.Time, now time.Time) {
	sort.Slice(hours, func(i, j int) bool { return hours[i].Before(hours[j]) })
	first, last := hours[0], minTime(hours[len(hours)-1].Add(time.Hour), now)
	if st.FirstSeen.IsZero() || first.Before(st.FirstSeen) {
		st.FirstSeen = first
	}
	if st.LastSeen.IsZero() || last.After(st.LastSeen) {
		st.LastSeen = last
	}
	if st.Clock.IsZero() || last.After(st.Clock) {
		st.Clock = last
	}
	st.Arrivals += int64(len(hours))
	var hist []store.FeedGap
	for i := 1; i < len(hours); i++ {
		if gap := hours[i].Sub(hours[i-1]); gap > time.Hour {
			hist = addGap(hist, hours[i], gap)
		}
	}
	day := now.Unix() / 86400
	merged := map[int64]int64{}
	for _, list := range [][]store.FeedGap{hist, st.Gaps} {
		for _, g := range list {
			if g.Day > day-feedGapDays && g.Sec > merged[g.Day] {
				merged[g.Day] = g.Sec
			}
		}
	}
	st.Gaps = st.Gaps[:0]
	for d, s := range merged {
		st.Gaps = append(st.Gaps, store.FeedGap{Day: d, Sec: s})
	}
	sort.Slice(st.Gaps, func(i, j int) bool { return st.Gaps[i].Day < st.Gaps[j].Day })
	st.dirty = true
}

// FeedView is one row of the Data health page.
type FeedView struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	// Module and Dataset are empty on the row about the host as a whole.
	Module       string     `json:"module"`
	Dataset      string     `json:"dataset"`
	Status       string     `json:"status"`
	Explanation  string     `json:"explanation,omitempty"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
	Arrivals     int64      `json:"arrivals"`
	UsualGapSec  int64      `json:"usual_gap_sec"`
	AllowanceSec int64      `json:"allowance_sec"`
	SilentSec    int64      `json:"silent_sec"`
	Muted        bool       `json:"muted"`
	Expected     bool       `json:"expected"`
	CanAlert     bool       `json:"can_alert"`
}

// FeedReport is the Data health page.
type FeedReport struct {
	Sources      []FeedView `json:"sources"`
	Bootstrapped bool       `json:"bootstrapped"`
	GraceUntil   *time.Time `json:"grace_until,omitempty"`
	// Note says when a limit means some sources are not tracked.
	Note string `json:"note,omitempty"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func viewOf(st *feedState, h *store.Host, off bool, now time.Time) FeedView {
	v := FeedView{
		HostID: st.HostID, Hostname: h.Hostname, Module: st.Module, Dataset: st.Dataset,
		FirstSeen: timePtr(st.FirstSeen), LastSeen: timePtr(st.LastSeen), Arrivals: st.Arrivals,
		UsualGapSec:  int64(usualGap(st.Gaps, now) / time.Second),
		AllowanceSec: int64(st.limit(now) / time.Second),
		Muted:        st.Muted, Expected: st.Expected, CanAlert: st.canAlert(now),
	}
	if !st.Clock.IsZero() {
		v.SilentSec = int64(max(now.Sub(st.Clock), 0) / time.Second)
	}
	host := st.Module == "" && st.Dataset == ""
	silentNow := !st.SilentSince.IsZero() && !st.returned
	switch {
	case st.Muted:
		v.Status, v.Explanation = FeedMuted, "Muted: this source never raises an alert."
	case st.FirstSeen.IsZero():
		v.Status, v.Explanation = FeedNeverSeen, "Marked as expected, but it has never sent any data. An alert is raised if it stays that way."
	case !host && off:
		v.Status, v.Explanation = FeedHostOffline, h.Hostname+" is offline, so this source is not being timed."
	case silentNow:
		v.Status, v.Explanation = FeedSilent, "This source has stopped sending data, for longer than its usual pattern allows."
	case quietFeed(st.Module) && !st.Expected:
		v.Status, v.Explanation = FeedQuiet, "Alert-only feed: it only has rows when something matched, so a quiet IDS may just mean nothing matched. It does not raise a silence alert unless you mark it expected."
	case !st.canAlert(now):
		v.Status, v.Explanation = FeedLearning, "Still learning its pattern. A source must be seen for a day and arrive at least 20 times before it can alert."
	default:
		v.Status = FeedOK
	}
	if host && v.Status == FeedOK && off {
		v.Explanation = h.Hostname + " is offline, but not for longer than usual yet."
	}
	return v
}

// Report builds the Data health page: every tracked source, plus known collector feeds that
// have never produced a row. Decommissioned hosts are left out.
func (f *FeedHealth) Report(ctx context.Context) (*FeedReport, error) {
	hosts, err := f.listHosts(ctx, store.HostFilter{})
	if err != nil {
		return nil, err
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	rep := &FeedReport{Sources: []FeedView{}, Bootstrapped: f.bootDone}
	if now.Before(f.graceUntil) {
		rep.GraceUntil = timePtr(f.graceUntil)
	}
	if f.full {
		rep.Note = fmt.Sprintf("Tracking stopped at %d sources, so newer ones are not shown.", feedMaxSources)
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		off := hostOffline(h, now)
		for k, st := range f.src {
			// A row with no data and no choice left on it is only a known feed, if anything.
			if k.host == h.ID && (!st.FirstSeen.IsZero() || st.Muted || st.Expected) {
				rep.Sources = append(rep.Sources, viewOf(st, h, off, now))
			}
		}
		for _, kf := range knownFeeds {
			if !f.feedApplies(kf, h, now) {
				continue
			}
			k := feedKey{h.ID, kf.module, kf.dataset}
			if st := f.src[k]; st != nil && (!st.FirstSeen.IsZero() || st.Muted || st.Expected) {
				continue // shown above
			}
			rep.Sources = append(rep.Sources, FeedView{
				HostID: h.ID, Hostname: h.Hostname, Module: kf.module, Dataset: kf.dataset,
				Status: FeedNeverSeen, Explanation: neverSeenText(kf, h),
				AllowanceSec: int64(feedDefault / time.Second),
			})
		}
	}
	sort.Slice(rep.Sources, func(i, j int) bool {
		a, b := &rep.Sources[i], &rep.Sources[j]
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.Dataset < b.Dataset
	})
	return rep, nil
}

func (f *FeedHealth) feedApplies(kf knownFeed, h *store.Host, now time.Time) bool {
	if kf.endpoint {
		return h.Kind == store.HostEndpoint
	}
	st := f.src[feedKey{h.ID, event.ModuleOPNsense, "opnsense.filterlog"}]
	return h.Kind == store.HostNetwork && st != nil && now.Sub(st.LastSeen) < 24*time.Hour
}

// neverSeenText adds what the agent itself says, when it has said anything.
func neverSeenText(kf knownFeed, h *store.Host) string {
	if kf.endpoint {
		for _, s := range h.Sensors {
			if s.Name == event.ModuleInventory && s.Error != "" {
				return kf.explain + " The agent says: " + s.Error
			}
		}
	}
	return kf.explain
}

// SetChoice records the owner's mute or expected choice for a source. Muting a source
// reported silent resolves its alert.
func (f *FeedHealth) SetChoice(ctx context.Context, hostID, module, dataset string, muted, expected *bool) error {
	if _, err := f.c.State.GetHost(ctx, hostID); err != nil {
		return err
	}
	k := feedKey{hostID, module, dataset}
	now := f.now()
	f.mu.Lock()
	st := f.src[k]
	if st == nil {
		st = &feedState{FeedSource: store.FeedSource{HostID: hostID, Module: module, Dataset: dataset}}
		f.src[k] = st
	}
	if muted != nil {
		st.Muted = *muted
	}
	if expected != nil {
		st.Expected = *expected
		st.ExpectedSince = time.Time{}
		if *expected {
			st.ExpectedSince = now
		}
	}
	st.dirty = true
	var action *feedAction
	if !st.SilentSince.IsZero() && !st.canAlert(now) {
		st.SilentSince, st.returned = time.Time{}, false
		action = &feedAction{key: k, note: "You changed this source's settings so it no longer alerts. HomeXDR resolved this alert itself."}
	}
	f.mu.Unlock()
	if action != nil {
		f.apply(ctx, *action)
	}
	f.Flush(ctx)
	return nil
}

// Run checks sources every minute and saves them, until ctx ends.
func (f *FeedHealth) Run(ctx context.Context) {
	tick := time.NewTicker(feedTick)
	defer tick.Stop()
	booted := false
	var retryBoot time.Time
	for {
		select {
		case <-ctx.Done():
			flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			f.Flush(flush)
			cancel()
			return
		case <-tick.C:
		}
		if now := f.now(); !booted && now.After(retryBoot) {
			booted = f.Bootstrap(ctx)
			retryBoot = now.Add(time.Hour)
		}
		f.Tick(ctx)
		f.Flush(ctx)
	}
}

// FeedHealthDigest is a ready digest section: a title and one line per problem. The
// integrator hands it to the notify package's AddDigestSection. No lines means nothing to say.
func (c *Core) FeedHealthDigest(ctx context.Context) (title string, lines []string) {
	title = "Data health"
	rep, err := c.Health.Feeds.Report(ctx)
	if err != nil {
		return title, []string{"Could not read data health: " + err.Error()}
	}
	never := 0
	for i := range rep.Sources {
		v := &rep.Sources[i]
		name := v.Dataset
		if name == "" {
			name = "all data"
		}
		switch v.Status {
		case FeedSilent:
			lines = append(lines, fmt.Sprintf("%s: %s has been silent for %s.", v.Hostname, name, plainDuration(time.Duration(v.SilentSec)*time.Second)))
		case FeedNeverSeen:
			never++
		}
	}
	if never > 0 {
		lines = append(lines, fmt.Sprintf("%d expected %s never sent any data. See the Data health page.", never, plural(never, "source has", "sources have")))
	}
	return title, lines
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// plainDuration writes a duration the way a person would say it.
func plainDuration(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	unit := func(n int64, name string) string {
		if n == 1 {
			return "1 " + name
		}
		return fmt.Sprintf("%d %ss", n, name)
	}
	switch {
	case d < time.Hour:
		return unit(int64(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return unit(int64((d+30*time.Minute)/time.Hour), "hour")
	}
	return unit(int64((d+12*time.Hour)/(24*time.Hour)), "day")
}
