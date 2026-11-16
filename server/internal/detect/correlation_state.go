package detect

import (
	"container/list"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds on correlation state.
const (
	// corrMaxGroups caps the groups one correlation rule tracks; the least recently
	// updated group is dropped to make room.
	corrMaxGroups = 10000
	// corrMaxPerGroup caps the timestamps or values one group keeps (maxThreshold).
	corrMaxPerGroup = maxThreshold
	// corrSweepEvery is how often expired groups are swept out.
	corrSweepEvery = 30 * time.Second
	// corrLateness is how far behind the newest event of a correlation an event may be and
	// still open a group: an agent sending a backlog, or a clock a little behind.
	corrLateness = 5 * time.Minute
)

// CorrelationMatch is a correlation or threshold rule whose condition was met.
type CorrelationMatch struct {
	Rule  *Rule
	Level string // the rule's level, or the highest of its base rules when it sets none
	// Group holds the group-by fields and their values ("" when the event had none).
	Group []GroupValue
	// Count is how many events, distinct values or rules met the condition. AtLeast says
	// there were more than the group keeps (Count is then a lower bound).
	Count   int
	AtLeast bool
	Window  time.Duration
	// First and Last are the times of the oldest and newest event in the window.
	First, Last time.Time
	// Summary says what happened, for the alert: "12 events ... within 5m for source.ip=...".
	Summary string
}

// GroupValue is one group-by field of a correlation match.
type GroupValue struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// GroupLabel renders the group as "field=value, field=value" ("" without group-by).
func (m *CorrelationMatch) GroupLabel() string {
	parts := make([]string, len(m.Group))
	for i, g := range m.Group {
		parts[i] = g.Field + "=" + g.Value
	}
	return strings.Join(parts, ", ")
}

// corrDef is a correlation rule linked to its base rules.
type corrDef struct {
	rule        *Rule
	c           *Correlation
	groupFields [][]string // per base: the field holding each group-by value
	level       string
	need        int
	baseTitles  []string
}

func newCorrDef(r *Rule, bases []*Rule) *corrDef {
	c := r.Correlation
	d := &corrDef{rule: r, c: c, level: r.Level, need: c.need()}
	best := 0
	for i, b := range bases {
		fields := make([]string, len(c.GroupBy))
		for j, g := range c.GroupBy {
			fields[j] = g
			if i < len(c.Rules) {
				if f := c.Aliases[g][c.Rules[i]]; f != "" {
					fields[j] = f
				}
			}
		}
		d.groupFields = append(d.groupFields, fields)
		if !containsStr(d.baseTitles, b.Title) {
			d.baseTitles = append(d.baseTitles, b.Title)
		}
		if levelRank[b.Level] > best {
			best = levelRank[b.Level]
			if !r.levelSet {
				d.level = b.Level
			}
		}
	}
	return d
}

var levelRank = map[string]int{"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

// corrKey identifies a correlation definition, so its state survives a rule reload that
// does not change it.
func corrKey(r *Rule, bases []*Rule) string {
	var b strings.Builder
	b.WriteString(r.ID)
	b.WriteByte(0)
	b.WriteString(r.YAML)
	for _, base := range bases {
		b.WriteByte(0)
		b.WriteString(base.ID)
		b.WriteByte('|')
		b.WriteString(base.Level)
		b.WriteByte('|')
		b.WriteString(base.Title)
	}
	return b.String()
}

// corrGroup is the window of one group of one correlation rule.
type corrGroup struct {
	key     string
	values  []string // group-by values, for the alert
	latest  time.Time
	fired   bool
	firedAt time.Time // window end when it last fired; quiet until a whole span later

	times   []time.Time          // event_count: ascending
	vals    map[string]time.Time // value_count: last seen
	minSeen time.Time            // value_count: oldest last-seen time in vals
	seen    [][]time.Time        // temporal: per base, ascending
	elem    *list.Element
}

// corrState keeps the sliding windows of one correlation rule. It is safe for concurrent
// use.
type corrState struct {
	def       *corrDef
	maxGroups int
	maxPer    int
	now       func() time.Time // wall clock, for pacing sweeps

	mu        sync.Mutex
	groups    map[string]*corrGroup
	lru       *list.List // of *corrGroup, most recently updated first
	maxSeen   time.Time  // newest event time fed
	lastSweep time.Time
}

func newCorrState(def *corrDef) *corrState {
	return &corrState{def: def, maxGroups: corrMaxGroups, maxPer: corrMaxPerGroup, now: time.Now,
		groups: map[string]*corrGroup{}, lru: list.New()}
}

// groupOf reads the group-by values of a matching event for base rule i.
func (s *corrState) groupOf(base int, d *Doc) (key string, values []string) {
	fields := s.def.groupFields[base]
	values = make([]string, len(fields))
	var b strings.Builder
	for i, f := range fields {
		v, _ := d.Get(f)
		values[i] = strings.Join(v, ", ")
		// Length-prefixed, so no value can imitate a field boundary.
		b.WriteString(strconv.Itoa(len(values[i])))
		b.WriteByte(':')
		b.WriteString(values[i])
	}
	return b.String(), values
}

// feed records that base rule i matched d at ts, and returns a match when the rule's
// condition becomes true for the event's group.
func (s *corrState) feed(base int, d *Doc, ts time.Time) *CorrelationMatch {
	def := s.def
	c := def.c
	var fieldVals []string
	if c.Type == CorrValueCount {
		v, ok := d.Get(c.Field)
		if !ok {
			return nil // nothing to count
		}
		for _, x := range v {
			if x != "" && !containsStr(fieldVals, x) {
				fieldVals = append(fieldVals, x)
			}
		}
	}
	key, values := s.groupOf(base, d)

	s.mu.Lock()
	defer s.mu.Unlock()
	if ts.After(s.maxSeen) {
		s.maxSeen = ts
	}
	s.sweepLocked(s.maxSeen)
	g := s.groups[key]
	switch {
	case g == nil:
		if !ts.After(s.maxSeen.Add(-c.Timespan - corrLateness)) {
			return nil
		}
		g = s.newGroup(key, values)
	case !ts.After(g.latest.Add(-c.Timespan)):
		return nil // older than the group's window: it can no longer count
	default:
		s.lru.MoveToFront(g.elem)
	}
	if ts.After(g.latest) {
		g.latest = ts
	}
	cut := g.latest.Add(-c.Timespan) // the window is (cut, latest]

	var count int
	var first time.Time
	var capped bool
	switch c.Type {
	case CorrEventCount:
		// The newest `need` times are enough to tell whether the threshold is met.
		g.times, capped = pruneTimes(insertTime(g.times, ts), cut, min(def.need, s.maxPer))
		count, first = len(g.times), g.times[0]
	case CorrValueCount:
		for _, v := range fieldVals {
			if old, ok := g.vals[v]; !ok || ts.After(old) {
				g.vals[v] = ts
			}
			if g.minSeen.IsZero() || ts.Before(g.minSeen) {
				g.minSeen = ts
			}
		}
		first, capped = s.pruneValues(g, cut)
		count = len(g.vals)
	case CorrTemporal:
		keep := 1 // the last time each rule matched is enough unless order matters
		if c.Ordered {
			keep = s.maxPer
		}
		g.seen[base] = insertTime(g.seen[base], ts)
		// Every rule's times, not only this one's: the window moved for all of them.
		for i := range g.seen {
			g.seen[i], _ = pruneTimes(g.seen[i], cut, keep)
			if l := g.seen[i]; len(l) > 0 && (first.IsZero() || l[0].Before(first)) {
				first = l[0]
			}
		}
		count = temporalCount(g.seen, cut)
	}

	if g.fired {
		if g.latest.Before(g.firedAt.Add(c.Timespan)) {
			return nil // already alerted for this window
		}
		g.fired = false
	}
	met := count >= def.need
	if c.Type == CorrTemporal && c.Ordered {
		met = inOrder(g.seen, g.latest)
		count = len(g.seen)
	}
	if !met {
		return nil
	}
	g.fired, g.firedAt = true, g.latest
	m := &CorrelationMatch{Rule: def.rule, Level: def.level, Count: count, AtLeast: capped, Window: c.Timespan, First: first, Last: g.latest}
	for i, f := range c.GroupBy {
		m.Group = append(m.Group, GroupValue{Field: f, Value: g.values[i]})
	}
	m.Summary = def.summary(m)
	return m
}

func (s *corrState) newGroup(key string, values []string) *corrGroup {
	if len(s.groups) >= s.maxGroups {
		if back := s.lru.Back(); back != nil {
			old := back.Value.(*corrGroup)
			s.lru.Remove(back)
			delete(s.groups, old.key)
		}
	}
	g := &corrGroup{key: key, values: values}
	switch s.def.c.Type {
	case CorrValueCount:
		g.vals = map[string]time.Time{}
	case CorrTemporal:
		g.seen = make([][]time.Time, len(s.def.groupFields))
	}
	g.elem = s.lru.PushFront(g)
	s.groups[key] = g
	return g
}

// pruneValues drops values last seen at or before cut, and the oldest beyond the cap. It
// returns the oldest last-seen time left (minSeen may be older than the true oldest when
// a value was seen again, which only costs an early scan), and whether values were dropped
// for the cap.
func (s *corrState) pruneValues(g *corrGroup, cut time.Time) (time.Time, bool) {
	if len(g.vals) <= s.maxPer && g.minSeen.After(cut) {
		return g.minSeen, false // nothing can have expired
	}
	capped := len(g.vals) > s.maxPer
	for len(g.vals) > s.maxPer {
		var oldest string
		var ot time.Time
		for v, t := range g.vals {
			if oldest == "" || t.Before(ot) {
				oldest, ot = v, t
			}
		}
		delete(g.vals, oldest)
	}
	var minSeen time.Time
	for v, t := range g.vals {
		if !t.After(cut) {
			delete(g.vals, v)
			continue
		}
		if minSeen.IsZero() || t.Before(minSeen) {
			minSeen = t
		}
	}
	g.minSeen = minSeen
	return minSeen, capped
}

// sweepLocked drops groups whose window ended well before ref, at most every
// corrSweepEvery. Callers hold s.mu.
func (s *corrState) sweepLocked(ref time.Time) {
	now := s.now()
	if now.Sub(s.lastSweep) < corrSweepEvery {
		return
	}
	s.lastSweep = now
	if ref.Before(s.maxSeen) {
		ref = s.maxSeen
	}
	expired := ref.Add(-s.def.c.Timespan - corrLateness)
	for key, g := range s.groups {
		if !g.latest.After(expired) {
			s.lru.Remove(g.elem)
			delete(s.groups, key)
		}
	}
}

// sweep is sweepLocked for callers without the lock; ref estimates the current event time.
func (s *corrState) sweep(ref time.Time) {
	s.mu.Lock()
	s.sweepLocked(ref)
	s.mu.Unlock()
}

// size returns the number of groups tracked.
func (s *corrState) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.groups)
}

// insertTime adds t to an ascending list.
func insertTime(l []time.Time, t time.Time) []time.Time {
	i := sort.Search(len(l), func(i int) bool { return l[i].After(t) })
	l = append(l, time.Time{})
	copy(l[i+1:], l[i:])
	l[i] = t
	return l
}

// pruneTimes drops times at or before cut, and keeps at most the newest keep. It reports
// whether times inside the window were dropped for the cap.
func pruneTimes(l []time.Time, cut time.Time, keep int) ([]time.Time, bool) {
	i := sort.Search(len(l), func(i int) bool { return l[i].After(cut) })
	capped := len(l)-i > keep
	if capped {
		i = len(l) - keep
	}
	if i == 0 {
		return l, false
	}
	return append(l[:0], l[i:]...), capped
}

// temporalCount counts the base rules that matched after cut.
func temporalCount(seen [][]time.Time, cut time.Time) int {
	n := 0
	for _, l := range seen {
		if len(l) > 0 && l[len(l)-1].After(cut) {
			n++
		}
	}
	return n
}

// inOrder reports whether every base rule matched, in order, by end. Lists hold only times
// inside the window. Going backwards and taking the latest possible time at each step
// leaves the most room for the steps before it.
func inOrder(seen [][]time.Time, end time.Time) bool {
	t := end
	for i := len(seen) - 1; i >= 0; i-- {
		l := seen[i]
		j := sort.Search(len(l), func(k int) bool { return l[k].After(t) }) - 1
		if j < 0 {
			return false
		}
		t = l[j]
	}
	return true
}

// summary describes a match for the alert.
func (d *corrDef) summary(m *CorrelationMatch) string {
	c := d.c
	span := formatSpan(c.Timespan)
	titles := quoteList(d.baseTitles)
	count := strconv.Itoa(m.Count)
	if m.AtLeast {
		count = "At least " + count
	}
	var s string
	switch {
	case c.Type == CorrEventCount && c.Aggregation:
		s = fmt.Sprintf("%s matching events within %s (threshold %s %d)", count, span, c.opSymbol(), c.Threshold)
	case c.Type == CorrEventCount:
		s = fmt.Sprintf("%s events matching %s within %s (threshold %s %d)", count, titles, span, c.opSymbol(), c.Threshold)
	case c.Type == CorrValueCount:
		s = fmt.Sprintf("%s distinct values of %s within %s (threshold %s %d)", count, c.Field, span, c.opSymbol(), c.Threshold)
		if !c.Aggregation {
			s += " in events matching " + titles
		}
	case c.Ordered:
		s = fmt.Sprintf("%s matched in that order within %s", strings.Join(quoteEach(d.baseTitles), ", then "), span)
	default:
		s = fmt.Sprintf("%d of %d rules matched within %s: %s", m.Count, len(d.groupFields), span, titles)
	}
	if label := m.GroupLabel(); label != "" {
		s += " for " + label
	}
	return s + "."
}

func quoteEach(titles []string) []string {
	out := make([]string, len(titles))
	for i, t := range titles {
		out[i] = strconv.Quote(t)
	}
	return out
}

func quoteList(titles []string) string {
	if len(titles) > 3 {
		return fmt.Sprintf("%d rules", len(titles))
	}
	return strings.Join(quoteEach(titles), " or ")
}
