package detect

import (
	"slices"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Coverage answers "could this rule fire on the data this install really has?". It holds a
// sample of real events. A rule can fire when some event passes its logsource filter and the
// fields of one way of matching it all occur in events that pass that filter.
type Coverage struct {
	docs   []*Doc
	groups map[LogSource]*Doc // union of the docs passing a logsource, nil Event when none
}

// NewCoverage returns an empty sample.
func NewCoverage() *Coverage { return &Coverage{groups: map[LogSource]*Doc{}} }

// Add adds a real event to the sample.
func (c *Coverage) Add(ev *event.Event) {
	c.docs = append(c.docs, NewDoc(ev))
	clear(c.groups)
}

// Size returns how many events are in the sample.
func (c *Coverage) Size() int { return len(c.docs) }

// RuleCoverage is the verdict for one rule.
type RuleCoverage struct {
	// SourceSeen: at least one sampled event passes the rule's logsource filter.
	SourceSeen bool
	// CanFire: SourceSeen, and the fields of some way of matching occur in those events.
	CanFire bool
	// Missing are the fields keeping it from firing, for the way of matching that comes closest.
	Missing []string
}

// union merges the docs passing a rule's logsource. Field values do not matter here.
func (c *Coverage) union(r *Rule) *Doc {
	if d, ok := c.groups[r.LogSource]; ok {
		return d
	}
	u := &Doc{flat: map[string][]string{}}
	for _, d := range c.docs {
		if r.logsource != nil && !r.logsource.match(d) {
			continue
		}
		if u.Event == nil {
			u.Event = d.Event
		}
		for k, v := range d.flat {
			if _, have := u.flat[k]; !have && nonEmpty(v) {
				u.flat[k] = v
			}
		}
	}
	c.groups[r.LogSource] = u
	return u
}

// Check reports whether the sampled events could make a rule fire.
func (c *Coverage) Check(r *Rule) RuleCoverage {
	u := c.union(r)
	if u.Event == nil {
		return RuleCoverage{}
	}
	out := RuleCoverage{SourceSeen: true}
	for _, a := range r.cond.alts(&synth{fieldsOnly: true}, true) {
		var missing []string
		for _, ct := range a {
			switch {
			case ct.absent:
			case ct.field == keywordKey:
				if len(u.Keywords()) == 0 && !slices.Contains(missing, "keywords") {
					missing = append(missing, "keywords")
				}
			default:
				if _, ok := u.Get(ct.field); !ok && !containsFoldStr(missing, ct.field) {
					missing = append(missing, ct.field)
				}
			}
		}
		if len(missing) == 0 {
			out.CanFire, out.Missing = true, nil
			return out
		}
		if out.Missing == nil || len(missing) < len(out.Missing) {
			out.Missing = missing
		}
	}
	return out
}

func containsFoldStr(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}
