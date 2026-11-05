package detect

// Synthesize builds an event that a rule should match, from the rule's own compiled
// selection. There is no attack content here: every value comes from the rule. Working out
// which values to set walks the condition tree, so "selection and not filter" sets the
// selection's fields and leaves the filter's out. Each attempt is then evaluated by the
// real matcher, so whatever this code gets wrong shows up as a failure rather than a pass.
//
// Rule fields go into event.Data, which Doc.Get falls back to for every field. That tests
// the rule's logic. Whether real events have those fields is the coverage check's job
// (coverage.go).

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	maxAlts     = 24  // ways to satisfy a rule tried when building an event
	maxFieldSet = 128 // distinct field sets kept when checking coverage
	maxSamples  = 4   // values of one field tried
	keywordKey  = "\x00keyword"
	sampleValue = "selfcheck"
)

// constraint is one requirement: a field has a value, or (absent) has none. A keyword
// constraint has field keywordKey.
type constraint struct {
	field  string
	value  string
	absent bool
}

// alt is one way to satisfy a condition: requirements that must all hold.
type alt []constraint

// synth walks a condition. In fields-only mode one value per field is enough and alternatives
// needing the same fields are merged, so large rules stay small.
type synth struct {
	fieldsOnly bool
}

func (s *synth) limit() int {
	if s.fieldsOnly {
		return maxFieldSet
	}
	return maxAlts
}

func altKey(a alt) string {
	parts := make([]string, 0, len(a))
	for _, c := range a {
		if !c.absent {
			parts = append(parts, strings.ToLower(c.field))
		}
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), "\x01")
}

func (s *synth) dedupe(in []alt) []alt {
	if !s.fieldsOnly {
		if len(in) > s.limit() {
			return in[:s.limit()]
		}
		return in
	}
	seen := map[string]bool{}
	out := in[:0:0]
	for _, a := range in {
		if k := altKey(a); !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	if len(out) > s.limit() {
		out = out[:s.limit()]
	}
	return out
}

// union: any one of these.
func (s *synth) union(lists ...[]alt) []alt {
	var out []alt
	for _, l := range lists {
		out = append(out, l...)
	}
	return s.dedupe(out)
}

// cross: one of each, for every combination up to the limit.
func (s *synth) cross(lists ...[]alt) []alt {
	out := []alt{nil}
	for _, l := range lists {
		var next []alt
		for _, a := range out {
			for _, b := range l {
				next = append(next, append(append(alt(nil), a...), b...))
			}
		}
		out = s.dedupe(next)
		if len(out) == 0 {
			return nil
		}
	}
	return out
}

func (a andCond) alts(s *synth, want bool) []alt {
	lists := make([][]alt, len(a))
	for i, c := range a {
		lists[i] = c.alts(s, want)
	}
	if want {
		return s.cross(lists...)
	}
	return s.union(lists...)
}

func (o orCond) alts(s *synth, want bool) []alt {
	lists := make([][]alt, len(o))
	for i, c := range o {
		lists[i] = c.alts(s, want)
	}
	if want {
		return s.union(lists...)
	}
	return s.cross(lists...)
}

func (n notCond) alts(s *synth, want bool) []alt    { return n.c.alts(s, !want) }
func (c searchCond) alts(s *synth, want bool) []alt { return c.m.alts(s, want) }

func (a allOf) alts(s *synth, want bool) []alt {
	lists := make([][]alt, len(a))
	for i, m := range a {
		lists[i] = m.alts(s, want)
	}
	if want {
		return s.cross(lists...)
	}
	return s.union(lists...)
}

func (a anyOf) alts(s *synth, want bool) []alt {
	lists := make([][]alt, len(a))
	for i, m := range a {
		lists[i] = m.alts(s, want)
	}
	if want {
		return s.union(lists...)
	}
	return s.cross(lists...)
}

func (f *fieldMatcher) alts(s *synth, want bool) []alt {
	if f.exists != nil {
		if *f.exists == want {
			return []alt{{{field: f.field, value: sampleValue}}}
		}
		return []alt{{{field: f.field, absent: true}}}
	}
	if !want {
		return []alt{{}} // leaving a field out never matches a value
	}
	if len(f.samples) == 0 {
		return nil
	}
	if f.matchAll || s.fieldsOnly {
		var a alt
		for _, v := range f.samples {
			a = append(a, constraint{field: f.field, value: v})
		}
		if s.fieldsOnly {
			a = a[:1]
		}
		return []alt{a}
	}
	var out []alt
	for i, v := range f.samples {
		if i == maxSamples {
			break
		}
		out = append(out, alt{{field: f.field, value: v}})
	}
	return out
}

func (f *fieldRefMatcher) alts(_ *synth, want bool) []alt {
	if !want {
		return []alt{{}}
	}
	a := alt{{field: f.field, value: sampleValue}}
	refs := f.refs
	if !f.matchAll {
		refs = refs[:1]
	}
	for _, r := range refs {
		a = append(a, constraint{field: r, value: sampleValue})
	}
	return []alt{a}
}

func (k *keywordMatcher) alts(s *synth, want bool) []alt {
	if !want {
		return []alt{{}}
	}
	if len(k.samples) == 0 {
		return nil
	}
	var out []alt
	for i, v := range k.samples {
		if i == maxSamples || (s.fieldsOnly && i == 1) {
			break
		}
		out = append(out, alt{{field: keywordKey, value: v}})
	}
	return out
}

// wildcardSample is a value a wildcard pattern accepts: * matches nothing, ? one character.
func wildcardSample(val string) string {
	var b strings.Builder
	for i := 0; i < len(val); i++ {
		c := val[i]
		switch {
		case c == '\\' && i+1 < len(val) && (val[i+1] == '*' || val[i+1] == '?' || val[i+1] == '\\'):
			i++
			b.WriteByte(val[i])
		case c == '*':
		case c == '?':
			b.WriteByte('x')
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return sampleValue // a field that is only * needs some value to be present
	}
	return b.String()
}

func numberSample(limit float64, op string) string {
	switch op {
	case "gt":
		limit++
	case "lt":
		limit--
	}
	return strconv.FormatFloat(limit, 'f', -1, 64)
}

// regexSample builds a string a regular expression should accept. It takes the shortest
// path through the expression; the caller's match decides whether that worked.
func regexSample(expr string) string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return ""
	}
	var b strings.Builder
	writeRegexSample(&b, re.Simplify())
	return b.String()
}

func writeRegexSample(b *strings.Builder, re *syntax.Regexp) {
	switch re.Op {
	case syntax.OpLiteral:
		b.WriteString(string(re.Rune))
	case syntax.OpCharClass:
		b.WriteRune(classSample(re.Rune))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte('x')
	case syntax.OpCapture, syntax.OpPlus:
		writeRegexSample(b, re.Sub[0])
	case syntax.OpRepeat:
		for range re.Min {
			writeRegexSample(b, re.Sub[0])
		}
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			writeRegexSample(b, sub)
		}
	case syntax.OpAlternate:
		writeRegexSample(b, re.Sub[0])
	}
}

// classSample picks a readable character from a character class's ranges.
func classSample(ranges []rune) rune {
	for _, want := range []rune{'x', 'a', '0', ' ', '/', '-', '.'} {
		for i := 0; i+1 < len(ranges); i += 2 {
			if ranges[i] <= want && want <= ranges[i+1] {
				return want
			}
		}
	}
	if len(ranges) > 0 {
		return ranges[0]
	}
	return 'x'
}

// logsource settings: what an event needs to pass a rule's logsource filter.
var categoryShape = map[string]func(e *event.Event){
	"process_creation":    shape(event.CategoryProcess, event.TypeStart),
	"process_termination": shape(event.CategoryProcess, event.TypeEnd),
	"network_connection":  shape(event.CategoryNetwork, event.TypeConnection),
	"firewall":            func(e *event.Event) { e.Observer = &event.Observer{Type: "firewall"} },
	"file_event":          shape(event.CategoryFile, event.TypeCreation),
	"file_change":         shape(event.CategoryFile, event.TypeChange),
	"file_rename": func(e *event.Event) {
		shape(event.CategoryFile, event.TypeChange)(e)
		e.File = &event.File{OldPath: sampleValue}
	},
	"file_delete":      shape(event.CategoryFile, event.TypeDeletion),
	"file_access":      shape(event.CategoryFile, event.TypeAccess),
	"registry_set":     shape(event.CategoryRegistry, event.TypeChange),
	"registry_add":     shape(event.CategoryRegistry, event.TypeCreation),
	"registry_delete":  shape(event.CategoryRegistry, event.TypeDeletion),
	"registry_event":   shape(event.CategoryRegistry, event.TypeChange),
	"dns_query":        func(e *event.Event) { e.DNS = &event.DNS{Question: event.DNSQuestion{Name: sampleValue}} },
	"dns":              func(e *event.Event) { e.DNS = &event.DNS{Question: event.DNSQuestion{Name: sampleValue}} },
	"image_load":       shape(event.CategoryLibrary, event.TypeStart),
	"driver_load":      shape(event.CategoryDriver, event.TypeStart),
	"ps_script":        func(e *event.Event) { e.Event.Code = "4104" },
	"ps_module":        func(e *event.Event) { e.Event.Code = "4103" },
	"ps_classic_start": func(e *event.Event) { e.Event.Code = "400" },
	"authentication":   shape(event.CategoryAuthentication, event.TypeStart),
}

func shape(category, typ string) func(e *event.Event) {
	return func(e *event.Event) {
		e.Event.Category = []string{category}
		e.Event.Type = []string{typ}
	}
}

// baseEvent is an empty event that passes the rule's logsource filter.
func baseEvent(ls LogSource) *event.Event {
	now := time.Now().UTC()
	e := &event.Event{ID: event.NewID(), Timestamp: now, Event: event.Meta{Kind: event.KindEvent}}
	switch p := strings.ToLower(strings.TrimSpace(ls.Product)); p {
	case "":
	case "windows", "linux":
		e.Host.OS = &event.OS{Platform: p}
	case "macos":
		e.Host.OS = &event.OS{Platform: event.PlatformDarwin}
	default:
		e.Event.Module = p
	}
	if c := strings.ToLower(strings.TrimSpace(ls.Category)); c != "" {
		if fn, ok := categoryShape[c]; ok {
			fn(e)
		} else {
			e.Event.Category = []string{c}
		}
	}
	if s := strings.ToLower(strings.TrimSpace(ls.Service)); s != "" {
		if p := serviceProviders[s]; len(p) > 0 {
			e.Event.Provider = p[0]
		} else {
			e.Event.Dataset = s
		}
	}
	return e
}

// buildSynthetic turns one alternative into an event, or nil when it contradicts itself.
func buildSynthetic(ls LogSource, a alt) *event.Event {
	e := baseEvent(ls)
	values := map[string][]string{}
	var keywords []string
	absent := map[string]bool{}
	for _, c := range a {
		key := strings.ToLower(c.field)
		switch {
		case c.field == keywordKey:
			keywords = append(keywords, c.value)
		case c.absent:
			absent[key] = true
		case !slices.Contains(values[key], c.value):
			values[key] = append(values[key], c.value)
		}
	}
	data := map[string]any{}
	for k, vs := range values {
		if absent[k] {
			return nil
		}
		if len(vs) == 1 {
			data[k] = vs[0]
			continue
		}
		list := make([]any, len(vs))
		for i, v := range vs {
			list[i] = v
		}
		data[k] = list
	}
	// These logsources need a real field set, and Doc.Get prefers it over event.Data.
	if e.DNS != nil {
		if vs := values["queryname"]; len(vs) > 0 {
			e.DNS.Question.Name = strings.Join(vs, " ")
		}
	}
	if e.File != nil && e.File.OldPath != "" {
		if vs := values["sourcefilename"]; len(vs) > 0 {
			e.File.OldPath = strings.Join(vs, " ")
		}
	}
	if len(data) > 0 {
		e.Data = data
	}
	e.Message = strings.Join(keywords, " ")
	return e
}

// Synthesize builds an event from the rule's own selection that the rule matches. An error
// means no such event could be built, which usually means the rule cannot fire at all.
func Synthesize(r *Rule) (*event.Event, error) {
	if r == nil || r.cond == nil {
		return nil, errors.New("the rule is not compiled")
	}
	s := &synth{}
	list := r.cond.alts(s, true)
	if len(list) == 0 {
		return nil, errors.New("its condition has no way to match")
	}
	tried := 0
	for _, a := range list {
		ev := buildSynthetic(r.LogSource, a)
		if ev == nil {
			continue
		}
		tried++
		if r.Match(NewDoc(ev)) {
			return ev, nil
		}
	}
	if tried == 0 {
		return nil, errors.New("its selection needs a field to be both set and absent")
	}
	return nil, fmt.Errorf("none of %d events built from its selection matched it", tried)
}
