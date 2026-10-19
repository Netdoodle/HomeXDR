// Package pipeline is the path from sensors to the spool: it stamps events with IDs,
// timestamps, agent and host fields, drops events matching the central config's
// filters, and appends the rest to the disk spool.
package pipeline

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Sink receives encoded NDJSON lines; *spool.Spool implements it.
type Sink interface {
	Append(line []byte) error
}

// Pipeline implements platform.Emitter.
type Pipeline struct {
	agentID  string
	version  string
	hostname atomic.Value // string
	sink     Sink
	log      *slog.Logger
	filters  atomic.Pointer[Filters]

	accepted atomic.Uint64
	filtered atomic.Uint64
	failed   atomic.Uint64
	lastErr  atomic.Int64 // unix seconds of the last logged append error
}

// New returns a pipeline writing to sink.
func New(agentID, version, hostname string, sink Sink, log *slog.Logger) *Pipeline {
	p := &Pipeline{agentID: agentID, version: version, sink: sink, log: log}
	p.hostname.Store(hostname)
	p.filters.Store(&Filters{})
	return p
}

// SetHostname updates the host name stamped on events.
func (p *Pipeline) SetHostname(h string) { p.hostname.Store(h) }

// SetFilters replaces the active filters.
func (p *Pipeline) SetFilters(fs []api.EventFilter) {
	f, bad := Compile(fs)
	for _, b := range bad {
		p.log.Warn("ignoring invalid event filter", "field", b.Field, "op", b.Op)
	}
	p.filters.Store(f)
}

// Counters returns accepted, filtered and failed (spool write error) counts.
func (p *Pipeline) Counters() (accepted, filtered, failed uint64) {
	return p.accepted.Load(), p.filtered.Load(), p.failed.Load()
}

// Stamp fills producer fields the sensor left empty.
func (p *Pipeline) Stamp(e *event.Event) {
	if e.ID == "" {
		e.ID = event.NewID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	e.Agent.ID = p.agentID
	e.Agent.Version = p.version
	e.Agent.Type = event.AgentTypeEndpoint
	if h, _ := p.hostname.Load().(string); h != "" {
		if e.Host.Name == "" {
			e.Host.Name = h
		}
		if e.Host.Hostname == "" {
			e.Host.Hostname = h
		}
	}
	if e.Event.Kind == "" {
		e.Event.Kind = event.KindEvent
	}
}

// Emit stamps, filters and spools one event.
func (p *Pipeline) Emit(e *event.Event) {
	if e == nil {
		return
	}
	p.Stamp(e)
	line, err := json.Marshal(e)
	if err != nil {
		p.failed.Add(1)
		return
	}
	if f := p.filters.Load(); !f.Empty() && f.Drop(e, line) {
		p.filtered.Add(1)
		return
	}
	if err := p.sink.Append(line); err != nil {
		p.failed.Add(1)
		// Rate-limit the log line: a full disk would otherwise log per event.
		now := time.Now().Unix()
		if last := p.lastErr.Load(); now-last >= 60 && p.lastErr.CompareAndSwap(last, now) {
			p.log.Error("cannot spool event", "err", err)
		}
		return
	}
	p.accepted.Add(1)
}

// Filters is a compiled filter list.
type Filters struct {
	list []filter
}

type filter struct {
	category string
	path     []string
	op       string
	value    string
}

// Empty reports whether there are no filters.
func (f *Filters) Empty() bool { return f == nil || len(f.list) == 0 }

// Compile validates filters; invalid ones are returned separately and ignored.
func Compile(fs []api.EventFilter) (*Filters, []api.EventFilter) {
	out := &Filters{}
	var bad []api.EventFilter
	for _, f := range fs {
		op := strings.ToLower(strings.TrimSpace(f.Op))
		field := strings.TrimSpace(f.Field)
		switch op {
		case "equals", "prefix", "suffix", "contains":
		default:
			bad = append(bad, f)
			continue
		}
		if field == "" {
			bad = append(bad, f)
			continue
		}
		out.list = append(out.list, filter{
			category: strings.ToLower(strings.TrimSpace(f.Category)),
			path:     strings.Split(field, "."),
			op:       op,
			value:    strings.ToLower(f.Value),
		})
	}
	return out, bad
}

// Drop reports whether any filter matches. line is the event's JSON encoding.
func (f *Filters) Drop(e *event.Event, line []byte) bool {
	var doc map[string]any
	for _, flt := range f.list {
		if flt.category != "" && !hasCategory(e, flt.category) {
			continue
		}
		if doc == nil {
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.UseNumber()
			if dec.Decode(&doc) != nil {
				return false
			}
		}
		for _, v := range lookup(doc, flt.path) {
			if flt.match(strings.ToLower(v)) {
				return true
			}
		}
	}
	return false
}

func (flt filter) match(v string) bool {
	switch flt.op {
	case "equals":
		return v == flt.value
	case "prefix":
		return strings.HasPrefix(v, flt.value)
	case "suffix":
		return strings.HasSuffix(v, flt.value)
	case "contains":
		return strings.Contains(v, flt.value)
	}
	return false
}

func hasCategory(e *event.Event, c string) bool {
	for _, x := range e.Event.Category {
		if strings.EqualFold(x, c) {
			return true
		}
	}
	return false
}

// lookup resolves a dotted path in a decoded event. Map keys may themselves contain dots
// (data keys such as "fim.changed"), so the longest matching key wins at each level.
// Arrays fan out to all elements.
func lookup(v any, path []string) []string {
	if len(path) == 0 {
		return leaves(v)
	}
	switch t := v.(type) {
	case map[string]any:
		for i := len(path); i >= 1; i-- {
			if child, ok := t[strings.Join(path[:i], ".")]; ok {
				if r := lookup(child, path[i:]); len(r) > 0 {
					return r
				}
			}
		}
		// Case-insensitive fallback for data.* keys.
		for i := len(path); i >= 1; i-- {
			key := strings.Join(path[:i], ".")
			for k, child := range t {
				if strings.EqualFold(k, key) {
					if r := lookup(child, path[i:]); len(r) > 0 {
						return r
					}
				}
			}
		}
	case []any:
		var out []string
		for _, el := range t {
			out = append(out, lookup(el, path)...)
		}
		return out
	}
	return nil
}

func leaves(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case json.Number:
		return []string{t.String()}
	case bool:
		if t {
			return []string{"true"}
		}
		return []string{"false"}
	case []any:
		var out []string
		for _, el := range t {
			out = append(out, leaves(el)...)
		}
		return out
	}
	return nil
}
