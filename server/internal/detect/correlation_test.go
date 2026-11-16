package detect

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func authFail(ip, user string, at time.Duration) *event.Event {
	return &event.Event{
		Timestamp: t0.Add(at),
		Host:      event.Host{ID: "h1", Name: "tower", OS: &event.OS{Platform: "linux"}},
		Event: event.Meta{Category: []string{event.CategoryAuthentication}, Type: []string{event.TypeStart},
			Action: "ssh_login", Outcome: event.OutcomeFailure, Module: event.ModuleAuthLog},
		User:   &event.User{Name: user},
		Source: &event.Endpoint{IP: ip, Port: 50000},
	}
}

func authOK(ip, user string, at time.Duration) *event.Event {
	e := authFail(ip, user, at)
	e.Event.Outcome = event.OutcomeSuccess
	return e
}

func conn(host, exe, dst string, port int, at time.Duration) *event.Event {
	return &event.Event{
		Timestamp: t0.Add(at),
		Host:      event.Host{ID: host, Name: host, OS: &event.OS{Platform: "linux"}},
		Event: event.Meta{Category: []string{event.CategoryNetwork}, Type: []string{event.TypeConnection},
			Action: "connection_failed", Outcome: event.OutcomeFailure, Module: event.ModuleEBPF},
		Network:     &event.Network{Transport: "tcp", Direction: event.DirectionOutbound},
		Source:      &event.Endpoint{IP: "192.168.1.5", Port: 40000},
		Destination: &event.Endpoint{IP: dst, Port: port},
		Process:     &event.Process{Name: filepath.Base(exe), Executable: exe, PID: 42},
	}
}

const failedBase = `title: SSH failure
id: base-fail
name: ssh_fail
level: low
logsource: {category: authentication}
detection:
  sel: {event.action: ssh_login, event.outcome: failure}
  condition: sel
`

const okBase = `title: SSH success
id: base-ok
name: ssh_ok
level: high
logsource: {category: authentication}
detection:
  sel: {event.action: ssh_login, event.outcome: success}
  condition: sel
`

const connBase = `title: Outbound
id: base-conn
name: outbound
logsource: {category: network_connection}
detection:
  sel: {Initiated: 'true'}
  condition: sel
`

// engineFrom loads every rule document in srcs (each may hold several) into an engine.
func engineFrom(t *testing.T, srcs ...string) (*Engine, []*Rule) {
	t.Helper()
	var rules []*Rule
	for _, src := range srcs {
		docs, err := ParseDocuments([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range docs {
			if d.Err != nil {
				t.Fatalf("%s: %v", d.Title, d.Err)
			}
			rules = append(rules, d.Rule)
		}
	}
	if errs := ResolveCorrelations(rules); len(errs) > 0 {
		t.Fatalf("unresolved: %v", errs)
	}
	e := NewEngine()
	e.SetRules(rules)
	return e, rules
}

// run feeds events and returns the correlation matches and single-event hits.
func run(e *Engine, evs ...*event.Event) ([]CorrelationMatch, []*Rule) {
	var ms []CorrelationMatch
	var hits []*Rule
	for _, ev := range evs {
		r := e.Detect(ev)
		ms = append(ms, r.Correlations...)
		hits = append(hits, r.Rules...)
	}
	return ms, hits
}

func TestCorrelationEventCount(t *testing.T) {
	e, _ := engineFrom(t, failedBase, `
title: Brute force
id: corr-bf
correlation:
  type: event_count
  rules: [ssh_fail]
  group-by: [source.ip, User]
  timespan: 1m
  condition: {gte: 3}
level: high
`)
	// Two failures each for two addresses: under the threshold, and grouped apart.
	ms, hits := run(e,
		authFail("1.2.3.4", "root", 0), authFail("5.6.7.8", "root", time.Second),
		authFail("1.2.3.4", "root", 2*time.Second), authFail("5.6.7.8", "root", 3*time.Second),
		authFail("1.2.3.4", "admin", 4*time.Second), // another user: another group
	)
	if len(ms) != 0 {
		t.Fatalf("fired under the threshold: %+v", ms)
	}
	if len(hits) != 0 {
		t.Fatalf("the base rule alerted on its own: %v", hits)
	}
	ms, _ = run(e, authFail("1.2.3.4", "root", 5*time.Second))
	if len(ms) != 1 {
		t.Fatalf("matches = %+v", ms)
	}
	m := ms[0]
	if m.Rule.ID != "corr-bf" || m.Count != 3 || m.Level != "high" || m.Window != time.Minute ||
		m.GroupLabel() != "source.ip=1.2.3.4, User=root" || !m.First.Equal(t0) || !m.Last.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("match = %+v", m)
	}
	if !strings.Contains(m.Summary, "3 events") || !strings.Contains(m.Summary, "1m") || !strings.Contains(m.Summary, "source.ip=1.2.3.4") {
		t.Fatalf("summary = %q", m.Summary)
	}

	// While the condition stays true, no more alerts for the group.
	var evs []*event.Event
	for i := 6; i < 60; i++ {
		evs = append(evs, authFail("1.2.3.4", "root", time.Duration(i)*time.Second))
	}
	if ms, _ := run(e, evs...); len(ms) != 0 {
		t.Fatalf("repeated alerts while the condition held: %d", len(ms))
	}
	// The other group still fires on its own.
	if ms, _ := run(e, authFail("5.6.7.8", "root", 30*time.Second)); len(ms) != 1 || ms[0].GroupLabel() != "source.ip=5.6.7.8, User=root" {
		t.Fatalf("second group = %+v", ms)
	}
	// After the window has rolled over (a minute past the alert), a fresh burst alerts again,
	// counting only events after the first alert.
	ms, _ = run(e, authFail("1.2.3.4", "root", 65*time.Second), authFail("1.2.3.4", "root", 66*time.Second))
	if len(ms) != 1 || ms[0].Count != 3 || !ms[0].AtLeast || !strings.HasPrefix(ms[0].Summary, "At least 3 events") {
		t.Fatalf("after rollover = %+v", ms)
	}
	// A burst entirely after the last alert's window counts from scratch.
	run(e, authFail("1.2.3.4", "root", 10*time.Minute))
	ms, _ = run(e, authFail("1.2.3.4", "root", 10*time.Minute+time.Second), authFail("1.2.3.4", "root", 10*time.Minute+2*time.Second))
	if len(ms) != 1 || ms[0].Count != 3 || ms[0].AtLeast || !strings.HasPrefix(ms[0].Summary, "3 events") {
		t.Fatalf("new burst = %+v", ms)
	}
}

func TestCorrelationValueCount(t *testing.T) {
	e, _ := engineFrom(t, connBase, `
title: Port scan
id: corr-scan
correlation:
  type: value_count
  rules: [outbound]
  group-by: [host.id, destination.ip]
  timespan: 1m
  condition: {gt: 3, field: destination.port}
`)
	// The same port again and again is one value.
	var evs []*event.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, conn("h1", "/usr/bin/nmap", "10.0.0.9", 22, time.Duration(i)*time.Second))
	}
	evs = append(evs, conn("h1", "/usr/bin/nmap", "10.0.0.9", 80, 11*time.Second), conn("h1", "/usr/bin/nmap", "10.0.0.9", 443, 12*time.Second))
	// Other destinations are other groups.
	evs = append(evs, conn("h1", "/usr/bin/nmap", "10.0.0.8", 8080, 13*time.Second), conn("h1", "/usr/bin/nmap", "10.0.0.7", 8081, 14*time.Second))
	if ms, _ := run(e, evs...); len(ms) != 0 {
		t.Fatalf("fired at 3 distinct ports: %+v", ms)
	}
	ms, _ := run(e, conn("h1", "/usr/bin/nmap", "10.0.0.9", 3389, 15*time.Second))
	if len(ms) != 1 || ms[0].Count != 4 || ms[0].GroupLabel() != "host.id=h1, destination.ip=10.0.0.9" || ms[0].Level != "medium" {
		t.Fatalf("matches = %+v", ms)
	}
	if !strings.Contains(ms[0].Summary, "4 distinct values of destination.port") {
		t.Fatalf("summary = %q", ms[0].Summary)
	}
	// Values seen only before the window do not count.
	if ms, _ := run(e, conn("h2", "/x", "10.0.0.1", 1, 0), conn("h2", "/x", "10.0.0.1", 2, 0), conn("h2", "/x", "10.0.0.1", 3, 0),
		conn("h2", "/x", "10.0.0.1", 4, 2*time.Minute)); len(ms) != 0 {
		t.Fatalf("expired values counted: %+v", ms)
	}
}

func TestCorrelationTemporal(t *testing.T) {
	e, _ := engineFrom(t, failedBase, okBase, `
title: Failure then success
id: corr-temporal
correlation:
  type: temporal
  rules: [ssh_fail, base-ok]
  group-by: [source.ip]
  timespan: 5m
`)
	// A success alone, and the pair from different addresses, do not fire.
	if ms, _ := run(e, authOK("1.1.1.1", "root", 0), authFail("2.2.2.2", "root", time.Second)); len(ms) != 0 {
		t.Fatalf("matches = %+v", ms)
	}
	// Unordered: a success then a failure from one address fires.
	ms, _ := run(e, authFail("1.1.1.1", "root", 2*time.Minute))
	if len(ms) != 1 || ms[0].Count != 2 || ms[0].GroupLabel() != "source.ip=1.1.1.1" {
		t.Fatalf("matches = %+v", ms)
	}
	// The level defaults to the highest of the base rules.
	if ms[0].Level != "high" {
		t.Fatalf("level = %s", ms[0].Level)
	}
	// Too far apart: no match.
	if ms, _ := run(e, authOK("3.3.3.3", "root", 0), authFail("3.3.3.3", "root", 6*time.Minute)); len(ms) != 0 {
		t.Fatalf("outside the span: %+v", ms)
	}
}

func TestCorrelationTemporalOrdered(t *testing.T) {
	e, _ := engineFrom(t, failedBase, okBase, `
title: Brute force success
id: corr-ordered
correlation:
  type: temporal_ordered
  rules: [ssh_fail, ssh_ok]
  group-by: [source.ip]
  timespan: 5m
`)
	// Success before failure: wrong order.
	if ms, _ := run(e, authOK("1.1.1.1", "root", 0), authFail("1.1.1.1", "root", time.Minute)); len(ms) != 0 {
		t.Fatalf("fired out of order: %+v", ms)
	}
	// Then a success after the failure completes the sequence.
	ms, _ := run(e, authOK("1.1.1.1", "root", 2*time.Minute))
	if len(ms) != 1 || !strings.Contains(ms[0].Summary, `"SSH failure", then "SSH success"`) {
		t.Fatalf("matches = %+v", ms)
	}
	// A failure arriving late (out of order) but timestamped before an earlier success
	// still completes the sequence.
	if ms, _ := run(e, authOK("2.2.2.2", "root", 3*time.Minute), authFail("2.2.2.2", "root", 2*time.Minute)); len(ms) != 1 {
		t.Fatalf("late first step: %+v", ms)
	}
	// Steps further apart than the span do not make a sequence.
	if ms, _ := run(e, authFail("4.4.4.4", "root", 0), authOK("4.4.4.4", "root", 10*time.Minute)); len(ms) != 0 {
		t.Fatalf("steps 10m apart: %+v", ms)
	}
	// After an alert, the sequence must happen again after the window rolls over.
	if ms, _ := run(e, authOK("1.1.1.1", "root", 3*time.Minute)); len(ms) != 0 {
		t.Fatalf("repeat inside the window: %+v", ms)
	}
	if ms, _ := run(e, authOK("1.1.1.1", "root", 8*time.Minute)); len(ms) != 0 {
		t.Fatalf("a success alone after the window fired: %+v", ms)
	}
	if ms, _ := run(e, authFail("1.1.1.1", "root", 9*time.Minute), authOK("1.1.1.1", "root", 9*time.Minute+time.Second)); len(ms) != 1 {
		t.Fatalf("a new sequence after the window: %+v", ms)
	}
}

func TestCorrelationLegacyCount(t *testing.T) {
	e, _ := engineFrom(t, `
title: Legacy brute force
id: legacy-bf
level: critical
logsource: {category: authentication}
detection:
  sel: {event.action: ssh_login, event.outcome: failure}
  timeframe: 1m
  condition: sel | count() by SourceIp > 3
`, `
title: Legacy user spray
id: legacy-spray
logsource: {category: authentication}
detection:
  sel: {event.action: ssh_login, event.outcome: failure}
  timeframe: 10m
  condition: sel | count(User) by SourceIp >= 3
`)
	ms, hits := run(e, authFail("9.9.9.9", "root", 0), authFail("9.9.9.9", "root", time.Second), authFail("9.9.9.9", "root", 2*time.Second))
	if len(hits) != 0 {
		t.Fatalf("an aggregation rule fired on single events: %v", hits)
	}
	if len(ms) != 0 {
		t.Fatalf("fired at 3 events by one user: %+v", ms)
	}
	ms, _ = run(e, authFail("9.9.9.9", "admin", 3*time.Second))
	if len(ms) != 1 || ms[0].Rule.ID != "legacy-bf" || ms[0].Count != 4 || ms[0].Level != "critical" || ms[0].GroupLabel() != "SourceIp=9.9.9.9" {
		t.Fatalf("count() = %+v", ms)
	}
	ms, _ = run(e, authFail("9.9.9.9", "oracle", 4*time.Second))
	if len(ms) != 1 || ms[0].Rule.ID != "legacy-spray" || ms[0].Count != 3 {
		t.Fatalf("count(User) = %+v", ms)
	}
	// Without group-by, everything is one group.
	e2, _ := engineFrom(t, `
title: Any burst
id: legacy-any
logsource: {category: authentication}
detection:
  sel: {event.outcome: failure}
  timeframe: 30s
  condition: sel | count() >= 2
`)
	if ms, _ := run(e2, authFail("1.1.1.1", "a", 0), authFail("2.2.2.2", "b", time.Second)); len(ms) != 1 || ms[0].GroupLabel() != "" {
		t.Fatalf("ungrouped = %+v", ms)
	}
}

func TestCorrelationOutOfOrder(t *testing.T) {
	e, _ := engineFrom(t, failedBase, `
title: Burst
id: corr-ooo
correlation: {type: event_count, rules: [ssh_fail], group-by: [source.ip], timespan: 1m, condition: {gte: 3}}
`)
	// Arriving out of order but within a minute of each other: counted.
	ms, _ := run(e, authFail("1.1.1.1", "r", 30*time.Second), authFail("1.1.1.1", "r", 10*time.Second), authFail("1.1.1.1", "r", 20*time.Second))
	if len(ms) != 1 || ms[0].Count != 3 || !ms[0].First.Equal(t0.Add(10*time.Second)) || !ms[0].Last.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("matches = %+v", ms)
	}
	// An event older than the group's window cannot count.
	ms, _ = run(e, authFail("2.2.2.2", "r", 2*time.Minute), authFail("2.2.2.2", "r", 0), authFail("2.2.2.2", "r", 2*time.Minute+time.Second))
	if len(ms) != 0 {
		t.Fatalf("a too-old event counted: %+v", ms)
	}
}

func TestCorrelationGroupCap(t *testing.T) {
	e, _ := engineFrom(t, failedBase, `
title: Burst
id: corr-cap
correlation: {type: event_count, rules: [ssh_fail], group-by: [source.ip], timespan: 1h, condition: {gte: 2}}
`)
	st := e.plan.Load().states[0]
	st.maxGroups = 3
	// 1.0.0.1 gets one event first, then three newer groups push it out.
	run(e, authFail("1.0.0.1", "r", 0))
	for i := 2; i <= 4; i++ {
		run(e, authFail(fmt.Sprintf("1.0.0.%d", i), "r", time.Duration(i)*time.Second))
	}
	if n := st.size(); n != 3 {
		t.Fatalf("groups = %d, want 3", n)
	}
	// The evicted group starts again from nothing; a kept one still has its event.
	if ms, _ := run(e, authFail("1.0.0.1", "r", 5*time.Second)); len(ms) != 0 {
		t.Fatalf("an evicted group kept its count: %+v", ms)
	}
	if ms, _ := run(e, authFail("1.0.0.4", "r", 6*time.Second)); len(ms) != 1 {
		t.Fatalf("a kept group lost its count: %+v", ms)
	}
	// 1.0.0.2 was least recently updated, so it went when 1.0.0.1 came back.
	if ms, _ := run(e, authFail("1.0.0.2", "r", 7*time.Second)); len(ms) != 0 {
		t.Fatalf("the least recently updated group was not evicted: %+v", ms)
	}
	if n := st.size(); n != 3 {
		t.Fatalf("groups = %d, want 3", n)
	}

	// The periodic sweep drops groups whose window ended long ago.
	clock := time.Now()
	st.now = func() time.Time { return clock }
	clock = clock.Add(time.Hour)
	run(e, authFail("1.0.0.9", "r", 3*time.Hour))
	if n := st.size(); n != 1 {
		t.Fatalf("groups after sweep = %d, want 1", n)
	}
}

func TestCorrelationValueCap(t *testing.T) {
	e, _ := engineFrom(t, connBase, `
title: Scan
id: corr-vcap
correlation: {type: value_count, rules: [outbound], timespan: 1h, condition: {gte: 1000, field: destination.port}}
`)
	st := e.plan.Load().states[0]
	var ms []CorrelationMatch
	for p := 1; p <= 1500; p++ {
		m, _ := run(e, conn("h", "/x", "10.0.0.1", p, time.Duration(p)*time.Millisecond))
		ms = append(ms, m...)
	}
	st.mu.Lock()
	n := 0
	for _, g := range st.groups {
		n = len(g.vals)
	}
	st.mu.Unlock()
	if n > corrMaxPerGroup || len(ms) != 1 || ms[0].Count != 1000 {
		t.Fatalf("values kept = %d, matches = %d", n, len(ms))
	}
}

func TestCorrelationGenerate(t *testing.T) {
	corr := `
title: Burst
id: corr-gen
correlation: {type: event_count, rules: [ssh_fail], timespan: 1m, condition: {gte: 2}, generate: %v}
`
	for _, gen := range []bool{false, true} {
		e, _ := engineFrom(t, failedBase, fmt.Sprintf(corr, gen))
		_, hits := run(e, authFail("1.1.1.1", "r", 0))
		if (len(hits) == 1) != gen {
			t.Errorf("generate %v: base hits = %v", gen, hits)
		}
	}
	// A base rule that is disabled still feeds an enabled correlation, silently.
	docs, _ := ParseDocuments([]byte(failedBase + "---\n" + fmt.Sprintf(corr, false)))
	base, c := docs[0].Rule, docs[1].Rule
	e := NewEngine()
	e.SetRuleSet([]*Rule{c}, []*Rule{base, c})
	if ms, hits := run(e, authFail("1.1.1.1", "r", 0), authFail("1.1.1.1", "r", time.Second)); len(ms) != 1 || len(hits) != 0 {
		t.Fatalf("disabled base: matches %d, hits %v", len(ms), hits)
	}
	// A base rule whose correlation is disabled stays quiet.
	e.SetRuleSet([]*Rule{base}, []*Rule{base, c})
	if ms, hits := run(e, authFail("1.1.1.1", "r", 0)); len(ms) != 0 || len(hits) != 0 {
		t.Fatalf("disabled correlation: matches %d, hits %v", len(ms), hits)
	}
}

func TestCorrelationStateSurvivesReload(t *testing.T) {
	e, rules := engineFrom(t, failedBase, `
title: Burst
id: corr-reload
correlation: {type: event_count, rules: [ssh_fail], timespan: 1m, condition: {gte: 2}}
`)
	run(e, authFail("1.1.1.1", "r", 0))
	// The same rules parsed again (a reload) keep the window.
	_, again := engineFrom(t, failedBase, `
title: Burst
id: corr-reload
correlation: {type: event_count, rules: [ssh_fail], timespan: 1m, condition: {gte: 2}}
`)
	e.SetRules(again)
	if ms, _ := run(e, authFail("1.1.1.1", "r", time.Second)); len(ms) != 1 {
		t.Fatalf("state lost on reload: %+v", ms)
	}
	_ = rules
}

func TestCorrelationParseErrors(t *testing.T) {
	head := "title: x\nid: x\n"
	bad := map[string]string{
		"lt":                head + "correlation: {type: event_count, rules: [a], timespan: 1h, condition: {lt: 5}}\n",
		"lte":               head + "correlation: {type: event_count, rules: [a], timespan: 1h, condition: {lte: 5}}\n",
		"value_sum":         head + "correlation: {type: value_sum, rules: [a], timespan: 1h, condition: {gt: 5, field: x}}\n",
		"no field":          head + "correlation: {type: value_count, rules: [a], timespan: 1h, condition: {gt: 5}}\n",
		"no timespan":       head + "correlation: {type: event_count, rules: [a], condition: {gt: 5}}\n",
		"bad timespan":      head + "correlation: {type: event_count, rules: [a], timespan: 2M, condition: {gt: 5}}\n",
		"no condition":      head + "correlation: {type: event_count, rules: [a], timespan: 1h}\n",
		"no rules":          head + "correlation: {type: event_count, timespan: 1h, condition: {gt: 5}}\n",
		"too high":          head + "correlation: {type: event_count, rules: [a], timespan: 1h, condition: {gte: 5000}}\n",
		"two ops":           head + "correlation: {type: event_count, rules: [a], timespan: 1h, condition: {gte: 5, gt: 6}}\n",
		"temporal one rule": head + "correlation: {type: temporal, rules: [a], timespan: 1h}\n",
		"both":              head + "correlation: {type: event_count, rules: [a], timespan: 1h, condition: {gt: 5}}\ndetection: {sel: {a: 1}, condition: sel}\n",
		"agg no timeframe":  head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  condition: sel | count() > 5\n",
		"timeframe no agg":  head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  timeframe: 5m\n  condition: sel\n",
		"agg less than":     head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  timeframe: 5m\n  condition: sel | count() < 5\n",
		"agg avg":           head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  timeframe: 5m\n  condition: sel | avg(x) > 5\n",
		"agg near":          head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  timeframe: 5m\n  condition: sel | near other\n",
		"agg two conds":     head + "logsource: {}\ndetection:\n  sel: {a: 1}\n  timeframe: 5m\n  condition: [sel | count() > 5, sel]\n",
	}
	for name, src := range bad {
		_, err := ParseRule([]byte(src))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		t.Logf("%s: %v", name, err)
	}
	if _, err := ParseRule([]byte(bad["lt"])); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("lt error = %v", err)
	}
}

func TestCorrelationUnresolved(t *testing.T) {
	docs, err := ParseDocuments([]byte(failedBase + `---
title: Missing base
id: corr-missing
correlation: {type: event_count, rules: [ssh_fail, nope], timespan: 1h, condition: {gte: 2}}
---
title: Chained
id: corr-chained
correlation: {type: event_count, rules: [corr-missing], timespan: 1h, condition: {gte: 2}}
---
title: Fine
id: corr-fine
correlation: {type: event_count, rules: [base-fail], timespan: 1h, condition: {gte: 2}}
`))
	if err != nil {
		t.Fatal(err)
	}
	var rules []*Rule
	for _, d := range docs {
		if d.Err != nil {
			t.Fatalf("%s: %v", d.Title, d.Err)
		}
		rules = append(rules, d.Rule)
	}
	errs := ResolveCorrelations(rules)
	if len(errs) != 2 || !strings.Contains(errs[rules[1]].Error(), `"nope" is not loaded`) || !strings.Contains(errs[rules[2]].Error(), "correlations of correlations") {
		t.Fatalf("errors = %v", errs)
	}
	// The engine skips them and runs the rest.
	e := NewEngine()
	e.SetRules(rules)
	if n := len(e.plan.Load().states); n != 1 {
		t.Fatalf("states = %d", n)
	}
	// Two loaded rules with one name: ambiguous.
	other := mustRule(t, strings.Replace(failedBase, "id: base-fail", "id: base-fail-2", 1))
	byName := mustRule(t, "title: y\nid: y\ncorrelation: {type: event_count, rules: [ssh_fail], timespan: 1h, condition: {gte: 2}}\n")
	if err := ResolveCorrelations([]*Rule{rules[0], other, byName})[byName]; err == nil || !strings.Contains(err.Error(), "reference it by id") {
		t.Fatalf("ambiguous = %v", err)
	}
}

func TestCorrelationConcurrent(t *testing.T) {
	e, _ := engineFrom(t, failedBase, `
title: Burst
id: corr-race
correlation: {type: event_count, rules: [ssh_fail], group-by: [source.ip], timespan: 1h, condition: {gte: 50}}
`)
	_, again := engineFrom(t, failedBase, `
title: Burst
id: corr-race
correlation: {type: event_count, rules: [ssh_fail], group-by: [source.ip], timespan: 1h, condition: {gte: 50}}
`)
	var mu sync.Mutex
	got := map[string]int{}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", w%4)
			for i := 0; i < 100; i++ {
				for _, m := range e.Detect(authFail(ip, "r", time.Duration(i)*time.Second)).Correlations {
					mu.Lock()
					got[m.GroupLabel()]++
					mu.Unlock()
				}
				if i == 50 && w == 0 {
					e.SetRules(again) // a reload in the middle keeps the state
				}
			}
		}(w)
	}
	wg.Wait()
	if len(got) != 4 {
		t.Fatalf("groups alerted = %v", got)
	}
	for g, n := range got {
		if n != 1 {
			t.Errorf("%s alerted %d times", g, n)
		}
	}
}

// The correlation rules HomeXDR ships fire on what they describe, and their base rules stay
// quiet on their own.
func TestShippedCorrelations(t *testing.T) {
	rules, errs := LoadDir(filepath.Join("..", "..", "..", "rules"))
	for _, e := range errs {
		t.Errorf("load %s: %v", e.Path, e.Err)
	}
	if unresolved := ResolveCorrelations(rules); len(unresolved) > 0 {
		t.Fatalf("unresolved: %v", unresolved)
	}
	e := NewEngine()
	e.SetRules(rules)
	ids := func(ms []CorrelationMatch) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.Rule.ID)
		}
		return out
	}

	var evs []*event.Event
	for i := 0; i < 19; i++ {
		evs = append(evs, authFail("192.168.1.66", fmt.Sprintf("user%d", i), time.Duration(i)*10*time.Second))
	}
	ms, hits := run(e, evs...)
	for _, h := range hits {
		if h.ID == "5833cd30-67cd-4c3a-a84a-e70f11aa53ac" {
			t.Fatal("the failed-login base rule alerted on its own")
		}
	}
	if len(ms) != 0 {
		t.Fatalf("19 failures fired: %v", ids(ms))
	}
	ms, _ = run(e, authFail("192.168.1.66", "x", 200*time.Second))
	if len(ms) != 1 || ms[0].Rule.ID != "120a93f9-201d-4db8-bdbe-e1a408d61beb" || ms[0].GroupLabel() != "source.ip=192.168.1.66" {
		t.Fatalf("20 failures = %v", ids(ms))
	}
	// Slow guessing (one a minute) does not.
	evs = nil
	for i := 0; i < 30; i++ {
		evs = append(evs, authFail("192.168.1.67", "root", time.Duration(i)*time.Minute))
	}
	if ms, _ := run(e, evs...); len(ms) != 0 {
		t.Fatalf("slow guessing fired: %v", ids(ms))
	}

	evs = nil
	for p := 1; p < 25; p++ {
		evs = append(evs, conn("h1", "/usr/bin/nmap", "192.168.1.1", p, time.Duration(p)*time.Second))
	}
	// Many addresses on one port (a peer-to-peer client) is not a port scan.
	for i := 1; i < 60; i++ {
		evs = append(evs, conn("h1", "/usr/bin/qbittorrent", fmt.Sprintf("81.2.3.%d", i), 6881, time.Duration(i)*time.Second))
	}
	ms, hits = run(e, evs...)
	for _, h := range hits {
		if h.ID == "bba4c407-37c0-4197-8ad0-fd4c7c10fab8" {
			t.Fatal("the outbound-connection base rule alerted on its own")
		}
	}
	if len(ms) != 0 {
		t.Fatalf("24 ports fired: %v", ids(ms))
	}
	ms, _ = run(e, conn("h1", "/usr/bin/nmap", "192.168.1.1", 3389, 30*time.Second))
	if len(ms) != 1 || ms[0].Rule.ID != "3a32324f-8693-41de-991d-d3fce4c5ff43" ||
		ms[0].GroupLabel() != "host.id=h1, process.executable=/usr/bin/nmap, destination.ip=192.168.1.1" {
		t.Fatalf("25 ports = %v", ids(ms))
	}
}
