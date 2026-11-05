package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Fixture rules. Their values are placeholders: the self-check tests the machinery, and real
// rules are the owner's to load.
func fixtureRule(id, logsource, detection string) string {
	return "title: Fixture " + id + "\nid: " + id + "\nlogsource:\n" + logsource + "\ndetection:\n" + detection + "\nlevel: low\n"
}

const (
	linuxProc = "  product: linux\n  category: process_creation"
	winProc   = "  product: windows\n  category: process_creation"
)

func selfCheckFixtures() map[string]string {
	return map[string]string{
		"a.yml": fixtureRule("10000000-0000-4000-8000-000000000001", linuxProc, "  selection:\n    Image|endswith: /sampletool\n  condition: selection"),
		"b.yml": fixtureRule("10000000-0000-4000-8000-000000000002", linuxProc, "  selection:\n    CommandLine|contains|all:\n      - one\n      - two\n  filter:\n    User: root\n  condition: selection and not filter"),
		"c.yml": fixtureRule("10000000-0000-4000-8000-000000000003", winProc, "  selection:\n    Image|endswith: \\sample.exe\n    IntegrityLevel: High\n  condition: selection"),
		"d.yml": fixtureRule("10000000-0000-4000-8000-000000000004", "  category: dns_query", "  selection:\n    QueryName|endswith: .example.invalid\n  condition: selection"),
	}
}

// TestSelfCheck is what CI runs: the machinery of the self-check on fixed rules. A change to
// the engine or the alert path that stops rules firing or alerts folding fails it.
func TestSelfCheck(t *testing.T) {
	c := healthCore(t, selfCheckFixtures())
	ctx := context.Background()
	alertsBefore, _, _ := c.State.ListAlerts(ctx, store.AlertFilter{})
	res := c.RunSelfCheck(ctx)
	if res.Rules != 4 || res.Fired != 4 || res.Rate != 100 || res.Failed != 0 {
		t.Fatalf("%+v", res)
	}
	if !res.Pipeline.Passed {
		t.Fatalf("pipeline: %+v", res.Pipeline)
	}
	if res.Previous != nil || res.Regression || res.Bad() {
		t.Fatalf("first run: %+v", res)
	}

	// Nothing real is touched.
	alerts, _, _ := c.State.ListAlerts(ctx, store.AlertFilter{})
	if len(alerts) != len(alertsBefore) {
		t.Fatalf("real alerts created: %+v", alerts)
	}
	if n, err := c.Events.Search(ctx, searchAll()); err != nil || n.Total != 0 {
		t.Fatalf("events written: %v %v", n, err)
	}
	if ents, _ := os.ReadDir(c.Cfg.DataDir); len(ents) == 0 {
		t.Fatal("data dir empty")
	} else {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "selfcheck-") {
				t.Fatalf("temporary folder left behind: %s", e.Name())
			}
		}
	}

	// The second run compares with the first.
	res2 := c.RunSelfCheck(ctx)
	if res2.Previous == nil || res2.Previous.Rate != 100 || res2.Regression {
		t.Fatalf("second run: %+v", res2)
	}
	if last := c.LastSelfCheck(ctx); last == nil || !last.At.Equal(res2.At) {
		t.Fatalf("not saved: %+v", last)
	}
}

func TestSelfCheckWithNoRulesStillTestsThePipeline(t *testing.T) {
	c := healthCore(t, nil)
	res := c.RunSelfCheck(context.Background())
	if res.Rules != 0 || !res.Pipeline.Passed {
		t.Fatalf("%+v", res)
	}
}

func TestSelfCheckReportsRegression(t *testing.T) {
	files := selfCheckFixtures()
	c := healthCore(t, files)
	ctx := context.Background()
	if res := c.RunSelfCheck(ctx); res.Rate != 100 {
		t.Fatalf("%+v", res)
	}
	// A rule that can never fire arrives, and the number drops.
	bad := fixtureRule("10000000-0000-4000-8000-000000000009", linuxProc, "  a:\n    Image: /a\n  condition: a and not a")
	if err := os.WriteFile(filepath.Join(c.Cfg.RulesDir, "z.yml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Rules.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	res := c.RunSelfCheck(ctx)
	if res.Rules != 5 || res.Fired != 4 || res.Failed != 1 {
		t.Fatalf("%+v", res)
	}
	if len(res.Failures) != 1 || res.Failures[0].RuleID != "10000000-0000-4000-8000-000000000009" || res.Failures[0].Reason == "" {
		t.Fatalf("%+v", res.Failures)
	}
	if !res.Regression || !res.Bad() || !strings.Contains(res.Reason, "fell") {
		t.Fatalf("%+v", res)
	}
}

func TestSelfCheckPipelineFailureIsReported(t *testing.T) {
	c := healthCore(t, nil)
	r, err := detect.ParseRule([]byte(selfCheckRule))
	if err != nil {
		t.Fatal(err)
	}
	// An event that does not match the rule can make no alert.
	got := c.selfCheckPipeline(context.Background(), r, &event.Event{Message: "nothing"})
	if got.Passed || !strings.Contains(got.Message, "made 0") {
		t.Fatalf("%+v", got)
	}
}

func TestSelfCheckFieldCoverage(t *testing.T) {
	c := healthCore(t, selfCheckFixtures())
	ctx := context.Background()
	now := time.Now().UTC()
	h := event.Host{ID: "tower", Name: "tower", OS: &event.OS{Platform: event.PlatformLinux}}
	var evs []*event.Event
	for i := range 3 {
		evs = append(evs, &event.Event{
			ID: event.NewID(), Timestamp: now.Add(time.Duration(-i) * time.Minute), Host: h,
			Event:   event.Meta{Kind: event.KindEvent, Module: "procfs", Dataset: "process.start", Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}},
			Process: &event.Process{Executable: "/usr/bin/x", CommandLine: "x"},
		})
	}
	if err := c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	cov := c.RunSelfCheck(ctx).Coverage
	if cov == nil || cov.Events != 3 || cov.Sources != 1 || cov.Rules != 4 {
		t.Fatalf("%+v", cov)
	}
	if cov.CanFire != 2 || cov.CannotFire != 2 {
		t.Fatalf("%+v", cov)
	}
	byLabel := map[string]CoverageGroup{}
	for _, g := range cov.Groups {
		byLabel[g.Logsource] = g
	}
	if g := byLabel["linux / process_creation"]; g.Rules != 2 || g.CanFire != 2 {
		t.Errorf("%+v", g)
	}
	if g := byLabel["windows / process_creation"]; g.Rules != 1 || g.NoEvents != 1 {
		t.Errorf("%+v", g)
	}
	if g := byLabel["dns_query"]; g.Rules != 1 || g.NoEvents != 1 {
		t.Errorf("%+v", g)
	}
	// Biggest gap first.
	if cov.Groups[0].Rules-cov.Groups[0].CanFire == 0 {
		t.Errorf("groups not sorted: %+v", cov.Groups)
	}
}

func TestSelfCheckFieldCoverageNamesMissingFields(t *testing.T) {
	files := map[string]string{"a.yml": fixtureRule("10000000-0000-4000-8000-000000000011", linuxProc, "  selection:\n    Image: /a\n    IntegrityLevel: High\n  condition: selection")}
	c := healthCore(t, files)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := c.Events.Insert(ctx, []*event.Event{{
		ID: event.NewID(), Timestamp: now, Host: event.Host{ID: "t", OS: &event.OS{Platform: event.PlatformLinux}},
		Event:   event.Meta{Kind: event.KindEvent, Module: "m", Dataset: "d", Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart}},
		Process: &event.Process{Executable: "/usr/bin/x"},
	}}); err != nil {
		t.Fatal(err)
	}
	cov := c.RunSelfCheck(ctx).Coverage
	if cov.CannotFire != 1 || len(cov.Missing) != 1 || cov.Missing[0].Field != "IntegrityLevel" || cov.Missing[0].Rules != 1 {
		t.Fatalf("%+v", cov)
	}
	if g := cov.Groups[0]; g.MissingField != 1 || len(g.Missing) != 1 {
		t.Fatalf("%+v", g)
	}
}

func TestSelfCheckBackgroundStart(t *testing.T) {
	c := healthCore(t, nil)
	if !c.Health.selfCheckRunning.CompareAndSwap(false, true) {
		t.Fatal("already running")
	}
	if c.Health.StartSelfCheck(c) {
		t.Fatal("a second run must not start")
	}
	c.Health.selfCheckRunning.Store(false)
}

func searchAll() events.SearchQuery { return events.SearchQuery{Limit: 1} }
