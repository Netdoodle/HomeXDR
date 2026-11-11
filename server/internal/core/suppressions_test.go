package core

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const pluginCheck = "php /usr/local/emhttp/plugins/dynamix.plugin.manager/scripts/plugin check user.scripts.plg"

func wgetHit(host string) *event.Event {
	return &event.Event{
		ID:    event.NewID(),
		Host:  event.Host{ID: host, Name: "tower"},
		Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}},
		Process: &event.Process{
			EntityID: event.NewID(), Name: "wget", Executable: "/usr/bin/wget",
			CommandLine: "wget -O /tmp/plugins/user.scripts.plg https://example.test/x",
			Parent: &event.Process{EntityID: event.NewID(), Name: "php", Executable: "/usr/bin/php",
				CommandLine: pluginCheck},
		},
	}
}

func wgetInput(ruleID, severity, host string) store.AlertInput {
	return store.AlertInput{
		Rule:     store.AlertRule{ID: ruleID, Title: "Wget to tmp", Level: severity},
		Severity: severity,
		Event:    wgetHit(host),
	}
}

func pluginSpec(reason string) SuppressionSpec {
	return SuppressionSpec{RuleID: "r-wget", Reason: reason, Conditions: []store.SuppressionCondition{
		{Field: "process.executable", Op: "equals", Value: "/usr/bin/wget"},
		{Field: "process.parent.command_line", Op: "contains", Value: "plugin check user.scripts.plg"},
	}}
}

func TestSuppressionValidation(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	cond := []store.SuppressionCondition{{Field: "process.name", Op: "equals", Value: "wget"}}
	bad := map[string]SuppressionSpec{
		"no scope":          {Reason: "x"},
		"host only":         {HostID: "h1", Reason: "x"},
		"broad, no confirm": {RuleID: "r1", Reason: "x"},
		"no reason":         {RuleID: "r1", HostID: "h1"},
		"blank reason":      {RuleID: "r1", HostID: "h1", Reason: "  "},
		"blank value":       {Reason: "x", Conditions: []store.SuppressionCondition{{Field: "process.name", Op: "contains", Value: " "}}},
		"bad op":            {Reason: "x", Conditions: []store.SuppressionCondition{{Field: "process.name", Op: "regex", Value: "x"}}},
		"bad field":         {Reason: "x", Conditions: []store.SuppressionCondition{{Field: "a b", Op: "equals", Value: "x"}}},
		"past expiry":       {RuleID: "r1", HostID: "h1", Reason: "x", ExpiresAt: &past},
		"both expiries":     {RuleID: "r1", HostID: "h1", Reason: "x", ExpiresAt: &future, NeverExpires: true},
	}
	for name, spec := range bad {
		var ve *ValidationError
		if _, err := spec.build("a", now); !errors.As(err, &ve) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}

	good := map[string]SuppressionSpec{
		"rule and host":     {RuleID: "r1", HostID: "h1", Reason: "x"},
		"condition only":    {Reason: "x", Conditions: cond},
		"broad, confirmed":  {RuleID: "r1", Reason: "x", ConfirmBroad: true},
		"host and contains": {HostID: "h1", Reason: "x", Conditions: cond},
	}
	for name, spec := range good {
		if _, err := spec.build("a", now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	sp, err := SuppressionSpec{RuleID: "r1", HostID: "h1", Reason: " x "}.build("alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if sp.ExpiresAt == nil || sp.ExpiresAt.Sub(now) != 90*24*time.Hour || sp.Reason != "x" || sp.CreatedBy != "alice" || !sp.Enabled {
		t.Fatalf("defaults: %+v", sp)
	}
	sp, err = SuppressionSpec{RuleID: "r1", HostID: "h1", Reason: "x", NeverExpires: true}.build("a", now)
	if err != nil || sp.ExpiresAt != nil {
		t.Fatalf("never expires: %+v, %v", sp, err)
	}
}

func TestSuppressionMatching(t *testing.T) {
	h := &hitView{ruleID: "r1", hostID: "h1", ev: wgetHit("h1")}
	cases := []struct {
		name string
		sp   store.Suppression
		want bool
	}{
		{"rule", store.Suppression{RuleID: "r1"}, true},
		{"other rule", store.Suppression{RuleID: "r2"}, false},
		{"host", store.Suppression{RuleID: "r1", HostID: "h1"}, true},
		{"other host", store.Suppression{RuleID: "r1", HostID: "h2"}, false},
	}
	cond := func(field, op, value string) store.Suppression {
		return store.Suppression{Conditions: []store.SuppressionCondition{{Field: field, Op: op, Value: value}}}
	}
	for _, c := range []struct {
		name             string
		field, op, value string
		want             bool
	}{
		{"equals", "process.executable", "equals", "/usr/bin/wget", true},
		{"equals is whole", "process.executable", "equals", "/usr/bin/wge", false},
		{"sigma name", "Image", "equals", "/usr/bin/wget", true},
		{"contains", "process.parent.command_line", "contains", "plugin check", true},
		{"contains nothing", "process.parent.command_line", "contains", "plugin remove", false},
		{"startswith", "process.command_line", "startswith", "wget -O", true},
		{"startswith wrong", "process.command_line", "startswith", "-O", false},
		{"endswith", "process.parent.executable", "endswith", "/php", true},
		{"endswith wrong", "process.parent.executable", "endswith", "/bash", false},
		{"case counts", "process.executable", "equals", "/usr/bin/WGET", false},
		{"missing field", "process.parent.parent.executable", "contains", "x", false},
	} {
		cases = append(cases, struct {
			name string
			sp   store.Suppression
			want bool
		}{c.name, cond(c.field, c.op, c.value), c.want})
	}
	all := store.Suppression{Conditions: []store.SuppressionCondition{
		{Field: "process.name", Op: "equals", Value: "wget"},
		{Field: "process.parent.name", Op: "equals", Value: "bash"},
	}}
	cases = append(cases, struct {
		name string
		sp   store.Suppression
		want bool
	}{"every condition must hold", all, false})
	for _, c := range cases {
		if got := h.matches(&c.sp); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	// Container fields from the agent can scope a suppression to an image.
	inCtr := wgetHit("h1")
	inCtr.Container = &event.Container{ID: "3f9c", Name: "binhex-sonarr", Runtime: "docker",
		Image: &event.ContainerImage{Name: "binhex/arch-sonarr", Tag: "latest"}}
	ctrHit := &hitView{ruleID: "r1", hostID: "h1", ev: inCtr}
	for _, c := range []struct {
		field, op, value string
		inCtr, onHost    bool
	}{
		{"container.image.name", "startswith", "binhex/", true, false},
		{"container.name", "equals", "binhex-sonarr", true, false},
		{"container.image.name", "equals", "binhex/arch-radarr", false, false},
	} {
		sp := cond(c.field, c.op, c.value)
		if got := ctrHit.matches(&sp); got != c.inCtr {
			t.Errorf("%s %s %s in a container: got %v", c.field, c.op, c.value, got)
		}
		if got := h.matches(&sp); got != c.onHost {
			t.Errorf("%s %s %s on the host: got %v", c.field, c.op, c.value, got)
		}
	}

	// An event with no process has nothing for a condition to match.
	noProc := &hitView{ruleID: "r1", hostID: "h1", ev: &event.Event{Host: event.Host{ID: "h1"}}}
	sp := cond("process.executable", "contains", "wget")
	if noProc.matches(&sp) {
		t.Error("a condition matched an event with no process")
	}
}

func createSuppression(t *testing.T, c *Core, spec SuppressionSpec) *SuppressionResult {
	t.Helper()
	res, err := c.CreateSuppression(context.Background(), spec, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSuppressedHitsOnArrival(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	sp := createSuppression(t, c, pluginSpec("Unraid plugin check")).Suppression

	in := wgetInput("r-wget", store.SevMedium, "h1")
	c.recordAlert(ctx, in)
	in.Event = wgetHit("h1")
	c.recordAlert(ctx, in)

	// One row for the shape, folded, status suppressed, and no AI investigation.
	list, total, err := c.State.ListAlerts(ctx, store.AlertFilter{Statuses: []string{store.AlertSuppressed}})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || list[0].Count != 2 || list[0].Status != store.AlertSuppressed {
		t.Fatalf("suppressed alerts: %d %+v", total, list)
	}
	if list[0].Suppression == nil || list[0].Suppression.ID != sp.ID || list[0].Suppression.Overridden {
		t.Fatalf("alert link to suppression: %+v", list[0].Suppression)
	}
	if _, err := c.State.GetTriage(ctx, list[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a suppressed alert reached the AI analyst: %v", err)
	}

	// Counters.
	got, err := c.State.GetSuppression(ctx, sp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 2 || got.LastHitAt == nil || got.OverrideCount != 0 {
		t.Fatalf("counters: %+v", got)
	}

	// Hidden by default.
	if _, total, _ := c.State.ListAlerts(ctx, store.AlertFilter{}); total != 0 {
		t.Fatalf("suppressed alert shown by default: %d", total)
	}
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 0 {
		t.Fatalf("suppressed alert counted as open: %d", open)
	}
	since := time.Now().Add(-time.Hour)
	if top, _ := c.State.TopRules(ctx, since, 10); len(top) != 0 {
		t.Fatalf("suppressed alert in top rules: %+v", top)
	}
	if top, _ := c.State.TopHosts(ctx, since, 10); len(top) != 0 {
		t.Fatalf("suppressed alert in top hosts: %+v", top)
	}
	if tl, _ := c.State.AlertTimeline(ctx, since); len(tl) != 0 {
		t.Fatalf("suppressed alert in the timeline: %+v", tl)
	}

	// A hit outside the suppression is untouched.
	other := wgetInput("r-wget", store.SevMedium, "h1")
	other.Event.Process.Parent.CommandLine = "bash -i"
	other.Event.Process.Parent.Executable = "/bin/bash"
	c.recordAlert(ctx, other)
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 1 {
		t.Fatalf("a shell's wget was suppressed: open=%d", open)
	}

	// Disabled: hits alert again straight away (API writes refresh the cache).
	off := false
	if _, err := c.UpdateSuppression(ctx, sp.ID, SuppressionPatch{Enabled: &off}, "alice"); err != nil {
		t.Fatal(err)
	}
	in.Event = wgetHit("h1")
	c.recordAlert(ctx, in)
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 2 {
		t.Fatalf("a disabled suppression still applied: open=%d", open)
	}
}

func TestSuppressedRowsStayBounded(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	createSuppression(t, c, pluginSpec("job"))
	in := wgetInput("r-wget", store.SevMedium, "h1")
	in.Event.Timestamp = time.Now().UTC().Add(-25 * time.Hour)
	c.recordAlert(ctx, in)
	// A day later the old row has aged out, and the shape gets a new one.
	for range 3 {
		in.Event = wgetHit("h1")
		c.recordAlert(ctx, in)
	}
	list, total, err := c.State.ListAlerts(ctx, store.AlertFilter{Statuses: []string{store.AlertSuppressed}})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("rows for one shape over two days: %d %+v", total, list)
	}
}

func TestExpiredSuppressionStopsMatching(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	res := createSuppression(t, c, pluginSpec("job"))
	// Expire it behind the API's back, as time passing would.
	past := time.Now().Add(-time.Minute)
	res.Suppression.ExpiresAt = &past
	if err := c.State.UpdateSuppression(ctx, res.Suppression); err != nil {
		t.Fatal(err)
	}
	c.Suppress.Invalidate()
	c.recordAlert(ctx, wgetInput("r-wget", store.SevMedium, "h1"))
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 1 {
		t.Fatalf("an expired suppression applied: open=%d", open)
	}
}

func TestMustAlertOverridesSuppression(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	sp := createSuppression(t, c, pluginSpec("job")).Suppression

	check := func(severity, host, wantWhy string) *store.Alert {
		t.Helper()
		before, _, _ := c.State.OpenAlertCounts(ctx)
		in := wgetInput("r-wget", severity, host)
		c.recordAlert(ctx, in)
		list, _, err := c.State.ListAlerts(ctx, store.AlertFilter{Statuses: []string{store.AlertNew}, Severities: []string{severity}})
		if err != nil || len(list) == 0 {
			t.Fatalf("%s hit was not kept as an alert (%v), open before %d", severity, err, before)
		}
		a := list[0]
		if a.Suppression == nil || !a.Suppression.Overridden || a.Suppression.ID != sp.ID || !strings.Contains(a.Suppression.Why, wantWhy) {
			t.Fatalf("override shown on the alert: %+v", a.Suppression)
		}
		return a
	}
	check(store.SevCritical, "h1", "critical")

	// The rule goes on the must-alert list: its high hit is kept too.
	if _, err := c.SaveNoiseSettings(ctx, NoiseSettings{MustAlertRules: []string{" r-wget ", "r-wget", ""}}, "alice"); err != nil {
		t.Fatal(err)
	}
	if n, _ := LoadNoiseSettings(ctx, c.State); len(n.MustAlertRules) != 1 || n.MustAlertRules[0] != "r-wget" {
		t.Fatalf("settings not cleaned up: %+v", n)
	}
	check(store.SevMedium, "h2", "must-alert")

	got, err := c.State.GetSuppression(ctx, sp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OverrideCount != 2 || got.LastOverrideAt == nil || got.HitCount != 0 {
		t.Fatalf("override counters: %+v", got)
	}
	entries, _, err := c.State.ListAudit(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	overrides := 0
	for _, e := range entries {
		if e.Action == "suppression.override" && e.Target == sp.ID {
			overrides++
		}
	}
	if overrides != 2 {
		t.Fatalf("audit entries for overrides: %d", overrides)
	}
}

func TestSuppressionCachePicksUpOtherProcess(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	in := wgetInput("r-wget", store.SevMedium, "h1")
	if c.Suppress.Check(ctx, in) != nil {
		t.Fatal("nothing should match yet")
	}
	// Another process writes directly to the database: not seen until the cache ages.
	if err := c.State.CreateSuppression(ctx, &store.Suppression{RuleID: "r-wget", HostID: "h1", Reason: "other process", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c.Suppress.Check(ctx, in) != nil {
		t.Fatal("the cache should still be fresh")
	}
	c.Suppress.mu.Lock()
	c.Suppress.loaded = time.Now().Add(-suppressionCacheTTL - time.Second)
	c.Suppress.mu.Unlock()
	if c.Suppress.Check(ctx, in) == nil {
		t.Fatal("the write was not picked up after the cache aged")
	}
}

func TestPreviewAndApply(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	// Three alerts of the shape by old keys, one critical, one of another shape.
	var ids []string
	for i := range 3 {
		in := wgetInput("r-wget", store.SevMedium, "h1")
		in.DedupEntity = "old-" + string(rune('a'+i)) // what per-process keys looked like
		a, _, err := c.State.RecordAlert(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
	}
	crit := wgetInput("r-wget", store.SevCritical, "h1")
	critical, _, err := c.State.RecordAlert(ctx, crit)
	if err != nil {
		t.Fatal(err)
	}
	other := wgetInput("r-wget", store.SevMedium, "h1")
	other.Event.Process.Parent.CommandLine = "bash -i"
	other.Event.Process.Parent.Executable = "/bin/bash"
	otherAlert, _, err := c.State.RecordAlert(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.State.QueueTriage(ctx, ids[0], "auto", "", store.EngineAPI); err != nil {
		t.Fatal(err)
	}

	p, err := c.PreviewSuppression(ctx, pluginSpec(""))
	if err != nil {
		t.Fatal(err)
	}
	if p.Matches != 3 || p.Kept != 1 || len(p.Sample) != 3 || p.Hits != 3 {
		t.Fatalf("preview: %+v", p)
	}
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 5 {
		t.Fatalf("a preview changed something: open=%d", open)
	}
	if _, err := c.PreviewSuppression(ctx, SuppressionSpec{}); err == nil {
		t.Fatal("preview without a scope accepted")
	}

	spec := pluginSpec("Unraid plugin check")
	spec.Apply = true
	res := createSuppression(t, c, spec)
	if res.Closed != 3 || res.Kept != 1 {
		t.Fatalf("apply: %+v", res)
	}
	a, err := c.State.GetAlert(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != store.AlertSuppressed || len(a.Notes) != 1 || !strings.Contains(a.Notes[0].Text, "Unraid plugin check") || a.Notes[0].Author != "alice" {
		t.Fatalf("closed alert: %+v", a)
	}
	if a.Suppression == nil || a.Suppression.ID != res.Suppression.ID {
		t.Fatalf("closed alert not linked: %+v", a.Suppression)
	}
	if tr, _ := c.State.GetTriage(ctx, ids[0]); tr.Status != store.TriageSkipped {
		t.Fatalf("waiting investigation of a closed alert: %+v", tr)
	}
	for _, id := range []string{critical.ID, otherAlert.ID} {
		if a, _ := c.State.GetAlert(ctx, id); a.Status != store.AlertNew {
			t.Fatalf("alert %s was closed: %+v", id, a.Status)
		}
	}
	// A new hit of the shape folds into a closed row rather than adding one.
	c.recordAlert(ctx, wgetInput("r-wget", store.SevMedium, "h1"))
	if _, total, _ := c.State.ListAlerts(ctx, store.AlertFilter{Statuses: []string{store.AlertSuppressed}}); total != 4 {
		t.Fatalf("suppressed rows: %d", total)
	}
}

func TestApplySuppressionSpecs(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	for i := range 4 {
		in := wgetInput("r-wget", store.SevMedium, "h1")
		in.DedupEntity = "old-" + string(rune('a'+i))
		if _, _, err := c.State.RecordAlert(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	specs, err := ParseSuppressionFile([]byte(`{"suppressions": [
		{"rule_id": "r-wget", "reason": "plugin check", "conditions": [
			{"field": "process.executable", "op": "equals", "value": "/usr/bin/wget"},
			{"field": "process.parent.command_line", "op": "contains", "value": "plugin check"}]},
		{"reason": "same alerts, another way", "conditions": [
			{"field": "process.parent.executable", "op": "equals", "value": "/usr/bin/php"}]}
	]}`))
	if err != nil || len(specs) != 2 {
		t.Fatalf("parse: %v %v", specs, err)
	}

	// A dry run counts and changes nothing.
	res, err := ApplySuppressionSpecs(ctx, c.State, specs, "cli", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Matches != 4 || res.Closed != 0 || res.Entries[0].Matches != 4 || res.Entries[1].Matches != 4 {
		t.Fatalf("dry run: %+v", res)
	}
	if list, _ := c.State.ListSuppressions(ctx); len(list) != 0 {
		t.Fatalf("a dry run created suppressions: %+v", list)
	}
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 4 {
		t.Fatalf("a dry run closed alerts: %d", open)
	}

	// A real run.
	res, err = ApplySuppressionSpecs(ctx, c.State, specs, "cli", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Closed != 4 {
		t.Fatalf("run: %+v", res)
	}
	list, _ := c.State.ListSuppressions(ctx)
	if len(list) != 2 || list[0].CreatedBy != "cli" || list[0].ExpiresAt == nil {
		t.Fatalf("created: %+v", list)
	}
	if open, _, _ := c.State.OpenAlertCounts(ctx); open != 0 {
		t.Fatalf("still open: %d", open)
	}
	entries, _, _ := c.State.ListAudit(ctx, 100, 0)
	if len(entries) < 4 {
		t.Fatalf("audit: %+v", entries)
	}

	// Running it again creates nothing new.
	res, err = ApplySuppressionSpecs(ctx, c.State, specs, "cli", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Closed != 0 || !res.Entries[0].Existing {
		t.Fatalf("second run: %+v", res)
	}
	if list, _ := c.State.ListSuppressions(ctx); len(list) != 2 {
		t.Fatalf("second run added suppressions: %d", len(list))
	}

	// One bad entry stops the whole file before anything changes.
	bad := append([]SuppressionSpec{{RuleID: "r2", HostID: "h1", Reason: "fine"}}, SuppressionSpec{RuleID: "r3"})
	if _, err := ApplySuppressionSpecs(ctx, c.State, bad, "cli", false); err == nil {
		t.Fatal("a bad entry was accepted")
	}
	if list, _ := c.State.ListSuppressions(ctx); len(list) != 2 {
		t.Fatal("the good entry before a bad one was applied")
	}

	// The other accepted file shapes.
	if specs, err := ParseSuppressionFile([]byte(`[{"rule_id":"r1"},{"rule_id":"r2"}]`)); err != nil || len(specs) != 2 {
		t.Fatalf("list: %v %v", specs, err)
	}
	if specs, err := ParseSuppressionFile([]byte(`{"rule_id":"r1","confirm_broad":true}`)); err != nil || len(specs) != 1 || !specs[0].ConfirmBroad {
		t.Fatalf("single: %v %v", specs, err)
	}
	if _, err := ParseSuppressionFile([]byte(`nonsense`)); err == nil {
		t.Fatal("nonsense parsed")
	}
}

// The command opens state.db while the server is writing to it. Neither side may fail,
// and in particular the server must not lose hits.
func TestApplyWhileServerWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	server, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for i := range 600 {
		in := wgetInput("r-wget", store.SevMedium, "h1")
		in.DedupEntity = "old-" + event.NewID() + string(rune('a'+i%26))
		if _, _, err := server.RecordAlert(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	cli, err := store.Open(path) // what the command does
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const writes = 150
	var wg sync.WaitGroup
	wg.Add(1)
	errs := make(chan error, writes)
	go func() {
		defer wg.Done()
		for i := range writes {
			in := wgetInput("r-other", store.SevMedium, "h1")
			in.DedupEntity = string(rune('a' + i%26))
			if _, _, err := server.RecordAlert(ctx, in); err != nil {
				errs <- err
			}
		}
	}()
	res, err := ApplySuppressionSpecs(ctx, cli, []SuppressionSpec{pluginSpec("job")}, "cli", false)
	wg.Wait()
	close(errs)
	if err != nil {
		t.Fatalf("the command failed: %v", err)
	}
	for err := range errs {
		t.Errorf("the server failed to record a hit: %v", err)
	}
	if res.Closed != 600 {
		t.Fatalf("closed %d of 600", res.Closed)
	}
}
