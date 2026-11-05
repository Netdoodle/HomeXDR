package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// repeatAlert records a fresh alert with the same rule, host and process shape as the
// first, after closing the first so it does not fold.
func repeatAlert(t *testing.T, f *fixture, closeID, severity string) *store.Alert {
	t.Helper()
	ctx := context.Background()
	st := store.AlertResolved
	if _, err := f.st.UpdateAlert(ctx, closeID, &st, nil); err != nil {
		t.Fatal(err)
	}
	ev := *f.hit
	ev.ID = event.NewID()
	a, isNew, err := f.st.RecordAlert(ctx, store.AlertInput{
		Rule: f.alert.Rule, Severity: severity, Event: &ev,
	})
	if err != nil || !isNew {
		t.Fatalf("repeat alert: new=%v err=%v", isNew, err)
	}
	return a
}

// investigated runs the fixture's alert through a real (fake provider) investigation.
func investigated(t *testing.T, f *fixture, verdict string) *fakeProvider {
	t.Helper()
	p := &fakeProvider{verdict: verdict}
	f.useProvider(p)
	f.save(t, nil)
	f.svc.AlertCreated(context.Background(), f.alert)
	f.drain(t)
	return p
}

func TestBenignVerdictIsReused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	investigated(t, f, "benign")
	used := f.svc.AutoToday(ctx)

	next := repeatAlert(t, f, f.alert.ID, store.SevMedium)
	f.svc.AlertCreated(ctx, next)

	tr, err := f.st.GetTriage(ctx, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != store.TriageDone || tr.Verdict != "benign" || tr.Trigger != store.TriggerReused {
		t.Fatalf("reused triage: %+v", tr)
	}
	if tr.ReusedFromAlert != f.alert.ID || tr.ReusedFromAt == nil || tr.ToolCalls != 0 || len(tr.Transcript) != 0 {
		t.Fatalf("where it came from: %+v", tr)
	}
	var rep Report
	if err := json.Unmarshal(tr.Report, &rep); err != nil {
		t.Fatal(err)
	}
	date := time.Now().UTC().Format("2006-01-02")
	if !strings.Contains(rep.Summary, f.alert.ID) || !strings.Contains(rep.Summary, date) || !strings.Contains(rep.Summary, "did not look at this alert") {
		t.Fatalf("the report does not say where it came from: %q", rep.Summary)
	}
	if rep.Verdict != "benign" {
		t.Fatalf("report verdict: %+v", rep)
	}

	// No AI call, not counted against the limit.
	if got := f.svc.AutoToday(ctx); got != used {
		t.Fatalf("reuse counted against the limit: %d, was %d", got, used)
	}
	if n, _ := f.st.CountQueuedTriages(ctx, store.EngineAPI); n != 0 {
		t.Fatalf("queued: %d", n)
	}

	// A person can still ask for a fresh look.
	if _, err := f.svc.Request(ctx, next.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	f.drain(t)
	tr, _ = f.st.GetTriage(ctx, next.ID)
	if tr.Trigger != TriggerManual || tr.ReusedFromAlert != "" || tr.ReusedFromAt != nil {
		t.Fatalf("after re-investigating: %+v", tr)
	}
}

func TestReuseLimits(t *testing.T) {
	ctx := context.Background()

	for _, verdict := range []string{"suspicious", "malicious", "inconclusive"} {
		f := newFixture(t)
		investigated(t, f, verdict)
		next := repeatAlert(t, f, f.alert.ID, store.SevMedium)
		f.svc.AlertCreated(ctx, next)
		tr, err := f.st.GetTriage(ctx, next.ID)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Trigger != TriggerAuto {
			t.Errorf("%s verdict was reused: %+v", verdict, tr)
		}
	}

	t.Run("older than a week", func(t *testing.T) {
		f := newFixture(t)
		investigated(t, f, "benign")
		tr, _ := f.st.GetTriage(ctx, f.alert.ID)
		// A later cutoff than the verdict finds nothing.
		next := repeatAlert(t, f, f.alert.ID, store.SevMedium)
		if _, err := f.st.BenignTriageForRepeat(ctx, next.ID, tr.FinishedAt.Add(time.Second)); err == nil {
			t.Fatal("an out-of-date verdict was found")
		}
	})

	t.Run("not from a reuse", func(t *testing.T) {
		f := newFixture(t)
		investigated(t, f, "benign")
		second := repeatAlert(t, f, f.alert.ID, store.SevMedium)
		f.svc.AlertCreated(ctx, second)
		third := repeatAlert(t, f, second.ID, store.SevMedium)
		f.svc.AlertCreated(ctx, third)
		tr, err := f.st.GetTriage(ctx, third.ID)
		if err != nil {
			t.Fatal(err)
		}
		if tr.ReusedFromAlert != f.alert.ID {
			t.Fatalf("the third alert should cite the real investigation: %+v", tr)
		}
	})

	t.Run("not across another shape", func(t *testing.T) {
		f := newFixture(t)
		investigated(t, f, "benign")
		ev := *f.hit
		ev.ID = event.NewID()
		ev.Process = &event.Process{EntityID: "other", Name: "other", Executable: "/bin/other"}
		a, _, err := f.st.RecordAlert(ctx, store.AlertInput{Rule: f.alert.Rule, Severity: store.SevMedium, Event: &ev})
		if err != nil {
			t.Fatal(err)
		}
		f.svc.AlertCreated(ctx, a)
		if tr, _ := f.st.GetTriage(ctx, a.ID); tr.Trigger != TriggerAuto {
			t.Fatalf("reused across shapes: %+v", tr)
		}
	})

	t.Run("not for critical", func(t *testing.T) {
		f := newFixture(t)
		investigated(t, f, "benign")
		a := repeatAlert(t, f, f.alert.ID, store.SevCritical)
		f.svc.AlertCreated(ctx, a)
		if tr, _ := f.st.GetTriage(ctx, a.ID); tr.Trigger != TriggerAuto {
			t.Fatalf("critical alert got a reused verdict: %+v", tr)
		}
	})
}

func TestDailyLimitKeepsRoomForHighAlerts(t *testing.T) {
	for _, c := range []struct {
		severity string
		limit    int
		want     int
	}{
		{store.SevMedium, 50, 40},
		{store.SevLow, 50, 40},
		{store.SevInformational, 50, 40},
		{store.SevHigh, 50, 50},
		{store.SevCritical, 50, 50},
		{store.SevMedium, 1, 1},
		{store.SevMedium, 2, 1},
		{store.SevMedium, 5, 4},
	} {
		if got := dailyLimitFor(c.severity, c.limit); got != c.want {
			t.Errorf("dailyLimitFor(%s, %d) = %d, want %d", c.severity, c.limit, got, c.want)
		}
	}

	ctx := context.Background()
	f := newFixture(t)
	f.useProvider(&fakeProvider{verdict: "suspicious"})
	f.save(t, func(s *Settings) { s.DailyLimit = 5; s.MinSeverity = store.SevLow })
	record := func(i int, severity string) *store.Alert {
		t.Helper()
		ev := *f.hit
		ev.ID = event.NewID()
		a, _, err := f.st.RecordAlert(ctx, store.AlertInput{
			Rule:     store.AlertRule{ID: "flood-" + severity + string(rune('a'+i)), Title: "x", Level: severity},
			Severity: severity, Event: &ev,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.svc.AlertCreated(ctx, a)
		return a
	}
	// Medium alerts stop at 4 of 5.
	for i := range 4 {
		a := record(i, store.SevMedium)
		if tr, _ := f.st.GetTriage(ctx, a.ID); tr.Status != store.TriageQueued {
			t.Fatalf("medium %d: %+v", i, tr)
		}
	}
	over := record(5, store.SevMedium)
	tr, _ := f.st.GetTriage(ctx, over.ID)
	if tr.Status != store.TriageSkipped || !strings.Contains(tr.Error, "kept for high and critical") {
		t.Fatalf("fifth medium: %+v", tr)
	}
	// A high alert still gets the last one, and then the day is over for everyone.
	high := record(6, store.SevHigh)
	if tr, _ := f.st.GetTriage(ctx, high.ID); tr.Status != store.TriageQueued {
		t.Fatalf("high alert after the medium share: %+v", tr)
	}
	crit := record(7, store.SevCritical)
	tr, _ = f.st.GetTriage(ctx, crit.ID)
	if tr.Status != store.TriageSkipped || !strings.Contains(tr.Error, "daily limit of 5") {
		t.Fatalf("over the whole limit: %+v", tr)
	}
}
