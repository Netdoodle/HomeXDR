package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestAlertsForEntities(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	hit := func(rule, host, entity string, at time.Time, sup *AlertSuppression) *Alert {
		t.Helper()
		ev := &event.Event{ID: event.NewID(), Timestamp: at, Host: event.Host{ID: host, Name: host},
			Process: &event.Process{EntityID: entity, Name: entity}}
		a, _, err := s.RecordAlert(ctx, AlertInput{Rule: AlertRule{ID: rule, Title: rule}, Severity: SevHigh, Event: ev,
			Mitre: []Mitre{{Tactic: "Defense Evasion"}}, Suppression: sup})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	older := hit("r1", "h1", "e-a", now.Add(-time.Hour), nil)
	newer := hit("r2", "h1", "e-b", now.Add(-time.Minute), nil)
	resolved := hit("r3", "h1", "e-a", now.Add(-30*time.Minute), nil)
	st := AlertResolved
	if _, err := s.UpdateAlert(ctx, resolved.ID, &st, nil); err != nil {
		t.Fatal(err)
	}
	hit("r4", "h1", "e-a", now, &AlertSuppression{ID: "s1", Reason: "noise"}) // suppressed: left out
	hit("r5", "h2", "e-a", now, nil)                                          // other host
	hit("r6", "h1", "e-c", now, nil)                                          // other process

	got, err := s.AlertsForEntities(ctx, "h1", []string{"e-a", "e-b"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{newer.ID, resolved.ID, older.ID}
	if len(got) != len(want) {
		t.Fatalf("got %d alerts, want %d: %+v", len(got), len(want), got)
	}
	for i, a := range got {
		if a.ID != want[i] {
			t.Errorf("alert %d = %s (%s), want %s", i, a.ID, a.Rule.Title, want[i])
		}
	}
	if got[0].Mitre[0].Tactic != "Defense Evasion" {
		t.Errorf("mitre = %+v", got[0].Mitre)
	}
	if got, _ := s.AlertsForEntities(ctx, "h1", []string{"e-a", "e-b"}, 1); len(got) != 1 || got[0].ID != newer.ID {
		t.Errorf("limit 1 = %+v", got)
	}
	if got, err := s.AlertsForEntities(ctx, "h1", nil, 10); err != nil || got == nil || len(got) != 0 {
		t.Errorf("no entities = %v, %v", got, err)
	}
}
