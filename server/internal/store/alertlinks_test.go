package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestLinkedAlerts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	hit := func(rule, sev, link, src string) *Alert {
		t.Helper()
		ev := &event.Event{ID: event.NewID(), Timestamp: time.Now(), Host: event.Host{ID: "h1", Name: "desk"}}
		a, _, err := s.RecordAlert(ctx, AlertInput{Rule: AlertRule{ID: rule, Title: rule}, Severity: sev, Event: ev,
			DedupEntity: link, LinkKey: link, LinkSource: src})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	const fileA, fileB = `malware|h1|c:\users\a\evil.exe`, `malware|h1|c:\users\a\other.exe`
	first := hit("av:malware", SevCritical, fileA, "HomeXDR antivirus")
	d1 := hit("sigma-defender", SevHigh, fileA, "Microsoft Defender")
	d2 := hit("sigma-defender", SevHigh, fileA, "Microsoft Defender") // 1117 after 1116
	d3 := hit("sigma-defender-2", SevHigh, fileA, "Microsoft Defender")
	if d1.ID != first.ID || d2.ID != first.ID || d3.ID != first.ID {
		t.Fatalf("not folded: %s %s %s %s", first.ID, d1.ID, d2.ID, d3.ID)
	}
	a, _ := s.GetAlert(ctx, first.ID)
	if a.Count != 4 || len(a.Linked) != 2 || a.Linked[0].Count != 2 || a.Linked[0].Source != "Microsoft Defender" ||
		a.Severity != SevCritical || a.LinkKey != fileA {
		t.Fatalf("alert = count %d linked %+v sev %s", a.Count, a.Linked, a.Severity)
	}
	// Another file stays apart; Defender first then the antivirus raises the severity.
	other := hit("sigma-defender", SevHigh, fileB, "Microsoft Defender")
	if other.ID == first.ID {
		t.Fatal("different files folded together")
	}
	av := hit("av:malware", SevCritical, fileB, "HomeXDR antivirus")
	if av.ID != other.ID || av.Severity != SevCritical || av.RiskScore != RiskScore(SevCritical) {
		t.Fatalf("antivirus after Defender: %+v", av)
	}
	// A closed alert no longer absorbs.
	closed := AlertResolved
	if _, err := s.UpdateAlert(ctx, first.ID, &closed, nil); err != nil {
		t.Fatal(err)
	}
	if again := hit("sigma-defender", SevHigh, fileA, "Microsoft Defender"); again.ID == first.ID {
		t.Fatal("folded into a closed alert")
	}
	// No link key: no folding across rules.
	x := hit("rule-x", SevLow, "", "")
	y := hit("rule-y", SevLow, "", "")
	if x.ID == y.ID {
		t.Fatal("unlinked alerts folded")
	}
}
