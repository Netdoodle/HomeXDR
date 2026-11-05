package store

import (
	"context"
	"testing"

	"github.com/Netdoodle/homexdr/shared/event"
)

func hit(entity, exe, parentExe string) *event.Event {
	p := &event.Process{EntityID: entity, Name: "wget", Executable: exe}
	if parentExe != "" {
		p.Parent = &event.Process{EntityID: "parent-" + entity, Name: "parent", Executable: parentExe}
	}
	return &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1", Name: "tower"}, Process: p}
}

func TestGroupingByProcessShape(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	record := func(in AlertInput) (*Alert, bool) {
		t.Helper()
		if in.Rule.ID == "" {
			in.Rule = AlertRule{ID: "r1", Title: "Wget to tmp", Level: SevMedium}
		}
		in.Severity = SevMedium
		a, isNew, err := s.RecordAlert(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return a, isNew
	}

	// Each run of a job is a new process but the same shape: they fold.
	first, isNew := record(AlertInput{Event: hit("run-1", "/usr/bin/wget", "/usr/bin/php")})
	if !isNew {
		t.Fatal("first hit is not new")
	}
	again, isNew := record(AlertInput{Event: hit("run-2", "/usr/bin/wget", "/usr/bin/php")})
	if isNew || again.ID != first.ID || again.Count != 2 {
		t.Fatalf("a second run did not fold: new=%v %+v", isNew, again)
	}

	// The same program from another parent is a different story, and a new alert.
	shell, isNew := record(AlertInput{Event: hit("run-3", "/usr/bin/wget", "/bin/bash")})
	if !isNew || shell.ID == first.ID {
		t.Fatal("wget from a shell folded into wget from php")
	}
	// So is another program from the same parent, and a process with no known parent.
	if _, isNew := record(AlertInput{Event: hit("run-4", "/tmp/wget", "/usr/bin/php")}); !isNew {
		t.Fatal("a different executable folded")
	}
	if _, isNew := record(AlertInput{Event: hit("run-5", "/usr/bin/wget", "")}); !isNew {
		t.Fatal("no parent folded into a known parent")
	}

	// Without an executable, the name is the shape.
	byName := func(entity, name, parent string) *event.Event {
		return &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1"}, Process: &event.Process{
			EntityID: entity, Name: name, Parent: &event.Process{Name: parent}}}
	}
	n1, isNew := record(AlertInput{Event: byName("n1", "curl", "cron")})
	if !isNew {
		t.Fatal("first by-name hit is not new")
	}
	if n2, isNew := record(AlertInput{Event: byName("n2", "curl", "cron")}); isNew || n2.ID != n1.ID {
		t.Fatal("same names did not fold")
	}
	if _, isNew := record(AlertInput{Event: byName("n3", "curl", "sshd")}); !isNew {
		t.Fatal("different parent name folded")
	}

	// DedupEntity overrides the shape: findings fold by what they are about.
	d1, isNew := record(AlertInput{Event: hit("d1", "/usr/bin/wget", "/usr/bin/php"), DedupEntity: "feed:suricata", Rule: AlertRule{ID: "health:x"}})
	if !isNew {
		t.Fatal("first finding is not new")
	}
	if d2, isNew := record(AlertInput{Event: hit("d2", "/bin/other", "/bin/else"), DedupEntity: "feed:suricata", Rule: AlertRule{ID: "health:x"}}); isNew || d2.ID != d1.ID {
		t.Fatal("DedupEntity did not override the shape")
	}
	if _, isNew := record(AlertInput{Event: hit("d3", "/usr/bin/wget", "/usr/bin/php"), DedupEntity: "feed:unbound", Rule: AlertRule{ID: "health:x"}}); !isNew {
		t.Fatal("different DedupEntity folded")
	}

	// Events with no process fold by rule and host.
	noProc := func() *event.Event { return &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1"}} }
	p1, isNew := record(AlertInput{Event: noProc(), Rule: AlertRule{ID: "r-net"}})
	if !isNew {
		t.Fatal("first process-less hit is not new")
	}
	if p2, isNew := record(AlertInput{Event: noProc(), Rule: AlertRule{ID: "r-net"}}); isNew || p2.ID != p1.ID {
		t.Fatal("process-less hits did not fold")
	}

	// A process we know nothing about but its ID keeps today's per-process grouping.
	unknown := func(id string) *event.Event {
		return &event.Event{ID: event.NewID(), Host: event.Host{ID: "h1"}, Process: &event.Process{EntityID: id}}
	}
	record(AlertInput{Event: unknown("u1"), Rule: AlertRule{ID: "r-u"}})
	if _, isNew := record(AlertInput{Event: unknown("u2"), Rule: AlertRule{ID: "r-u"}}); !isNew {
		t.Fatal("processes with no shape folded")
	}

	// Another host never folds.
	other := hit("o1", "/usr/bin/wget", "/usr/bin/php")
	other.Host.ID = "h2"
	if _, isNew := record(AlertInput{Event: other}); !isNew {
		t.Fatal("a different host folded")
	}

	// A closed alert stops absorbing.
	st := AlertResolved
	if _, err := s.UpdateAlert(ctx, first.ID, &st, nil); err != nil {
		t.Fatal(err)
	}
	if a, isNew := record(AlertInput{Event: hit("run-9", "/usr/bin/wget", "/usr/bin/php")}); !isNew || a.ID == first.ID {
		t.Fatal("a resolved alert absorbed a hit")
	}
}

func TestOldOpenAlertsStopAbsorbing(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	in := AlertInput{Rule: AlertRule{ID: "r1"}, Severity: SevMedium, Event: hit("run-1", "/usr/bin/wget", "/usr/bin/php")}
	old, _, err := s.RecordAlert(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// An alert stored by an older version is keyed on the process entity ID.
	if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET dedup_key = ? WHERE id = ?`, "r1|h1|run-1", old.ID); err != nil {
		t.Fatal(err)
	}
	in.Event = hit("run-1", "/usr/bin/wget", "/usr/bin/php")
	if a, isNew, err := s.RecordAlert(ctx, in); err != nil || !isNew || a.ID == old.ID {
		t.Fatalf("old alert absorbed a hit: new=%v err=%v", isNew, err)
	}
}
