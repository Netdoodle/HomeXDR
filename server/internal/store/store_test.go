package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUsersAndSessions(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if _, err := s.CreateFirstUser(ctx, "admin", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("want weak password error, got %v", err)
	}
	u, err := s.CreateFirstUser(ctx, "admin", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateFirstUser(ctx, "admin2", "correct horse battery"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second first-user should conflict, got %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin", "wrong password!"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad password should fail, got %v", err)
	}
	if _, err := s.Authenticate(ctx, "ADMIN", "correct horse battery"); err != nil {
		t.Fatalf("case-insensitive username login failed: %v", err)
	}
	tok, _, err := s.CreateSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionUser(ctx, tok)
	if err != nil || got.ID != u.ID {
		t.Fatalf("SessionUser = %v, %v", got, err)
	}
	if _, err := s.UpdateUser(ctx, u.ID, RoleViewer, ""); err == nil {
		t.Fatal("demoting the last admin should fail")
	}
	if _, err := s.UpdateUser(ctx, u.ID, "", "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatal("password change should end sessions")
	}
	if err := s.DeleteUser(ctx, u.ID); err == nil {
		t.Fatal("deleting the last admin should fail")
	}
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	one := 1
	tok, err := s.CreateToken(ctx, "laptops", "admin", nil, &one, []string{"laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseToken(ctx, tok.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseToken(ctx, tok.Token); !errors.Is(err, ErrTokenUsedUp) {
		t.Fatalf("want used up, got %v", err)
	}
	past := time.Now().Add(-time.Hour)
	exp, _ := s.CreateToken(ctx, "old", "admin", &past, nil, nil)
	if _, err := s.UseToken(ctx, exp.Token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("want invalid for expired token, got %v", err)
	}
	if _, err := s.UseToken(ctx, "hxe_nope"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("want invalid, got %v", err)
	}
}

func TestHostsAlertsCommands(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	info := api.HostInfo{Hostname: "desk", OS: event.OS{Platform: "windows", Name: "Windows 11"}, IPs: []string{"192.168.1.20"}}
	h, err := s.CreateEndpoint(ctx, "agent-1", info, []string{"gaming", " Gaming ", "lab", ""}, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Labels) != 2 || h.Labels[0] != "gaming" || h.Labels[1] != "lab" {
		t.Fatalf("labels not cleaned: %q", h.Labels)
	}
	if h.Status != "online" || h.Hostname != "desk" || h.OS.Platform != "windows" {
		t.Fatalf("unexpected host %+v", h)
	}
	hosts, err := s.ListHosts(ctx, HostFilter{Q: "192.168.1"})
	if err != nil || len(hosts) != 1 {
		t.Fatalf("ListHosts by IP = %d, %v", len(hosts), err)
	}

	ev := &event.Event{ID: event.NewID(), Timestamp: time.Now(), Host: event.Host{ID: "agent-1", Name: "desk"},
		Process: &event.Process{EntityID: "ent1", Name: "powershell.exe", CommandLine: "powershell -enc AAA"}}
	in := AlertInput{Rule: AlertRule{ID: "r1", Title: "Encoded PowerShell", Level: SevHigh}, Severity: SevHigh, Event: ev}
	a1, isNew, err := s.RecordAlert(ctx, in)
	if err != nil || !isNew {
		t.Fatalf("first alert: new=%v err=%v", isNew, err)
	}
	ev2 := *ev
	ev2.ID = event.NewID()
	in.Event = &ev2
	a2, isNew, err := s.RecordAlert(ctx, in)
	if err != nil || isNew || a2.ID != a1.ID || a2.Count != 2 || len(a2.EventIDs) != 2 {
		t.Fatalf("dedup failed: new=%v id=%s/%s count=%d err=%v", isNew, a1.ID, a2.ID, a2.Count, err)
	}
	h, _ = s.GetHost(ctx, "agent-1")
	if h.OpenAlerts != 1 {
		t.Fatalf("open alerts = %d", h.OpenAlerts)
	}
	resolved := AlertResolved
	if _, err := s.UpdateAlert(ctx, a1.ID, &resolved, nil); err != nil {
		t.Fatal(err)
	}
	if _, isNew, _ := s.RecordAlert(ctx, in); !isNew {
		t.Fatal("hit after resolve should open a new alert")
	}

	params, _ := json.Marshal(api.KillParams{PID: 42})
	c, err := s.CreateCommand(ctx, "agent-1", api.CmdProcessKill, params, "admin", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.TakePendingCommands(ctx, "agent-1", 10)
	if err != nil || len(pending) != 1 || pending[0].ID != c.ID {
		t.Fatalf("TakePendingCommands = %v, %v", pending, err)
	}
	if more, _ := s.TakePendingCommands(ctx, "agent-1", 10); len(more) != 0 {
		t.Fatal("command delivered twice")
	}
	if _, err := s.RecordResult(ctx, "other-agent", api.CommandResult{CommandID: c.ID, Status: api.StatusCompleted}); !errors.Is(err, ErrNotFound) {
		t.Fatal("another agent must not complete this command")
	}
	done, err := s.RecordResult(ctx, "agent-1", api.CommandResult{CommandID: c.ID, Status: api.StatusCompleted, Output: json.RawMessage(`{"killed":[42]}`)})
	if err != nil || done.Status != api.StatusCompleted || done.CompletedAt == nil {
		t.Fatalf("RecordResult = %+v, %v", done, err)
	}
	if _, err := s.RecordResult(ctx, "agent-1", api.CommandResult{CommandID: c.ID, Status: api.StatusFailed}); !errors.Is(err, ErrConflict) {
		t.Fatal("final command must not change")
	}

	// A delivered command whose agent never answers is failed after expiry + grace.
	stuck, err := s.CreateCommand(ctx, "agent-1", api.CmdFileHash, json.RawMessage(`{"path":"C:\\x"}`), "admin", "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s.TakePendingCommands(ctx, "agent-1", 10) // too late: already expired, stays queued
	if _, err := s.db.ExecContext(ctx, `UPDATE commands SET status = 'running', expires_at = ? WHERE id = ?`,
		ts(time.Now().Add(-StaleResultGrace-time.Minute)), stuck.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireCommands(ctx); err != nil || n < 1 {
		t.Fatalf("ExpireCommands = %d, %v", n, err)
	}
	if got, _ := s.GetCommand(ctx, stuck.ID); got.Status != api.StatusFailed || got.Error != "no result from agent" {
		t.Fatalf("stuck command = %s %q", got.Status, got.Error)
	}
}

func TestHunts(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.CreateEndpoint(ctx, "a1", api.HostInfo{Hostname: "one", OS: event.OS{Platform: "linux"}}, []string{"servers"}, "")
	s.CreateEndpoint(ctx, "a2", api.HostInfo{Hostname: "two", OS: event.OS{Platform: "windows"}}, nil, "")
	target := HuntTarget{Labels: []string{"SERVERS"}}
	h, err := s.CreateHunt(ctx, "process.list", nil, "", target, "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := s.ListHosts(ctx, HostFilter{})
	var matched int
	for _, host := range hosts {
		if target.Matches(host) {
			matched++
			c, err := s.CreateCommand(ctx, host.ID, api.CmdArtifact, nil, "admin", h.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.AddRows(ctx, c, []json.RawMessage{json.RawMessage(`{"pid":1}`), json.RawMessage(`{"pid":2}`)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("matched %d hosts, want 1", matched)
	}
	got, err := s.GetHunt(ctx, h.ID)
	if err != nil || got.Stats.Scheduled != 1 || got.Stats.Rows != 2 {
		t.Fatalf("hunt stats = %+v, %v", got.Stats, err)
	}
	rows, total, err := s.HuntResults(ctx, h.ID, "", 10, 0)
	if err != nil || total != 2 || rows[0].Hostname != "one" {
		t.Fatalf("HuntResults = %v, %d, %v", rows, total, err)
	}
}
