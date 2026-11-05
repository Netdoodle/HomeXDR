package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// healthCore builds a Core on temporary stores, with the given rule files.
func healthCore(t *testing.T, ruleFiles map[string]string) *Core {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, src := range ruleFiles {
		if err := os.WriteFile(filepath.Join(rules, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	cfg := config.Config{DataDir: dir, RulesDir: rules, EventStore: "sqlite", SyslogAddr: ":5514", RetentionDays: 30}
	c, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func doctorResult(t *testing.T, rep *DoctorReport, id string) CheckResult {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no check %q in %+v", id, rep.Results)
	return CheckResult{}
}

func TestDoctorFreshInstall(t *testing.T) {
	c := healthCore(t, nil)
	rep := c.RunDoctor(context.Background())
	if rep.Fail != 0 {
		t.Fatalf("fresh install failed checks: %+v", rep.Results)
	}
	for id, want := range map[string]string{
		"state_db": CheckOK, "event_store": CheckOK, "disk": CheckOK, "rules": CheckWarn, "rule_repos": CheckSkip,
		"syslog": CheckWarn, "agent_release": CheckWarn, "agents": CheckSkip, "ai": CheckWarn, "feeds": CheckOK,
	} {
		if r := doctorResult(t, rep, id); r.Status != want {
			t.Errorf("%s: %+v, want %s", id, r, want)
		}
	}
	if r := doctorResult(t, rep, "syslog"); !strings.Contains(r.Fix, "5514") {
		t.Errorf("syslog fix: %+v", r)
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	c := healthCore(t, nil)
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	soon := time.Now().Add(48 * time.Hour)

	h1, err := c.State.CreateEndpoint(ctx, "a", api.HostInfo{Hostname: "soon", OS: event.OS{Platform: "linux"}}, nil, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.State.UseCert(ctx, h1.ID, "s1", soon); err != nil {
		t.Fatal(err)
	}
	if r := doctorResult(t, c.RunDoctor(ctx), "agents"); r.Status != CheckWarn || !strings.Contains(r.Message, "soon") {
		t.Errorf("expiring: %+v", r)
	}
	h2, err := c.State.CreateEndpoint(ctx, "b", api.HostInfo{Hostname: "gone", OS: event.OS{Platform: "linux"}}, nil, "s2")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.State.UseCert(ctx, h2.ID, "s2", expired); err != nil {
		t.Fatal(err)
	}
	if r := doctorResult(t, c.RunDoctor(ctx), "agents"); r.Status != CheckFail || !strings.Contains(r.Message, "gone") {
		t.Errorf("expired: %+v", r)
	}

	if _, err := c.State.EnsureNetworkHost(ctx, "192.0.2.1", "fw", "OPNsense"); err != nil {
		t.Fatal(err)
	}
	if r := doctorResult(t, c.RunDoctor(ctx), "syslog"); r.Status != CheckOK || !strings.Contains(r.Message, "fw") {
		t.Errorf("syslog: %+v", r)
	}

	c.Events = brokenStore{c.Events}
	rep := c.RunDoctor(ctx)
	if r := doctorResult(t, rep, "event_store"); r.Status != CheckFail {
		t.Errorf("event store: %+v", r)
	}
	if rep.Fail == 0 {
		t.Error("a failing check must be counted")
	}
}

type brokenStore struct{ events.Store }

func (brokenStore) Ping(context.Context) error { return errors.New("dial tcp: connection refused") }

func TestDoctorNeverShowsSecrets(t *testing.T) {
	const password, apiKey = "hunter2-dsn-password", "sk-test-do-not-print"
	c := healthCore(t, nil)
	ctx := context.Background()
	c.Cfg.ClickHouseDSN = "clickhouse://user:" + password + "@db:9000/homexdr"
	// A driver error quoting the address must not leak it.
	c.Events = quotingStore{c.Events, c.Cfg.ClickHouseDSN}
	set := c.Triage.Settings(ctx)
	set.Enabled, set.APIKey = true, apiKey
	set.APIKeys = map[string]string{set.Provider: apiKey}
	if _, err := c.Triage.SaveSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	rep := c.RunDoctor(ctx)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{password, apiKey} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("secret %q in report: %s", secret, b)
		}
	}
	if r := doctorResult(t, rep, "event_store"); r.Status != CheckFail || !strings.Contains(r.Message, "did not answer") {
		t.Errorf("%+v", r)
	}
	if got := c.scrub("dial https://bob:pw@host:1/x failed"); strings.Contains(got, "pw") {
		t.Errorf("scrub: %s", got)
	}
}

type quotingStore struct {
	events.Store
	dsn string
}

func (s quotingStore) Ping(context.Context) error { return errors.New("cannot reach " + s.dsn) }

func TestDoctorRegistrationPoint(t *testing.T) {
	before := len(doctorChecks)
	t.Cleanup(func() { doctorChecks = doctorChecks[:before] })
	RegisterDoctorCheck(DoctorCheck{ID: "feature_x", Name: "Feature X", Run: func(context.Context, *Core) CheckResult {
		return checkWarn("do the thing", "needs attention")
	}})
	rep := healthCore(t, nil).RunDoctor(context.Background())
	if r := doctorResult(t, rep, "feature_x"); r.Status != CheckWarn || r.Name != "Feature X" || r.Fix != "do the thing" {
		t.Fatalf("%+v", r)
	}
}

func TestDoctorSlowCheckDoesNotHang(t *testing.T) {
	c := healthCore(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := c.runCheck(ctx, DoctorCheck{Run: func(ctx context.Context, _ *Core) CheckResult {
		<-make(chan struct{})
		return CheckResult{}
	}})
	if r.Status != CheckFail {
		t.Fatalf("%+v", r)
	}
}

func TestDoctorAIEngine(t *testing.T) {
	c := healthCore(t, nil)
	ctx := context.Background()
	set := c.Triage.Settings(ctx)
	set.Enabled, set.Engine, set.MCPEnabled = true, store.EngineMCP, true
	if _, err := c.Triage.SaveSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	if r := doctorResult(t, c.RunDoctor(ctx), "ai"); r.Status != CheckOK {
		t.Errorf("command line cannot judge the runner: %+v", r)
	}
	c.Health.serving.Store(true)
	if r := doctorResult(t, c.RunDoctor(ctx), "ai"); r.Status != CheckWarn {
		t.Errorf("no runner: %+v", r)
	}
	c.Triage.NoteRunner("desk")
	if r := doctorResult(t, c.RunDoctor(ctx), "ai"); r.Status != CheckOK || !strings.Contains(r.Message, "desk") {
		t.Errorf("runner seen: %+v", r)
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[uint64]string{512: "512 B", 2048: "2.0 KiB", 5 << 30: "5.0 GiB"} {
		if got := formatBytes(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}
