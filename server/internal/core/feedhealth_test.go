package core

import (
	"context"
	"io"
	"log/slog"
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

// feedRig is a Core on a temporary store with a clock the test moves.
type feedRig struct {
	t        *testing.T
	c        *Core
	f        *FeedHealth
	now      time.Time
	host     *store.Host
	lastSeen map[string]time.Time
	sensors  map[string][]api.SensorStatus
}

func newFeedRig(t *testing.T) *feedRig {
	t.Helper()
	dir := t.TempDir()
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
	cfg := config.Config{DataDir: dir, RulesDir: filepath.Join(dir, "rules"), EventStore: "sqlite"}
	c, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := st.CreateEndpoint(context.Background(), "host-1", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux"}}, nil, "serial")
	if err != nil {
		t.Fatal(err)
	}
	r := &feedRig{t: t, c: c, host: h, now: time.Now().UTC(), lastSeen: map[string]time.Time{}, sensors: map[string][]api.SensorStatus{}}
	r.restart()
	return r
}

// restart builds a fresh tracker from what was saved, as a server start does.
func (r *feedRig) restart() {
	r.t.Helper()
	r.f = newFeedHealth(r.c, func() time.Time { return r.now })
	r.f.listHosts = func(ctx context.Context, flt store.HostFilter) ([]*store.Host, error) {
		list, err := r.c.State.ListHosts(ctx, flt)
		for _, h := range list {
			if t, ok := r.lastSeen[h.ID]; ok {
				h.LastSeen = &t
			}
			if s, ok := r.sensors[h.ID]; ok {
				h.Sensors = s
			}
		}
		return list, err
	}
	if err := r.f.load(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	r.c.Health.Feeds = r.f
}

// heartbeat makes the host look online right now, on the rig's clock.
func (r *feedRig) heartbeat() { r.lastSeen[r.host.ID] = r.now }

func (r *feedRig) batch(module, dataset string) {
	r.f.observe(r.host, []*event.Event{{Event: event.Meta{Module: module, Dataset: dataset}}})
}

// run advances the clock in one-minute ticks with the host online, sending rows on a rhythm.
func (r *feedRig) run(d time.Duration, every time.Duration, module, dataset string) {
	r.t.Helper()
	var since time.Duration
	for i := time.Duration(0); i < d; i += time.Minute {
		r.now = r.now.Add(time.Minute)
		since += time.Minute
		r.heartbeat()
		if every > 0 && since >= every {
			r.batch(module, dataset)
			since = 0
		}
		r.f.Tick(context.Background())
	}
}

func (r *feedRig) alerts() []*store.Alert {
	r.t.Helper()
	list, _, err := r.c.State.ListAlerts(context.Background(), store.AlertFilter{Limit: 50})
	if err != nil {
		r.t.Fatal(err)
	}
	return list
}

func (r *feedRig) openAlerts() int {
	n := 0
	for _, a := range r.alerts() {
		if a.Status == store.AlertNew || a.Status == store.AlertInProgress {
			n++
		}
	}
	return n
}

func (r *feedRig) status(module, dataset string) FeedView {
	r.t.Helper()
	rep, err := r.f.Report(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	for _, v := range rep.Sources {
		if v.Module == module && v.Dataset == dataset {
			return v
		}
	}
	r.t.Fatalf("%s/%s not in report", module, dataset)
	return FeedView{}
}

func TestAllowance(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	day := now.Unix() / 86400
	if got := allowance(nil, now); got != feedFloor {
		t.Errorf("no history: %v", got)
	}
	short := []store.FeedGap{{Day: day, Sec: 60}}
	if got := allowance(short, now); got != feedFloor {
		t.Errorf("short gaps use the floor: %v", got)
	}
	six := []store.FeedGap{{Day: day, Sec: 6 * 3600}}
	if got := allowance(six, now); got != 18*time.Hour {
		t.Errorf("3x the usual gap: %v", got)
	}
	week := []store.FeedGap{{Day: day, Sec: 5 * 86400}}
	if got := allowance(week, now); got != feedCap {
		t.Errorf("capped: %v", got)
	}
	// One reboot among many ordinary days does not set the baseline.
	var mixed []store.FeedGap
	for i := int64(0); i < 7; i++ {
		mixed = append(mixed, store.FeedGap{Day: day - i, Sec: 600})
	}
	mixed[3].Sec = 86400
	if got := usualGap(mixed, now); got != 10*time.Minute {
		t.Errorf("outlier ignored: %v", got)
	}
	// Old days fall out.
	old := []store.FeedGap{{Day: day - feedGapDays - 1, Sec: 86400}}
	if got := usualGap(old, now); got != 0 {
		t.Errorf("old gap counted: %v", got)
	}
}

func TestAddGapKeepsDailyLongest(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	var g []store.FeedGap
	g = addGap(g, at, time.Minute)
	g = addGap(g, at, time.Hour)
	g = addGap(g, at, 2*time.Minute)
	if len(g) != 1 || g[0].Sec != 3600 {
		t.Fatalf("%+v", g)
	}
	g = addGap(g, at.AddDate(0, 0, feedGapDays+1), time.Minute)
	if len(g) != 1 {
		t.Fatalf("old day not dropped: %+v", g)
	}
}

func TestNewSourceDoesNotAlertBeforeItIsTrusted(t *testing.T) {
	r := newFeedRig(t)
	r.run(6*time.Hour, 5*time.Minute, "m", "d") // 6 hours is not a day
	r.run(2*time.Hour, 0, "", "")
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("got %d alerts", n)
	}
	if v := r.status("m", "d"); v.Status != FeedLearning {
		t.Fatalf("status %q", v.Status)
	}
}

func TestSilenceRaisesOneAlertAndReturnResolvesIt(t *testing.T) {
	r := newFeedRig(t)
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	if v := r.status("m", "d"); v.Status != FeedOK || !v.CanAlert {
		t.Fatalf("before: %+v", v)
	}
	r.run(14*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("alert before the allowance: %d", n)
	}
	r.run(10*time.Minute, 0, "", "")
	r.run(2*time.Hour, 0, "", "")
	list := r.alerts()
	if len(list) != 1 || list[0].Rule.ID != RuleFeedSilent || list[0].Severity != store.SevMedium {
		t.Fatalf("%+v", list)
	}
	if list[0].Count != 1 {
		t.Fatalf("should raise once, count=%d", list[0].Count)
	}
	if v := r.status("m", "d"); v.Status != FeedSilent {
		t.Fatalf("status %q", v.Status)
	}

	r.batch("m", "d")
	r.now = r.now.Add(time.Minute)
	r.heartbeat()
	r.f.Tick(context.Background())
	got, err := r.c.State.GetAlert(context.Background(), list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.AlertResolved || len(got.Notes) != 1 || !strings.Contains(got.Notes[0].Text, "arriving again") {
		t.Fatalf("not resolved with a note: %+v", got)
	}
	if v := r.status("m", "d"); v.Status != FeedOK {
		t.Fatalf("status %q", v.Status)
	}
}

func TestOutageStaysOutOfTheBaseline(t *testing.T) {
	r := newFeedRig(t)
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	r.run(3*time.Hour, 0, "", "")
	r.batch("m", "d")
	if v := r.status("m", "d"); v.UsualGapSec > 600 {
		t.Fatalf("outage counted as usual: %+v", v)
	}
}

func TestOfflineHostGetsOneFindingNotOnePerDataset(t *testing.T) {
	r := newFeedRig(t)
	for i := time.Duration(0); i < 25*time.Hour; i += time.Minute {
		r.now = r.now.Add(time.Minute)
		r.heartbeat()
		r.batch("m", "a")
		r.batch("m", "b")
		r.batch("m", "c")
		r.f.Tick(context.Background())
	}
	// The agent stops: no heartbeat and no data.
	for i := 0; i < 180; i++ {
		r.now = r.now.Add(time.Minute)
		r.f.Tick(context.Background())
	}
	list := r.alerts()
	if len(list) != 1 || !strings.Contains(list[0].Rule.Title, "stopped sending data") {
		t.Fatalf("%d alerts: %+v", len(list), list)
	}
	if v := r.status("m", "a"); v.Status != FeedHostOffline {
		t.Fatalf("status %q", v.Status)
	}
	// It comes back, data and all: the finding resolves and nothing else fires.
	for i := 0; i < 30; i++ {
		r.now = r.now.Add(time.Minute)
		r.heartbeat()
		r.batch("m", "a")
		r.batch("m", "b")
		r.batch("m", "c")
		r.f.Tick(context.Background())
	}
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("%d alerts open after return: %+v", n, r.alerts())
	}
}

func TestOfflineTimeDoesNotCountAgainstDatasets(t *testing.T) {
	r := newFeedRig(t)
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	for i := 0; i < 600; i++ {
		r.now = r.now.Add(time.Minute)
		r.f.Tick(context.Background())
	}
	// Back online, but the dataset has not sent anything yet.
	r.heartbeat()
	r.f.Tick(context.Background())
	for _, a := range r.alerts() {
		if strings.Contains(a.Rule.Title, "Data source") {
			t.Fatalf("dataset alert for offline time: %+v", a)
		}
	}
}

func TestServerDowntimeIsNotSilence(t *testing.T) {
	r := newFeedRig(t)
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	r.f.Flush(context.Background())

	// The server is stopped for three days, then starts again.
	r.now = r.now.Add(72 * time.Hour)
	r.restart()
	if v := r.status("m", "d"); v.SilentSec > 600 {
		t.Fatalf("downtime counted as silence: %ds", v.SilentSec)
	}
	r.run(10*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("%d alerts during grace", n)
	}
	// A source that really is dead still alerts once the grace period is over.
	r.run(20*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 1 {
		t.Fatalf("got %d alerts", n)
	}
}

func TestReportedSilenceSurvivesRestart(t *testing.T) {
	r := newFeedRig(t)
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	r.run(30*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 1 {
		t.Fatalf("got %d", n)
	}
	r.f.Flush(context.Background())
	r.restart()
	r.run(40*time.Minute, 0, "", "")
	a := r.alerts()
	if len(a) != 1 || a[0].Count != 1 {
		t.Fatalf("raised again after restart: %+v", a)
	}
}

func TestMuteAndDecommission(t *testing.T) {
	r := newFeedRig(t)
	ctx := context.Background()
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	r.run(30*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 1 {
		t.Fatalf("got %d", n)
	}
	on := true
	if err := r.f.SetChoice(ctx, r.host.ID, "m", "d", &on, nil); err != nil {
		t.Fatal(err)
	}
	if n := r.openAlerts(); n != 0 {
		t.Fatal("muting should resolve the alert")
	}
	if v := r.status("m", "d"); v.Status != FeedMuted || v.CanAlert {
		t.Fatalf("%+v", v)
	}
	r.run(2*time.Hour, 0, "", "")
	if n := r.openAlerts(); n != 0 {
		t.Fatal("a muted source raised an alert")
	}

	off := false
	if err := r.f.SetChoice(ctx, r.host.ID, "m", "d", &off, nil); err != nil {
		t.Fatal(err)
	}
	r.run(5*time.Minute, 0, "", "")
	if n := r.openAlerts(); n != 1 {
		t.Fatalf("unmuted silent source: %d alerts", n)
	}
	if err := r.c.State.DecommissionHost(ctx, r.host.ID); err != nil {
		t.Fatal(err)
	}
	r.f.Tick(ctx)
	if n := r.openAlerts(); n != 0 {
		t.Fatal("decommissioning should resolve the alert")
	}
	rep, err := r.f.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != 0 {
		t.Fatalf("decommissioned host still listed: %+v", rep.Sources)
	}
}

func TestNeverSeenFeeds(t *testing.T) {
	r := newFeedRig(t)
	ctx := context.Background()
	r.sensors[r.host.ID] = []api.SensorStatus{{Name: "inventory", Error: "software.list: no supported package database found"}}
	r.heartbeat()
	v := r.status(event.ModuleInventory, "inventory.software.list")
	if v.Status != FeedNeverSeen || !strings.Contains(v.Explanation, "no supported package database") {
		t.Fatalf("%+v", v)
	}
	// Never seen is shown, not alerted on.
	r.run(48*time.Hour, 0, "", "")
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("%d alerts for a never-seen feed", n)
	}

	// Marked expected, it alerts after a day, and first data resolves it.
	on := true
	if err := r.f.SetChoice(ctx, r.host.ID, event.ModuleInventory, "inventory.software.list", nil, &on); err != nil {
		t.Fatal(err)
	}
	r.run(25*time.Hour, 0, "", "")
	if n := r.openAlerts(); n != 1 {
		t.Fatalf("expected feed: %d alerts", n)
	}
	r.batch(event.ModuleInventory, "inventory.software.list")
	r.now = r.now.Add(time.Minute)
	r.heartbeat()
	r.f.Tick(ctx)
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("still open after first data: %d", n)
	}
}

func TestSuricataIsQuietByDefault(t *testing.T) {
	r := newFeedRig(t)
	ctx := context.Background()
	// OPNsense syslog is arriving, and Suricata has never sent anything.
	net, err := r.c.State.EnsureNetworkHost(ctx, "192.0.2.1", "opnsense", "OPNsense")
	if err != nil {
		t.Fatal(err)
	}
	r.f.observe(net, []*event.Event{{Event: event.Meta{Module: event.ModuleOPNsense, Dataset: "opnsense.filterlog"}}})
	r.lastSeen[net.ID] = r.now
	v := r.status(event.ModuleSuricata, "suricata.alert")
	if v.Status != FeedNeverSeen || !strings.Contains(v.Explanation, "quiet IDS") {
		t.Fatalf("%+v", v)
	}
	// Once it has data it reads as quiet and never alerts.
	st := &feedState{FeedSource: store.FeedSource{HostID: net.ID, Module: event.ModuleSuricata, Dataset: "suricata.alert",
		FirstSeen: r.now.Add(-30 * 24 * time.Hour), LastSeen: r.now.Add(-20 * 24 * time.Hour), Clock: r.now.Add(-20 * 24 * time.Hour), Arrivals: 100}}
	r.f.mu.Lock()
	r.f.src[feedKey{net.ID, st.Module, st.Dataset}] = st
	r.f.mu.Unlock()
	r.run(16*time.Minute, 0, "", "")
	r.lastSeen[net.ID] = r.now
	if v := r.status(event.ModuleSuricata, "suricata.alert"); v.Status != FeedQuiet || v.CanAlert {
		t.Fatalf("%+v", v)
	}
	if n := r.openAlerts(); n != 0 {
		t.Fatalf("got %d alerts", n)
	}
}

func TestBootstrapFromHistory(t *testing.T) {
	r := newFeedRig(t)
	r.now = time.Now().UTC()
	ctx := context.Background()
	var evs []*event.Event
	start := r.now.Add(-10 * 24 * time.Hour)
	// Rows every six hours for ten days, with some rows sharing an hour.
	for i := 0; i < 40; i++ {
		at := start.Add(time.Duration(i) * 6 * time.Hour)
		for j := 0; j < 2; j++ {
			evs = append(evs, &event.Event{
				ID: event.NewID(), Timestamp: at, Host: event.Host{ID: r.host.ID, Name: "tower"},
				Event: event.Meta{Kind: event.KindState, Module: "inventory", Dataset: "inventory.system.info"},
			})
		}
	}
	// A server's own finding and an unregistered host are not sources.
	evs = append(evs,
		&event.Event{ID: event.NewID(), Timestamp: start, Host: event.Host{ID: ServerHostID}, Event: event.Meta{Module: event.ModuleHomeXDR, Dataset: "homexdr.health"}},
		&event.Event{ID: event.NewID(), Timestamp: start, Host: event.Host{ID: "gone"}, Event: event.Meta{Module: "m", Dataset: "d"}},
	)
	if err := r.c.Events.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if !r.f.Bootstrap(ctx) {
		t.Fatal("bootstrap failed")
	}
	v := r.status("inventory", "inventory.system.info")
	if v.Arrivals != 40 {
		t.Errorf("arrivals = %d", v.Arrivals)
	}
	if v.UsualGapSec != 6*3600 {
		t.Errorf("usual gap = %d", v.UsualGapSec)
	}
	if v.AllowanceSec != 18*3600 {
		t.Errorf("allowance = %d", v.AllowanceSec)
	}
	if !v.CanAlert {
		t.Errorf("a bootstrapped source should be able to alert: %+v", v)
	}
	if len(r.f.src) != 2 { // the source and the host row
		t.Errorf("sources: %+v", r.f.src)
	}
	r.f.Flush(ctx)
	// A later start does not read history again.
	r.restart()
	if !r.f.bootDone {
		t.Fatal("bootstrap flag not saved")
	}
}

func TestEventStoreOutageIsNotSilence(t *testing.T) {
	r := newFeedRig(t)
	ctx := context.Background()
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	r.c.Events = closedStore{r.c.Events} // Ping fails from here on.
	for i := 0; i < 180; i++ {
		r.now = r.now.Add(time.Minute)
		r.heartbeat()
		r.f.Tick(ctx)
	}
	if v := r.status("m", "d"); v.SilentSec > 600 {
		t.Fatalf("outage counted: %ds", v.SilentSec)
	}
}

type closedStore struct{ events.Store }

func (closedStore) Ping(context.Context) error { return io.ErrClosedPipe }

func TestDigestSection(t *testing.T) {
	r := newFeedRig(t)
	ctx := context.Background()
	r.run(25*time.Hour, 5*time.Minute, "m", "d")
	title, lines := r.c.FeedHealthDigest(ctx)
	if title == "" {
		t.Fatal("no title")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "never sent") {
		t.Fatalf("%v", lines)
	}
	r.run(30*time.Minute, 0, "", "")
	_, lines = r.c.FeedHealthDigest(ctx)
	if len(lines) != 2 || !strings.Contains(lines[0], "silent") {
		t.Fatalf("%v", lines)
	}
}

func BenchmarkObserve(b *testing.B) {
	f := &FeedHealth{now: time.Now, src: map[feedKey]*feedState{}}
	host := &store.Host{ID: "h"}
	evs := make([]*event.Event, 500)
	for i := range evs {
		evs[i] = &event.Event{Event: event.Meta{Module: "procfs", Dataset: "process.procconn"}}
	}
	b.ReportAllocs()
	for b.Loop() {
		f.observe(host, evs)
	}
}
