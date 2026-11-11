package behavior

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/netscope"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

type harness struct {
	t      *testing.T
	ev     events.Store
	st     *store.Store
	r      *Runner
	now    time.Time
	enrich enrich.Lookup
	found  []Finding
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev := openEvents(t, dir)
	t.Cleanup(func() { ev.Close() })
	h := &harness{t: t, ev: ev, st: st, enrich: enrich.Nop{}, now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	scope := netscope.New(netscope.Config{}, []netip.Addr{netip.MustParseAddr("192.168.20.1"), netip.MustParseAddr("203.0.113.9")})
	h.r = New(Deps{
		Events: ev, State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enrich: func() enrich.Lookup { return h.enrich },
		Scope:  func() *netscope.Scope { return scope },
		Label:  func(ip string) (string, string) { return "ip:" + ip, ip },
		Raise:  func(_ context.Context, f Finding) error { h.found = append(h.found, f); return nil },
		Now:    func() time.Time { return h.now },
	})
	return h
}

// openEvents uses SQLite, or a database of its own on ClickHouse when
// HOMEXDR_TEST_CLICKHOUSE_DSN is set, so the detectors are tested on both backends.
func openEvents(t *testing.T, dir string) events.Store {
	t.Helper()
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = fmt.Sprintf("%s_%d", u.Path, time.Now().UnixNano())
	ev, err := events.OpenClickHouse(context.Background(), u.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func (h *harness) insert(evs ...*event.Event) {
	h.t.Helper()
	if err := h.ev.Insert(context.Background(), evs); err != nil {
		h.t.Fatal(err)
	}
}

// run runs one detector and returns what it found this time.
func (h *harness) run(id string) []Finding {
	h.t.Helper()
	h.found = nil
	h.r.runOne(context.Background(), h.r.spec(id))
	st := h.status(id)
	if st.State == StatusError {
		h.t.Fatalf("%s failed: %s", id, st.Error)
	}
	return h.found
}

func (h *harness) status(id string) Status {
	for _, s := range h.r.Statuses() {
		if s.ID == id {
			return s
		}
	}
	h.t.Fatalf("no detector %s", id)
	return Status{}
}

func (h *harness) settings(id string, ds DetectorSetting) {
	h.t.Helper()
	if err := h.r.SetSettings(context.Background(), Settings{Detectors: map[string]DetectorSetting{id: ds}}); err != nil {
		h.t.Fatal(err)
	}
}

// keepFlowsVisible puts one NetFlow row in the data window, so a detector sees full input.
func (h *harness) keepFlowsVisible() {
	h.insert(flow(h.now.Add(-time.Minute), "192.168.20.250", 50000, "192.168.20.251", 80, "tcp", 1))
}

func flow(ts time.Time, src string, sport int, dst string, dport int, proto string, bytes int64) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: ts, Host: event.Host{ID: "fw", Name: "fw"},
		Event:       event.Meta{Kind: event.KindEvent, Module: event.ModuleNetFlow, Dataset: "netflow.flow", Action: "flow"},
		Source:      &event.Endpoint{IP: src, Port: sport},
		Destination: &event.Endpoint{IP: dst, Port: dport},
		Network:     &event.Network{Transport: proto, Bytes: bytes, Direction: direction(src, dst)},
	}
}

func direction(src, dst string) string {
	return netscope.Direction(netip.MustParseAddr(src), netip.MustParseAddr(dst))
}

func fwRow(ts time.Time, action, dir, src string, sport int, dst string, dport int, proto string) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: ts, Host: event.Host{ID: "fw", Name: "fw"},
		Event:       event.Meta{Kind: event.KindEvent, Module: event.ModuleOPNsense, Dataset: "opnsense.filterlog", Action: action},
		Source:      &event.Endpoint{IP: src, Port: sport},
		Destination: &event.Endpoint{IP: dst, Port: dport},
		Network:     &event.Network{Transport: proto, Direction: dir},
	}
}

func dnsRow(ts time.Time, src, name string) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: ts, Host: event.Host{ID: "fw", Name: "fw"},
		Event:  event.Meta{Kind: event.KindEvent, Module: event.ModuleDNS, Dataset: "dns.unbound"},
		Source: &event.Endpoint{IP: src},
		DNS:    &event.DNS{Type: "query", Question: event.DNSQuestion{Name: name, Type: "A"}},
	}
}

// beat inserts connections from src to dst:port at a fixed gap, each from a new port.
func (h *harness) beat(src, dst string, port int, proto string, gap time.Duration, n int) {
	h.t.Helper()
	var evs []*event.Event
	for i := range n {
		evs = append(evs, flow(h.now.Add(-time.Duration(n-i)*gap), src, 40000+i, dst, port, proto, 600))
	}
	h.insert(evs...)
}

func TestBeatsAndMath(t *testing.T) {
	base := time.Unix(1000, 0)
	n, gaps := beats([]time.Time{base, base.Add(time.Second), base.Add(60 * time.Second), base.Add(120 * time.Second)})
	if n != 3 || len(gaps) != 2 || gaps[0] != 60 || gaps[1] != 60 {
		t.Fatalf("beats %d %v", n, gaps)
	}
	if m, s := meanStd([]float64{10, 10}); m != 10 || s != 0 {
		t.Fatalf("mean %v std %v", m, s)
	}
	if entropy("aaaa") != 0 || entropy("ab") != 1 {
		t.Fatal("entropy")
	}
	for in, want := range map[string]string{"a.b.example.com": "example.com", "example.com": "example.com", "x.y.example.co.uk": "example.co.uk", "com": "com"} {
		if got := baseDomain(in); got != want {
			t.Errorf("baseDomain(%s) = %s", in, got)
		}
	}
	if !localOnly("a.home.arpa") || !localOnly("printer") || localOnly("example.com") {
		t.Error("localOnly")
	}
}

func TestBeaconingFires(t *testing.T) {
	h := newHarness(t)
	h.beat("192.168.20.5", "198.51.100.10", 8443, "tcp", 5*time.Minute, 20)
	f := h.run("beaconing")
	if len(f) != 1 {
		t.Fatalf("findings %+v", f)
	}
	got := f[0]
	if got.Rule != "net:beaconing" || got.Severity != store.SevMedium || got.Source.IP != "192.168.20.5" || got.Destination.IP != "198.51.100.10" || got.Destination.Port != 8443 {
		t.Fatalf("finding %+v", got)
	}
	if !strings.Contains(got.Description, "5 minutes") || !strings.Contains(got.Description, "20 check-ins") || got.Data["interval_sec"] != float64(300) {
		t.Fatalf("evidence %s %+v", got.Description, got.Data)
	}
	if st := h.status("beaconing"); st.State != StatusOK || st.LastFindings != 1 || st.LastRun == nil || st.DataNeeded != "" {
		t.Fatalf("status %+v", st)
	}
	// Reported once in reported_days, then again.
	if f := h.run("beaconing"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
	h.now = h.now.Add(8 * 24 * time.Hour)
	h.beat("192.168.20.5", "198.51.100.10", 8443, "tcp", 5*time.Minute, 20)
	if f := h.run("beaconing"); len(f) != 1 {
		t.Fatalf("after reported_days %+v", f)
	}
}

func TestBeaconingBenign(t *testing.T) {
	h := newHarness(t)
	h.keepFlowsVisible()
	// NTP every 64 seconds, phone push, Tailscale and STUN.
	h.beat("192.168.20.5", "198.51.100.1", 123, "udp", 64*time.Second, 40)
	h.beat("192.168.20.5", "198.51.100.2", 5223, "tcp", 5*time.Minute, 20)
	h.beat("192.168.20.5", "198.51.100.3", 41641, "udp", time.Minute, 30)
	h.beat("192.168.20.5", "198.51.100.4", 3478, "udp", time.Minute, 30)
	// A push service on 443, known by the name TLS showed.
	h.beat("192.168.20.6", "198.51.100.5", 443, "tcp", 5*time.Minute, 20)
	h.insert(&event.Event{
		ID: event.NewID(), Timestamp: h.now.Add(-time.Hour), Event: event.Meta{Module: event.ModuleSuricata, Dataset: "suricata.tls"},
		Source: &event.Endpoint{IP: "192.168.20.6"}, Destination: &event.Endpoint{IP: "198.51.100.5", Port: 443, Domain: "courier.push.apple.com"},
	})
	// Too few, too short, not regular, or only retries.
	h.beat("192.168.20.7", "198.51.100.6", 8443, "tcp", 5*time.Minute, 5)
	h.beat("192.168.20.7", "198.51.100.7", 8443, "tcp", 30*time.Second, 12)
	rng := rand.New(rand.NewSource(7))
	t0 := h.now.Add(-6 * time.Hour)
	var evs []*event.Event
	for i := range 40 {
		t0 = t0.Add(time.Duration(rng.Intn(1200)+10) * time.Second)
		evs = append(evs, flow(t0, "192.168.20.7", 40000+i, "198.51.100.8", 8443, "tcp", 600))
	}
	for i := range 30 {
		evs = append(evs, flow(h.now.Add(-time.Duration(i)*time.Second), "192.168.20.7", 41000+i, "198.51.100.9", 8443, "tcp", 600))
	}
	// One long connection the exporter reports every 30 minutes keeps its source port.
	for i := range 20 {
		evs = append(evs, flow(h.now.Add(-time.Duration(i)*30*time.Minute), "192.168.20.8", 50123, "198.51.100.11", 8443, "tcp", 90000))
	}
	// The firewall's own WAN address, and public to public: nothing to do with a device.
	for i := range 20 {
		evs = append(evs, fwRow(h.now.Add(-time.Duration(i)*5*time.Minute), "pass", event.DirectionOutbound, "203.0.113.9", 40000+i, "198.51.100.12", 8443, "tcp"))
	}
	h.insert(evs...)
	if f := h.run("beaconing"); len(f) != 0 {
		for _, x := range f {
			t.Errorf("fired: %s", x.Description)
		}
	}
	// Listed destinations and ports are left out too.
	h.beat("192.168.20.9", "198.51.100.13", 8883, "tcp", 5*time.Minute, 20)
	h.settings("beaconing", DetectorSetting{Lists: map[string][]string{"ignore_ports": {"tcp/8883"}}})
	if f := h.run("beaconing"); len(f) != 0 {
		t.Errorf("listed port fired: %+v", f)
	}
}

// byDomain gives every name a rank, as the offline lists would.
type byDomain struct {
	enrich.Nop
	rank map[string]int
}

func (b byDomain) Domain(name string) enrich.DomainInfo {
	return enrich.DomainInfo{Registered: baseDomain(name), Rank: b.rank[baseDomain(name)]}
}

func tlsName(ts time.Time, src, dst, name string) *event.Event {
	return &event.Event{
		ID: event.NewID(), Timestamp: ts, Event: event.Meta{Module: event.ModuleSuricata, Dataset: "suricata.tls"},
		Source: &event.Endpoint{IP: src}, Destination: &event.Endpoint{IP: dst, Port: 443, Domain: name},
	}
}

func TestBeaconingCaps(t *testing.T) {
	h := newHarness(t)
	h.enrich = byDomain{rank: map[string]int{"popular.example": 500}}
	// Popular and one device: low, and said so.
	h.beat("192.168.20.5", "198.51.100.20", 443, "tcp", 5*time.Minute, 20)
	h.insert(tlsName(h.now.Add(-time.Hour), "192.168.20.5", "198.51.100.20", "api.popular.example"))
	f := h.run("beaconing")
	if len(f) != 1 || f[0].Severity != store.SevLow || !strings.Contains(f[0].Description, "popular") {
		t.Fatalf("popular alone %+v", f)
	}
	// Popular and a second device: left out.
	h = newHarness(t)
	h.enrich = byDomain{rank: map[string]int{"popular.example": 500}}
	h.beat("192.168.20.5", "198.51.100.20", 443, "tcp", 5*time.Minute, 20)
	h.beat("192.168.20.6", "198.51.100.21", 443, "tcp", 5*time.Minute, 20)
	h.insert(tlsName(h.now.Add(-time.Hour), "192.168.20.5", "198.51.100.20", "api.popular.example"),
		tlsName(h.now.Add(-time.Hour), "192.168.20.6", "198.51.100.21", "api.popular.example"))
	if f := h.run("beaconing"); len(f) != 0 {
		t.Fatalf("popular and shared %+v", f)
	}
	// Three devices at one unnamed address: a common service.
	h = newHarness(t)
	for _, s := range []string{"192.168.20.5", "192.168.20.6", "192.168.20.7"} {
		h.beat(s, "198.51.100.30", 8443, "tcp", 5*time.Minute, 20)
	}
	if f := h.run("beaconing"); len(f) != 0 {
		t.Fatalf("shared %+v", f)
	}
	// A client polling many servers the same way is held to its fan-out budget.
	h = newHarness(t)
	h.settings("beaconing", DetectorSetting{Values: map[string]float64{"fanout_per_day": 2}})
	for i := range 5 {
		h.beat("192.168.20.5", fmt.Sprintf("198.51.100.%d", 40+i), 8443, "tcp", 5*time.Minute, 20)
	}
	if f := h.run("beaconing"); len(f) != 2 {
		t.Fatalf("fan-out %d findings", len(f))
	}
}

func TestDataStatus(t *testing.T) {
	h := newHarness(t)
	h.run("beaconing")
	if st := h.status("beaconing"); st.State != StatusNeedData || !strings.Contains(st.DataNeeded, "NetFlow") {
		t.Fatalf("no data %+v", st)
	}
	h.run("upload_spike")
	if st := h.status("upload_spike"); st.State != StatusNeedData {
		t.Fatalf("no flows %+v", st)
	}
	h.run("dns_tunnel")
	if st := h.status("dns_tunnel"); st.State != StatusNeedData || !strings.Contains(st.DataNeeded, "Unbound") {
		t.Fatalf("no DNS %+v", st)
	}
	// Firewall rows are a partial view for traffic detectors, enough for others, and no
	// help for an upload spike.
	h.insert(fwRow(h.now.Add(-time.Hour), "pass", event.DirectionOutbound, "203.0.113.9", 40000, "1.1.1.1", 443, "tcp"))
	h.run("beaconing")
	if st := h.status("beaconing"); st.State != StatusLimited || !strings.Contains(st.DataNeeded, "firewall rows only") {
		t.Fatalf("firewall only %+v", st)
	}
	h.run("upload_spike")
	if st := h.status("upload_spike"); st.State != StatusNeedData {
		t.Fatalf("firewall only, upload %+v", st)
	}
	h.run("internal_scan")
	if st := h.status("internal_scan"); st.State != StatusOK || st.DataNeeded != "" {
		t.Fatalf("firewall is enough for a scan %+v", st)
	}
	h.keepFlowsVisible()
	h.run("beaconing")
	if st := h.status("beaconing"); st.State != StatusOK {
		t.Fatalf("with flows %+v", st)
	}
	// Status survives a restart.
	fresh := New(h.r.d)
	if err := fresh.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := fresh.Statuses()[0]; st.State != StatusOK || st.LastRun == nil || st.Title != "Beaconing" {
		t.Fatalf("reloaded %+v", st)
	}
}

func TestLearningRestartsWhenNetFlowArrives(t *testing.T) {
	h := newHarness(t)
	h.insert(fwRow(h.now.Add(-time.Minute), "pass", event.DirectionInbound, "192.168.20.5", 40000, "1.1.1.1", 443, "tcp"))
	h.run("unusual_port")
	first := h.status("unusual_port")
	if first.State != StatusLearning || first.LearningUntil == nil || !first.LearningUntil.Equal(h.now.AddDate(0, 0, 7)) {
		t.Fatalf("first %+v", first)
	}
	h.now = h.now.AddDate(0, 0, 10)
	h.insert(fwRow(h.now.Add(-time.Minute), "pass", event.DirectionInbound, "192.168.20.5", 40000, "1.1.1.1", 443, "tcp"))
	h.run("unusual_port")
	if st := h.status("unusual_port"); st.State != StatusLimited {
		t.Fatalf("after learning, firewall only %+v", st)
	}
	h.keepFlowsVisible()
	h.run("unusual_port")
	if st := h.status("unusual_port"); st.State != StatusLearning || !st.LearningUntil.Equal(h.now.AddDate(0, 0, 7)) {
		t.Fatalf("NetFlow arriving %+v", st)
	}
}

func TestDNSTunnel(t *testing.T) {
	h := newHarness(t)
	ts := h.now.Add(-10 * time.Minute)
	var evs []*event.Event
	rng := rand.New(rand.NewSource(1))
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	randLabel := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = chars[rng.Intn(len(chars))]
		}
		return string(b)
	}
	// Long encoded labels under one zone.
	for range 30 {
		evs = append(evs, dnsRow(ts, "192.168.20.5", randLabel(40)+".t.evil.example"))
	}
	// Many short random labels under another.
	for range 120 {
		evs = append(evs, dnsRow(ts, "192.168.20.6", randLabel(16)+".dga.example"))
	}
	// An agent's own lookups, which have no client address.
	for range 30 {
		e := dnsRow(ts, "127.0.0.1", randLabel(40)+".agent.example")
		e.Event.Module = event.ModuleEBPF
		e.Host = event.Host{ID: "tower", Name: "tower"}
		evs = append(evs, e)
	}
	h.insert(evs...)
	f := h.run("dns_tunnel")
	if len(f) != 3 {
		t.Fatalf("findings %d: %+v", len(f), f)
	}
	seen := map[string]Finding{}
	for _, x := range f {
		seen[x.Data["domain"].(string)] = x
	}
	if x := seen["evil.example"]; x.Severity != store.SevMedium || x.Source.IP != "192.168.20.5" || x.Data["long_names"] != 30 {
		t.Fatalf("long labels %+v", x)
	}
	if x := seen["dga.example"]; x.Source.IP != "192.168.20.6" || x.Data["unique_names"] != 120 {
		t.Fatalf("random labels %+v", x)
	}
	if x := seen["agent.example"]; x.Source != nil || !strings.Contains(x.Title, "tower") {
		t.Fatalf("agent %+v", x)
	}
	if f := h.run("dns_tunnel"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
}

func TestDNSTunnelBenign(t *testing.T) {
	h := newHarness(t)
	h.enrich = byDomain{rank: map[string]int{"popular.example": 50}}
	ts := h.now.Add(-10 * time.Minute)
	long := strings.Repeat("abcdef0123456789", 3)
	var evs []*event.Event
	for i := range 150 {
		evs = append(evs,
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("%s%d.cloudfront.net", long, i)),  // a CDN numbers its hosts
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("%s%d.popular.example", long, i)), // popular list
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("%s%d.local", long, i)),           // local only
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("%d.20.168.192.in-addr.arpa", i)), // reverse lookups
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("img%d.photos.example", i)),       // many names, none random
			dnsRow(ts, "203.0.113.7", fmt.Sprintf("%s%d.outsider.example", long, i)), // not a device here
			dnsRow(ts, "192.168.20.5", fmt.Sprintf("%s%d.listed.example", long, i)),  // listed below
		)
	}
	// A handful of long names is not a tunnel.
	for i := range 5 {
		evs = append(evs, dnsRow(ts, "192.168.20.5", fmt.Sprintf("%s%d.few.example", long, i)))
	}
	h.insert(evs...)
	h.settings("dns_tunnel", DetectorSetting{Lists: map[string][]string{"ignore_domains": {"listed.example"}}})
	if f := h.run("dns_tunnel"); len(f) != 0 {
		for _, x := range f {
			t.Errorf("fired: %s", x.Description)
		}
	}
}

func TestDNSBypass(t *testing.T) {
	h := newHarness(t)
	ts := func() time.Time { return h.now.Add(-time.Minute) }
	h.keepFlowsVisible()
	h.insert(flow(ts(), "192.168.20.40", 50000, "8.8.8.8", 53, "udp", 80)) // a camera with a hardcoded resolver
	if f := h.run("dns_bypass"); len(f) != 0 {
		t.Fatalf("during learning %+v", f)
	}
	if st := h.status("dns_bypass"); st.State != StatusLearning {
		t.Fatalf("status %+v", st)
	}
	h.now = h.now.AddDate(0, 0, 4)
	h.keepFlowsVisible()
	h.insert(
		flow(ts(), "192.168.20.40", 50000, "8.8.8.8", 53, "udp", 80),      // learned
		flow(ts(), "192.168.20.5", 50000, "192.168.20.1", 53, "udp", 80),  // the firewall
		flow(ts(), "192.168.20.5", 50000, "192.168.10.1", 53, "udp", 80),  // the firewall on another VLAN
		flow(ts(), "192.168.20.5", 50000, "192.168.20.53", 53, "udp", 80), // approved below
		flow(ts(), "8.8.8.8", 53, "192.168.20.5", 50000, "udp", 80),       // a reply
		flow(ts(), "203.0.113.9", 50000, "8.8.8.8", 53, "udp", 80),        // the firewall's own lookups
		fwRow(ts(), "block", event.DirectionInbound, "192.168.20.6", 50000, "9.9.9.9", 853, "tcp"),
		fwRow(ts(), "block", event.DirectionInbound, "192.168.20.6", 50001, "9.9.9.9", 853, "tcp"),
		flow(ts(), "192.168.20.7", 50000, "1.1.1.1", 53, "udp", 80),
	)
	h.settings("dns_bypass", DetectorSetting{Lists: map[string][]string{"approved_resolvers": {"192.168.20.53"}}})
	f := h.run("dns_bypass")
	if len(f) != 2 {
		t.Fatalf("findings %+v", f)
	}
	var dot, plain Finding
	for _, x := range f {
		if x.Data["port"] == 853 {
			dot = x
		} else {
			plain = x
		}
	}
	if dot.Severity != store.SevLow || dot.Source.IP != "192.168.20.6" || dot.Data["blocked"] != float64(2) || !strings.Contains(dot.Description, "DNS over TLS") {
		t.Fatalf("DoT %+v", dot)
	}
	if plain.Source.IP != "192.168.20.7" || plain.Destination.IP != "1.1.1.1" || !strings.Contains(plain.Description, "plain DNS") {
		t.Fatalf("plain %+v", plain)
	}
	if f := h.run("dns_bypass"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
}

func TestUploadSpike(t *testing.T) {
	h := newHarness(t)
	const camera, laptop, phone, quiet = "192.168.20.40", "192.168.20.5", "192.168.20.6", "192.168.20.7"
	const mb = int64(1_000_000)
	// One hour on each of ten days at the same hour of day. Clock: half past the next hour.
	hourOf := func(day int) (time.Time, time.Time) {
		start := time.Date(2026, 11, 1+day, 10, 0, 0, 0, time.UTC)
		return start, start.Add(time.Hour + 31*time.Minute)
	}
	upload := func(start time.Time, src string, bytes int64) *event.Event {
		return flow(start.Add(10*time.Minute), src, 50000, "198.51.100.77", 443, "tcp", bytes)
	}
	for day := range 9 {
		start, now := hourOf(day)
		h.now = now
		h.insert(upload(start, camera, 340*mb), upload(start, laptop, 20*mb), upload(start, phone, 400*mb), upload(start, quiet, mb))
		if f := h.run("upload_spike"); len(f) != 0 {
			t.Fatalf("day %d: %+v", day, f)
		}
		if st := h.status("upload_spike"); day < 7 && st.State != StatusLearning {
			t.Fatalf("day %d: %+v", day, st)
		}
		// Each hour counts once, however often the detector runs.
		if f := h.run("upload_spike"); len(f) != 0 {
			t.Fatalf("second run %+v", f)
		}
	}
	start, now := hourOf(9)
	h.now = now
	h.insert(
		upload(start, camera, 700*mb),  // twice its normal: not enough
		upload(start, laptop, 2000*mb), // 100 times its normal
		upload(start, phone, 450*mb),   // about its normal
		upload(start, quiet, 200*mb),   // 200 times, but small
		flow(start.Add(time.Minute), "198.51.100.77", 443, laptop, 50000, "tcp", 9000*mb), // a download
	)
	f := h.run("upload_spike")
	if len(f) != 1 {
		t.Fatalf("findings %+v", f)
	}
	got := f[0]
	if got.Severity != store.SevMedium || got.Source.IP != laptop || got.Data["bytes"] != 2000*mb || got.Data["normal_bytes"] != float64(20*mb) {
		t.Fatalf("finding %+v", got)
	}
	if !strings.Contains(got.Description, "2.0 GB") || !strings.Contains(got.Description, "100 times") || !strings.Contains(got.Description, "198.51.100.77") {
		t.Fatalf("text %s", got.Description)
	}
}

func TestUnusualPort(t *testing.T) {
	h := newHarness(t)
	ts := func() time.Time { return h.now.Add(-time.Minute) }
	h.insert(flow(ts(), "192.168.20.5", 50000, "198.51.100.1", 8443, "tcp", 500))
	if f := h.run("unusual_port"); len(f) != 0 {
		t.Fatalf("learning %+v", f)
	}
	h.now = h.now.AddDate(0, 0, 8)
	h.insert(
		flow(ts(), "192.168.20.5", 50000, "198.51.100.1", 8443, "tcp", 500),  // learned
		flow(ts(), "192.168.20.5", 50000, "198.51.100.1", 443, "tcp", 500),   // always usual
		flow(ts(), "192.168.20.5", 50000, "198.51.100.1", 40000, "udp", 500), // high UDP: games and calls
		flow(ts(), "192.168.20.5", 443, "198.51.100.1", 52000, "tcp", 500),   // a reply from a service here
		flow(ts(), "192.168.20.5", 50000, "192.168.20.9", 4444, "tcp", 500),  // not the internet
		flow(ts(), "203.0.113.9", 50000, "198.51.100.1", 4445, "tcp", 500),   // the firewall itself
		fwRow(ts(), "block", event.DirectionInbound, "192.168.20.5", 50000, "198.51.100.1", 4446, "tcp"),
		flow(ts(), "192.168.20.5", 50000, "198.51.100.1", 8883, "tcp", 500), // listed below
		flow(ts(), "192.168.20.6", 50000, "198.51.100.2", 4444, "tcp", 500),
		flow(ts(), "192.168.20.6", 50001, "198.51.100.3", 4444, "tcp", 500),
		flow(ts(), "192.168.20.7", 50000, "198.51.100.1", 4444, "tcp", 500),
	)
	h.settings("unusual_port", DetectorSetting{Lists: map[string][]string{"allowed_ports": {"tcp/8883"}}})
	f := h.run("unusual_port")
	if len(f) != 2 { // two devices started on the new port in the same run
		t.Fatalf("findings %+v", f)
	}
	got := f[0]
	if got.Severity != store.SevLow || got.Source.IP != "192.168.20.6" || got.Data["port"] != "tcp/4444" || got.Data["destinations"] != 2 {
		t.Fatalf("finding %+v", got)
	}
	// Now the house has used it.
	h.insert(flow(ts(), "192.168.20.8", 50000, "198.51.100.1", 4444, "tcp", 500))
	if f := h.run("unusual_port"); len(f) != 0 {
		t.Fatalf("after the first report %+v", f)
	}
}

func TestInternalScan(t *testing.T) {
	h := newHarness(t)
	ts := h.now.Add(-5 * time.Minute)
	var evs []*event.Event
	for i := range 40 {
		// A sweep across hosts, and across the ports of one host.
		evs = append(evs,
			fwRow(ts, "block", event.DirectionInbound, "192.168.20.66", 50000+i, fmt.Sprintf("192.168.10.%d", i+2), 445, "tcp"),
			flow(ts, "192.168.20.67", 50000+i, "192.168.10.200", 1+i, "tcp", 60),
		)
	}
	h.insert(evs...)
	f := h.run("internal_scan")
	if len(f) != 2 {
		t.Fatalf("findings %+v", f)
	}
	var hosts, ports Finding
	for _, x := range f {
		if x.Source.IP == "192.168.20.66" {
			hosts = x
		} else {
			ports = x
		}
	}
	if hosts.Severity != store.SevMedium || hosts.Data["hosts"] != 40 || !strings.Contains(hosts.Description, "40 other addresses") {
		t.Fatalf("hosts %+v", hosts)
	}
	if ports.Destination.IP != "192.168.10.200" || ports.Data["ports"] != float64(40) {
		t.Fatalf("ports %+v", ports)
	}
	if f := h.run("internal_scan"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
}

func TestInternalScanBenign(t *testing.T) {
	h := newHarness(t)
	ts := h.now.Add(-5 * time.Minute)
	var evs []*event.Event
	for i := range 40 {
		dest := fmt.Sprintf("192.168.10.%d", i+2)
		evs = append(evs,
			flow(ts, "192.168.20.5", 50000+i, "239.255.255.250", 1900, "udp", 100), // SSDP
			flow(ts, "192.168.20.5", 50000+i, dest, 5353, "udp", 100),              // mDNS
			flow(ts, "192.168.20.5", 50000+i, dest, 137, "udp", 100),               // NetBIOS
			flow(ts, "192.168.20.9", 445, dest, 50000+i, "tcp", 100),               // a file server replying
			flow(ts, "192.168.20.1", 50000+i, dest, 22, "tcp", 100),                // the firewall
			flow(ts, "192.168.20.8", 50000+i, dest, 22, "tcp", 100),                // listed below
			flow(ts, "192.168.20.7", 50000+i, "8.8.8.8", 1+i, "tcp", 100),          // not internal
		)
	}
	for i := range 10 { // below the thresholds
		evs = append(evs, flow(ts, "192.168.20.6", 50000+i, fmt.Sprintf("192.168.10.%d", i+2), 443, "tcp", 100),
			flow(ts, "192.168.20.6", 50000+i, "192.168.10.200", 1+i, "tcp", 100))
	}
	// Old traffic is out of the window.
	for i := range 40 {
		evs = append(evs, flow(h.now.Add(-2*time.Hour), "192.168.20.3", 50000+i, fmt.Sprintf("192.168.10.%d", i+2), 22, "tcp", 100))
	}
	h.insert(evs...)
	h.settings("internal_scan", DetectorSetting{Lists: map[string][]string{"allowed_scanners": {"192.168.20.8"}}})
	if f := h.run("internal_scan"); len(f) != 0 {
		for _, x := range f {
			t.Errorf("fired: %s", x.Description)
		}
	}
}

func withFlags(ev *event.Event, flags string) *event.Event {
	ev.Data = map[string]any{"tcp_flags": flags}
	return ev
}

// NetFlow has both directions of every conversation. A service on a high port answering a
// client's lower ephemeral ports passes the port rule, so the flags and the reverse records
// must keep it from looking like a scan, while real scans still count.
func TestInternalScanReplies(t *testing.T) {
	h := newHarness(t)
	ts := h.now.Add(-5 * time.Minute)
	const printer, master = "192.168.20.189", "192.168.10.52"
	var evs []*event.Event
	for i := range 40 {
		cport := 40000 + i*100
		evs = append(evs,
			// The printer: a session on its port 53048, and its status port 3910.
			withFlags(flow(ts, master, cport, printer, 53048, "tcp", 500), "FSPA"),
			withFlags(flow(ts, printer, 53048, master, cport, "tcp", 900), "FSPA"),
			withFlags(flow(ts, printer, 53048, master, cport, "tcp", 300), "A"),
			withFlags(flow(ts, master, cport+1, printer, 3910, "tcp", 500), "FSPA"),
			withFlags(flow(ts, printer, 3910, master, cport+1, "tcp", 900), "FSPA"),
			// A server on a high port answering 40 hosts.
			withFlags(flow(ts, fmt.Sprintf("192.168.10.%d", i+2), 30000+i, "192.168.20.90", 60000, "tcp", 500), "SPA"),
			withFlags(flow(ts, "192.168.20.90", 60000, fmt.Sprintf("192.168.10.%d", i+2), 30000+i, "tcp", 500), "SPA"),
			// A SYN scan from one source port, answered with resets.
			withFlags(flow(ts, "192.168.20.70", 61000, "192.168.10.201", 1+i, "tcp", 44), "S"),
			withFlags(flow(ts, "192.168.10.201", 1+i, "192.168.20.70", 61000, "tcp", 40), "RA"),
			// A connect scan of open ports, a new source port each time.
			withFlags(flow(ts, "192.168.20.71", 50000+i, "192.168.10.202", 1000+i, "tcp", 120), "FSA"),
			withFlags(flow(ts, "192.168.10.202", 1000+i, "192.168.20.71", 50000+i, "tcp", 120), "FSA"),
		)
	}
	// The printer opening a few connections of its own still counts, below the threshold.
	evs = append(evs, withFlags(flow(ts, printer, 43220, master, 5357, "tcp", 60), "S"))
	h.insert(evs...)
	got := map[string]Finding{}
	for _, x := range h.run("internal_scan") {
		got[x.Source.IP] = x
	}
	if len(got) != 2 {
		for _, x := range got {
			t.Errorf("finding: %s", x.Description)
		}
		t.FailNow()
	}
	for _, src := range []string{"192.168.20.70", "192.168.20.71"} {
		if x, ok := got[src]; !ok || x.Data["ports"] != float64(40) || !strings.Contains(x.Title, "Port scan") {
			t.Errorf("%s: %+v", src, x)
		}
	}
}

func TestRogueDHCP(t *testing.T) {
	h := newHarness(t)
	ts := func() time.Time { return h.now.Add(-time.Minute) }
	reply := func(src string) *event.Event {
		return fwRow(ts(), "block", event.DirectionInbound, src, 67, "255.255.255.255", 68, "udp")
	}
	h.insert(reply("192.168.20.2"), reply("192.168.20.1"))
	if f := h.run("rogue_dhcp"); len(f) != 0 {
		t.Fatalf("learning %+v", f)
	}
	h.now = h.now.AddDate(0, 0, 4)
	h.insert(reply("192.168.20.2"), reply("192.168.20.1"), reply("192.168.10.1"), reply("192.168.20.3"), reply("192.168.20.99"),
		fwRow(ts(), "pass", event.DirectionInbound, "192.168.20.98", 68, "192.168.20.1", 67, "udp")) // a client asking
	h.settings("rogue_dhcp", DetectorSetting{Lists: map[string][]string{"approved_servers": {"192.168.20.3"}}})
	f := h.run("rogue_dhcp")
	if len(f) != 1 || f[0].Source.IP != "192.168.20.99" || f[0].Severity != store.SevMedium || !strings.Contains(f[0].Description, "answered DHCP 1 times") {
		t.Fatalf("findings %+v", f)
	}
	if f := h.run("rogue_dhcp"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
}

func TestExposure(t *testing.T) {
	h := newHarness(t)
	ts := func() time.Time { return h.now.Add(-time.Minute) }
	inbound := func(action, src, dst string, port int) *event.Event {
		return fwRow(ts(), action, event.DirectionInbound, src, 50000, dst, port, "tcp")
	}
	h.insert(inbound("pass", "198.51.100.1", "192.168.20.20", 443)) // an existing port forward
	if f := h.run("exposure"); len(f) != 0 {
		t.Fatalf("learning %+v", f)
	}
	h.now = h.now.AddDate(0, 0, 4)
	h.keepFlowsVisible()
	h.insert(
		inbound("pass", "198.51.100.1", "192.168.20.20", 443),               // learned
		inbound("block", "198.51.100.2", "192.168.20.30", 22),               // blocked
		inbound("pass", "192.168.10.5", "192.168.20.30", 22),                // from inside
		inbound("pass", "100.100.1.1", "192.168.20.30", 23),                 // from a Tailscale peer
		inbound("pass", "203.0.113.9", "192.168.20.30", 24),                 // the firewall's own WAN address: hairpin
		inbound("pass", "198.51.100.3", "192.168.20.21", 8443),              // listed below
		flow(ts(), "198.51.100.4", 443, "192.168.20.31", 52000, "tcp", 900), // a reply to a client
		flow(ts(), "198.51.100.4", 53, "192.168.20.31", 52000, "udp", 900),  // a DNS reply
		inbound("pass", "198.51.100.5", "192.168.20.30", 8080),
		inbound("pass", "198.51.100.6", "192.168.20.30", 8080),
		flow(ts(), "198.51.100.7", 50000, "192.168.20.32", 22, "tcp", 900),
	)
	h.settings("exposure", DetectorSetting{Lists: map[string][]string{"expected": {"192.168.20.21:8443"}}})
	f := h.run("exposure")
	if len(f) != 2 {
		for _, x := range f {
			t.Errorf("found: %s", x.Description)
		}
		t.Fatalf("%d findings", len(f))
	}
	var fw, nf Finding
	for _, x := range f {
		if x.Destination.Port == 8080 {
			fw = x
		} else {
			nf = x
		}
	}
	if fw.Severity != store.SevMedium || fw.Destination.IP != "192.168.20.30" || fw.Data["public_sources"] != 2 || !strings.Contains(fw.Description, "tcp/8080") {
		t.Fatalf("firewall %+v", fw)
	}
	if nf.Destination.IP != "192.168.20.32" || nf.Destination.Port != 22 {
		t.Fatalf("NetFlow %+v", nf)
	}
	if f := h.run("exposure"); len(f) != 0 {
		t.Fatalf("repeat %+v", f)
	}
}

func TestSettings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	views := h.r.DetectorViews()
	if len(views) != 8 {
		t.Fatalf("%d detectors", len(views))
	}
	want := map[string]float64{"min_count": 10, "min_span_sec": 600, "max_cv": 0.15, "min_interval_sec": 5, "reported_days": 7}
	for k, v := range want {
		if views[0].Values[k] != v {
			t.Errorf("default %s = %v", k, views[0].Values[k])
		}
	}
	for _, v := range views {
		if !v.Enabled || v.About == "" || len(v.Thresholds) == 0 {
			t.Errorf("view %+v", v)
		}
		for _, th := range v.Thresholds {
			if th.Help == "" || th.Default < th.Min || th.Default > th.Max {
				t.Errorf("%s/%s: %+v", v.ID, th.Key, th)
			}
		}
	}
	bad := []Settings{
		{Detectors: map[string]DetectorSetting{"nope": {}}},
		{Detectors: map[string]DetectorSetting{"beaconing": {Values: map[string]float64{"nope": 1}}}},
		{Detectors: map[string]DetectorSetting{"beaconing": {Values: map[string]float64{"max_cv": 5}}}},
		{Detectors: map[string]DetectorSetting{"beaconing": {Lists: map[string][]string{"nope": {"x"}}}}},
		{Detectors: map[string]DetectorSetting{"dns_bypass": {Lists: map[string][]string{"approved_resolvers": {"not an ip"}}}}},
		{Detectors: map[string]DetectorSetting{"exposure": {Lists: map[string][]string{"expected": {"http"}}}}},
	}
	for _, s := range bad {
		var ie *InputError
		if err := h.r.SetSettings(ctx, s); !errors.As(err, &ie) {
			t.Errorf("%+v: %v", s, err)
		}
	}
	// Entries are stored the way detectors compare them.
	h.settings("beaconing", DetectorSetting{Lists: map[string][]string{"benign_domains": {"Vendor.Example."}}})
	h.settings("dns_bypass", DetectorSetting{Lists: map[string][]string{"approved_resolvers": {"::ffff:192.168.20.53"}}})
	for _, v := range h.r.DetectorViews() {
		if v.ID == "dns_bypass" && v.Lists["approved_resolvers"][0] != "192.168.20.53" {
			t.Errorf("address %v", v.Lists)
		}
	}
	h.settings("beaconing", DetectorSetting{Lists: map[string][]string{"benign_domains": {"Vendor.Example."}}})
	if got := h.r.DetectorViews()[0].Lists["benign_domains"][0]; got != "vendor.example" {
		t.Errorf("domain %q", got)
	}
	var ie *InputError
	if err := h.r.SetSettings(ctx, Settings{Detectors: map[string]DetectorSetting{"beaconing": {Lists: map[string][]string{"benign_domains": {"justaword"}}}}}); !errors.As(err, &ie) {
		t.Errorf("a bare word as a domain: %v", err)
	}
	// A toggle stops the detector, and its status says so.
	off := false
	h.beat("192.168.20.5", "198.51.100.10", 8443, "tcp", 5*time.Minute, 20)
	h.settings("beaconing", DetectorSetting{Enabled: &off})
	if f := h.run("beaconing"); len(f) != 0 {
		t.Fatalf("disabled detector fired: %+v", f)
	}
	if st := h.status("beaconing"); st.State != StatusDisabled || st.Enabled {
		t.Fatalf("status %+v", st)
	}
	// Thresholds apply and survive a restart.
	h.settings("beaconing", DetectorSetting{Values: map[string]float64{"min_count": 50}})
	if f := h.run("beaconing"); len(f) != 0 {
		t.Fatalf("threshold ignored: %+v", f)
	}
	fresh := New(h.r.d)
	if err := fresh.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v := fresh.DetectorViews()[0]; v.Values["min_count"] != 50 || !v.Enabled {
		t.Fatalf("reloaded %+v", v)
	}
}

func TestScheduleOneAtATime(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for range h.r.specs {
		s := h.r.nextDue()
		if s == nil || seen[s.ID] {
			t.Fatalf("next %+v", s)
		}
		seen[s.ID] = true
		h.r.runOne(context.Background(), s)
	}
	if s := h.r.nextDue(); s != nil {
		t.Fatalf("%s is due right after running", s.ID)
	}
	h.now = h.now.Add(defaultEvery)
	got := map[string]bool{}
	for {
		s := h.r.nextDue()
		if s == nil {
			break
		}
		got[s.ID] = true
		h.r.runOne(context.Background(), s)
	}
	if got["beaconing"] || len(got) != len(h.r.specs)-1 {
		t.Fatalf("due after 15 minutes: %v", got)
	}
	h.now = h.now.Add(time.Hour)
	if !func() bool {
		for range h.r.specs {
			if s := h.r.nextDue(); s != nil && s.ID == "beaconing" {
				return true
			}
		}
		return false
	}() {
		t.Fatal("beaconing not due after an hour")
	}
}

func TestPerRunCap(t *testing.T) {
	h := newHarness(t)
	for i := range maxFindingsPerRun + 5 {
		h.beat(fmt.Sprintf("192.168.20.%d", i+2), fmt.Sprintf("198.51.100.%d", i+2), 8443, "tcp", 5*time.Minute, 12)
	}
	if f := h.run("beaconing"); len(f) != maxFindingsPerRun {
		t.Fatalf("%d findings", len(f))
	}
	if f := h.run("beaconing"); len(f) != 5 {
		t.Fatalf("the rest: %d findings", len(f))
	}
}

func TestPortItems(t *testing.T) {
	for _, s := range []string{"443", "tcp/443", "192.168.20.20:443", "192.168.20.20:udp/443"} {
		if _, _, _, ok := parsePortItem(s); !ok {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range []string{"", "http", "tcp/", "icmp/1", "99999", "1.2.3.4:"} {
		if _, _, _, ok := parsePortItem(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
	list := []string{"192.168.20.20:443", "udp/53", "8080"}
	cases := []struct {
		ip, proto string
		port      int
		want      bool
	}{
		{"192.168.20.20", "tcp", 443, true},
		{"192.168.20.21", "tcp", 443, false},
		{"", "udp", 53, true},
		{"", "tcp", 53, false},
		{"", "tcp", 8080, true},
	}
	for _, c := range cases {
		if got := portListed(list, c.ip, c.proto, c.port); got != c.want {
			t.Errorf("%+v = %v", c, got)
		}
	}
}
