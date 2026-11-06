package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const testPassword = "s3cret-pass-do-not-leak"

// fakeAdGuard serves /control/status and /control/querylog like AdGuard Home does: newest
// first, older_than exclusive, "oldest" naming the last entry returned.
type fakeAdGuard struct {
	mu      sync.Mutex
	entries []map[string]any // newest first
	calls   int
}

func (f *fakeAdGuard) add(t time.Time, client, name, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := map[string]any{
		"time": t.Format(time.RFC3339Nano), "client": client,
		"question": map[string]any{"class": "IN", "name": name, "type": "A"},
		"status":   "NOERROR", "reason": reason, "elapsedMs": "1.5", "upstream": "https://dns10.quad9.net:443/dns-query",
		"answer":      []map[string]any{{"type": "A", "value": "93.184.216.34", "ttl": 60}},
		"client_info": map[string]any{"name": "laptop"},
	}
	f.entries = append([]map[string]any{e}, f.entries...)
}

func (f *fakeAdGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "admin" || p != testPassword {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/control/status":
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "v0.107.79", "running": true})
	case "/control/querylog":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var older time.Time
		if s := r.URL.Query().Get("older_than"); s != "" {
			older, _ = time.Parse(time.RFC3339Nano, s)
		}
		out := []map[string]any{}
		for _, e := range f.entries {
			t, _ := time.Parse(time.RFC3339Nano, e["time"].(string))
			if !older.IsZero() && !t.Before(older) {
				continue
			}
			if len(out) == limit {
				break
			}
			out = append(out, e)
		}
		oldest := ""
		if len(out) > 0 {
			oldest = out[len(out)-1]["time"].(string)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out, "oldest": oldest})
	default:
		http.NotFound(w, r)
	}
}

func newTestPoller(t *testing.T) (*Poller, *[]*event.Event) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var mu sync.Mutex
	got := &[]*event.Event{}
	p := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), func(_ context.Context, evs []*event.Event) error {
		mu.Lock()
		defer mu.Unlock()
		*got = append(*got, evs...)
		return nil
	})
	if err := p.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p, got
}

func TestPollStartsFromNowThenReadsOnlyNewLookups(t *testing.T) {
	fake := &fakeAdGuard{}
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		fake.add(base.Add(time.Duration(i)*time.Second), "192.168.20.5", fmt.Sprintf("old%d.example", i), "NotFilteredNotFound")
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	p, got := newTestPoller(t)
	ctx := context.Background()
	if _, err := p.Save(ctx, Input{Settings: Settings{Enabled: true, URL: srv.URL, Username: "admin", Password: testPassword}}); err != nil {
		t.Fatal(err)
	}
	set := p.settings()

	// First poll: history before turning it on is not imported.
	p.pollOnce(ctx, set)
	if len(*got) != 0 {
		t.Fatalf("first poll imported %d old lookups", len(*got))
	}

	// 1,234 new lookups span three pages; two share the cursor's instant later.
	for i := 0; i < 1234; i++ {
		fake.add(base.Add(time.Minute+time.Duration(i)*time.Millisecond), "192.168.20.7", fmt.Sprintf("n%d.example", i), "NotFilteredNotFound")
	}
	p.pollOnce(ctx, set)
	if len(*got) != 1234 {
		t.Fatalf("got %d lookups, want 1234", len(*got))
	}
	if (*got)[0].DNS.Question.Name != "n0.example" || (*got)[1233].DNS.Question.Name != "n1233.example" {
		t.Fatalf("not oldest first: %s .. %s", (*got)[0].DNS.Question.Name, (*got)[1233].DNS.Question.Name)
	}

	// Two more at the same instant as the newest seen, plus one later: only those three.
	last := base.Add(time.Minute + 1233*time.Millisecond)
	fake.add(last, "192.168.20.8", "same-instant.example", "NotFilteredNotFound")
	fake.add(last.Add(time.Second), "192.168.20.8", "blocked.example", "FilteredBlackList")
	p.pollOnce(ctx, set)
	if len(*got) != 1236 {
		t.Fatalf("got %d lookups after the third poll, want 1236", len(*got))
	}
	p.pollOnce(ctx, set)
	if len(*got) != 1236 {
		t.Fatalf("an idle poll stored %d more", len(*got)-1236)
	}
	v := p.View()
	if v.Status.State != "ok" || v.Status.Imported != 1236 || v.Status.Version != "v0.107.79" {
		t.Fatalf("status = %+v", v.Status)
	}
	b := (*got)[1235]
	if b.Event.Action != "dns-blocked" || b.Event.Outcome != event.OutcomeFailure {
		t.Fatalf("blocked lookup: action %q outcome %q", b.Event.Action, b.Event.Outcome)
	}
}

func TestEventShape(t *testing.T) {
	var e Entry
	raw := `{"answer":[{"type":"A","value":"93.184.216.34","ttl":60},{"type":"SOA","value":{"ns":"a"},"ttl":5}],
	  "cached":true,"client":"::ffff:192.168.20.5","client_info":{"name":"laptop"},"client_proto":"doh",
	  "elapsedMs":"0.43","question":{"class":"IN","name":"Example.COM.","type":"a"},
	  "reason":"NotFilteredNotFound","rules":[],"status":"NOERROR","time":"2026-11-06T04:00:00.123456789-06:00",
	  "upstream":"https://dns10.quad9.net:443/dns-query"}`
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	ev := e.Event()
	if ev == nil {
		t.Fatal("no event")
	}
	if ev.Event.Module != event.ModuleDNS || ev.Event.Dataset != Dataset || ev.Source.IP != "192.168.20.5" {
		t.Fatalf("module %q dataset %q source %q", ev.Event.Module, ev.Event.Dataset, ev.Source.IP)
	}
	if ev.DNS.Question.Name != "example.com" || ev.DNS.Question.Type != "A" || ev.DNS.ResponseCode != "NOERROR" {
		t.Fatalf("dns = %+v", ev.DNS)
	}
	if len(ev.DNS.ResolvedIP) != 1 || ev.DNS.ResolvedIP[0] != "93.184.216.34" || len(ev.DNS.Answers) != 2 {
		t.Fatalf("answers = %+v", ev.DNS)
	}
	if !ev.Timestamp.Equal(time.Date(2026, 11, 6, 10, 0, 0, 123456789, time.UTC)) {
		t.Fatalf("time = %v", ev.Timestamp)
	}
	d := ev.Data["adguard"].(map[string]any)
	if d["client_proto"] != "doh" || d["client_name"] != "laptop" || d["response_time_ms"] != 0.43 || d["cached"] != true {
		t.Fatalf("data = %v", d)
	}
	e.Client = "not-an-ip"
	if e.Event() != nil {
		t.Fatal("an entry without a client address made an event")
	}
}

func TestBadPasswordAndSecretsStayHidden(t *testing.T) {
	srv := httptest.NewServer(&fakeAdGuard{})
	defer srv.Close()
	p, _ := newTestPoller(t)
	ctx := context.Background()
	v, err := p.Save(ctx, Input{Settings: Settings{Enabled: true, URL: srv.URL, Username: "admin", Password: "wrong-" + testPassword}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	if strings.Contains(string(out), testPassword) || !v.PasswordSet {
		t.Fatalf("view leaks or forgets the password: %s", out)
	}
	p.pollOnce(ctx, p.settings())
	v = p.View()
	if v.Status.State != "error" || v.Status.LastError != ErrAuth.Error() {
		t.Fatalf("status = %+v", v.Status)
	}
	res, err := p.Test(ctx, Input{})
	if err != nil || res.OK || strings.Contains(res.Message, testPassword) {
		t.Fatalf("test with the stored wrong password = %+v, %v", res, err)
	}
	// An empty password keeps the stored one; the right one fixes it.
	res, err = p.Test(ctx, Input{Settings: Settings{URL: srv.URL, Username: "admin", Password: testPassword}})
	if err != nil || !res.OK || !strings.Contains(res.Message, "plain http") {
		t.Fatalf("test = %+v, %v", res, err)
	}
	if _, err := p.Save(ctx, Input{Settings: Settings{Enabled: true, URL: srv.URL, Username: "admin"}}); err != nil {
		t.Fatalf("saving without retyping the password: %v", err)
	}
	if p.settings().Password == "" {
		t.Fatal("an empty password field cleared the stored password")
	}
}

func TestSettingsValidation(t *testing.T) {
	p, _ := newTestPoller(t)
	ctx := context.Background()
	for _, in := range []Input{
		{Settings: Settings{Enabled: true, URL: "ftp://x", Username: "a", Password: "b"}},
		{Settings: Settings{Enabled: true, URL: "https://admin:pw@192.168.20.1:3001", Username: "a", Password: "b"}},
		{Settings: Settings{Enabled: true, URL: "https://192.168.20.1:3001/control", Username: "a", Password: "b"}},
		{Settings: Settings{Enabled: true, URL: "https://192.168.20.1:3001"}},
		{Settings: Settings{Enabled: true, URL: "https://192.168.20.1:3001", Username: "a", Password: "b", PinSHA256: "abc"}},
		{Settings: Settings{Enabled: true, URL: "http://192.168.20.1:3000", Username: "a", Password: "b", ServerName: "ads.example"}},
		{Settings: Settings{Enabled: true, URL: "https://192.168.20.1:3001", Username: "a", Password: "b", IntervalSec: 5}},
	} {
		if _, err := p.Save(ctx, in); err == nil {
			t.Errorf("accepted %+v", in.Settings)
		}
	}
	if _, err := p.Save(ctx, Input{}); err != nil {
		t.Fatalf("saving it off and empty: %v", err)
	}
}

func TestCertificateTrustByFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(&fakeAdGuard{})
	defer srv.Close()
	p, _ := newTestPoller(t)
	ctx := context.Background()
	in := Input{Settings: Settings{URL: srv.URL, Username: "admin", Password: testPassword}}
	res, err := p.Test(ctx, in)
	if err != nil || res.OK || res.Certificate == nil || len(res.Certificate.Fingerprint) != 95 {
		t.Fatalf("self-signed test = %+v, %v", res, err)
	}
	in.PinSHA256 = res.Certificate.Fingerprint
	if res, err = p.Test(ctx, in); err != nil || !res.OK {
		t.Fatalf("pinned test = %+v, %v", res, err)
	}
	in.PinSHA256 = strings.Repeat("ab", 32)
	if res, err = p.Test(ctx, in); err != nil || res.OK || !strings.Contains(res.Message, "certificate changed") {
		t.Fatalf("wrong pin test = %+v, %v", res, err)
	}
}
