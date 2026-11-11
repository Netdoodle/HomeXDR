package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// fakePiHole serves Pi-hole v6's /api/auth, /api/info/version and /api/queries: newest
// first, "cursor" pinning the newest id when paging began, "start" an offset.
type fakePiHole struct {
	mu       sync.Mutex
	queries  []map[string]any // newest first
	nextID   int64
	logins   int
	logouts  int
	sessions map[string]bool
}

func (f *fakePiHole) add(t time.Time, client, domain, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	q := map[string]any{
		"id": f.nextID, "time": float64(t.UnixNano()) / 1e9, "type": "A", "domain": domain, "status": status,
		"client": map[string]any{"ip": client, "name": "laptop.lan"}, "reply": map[string]any{"type": "IP", "time": 2.5},
		"upstream": "1.1.1.1#53", "dnssec": "UNKNOWN",
	}
	f.queries = append([]map[string]any{q}, f.queries...)
}

func (f *fakePiHole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessions == nil {
		f.sessions = map[string]bool{}
	}
	if r.URL.Path == "/api/auth" {
		switch r.Method {
		case http.MethodPost:
			var b struct{ Password string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.Password != testPassword {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"valid": false}})
				return
			}
			f.logins++
			sid := fmt.Sprintf("sid-%d", f.logins)
			f.sessions[sid] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"valid": true, "sid": sid, "validity": 1800}})
		case http.MethodDelete:
			delete(f.sessions, r.Header.Get("X-FTL-SID"))
			f.logouts++
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if !f.sessions[r.Header.Get("X-FTL-SID")] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/info/version":
		_ = json.NewEncoder(w).Encode(map[string]any{"version": map[string]any{"core": map[string]any{"local": map[string]any{"version": "v6.1"}}}})
	case "/api/queries":
		q := r.URL.Query()
		length, _ := strconv.Atoi(q.Get("length"))
		start, _ := strconv.Atoi(q.Get("start"))
		cursor, _ := strconv.ParseInt(q.Get("cursor"), 10, 64)
		until, _ := strconv.ParseFloat(q.Get("until"), 64)
		var match []map[string]any
		for _, e := range f.queries {
			if cursor > 0 && e["id"].(int64) > cursor {
				continue
			}
			if until > 0 && e["time"].(float64) > until {
				continue
			}
			match = append(match, e)
		}
		if cursor == 0 && len(match) > 0 {
			cursor = match[0]["id"].(int64)
		}
		out := []map[string]any{}
		for i := start; i < len(match) && len(out) < length; i++ {
			out = append(out, match[i])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"queries": out, "cursor": cursor, "recordsFiltered": len(match)})
	default:
		http.NotFound(w, r)
	}
}

func TestPiHolePollsWithOneSession(t *testing.T) {
	fake := &fakePiHole{}
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	fake.add(base, "192.168.20.5", "before.example", "FORWARDED")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	p, got := newTestPoller(t)
	ctx := context.Background()

	res, err := p.Test(ctx, Input{Settings: Settings{Kind: KindPiHole, URL: srv.URL, Username: "ignored", Password: testPassword}})
	if err != nil || !res.OK || !strings.Contains(res.Message, "Pi-hole v6.1") {
		t.Fatalf("test = %+v, %v", res, err)
	}
	if fake.logouts != 1 {
		t.Errorf("the connection test left its session open (logouts %d)", fake.logouts)
	}
	v, err := p.Save(ctx, Input{Settings: Settings{Kind: KindPiHole, Enabled: true, URL: srv.URL, Username: "ignored", Password: testPassword}})
	if err != nil || v.Kind != KindPiHole || v.Username != "" {
		t.Fatalf("save = %+v, %v", v, err)
	}
	p.pollOnce(ctx, p.settings()) // starts from now
	for i := 0; i < 1200; i++ {   // three pages
		fake.add(base.Add(time.Duration(i+1)*time.Millisecond), "192.168.20.5", fmt.Sprintf("n%d.example", i), "FORWARDED")
	}
	fake.add(base.Add(2*time.Second), "192.168.20.6", "ads.example", "GRAVITY")
	p.pollOnce(ctx, p.settings())
	p.pollOnce(ctx, p.settings())
	if st := p.View().Status; st.State != "ok" || len(*got) != 1201 {
		t.Fatalf("status %+v, stored %d", st, len(*got))
	}
	logins := fake.logins
	if logins != 2 { // one for the test, one for polling
		t.Errorf("logins = %d, want one session reused across polls", logins)
	}
	last := (*got)[len(*got)-1]
	if last.Event.Dataset != DatasetPiHole || last.Event.Action != "dns-blocked" || last.Observer.Product != "Pi-hole" {
		t.Fatalf("blocked event = %+v / %+v", last.Event, last.Observer)
	}
	d := last.Data["pihole"].(map[string]any)
	if d["reason"] != "GRAVITY" || d["client_name"] != "laptop.lan" || d["response_time_ms"] != 2.5 {
		t.Fatalf("data = %v", d)
	}
	first := (*got)[0]
	if first.DNS.ResponseCode != "NOERROR" || first.Event.Action != "dns-answer" || first.Source.IP != "192.168.20.5" {
		t.Fatalf("first = %+v %+v", first.Event, first.DNS)
	}

	// An expired session is replaced without an error.
	fake.mu.Lock()
	fake.sessions = map[string]bool{}
	fake.mu.Unlock()
	fake.add(base.Add(3*time.Second), "192.168.20.5", "after.example", "CACHE")
	p.pollOnce(ctx, p.settings())
	if st := p.View().Status; st.State != "ok" || len(*got) != 1202 {
		t.Fatalf("after expiry: status %+v, stored %d", st, len(*got))
	}
}

func TestPiHoleBackfill(t *testing.T) {
	fake := &fakePiHole{}
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 700; i++ {
		fake.add(base.Add(time.Duration(i)*time.Second), "192.168.20.5", fmt.Sprintf("old%d.example", i), "FORWARDED")
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	p, _ := newTestPoller(t)
	var hist []*event.Event
	var mu sync.Mutex
	p.SetHistory(func(_ context.Context, evs []*event.Event) error {
		mu.Lock()
		hist = append(hist, evs...)
		mu.Unlock()
		return nil
	})
	ctx := context.Background()
	if _, err := p.Save(ctx, Input{Settings: Settings{Kind: KindPiHole, Enabled: true, URL: srv.URL, Password: testPassword}}); err != nil {
		t.Fatal(err)
	}
	p.pollOnce(ctx, p.settings())
	if err := p.Backfill(ctx); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); p.BackfillState(ctx).State == "running"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("backfill did not finish")
		}
	}
	if st := p.BackfillState(ctx); st.State != "done" || len(hist) != 700 {
		t.Fatalf("status %+v, history %d", st, len(hist))
	}
}

// fakeTechnitium serves the Technitium API: the token in the form body, a query log app,
// and /api/logs/query pages, newest first.
type fakeTechnitium struct {
	mu      sync.Mutex
	entries []map[string]any // newest first
	noApp   bool
}

func (f *fakeTechnitium) add(t time.Time, client, name, rtype, answer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := map[string]any{
		"timestamp": t.Format(time.RFC3339Nano), "clientIpAddress": client, "protocol": "Udp",
		"responseType": rtype, "responseRtt": 4.25, "rcode": "NoError", "qname": name, "qtype": "A", "qclass": "IN", "answer": answer,
	}
	f.entries = append([]map[string]any{e}, f.entries...)
}

func (f *fakeTechnitium) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Query().Get("token") != "" {
		http.Error(w, "token in the address", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	if r.PostForm.Get("token") != testPassword {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
		return
	}
	ok := func(resp any) { _ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "response": resp}) }
	switch r.URL.Path {
	case "/api/user/session/get":
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": map[string]any{"version": "13.6"}})
	case "/api/apps/list":
		apps := []any{map[string]any{"name": "Split Horizon", "dnsApps": []any{map[string]any{"classPath": "SplitHorizon.App"}}}}
		if !f.noApp {
			apps = append(apps, map[string]any{"name": "Query Logs (Sqlite)", "dnsApps": []any{map[string]any{"classPath": "QueryLogsSqlite.App", "isQueryLogger": true}}})
		}
		ok(map[string]any{"apps": apps})
	case "/api/logs/query":
		if r.PostForm.Get("name") != "Query Logs (Sqlite)" || r.PostForm.Get("classPath") != "QueryLogsSqlite.App" {
			http.Error(w, "wrong app", http.StatusBadRequest)
			return
		}
		page, _ := strconv.Atoi(r.PostForm.Get("pageNumber"))
		per, _ := strconv.Atoi(r.PostForm.Get("entriesPerPage"))
		total := (len(f.entries) + per - 1) / per
		out := []map[string]any{}
		for i := (page - 1) * per; i < len(f.entries) && len(out) < per; i++ {
			out = append(out, f.entries[i])
		}
		ok(map[string]any{"pageNumber": page, "totalPages": total, "totalEntries": len(f.entries), "entries": out})
	default:
		http.NotFound(w, r)
	}
}

func TestTechnitiumPolls(t *testing.T) {
	fake := &fakeTechnitium{noApp: true}
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	fake.add(base, "192.168.20.5", "before.example", "Recursive", "93.184.216.34")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	p, got := newTestPoller(t)
	ctx := context.Background()

	in := Input{Settings: Settings{Kind: KindTechnitium, URL: srv.URL, Password: testPassword}}
	res, err := p.Test(ctx, in)
	if err != nil || res.OK || !strings.Contains(res.Message, "Query Logs (Sqlite)") {
		t.Fatalf("without a query log app: %+v, %v", res, err)
	}
	fake.noApp = false
	if res, err = p.Test(ctx, in); err != nil || !res.OK || !strings.Contains(res.Message, "Technitium DNS Server 13.6") {
		t.Fatalf("test = %+v, %v", res, err)
	}
	bad := in
	bad.Password = "wrong"
	if res, _ = p.Test(ctx, bad); res.OK || !strings.Contains(res.Message, "refused") || strings.Contains(res.Message, testPassword) {
		t.Fatalf("bad token = %+v", res)
	}

	in.Enabled = true
	if _, err := p.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	p.pollOnce(ctx, p.settings())
	for i := 0; i < 900; i++ {
		fake.add(base.Add(time.Duration(i+1)*time.Millisecond), "192.168.20.5", fmt.Sprintf("n%d.example", i), "Cached", "10.0.0.1, 2001:db8::1")
	}
	fake.add(base.Add(2*time.Second), "192.168.20.6", "ads.example", "Blocked", "0.0.0.0")
	p.pollOnce(ctx, p.settings())
	if st := p.View().Status; st.State != "ok" || len(*got) != 901 || st.Version != "13.6" {
		t.Fatalf("status %+v, stored %d", st, len(*got))
	}
	first := (*got)[0]
	if first.Event.Dataset != DatasetTechnitium || len(first.DNS.ResolvedIP) != 2 || first.DNS.ResponseCode != "NOERROR" {
		t.Fatalf("first = %+v %+v", first.Event, first.DNS)
	}
	if d := first.Data["technitium"].(map[string]any); d["cached"] != true || d["response_time_ms"] != 4.25 || d["client_proto"] != "udp" {
		t.Fatalf("data = %v", d)
	}
	if last := (*got)[len(*got)-1]; last.Event.Action != "dns-blocked" {
		t.Fatalf("blocked = %+v", last.Event)
	}
}

func TestSwitchingResolverNeedsTheNewSecret(t *testing.T) {
	p, _ := newTestPoller(t)
	ctx := context.Background()
	if _, err := p.Save(ctx, Input{Settings: Settings{Enabled: true, URL: "https://192.168.20.1:3001", Username: "admin", Password: testPassword}}); err != nil {
		t.Fatal(err)
	}
	// The AdGuard Home password must not become the Pi-hole password.
	if _, err := p.Save(ctx, Input{Settings: Settings{Kind: KindPiHole, Enabled: true, URL: "https://192.168.20.1:3001"}}); err == nil {
		t.Fatal("switching resolver kept the old password")
	}
}
