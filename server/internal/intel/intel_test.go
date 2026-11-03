package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in, value, kind, hash string
		private               bool
	}{
		{in: "8.8.8.8", value: "8.8.8.8", kind: KindIP},
		{in: " 8[.]8[.]8[.]8 ", value: "8.8.8.8", kind: KindIP},
		{in: "2606:4700:4700::1111", value: "2606:4700:4700::1111", kind: KindIP},
		{in: "[2606:4700:4700::1111]", value: "2606:4700:4700::1111", kind: KindIP},
		{in: "192.168.20.20", value: "192.168.20.20", kind: KindIP, private: true},
		{in: "10.0.0.1", value: "10.0.0.1", kind: KindIP, private: true},
		{in: "127.0.0.1", value: "127.0.0.1", kind: KindIP, private: true},
		{in: "100.64.1.1", value: "100.64.1.1", kind: KindIP, private: true},
		{in: "203.0.113.7", value: "203.0.113.7", kind: KindIP, private: true},
		{in: "fe80::1", value: "fe80::1", kind: KindIP, private: true},
		{in: "fd00::1", value: "fd00::1", kind: KindIP, private: true},
		{in: "Evil.Example.COM.", value: "evil.example.com", kind: KindDomain},
		{in: "evil[.]com", value: "evil.com", kind: KindDomain},
		{in: "evil(dot)com", value: "evil.com", kind: KindDomain},
		{in: "tower.local", value: "tower.local", kind: KindDomain, private: true},
		{in: "printer.home.arpa", value: "printer.home.arpa", kind: KindDomain, private: true},
		{in: "tower2.netdoodle.com", value: "tower2.netdoodle.com", kind: KindDomain, private: true},
		{in: "netdoodle.com", value: "netdoodle.com", kind: KindDomain, private: true},
		{in: "xnetdoodle.com", value: "xnetdoodle.com", kind: KindDomain},
		{in: "hxxps://evil[.]com/a?b=1#frag", value: "https://evil.com/a?b=1", kind: KindURL},
		{in: "evil.com/payload.exe", value: "http://evil.com/payload.exe", kind: KindURL},
		{in: "http://192.168.1.1/admin", value: "http://192.168.1.1/admin", kind: KindURL, private: true},
		{in: "D41D8CD98F00B204E9800998ECF8427E", value: "d41d8cd98f00b204e9800998ecf8427e", kind: KindHash, hash: "md5"},
		{in: strings.Repeat("a", 40), value: strings.Repeat("a", 40), kind: KindHash, hash: "sha1"},
		{in: strings.Repeat("b", 64), value: strings.Repeat("b", 64), kind: KindHash, hash: "sha256"},
	} {
		ind, err := Parse(tc.in, []string{"netdoodle.com"})
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if ind.Value != tc.value || ind.Kind != tc.kind || ind.HashType != tc.hash || ind.Private != tc.private {
			t.Errorf("%q = %+v", tc.in, ind)
		}
	}
	for _, in := range []string{"", "   ", "not an indicator", "localhost", "abcdef", strings.Repeat("c", 50), "8.8.8.0/24", "http://", "javascript:alert(1)", strings.Repeat("a.", 2000) + "com"} {
		if ind, err := Parse(in, nil); err == nil {
			t.Errorf("%q parsed as %+v", in, ind)
		}
	}
}

func TestScore(t *testing.T) {
	res := func(source string, risk int) Result {
		return Result{Source: source, Name: source, State: StateOK, Risk: &risk}
	}
	for _, tc := range []struct {
		name    string
		in      []Result
		score   int
		verdict string
	}{
		{"nothing answered", []Result{{Source: "virustotal", State: StateNoData}}, -1, VerdictUnknown},
		{"context only", []Result{{Source: "ipwho", State: StateOK}}, -1, VerdictUnknown},
		{"one engine out of 92 and no abuse reports", []Result{res("virustotal", 10), res("abuseipdb", 0)}, 8, VerdictClean},
		{"only weak sources, nothing bad", []Result{res("otx", 0), res("pulsedive", 0)}, 0, VerdictNoSignal},
		{"a solid report is not averaged away", []Result{res("malwarebazaar", 100), res("virustotal", 0), res("otx", 0)}, 77, VerdictMalicious},
		{"several sources agree", []Result{res("abuseipdb", 100), res("virustotal", 75), res("otx", 20)}, 91, VerdictMalicious},
		{"moderate", []Result{res("abuseipdb", 60), res("virustotal", 30)}, 54, VerdictSuspicious},
		{"weak", []Result{res("virustotal", 30), res("abuseipdb", 0)}, 24, VerdictLow},
		{"pending sources do not count", []Result{res("virustotal", 0), {Source: "abuseipdb", State: StatePending}}, 0, VerdictClean},
	} {
		got, verdict, _ := score(tc.in)
		v := -1
		if got != nil {
			v = *got
		}
		if v != tc.score || verdict != tc.verdict {
			t.Errorf("%s: score %d %s, want %d %s", tc.name, v, verdict, tc.score, tc.verdict)
		}
	}
	if vtRisk(1, 0) >= 20 || vtRisk(0, 0) != 0 || vtRisk(5, 0) < 70 || vtRisk(30, 0) != 100 {
		t.Error("vtRisk bands moved")
	}
	now := time.Now()
	if otxRisk(50, now, now) != 60 || otxRisk(50, now.AddDate(-2, 0, 0), now) != 30 || otxRisk(1, now, now) != 20 {
		t.Error("otxRisk bands moved")
	}
}

// fakeServices answers like the real services, by request host.
type fakeServices struct {
	mu       sync.Mutex
	requests []string
	headers  map[string]http.Header
	answers  map[string]fakeAnswer
}

type fakeAnswer struct {
	status int
	body   string
}

func (f *fakeServices) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req.URL.Host+req.URL.Path)
	f.headers[req.URL.Host] = req.Header.Clone()
	a, ok := f.answers[req.URL.Host]
	if !ok {
		a = fakeAnswer{http.StatusNotFound, `{}`}
	}
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(strings.NewReader(a.body)), Header: http.Header{}, Request: req}, nil
}

func (f *fakeServices) hosts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for _, r := range f.requests {
		out[strings.SplitN(r, "/", 2)[0]]++
	}
	return out
}

func newTestService(t *testing.T) (*Service, *fakeServices, events.Store, *store.Store) {
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
	s := New(st, ev, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f := &fakeServices{headers: map[string]http.Header{}, answers: map[string]fakeAnswer{}}
	s.HTTP = &http.Client{Transport: f}
	t.Cleanup(s.Wait)
	return s, f, ev, st
}

// ipAnswers are responses in each service's documented shape, for a hostile IP.
var ipAnswers = map[string]fakeAnswer{
	"www.virustotal.com":     {200, `{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"suspicious":1,"harmless":50,"undetected":29,"timeout":0},"reputation":-7,"last_analysis_date":1793000000,"as_owner":"Bad Hosting","country":"NL","tags":["botnet"]}}}`},
	"api.abuseipdb.com":      {200, `{"data":{"abuseConfidenceScore":100,"totalReports":728,"numDistinctUsers":90,"lastReportedAt":"2026-10-28T10:00:00+00:00","usageType":"Data Center","isp":"Bad Hosting","countryCode":"NL","isWhitelisted":false,"isTor":true}}`},
	"urlhaus-api.abuse.ch":   {200, `{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/198.51.99.7/","firstseen":"2026-09-01 10:00:00 UTC","url_count":"3","urls":[{"url_status":"online","threat":"malware_download","tags":["elf","mirai"]},{"url_status":"offline","threat":"malware_download","tags":["elf"]}]}`},
	"threatfox-api.abuse.ch": {200, `{"query_status":"ok","data":[{"threat_type_desc":"botnet C2","malware_printable":"Mirai","confidence_level":90,"first_seen":"2026-09-01 10:00:00 UTC","last_seen":"2026-10-01 10:00:00 UTC","tags":["mirai"]}]}`},
	"api.greynoise.io":       {200, `{"noise":true,"riot":false,"classification":"malicious","name":"unknown","link":"https://viz.greynoise.io/ip/198.51.99.7","last_seen":"2026-11-02"}`},
	"otx.alienvault.com":     {200, `{"pulse_info":{"count":12,"pulses":[{"name":"Botnet infra","modified":"` + time.Now().UTC().Format("2006-01-02T15:04:05") + `.584000","tags":["botnet"],"malware_families":[{"display_name":"Mirai"}]}]},"validation":[{"source":"tor_exits"}]}`},
	"pulsedive.com":          {200, `{"iid":42,"risk":"high","stamp_seen":"2026-11-01 01:00:00","threats":[{"name":"Mirai"}],"feeds":[{"name":"Bad IPs"}],"riskfactors":[{"description":"self-signed SSL certificate"}],"retired":null}`},
	"internetdb.shodan.io":   {200, `{"ports":[22,80],"hostnames":["bad.example.net"],"cpes":["cpe:/a:openbsd:openssh:7.4"],"tags":["compromised"],"vulns":["CVE-2023-1234"]}`},
	"proxycheck.io":          {200, `{"status":"ok","198.51.99.7":{"proxy":"yes","type":"TOR","provider":"Bad Hosting","hostname":"bad.example.net","range":"198.51.99.0/24","asn":"AS666"}}`},
	"urlscan.io":             {200, `{"total":2,"results":[{"_id":"abc","task":{"time":"2026-10-25T10:00:00Z"},"page":{"ip":"198.51.99.7","asnname":"BAD-AS","title":"Login","server":"nginx","tlsIssuer":"R3"}}]}`},
	"ipwho.is":               {200, `{"success":true,"city":"Amsterdam","region":"North Holland","country":"Netherlands","country_code":"NL","latitude":52.37,"longitude":4.89,"connection":{"asn":666,"org":"Bad Hosting","isp":"Bad ISP"},"timezone":{"id":"Europe/Amsterdam"}}`},
	"rdap.org":               {200, `{"name":"BAD-NET","startAddress":"198.51.99.0","endAddress":"198.51.99.255","country":"NL","events":[{"eventAction":"registration","eventDate":"2020-01-02T00:00:00Z"},{"eventAction":"last changed","eventDate":"2021-03-04T00:00:00Z"}],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Bad Hosting B.V."]]],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@bad.example"]]]}]}]}`},
}

func byName(v *View, name string) *Result {
	for i := range v.Results {
		if v.Results[i].Name == name {
			return &v.Results[i]
		}
	}
	return nil
}

func TestLookupWithKeys(t *testing.T) {
	ctx := context.Background()
	s, f, _, st := newTestService(t)
	f.answers = ipAnswers
	set := s.Settings(ctx)
	set.Providers["virustotal"] = ProviderSetting{Key: "vt-secret"}
	set.Providers["abuseipdb"] = ProviderSetting{Key: "abuse-secret"}
	set.Providers["abusech"] = ProviderSetting{Key: "ach-secret"}
	if _, err := s.SaveSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "198.51.99.7"); err != store.ErrNotFound {
		t.Fatalf("before any lookup: %v", err)
	}
	v, err := s.Start(ctx, "198[.]51[.]99[.]7", false, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Running || v.Indicator.Value != "198.51.99.7" {
		t.Fatalf("started: %+v", v)
	}
	s.Wait()
	v, err = s.Get(ctx, "198.51.99.7")
	if err != nil {
		t.Fatal(err)
	}
	if v.Running || v.Summary.Score == nil || *v.Summary.Score < 75 || v.Summary.Verdict != VerdictMalicious || v.UpdatedBy != "alice" {
		t.Fatalf("summary: %+v", v.Summary)
	}
	if v.Summary.Coverage.WithData != 12 || v.Summary.Coverage.NeedsKey != 0 || v.Summary.Coverage.Failed != 0 {
		t.Fatalf("coverage: %+v", v.Summary.Coverage)
	}
	for _, r := range v.Results {
		if r.State != StateOK {
			t.Errorf("%s: %s %s", r.Name, r.State, r.Message)
		}
	}
	// What each source's answer became.
	for _, c := range []struct {
		name, headline string
		risk           int
	}{
		{"VirusTotal", "13 of 92 engines flag it", 90},
		{"AbuseIPDB", "Abuse confidence 100%, 728 reports in 90 days", 100},
		{"URLhaus", "Serving malware now", 95},
		{"ThreatFox", "Reported IOC: Mirai", 90},
		{"GreyNoise", "Classified as malicious", 85},
		{"AlienVault OTX", "In 12 threat reports", 60},
		{"Pulsedive", "Risk rating: high", 75},
		{"Shodan InternetDB", "2 open ports, 1 known CVEs", 75},
	} {
		r := byName(v, c.name)
		if r == nil || r.Headline != c.headline || r.Risk == nil || *r.Risk != c.risk {
			t.Errorf("%s = %+v", c.name, r)
		}
	}
	if w := v.Summary.Whois; w == nil || w.Registrant != "Bad Hosting B.V." || w.Abuse != "abuse@bad.example" || w.NetName != "BAD-NET" || w.Range != "198.51.99.0 – 198.51.99.255" || w.Created != "2020-01-02" {
		t.Errorf("whois: %+v", w)
	}
	if g := v.Summary.Geo; g == nil || g.City != "Amsterdam" || g.ASN != "AS666" || g.Lat != 52.37 {
		t.Errorf("geo: %+v", g)
	}
	if r := byName(v, "ProxyCheck"); r.Risk != nil || r.Headline != "Anonymizing service: TOR" {
		t.Errorf("proxycheck is context only: %+v", r)
	}
	brief := strings.Join(v.Summary.Brief, " ")
	for _, want := range []string{"looks malicious", "AbuseIPDB", "Anonymizing service: TOR", "1 known CVEs"} {
		if !strings.Contains(brief, want) {
			t.Errorf("brief lacks %q: %s", want, brief)
		}
	}
	// Keys go in headers, to their own service only, and are never stored with results.
	if f.headers["www.virustotal.com"].Get("x-apikey") != "vt-secret" || f.headers["api.abuseipdb.com"].Get("Key") != "abuse-secret" ||
		f.headers["urlhaus-api.abuse.ch"].Get("Auth-Key") != "ach-secret" || f.headers["threatfox-api.abuse.ch"].Get("Auth-Key") != "ach-secret" {
		t.Errorf("keys: %v", f.headers)
	}
	if h := f.headers["internetdb.shodan.io"]; h.Get("Key") != "" || h.Get("x-apikey") != "" {
		t.Errorf("a key went to another service: %v", h)
	}
	b, _ := json.Marshal(v)
	if rec, _ := st.GetIntelLookup(ctx, "198.51.99.7"); strings.Contains(string(rec.Results), "secret") || strings.Contains(string(b), "secret") {
		t.Error("an API key leaked into results")
	}
	// The indicator itself is never contacted.
	for h := range f.hosts() {
		if strings.Contains(h, "198.51.99.7") {
			t.Errorf("contacted the indicator: %s", h)
		}
	}

	// A repeat within the cache time asks nobody; refresh asks everybody.
	before := len(f.requests)
	if v, _ = s.Start(ctx, "198.51.99.7", false, "bob"); v.Running || len(f.requests) != before {
		t.Fatalf("cached lookup ran: %d to %d", before, len(f.requests))
	}
	if v, _ = s.Start(ctx, "198.51.99.7", true, "bob"); !v.Running {
		t.Fatal("refresh did not run")
	}
	s.Wait()
	if len(f.requests) <= before {
		t.Fatal("refresh asked nobody")
	}
	list, _ := s.History(ctx, 10)
	if len(list) != 1 || list[0].Indicator != "198.51.99.7" || list[0].Lookups != 2 || list[0].Score == nil || list[0].UpdatedBy != "bob" {
		t.Fatalf("history: %+v", list)
	}
	audit, _, _ := st.ListAudit(ctx, 10, 0)
	if len(audit) != 2 || audit[0].Action != "intel.lookup" || !strings.Contains(audit[0].Details, "VirusTotal") {
		t.Fatalf("audit: %+v", audit)
	}
}

func TestLookupWithoutKeys(t *testing.T) {
	ctx := context.Background()
	s, f, _, _ := newTestService(t)
	f.answers = map[string]fakeAnswer{
		"api.greynoise.io":     {404, `{"noise":false,"riot":false,"message":"IP not observed"}`},
		"otx.alienvault.com":   {200, `{"pulse_info":{"count":3,"pulses":[{"name":"x","modified":"2026-10-30T07:50:17"}]},"validation":[{"source":"whitelist"}]}`},
		"pulsedive.com":        {429, `{}`},
		"internetdb.shodan.io": {404, `{"detail":"No information available"}`},
		"proxycheck.io":        {200, `{"status":"denied","message":"limit reached"}`},
		"urlscan.io":           {500, `oops`},
		"ipwho.is":             {200, `{"success":false,"message":"Reserved range"}`},
		"rdap.org":             {200, `not json`},
	}
	s.Start(ctx, "8.8.8.8", false, "alice")
	s.Wait()
	v, err := s.Get(ctx, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	hosts := f.hosts()
	for _, h := range []string{"www.virustotal.com", "api.abuseipdb.com", "urlhaus-api.abuse.ch", "threatfox-api.abuse.ch"} {
		if hosts[h] != 0 {
			t.Errorf("asked %s without a key", h)
		}
	}
	want := map[string]string{"VirusTotal": StateNeedsKey, "AbuseIPDB": StateNeedsKey, "URLhaus": StateNeedsKey, "GreyNoise": StateNoData, "AlienVault OTX": StateOK,
		"Pulsedive": StateQuota, "Shodan InternetDB": StateNoData, "ProxyCheck": StateQuota, "urlscan.io": StateError, "ipwho.is": StateNoData, "WHOIS (RDAP)": StateError}
	for name, state := range want {
		if r := byName(v, name); r == nil || r.State != state {
			t.Errorf("%s = %+v, want %s", name, r, state)
		}
	}
	if r := byName(v, "AlienVault OTX"); !r.Benign || *r.Risk != 0 || !strings.Contains(r.Headline, "allowlist") {
		t.Errorf("otx: %+v", r)
	}
	if v.Summary.Verdict != VerdictNoSignal {
		t.Errorf("only weak data must not read as clean: %+v", v.Summary)
	}
	brief := strings.Join(v.Summary.Brief, " ")
	if !strings.Contains(brief, "VirusTotal, AbuseIPDB and abuse.ch need a free API key") || !strings.Contains(brief, "Pulsedive (over its quota)") {
		t.Errorf("brief: %s", brief)
	}
	// Failures are asked again; answers are not.
	before := f.hosts()
	s.Start(ctx, "8.8.8.8", false, "alice")
	s.Wait()
	after := f.hosts()
	if after["pulsedive.com"] != before["pulsedive.com"]+1 || after["api.greynoise.io"] != before["api.greynoise.io"] {
		t.Errorf("retries: %v to %v", before, after)
	}
	// A disabled provider is neither shown nor asked.
	set := s.Settings(ctx)
	set.Providers["otx"] = ProviderSetting{Disabled: true}
	s.SaveSettings(ctx, set)
	if v, _ = s.Get(ctx, "8.8.8.8"); byName(v, "AlienVault OTX") != nil {
		t.Error("a disabled provider is still shown")
	}
	// Adding a key: the next lookup asks that source, and only sources without an answer.
	set = s.Settings(ctx)
	set.Providers["virustotal"] = ProviderSetting{Key: "k"}
	s.SaveSettings(ctx, set)
	before = f.hosts()
	s.Start(ctx, "8.8.8.8", false, "alice")
	s.Wait()
	after = f.hosts()
	if after["www.virustotal.com"] != 1 || after["api.greynoise.io"] != before["api.greynoise.io"] {
		t.Errorf("after adding a key: %v to %v", before, after)
	}
}

func TestPrivateIndicatorsStayHere(t *testing.T) {
	ctx := context.Background()
	s, f, _, st := newTestService(t)
	set := s.Settings(ctx)
	set.InternalDomains = []string{"NetDoodle.com."}
	if set, err := s.SaveSettings(ctx, set); err != nil || set.InternalDomains[0] != "netdoodle.com" {
		t.Fatalf("%v %v", set, err)
	}
	for _, in := range []string{"192.168.20.20", "tower.local", "tower2.netdoodle.com", "http://10.0.0.1/x", "https://tower2.netdoodle.com/"} {
		if _, err := s.Start(ctx, in, true, "alice"); err != nil {
			t.Fatal(in, err)
		}
		s.Wait()
		v, err := s.Get(ctx, in)
		if err != nil {
			t.Fatal(in, err)
		}
		if !v.Indicator.Private || v.Summary.Verdict != VerdictInternal || len(v.Results) != 0 {
			t.Errorf("%s: %+v", in, v)
		}
	}
	if len(f.requests) != 0 {
		t.Fatalf("a private indicator left the server: %v", f.requests)
	}
	if audit, _, _ := st.ListAudit(ctx, 10, 0); len(audit) != 0 {
		t.Fatalf("nothing was sent, so nothing to audit: %+v", audit)
	}
}

func TestSettingsValidation(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestService(t)
	set := s.Settings(ctx)
	if !set.AIAccess || set.CacheHours != 24 {
		t.Fatalf("defaults: %+v", set)
	}
	set.CacheHours = 9999
	if _, err := s.SaveSettings(ctx, set); err == nil {
		t.Error("accepted a huge cache time")
	}
	set = s.Settings(ctx)
	set.InternalDomains = []string{"not a domain"}
	if _, err := s.SaveSettings(ctx, set); err == nil {
		t.Error("accepted a bad domain")
	}
	set = s.Settings(ctx)
	set.Providers["acme"] = ProviderSetting{}
	if _, err := s.SaveSettings(ctx, set); err == nil {
		t.Error("accepted an unknown provider")
	}
}

func TestSightings(t *testing.T) {
	s, _, ev, st := newTestService(t)
	testSightings(t, s, ev, st)
}

// TestSightingsClickHouse runs the searches on a real server when
// HOMEXDR_TEST_CLICKHOUSE_DSN is set.
func TestSightingsClickHouse(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	s, _, _, st := newTestService(t)
	ev, err := events.OpenClickHouse(context.Background(), dsn, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	s.ev = ev
	testSightings(t, s, ev, st)
}

func testSightings(t *testing.T, s *Service, ev events.Store, st *store.Store) {
	ctx := context.Background()
	now := time.Now().UTC()
	// Values unique to this run keep repeated runs on a real server independent.
	run := strings.ToLower(event.NewID())
	sum := sha256.Sum256([]byte(run))
	sha, md := hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:16])
	bad := fmt.Sprintf("198.51.%d.%d", sum[0]%90+1, sum[1]%200+1)
	domain := "evil" + run[len(run)-8:] + ".example.net"
	host := func(n string) string { return n + "-" + run }
	mk := func(id, name, proc string, age time.Duration, set func(e *event.Event)) *event.Event {
		e := &event.Event{ID: id + "-" + run, Timestamp: now.Add(-age), Host: event.Host{ID: "id-" + host(name), Name: host(name)},
			Event: event.Meta{Kind: "event", Category: []string{"network"}, Module: "procconn"}, Process: &event.Process{Name: proc}}
		set(e)
		return e
	}
	evs := []*event.Event{
		mk("e1", "web1", "curl", time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{IP: bad} }),
		mk("e2", "web1", "curl", 2*time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{IP: bad} }),
		mk("e3", "db1", "wget", 3*time.Hour, func(e *event.Event) { e.Source = &event.Endpoint{IP: bad} }),
		mk("e4", "web1", "curl", time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{IP: "1.1.1.1"} }),
		mk("e5", "old1", "curl", 90*24*time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{IP: bad} }),
		mk("e6", "web1", "dig", time.Hour, func(e *event.Event) {
			e.DNS = &event.DNS{Question: event.DNSQuestion{Name: "c2." + domain}}
		}),
		mk("e7", "db1", "curl", time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{Domain: domain} }),
		mk("e8", "web1", "curl", time.Hour, func(e *event.Event) { e.Destination = &event.Endpoint{Domain: "not" + domain} }),
		mk("e9", "db1", "dropper", time.Hour, func(e *event.Event) { e.Process.Hash = &event.Hash{SHA256: sha, MD5: md} }),
	}
	if err := ev.Insert(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RecordAlert(ctx, store.AlertInput{Rule: store.AlertRule{ID: "r1", Title: "Bad connection"}, Severity: "high", Event: evs[0]}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Sightings(ctx, bad, 30)
	if err != nil {
		t.Fatal(err)
	}
	if got.Events != 3 || len(got.Hosts) != 2 || got.Hosts[0].Name != host("web1") || got.Hosts[0].Count != 2 || got.Hosts[0].ID != "id-"+host("web1") {
		t.Fatalf("ip sightings: %+v", got)
	}
	if len(got.Processes) != 2 || got.Processes[0] != (Count{"curl", 2}) || got.First == "" || got.Last == "" || got.First > got.Last || len(got.Recent) != 3 {
		t.Fatalf("ip sightings: %+v", got)
	}
	if len(got.Alerts) != 1 || got.Alerts[0].Rule.Title != "Bad connection" {
		t.Fatalf("alerts: %+v", got.Alerts)
	}
	got, err = s.Sightings(ctx, bad, 365)
	if err != nil || got.Events != 4 {
		t.Fatalf("a wider window: %+v %v", got, err)
	}

	// A domain matches itself and subdomains, not lookalikes.
	got, err = s.Sightings(ctx, domain, 30)
	if err != nil || got.Events != 2 {
		t.Fatalf("domain sightings: %+v %v", got, err)
	}
	got, err = s.Sightings(ctx, "hxxps://"+strings.ReplaceAll(domain, ".", "[.]")+"/x", 30)
	if err != nil || got.Events != 2 || got.Note == "" {
		t.Fatalf("url sightings: %+v %v", got, err)
	}
	got, err = s.Sightings(ctx, sha, 30)
	if err != nil || got.Events != 1 || got.Hosts[0].Name != host("db1") {
		t.Fatalf("sha256 sightings: %+v %v", got, err)
	}
	got, err = s.Sightings(ctx, md, 30)
	if err != nil || got.Events != 1 {
		t.Fatalf("md5 sightings: %+v %v", got, err)
	}
	got, err = s.Sightings(ctx, "9.9.9.9", 30)
	if err != nil || got.Events != 0 || len(got.Hosts) != 0 {
		t.Fatalf("not seen: %+v %v", got, err)
	}
}

func TestForAI(t *testing.T) {
	ctx := context.Background()
	s, f, _, _ := newTestService(t)
	f.answers = ipAnswers
	out, err := s.ForAI(ctx, "198.51.99.7")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Score   *int `json:"score"`
		Verdict string
		Sources []struct{ Source string }
		Unavail []string       `json:"unavailable"`
		Seen    map[string]any `json:"seen_in_this_environment"`
		Note    string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err, out)
	}
	if got.Score == nil || len(got.Sources) == 0 || got.Note == "" || got.Seen["events"] != float64(0) || len(got.Unavail) == 0 {
		t.Fatalf("report: %s", out)
	}
	set := s.Settings(ctx)
	set.AIAccess = false
	s.SaveSettings(ctx, set)
	if _, err := s.ForAI(ctx, "198.51.99.8"); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Fatalf("lookups off: %v", err)
	}
	if n := f.hosts()["ipwho.is"]; n != 1 {
		t.Errorf("asked ipwho.is %d times", n)
	}
}
