package lists

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/enrich"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(filepath.Join(dir, "lists"), st, slog.New(slog.NewTextHandler(io.Discard, nil))), st
}

func zipOf(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	z.Close()
	return b.Bytes()
}

func gzipOf(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.Bytes()
}

func ut1Archive(t *testing.T, cat, domains string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{cat + "/domains": domains, cat + "/urls": "not/a/domain.example/x\n", cat + "/usage": "black\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

const (
	// The real files' first lines, as read from each source on 2026-11-05.
	trancoCSV = "1,google.com\r\n2,cloudflare.com\r\n3,ezviz7.com\r\n1000,Mixed-Case.Example.ORG\r\n999999,sub.example.co.uk\r\n1000000,keto4vegans.com\r\n"
	ouiCSV    = "Registry,Assignment,Organization Name,Organization Address\n" +
		"MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai Shanghai   CN 201206 \"\n" +
		"MA-L,38E2CA,Katun Corporation,7760 France Ave S Suite 340 Bloomington MN US 55438 \n" +
		"MA-L,E80AB9,\"Cisco Systems, Inc\",80 West Tasman Drive San Jose CA US 94568 \n"
	manufFixture = "# Comment\n00:00:0C\tCisco\tCisco Systems, Inc\n00:00:01\tXerox\tXerox Corporation\n" +
		"00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.\nAA:BB:CC\tNoLong\n"
	asnTSV = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
		"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
		"1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP - Gtelecom Pty Ltd\n" +
		"::\t::1\t0\tNone\tNot routed\n" +
		"2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n"
	nrdFixture = "applancerepairparts.store\nshhhh.dev\ntms-nc.com\n"
)

func TestParseTranco(t *testing.T) {
	tb, err := parseTranco([]byte(trancoCSV))
	if err != nil {
		t.Fatal(err)
	}
	if tb.size() != 6 {
		t.Fatalf("size = %d", tb.size())
	}
	for name, want := range map[string]uint32{"google.com": 1, "mixed-case.example.org": 1000, "keto4vegans.com": 1000000} {
		if got, ok := tb.get(name); !ok || got != want {
			t.Errorf("%s = %d %v", name, got, ok)
		}
	}
	if _, ok := tb.get("nope.example"); ok {
		t.Error("found a domain that is not there")
	}
	if _, err := parseTranco([]byte("<html>blocked</html>,x\n")); err == nil {
		t.Error("a block page should not parse")
	}
	// Duplicates keep the best rank.
	tb, err = parseTranco([]byte("5,a.example\n2,a.example\n"))
	if err != nil || tb.size() != 1 {
		t.Fatal(tb, err)
	}
	if got, _ := tb.get("a.example"); got != 2 {
		t.Errorf("rank %d", got)
	}
}

func installTables(t *testing.T, s *Service) {
	t.Helper()
	ranks, err := parseTranco([]byte(trancoCSV))
	if err != nil {
		t.Fatal(err)
	}
	s.tables.ranks.Store(ranks)
	oui, err := parseOUICSV(strings.NewReader(ouiCSV))
	if err != nil {
		t.Fatal(err)
	}
	s.tables.oui.Store(oui)
	asn, err := parseIPToASN(strings.NewReader(asnTSV))
	if err != nil {
		t.Fatal(err)
	}
	s.tables.asn.Store(asn)
}

func TestLookups(t *testing.T) {
	s, _ := newService(t)

	// With nothing downloaded, only the built-in public suffix list answers.
	if got := s.Domain("A.B.Example.CO.UK."); got != (enrich.DomainInfo{Registered: "example.co.uk"}) {
		t.Errorf("%+v", got)
	}
	if got := s.IP("1.0.0.1"); got != (enrich.IPInfo{}) {
		t.Errorf("%+v", got)
	}
	if got := s.MAC("28:6f:b9:00:00:01"); got != (enrich.MACInfo{}) {
		t.Errorf("%+v", got)
	}

	installTables(t, s)
	for name, want := range map[string]enrich.DomainInfo{
		"google.com":          {Registered: "google.com", Rank: 1},
		"www.google.com":      {Registered: "google.com", Rank: 1},
		"sub.example.co.uk":   {Registered: "example.co.uk", Rank: 999999},
		"other.example.co.uk": {Registered: "example.co.uk"},
		"nothing.example":     {Registered: "nothing.example"},
		"localhost":           {},
		"":                    {},
	} {
		if got := s.Domain(name); got != want {
			t.Errorf("%q: %+v", name, got)
		}
	}
	for ip, want := range map[string]enrich.IPInfo{
		"1.0.0.0":              {ASN: 13335, ASName: "CLOUDFLARENET - Cloudflare, Inc.", Country: "US"},
		"1.0.0.255":            {ASN: 13335, ASName: "CLOUDFLARENET - Cloudflare, Inc.", Country: "US"},
		"1.0.2.1":              {},
		"1.0.5.5":              {ASN: 38803, ASName: "GTELECOM-AS-AP - Gtelecom Pty Ltd", Country: "AU"},
		"::ffff:1.0.0.1":       {ASN: 13335, ASName: "CLOUDFLARENET - Cloudflare, Inc.", Country: "US"},
		"2001:4860:4860::8888": {ASN: 15169, ASName: "GOOGLE", Country: "US"},
		"2001:4861::1":         {},
		"192.168.1.1":          {},
		"not an address":       {},
	} {
		if got := s.IP(ip); got != want {
			t.Errorf("%s: %+v", ip, got)
		}
	}
	for mac, want := range map[string]enrich.MACInfo{
		"28:6F:B9:00:00:01": {Vendor: "Nokia Shanghai Bell Co., Ltd."},
		"28-6f-b9-00-00-01": {Vendor: "Nokia Shanghai Bell Co., Ltd."},
		"e80a.b900.0001":    {Vendor: "Cisco Systems, Inc"},
		"00:00:00:00:00:01": {},
		"02:00:00:00:00:01": {Randomized: true},
		"da:a1:19:00:00:01": {Randomized: true},
		"nonsense":          {},
		"28:6f:b9":          {},
	} {
		if got := s.MAC(mac); got != want {
			t.Errorf("%s: %+v", mac, got)
		}
	}
}

func TestDescribe(t *testing.T) {
	s, _ := newService(t)
	installTables(t, s)
	if f := enrich.Describe(s, "https://www.google.com/a?b=1"); f == nil || f.Domain == nil || f.Domain.Rank != 1 {
		t.Errorf("url: %+v", f)
	}
	if f := enrich.Describe(s, "1.0.0.1"); f == nil || f.IP == nil || f.IP.ASN != 13335 {
		t.Errorf("ip: %+v", f)
	}
	if f := enrich.Describe(s, "28:6f:b9:00:00:01"); f == nil || f.MAC == nil || f.MAC.Vendor == "" {
		t.Errorf("mac: %+v", f)
	}
	for _, none := range []string{"", "d41d8cd98f00b204e9800998ecf8427e", "192.168.1.1", "just-a-word"} {
		if f := enrich.Describe(s, none); f != nil {
			t.Errorf("%q: %+v", none, f)
		}
	}
}

func TestParseManufFallback(t *testing.T) {
	tb, err := parseManuf(strings.NewReader(manufFixture))
	if err != nil {
		t.Fatal(err)
	}
	if tb.size() != 3 {
		t.Fatalf("size %d", tb.size())
	}
	if v, ok := tb.get(0x00000C); !ok || v != "Cisco Systems, Inc" {
		t.Errorf("%q %v", v, ok)
	}
	if v, ok := tb.get(0xAABBCC); !ok || v != "NoLong" {
		t.Errorf("%q %v", v, ok)
	}
}

func TestOUIRejectsOtherFiles(t *testing.T) {
	if _, err := parseOUICSV(strings.NewReader("<html><body>blocked</body></html>\n")); err == nil {
		t.Fatal("a block page should not parse")
	}
}

// serve answers a test server's requests from a table of bodies, honouring ETags.
type fakeSite struct {
	bodies map[string][]byte
	codes  map[string]int
	etag   string
	gets   atomic.Int32
	full   atomic.Int32
}

func (f *fakeSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.gets.Add(1)
	if c, ok := f.codes[r.URL.Path]; ok {
		w.WriteHeader(c)
		return
	}
	body, ok := f.bodies[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", f.etag)
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	f.full.Add(1)
	_, _ = w.Write(body)
}

func pointAt(src *Source, base string, min int) {
	src.MinEntries = min
	inner := src.Files
	src.Files = func(now time.Time) []RemoteFile {
		out := inner(now)
		for i := range out {
			out[i].URL = base + "/" + out[i].Name
			if fb := out[i].Fallback; fb != nil {
				out[i].Fallback = &RemoteFile{Name: fb.Name, URL: base + "/" + fb.Name}
			}
		}
		return out
	}
}

func viewOf(s *Service, id string) View {
	for _, v := range s.Views() {
		if v.ID == id {
			return v
		}
	}
	return View{}
}

func TestRefreshLoadsAndSkipsUnchanged(t *testing.T) {
	s, _ := newService(t)
	site := &fakeSite{etag: `"v1"`, bodies: map[string][]byte{"/" + trancoFile: zipOf(t, "top-1m.csv", trancoCSV)}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	pointAt(s.source("tranco"), srv.URL, 3)

	ctx := context.Background()
	if err := s.Refresh(ctx, "tranco"); err != nil {
		t.Fatal(err)
	}
	if got := s.Domain("google.com").Rank; got != 1 {
		t.Fatalf("rank %d", got)
	}
	v := viewOf(s, "tranco")
	if v.Entries != 6 || v.LastUpdate == nil || v.LastCheck == nil || v.Error != "" {
		t.Fatalf("%+v", v)
	}
	updated := *v.LastUpdate

	// Unchanged: a conditional request, no new download, no change to the update time.
	if err := s.Refresh(ctx, "tranco"); err != nil {
		t.Fatal(err)
	}
	if site.full.Load() != 1 {
		t.Fatalf("full downloads: %d", site.full.Load())
	}
	if v := viewOf(s, "tranco"); !v.LastUpdate.Equal(updated) {
		t.Fatalf("update time moved: %+v", v)
	}

	// Changed: replaced, and the previous copy is kept.
	site.etag = `"v2"`
	site.bodies["/"+trancoFile] = zipOf(t, "top-1m.csv", "1,new.example\n2,b.example\n3,c.example\n")
	if err := s.Refresh(ctx, "tranco"); err != nil {
		t.Fatal(err)
	}
	if s.Domain("new.example").Rank != 1 || s.Domain("google.com").Rank != 0 {
		t.Fatal("not replaced")
	}
	if _, err := os.Stat(filepath.Join(s.dir, "tranco", lastGoodDir, trancoFile)); err != nil {
		t.Fatalf("no last-good copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "tranco", newDir)); !os.IsNotExist(err) {
		t.Fatalf("temporary folder left behind: %v", err)
	}
}

func TestBadDownloadsKeepTheGoodCopy(t *testing.T) {
	s, _ := newService(t)
	site := &fakeSite{etag: `"v1"`, bodies: map[string][]byte{"/" + trancoFile: zipOf(t, "top-1m.csv", trancoCSV)}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	pointAt(s.source("tranco"), srv.URL, 3)
	ctx := context.Background()
	if err := s.Refresh(ctx, "tranco"); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		body []byte
		want string
	}{
		"not a zip":     {[]byte("<html>blocked by your administrator</html>"), "could not be read"},
		"too few lines": {zipOf(t, "top-1m.csv", "1,one.example\n"), "only 1 entries"},
		"too large":     {bytes.Repeat([]byte("x"), 2<<20), "more than"},
	}
	s.source("tranco").MaxBytes = 1 << 20
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			site.etag = `"` + name + `"`
			site.bodies["/"+trancoFile] = c.body
			err := s.Refresh(ctx, "tranco")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v", err)
			}
			if v := viewOf(s, "tranco"); !strings.Contains(v.Error, c.want) || v.Entries != 6 {
				t.Fatalf("%+v", v)
			}
			if got := s.Domain("google.com").Rank; got != 1 {
				t.Fatalf("good list lost: rank %d", got)
			}
		})
	}
}

func TestServerRefusalIsExplained(t *testing.T) {
	s, _ := newService(t)
	site := &fakeSite{etag: `"v1"`, codes: map[string]int{"/" + trancoFile: http.StatusForbidden}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	pointAt(s.source("tranco"), srv.URL, 1)
	err := s.Refresh(context.Background(), "tranco")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("got %v", err)
	}
}

func TestDescribeFetchError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "x"}, "Could not look up h.example"},
		{&net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4zero, Port: 443}, Err: errors.New("connection refused")}, "DNS blocklist"},
		{&net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}, Err: errors.New("connection refused")}, "Could not reach"},
		{os.ErrDeadlineExceeded, "Timed out"},
	}
	for _, c := range cases {
		got := describeFetchError("h.example", c.err)
		if !strings.Contains(got, c.want) || !strings.Contains(got, "allow this host") {
			t.Errorf("%v: %s", c.err, got)
		}
	}
}

func TestOUIFallback(t *testing.T) {
	s, _ := newService(t)
	site := &fakeSite{etag: `"m1"`, codes: map[string]int{"/" + ouiFile: http.StatusTeapot}, bodies: map[string][]byte{"/" + manufFile: []byte(manufFixture)}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	pointAt(s.source("oui"), srv.URL, 1)
	ctx := context.Background()
	if err := s.Refresh(ctx, "oui"); err != nil {
		t.Fatal(err)
	}
	if got := s.MAC("00:00:0c:00:00:01").Vendor; got != "Cisco Systems, Inc" {
		t.Fatalf("vendor %q", got)
	}
	// Both sources down: the copy stays.
	site.codes["/"+manufFile] = http.StatusBadGateway
	site.etag = `"m2"`
	err := s.Refresh(ctx, "oui")
	if err == nil || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("got %v", err)
	}
	if got := s.MAC("00:00:0c:00:00:01").Vendor; got == "" {
		t.Fatal("copy lost")
	}
}

func TestASNAndCategoriesAndNewDomains(t *testing.T) {
	s, _ := newService(t)
	now := s.now()
	day1 := now.AddDate(0, 0, -1).Format("2006-01-02") + nrdSuffix
	day2 := now.AddDate(0, 0, -2).Format("2006-01-02") + nrdSuffix
	site := &fakeSite{etag: `"a"`, bodies: map[string][]byte{
		"/" + asnFile:              gzipOf(t, asnTSV),
		"/" + ut1File("malware"):   ut1Archive(t, "malware", "Bad.Example\nalso-ads.example\n"),
		"/" + ut1File("publicite"): ut1Archive(t, "publicite", "ads.example\nalso-ads.example\n"),
		"/" + day1:                 []byte(nrdFixture),
		"/" + day2:                 []byte("older.example\n"),
	}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	for id, min := range map[string]int{"iptoasn": 3, "ut1": 3, "nrd": 3} {
		pointAt(s.source(id), srv.URL, min)
	}
	ctx := context.Background()
	if err := s.Refresh(ctx, "iptoasn"); err != nil {
		t.Fatal(err)
	}
	if got := s.IP("1.0.0.1").ASN; got != 13335 {
		t.Fatalf("asn %d", got)
	}

	// UT1 and NRD are off by default: they download only when asked, and do not answer until on.
	if s.Enabled("ut1") || s.Enabled("nrd") {
		t.Fatal("opt-in lists must default to off")
	}
	if err := s.Refresh(ctx, "ut1"); err != nil {
		t.Fatal(err)
	}
	if got := s.Domain("ads.example").Category; got != "" {
		t.Fatalf("a list that is off answered: %q", got)
	}
	s.settings["ut1"] = true
	s.settings["nrd"] = true
	s.LoadAll()
	if got := s.Domain("bad.example").Category; got != "malware" {
		t.Errorf("case or merge: %q", got)
	}
	if got := s.Domain("cdn.ads.example").Category; got != "advertising" {
		t.Errorf("parent domain: %q", got)
	}
	if got := s.Domain("also-ads.example").Category; got != "malware" {
		t.Errorf("precedence: %q", got)
	}

	if err := s.Refresh(ctx, "nrd"); err != nil {
		t.Fatal(err)
	}
	if !s.Domain("shhhh.dev").NewlyRegistered || !s.Domain("www.older.example").NewlyRegistered {
		t.Error("not flagged as new")
	}
	if s.Domain("google.com").NewlyRegistered {
		t.Error("flagged wrongly")
	}

	// Yesterday's file leaves the site's root, and stays here within the keep window.
	delete(site.bodies, "/"+day2)
	site.etag = `"b"`
	if err := s.Refresh(ctx, "nrd"); err != nil {
		t.Fatal(err)
	}
	if !s.Domain("older.example").NewlyRegistered {
		t.Error("old day dropped too soon")
	}
}

func TestNRDKeepWindow(t *testing.T) {
	s, _ := newService(t)
	src := s.source("nrd")
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	if !src.KeepOld("2026-10-20"+nrdSuffix, now) || src.KeepOld("2026-09-20"+nrdSuffix, now) || src.KeepOld("other.csv", now) {
		t.Error("keep window wrong")
	}
	files := src.Files(now)
	if len(files) != nrdDaysOnline || !files[0].Optional || !strings.HasPrefix(files[0].Name, "2026-11-04") {
		t.Errorf("%+v", files)
	}
}

func TestSettingsAndRestart(t *testing.T) {
	s, st := newService(t)
	site := &fakeSite{etag: `"v1"`, bodies: map[string][]byte{"/" + trancoFile: zipOf(t, "top-1m.csv", trancoCSV)}}
	srv := httptest.NewServer(site)
	defer srv.Close()
	pointAt(s.source("tranco"), srv.URL, 3)
	ctx := context.Background()
	if err := s.Refresh(ctx, "tranco"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(ctx, "tranco", false); err != nil {
		t.Fatal(err)
	}
	if s.Domain("google.com").Rank != 0 {
		t.Fatal("still answering when off")
	}
	if err := s.SetEnabled(ctx, "nope", true); !errors.Is(err, ErrNoSuchList) {
		t.Fatalf("%v", err)
	}
	if err := s.SetEnabled(ctx, "tranco", true); err != nil {
		t.Fatal(err)
	}
	if s.Domain("google.com").Rank != 1 {
		t.Fatal("not answering when back on")
	}
	for s.viewUpdating("tranco") {
		runtime.Gosched()
	}

	// A new start answers from disk with no network at all, and remembers settings.
	s2 := New(s.dir, st, s.log)
	if !s2.Enabled("tranco") {
		t.Fatal("setting lost")
	}
	if s2.Domain("google.com").Rank != 0 {
		t.Fatal("answered before load")
	}
	s2.HTTP = nil // any network use would panic
	s2.LoadAll()
	if s2.Domain("google.com").Rank != 1 {
		t.Fatal("not loaded from disk")
	}
	if v := viewOf(s2, "tranco"); v.Entries != 6 {
		t.Fatalf("%+v", v)
	}

	// A damaged current copy falls back to the last good one.
	root := filepath.Join(s.dir, "tranco")
	if err := os.MkdirAll(filepath.Join(root, lastGoodDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, lastGoodDir, trancoFile), zipOf(t, "top-1m.csv", "7,kept.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, currentDir, trancoFile), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := New(s.dir, st, s.log)
	s3.LoadAll()
	if s3.Domain("kept.example").Rank != 7 {
		t.Fatal("did not fall back to the last good copy")
	}
}

func (s *Service) viewUpdating(id string) bool { return viewOf(s, id).Updating }

func TestDefaultsAndSchedule(t *testing.T) {
	s, _ := newService(t)
	on := map[string]bool{}
	for _, v := range s.Views() {
		on[v.ID] = v.Enabled
		if v.Enabled != v.DefaultOn || v.License == "" || !strings.HasPrefix(v.SiteURL, "https://") || v.About == "" || v.EveryHours == 0 {
			t.Errorf("%+v", v)
		}
	}
	for id, want := range map[string]bool{"tranco": true, "oui": true, "iptoasn": true, "ut1": false, "nrd": false} {
		if on[id] != want {
			t.Errorf("%s default = %v", id, on[id])
		}
	}
	src := s.source("tranco")
	now := s.now()
	if !s.due(src, now) {
		t.Error("never checked: due")
	}
	s.statusLocked("tranco").LastCheck = &now
	if s.due(src, now.Add(time.Hour)) {
		t.Error("checked just now: not due")
	}
	if !s.due(src, now.Add(8*24*time.Hour)) {
		t.Error("a week later: due")
	}
	s.statusLocked("tranco").Error = "boom"
	if !s.due(src, now.Add(7*time.Hour)) {
		t.Error("after a failure it should retry sooner")
	}
	if s.due(s.source("ut1"), now) {
		t.Error("a list that is off is never due")
	}
	for _, src := range s.builtinSources() {
		for _, f := range src.Files(now) {
			if !strings.HasPrefix(f.URL, "https://") {
				t.Errorf("%s: %s is not https", src.ID, f.URL)
			}
		}
	}
}

// bigTranco builds a Tranco-shaped list of n domains.
func bigTranco(n int) []byte {
	var b bytes.Buffer
	b.Grow(n * 28)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "%d,site-%07d.example-domain.com\r\n", i, i*7919%10000019)
	}
	return b.Bytes()
}

// TestMillionDomainsMemory measures the point of the sorted blob: under 45 MB for a million
// domains of about 28 characters, where a map[string]uint32 takes about 100 MB and more.
func TestMillionDomainsMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	data := bigTranco(1_000_000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tb, err := parseTranco(data)
	if err != nil {
		t.Fatal(err)
	}
	data = nil
	runtime.GC()
	runtime.ReadMemStats(&after)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// data was live in before and is gone in after; add back what the table copied from it.
	tableBytes := int64(len(tb.blob) + 4*len(tb.off) + 4*len(tb.val))
	t.Logf("table: %d MB of slices; heap change %d MB; %d domains", tableBytes>>20, used>>20, tb.size())
	if tb.size() != 1_000_000 {
		t.Fatalf("size %d", tb.size())
	}
	if tableBytes > 45<<20 {
		t.Fatalf("table takes %d MB", tableBytes>>20)
	}
	if r, ok := tb.get(fmt.Sprintf("site-%07d.example-domain.com", 777*7919%10000019)); !ok || r != 777 {
		t.Fatalf("lookup: %d %v", r, ok)
	}
	if allocs := testing.AllocsPerRun(100, func() { tb.get("site-0000042.example-domain.com") }); allocs != 0 {
		t.Fatalf("lookup allocates %v times", allocs)
	}
	runtime.KeepAlive(tb)
}

func BenchmarkDomainLookup(b *testing.B) {
	s := &Service{}
	tb, err := parseTranco(bigTranco(1_000_000))
	if err != nil {
		b.Fatal(err)
	}
	s.tables.ranks.Store(tb)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.Domain("www.site-0000042.example-domain.com")
	}
}

func BenchmarkIPLookup(b *testing.B) {
	var sb strings.Builder
	for i := range 500_000 {
		fmt.Fprintf(&sb, "%s\t%s\t%d\tUS\tNET-%d\n", netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0}), netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 255}), i%70000+1, i%70000)
	}
	tb, err := parseIPToASN(strings.NewReader(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	s := &Service{}
	s.tables.asn.Store(tb)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.IP("1.2.3.4")
	}
}
