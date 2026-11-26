package vuln

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/lists"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// kevFixture has the real file's fields and these real entries' shapes.
const kevFixture = `{
 "title": "CISA Catalog of Known Exploited Vulnerabilities",
 "catalogVersion": "2026.11.04", "dateReleased": "2026-11-04T20:00:05.774Z", "count": 7,
 "vulnerabilities": [
  {"cveID":"CVE-2021-3156","vendorProject":"Sudo","product":"Sudo","vulnerabilityName":"Sudo Heap-Based Buffer Overflow Vulnerability","dateAdded":"2022-04-06","shortDescription":"Sudo contains an off-by-one error that can result in a heap-based buffer overflow.","requiredAction":"Apply updates.","dueDate":"2022-04-27","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":["CWE-193"]},
  {"cveID":"CVE-2010-4344","vendorProject":"Exim","product":"Exim","vulnerabilityName":"Exim Heap-Based Buffer Overflow Vulnerability","dateAdded":"2022-03-25","shortDescription":"Heap-based buffer overflow in the string_vformat function in string.c in Exim before 4.70 allows remote attackers to execute arbitrary code.","dueDate":"2022-04-15","knownRansomwareCampaignUse":"Known"},
  {"cveID":"CVE-2022-0847","vendorProject":"Linux","product":"Kernel","vulnerabilityName":"Linux Kernel Privilege Escalation Vulnerability","dateAdded":"2022-04-25","shortDescription":"Linux kernel contains an improper initialization vulnerability.","dueDate":"2022-05-16","knownRansomwareCampaignUse":"Unknown"},
  {"cveID":"CVE-2024-27834","vendorProject":"Apple","product":"Multiple Products","vulnerabilityName":"Apple Multiple Products Improper Authentication Vulnerability","dateAdded":"2026-11-04","shortDescription":"Apple iOS, iPadOS and macOS 10.5 contain an improper authentication vulnerability.","dueDate":"2026-11-25","knownRansomwareCampaignUse":"Unknown"},
  {"cveID":"CVE-2020-5741","vendorProject":"Plex","product":"Media Server","vulnerabilityName":"Plex Media Server Remote Code Execution Vulnerability","dateAdded":"2023-03-10","shortDescription":"Plex Media Server contains a remote code execution vulnerability.","dueDate":"2023-03-31","knownRansomwareCampaignUse":"Unknown"},
  {"cveID":"CVE-2014-0160","vendorProject":"OpenSSL","product":"OpenSSL","vulnerabilityName":"OpenSSL Information Disclosure Vulnerability","dateAdded":"2022-05-04","shortDescription":"The TLS implementation in OpenSSL 1.0.1 before 1.0.1g does not properly handle Heartbeat Extension packets.","dueDate":"2022-05-25","knownRansomwareCampaignUse":"Unknown"},
  {"cveID":"CVE-2026-1111","vendorProject":"Unrelated Vendor","product":"Core","vulnerabilityName":"Generic Core Vulnerability","dateAdded":"2026-01-01","shortDescription":"Something.","dueDate":"2026-02-01","knownRansomwareCampaignUse":"Unknown"}
 ]
}`

func TestParseCatalogNames(t *testing.T) {
	r := newRig(t, "", "")
	r.loadCatalog()
	c := r.s.kev.Load()
	if c.entries != 7 || c.version != "2026.11.04" {
		t.Fatalf("%+v", c)
	}
	for name, want := range map[string]string{"sudo": "CVE-2021-3156", "exim4": "CVE-2010-4344", "plex": "CVE-2020-5741", "kernel": "CVE-2022-0847", "opensslsolibs": "CVE-2014-0160"} {
		if got := c.byName[name]; len(got) != 1 || got[0].CVE != want {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// "Core" from an unknown vendor and Apple's "Multiple Products" match nothing.
	for _, name := range []string{"core", "multipleproducts", "unrelatedvendorcore", "kernelmodules"} {
		if len(c.byName[name]) != 0 {
			t.Errorf("%s matched", name)
		}
	}
}

func TestParseCatalogRejectsOtherFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(p, []byte("<html>blocked</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCatalog(p); err == nil {
		t.Fatal("a block page should not parse")
	}
}

func TestDescriptionBound(t *testing.T) {
	cases := []struct {
		text      string
		version   string
		inclusive bool
		ok        bool
	}{
		{"in Exim before 4.70 allows", "4.70", false, true},
		{"in versions prior to 5.0.2, which can", "5.0.2", false, true},
		{"firmware through 10.0.0.50 allows", "10.0.0.50", true, true},
		{"Sudo contains an off-by-one error", "", false, false},
		{"Apple iOS before 8 and Apple TV before 7", "", false, false}, // no dotted version
		{"X before 1.2.3 and Y before 2.3.4", "", false, false},        // two different limits
		{"X before 1.2.3 and also before 1.2.3 here", "1.2.3", false, true},
		{"versions 1.2 through 1.4", "", false, false}, // a lower end too
		{"OpenSSL 1.0.1 before 1.0.1g does not", "1.0.1g", false, true},
		{"from version 2.0 to 2.5", "", false, false},
	}
	for _, c := range cases {
		b, ok := descriptionBound(c.text)
		if ok != c.ok || b.version != c.version || b.inclusive != c.inclusive {
			t.Errorf("%q: %+v %v", c.text, b, ok)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.10", "1.2.9", 1},
		{"4.69", "4.70", -1},
		{"1.2", "1.2.0", 0},
		{"1.0.1f", "1.0.1g", -1},
		{"1.0.1", "1.0.1g", -1},
		{"1.9.17p2", "1.9.17p10", -1},
		{"1.9.17p2", "1.9.17", 1},
		{"1.2rc1", "1.2", -1},
		{"1.2-beta", "1.2", -1},
		{"v3.5.7", "3.5.7", 0},
		{"2.43", "2.100", -1},
	}
	for _, c := range cases {
		if got, ok := compareVersions(c.a, c.b); !ok || got != c.want {
			t.Errorf("%s vs %s: %d %v", c.a, c.b, got, ok)
		}
	}
	for _, bad := range []string{"latest", "", "stable"} {
		if _, ok := compareVersions(bad, "1.0"); ok {
			t.Errorf("%q compared", bad)
		}
	}
}

type rig struct {
	t    *testing.T
	s    *Service
	st   *store.Store
	ev   events.Store
	dir  string
	now  time.Time
	host *store.Host
}

type fakeExposure map[string][]int

func (f fakeExposure) InternetExposure(context.Context) (map[string][]int, error) { return f, nil }

func newRig(t *testing.T, osName, osVersion string) *rig {
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	l := lists.New(filepath.Join(dir, "lists"), st, log)
	s := New(st, ev, l, log)
	h, err := st.CreateEndpoint(context.Background(), "tower-id", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux", Name: osName, Version: osVersion}}, nil, "serial")
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, s: s, st: st, ev: ev, dir: dir, now: time.Now().UTC(), host: h}
}

func (r *rig) loadCatalog() {
	r.t.Helper()
	dir := r.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, kevFileName), []byte(kevFixture), 0o600); err != nil {
		r.t.Fatal(err)
	}
	c, err := parseCatalog(filepath.Join(dir, kevFileName))
	if err != nil {
		r.t.Fatal(err)
	}
	r.s.kev.Store(c)
}

// loadOSV writes a distro export as the offline list would have downloaded it.
func (r *rig) loadOSV(file string, records ...string) {
	r.t.Helper()
	dir := filepath.Join(r.dir, "lists", OSVListID, "current")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, file))
	if err != nil {
		r.t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, rec := range records {
		var head struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(rec), &head); err != nil {
			r.t.Fatal(err)
		}
		w, err := zw.Create(head.ID + ".json")
		if err != nil {
			r.t.Fatal(err)
		}
		_, _ = w.Write([]byte(rec))
	}
	if err := zw.Close(); err != nil {
		r.t.Fatal(err)
	}
	f.Close()
	r.s.osvMu.Lock()
	r.s.osvGen++
	r.s.osvMu.Unlock()
}

// snapshot stores a software list, as the inventory sensor emits it.
func (r *rig) snapshot(at time.Time, rows ...pkg) {
	r.t.Helper()
	var evs []*event.Event
	for _, p := range rows {
		evs = append(evs, &event.Event{
			ID: event.NewID(), Timestamp: at, Host: event.Host{ID: r.host.ID, Name: "tower"},
			Event:   event.Meta{Kind: event.KindState, Module: event.ModuleInventory, Dataset: "inventory.software.list"},
			Package: &event.Package{Name: p.name, Version: p.version, Type: p.typ, Source: p.source},
		})
	}
	if err := r.ev.Insert(context.Background(), evs); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) scan() []store.VulnFinding {
	r.t.Helper()
	if err := r.s.Scan(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	list, err := r.st.ListVulnFindings(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return list
}

func open(list []store.VulnFinding) []store.VulnFinding {
	var out []store.VulnFinding
	for _, f := range list {
		if f.Status != store.VulnFixed {
			out = append(out, f)
		}
	}
	return out
}

func find(list []store.VulnFinding, pkgName, cve string) *store.VulnFinding {
	for i := range list {
		if list[i].Package == pkgName && list[i].CVE == cve {
			return &list[i]
		}
	}
	return nil
}

func TestMatchingConfidence(t *testing.T) {
	r := newRig(t, "Unraid OS", "7.2.8")
	r.loadCatalog()
	r.snapshot(r.now,
		pkg{name: "sudo", version: "1.9.17p2", typ: "slackware"},                // no limit stated: possible
		pkg{name: "exim", version: "4.69", typ: "slackware"},                    // below the stated limit: confirmed
		pkg{name: "plex-unrelated", version: "1.0", typ: "slackware"},           // does not match
		pkg{name: "lscr.io/linuxserver/plex", version: "latest", typ: "docker"}, // image, by its short name
		pkg{name: "kernel-modules", version: "6.12", typ: "slackware"},          // not the kernel package
	)
	list := r.scan()
	if len(list) != 3 {
		t.Fatalf("%+v", list)
	}
	if m := find(list, "sudo", "CVE-2021-3156"); m == nil || m.Confidence != Possible || !strings.Contains(m.Summary, "name matches") {
		t.Errorf("%+v", m)
	}
	if m := find(list, "exim", "CVE-2010-4344"); m == nil || m.Confidence != Confirmed || !m.Ransomware || !m.KEV || m.KEVDueDate != "2022-04-15" || !strings.Contains(m.Summary, "before 4.70") {
		t.Errorf("%+v", m)
	}
	if m := find(list, "lscr.io/linuxserver/plex", "CVE-2020-5741"); m == nil || m.Confidence != Possible {
		t.Errorf("%+v", m)
	}
	rep, err := r.s.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts[0].Coverage != CoverageKEVOnly {
		t.Errorf("coverage %+v", rep.Hosts[0])
	}
}

func TestPatchedVersionIsDropped(t *testing.T) {
	r := newRig(t, "Unraid OS", "7.2.8")
	r.loadCatalog()
	r.snapshot(r.now, pkg{name: "exim", version: "4.98", typ: "slackware"})
	if list := r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestBackportingDistroStaysPossible(t *testing.T) {
	r := newRig(t, "Debian GNU/Linux", "12")
	r.loadCatalog()
	// With no distro advisories downloaded, an old-looking number on Debian may well be patched,
	// so it is never confirmed by number.
	r.snapshot(r.now, pkg{name: "exim4", version: "4.69-1+deb12u1", typ: "deb"}, pkg{name: "openssl", version: "1.0.1e-2+deb7u5", typ: "deb"})
	list := r.scan()
	if m := find(list, "exim4", "CVE-2010-4344"); m == nil || m.Confidence != Possible || !strings.Contains(m.Summary, "distributions") {
		t.Fatalf("%+v", m)
	}
}

func TestDockerTagVersionCheck(t *testing.T) {
	for _, c := range []struct {
		tag  string
		want string // "" means dropped
	}{
		{"4.69.1-alpine", Confirmed}, {"4.71.0", ""}, {"4.69", Possible}, {"latest", Possible},
	} {
		r := newRig(t, "", "")
		r.loadCatalog()
		r.snapshot(r.now, pkg{name: "example/exim", version: c.tag, typ: "docker"})
		list := r.scan()
		switch {
		case c.want == "" && len(list) != 0:
			t.Errorf("%s: %+v", c.tag, list)
		case c.want != "" && (len(list) != 1 || list[0].Confidence != c.want):
			t.Errorf("%s: %+v", c.tag, list)
		}
	}
}

func TestOnlyNewestSnapshotCounts(t *testing.T) {
	r := newRig(t, "", "")
	r.loadCatalog()
	r.snapshot(r.now.Add(-6*time.Hour), pkg{name: "sudo", version: "1.0", typ: "slackware"}, pkg{name: "exim", version: "4.69", typ: "slackware"})
	r.snapshot(r.now, pkg{name: "bash", version: "5.3", typ: "slackware"}) // sudo and exim are gone
	if list := r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestFindingsFollowTheInventory(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	r.loadCatalog()
	r.snapshot(r.now.Add(-2*time.Hour), pkg{name: "exim", version: "4.69", typ: "slackware"})
	list := r.scan()
	if len(list) != 1 || list[0].Status != store.VulnOpen {
		t.Fatalf("%+v", list)
	}
	firstSeen := list[0].FirstSeen

	// Accepted, it stays accepted on the next scan, and keeps when it was first seen.
	if err := r.s.SetAccepted(ctx, r.host.ID, "exim", "CVE-2010-4344", true, " behind the VPN "); err != nil {
		t.Fatal(err)
	}
	r.s.now = func() time.Time { return r.now.Add(time.Hour) }
	list = r.scan()
	if len(list) != 1 || list[0].Status != store.VulnAccepted || list[0].AcceptedNote != "behind the VPN" || !list[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("%+v", list)
	}

	// Patched: it is kept as fixed, with the time.
	r.snapshot(r.now.Add(-time.Minute), pkg{name: "exim", version: "4.98", typ: "slackware"})
	r.s.now = func() time.Time { return r.now.Add(2 * time.Hour) }
	list = r.scan()
	if len(list) != 1 || list[0].Status != store.VulnFixed || list[0].FixedAt == nil {
		t.Fatalf("%+v", list)
	}
	fixedAt := *list[0].FixedAt
	list = r.scan()
	if !list[0].FixedAt.Equal(fixedAt) {
		t.Fatalf("fixed time moved: %+v", list[0])
	}
	if err := r.s.SetAccepted(ctx, r.host.ID, "exim", "CVE-2010-4344", true, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("accepting a fixed finding: %v", err)
	}

	// After 30 days it is forgotten.
	r.s.now = func() time.Time { return r.now.Add(31 * 24 * time.Hour) }
	if list = r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestDecommissionedHostIsForgotten(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	r.loadCatalog()
	r.snapshot(r.now, pkg{name: "exim", version: "4.69", typ: "slackware"})
	r.scan()
	if err := r.st.DecommissionHost(ctx, r.host.ID); err != nil {
		t.Fatal(err)
	}
	if list := r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestReportExplainsMissingData(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	rep, err := r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Hosts) != 1 || rep.Hosts[0].Packages != 0 || rep.Hosts[0].Coverage != CoverageNone || rep.OSVAPI.Enabled {
		t.Fatalf("%+v", rep)
	}
	ids := map[string]bool{}
	for _, src := range rep.Sources {
		ids[src.ID] = src.Enabled
	}
	if !ids[ListID] || !ids[OSVListID] || !ids[EPSSListID] {
		t.Fatalf("sources %+v", rep.Sources)
	}
	// With no catalog, a software list is still counted, and nothing matches.
	r.snapshot(r.now, pkg{name: "sudo", version: "1.0", typ: "slackware"})
	r.scan()
	rep, err = r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts[0].Packages != 1 || rep.Hosts[0].SnapshotAt == nil || len(rep.Findings) != 0 || rep.LastRun == nil {
		t.Fatalf("%+v", rep)
	}
	r.loadCatalog()
	r.scan()
	rep, err = r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Open != 1 || rep.Summary.KEV != 1 || rep.Summary.New7d != 1 || len(rep.History) != 1 || rep.Hosts[0].Open != 1 {
		t.Fatalf("%+v", rep)
	}
}

func TestOSVEcosystems(t *testing.T) {
	for _, c := range []struct {
		name, version, typ, want string
	}{
		{"Debian GNU/Linux", "12.5", "deb", "Debian:12"},
		{"Ubuntu", "22.04", "deb", "Ubuntu:22.04:LTS"},
		{"Ubuntu", "23.10", "deb", "Ubuntu:23.10"},
		{"Alpine Linux", "3.18.4", "apk", "Alpine:v3.18"},
		{"Unraid OS", "7.2.8", "slackware", ""},
		{"Debian GNU/Linux", "12", "docker", ""},
		{"Fedora", "40", "rpm", ""},
	} {
		if got := osvEcosystem(event.OS{Name: c.name, Version: c.version}, c.typ); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
	for _, c := range []struct{ name, version, want string }{
		{"Debian GNU/Linux", "12", "Debian:12"},
		{"Raspbian GNU/Linux", "12", "Debian:12"},
		{"Kali GNU/Linux", "2025.4", "Debian:14"},
		{"Ubuntu", "24.04", "Ubuntu:24.04:LTS"},
		{"Alpine Linux", "3.20.3", "Alpine:v3.20"},
		{"Rocky Linux", "9.4", "Rocky Linux:9"},
		{"AlmaLinux", "9.4", "AlmaLinux:9"},
		{"Unraid OS", "7.2.8", ""},
	} {
		got, _, _ := hostEcosystem(event.OS{Name: c.name, Version: c.version})
		if got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestOSVIsOffByDefaultAndSendsOnlyPossibleMatches(t *testing.T) {
	r := newRig(t, "Debian GNU/Linux", "12")
	r.loadCatalog()
	var queries [][]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Queries []map[string]any `json:"queries"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		queries = append(queries, body.Queries)
		res := make([]map[string]any, len(body.Queries))
		for i, q := range body.Queries {
			vulns := []map[string]string{}
			if q["package"].(map[string]any)["name"] == "openssl" {
				vulns = append(vulns, map[string]string{"id": "DEBIAN-CVE-2014-0160"}, map[string]string{"id": "DEBIAN-CVE-1999-0001"})
			}
			res[i] = map[string]any{"vulns": vulns}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	r.s.OSVURL = srv.URL
	r.snapshot(r.now, pkg{name: "openssl", version: "1.0.1e-2", typ: "deb"}, pkg{name: "sudo", version: "1.9.5-1", typ: "deb"},
		pkg{name: "bash", version: "5.2-1", typ: "deb"}, pkg{name: "vim", version: "9.0-1", typ: "deb"})

	// Off: nothing is sent.
	list := r.scan()
	if len(queries) != 0 {
		t.Fatalf("sent while off: %v", queries)
	}
	if m := find(list, "openssl", "CVE-2014-0160"); m == nil || m.Confidence != Possible {
		t.Fatalf("%+v", m)
	}

	// On: only possibly matching packages are sent, and OSV's answer confirms.
	if err := r.s.SaveSettings(context.Background(), Settings{OSV: true}); err != nil {
		t.Fatal(err)
	}
	list = r.scan()
	if len(queries) != 1 || len(queries[0]) != 2 {
		t.Fatalf("queries: %v", queries)
	}
	for _, q := range queries[0] {
		p := q["package"].(map[string]any)
		if p["name"] == "vim" || p["name"] == "bash" {
			t.Errorf("sent a package with no match: %v", q)
		}
		if p["ecosystem"] != "Debian:12" {
			t.Errorf("ecosystem: %v", q)
		}
	}
	if m := find(list, "openssl", "CVE-2014-0160"); m == nil || m.Confidence != Confirmed || !strings.Contains(m.Summary, "OSV") {
		t.Fatalf("%+v", m)
	}
	if m := find(list, "sudo", "CVE-2021-3156"); m == nil || m.Confidence != Possible {
		t.Fatalf("%+v", m)
	}

	// OSV down: results stay, the error shows, nothing else breaks.
	srv.Close()
	r.scan()
	rep, err := r.s.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.OSVAPI.Error, "api.osv.dev") {
		t.Fatalf("%+v", rep.OSVAPI)
	}
}

// Shaped like the real Debian export's records.
const debOpenSSL = `{"id":"DEBIAN-CVE-2024-0727","upstream":["CVE-2024-0727"],"details":"Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash. More text.",
 "affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-1~deb12u1"}]}]},
  {"package":{"name":"openssl","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.5-1"}]}]}],
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`

const debCurlUnfixed = `{"id":"DEBIAN-CVE-2025-0001","upstream":["CVE-2025-0001"],"details":"A local flaw in curl.",
 "affected":[{"package":{"name":"curl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"low"}}],
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]}`

const debUnimportant = `{"id":"DEBIAN-CVE-2025-0002","upstream":["CVE-2025-0002"],"details":"Nothing to see.",
 "affected":[{"package":{"name":"curl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"unimportant"}}]}`

const dsaDuplicate = `{"id":"DSA-5000-1","upstream":["CVE-2024-0727"],"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}]}`

func TestDistroAdvisoriesMatchSourcePackages(t *testing.T) {
	r := newRig(t, "Debian GNU/Linux", "12")
	r.loadCatalog()
	r.loadOSV("Debian.zip", debOpenSSL, debCurlUnfixed, debUnimportant, dsaDuplicate)
	r.s.epss.Store(&epssTable{scores: map[string]epssScore{"CVE-2024-0727": {Prob: 0.002, Percentile: 0.5}}})
	r.snapshot(r.now,
		pkg{name: "libssl3", version: "3.0.11-1~deb12u2", typ: "deb", source: "openssl"}, // affected, via its source
		pkg{name: "openssl", version: "3.0.13-1~deb12u1", typ: "deb"},                    // the fixed version
		pkg{name: "curl", version: "7.88.1-10+deb12u5", typ: "deb"},                      // no fix released yet
		pkg{name: "sudo", version: "1.9.13p3-1+deb12u1", typ: "deb"},                     // no advisory: and no name matching either
	)
	list := r.scan()
	if len(list) != 2 {
		t.Fatalf("%+v", list)
	}
	f := find(list, "libssl3", "CVE-2024-0727")
	if f == nil || f.SourcePackage != "openssl" || f.FixedVersion != "3.0.13-1~deb12u1" || f.Confidence != Confirmed ||
		f.CVSS == nil || *f.CVSS != 9.8 || f.AttackVector != "network" || f.SeveritySource != "osv" || f.EPSS == nil {
		t.Fatalf("%+v", f)
	}
	// Not internet-facing: likelihood 3, so 9.8 becomes 2.9.
	if f.Exposure != ExposureLAN || f.Likelihood != 3 || f.Risk != 2.9 || f.Band != BandLow || !strings.HasPrefix(f.Summary, "Issue summary") || !strings.HasPrefix(f.Title, "Processing a maliciously") {
		t.Fatalf("%+v", f)
	}
	c := find(list, "curl", "CVE-2025-0001")
	if c == nil || c.FixedVersion != "" || c.AttackVector != "local" || c.Likelihood != 1.5 {
		t.Fatalf("%+v", c)
	}
	rep, err := r.s.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts[0].Coverage != CoverageFull || rep.Summary.NoFix != 1 || rep.Findings[0].CVE != "CVE-2024-0727" {
		t.Fatalf("%+v", rep)
	}
	if got := r.s.ecosystemsInUse(); len(got) != 1 || got[0] != "Debian" {
		t.Fatalf("in use: %v", got)
	}

	// Port-forwarded: the same CVE scores much higher.
	r.s.Exposure = fakeExposure{r.host.ID: {443}}
	r.s.mu.Lock()
	r.s.exposure = nil
	r.s.mu.Unlock()
	list = r.scan()
	f = find(list, "libssl3", "CVE-2024-0727")
	if f.Exposure != ExposureInternet || f.Likelihood != 7 || f.Risk != 6.9 || f.Band != BandHigh || len(f.ExposedPorts) != 1 {
		t.Fatalf("%+v", f)
	}
}

func TestCVSS(t *testing.T) {
	for _, c := range []struct {
		vec    string
		score  float64
		av     string
		approx bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "network", false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10, "network", false},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5, "local", false},
		{"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 7.7, "local", false},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "network", false},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, "physical", false},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.8, "network", true},
	} {
		got, ok := parseCVSS(c.vec)
		if !ok || got.Score != c.score || got.AttackVector != c.av || got.Approximate != c.approx {
			t.Errorf("%s: %+v %v", c.vec, got, ok)
		}
	}
	if _, ok := parseCVSS("AV:N/AC:L"); ok {
		t.Error("accepted a vector with no version")
	}
}

func TestRiskScore(t *testing.T) {
	for _, c := range []struct {
		name string
		in   riskInput
		l, r float64
		band string
	}{
		{"lan network", riskInput{CVSS: 9.5, AttackVector: "network", Exposure: ExposureLAN, EPSS: 0.001}, 3, 2.9, BandLow},
		{"internet network", riskInput{CVSS: 9.5, AttackVector: "network", Exposure: ExposureInternet, Ports: []int{443}, EPSS: 0.001}, 7, 6.7, BandHigh},
		{"internet kev", riskInput{CVSS: 9.8, AttackVector: "network", Exposure: ExposureInternet, Ports: []int{443}, EPSS: 0.9, KEV: true}, 10, 9.8, BandCritical},
		{"lan kev", riskInput{CVSS: 9.8, AttackVector: "network", Exposure: ExposureLAN, EPSS: 0.2, KEV: true}, 8, 7.8, BandHigh},
		{"local", riskInput{CVSS: 7.8, AttackVector: "local", Exposure: ExposureInternet, EPSS: -1}, 1.5, 1.2, BandLow},
		{"physical", riskInput{CVSS: 6.8, AttackVector: "physical", Exposure: ExposureLAN, EPSS: -1}, 0.5, 0.3, BandLow},
		{"epss bump", riskInput{CVSS: 7.5, AttackVector: "network", Exposure: ExposureLAN, EPSS: 0.05}, 4, 3, BandMedium},
	} {
		got := score(c.in)
		if got.Likelihood != c.l || got.Risk != c.r || got.Band != c.band || len(got.Reasons) == 0 {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestInRange(t *testing.T) {
	ev := []osvEvent{{Introduced: "1.0-1"}, {Fixed: "1.2-1"}, {Introduced: "2.0-1"}, {LastAffected: "2.1-1"}}
	for _, c := range []struct {
		v     string
		hit   bool
		fixed string
	}{
		{"0.9-1", false, ""}, {"1.0-1", true, "1.2-1"}, {"1.1-3", true, "1.2-1"}, {"1.2-1", false, ""},
		{"2.0-1", true, ""}, {"2.1-1", true, ""}, {"2.2-1", false, ""},
	} {
		hit, fixed := inRange("deb", c.v, ev)
		if hit != c.hit || fixed != c.fixed {
			t.Errorf("%s: %v %q", c.v, hit, fixed)
		}
	}
}

func TestParseEPSS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, epssFileName)
	f, _ := os.Create(path)
	zw := gzip.NewWriter(f)
	_, _ = zw.Write([]byte("#model_version:v2026.06.15,score_date:2026-11-25T12:00:23Z\ncve,epss,percentile\nCVE-1999-0001,0.04753,0.92648\nbad,row\n"))
	zw.Close()
	f.Close()
	tb, err := parseEPSS(path)
	if err != nil || tb.date != "2026-11-25" || len(tb.scores) != 1 || tb.scores["CVE-1999-0001"].Prob < 0.047 {
		t.Fatalf("%+v %v", tb, err)
	}
}

func TestExcludedGroupIsHiddenAndComesBack(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	r.loadCatalog()
	r.snapshot(r.now.Add(-time.Hour), pkg{name: "exim", version: "4.69", typ: "slackware"})
	if list := r.scan(); len(list) != 1 {
		t.Fatalf("%+v", list)
	}
	rep, err := r.s.Report(ctx)
	if err != nil || len(rep.Findings) != 1 || rep.Summary.Open != 1 || len(rep.Hosts) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}

	// The host's group turns vulnerability management off: it vanishes from the report,
	// the counts and the day's history, but its findings stay stored.
	off := true
	r.s.Excluded = func(string) bool { return off }
	r.s.now = func() time.Time { return r.now.Add(time.Hour) }
	if list := r.scan(); len(list) != 1 {
		t.Fatalf("findings must be kept while hidden: %+v", list)
	}
	rep, err = r.s.Report(ctx)
	if err != nil || len(rep.Findings) != 0 || rep.Summary.Open != 0 || rep.Summary.KEV != 0 || len(rep.Hosts) != 0 {
		t.Fatalf("host still reported: %+v %v", rep, err)
	}
	hist, err := r.st.ListVulnHistory(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range hist {
		if p.Critical+p.High+p.Medium+p.Low+p.New != 0 {
			t.Fatalf("history counts an excluded host: %+v", p)
		}
	}

	// Back on: it is there at once, without a scan.
	off = false
	rep, err = r.s.Report(ctx)
	if err != nil || len(rep.Findings) != 1 || rep.Summary.Open != 1 || len(rep.Hosts) != 1 {
		t.Fatalf("host did not come back: %+v %v", rep, err)
	}
}
