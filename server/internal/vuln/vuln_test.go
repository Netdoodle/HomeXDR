package vuln

import (
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

type recorder struct {
	raised   []store.VulnMatch
	resolved []string
	fail     bool
}

func (r *recorder) RaiseVuln(_ context.Context, m store.VulnMatch) error {
	if r.fail {
		return errors.New("store is down")
	}
	r.raised = append(r.raised, m)
	return nil
}

func (r *recorder) ResolveVuln(_ context.Context, hostID, cve, _ string) error {
	r.resolved = append(r.resolved, hostID+"/"+cve)
	return nil
}

type rig struct {
	t    *testing.T
	s    *Service
	st   *store.Store
	ev   events.Store
	rec  *recorder
	now  time.Time
	host *store.Host
}

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
	rec := &recorder{}
	s := New(st, ev, l, rec, log)
	h, err := st.CreateEndpoint(context.Background(), "tower-id", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux", Name: osName, Version: osVersion}}, nil, "serial")
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, s: s, st: st, ev: ev, rec: rec, now: time.Now().UTC(), host: h}
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

// snapshot stores a software list, as the inventory sensor emits it.
func (r *rig) snapshot(at time.Time, rows ...pkg) {
	r.t.Helper()
	var evs []*event.Event
	for _, p := range rows {
		evs = append(evs, &event.Event{
			ID: event.NewID(), Timestamp: at, Host: event.Host{ID: r.host.ID, Name: "tower"},
			Event:   event.Meta{Kind: event.KindState, Module: event.ModuleInventory, Dataset: "inventory.software.list"},
			Package: &event.Package{Name: p.name, Version: p.version, Type: p.typ},
		})
	}
	if err := r.ev.Insert(context.Background(), evs); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) scan() []store.VulnMatch {
	r.t.Helper()
	if err := r.s.Scan(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	list, err := r.st.ListVulnMatches(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return list
}

func find(list []store.VulnMatch, pkgName, cve string) *store.VulnMatch {
	for i := range list {
		if list[i].Package == pkgName && list[i].CVE == cve {
			return &list[i]
		}
	}
	return nil
}

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

func TestMatchingConfidence(t *testing.T) {
	r := newRig(t, "Unraid OS", "7.2.8")
	r.loadCatalog()
	r.snapshot(r.now,
		pkg{"sudo", "1.9.17p2", "slackware"},                // no limit stated: possible
		pkg{"exim", "4.69", "slackware"},                    // below the stated limit: confirmed
		pkg{"plex-unrelated", "1.0", "slackware"},           // does not match
		pkg{"lscr.io/linuxserver/plex", "latest", "docker"}, // image, by its short name
		pkg{"kernel-modules", "6.12", "slackware"},          // not the kernel package
	)
	list := r.scan()
	if len(list) != 3 {
		t.Fatalf("%+v", list)
	}
	if m := find(list, "sudo", "CVE-2021-3156"); m == nil || m.Confidence != Possible || !strings.Contains(m.Reason, "name matches") {
		t.Errorf("%+v", m)
	}
	if m := find(list, "exim", "CVE-2010-4344"); m == nil || m.Confidence != Confirmed || !m.Ransomware || m.KEVDate != "2022-03-25" || m.DueDate != "2022-04-15" || !strings.Contains(m.Reason, "before 4.70") {
		t.Errorf("%+v", m)
	}
	if m := find(list, "lscr.io/linuxserver/plex", "CVE-2020-5741"); m == nil || m.Confidence != Possible {
		t.Errorf("%+v", m)
	}
	// Confirmed first.
	if list[0].Confidence != Confirmed {
		t.Errorf("order: %+v", list)
	}
	// Only the confirmed one alerts.
	if len(r.rec.raised) != 1 || r.rec.raised[0].CVE != "CVE-2010-4344" {
		t.Fatalf("%+v", r.rec.raised)
	}
}

func TestPatchedVersionIsDropped(t *testing.T) {
	r := newRig(t, "Unraid OS", "7.2.8")
	r.loadCatalog()
	r.snapshot(r.now, pkg{"exim", "4.98", "slackware"})
	if list := r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestBackportingDistroStaysPossible(t *testing.T) {
	r := newRig(t, "Debian GNU/Linux", "12")
	r.loadCatalog()
	// An old-looking number on Debian may well be patched, so it is never confirmed by number.
	r.snapshot(r.now, pkg{"exim4", "4.69-1+deb12u1", "deb"}, pkg{"openssl", "1.0.1e-2+deb7u5", "deb"})
	list := r.scan()
	if m := find(list, "exim4", "CVE-2010-4344"); m == nil || m.Confidence != Possible || !strings.Contains(m.Reason, "distributions") {
		t.Fatalf("%+v", m)
	}
	if len(r.rec.raised) != 0 {
		t.Fatalf("raised: %+v", r.rec.raised)
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
		r.snapshot(r.now, pkg{"example/exim", c.tag, "docker"})
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
	r.snapshot(r.now.Add(-6*time.Hour), pkg{"sudo", "1.0", "slackware"}, pkg{"exim", "4.69", "slackware"})
	r.snapshot(r.now, pkg{"bash", "5.3", "slackware"}) // sudo and exim are gone
	list := r.scan()
	if len(list) != 0 {
		t.Fatalf("%+v", list)
	}
}

func TestFindingsFollowTheInventory(t *testing.T) {
	r := newRig(t, "", "")
	r.loadCatalog()
	// Two packages with the same CVE on one host make one alert.
	r.snapshot(r.now.Add(-2*time.Hour), pkg{"exim", "4.69", "slackware"}, pkg{"exim4", "4.69", "slackware"})
	list := r.scan()
	if len(list) != 2 || len(r.rec.raised) != 1 {
		t.Fatalf("list %+v raised %+v", list, r.rec.raised)
	}
	firstSeen := list[0].FirstSeen

	// Scanning again raises nothing new and keeps when it was first seen.
	r.s.now = func() time.Time { return r.now.Add(time.Hour) }
	list = r.scan()
	if len(r.rec.raised) != 1 || !list[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("raised again: %+v", r.rec.raised)
	}

	// Patched: the alert resolves, once.
	r.snapshot(r.now.Add(-time.Minute), pkg{"exim", "4.98", "slackware"}, pkg{"exim4", "4.98", "slackware"})
	r.s.now = func() time.Time { return r.now.Add(2 * time.Hour) }
	if list = r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
	if len(r.rec.resolved) != 1 || r.rec.resolved[0] != r.host.ID+"/CVE-2010-4344" {
		t.Fatalf("%+v", r.rec.resolved)
	}
	r.scan()
	if len(r.rec.resolved) != 1 {
		t.Fatalf("resolved again: %+v", r.rec.resolved)
	}
}

func TestRaiseFailureRetries(t *testing.T) {
	r := newRig(t, "", "")
	r.loadCatalog()
	r.snapshot(r.now, pkg{"exim", "4.69", "slackware"})
	r.rec.fail = true
	r.scan()
	r.rec.fail = false
	r.scan()
	if len(r.rec.raised) != 1 {
		t.Fatalf("%+v", r.rec.raised)
	}
}

func TestDecommissionedHostIsForgotten(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	r.loadCatalog()
	r.snapshot(r.now, pkg{"exim", "4.69", "slackware"})
	r.scan()
	if err := r.st.DecommissionHost(ctx, r.host.ID); err != nil {
		t.Fatal(err)
	}
	if list := r.scan(); len(list) != 0 {
		t.Fatalf("%+v", list)
	}
	if len(r.rec.resolved) != 1 {
		t.Fatalf("%+v", r.rec.resolved)
	}
}

func TestReportExplainsMissingData(t *testing.T) {
	r := newRig(t, "", "")
	ctx := context.Background()
	rep, err := r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.KEV.Entries != 0 || !rep.KEV.Enabled || len(rep.Hosts) != 1 || rep.Hosts[0].Packages != 0 || rep.OSV.Enabled {
		t.Fatalf("%+v", rep)
	}
	// With no catalog, a software list is still counted, and nothing matches.
	r.snapshot(r.now, pkg{"sudo", "1.0", "slackware"})
	r.scan()
	rep, err = r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts[0].Packages != 1 || rep.Hosts[0].SnapshotAt == nil || len(rep.Matches) != 0 || rep.LastRun == nil {
		t.Fatalf("%+v", rep)
	}
	r.loadCatalog()
	r.scan()
	rep, err = r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Possible != 1 || rep.Confirmed != 0 || rep.KEV.Version != "2026.11.04" {
		t.Fatalf("%+v", rep)
	}
	// Turning the catalog off hides results that nothing stands behind any more.
	if err := r.s.lists.SetEnabled(ctx, ListID, false); err != nil {
		t.Fatal(err)
	}
	rep, err = r.s.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Matches) != 0 || rep.Possible != 0 || rep.KEV.Enabled || r.s.kev.Load() != nil {
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
	r.snapshot(r.now, pkg{"openssl", "1.0.1e-2", "deb"}, pkg{"sudo", "1.9.5-1", "deb"}, pkg{"bash", "5.2-1", "deb"}, pkg{"vim", "9.0-1", "deb"})

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
	if m := find(list, "openssl", "CVE-2014-0160"); m == nil || m.Confidence != Confirmed || !strings.Contains(m.Reason, "OSV") {
		t.Fatalf("%+v", m)
	}
	if m := find(list, "sudo", "CVE-2021-3156"); m == nil || m.Confidence != Possible {
		t.Fatalf("%+v", m)
	}
	if len(r.rec.raised) != 1 || r.rec.raised[0].CVE != "CVE-2014-0160" {
		t.Fatalf("%+v", r.rec.raised)
	}

	// OSV down: results stay, the error shows, nothing else breaks.
	srv.Close()
	r.scan()
	rep, err := r.s.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.OSV.Error, "api.osv.dev") {
		t.Fatalf("%+v", rep.OSV)
	}
}
