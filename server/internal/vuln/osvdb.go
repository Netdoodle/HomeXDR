package vuln

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/lists"
	"github.com/Netdoodle/homexdr/server/internal/vuln/version"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Distro advisories come from OSV's per-ecosystem exports: one zip of JSON records per
// distribution, each record naming the packages and the version that fixed them, release by
// release. Only the zips of distributions your hosts run are downloaded, and nothing about your
// hosts is sent anywhere.
const (
	OSVListID     = "osv-distros"
	osvBucket     = "https://osv-vulnerabilities.storage.googleapis.com/"
	ecosystemsKey = "vuln_ecosystems"
	osvMaxRecord  = 8 << 20
)

// distro is one OSV export.
type distro struct {
	Name string // OSV's ecosystem name, also the bucket folder
	File string // file name on disk
	Kind string // version scheme: deb, apk or rpm
	// Prefixes of the record IDs to read. Debian and Ubuntu publish one record per CVE and
	// also one per advisory (DSA, DLA, USN) covering the same fixes, so only the first are read.
	IDPrefixes []string
}

var distros = []distro{
	{Name: "Debian", File: "Debian.zip", Kind: "deb", IDPrefixes: []string{"DEBIAN-CVE-"}},
	{Name: "Ubuntu", File: "Ubuntu.zip", Kind: "deb", IDPrefixes: []string{"UBUNTU-CVE-"}},
	{Name: "Alpine", File: "Alpine.zip", Kind: "apk"},
	{Name: "Rocky Linux", File: "Rocky-Linux.zip", Kind: "rpm"},
	{Name: "AlmaLinux", File: "AlmaLinux.zip", Kind: "rpm"},
}

func distroByName(name string) *distro {
	for i := range distros {
		if distros[i].Name == name {
			return &distros[i]
		}
	}
	return nil
}

// hostEcosystem names the OSV ecosystem (with release) of a host, and its export. ok is false
// for an operating system OSV has no distro advisories for, such as Slackware and Unraid.
func hostEcosystem(os event.OS) (eco string, d *distro, ok bool) {
	name := strings.ToLower(os.Name)
	major, _, _ := strings.Cut(os.Version, ".")
	switch {
	case strings.Contains(name, "ubuntu"):
		e := osvEcosystem(os, "deb")
		return e, distroByName("Ubuntu"), e != ""
	case strings.Contains(name, "debian"), strings.Contains(name, "raspbian"):
		if major == "" {
			return "", nil, false
		}
		return "Debian:" + major, distroByName("Debian"), true
	case strings.Contains(name, "alpine"):
		e := osvEcosystem(os, "apk")
		return e, distroByName("Alpine"), e != ""
	case strings.Contains(name, "rocky"):
		if major == "" {
			return "", nil, false
		}
		return "Rocky Linux:" + major, distroByName("Rocky Linux"), true
	case strings.Contains(name, "almalinux"):
		if major == "" {
			return "", nil, false
		}
		return "AlmaLinux:" + major, distroByName("AlmaLinux"), true
	}
	return "", nil, false
}

// packageKind is the package type a distro's packages come in.
func packageKind(pkgType string) string {
	switch pkgType {
	case "deb", "apk", "rpm":
		return pkgType
	}
	return ""
}

func (s *Service) registerOSV(l *lists.Service) {
	l.Register(&lists.Source{
		ID: OSVListID, Name: "Distro security advisories (OSV)",
		About:   "Which package versions fix each CVE, for Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux. Only the distributions your hosts run are downloaded. See the Vulnerabilities page.",
		SiteURL: "https://osv.dev/", DefaultOn: true, Every: 24 * time.Hour, MaxBytes: 1200 << 20, MinEntries: 0,
		Warning: "Ubuntu's export is about 850 MB, so it is only downloaded when a host runs Ubuntu.",
		License: "Free to use. Each distribution's data keeps its own license, listed on osv.dev.", LicenseURL: "https://google.github.io/osv.dev/data/",
		Files: func(time.Time) []lists.RemoteFile {
			var out []lists.RemoteFile
			for _, name := range s.ecosystemsInUse() {
				if d := distroByName(name); d != nil {
					out = append(out, lists.RemoteFile{Name: d.File, URL: osvBucket + url.PathEscape(d.Name) + "/all.zip"})
				}
			}
			return out
		},
		Load: func(dir string) (func(), int, error) {
			n, err := countOSV(dir)
			if err != nil {
				return nil, 0, err
			}
			return func() {
				s.osvMu.Lock()
				s.osvGen++
				s.osvMu.Unlock()
				s.Poke()
			}, n, nil
		},
		Clear: func() {
			s.osvMu.Lock()
			s.osvGen++
			s.osvIdx = nil
			s.osvMu.Unlock()
		},
	})
}

// countOSV checks every zip in dir opens, and counts its records.
func countOSV(dir string) (int, error) {
	n := 0
	for _, d := range distros {
		path := filepath.Join(dir, d.File)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		zr, err := zip.OpenReader(path)
		if err != nil {
			return 0, fmt.Errorf("%s is not a readable zip: %w", d.File, err)
		}
		n += len(zr.File)
		zr.Close()
	}
	return n, nil
}

// ecosystemsInUse is the distros the last scan found, kept so a restart downloads the same.
func (s *Service) ecosystemsInUse() []string {
	var names []string
	_ = s.st.GetKV(context.Background(), ecosystemsKey, &names)
	return names
}

// noteEcosystems remembers the distros in use, and fetches the advisories when that changed.
func (s *Service) noteEcosystems(ctx context.Context, used map[string]bool) {
	names := make([]string, 0, len(used))
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	old := s.ecosystemsInUse()
	if strings.Join(old, ",") == strings.Join(names, ",") {
		return
	}
	if err := s.st.SetKV(ctx, ecosystemsKey, names); err != nil {
		s.log.Warn("vulnerabilities: save distros in use", "err", err)
		return
	}
	if s.lists.Enabled(OSVListID) {
		s.lists.StartRefresh(OSVListID)
	}
}

// osvEvent is one point of an OSV range.
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRecord struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Upstream []string      `json:"upstream"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
		Versions          []string      `json:"versions"`
		Severity          []osvSeverity `json:"severity"`
		EcosystemSpecific struct {
			Urgency string `json:"urgency"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// advisory is one record's entry for one package in one release.
type advisory struct {
	ID       string
	CVEs     []string
	Summary  string
	Severity []osvSeverity
	Urgency  string
	Ranges   [][]osvEvent
	Versions []string
}

type ecoPkg struct{ eco, pkg string }

// osvIndex holds the advisories for the packages hosts have, built from the zips on disk.
type osvIndex struct {
	gen   int
	want  string // fingerprint of the packages it was built for
	byPkg map[ecoPkg][]*advisory
	// records is how many records were read, for the sources list.
	records int
}

// index returns advisories for the wanted ecosystem packages, rebuilding when the zips or the
// wanted set changed. Building reads each zip once.
func (s *Service) index(want map[string]map[string]bool) (*osvIndex, error) {
	var fp strings.Builder
	ecos := make([]string, 0, len(want))
	for e := range want {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		pk := make([]string, 0, len(want[e]))
		for p := range want[e] {
			pk = append(pk, p)
		}
		sort.Strings(pk)
		fp.WriteString(e + "=" + strings.Join(pk, ",") + ";")
	}
	s.osvMu.Lock()
	gen, idx := s.osvGen, s.osvIdx
	s.osvMu.Unlock()
	if idx != nil && idx.gen == gen && idx.want == fp.String() {
		return idx, nil
	}
	dir := s.lists.Dir(OSVListID)
	idx = &osvIndex{gen: gen, want: fp.String(), byPkg: map[ecoPkg][]*advisory{}}
	if dir == "" || !s.lists.Enabled(OSVListID) {
		return idx, nil
	}
	byDistro := map[string]bool{}
	for e := range want {
		name, _, _ := strings.Cut(e, ":")
		byDistro[name] = true
	}
	for _, d := range distros {
		if !byDistro[d.Name] {
			continue
		}
		path := filepath.Join(dir, d.File)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := readOSVZip(path, d, want, idx); err != nil {
			return nil, err
		}
	}
	s.osvMu.Lock()
	if s.osvGen == gen {
		s.osvIdx = idx
	}
	s.osvMu.Unlock()
	return idx, nil
}

func readOSVZip(path string, d distro, want map[string]map[string]bool, idx *osvIndex) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("%s: %w", d.File, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if len(d.IDPrefixes) > 0 {
			ok := false
			for _, p := range d.IDPrefixes {
				if strings.HasPrefix(f.Name, p) {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if f.UncompressedSize64 > osvMaxRecord {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var r osvRecord
		err = json.NewDecoder(io.LimitReader(rc, osvMaxRecord)).Decode(&r)
		rc.Close()
		if err != nil {
			continue
		}
		idx.records++
		addRecord(&r, want, idx)
	}
	return nil
}

func recordCVEs(r *osvRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{{r.ID}, r.Upstream, r.Aliases} {
		for _, s := range list {
			if c := cveRe.FindString(s); c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

func addRecord(r *osvRecord, want map[string]map[string]bool, idx *osvIndex) {
	var cves []string
	cvesDone := false
	for _, a := range r.Affected {
		pk := want[a.Package.Ecosystem]
		if pk == nil || !pk[a.Package.Name] {
			continue
		}
		// Debian marks issues of no security impact as "unimportant".
		if strings.EqualFold(a.EcosystemSpecific.Urgency, "unimportant") {
			continue
		}
		if !cvesDone {
			cves, cvesDone = recordCVEs(r), true
		}
		adv := &advisory{ID: r.ID, CVEs: cves, Summary: r.Summary, Severity: r.Severity, Urgency: a.EcosystemSpecific.Urgency, Versions: a.Versions}
		if len(adv.Severity) == 0 {
			adv.Severity = a.Severity
		}
		if adv.Summary == "" {
			adv.Summary = firstSentence(r.Details)
		}
		for _, rg := range a.Ranges {
			if rg.Type == "ECOSYSTEM" {
				adv.Ranges = append(adv.Ranges, rg.Events)
			}
		}
		k := ecoPkg{a.Package.Ecosystem, a.Package.Name}
		idx.byPkg[k] = append(idx.byPkg[k], adv)
	}
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < 300 {
		return s[:i+1]
	}
	if len(s) > 300 {
		return s[:297] + "..."
	}
	return s
}

// affects says whether version v of a package is affected, and the version that fixes it ("" when
// no fix is released). ok is false when the versions could not be compared.
func (a *advisory) affects(kind, v string) (affected bool, fixed string) {
	for _, x := range a.Versions {
		if x == v {
			affected = true
		}
	}
	for _, events := range a.Ranges {
		hit, fix := inRange(kind, v, events)
		if hit {
			return true, fix
		}
	}
	if affected {
		// Listed as affected, with no range saying what fixed it.
		return true, ""
	}
	return false, ""
}

// inRange walks one OSV range: introduced opens an interval, fixed or last_affected closes it.
func inRange(kind, v string, events []osvEvent) (bool, string) {
	cmp := func(a, b string) (int, bool) {
		if b == "0" {
			return 1, true
		}
		return version.Compare(kind, a, b)
	}
	open := false
	for _, e := range events {
		switch {
		case e.Introduced != "":
			c, ok := cmp(v, e.Introduced)
			if !ok {
				return false, ""
			}
			if c >= 0 {
				open = true
			} else {
				open = false
			}
		case e.Fixed != "":
			if open {
				c, ok := version.Compare(kind, v, e.Fixed)
				if !ok {
					return false, ""
				}
				if c < 0 {
					return true, e.Fixed
				}
			}
			open = false
		case e.LastAffected != "":
			if open {
				c, ok := version.Compare(kind, v, e.LastAffected)
				if !ok {
					return false, ""
				}
				if c <= 0 {
					return true, ""
				}
			}
			open = false
		}
	}
	return open, ""
}

// advisorySeverity picks a CVSS score: a 3.x vector first, then 4.0, then the distro's own
// rating. src is "osv", "distro" or "estimated".
func advisorySeverity(a *advisory) (info cvssInfo, src string) {
	var v4 *cvssInfo
	for _, sv := range a.Severity {
		if c, ok := parseCVSS(sv.Score); ok {
			if !c.Approximate {
				return c, "osv"
			}
			if v4 == nil {
				cc := c
				v4 = &cc
			}
		}
	}
	if v4 != nil {
		return *v4, "osv"
	}
	rating := strings.ToLower(a.Urgency)
	for _, sv := range a.Severity {
		if strings.EqualFold(sv.Type, "Ubuntu") {
			rating = strings.ToLower(sv.Score)
		}
	}
	switch {
	case strings.HasPrefix(rating, "critical"):
		return cvssInfo{Score: 9.0}, "distro"
	case strings.HasPrefix(rating, "high"):
		return cvssInfo{Score: 7.5}, "distro"
	case strings.HasPrefix(rating, "medium"):
		return cvssInfo{Score: 5.5}, "distro"
	case strings.HasPrefix(rating, "low"), strings.HasPrefix(rating, "negligible"):
		return cvssInfo{Score: 3.0}, "distro"
	}
	return cvssInfo{Score: 5.0}, "estimated"
}

// shortTitle is a one-line title from an advisory's summary, or its ID when it has none.
func shortTitle(summary, id string) string {
	t := strings.TrimSpace(summary)
	t = strings.TrimPrefix(t, "Issue summary: ")
	if t == "" {
		return id
	}
	if r := []rune(t); len(r) > 100 {
		t = strings.TrimSpace(string(r[:97])) + "…"
	}
	return strings.TrimSuffix(t, ".")
}
