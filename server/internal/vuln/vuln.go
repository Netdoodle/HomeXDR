// Package vuln finds known vulnerabilities in the software agents report, and scores each by
// real risk: how bad it is (CVSS) times how likely it is to be used against that host. Distro
// packages are checked against OSV's distro advisories, downloaded in advance; other software
// is matched by name against CISA's catalog of known exploited vulnerabilities. Findings live on
// the Vulnerabilities page and raise no alerts. See docs/vulnerabilities.md.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/lists"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	// ListID is the catalog's entry on the Offline lists tab.
	ListID = "kev"

	kevFileName = "known_exploited_vulnerabilities.json"
	kevURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	settingsKey = "vuln_settings"

	// Confidence of a match.
	Confirmed = "confirmed"
	Possible  = "possible"

	scanEvery      = time.Hour
	scanStartDelay = 2 * time.Minute
	inventoryDays  = 14               // an older software list is not used
	snapshotWindow = 30 * time.Minute // rows of one snapshot arrive within this
	maxPackages    = 50000
	maxOSVQueries  = 200
	osvURL         = "https://api.osv.dev/v1/querybatch"
)

// Settings configure optional checks.
type Settings struct {
	// OSV sends the names and versions of possibly matching packages to api.osv.dev.
	OSV bool `json:"osv"`
}

// ExposureSource says which hosts take connections from the internet, and on which ports.
// Core implements it from the firewall log.
type ExposureSource interface {
	InternetExposure(ctx context.Context) (map[string][]int, error)
}

// Coverage of a host.
const (
	CoverageFull    = "full"     // distro advisories cover its packages
	CoverageKEVOnly = "kev_only" // only CISA's catalog, by name
	CoverageNone    = "none"     // no software list
)

// Host is one host on the Vulnerabilities page.
type Host struct {
	HostID     string     `json:"host_id"`
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os"`
	Packages   int        `json:"packages"`
	SnapshotAt *time.Time `json:"snapshot_at,omitempty"`
	// Note says why there is no data, when the agent gave a reason.
	Note         string  `json:"note,omitempty"`
	Coverage     string  `json:"coverage"`
	Exposure     string  `json:"exposure"`
	ExposedPorts []int   `json:"exposed_ports"`
	Open         int     `json:"open"`
	MaxRisk      float64 `json:"max_risk"`
}

// Summary counts the open findings.
type Summary struct {
	Open            int `json:"open"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	InternetExposed int `json:"internet_exposed"`
	KEV             int `json:"kev"`
	New7d           int `json:"new_7d"`
	Fixed7d         int `json:"fixed_7d"`
	NoFix           int `json:"no_fix"`
}

// SourceStatus is one data source.
type SourceStatus struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Entries    int        `json:"entries"`
	LastUpdate *time.Time `json:"last_update,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// OSVStatus is the optional online OSV check.
type OSVStatus struct {
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}

// Report is the Vulnerabilities page.
type Report struct {
	Findings []store.VulnFinding      `json:"findings"`
	Summary  Summary                  `json:"summary"`
	History  []store.VulnHistoryPoint `json:"history"`
	Hosts    []Host                   `json:"hosts"`
	Sources  []SourceStatus           `json:"sources"`
	OSVAPI   OSVStatus                `json:"osv_api"`
	LastRun  *time.Time               `json:"last_run,omitempty"`
	Running  bool                     `json:"running"`
}

// Service keeps findings up to date.
type Service struct {
	st    *store.Store
	ev    events.Store
	lists *lists.Service
	log   *slog.Logger
	// Exposure, when set, says which hosts the internet can reach.
	Exposure ExposureSource
	// Excluded, when set, says whether hosts in a group are left out of vulnerability
	// management (the group's Vulnerability management setting is Off). Their findings are
	// kept but hidden and not refreshed, so turning it back On shows them again at once.
	Excluded func(groupID string) bool
	// HTTP makes the optional OSV requests (tests replace it and OSVURL).
	HTTP   *http.Client
	OSVURL string
	NVDURL string
	now    func() time.Time

	kev     atomic.Pointer[catalog]
	epss    atomic.Pointer[epssTable]
	poke    chan struct{}
	running atomic.Bool

	nvdMu    sync.Mutex
	nvdCache map[string]nvdCacheEntry

	osvMu  sync.Mutex
	osvGen int
	osvIdx *osvIndex

	mu         sync.Mutex
	hosts      map[string]Host
	lastRun    time.Time
	osvError   string
	exposure   map[string][]int
	exposureAt time.Time
}

// New registers the catalog, the distro advisories and the exploit scores on the offline lists.
// It starts nothing.
func New(st *store.Store, ev events.Store, l *lists.Service, log *slog.Logger) *Service {
	s := &Service{
		st: st, ev: ev, lists: l, log: log, OSVURL: osvURL, NVDURL: nvdURL,
		HTTP: &http.Client{Timeout: time.Minute},
		now:  func() time.Time { return time.Now().UTC() },
		poke: make(chan struct{}, 1), hosts: map[string]Host{},
	}
	l.Register(&lists.Source{
		ID: ListID, Name: "Known exploited vulnerabilities (CISA)",
		About:   "The vulnerabilities CISA knows are being exploited. Used in the risk score on the Vulnerabilities page, and to match software no distro advisories cover.",
		SiteURL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", DefaultOn: true, Every: 24 * time.Hour, MaxBytes: 32 << 20, MinEntries: 100,
		License: "U.S. government data from CISA, free to use.", LicenseURL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		Files: func(time.Time) []lists.RemoteFile { return []lists.RemoteFile{{Name: kevFileName, URL: kevURL}} },
		Load: func(dir string) (func(), int, error) {
			c, err := parseCatalog(filepath.Join(dir, kevFileName))
			if err != nil {
				return nil, 0, err
			}
			return func() {
				s.kev.Store(c)
				s.Poke()
			}, c.entries, nil
		},
		Clear: func() { s.kev.Store(nil) },
	})
	s.registerOSV(l)
	s.registerEPSS(l)
	return s
}

// excludedHosts returns the IDs of hosts whose group has vulnerability management off.
func (s *Service) excludedHosts(hosts []*store.Host) map[string]bool {
	out := map[string]bool{}
	if s.Excluded == nil {
		return out
	}
	for _, h := range hosts {
		if s.Excluded(h.GroupID) {
			out[h.ID] = true
		}
	}
	return out
}

// Poke asks for a scan soon.
func (s *Service) Poke() {
	select {
	case s.poke <- struct{}{}:
	default:
	}
}

// Settings returns the optional check settings.
func (s *Service) Settings(ctx context.Context) Settings {
	var set Settings
	_ = s.st.GetKV(ctx, settingsKey, &set)
	return set
}

// SaveSettings stores them.
func (s *Service) SaveSettings(ctx context.Context, set Settings) error {
	return s.st.SetKV(ctx, settingsKey, set)
}

// pkg is one line of a host's software list.
type pkg struct {
	name, version, typ string
	// source is the source package, when the package manager records one.
	source string
}

// inventoryEvents reads the events of a host's newest software list: its newest row, then
// the rows of that snapshot.
func (s *Service) inventoryEvents(ctx context.Context, hostID string, now time.Time) ([]*event.Event, time.Time, error) {
	from, to := now.AddDate(0, 0, -inventoryDays), now.Add(time.Minute)
	newest, err := events.SampleSource(ctx, s.ev, hostID, event.ModuleInventory, "inventory.software.list", from, to, 1)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(newest) == 0 {
		return nil, time.Time{}, nil
	}
	at := newest[0].Timestamp
	rows, err := events.SampleSource(ctx, s.ev, hostID, event.ModuleInventory, "inventory.software.list", at.Add(-snapshotWindow), to, maxPackages)
	if err != nil {
		return nil, time.Time{}, err
	}
	return rows, at, nil
}

// inventory reads a host's newest software list.
func (s *Service) inventory(ctx context.Context, hostID string, now time.Time) ([]pkg, time.Time, error) {
	rows, at, err := s.inventoryEvents(ctx, hostID, now)
	if err != nil || len(rows) == 0 {
		return nil, at, err
	}
	seen := map[pkg]bool{}
	out := make([]pkg, 0, len(rows))
	for _, e := range rows {
		if e.Package == nil || e.Package.Name == "" {
			continue
		}
		p := pkg{name: e.Package.Name, version: e.Package.Version, typ: e.Package.Type, source: e.Package.Source}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, at, nil
}

// matchPackages compares a host's software with the catalog.
func matchPackages(c *catalog, host *store.Host, pkgs []pkg, now time.Time) []store.VulnMatch {
	var out []store.VulnMatch
	for _, p := range pkgs {
		name := p.name
		if p.typ == "docker" {
			name = imageName(name)
		}
		for _, e := range c.byName[norm(name)] {
			m := store.VulnMatch{
				HostID: host.ID, Hostname: host.Hostname, Package: p.name, Version: p.version, PackageType: p.typ,
				CVE: e.CVE, Title: e.Name, KEVDate: e.DateAdded, DueDate: e.DueDate,
				Ransomware: strings.EqualFold(e.Ransomware, "known"), FirstSeen: now, LastSeen: now,
				Confidence: Possible,
			}
			if keep := judgeVersion(&m, e); keep {
				out = append(out, m)
			}
		}
	}
	return out
}

// judgeVersion applies the version limit in the catalog's description, when it states one and
// the package's version number can be trusted. It returns false for a version past the limit.
func judgeVersion(m *store.VulnMatch, e *Entry) bool {
	m.Reason = "The name matches. CISA's catalog has no version ranges, so this does not say your version is affected."
	b, ok := descriptionBound(e.Description)
	if !ok {
		return true
	}
	if !trustsVersionNumber(m.PackageType, m.Version) {
		m.Reason = "The name matches. CISA's description names a fixed version, but this package's version number cannot settle it, because distributions fix old versions without raising the number."
		return true
	}
	cmp, ok := compareVersions(comparableVersion(m.PackageType, m.Version), b.version)
	if !ok {
		return true
	}
	if cmp < 0 || (cmp == 0 && b.inclusive) {
		m.Confidence = Confirmed
		word := "before"
		if b.inclusive {
			word = "up to"
		}
		m.Reason = fmt.Sprintf("Version %s is affected: CISA's description says versions %s %s are.", m.Version, word, b.version)
		return true
	}
	return false
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d+`)

// osvEcosystem names the OSV ecosystem for a package on a host, or "" when OSV has none. It
// has none for Slackware or Docker images.
func osvEcosystem(os event.OS, pkgType string) string {
	name := strings.ToLower(os.Name)
	switch pkgType {
	case "deb":
		switch {
		case strings.Contains(name, "ubuntu"):
			if strings.HasSuffix(os.Version, ".04") && len(os.Version) >= 2 && (os.Version[1]-'0')%2 == 0 {
				return "Ubuntu:" + os.Version + ":LTS"
			}
			return "Ubuntu:" + os.Version
		case strings.Contains(name, "debian"):
			major, _, _ := strings.Cut(os.Version, ".")
			return "Debian:" + major
		}
	case "apk":
		if strings.Contains(name, "alpine") {
			parts := strings.Split(os.Version, ".")
			if len(parts) >= 2 {
				return "Alpine:v" + parts[0] + "." + parts[1]
			}
		}
	}
	return ""
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// osvCheck asks OSV about possible matches only, never a host's whole software list. A match
// OSV lists for that exact version becomes confirmed. Anything else stays as it was.
func (s *Service) osvCheck(ctx context.Context, host *store.Host, list []store.VulnMatch) error {
	type key struct{ name, version string }
	index := map[key]int{}
	var queries []osvQuery
	for i := range list {
		m := &list[i]
		if m.Confidence != Possible {
			continue
		}
		eco := osvEcosystem(host.OS, m.PackageType)
		if eco == "" || m.Version == "" {
			continue
		}
		k := key{m.Package, m.Version}
		if _, ok := index[k]; ok {
			continue
		}
		if len(queries) == maxOSVQueries {
			break
		}
		index[k] = len(queries)
		var q osvQuery
		q.Package.Name, q.Package.Ecosystem, q.Version = m.Package, eco, m.Version
		queries = append(queries, q)
	}
	if len(queries) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.OSVURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return errors.New("could not reach api.osv.dev. If your firewall or DNS blocklist blocks it, allow this host or turn this check off")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api.osv.dev answered HTTP %d", resp.StatusCode)
	}
	var res struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&res); err != nil {
		return fmt.Errorf("api.osv.dev sent something unreadable: %w", err)
	}
	if len(res.Results) != len(queries) {
		return errors.New("api.osv.dev answered a different number of questions than it was asked")
	}
	for i := range list {
		m := &list[i]
		idx, ok := index[key{m.Package, m.Version}]
		if !ok || m.Confidence != Possible {
			continue
		}
		for _, v := range res.Results[idx].Vulns {
			if cveRe.FindString(v.ID) == m.CVE {
				m.Confidence = Confirmed
				m.Reason = fmt.Sprintf("OSV lists version %s of this package as affected by %s.", m.Version, m.CVE)
				break
			}
		}
	}
	return nil
}

// exposureEvery is how often the firewall log is asked which hosts the internet reaches. The
// query reads days of firewall log, so it is not run every scan.
const (
	exposureEvery = 6 * time.Hour
	keepFixed     = 30 * 24 * time.Hour
	historyDays   = 180
)

// internetExposure returns host ID -> ports reached from the internet, cached.
func (s *Service) internetExposure(ctx context.Context, now time.Time) map[string][]int {
	s.mu.Lock()
	cached, at := s.exposure, s.exposureAt
	s.mu.Unlock()
	if cached != nil && now.Sub(at) < exposureEvery {
		return cached
	}
	if s.Exposure == nil {
		return map[string][]int{}
	}
	m, err := s.Exposure.InternetExposure(ctx)
	if err != nil {
		s.log.Warn("vulnerabilities: read exposure from the firewall log", "err", err)
		if cached != nil {
			return cached
		}
		return map[string][]int{}
	}
	s.mu.Lock()
	s.exposure, s.exposureAt = m, now
	s.mu.Unlock()
	return m
}

// matchName is the name distro advisories use for a package: the source package for deb and
// apk, the package itself for rpm.
func matchName(p pkg) string {
	if p.typ != "rpm" && p.source != "" {
		return p.source
	}
	return p.name
}

type hostScan struct {
	host *store.Host
	pkgs []pkg
	at   time.Time
	eco  string
	d    *distro
}

// Scan checks every host's newest software list, scores what it finds, and keeps the results
// and the day's counts. A host with no recent list keeps its results.
func (s *Service) Scan(ctx context.Context) error {
	now := s.now()
	kevCat := s.kev.Load()
	scores := s.epss.Load()
	hosts, err := s.st.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return err
	}
	existing, err := s.st.ListVulnFindings(ctx)
	if err != nil {
		return err
	}
	byHost := map[string][]store.VulnFinding{}
	for _, f := range existing {
		byHost[f.HostID] = append(byHost[f.HostID], f)
	}
	exposure := s.internetExposure(ctx, now)
	osvOn := s.Settings(ctx).OSV
	var osvErr string

	// 1. Read every host's software list, and note which distro packages to look up.
	active := map[string]bool{}
	infos := map[string]Host{}
	var scans []hostScan
	want := map[string]map[string]bool{}
	used := map[string]bool{}
	excluded := s.excludedHosts(hosts)
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		active[h.ID] = true
		if excluded[h.ID] {
			// Vulnerability management is off for the host's group: keep its old findings
			// untouched (hidden from reports) and look at nothing new.
			continue
		}
		info := Host{HostID: h.ID, Hostname: h.Hostname, OS: strings.TrimSpace(h.OS.Name + " " + h.OS.Version), Coverage: CoverageNone,
			Exposure: ExposureLAN, ExposedPorts: []int{}}
		if ports := exposure[h.ID]; len(ports) > 0 {
			info.Exposure, info.ExposedPorts = ExposureInternet, ports
		}
		for _, sensor := range h.Sensors {
			if sensor.Name == event.ModuleInventory {
				info.Note = sensor.Error
			}
		}
		pkgs, at, err := s.inventory(ctx, h.ID, now)
		if err != nil {
			s.log.Warn("vulnerabilities: read software list", "host", h.Hostname, "err", err)
		}
		infos[h.ID] = info
		if err != nil || len(pkgs) == 0 {
			continue
		}
		info.Packages, info.SnapshotAt = len(pkgs), &at
		info.Coverage = CoverageKEVOnly
		hs := hostScan{host: h, pkgs: pkgs, at: at}
		if eco, d, ok := hostEcosystem(h.OS); ok {
			hs.eco, hs.d = eco, d
			used[d.Name] = true
			if want[eco] == nil {
				want[eco] = map[string]bool{}
			}
			for _, p := range pkgs {
				if packageKind(p.typ) == d.Kind {
					want[eco][matchName(p)] = true
				}
			}
		}
		infos[h.ID] = info
		scans = append(scans, hs)
	}
	s.noteEcosystems(ctx, used)
	idx, err := s.index(want)
	if err != nil {
		s.log.Warn("vulnerabilities: read distro advisories", "err", err)
		idx = &osvIndex{byPkg: map[ecoPkg][]*advisory{}}
	}
	osvDir := s.lists.Dir(OSVListID)

	// 2. Match, score and keep each host's findings.
	for _, hs := range scans {
		h := hs.host
		info := infos[h.ID]
		covered := false
		if hs.d != nil && osvDir != "" && s.lists.Enabled(OSVListID) {
			if _, err := os.Stat(filepath.Join(osvDir, hs.d.File)); err == nil {
				covered = true
				info.Coverage = CoverageFull
			}
		}
		found := map[string]*store.VulnFinding{}
		add := func(f store.VulnFinding) {
			k := f.SourcePackage + "|" + f.CVE
			if old, ok := found[k]; ok {
				// Two advisories for the same CVE: keep the more severe, and the later fix.
				if f.CVSS != nil && (old.CVSS == nil || *f.CVSS > *old.CVSS) {
					old.CVSS, old.CVSSVector, old.SeveritySource, old.AttackVector = f.CVSS, f.CVSSVector, f.SeveritySource, f.AttackVector
				}
				if f.FixedVersion == "" {
					old.FixedVersion = ""
				}
				return
			}
			found[k] = &f
		}
		if covered {
			seen := map[string]bool{}
			for _, p := range hs.pkgs {
				if packageKind(p.typ) != hs.d.Kind {
					continue
				}
				name := matchName(p)
				if seen[name+"|"+p.version] {
					continue
				}
				seen[name+"|"+p.version] = true
				for _, adv := range idx.byPkg[ecoPkg{hs.eco, name}] {
					hit, fixed := adv.affects(hs.d.Kind, p.version)
					if !hit {
						continue
					}
					sev, src := advisorySeverity(adv)
					cvss := sev.Score
					ids := adv.CVEs
					if len(ids) == 0 {
						ids = []string{adv.ID}
					}
					for _, id := range ids {
						add(store.VulnFinding{
							HostID: h.ID, Hostname: h.Hostname, Package: p.name, SourcePackage: name, Version: p.version, PackageType: p.typ,
							CVE: id, Title: shortTitle(adv.Summary, adv.ID), Summary: adv.Summary, FixedVersion: fixed,
							CVSS: &cvss, CVSSVector: sev.Vector, SeveritySource: src, AttackVector: sev.AttackVector,
							Confidence: Confirmed,
						})
					}
				}
			}
		}
		// Software no distro advisories cover is matched by name against CISA's catalog.
		if kevCat != nil {
			var rest []pkg
			for _, p := range hs.pkgs {
				if !covered || packageKind(p.typ) != hs.d.Kind {
					rest = append(rest, p)
				}
			}
			if !covered && h.OS.Name != "" {
				rest = append(rest, pkg{name: h.OS.Name, version: h.OS.Version, typ: "os"})
			}
			matches := matchPackages(kevCat, h, rest, now)
			if osvOn {
				if err := s.osvCheck(ctx, h, matches); err != nil {
					osvErr = err.Error()
					s.log.Warn("vulnerabilities: OSV check failed", "err", err)
				}
				// Whole-OS products without a distro feed (Unraid) are settled by the NVD.
				var extra []store.VulnFinding
				var err error
				matches, extra, err = s.nvdRefine(ctx, h, matches, rest)
				if err != nil {
					osvErr = err.Error()
					s.log.Warn("vulnerabilities: NVD check failed", "err", err)
				}
				for _, f := range extra {
					add(f)
				}
			}
			for _, m := range matches {
				est := 7.5
				add(store.VulnFinding{
					HostID: h.ID, Hostname: h.Hostname, Package: m.Package, SourcePackage: m.Package, Version: m.Version, PackageType: m.PackageType,
					CVE: m.CVE, Title: m.Title, Summary: m.Reason, CVSS: &est, SeveritySource: "estimated", Confidence: m.Confidence,
				})
			}
		}
		list := make([]store.VulnFinding, 0, len(found))
		for _, f := range found {
			s.enrich(f, kevCat, scores, info)
			list = append(list, *f)
		}
		merged := mergeFindings(list, byHost[h.ID], now)
		if err := s.st.ReplaceVulnFindings(ctx, h.ID, merged); err != nil {
			return err
		}
		infos[h.ID] = info
	}
	// Hosts that are gone: forget their results. Hosts with no recent software list keep
	// theirs, but fixed ones still go after 30 days.
	scanned := map[string]bool{}
	for _, hs := range scans {
		scanned[hs.host.ID] = true
	}
	for hostID, old := range byHost {
		if !active[hostID] {
			if err := s.st.ReplaceVulnFindings(ctx, hostID, nil); err != nil {
				return err
			}
			continue
		}
		if scanned[hostID] || excluded[hostID] {
			continue
		}
		kept := old[:0:0]
		for _, f := range old {
			if f.Status == store.VulnFixed && f.FixedAt != nil && now.Sub(*f.FixedAt) > keepFixed {
				continue
			}
			kept = append(kept, f)
		}
		if len(kept) != len(old) {
			if err := s.st.ReplaceVulnFindings(ctx, hostID, kept); err != nil {
				return err
			}
		}
	}
	if err := s.saveHistory(ctx, now, excluded); err != nil {
		s.log.Warn("vulnerabilities: save history", "err", err)
	}
	s.mu.Lock()
	s.hosts, s.lastRun, s.osvError = infos, now, osvErr
	s.mu.Unlock()
	return nil
}

// enrich adds what is known about the CVE and the host, and the risk score.
func (s *Service) enrich(f *store.VulnFinding, kevCat *catalog, scores *epssTable, h Host) {
	f.Exposure, f.ExposedPorts = h.Exposure, h.ExposedPorts
	in := riskInput{AttackVector: f.AttackVector, Exposure: h.Exposure, Ports: h.ExposedPorts, EPSS: -1}
	if f.CVSS != nil {
		in.CVSS = *f.CVSS
	}
	if kevCat != nil {
		if e := kevCat.byCVE[f.CVE]; e != nil {
			f.KEV, f.KEVDueDate = true, e.DueDate
			f.Ransomware = strings.EqualFold(e.Ransomware, "known")
			f.Title = e.Name
		}
	}
	in.KEV, in.Ransomware = f.KEV, f.Ransomware
	if scores != nil {
		if sc, ok := scores.scores[f.CVE]; ok {
			p, pct := float64(sc.Prob), float64(sc.Percentile)
			f.EPSS, f.EPSSPercentile = &p, &pct
			in.EPSS = p
		}
	}
	r := score(in)
	f.Likelihood, f.Risk, f.Band, f.LikelihoodReasons = r.Likelihood, r.Risk, r.Band, r.Reasons
}

// mergeFindings carries state across scans: when each was first seen, accepted risks, and fixed
// ones (gone from the newest software list), which are kept for 30 days.
func mergeFindings(found, old []store.VulnFinding, now time.Time) []store.VulnFinding {
	prev := map[string]store.VulnFinding{}
	for _, o := range old {
		prev[o.SourcePackage+"|"+o.CVE] = o
	}
	in := map[string]bool{}
	out := make([]store.VulnFinding, 0, len(found)+len(old))
	for _, f := range found {
		k := f.SourcePackage + "|" + f.CVE
		in[k] = true
		f.Status, f.FirstSeen, f.LastSeen, f.FixedAt = store.VulnOpen, now, now, nil
		if o, ok := prev[k]; ok {
			if !o.FirstSeen.IsZero() {
				f.FirstSeen = o.FirstSeen
			}
			if o.Status == store.VulnAccepted {
				f.Status, f.AcceptedNote = store.VulnAccepted, o.AcceptedNote
			}
		}
		out = append(out, f)
	}
	for _, o := range old {
		if in[o.SourcePackage+"|"+o.CVE] {
			continue
		}
		if o.Status != store.VulnFixed {
			t := now
			o.Status, o.FixedAt = store.VulnFixed, &t
		}
		if o.FixedAt != nil && now.Sub(*o.FixedAt) > keepFixed {
			continue
		}
		out = append(out, o)
	}
	return out
}

// saveHistory stores today's counts for the charts.
func (s *Service) saveHistory(ctx context.Context, now time.Time, excluded map[string]bool) error {
	list, err := s.st.ListVulnFindings(ctx)
	if err != nil {
		return err
	}
	day := now.Format("2006-01-02")
	p := store.VulnHistoryPoint{Date: day}
	for _, f := range list {
		if excluded[f.HostID] {
			continue
		}
		if f.FirstSeen.Format("2006-01-02") == day {
			p.New++
		}
		if f.FixedAt != nil && f.FixedAt.Format("2006-01-02") == day {
			p.Fixed++
		}
		if f.Status != store.VulnOpen {
			continue
		}
		switch f.Band {
		case BandCritical:
			p.Critical++
		case BandHigh:
			p.High++
		case BandMedium:
			p.Medium++
		default:
			p.Low++
		}
	}
	return s.st.SaveVulnHistory(ctx, p)
}

// SetAccepted marks a finding as an accepted risk, or undoes that.
func (s *Service) SetAccepted(ctx context.Context, hostID, pkg, cve string, accepted bool, note string) error {
	return s.st.SetVulnAccepted(ctx, hostID, pkg, cve, accepted, strings.TrimSpace(note))
}

// Report builds the Vulnerabilities page.
func (s *Service) Report(ctx context.Context) (*Report, error) {
	list, err := s.st.ListVulnFindings(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := s.st.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return nil, err
	}
	if excluded := s.excludedHosts(hosts); len(excluded) > 0 {
		kept := list[:0:0]
		for _, f := range list {
			if !excluded[f.HostID] {
				kept = append(kept, f)
			}
		}
		list = kept
		visible := hosts[:0:0]
		for _, h := range hosts {
			if !excluded[h.ID] {
				visible = append(visible, h)
			}
		}
		hosts = visible
	}
	now := s.now()
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Risk != list[j].Risk {
			return list[i].Risk > list[j].Risk
		}
		if list[i].Hostname != list[j].Hostname {
			return list[i].Hostname < list[j].Hostname
		}
		return list[i].CVE < list[j].CVE
	})
	rep := &Report{Findings: list, Hosts: []Host{}, Sources: []SourceStatus{}, Running: s.running.Load()}
	type hostAgg struct {
		open int
		max  float64
	}
	agg := map[string]*hostAgg{}
	week := now.Add(-7 * 24 * time.Hour)
	for _, f := range list {
		if f.FixedAt != nil && f.FixedAt.After(week) {
			rep.Summary.Fixed7d++
		}
		if f.Status != store.VulnOpen {
			continue
		}
		sm := &rep.Summary
		sm.Open++
		switch f.Band {
		case BandCritical:
			sm.Critical++
		case BandHigh:
			sm.High++
		case BandMedium:
			sm.Medium++
		default:
			sm.Low++
		}
		if f.Exposure == ExposureInternet {
			sm.InternetExposed++
		}
		if f.KEV {
			sm.KEV++
		}
		if f.FirstSeen.After(week) {
			sm.New7d++
		}
		if f.FixedVersion == "" {
			sm.NoFix++
		}
		a := agg[f.HostID]
		if a == nil {
			a = &hostAgg{}
			agg[f.HostID] = a
		}
		a.open++
		if f.Risk > a.max {
			a.max = f.Risk
		}
	}
	hist, err := s.st.ListVulnHistory(ctx, now.AddDate(0, 0, -historyDays).Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	rep.History = hist
	views := s.lists.Views()
	for _, id := range []string{OSVListID, EPSSListID, ListID} {
		for _, v := range views {
			if v.ID == id {
				rep.Sources = append(rep.Sources, SourceStatus{ID: v.ID, Name: v.Name, Enabled: v.Enabled, Entries: v.Entries, LastUpdate: v.LastUpdate, Error: v.Error})
			}
		}
	}
	rep.OSVAPI.Enabled = s.Settings(ctx).OSV
	s.mu.Lock()
	defer s.mu.Unlock()
	rep.OSVAPI.Error = s.osvError
	if !s.lastRun.IsZero() {
		t := s.lastRun
		rep.LastRun = &t
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		info, ok := s.hosts[h.ID]
		if !ok {
			info = Host{HostID: h.ID, Hostname: h.Hostname, OS: strings.TrimSpace(h.OS.Name + " " + h.OS.Version), Coverage: CoverageNone, Exposure: ExposureLAN, ExposedPorts: []int{}}
		}
		if a := agg[h.ID]; a != nil {
			info.Open, info.MaxRisk = a.open, a.max
		}
		rep.Hosts = append(rep.Hosts, info)
	}
	return rep, nil
}

// StartScan runs a scan in the background, unless one is running.
func (s *Service) StartScan() bool {
	if !s.running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer s.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := s.Scan(ctx); err != nil {
			s.log.Warn("vulnerabilities: scan failed", "err", err)
		}
	}()
	return true
}

// Run scans every hour, and soon after the catalog changes, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	wait := time.NewTimer(scanStartDelay)
	defer wait.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.poke:
		case <-wait.C:
		}
		if s.running.CompareAndSwap(false, true) {
			if err := s.Scan(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("vulnerabilities: scan failed", "err", err)
			}
			s.running.Store(false)
		}
		wait.Reset(scanEvery)
	}
}
