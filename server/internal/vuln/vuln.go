// Package vuln compares the software agents report with CISA's catalog of known exploited
// vulnerabilities. The catalog has no version ranges, so matching is by name and conservative:
// a result is a "possible match" unless a version check confirms it, and only confirmed matches
// raise an alert. See docs/vulnerabilities.md.
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
	"path/filepath"
	"regexp"
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

// Notifier raises and resolves alerts. Core implements it, so this package need not know how.
type Notifier interface {
	RaiseVuln(ctx context.Context, m store.VulnMatch) error
	ResolveVuln(ctx context.Context, hostID, cve, note string) error
}

// HostInventory says what software data a host has given.
type HostInventory struct {
	HostID     string     `json:"host_id"`
	Hostname   string     `json:"hostname"`
	Packages   int        `json:"packages"`
	SnapshotAt *time.Time `json:"snapshot_at,omitempty"`
	// Note says why there is no data, when the agent gave a reason.
	Note string `json:"note,omitempty"`
}

// Report is the Vulnerabilities page.
type Report struct {
	Matches   []store.VulnMatch `json:"matches"`
	Confirmed int               `json:"confirmed"`
	Possible  int               `json:"possible"`
	Hosts     []HostInventory   `json:"hosts"`
	KEV       KEVStatus         `json:"kev"`
	OSV       OSVStatus         `json:"osv"`
	LastRun   *time.Time        `json:"last_run,omitempty"`
	Running   bool              `json:"running"`
}

// KEVStatus is how the catalog download is doing.
type KEVStatus struct {
	Enabled    bool       `json:"enabled"`
	Entries    int        `json:"entries"`
	Version    string     `json:"version,omitempty"`
	LastUpdate *time.Time `json:"last_update,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// OSVStatus is the optional OSV check.
type OSVStatus struct {
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}

// Service keeps matches up to date.
type Service struct {
	st     *store.Store
	ev     events.Store
	lists  *lists.Service
	notify Notifier
	log    *slog.Logger
	// HTTP makes the optional OSV requests (tests replace it and OSVURL).
	HTTP   *http.Client
	OSVURL string
	now    func() time.Time

	kev     atomic.Pointer[catalog]
	poke    chan struct{}
	running atomic.Bool

	mu       sync.Mutex
	hosts    map[string]HostInventory
	lastRun  time.Time
	osvError string
}

// New registers the catalog on the offline lists. It starts nothing.
func New(st *store.Store, ev events.Store, l *lists.Service, n Notifier, log *slog.Logger) *Service {
	s := &Service{
		st: st, ev: ev, lists: l, notify: n, log: log, OSVURL: osvURL,
		HTTP: &http.Client{Timeout: time.Minute},
		now:  func() time.Time { return time.Now().UTC() },
		poke: make(chan struct{}, 1), hosts: map[string]HostInventory{},
	}
	l.Register(&lists.Source{
		ID: ListID, Name: "Known exploited vulnerabilities (CISA)",
		About:   "The vulnerabilities CISA knows are being exploited, compared with the software your agents report. See the Vulnerabilities page.",
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
	return s
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
}

// inventory reads a host's newest software list: its newest row, then the rows of that snapshot.
func (s *Service) inventory(ctx context.Context, hostID string, now time.Time) ([]pkg, time.Time, error) {
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
	seen := map[pkg]bool{}
	out := make([]pkg, 0, len(rows))
	for _, e := range rows {
		if e.Package == nil || e.Package.Name == "" {
			continue
		}
		p := pkg{e.Package.Name, e.Package.Version, e.Package.Type}
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

// Scan compares every host's newest software list with the catalog, and raises and resolves
// alerts for what changed. A host with no recent list keeps its results.
func (s *Service) Scan(ctx context.Context) error {
	c := s.kev.Load()
	now := s.now()
	hosts, err := s.st.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return err
	}
	existing, err := s.st.ListVulnMatches(ctx)
	if err != nil {
		return err
	}
	byHost := map[string][]store.VulnMatch{}
	for _, m := range existing {
		byHost[m.HostID] = append(byHost[m.HostID], m)
	}
	inventories := map[string]HostInventory{}
	osvOn := s.Settings(ctx).OSV
	var osvErr string
	active := map[string]bool{}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		active[h.ID] = true
		inv := HostInventory{HostID: h.ID, Hostname: h.Hostname}
		for _, sensor := range h.Sensors {
			if sensor.Name == event.ModuleInventory {
				inv.Note = sensor.Error
			}
		}
		pkgs, at, err := s.inventory(ctx, h.ID, now)
		if err != nil {
			s.log.Warn("vulnerabilities: read software list", "host", h.Hostname, "err", err)
			inventories[h.ID] = inv
			continue
		}
		if len(pkgs) == 0 {
			inventories[h.ID] = inv
			continue
		}
		inv.Packages, inv.SnapshotAt = len(pkgs), &at
		inventories[h.ID] = inv
		if c == nil {
			continue
		}
		if h.OS.Name != "" {
			pkgs = append(pkgs, pkg{h.OS.Name, h.OS.Version, "os"})
		}
		found := matchPackages(c, h, pkgs, now)
		if osvOn {
			if err := s.osvCheck(ctx, h, found); err != nil {
				osvErr = err.Error()
				s.log.Warn("vulnerabilities: OSV check failed", "err", err)
			}
		}
		if err := s.reconcile(ctx, h.ID, found, byHost[h.ID]); err != nil {
			return err
		}
	}
	// Hosts that are gone: forget their results.
	for hostID, list := range byHost {
		if !active[hostID] {
			if err := s.reconcile(ctx, hostID, nil, list); err != nil {
				return err
			}
		}
	}
	s.mu.Lock()
	s.hosts, s.lastRun, s.osvError = inventories, now, osvErr
	s.mu.Unlock()
	return nil
}

// reconcile stores a host's new results, keeps when each was first seen, and raises or resolves
// one alert per host and CVE: raised for a CVE newly confirmed, resolved when it stops being so.
func (s *Service) reconcile(ctx context.Context, hostID string, found, old []store.VulnMatch) error {
	first := map[string]time.Time{}
	raised := map[string]bool{}
	for _, m := range old {
		first[m.Package+"|"+m.CVE] = m.FirstSeen
		if m.Raised {
			raised[m.CVE] = true
		}
	}
	confirmed := map[string]bool{}
	for i := range found {
		m := &found[i]
		if t, ok := first[m.Package+"|"+m.CVE]; ok && !t.IsZero() {
			m.FirstSeen = t
		}
		if m.Confidence == Confirmed {
			if !confirmed[m.CVE] && !raised[m.CVE] {
				if err := s.notify.RaiseVuln(ctx, *m); err != nil {
					s.log.Warn("vulnerabilities: raise finding", "cve", m.CVE, "err", err)
					// Left unraised, it is tried again next scan.
					continue
				}
			}
			confirmed[m.CVE] = true
		}
	}
	for i := range found {
		found[i].Raised = confirmed[found[i].CVE]
	}
	for cve := range raised {
		if !confirmed[cve] {
			if err := s.notify.ResolveVuln(ctx, hostID, cve, "This software no longer shows this vulnerability in the newest software list: it was updated, removed, or the host is gone. HomeXDR resolved this alert itself."); err != nil {
				s.log.Warn("vulnerabilities: resolve finding", "cve", cve, "err", err)
			}
		}
	}
	return s.st.ReplaceVulnMatches(ctx, hostID, found)
}

// Report builds the Vulnerabilities page.
func (s *Service) Report(ctx context.Context) (*Report, error) {
	list, err := s.st.ListVulnMatches(ctx)
	if err != nil {
		return nil, err
	}
	rep := &Report{Matches: list, Hosts: []HostInventory{}, Running: s.running.Load()}
	for _, v := range s.lists.Views() {
		if v.ID == ListID {
			rep.KEV = KEVStatus{Enabled: v.Enabled, Entries: v.Entries, LastUpdate: v.LastUpdate, Error: v.Error}
		}
	}
	// With the catalog off there is nothing to stand behind these results.
	if !rep.KEV.Enabled {
		rep.Matches = []store.VulnMatch{}
	}
	for _, m := range rep.Matches {
		if m.Confidence == Confirmed {
			rep.Confirmed++
		} else {
			rep.Possible++
		}
	}
	if c := s.kev.Load(); c != nil {
		rep.KEV.Version = c.version
	}
	hosts, err := s.st.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return nil, err
	}
	rep.OSV.Enabled = s.Settings(ctx).OSV
	s.mu.Lock()
	defer s.mu.Unlock()
	rep.OSV.Error = s.osvError
	if !s.lastRun.IsZero() {
		t := s.lastRun
		rep.LastRun = &t
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		inv, ok := s.hosts[h.ID]
		if !ok {
			inv = HostInventory{HostID: h.ID, Hostname: h.Hostname}
		}
		rep.Hosts = append(rep.Hosts, inv)
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
