// Package lists downloads public lists in advance and answers questions from them with no
// network: popular domains, MAC vendors, IP networks, and whatever else registers a Source
// (the known-exploited vulnerability catalog does). Each list keeps its last good copy, so a
// failed or bad download changes nothing. See docs/lists.md.
package lists

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

const (
	settingsKey = "lists_settings"
	statusKey   = "lists_status"

	currentDir  = "current"
	lastGoodDir = "last-good"
	newDir      = "new"

	checkEvery   = 10 * time.Minute
	startDelay   = time.Minute
	retryFailure = 6 * time.Hour
	fetchTimeout = 5 * time.Minute
	userAgent    = "HomeXDR offline lists (self-hosted; https://github.com/Netdoodle/homexdr)"
)

// RemoteFile is one file of a list.
type RemoteFile struct {
	Name string // file name on disk
	URL  string
	// Optional files may be missing, as long as the list as a whole still loads.
	Optional bool
	// Fallback, when set, is tried if URL fails. The list's Load must read either.
	Fallback *RemoteFile
}

// Source is a list: where it comes from, and how to read it.
type Source struct {
	ID, Name string
	// About says in one sentence what the list gives you.
	About string
	// SiteURL is the page shown as the list's source. Warning, if any, is shown beside it.
	SiteURL string
	Warning string
	// License and LicenseURL say what the source's terms are, in plain words.
	License, LicenseURL string
	DefaultOn           bool
	Every               time.Duration
	// MaxBytes caps each downloaded file.
	MaxBytes int64
	// MinEntries guards against replacing a good list with a page of HTML or a truncated file.
	MinEntries int
	// Files lists the files to fetch now.
	Files func(now time.Time) []RemoteFile
	// KeepOld, if set, keeps a file from the current copy that Files no longer asks for.
	KeepOld func(name string, now time.Time) bool
	// Load parses a folder of files without changing anything. The returned function makes
	// the result live; nothing is live until it is called.
	Load func(dir string) (apply func(), entries int, err error)
	// Clear stops answering from this list.
	Clear func()
}

type fileState struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// status is what is remembered about a list.
type status struct {
	LastCheck  *time.Time           `json:"last_check,omitempty"`
	LastUpdate *time.Time           `json:"last_update,omitempty"`
	Entries    int                  `json:"entries"`
	Error      string               `json:"error,omitempty"`
	Files      map[string]fileState `json:"files,omitempty"`
}

// View is one line of the Offline lists settings tab.
type View struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	About      string     `json:"about"`
	SiteURL    string     `json:"site_url"`
	Warning    string     `json:"warning,omitempty"`
	License    string     `json:"license"`
	LicenseURL string     `json:"license_url,omitempty"`
	Enabled    bool       `json:"enabled"`
	DefaultOn  bool       `json:"default_on"`
	EveryHours int        `json:"every_hours"`
	LastCheck  *time.Time `json:"last_check,omitempty"`
	LastUpdate *time.Time `json:"last_update,omitempty"`
	Entries    int        `json:"entries"`
	Error      string     `json:"error,omitempty"`
	Updating   bool       `json:"updating"`
}

// ErrNoSuchList is returned for an unknown list ID.
var ErrNoSuchList = errors.New("no such list")

// Service holds every list.
type Service struct {
	dir string
	st  *store.Store
	log *slog.Logger
	// HTTP makes the downloads (tests replace it).
	HTTP *http.Client
	now  func() time.Time

	mu       sync.Mutex
	sources  []*Source
	statuses map[string]*status
	settings map[string]bool // id -> enabled, only where the owner chose
	updating map[string]bool
	loaded   bool

	tables tables
}

// New returns the service with the built-in lists. It reads settings, and downloads and loads
// nothing until Run.
func New(dir string, st *store.Store, log *slog.Logger) *Service {
	s := &Service{
		dir: dir, st: st, log: log, now: func() time.Time { return time.Now().UTC() },
		statuses: map[string]*status{}, settings: map[string]bool{}, updating: map[string]bool{},
		HTTP: &http.Client{
			Timeout: fetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
					return errors.New("redirected away from https")
				}
				return nil
			},
		},
	}
	s.sources = s.builtinSources()
	ctx := context.Background()
	_ = st.GetKV(ctx, settingsKey, &s.settings)
	_ = st.GetKV(ctx, statusKey, &s.statuses)
	if s.settings == nil {
		s.settings = map[string]bool{}
	}
	if s.statuses == nil {
		s.statuses = map[string]*status{}
	}
	return s
}

// Known reports whether a list exists.
func (s *Service) Known(id string) bool { return s.source(id) != nil }

// Register adds a list, for features outside this package.
func (s *Service) Register(src *Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, src)
}

func (s *Service) source(id string) *Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, src := range s.sources {
		if src.ID == id {
			return src
		}
	}
	return nil
}

func (s *Service) enabledLocked(src *Source) bool {
	if on, ok := s.settings[src.ID]; ok {
		return on
	}
	return src.DefaultOn
}

// Enabled reports whether a list is switched on.
func (s *Service) Enabled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, src := range s.sources {
		if src.ID == id {
			return s.enabledLocked(src)
		}
	}
	return false
}

func (s *Service) statusLocked(id string) *status {
	st := s.statuses[id]
	if st == nil {
		st = &status{}
		s.statuses[id] = st
	}
	return st
}

// saveStatus stores every list's status. The caller holds no lock.
func (s *Service) saveStatus(ctx context.Context) {
	s.mu.Lock()
	cp := make(map[string]status, len(s.statuses))
	for id, st := range s.statuses {
		cp[id] = *st
	}
	s.mu.Unlock()
	if err := s.st.SetKV(ctx, statusKey, cp); err != nil {
		s.log.Warn("lists: save status", "err", err)
	}
}

// Views returns every list for the settings tab.
func (s *Service) Views() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.sources))
	for _, src := range s.sources {
		st := s.statusLocked(src.ID)
		out = append(out, View{
			ID: src.ID, Name: src.Name, About: src.About, SiteURL: src.SiteURL, Warning: src.Warning,
			License: src.License, LicenseURL: src.LicenseURL, Enabled: s.enabledLocked(src), DefaultOn: src.DefaultOn,
			EveryHours: int(src.Every / time.Hour), LastCheck: st.LastCheck, LastUpdate: st.LastUpdate,
			Entries: st.Entries, Error: st.Error, Updating: s.updating[src.ID],
		})
	}
	return out
}

// SetEnabled switches a list on or off. Turning one on loads its copy on disk, and downloads
// it in the background if it is out of date; turning one off stops answering from it.
func (s *Service) SetEnabled(ctx context.Context, id string, on bool) error {
	src := s.source(id)
	if src == nil {
		return ErrNoSuchList
	}
	s.mu.Lock()
	s.settings[id] = on
	cp := make(map[string]bool, len(s.settings))
	for k, v := range s.settings {
		cp[k] = v
	}
	s.mu.Unlock()
	if err := s.st.SetKV(ctx, settingsKey, cp); err != nil {
		return err
	}
	if !on {
		src.Clear()
		s.mu.Lock()
		s.statusLocked(id).Error = ""
		s.mu.Unlock()
		s.saveStatus(ctx)
		return nil
	}
	s.loadFromDisk(src)
	s.StartRefresh(id)
	return nil
}

// StartRefresh checks a list for a new copy in the background, unless a check is running.
func (s *Service) StartRefresh(id string) bool {
	if s.source(id) == nil || !s.claim(id) {
		return false
	}
	go func() {
		defer s.release(id)
		ctx, cancel := context.WithTimeout(context.Background(), 2*fetchTimeout)
		defer cancel()
		if err := s.refresh(ctx, s.source(id)); err != nil {
			s.log.Warn("lists: update failed", "list", id, "err", err)
		}
	}()
	return true
}

func (s *Service) claim(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updating[id] {
		return false
	}
	s.updating[id] = true
	return true
}

func (s *Service) release(id string) {
	s.mu.Lock()
	delete(s.updating, id)
	s.mu.Unlock()
}

// Refresh checks one list now and waits for the result.
func (s *Service) Refresh(ctx context.Context, id string) error {
	src := s.source(id)
	if src == nil {
		return ErrNoSuchList
	}
	if !s.claim(id) {
		return errors.New("already updating")
	}
	defer s.release(id)
	return s.refresh(ctx, src)
}

// refresh downloads what changed, tests it, and only then replaces the current copy.
func (s *Service) refresh(ctx context.Context, src *Source) error {
	now := s.now()
	finish := func(err error) error {
		s.mu.Lock()
		st := s.statusLocked(src.ID)
		st.LastCheck = &now
		st.Error = ""
		if err != nil {
			st.Error = err.Error()
		}
		s.mu.Unlock()
		s.saveStatus(ctx)
		return err
	}
	root := filepath.Join(s.dir, src.ID)
	cur, tmp := filepath.Join(root, currentDir), filepath.Join(root, newDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return finish(fmt.Errorf("cannot write to %s: %w", root, err))
	}
	_ = os.RemoveAll(tmp)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return finish(fmt.Errorf("cannot write to %s: %w", root, err))
	}
	defer os.RemoveAll(tmp)

	s.mu.Lock()
	known := map[string]fileState{}
	for k, v := range s.statusLocked(src.ID).Files {
		known[k] = v
	}
	s.mu.Unlock()

	changed := false
	nextFiles := map[string]fileState{}
	var errs []string
	wanted := map[string]bool{}
	files := src.Files(now)
	for _, f := range files {
		wanted[f.Name] = true
		got, state, err := s.fetchWithFallback(ctx, src, f, cur, tmp, known)
		if err != nil {
			if !f.Optional {
				errs = append(errs, err.Error())
				continue
			}
			// An optional file that cannot be fetched now keeps the copy already here.
			if linkOrCopy(filepath.Join(cur, f.Name), filepath.Join(tmp, f.Name)) == nil {
				nextFiles[f.Name] = known[f.Name]
			}
			continue
		}
		wanted[got] = true
		nextFiles[got] = state.fileState
		if state.changed {
			changed = true
		}
	}
	if len(errs) > 0 {
		return finish(errors.New(strings.Join(errs, " ")))
	}
	// Files no longer asked for: keep the ones the list still wants, and any change to the
	// set counts as a change.
	if ents, err := os.ReadDir(cur); err == nil {
		for _, e := range ents {
			if wanted[e.Name()] {
				continue
			}
			if src.KeepOld != nil && src.KeepOld(e.Name(), now) {
				if err := linkOrCopy(filepath.Join(cur, e.Name()), filepath.Join(tmp, e.Name())); err == nil {
					nextFiles[e.Name()] = known[e.Name()]
				}
			} else {
				changed = true
			}
		}
	}
	if !changed {
		s.mu.Lock()
		s.statusLocked(src.ID).Files = nextFiles
		s.mu.Unlock()
		return finish(nil)
	}
	apply, entries, err := src.Load(tmp)
	if err != nil {
		return finish(fmt.Errorf("the download could not be read, so the previous copy stays in use: %w", err))
	}
	if entries < src.MinEntries {
		return finish(fmt.Errorf("the download had only %d entries where at least %d were expected, so the previous copy stays in use", entries, src.MinEntries))
	}
	// Swap: current becomes last-good, the tested download becomes current. A crash between
	// the two renames leaves last-good, which loading falls back to.
	good := filepath.Join(root, lastGoodDir)
	if _, err := os.Stat(cur); err == nil {
		if err := os.RemoveAll(good); err != nil {
			return finish(fmt.Errorf("cannot replace the list: %w", err))
		}
		if err := os.Rename(cur, good); err != nil {
			return finish(fmt.Errorf("cannot replace the list: %w", err))
		}
	}
	if err := os.Rename(tmp, cur); err != nil {
		return finish(fmt.Errorf("cannot replace the list: %w", err))
	}
	if s.Enabled(src.ID) {
		apply()
	}
	s.mu.Lock()
	st := s.statusLocked(src.ID)
	st.Entries, st.LastUpdate, st.Files = entries, &now, nextFiles
	s.mu.Unlock()
	s.log.Info("lists: updated", "list", src.ID, "entries", entries)
	return finish(nil)
}

type fetchState struct {
	fileState
	changed bool
}

// fetchWithFallback gets a file, trying its fallback if that fails. It returns the name of
// the file it ended up with.
func (s *Service) fetchWithFallback(ctx context.Context, src *Source, f RemoteFile, cur, tmp string, known map[string]fileState) (string, fetchState, error) {
	state, err := s.fetchOne(ctx, src, f, cur, tmp, known)
	if err == nil {
		return f.Name, state, nil
	}
	if f.Fallback == nil {
		return "", fetchState{}, err
	}
	s.log.Info("lists: trying the fallback source", "list", src.ID, "err", err)
	state, ferr := s.fetchOne(ctx, src, *f.Fallback, cur, tmp, known)
	if ferr != nil {
		return "", fetchState{}, fmt.Errorf("%v The fallback also failed: %v", err, ferr)
	}
	return f.Fallback.Name, state, nil
}

// fetchOne downloads one file into tmp, or links the current copy there if it is unchanged.
func (s *Service) fetchOne(ctx context.Context, src *Source, f RemoteFile, cur, tmp string, known map[string]fileState) (fetchState, error) {
	host := hostOf(f.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fetchState{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	curPath := filepath.Join(cur, f.Name)
	old := known[f.Name]
	_, statErr := os.Stat(curPath)
	haveCurrent := statErr == nil
	if haveCurrent {
		if old.ETag != "" {
			req.Header.Set("If-None-Match", old.ETag)
		}
		if old.LastModified != "" {
			req.Header.Set("If-Modified-Since", old.LastModified)
		}
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fetchState{}, errors.New(describeFetchError(host, err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && haveCurrent:
		if err := linkOrCopy(curPath, filepath.Join(tmp, f.Name)); err != nil {
			return fetchState{}, err
		}
		return fetchState{fileState: old}, nil
	case resp.StatusCode != http.StatusOK:
		return fetchState{}, errors.New(describeStatus(host, resp.StatusCode))
	}
	out, err := os.Create(filepath.Join(tmp, f.Name))
	if err != nil {
		return fetchState{}, err
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, src.MaxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fetchState{}, errors.New(describeFetchError(host, err))
	}
	if n > src.MaxBytes {
		return fetchState{}, fmt.Errorf("%s sent more than the %d MB allowed for this list, so the download was stopped.", host, src.MaxBytes>>20)
	}
	return fetchState{fileState: fileState{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, changed: true}, nil
}

func linkOrCopy(from, to string) error {
	if err := os.Link(from, to); err == nil {
		return nil
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return raw
}

const blockedHint = "If your firewall or DNS blocklist blocks it, allow this host or turn this list off."

// describeFetchError turns a failed request into a sentence a homelab owner can act on. A DNS
// blocklist is the usual cause, and it shows up in a few different ways.
func describeFetchError(host string, err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Sprintf("Could not look up %s. %s", host, blockedHint)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Addr != nil {
		addr := opErr.Addr.String()
		if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "[::]") || strings.HasPrefix(addr, "[::1]") {
			return fmt.Sprintf("%s resolved to %s, which is what a DNS blocklist answers with. %s", host, addr, blockedHint)
		}
	}
	var certErr *x509.HostnameError
	var unknownErr x509.UnknownAuthorityError
	if errors.As(err, &certErr) || errors.As(err, &unknownErr) {
		return fmt.Sprintf("%s answered with a certificate that does not match, so something on the way may be answering in its place. %s", host, blockedHint)
	}
	var timeoutErr interface{ Timeout() bool }
	if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
		return fmt.Sprintf("Timed out reaching %s. %s", host, blockedHint)
	}
	return fmt.Sprintf("Could not reach %s. %s", host, blockedHint)
}

func describeStatus(host string, code int) string {
	switch code {
	case http.StatusForbidden, http.StatusTeapot, http.StatusTooManyRequests, http.StatusUnavailableForLegalReasons:
		return fmt.Sprintf("%s refused the download (HTTP %d). It may block automated downloads.", host, code)
	case http.StatusNotFound, http.StatusGone:
		return fmt.Sprintf("%s no longer has this file (HTTP %d). The list may have moved.", host, code)
	}
	return fmt.Sprintf("%s answered HTTP %d.", host, code)
}

// loadFromDisk makes the copy on disk live, falling back to the last good copy.
func (s *Service) loadFromDisk(src *Source) {
	root := filepath.Join(s.dir, src.ID)
	for _, d := range []string{currentDir, lastGoodDir} {
		dir := filepath.Join(root, d)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		apply, entries, err := src.Load(dir)
		if err != nil {
			s.log.Warn("lists: could not read a stored copy", "list", src.ID, "copy", d, "err", err)
			continue
		}
		apply()
		s.mu.Lock()
		s.statusLocked(src.ID).Entries = entries
		s.mu.Unlock()
		return
	}
}

// LoadAll loads every enabled list's copy from disk.
func (s *Service) LoadAll() {
	s.mu.Lock()
	sources := append([]*Source(nil), s.sources...)
	s.mu.Unlock()
	for _, src := range sources {
		if s.Enabled(src.ID) {
			s.loadFromDisk(src)
		}
	}
	s.mu.Lock()
	s.loaded = true
	s.mu.Unlock()
}

// due reports whether a list should be checked now.
func (s *Service) due(src *Source, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabledLocked(src) {
		return false
	}
	st := s.statusLocked(src.ID)
	if st.LastCheck == nil {
		return true
	}
	wait := src.Every
	if st.Error != "" && wait > retryFailure {
		wait = retryFailure
	}
	return now.Sub(*st.LastCheck) >= wait
}

// runDue checks every list that is due, one at a time.
func (s *Service) runDue(ctx context.Context) {
	s.mu.Lock()
	sources := append([]*Source(nil), s.sources...)
	s.mu.Unlock()
	for _, src := range sources {
		if ctx.Err() != nil || !s.due(src, s.now()) || !s.claim(src.ID) {
			continue
		}
		if err := s.refresh(ctx, src); err != nil {
			s.log.Warn("lists: update failed", "list", src.ID, "err", err)
		}
		s.release(src.ID)
	}
}

// Run loads the lists from disk, then keeps them up to date until ctx ends.
func (s *Service) Run(ctx context.Context) {
	s.LoadAll()
	wait := startDelay
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		s.runDue(ctx)
		wait = checkEvery
	}
}
