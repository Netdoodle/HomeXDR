// Package av is HomeXDR's antivirus: it judges the programs that run on enrolled hosts
// and, when one is malware, has the agent stop it and quarantine the file.
//
// It works from the agents' process events, which carry the executable's SHA-256:
//
//  1. Hashes on the user's blocklist are malware; hashes on the allowlist are skipped.
//  2. A stored verdict is reused, so each file is judged once for the whole fleet.
//  3. Files outside the operating system's own folders are looked up with the threat
//     intel sources (MalwareBazaar, VirusTotal, ... and CIRCL's list of known files).
//  4. Files nobody vouches for are fetched from the host (file.get) and scanned with
//     ClamAV and YARA on the server. The upload is deleted after the scan.
//
// There is no kernel driver, so this happens after a program starts, within seconds,
// rather than before; Windows Defender (or another real-time scanner) stays in place.
package av

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

const (
	settingsKey = "av_settings"

	ActionAlert      = "alert"      // raise an alert only
	ActionQuarantine = "quarantine" // stop the process (and its children) and quarantine the file

	// rescanAfter: a file that was clean is scanned again when seen after this long, so
	// newer signatures get a chance.
	rescanAfter = 7 * 24 * time.Hour
	// respondEvery limits repeated responses to the same process.
	respondEvery = 10 * time.Minute
	queueSize    = 2048
	workers      = 2
	maxHashes    = 20000
)

// Settings are stored in the kv table.
type Settings struct {
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"`
	// ScanUnknown fetches programs no reputation source vouches for and scans them with
	// ClamAV and YARA (needs HOMEXDR_CLAMD_ADDR or HOMEXDR_YARA_ADDR).
	ScanUnknown bool `json:"scan_unknown"`
	// UseIntel looks hashes up with the threat intel sources configured under Settings →
	// Threat intel (only hashes are sent, never files).
	UseIntel      bool     `json:"use_intel"`
	MaxFileMB     int      `json:"max_file_mb"`
	BlockedHashes []string `json:"blocked_hashes"`
	AllowedHashes []string `json:"allowed_hashes"`
}

// DefaultSettings: on, stopping and quarantining what it finds.
func DefaultSettings() Settings {
	return Settings{Enabled: true, Action: ActionQuarantine, ScanUnknown: true, UseIntel: true, MaxFileMB: 64}
}

// InputError is a bad setting.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func normalizeHashes(in []string, what string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		if !hexRe.MatchString(h) {
			return nil, &InputError{fmt.Sprintf("%s: %q is not a SHA-256 hash (64 hex characters)", what, h)}
		}
		seen[h] = true
		out = append(out, h)
	}
	if len(out) > maxHashes {
		return nil, &InputError{fmt.Sprintf("%s: at most %d hashes", what, maxHashes)}
	}
	return out, nil
}

func (s Settings) validate() (Settings, error) {
	switch s.Action {
	case ActionAlert, ActionQuarantine:
	case "":
		s.Action = ActionQuarantine
	default:
		return s, &InputError{"action must be alert or quarantine"}
	}
	if s.MaxFileMB <= 0 {
		s.MaxFileMB = 64
	}
	if s.MaxFileMB > 100 {
		return s, &InputError{"max file size is 100 MB"}
	}
	var err error
	if s.BlockedHashes, err = normalizeHashes(s.BlockedHashes, "blocked hashes"); err != nil {
		return s, err
	}
	if s.AllowedHashes, err = normalizeHashes(s.AllowedHashes, "allowed hashes"); err != nil {
		return s, err
	}
	return s, nil
}

// Candidate is a program (or file) seen on a host.
type Candidate struct {
	HostID, Hostname, Platform string
	Path                       string
	SHA256                     string
	PID                        int64
	EntityID                   string
}

// Reputation is what the threat intel sources say about a hash.
type Reputation struct {
	Malicious bool
	Known     bool   // a source vouches for it (a known software file)
	Name      string // threat name or headline
	Source    string // which source decided
}

// Detection is a candidate found to be malware.
type Detection struct {
	Candidate
	Source    string // blocklist, intel:<source>, clamav, yara, yara:tool, yara:suspicious
	Signature string
}

// AlertOnly: the detection raises an alert but is not stopped automatically.
func (d Detection) AlertOnly() bool { return AlertOnly(d.Source) }

// ErrSkip means a file cannot be fetched for a lasting reason (too large, gone, not
// allowed); the verdict "skipped" is stored so it is not fetched again and again.
var ErrSkip = errors.New("file cannot be scanned")

// Deps connects the service to the rest of the server.
type Deps struct {
	State *store.Store
	Log   *slog.Logger
	Clamd *Clamd // nil: no ClamAV scanning
	Yara  *Yara  // nil: no YARA scanning
	// Lookup asks the threat intel sources about a hash; nil: none.
	Lookup func(ctx context.Context, sha256 string) (Reputation, error)
	// Fetch uploads the file from its host and returns the local path; the service
	// removes it. Lasting failures wrap ErrSkip.
	Fetch func(ctx context.Context, c Candidate, maxBytes int64) (string, error)
	// Detected raises the alert and, with ActionQuarantine, the response.
	Detected func(ctx context.Context, d Detection, s Settings)
}

// Service is the antivirus.
type Service struct {
	d Deps

	mu        sync.Mutex
	set       Settings
	blocked   map[string]bool
	allowed   map[string]bool
	waiting   map[string][]Candidate // hash → candidates waiting for its verdict
	responded map[string]time.Time
	lastErr   string

	queue             chan string
	scanned, detected atomic.Uint64
	now               func() time.Time
}

// New returns the service with default settings; call Load.
func New(d Deps) *Service {
	s := &Service{d: d, waiting: map[string][]Candidate{}, responded: map[string]time.Time{},
		queue: make(chan string, queueSize), now: time.Now}
	s.apply(DefaultSettings())
	return s
}

func (s *Service) apply(set Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set = set
	s.blocked = toSet(set.BlockedHashes)
	s.allowed = toSet(set.AllowedHashes)
}

func toSet(hs []string) map[string]bool {
	m := make(map[string]bool, len(hs))
	for _, h := range hs {
		m[h] = true
	}
	return m
}

// Load reads the stored settings.
func (s *Service) Load(ctx context.Context) error {
	set := DefaultSettings()
	err := s.d.State.GetKV(ctx, settingsKey, &set)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if set, err = set.validate(); err != nil {
		return err
	}
	s.apply(set)
	return nil
}

// Settings returns the current settings.
func (s *Service) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set
}

// Save validates and stores new settings.
func (s *Service) Save(ctx context.Context, set Settings) (Settings, error) {
	set, err := set.validate()
	if err != nil {
		return set, err
	}
	if err := s.d.State.SetKV(ctx, settingsKey, set); err != nil {
		return set, err
	}
	s.apply(set)
	return set, nil
}

// Observe queues a candidate. It never blocks the ingest path: when the queue is full
// the candidate is dropped (it is seen again the next time the program runs).
func (s *Service) Observe(c Candidate) {
	c.SHA256 = strings.ToLower(strings.TrimSpace(c.SHA256))
	if !hexRe.MatchString(c.SHA256) {
		return
	}
	s.mu.Lock()
	if !s.set.Enabled || s.allowed[c.SHA256] {
		s.mu.Unlock()
		return
	}
	if w, busy := s.waiting[c.SHA256]; busy {
		if len(w) < 64 {
			s.waiting[c.SHA256] = append(w, c)
		}
		s.mu.Unlock()
		return
	}
	s.waiting[c.SHA256] = []Candidate{c}
	s.mu.Unlock()
	select {
	case s.queue <- c.SHA256:
	default:
		s.mu.Lock()
		delete(s.waiting, c.SHA256)
		s.mu.Unlock()
		s.d.Log.Warn("antivirus: queue full, dropping a candidate", "sha256", c.SHA256, "path", c.Path)
	}
}

// Run processes the queue until ctx ends.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case h := <-s.queue:
					s.process(ctx, h)
				}
			}
		}()
	}
	wg.Wait()
}

// process decides one hash and then handles every candidate that waited for it.
func (s *Service) process(ctx context.Context, hash string) {
	s.mu.Lock()
	first := s.waiting[hash][0]
	s.mu.Unlock()
	det, err := s.judge(ctx, first)
	if err != nil && ctx.Err() == nil {
		s.mu.Lock()
		s.lastErr = fmt.Sprintf("%s: %v", s.now().UTC().Format(time.RFC3339), err)
		s.mu.Unlock()
		s.d.Log.Warn("antivirus: could not judge a file", "sha256", hash, "path", first.Path, "err", err)
	}
	s.mu.Lock()
	cands := s.waiting[hash]
	delete(s.waiting, hash)
	set := s.set
	s.mu.Unlock()
	if det == nil {
		return
	}
	for _, c := range cands {
		d := *det
		d.Candidate = c
		s.respond(ctx, d, set)
	}
}

// judge returns a detection when the file is malware, nil otherwise.
func (s *Service) judge(ctx context.Context, c Candidate) (*Detection, error) {
	set := s.Settings()
	if !set.Enabled {
		return nil, nil
	}
	s.mu.Lock()
	blocked := s.blocked[c.SHA256]
	s.mu.Unlock()
	if blocked {
		return &Detection{Source: "blocklist", Signature: "Blocked hash"}, nil
	}
	v, err := s.d.State.GetAVVerdict(ctx, c.SHA256)
	switch {
	case err == nil && v.Verdict == store.AVMalicious:
		return &Detection{Source: v.Source, Signature: v.Signature}, nil
	case err == nil && (v.Verdict != store.AVClean || s.now().Sub(v.CheckedAt) < rescanAfter):
		return nil, nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	if !Eligible(c.Platform, c.Path) {
		return nil, nil
	}
	if set.UseIntel && s.d.Lookup != nil {
		lctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		rep, err := s.d.Lookup(lctx, c.SHA256)
		cancel()
		switch {
		case err != nil:
			s.d.Log.Debug("antivirus: intel lookup failed", "sha256", c.SHA256, "err", err)
		case rep.Malicious:
			return s.verdict(ctx, c, store.AVMalicious, "intel:"+rep.Source, rep.Name)
		case rep.Known:
			_, err := s.verdict(ctx, c, store.AVKnown, "intel:"+rep.Source, "")
			return nil, err
		}
	}
	if !set.ScanUnknown || (s.d.Clamd == nil && s.d.Yara == nil) || s.d.Fetch == nil {
		return nil, nil
	}
	fctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	path, err := s.d.Fetch(fctx, c, int64(set.MaxFileMB)<<20)
	if err != nil {
		if errors.Is(err, ErrSkip) {
			_, verr := s.verdict(ctx, c, store.AVSkipped, "fetch", "")
			return nil, errors.Join(err, verr)
		}
		return nil, fmt.Errorf("fetch %s from %s: %w", c.Path, c.Hostname, err)
	}
	defer os.Remove(path)
	source, sig, err := s.scanFile(fctx, path)
	if err != nil {
		return nil, fmt.Errorf("scan of %s: %w", c.Path, err)
	}
	s.scanned.Add(1)
	if sig != "" {
		return s.verdict(ctx, c, store.AVMalicious, source, sig)
	}
	_, err = s.verdict(ctx, c, store.AVClean, source, "")
	return nil, err
}

// scanFile runs a fetched file through ClamAV and YARA. On a match it returns the
// verdict source and signature; when every scanner finds it clean, the scanners that
// ran ("clamav+yara") and no signature. A scanner that fails means no verdict, so the
// file is tried again the next time it runs.
func (s *Service) scanFile(ctx context.Context, path string) (source, sig string, err error) {
	var errs []error
	var ran []string
	scan := func(name string, fn func(f *os.File) (string, string, error)) (string, string, bool) {
		f, err := os.Open(path)
		if err != nil {
			errs = append(errs, err)
			return "", "", false
		}
		defer f.Close()
		src, sig, err := fn(f)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		case sig != "":
			return src, sig, true
		default:
			ran = append(ran, name)
		}
		return "", "", false
	}
	if s.d.Clamd != nil {
		if src, sig, hit := scan("clamav", func(f *os.File) (string, string, error) {
			sig, err := s.d.Clamd.Scan(ctx, f)
			return "clamav", sig, err
		}); hit {
			return src, sig, nil
		}
	}
	if s.d.Yara != nil {
		if src, sig, hit := scan("yara", func(f *os.File) (string, string, error) {
			ms, err := s.d.Yara.Scan(ctx, f)
			if err != nil || len(ms) == 0 {
				return "", "", err
			}
			src, sig := yaraVerdict(ms)
			return src, sig, nil
		}); hit {
			return src, sig, nil
		}
	}
	if len(errs) > 0 {
		return "", "", errors.Join(errs...)
	}
	return strings.Join(ran, "+"), "", nil
}

func (s *Service) verdict(ctx context.Context, c Candidate, verdict, source, sig string) (*Detection, error) {
	err := s.d.State.PutAVVerdict(ctx, &store.AVVerdict{SHA256: c.SHA256, Verdict: verdict, Source: source,
		Signature: sig, Path: c.Path, HostID: c.HostID})
	if verdict != store.AVMalicious {
		return nil, err
	}
	return &Detection{Source: source, Signature: sig}, err
}

// respond reports a detection once per process (and once per path for files without
// one) every respondEvery.
func (s *Service) respond(ctx context.Context, d Detection, set Settings) {
	key := d.HostID + "|" + d.EntityID
	if d.EntityID == "" {
		key = d.HostID + "|" + strings.ToLower(d.Path)
	}
	now := s.now()
	s.mu.Lock()
	if t, ok := s.responded[key]; ok && now.Sub(t) < respondEvery {
		s.mu.Unlock()
		return
	}
	s.responded[key] = now
	for k, t := range s.responded {
		if now.Sub(t) > respondEvery {
			delete(s.responded, k)
		}
	}
	s.mu.Unlock()
	s.detected.Add(1)
	if s.d.Detected != nil {
		s.d.Detected(ctx, d, set)
	}
}

// windowsSystemDirs hold Windows' own signed files; they are not fetched or looked up
// (the blocklist and stored verdicts still apply to them).
var windowsSystemDirs = []string{
	`\windows\system32\`, `\windows\syswow64\`, `\windows\winsxs\`, `\windows\servicing\`,
	`\windows\systemapps\`, `\windows\immersivecontrolpanel\`, `\windows\microsoft.net\`,
	`\windows\explorer.exe`, `\program files\windowsapps\`, `\programdata\microsoft\windows defender\`,
}

var unixSystemDirs = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/snap/", "/nix/store/"}

// Eligible reports whether a program is looked up and scanned: everything except the
// operating system's own folders.
func Eligible(platform, path string) bool {
	if path == "" {
		return false
	}
	if platform == "windows" || strings.Contains(path, `\`) {
		p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
		if len(p) >= 2 && p[1] == ':' {
			p = p[2:]
		}
		for _, d := range windowsSystemDirs {
			if strings.HasPrefix(p, d) {
				return false
			}
		}
		return true
	}
	for _, d := range unixSystemDirs {
		if strings.HasPrefix(path, d) {
			return false
		}
	}
	return true
}

// ClamdStatus describes the ClamAV daemon.
type ClamdStatus struct {
	Configured bool   `json:"configured"`
	OK         bool   `json:"ok"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// View is the settings page's data.
type View struct {
	Settings   Settings           `json:"settings"`
	Clamd      ClamdStatus        `json:"clamd"`
	Yara       YaraStatus         `json:"yara"`
	Verdicts   map[string]int     `json:"verdicts"`
	Scanned    uint64             `json:"scanned"`  // files scanned since the server started
	Detected   uint64             `json:"detected"` // detections since the server started
	Queue      int                `json:"queue"`
	LastError  string             `json:"last_error,omitempty"`
	Detections []*store.AVVerdict `json:"detections"`
}

// Status returns the current state.
func (s *Service) Status(ctx context.Context) View {
	v := View{Settings: s.Settings(), Scanned: s.scanned.Load(), Detected: s.detected.Load(), Queue: len(s.queue)}
	s.mu.Lock()
	v.LastError = s.lastErr
	s.mu.Unlock()
	if s.d.Clamd != nil {
		v.Clamd.Configured = true
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ver, err := s.d.Clamd.Version(cctx)
		cancel()
		if err != nil {
			v.Clamd.Error = err.Error()
		} else {
			v.Clamd.OK, v.Clamd.Version = true, ver
		}
	}
	if s.d.Yara != nil {
		v.Yara.Configured = true
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := s.d.Yara.Status(cctx)
		cancel()
		if err != nil {
			v.Yara.Error = err.Error()
		} else {
			v.Yara = st
		}
	}
	v.Verdicts, _ = s.d.State.AVVerdictCounts(ctx)
	v.Detections, _ = s.d.State.AVDetections(ctx, 20)
	if v.Detections == nil {
		v.Detections = []*store.AVVerdict{}
	}
	return v
}
