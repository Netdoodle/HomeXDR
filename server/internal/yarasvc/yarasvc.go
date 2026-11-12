// Package yarasvc is HomeXDR's YARA scanner: a small HTTP service that runs next to the
// server (like ClamAV) and scans the files the antivirus uploads from hosts with YARA
// rules. It keeps the YARA Forge community rule package current and adds the user's own
// rules from a folder.
//
// It drives the yara and yarac command-line tools, so the server and this service stay
// pure Go; the container image provides the tools (deploy/yara/Dockerfile).
//
//	POST /scan     the file as the request body → {"matches":[{"namespace","rule"}]}
//	GET  /status   rule package, rule count, last update, errors
//	GET  /healthz  200 when rules are loaded
package yarasvc

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is read from the environment by cmd/homexdr-yara.
type Config struct {
	Addr      string // listen address, default :3320
	DataDir   string // downloaded and compiled rules
	CustomDir string // the user's own *.yar / *.yara files; "" for none
	// ForgeURL is the YARA Forge package to download; "" means no download (custom
	// rules only).
	ForgeURL    string
	UpdateEvery time.Duration // how often to check for a new package, default 24h
	MaxBytes    int64         // largest file accepted, default 100 MB
	ScanTimeout time.Duration // per file, default 60s
	Parallel    int           // concurrent scans, default 2
	Yara, Yarac string        // tool paths, default from PATH
}

// DefaultForgeURL is YARA Forge's "core" package: rules that passed its quality, score
// and age checks, meant for scanning with few false positives.
const DefaultForgeURL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

func (c *Config) defaults() {
	if c.Addr == "" {
		c.Addr = ":3320"
	}
	if c.UpdateEvery <= 0 {
		c.UpdateEvery = 24 * time.Hour
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = 100 << 20
	}
	if c.ScanTimeout <= 0 {
		c.ScanTimeout = 60 * time.Second
	}
	if c.Parallel <= 0 {
		c.Parallel = 2
	}
	if c.Yara == "" {
		c.Yara = "yara"
	}
	if c.Yarac == "" {
		c.Yarac = "yarac"
	}
}

// Status is what GET /status returns.
type Status struct {
	OK          bool       `json:"ok"`
	YaraVersion string     `json:"yara_version,omitempty"`
	Rules       int        `json:"rules"`
	Package     string     `json:"package,omitempty"`      // e.g. "YARA Forge core 2026-11-08"
	CustomFiles int        `json:"custom_files"`           // the user's rule files loaded
	Compiled    *time.Time `json:"compiled,omitempty"`     // when the loaded rules were compiled
	Checked     *time.Time `json:"checked,omitempty"`      // last check for a new package
	Error       string     `json:"error,omitempty"`        // last download or compile problem
	CustomError string     `json:"custom_error,omitempty"` // the user's rules that did not compile
}

// Match is one rule that matched.
type Match struct {
	Namespace string `json:"namespace"`
	Rule      string `json:"rule"`
}

// ScanResult is what POST /scan returns.
type ScanResult struct {
	Matches []Match `json:"matches"`
}

// Service holds the compiled rules.
type Service struct {
	cfg Config
	log *slog.Logger
	sem chan struct{}

	mu       sync.RWMutex // held for reading while yara runs on the compiled file
	compiled string       // path of the compiled rules in use; "" before the first compile
	status   Status
	srcSig   string    // signature of the sources behind compiled
	next     time.Time // next check for a new package
	client   *http.Client
}

// New prepares the service; call Start.
func New(cfg Config, log *slog.Logger) *Service {
	cfg.defaults()
	return &Service{cfg: cfg, log: log, sem: make(chan struct{}, cfg.Parallel),
		client: &http.Client{Timeout: 5 * time.Minute}}
}

func (s *Service) forgePath() string { return filepath.Join(s.cfg.DataDir, "forge.yar") }
func (s *Service) tmpDir() string    { return filepath.Join(s.cfg.DataDir, "tmp") }

// Start compiles what is on disk, then keeps the package and the user's rules current
// until ctx ends.
func (s *Service) Start(ctx context.Context) error {
	if err := os.MkdirAll(s.tmpDir(), 0o700); err != nil {
		return err
	}
	// Leftovers from a previous run.
	if old, _ := filepath.Glob(filepath.Join(s.tmpDir(), "*")); len(old) > 0 {
		for _, f := range old {
			os.Remove(f)
		}
	}
	if old, _ := filepath.Glob(filepath.Join(s.cfg.DataDir, "rules-*.yarc")); len(old) > 0 {
		for _, f := range old {
			os.Remove(f)
		}
	}
	if out, err := exec.CommandContext(ctx, s.cfg.Yara, "-v").Output(); err == nil {
		s.status.YaraVersion = strings.TrimSpace(string(out))
	} else {
		return fmt.Errorf("yara not found: %w", err)
	}
	s.refresh(ctx, false)
	go s.loop(ctx)
	return nil
}

func (s *Service) loop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.refresh(ctx, false)
	}
}

// refresh downloads the package when it is due, then recompiles when the sources
// changed.
func (s *Service) refresh(ctx context.Context, force bool) {
	if s.cfg.ForgeURL != "" && (force || s.downloadDue()) {
		err := s.download(ctx)
		now := time.Now().UTC()
		s.mu.Lock()
		s.status.Checked = &now
		if err != nil {
			// Try again within the hour rather than waiting a whole update interval.
			s.next = now.Add(min(time.Hour, s.cfg.UpdateEvery))
			s.status.Error = "rule package download: " + err.Error()
		} else {
			s.next = now.Add(s.cfg.UpdateEvery)
			if strings.HasPrefix(s.status.Error, "rule package") {
				s.status.Error = ""
			}
		}
		s.mu.Unlock()
		if err != nil {
			s.log.Warn("yara: rule package download failed", "err", err)
		}
	}
	srcs, sig := s.sources()
	s.mu.Lock()
	if len(srcs) == 0 {
		if s.compiled == "" && s.status.Error == "" {
			s.status.Error = "no rules: the rule package has not been downloaded and there are no custom rules"
		}
		s.mu.Unlock()
		return
	}
	same := sig == s.srcSig
	s.mu.Unlock()
	if same {
		return
	}
	if err := s.compile(ctx, srcs, sig); err != nil {
		s.log.Error("yara: compile failed", "err", err)
	}
}

// downloadDue: no package yet, or the next check time has passed (on start, the
// package file's age decides).
func (s *Service) downloadDue() bool {
	s.mu.RLock()
	next := s.next
	s.mu.RUnlock()
	if !next.IsZero() {
		return time.Now().After(next)
	}
	fi, err := os.Stat(s.forgePath())
	return err != nil || time.Since(fi.ModTime()) > s.cfg.UpdateEvery
}

// source is one rule file and its namespace.
type source struct {
	ns, path string
	custom   bool
}

// sources lists the package and the user's rule files, with a signature of their
// names, sizes and modification times.
func (s *Service) sources() ([]source, string) {
	var out []source
	h := sha256.New()
	add := func(src source) {
		fi, err := os.Stat(src.path)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		fmt.Fprintf(h, "%s|%d|%d\n", src.path, fi.Size(), fi.ModTime().UnixNano())
		out = append(out, src)
	}
	add(source{ns: "forge", path: s.forgePath()})
	if s.cfg.CustomDir != "" {
		var files []string
		for _, pat := range []string{"*.yar", "*.yara"} {
			m, _ := filepath.Glob(filepath.Join(s.cfg.CustomDir, pat))
			files = append(files, m...)
		}
		sort.Strings(files)
		for _, f := range files {
			add(source{ns: "custom", path: f, custom: true})
		}
	}
	return out, hex.EncodeToString(h.Sum(nil))
}

// compile builds the rules with yarac. When the user's rules break the build, the
// package is compiled alone and their error is reported.
func (s *Service) compile(ctx context.Context, srcs []source, sig string) error {
	var forge, custom []source
	for _, src := range srcs {
		if src.custom {
			custom = append(custom, src)
		} else {
			forge = append(forge, src)
		}
	}
	out, err := s.yarac(ctx, srcs)
	customErr := ""
	loaded := len(custom)
	if err != nil && len(custom) > 0 {
		customErr = err.Error()
		loaded = 0
		if len(forge) > 0 {
			out, err = s.yarac(ctx, forge)
		}
	}
	if err != nil {
		s.mu.Lock()
		s.srcSig = sig // do not retry the same broken sources every minute
		s.status.Error = "compile: " + err.Error()
		s.status.CustomError = customErr
		s.mu.Unlock()
		return err
	}
	var used []source
	if loaded > 0 {
		used = srcs
	} else {
		used = forge
	}
	n, pkg := 0, ""
	for _, src := range used {
		b, err := os.ReadFile(src.path)
		if err != nil {
			continue
		}
		n += CountRules(b)
		if !src.custom {
			pkg = PackageName(b)
		}
	}
	now := time.Now().UTC()
	s.mu.Lock()
	old := s.compiled
	s.compiled, s.srcSig = out, sig
	s.status.OK, s.status.Rules, s.status.Package, s.status.CustomFiles = true, n, pkg, loaded
	s.status.Compiled = &now
	s.status.CustomError = customErr
	if strings.HasPrefix(s.status.Error, "compile") || strings.HasPrefix(s.status.Error, "no rules") {
		s.status.Error = ""
	}
	s.mu.Unlock() // no scan is using old once the write lock was taken
	if old != "" {
		os.Remove(old)
	}
	s.log.Info("yara: rules loaded", "rules", n, "package", pkg, "custom_files", loaded)
	if customErr != "" {
		s.log.Warn("yara: custom rules not loaded", "err", customErr)
	}
	return nil
}

func (s *Service) yarac(ctx context.Context, srcs []source) (string, error) {
	out := filepath.Join(s.cfg.DataDir, fmt.Sprintf("rules-%d.yarc", time.Now().UnixNano()))
	args := []string{"-w"}
	for _, src := range srcs {
		args = append(args, src.ns+":"+src.path)
	}
	args = append(args, out)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, s.cfg.Yarac, args...)
	var stderr bytes.Buffer
	cmd.Stderr, cmd.Stdout = &stderr, &stderr
	if err := cmd.Run(); err != nil {
		os.Remove(out)
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "…"
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return out, nil
}

// download fetches the package zip and stores its rule file, if it changed.
func (s *Service) download(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.ForgeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "homexdr-yara")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", s.cfg.ForgeURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 64<<20 {
		return errors.New("rule package larger than 64 MB")
	}
	rules, err := RulesFromZip(body)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(s.forgePath()); err == nil && bytes.Equal(cur, rules) {
		now := time.Now()
		os.Chtimes(s.forgePath(), now, now)
		return nil
	}
	tmp := s.forgePath() + ".tmp"
	if err := os.WriteFile(tmp, rules, 0o600); err != nil {
		return err
	}
	// Check it compiles before it replaces the working package.
	if out, err := s.yarac(ctx, []source{{ns: "forge", path: tmp}}); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("new package does not compile: %w", err)
	} else {
		os.Remove(out)
	}
	s.log.Info("yara: new rule package", "package", PackageName(rules), "rules", CountRules(rules))
	return os.Rename(tmp, s.forgePath())
}

// RulesFromZip returns the .yar file inside a YARA Forge package (the largest, should
// there be several).
func RulesFromZip(b []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	var best *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".yar") && (best == nil || f.UncompressedSize64 > best.UncompressedSize64) {
			best = f
		}
	}
	if best == nil {
		return nil, errors.New("no .yar file in the package")
	}
	if best.UncompressedSize64 > 256<<20 {
		return nil, errors.New("rule file larger than 256 MB")
	}
	r, err := best.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 256<<20))
}

var (
	ruleRe     = regexp.MustCompile(`(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+[A-Za-z_][A-Za-z0-9_]*`)
	privateRe  = regexp.MustCompile(`(?m)^[ \t]*(?:global[ \t]+)?private[ \t]+(?:global[ \t]+)?rule[ \t]`)
	pkgNameRe  = regexp.MustCompile(`(?m)^\s*\*\s*Name:\s*(\S+)`)
	pkgDateRe  = regexp.MustCompile(`(?m)^\s*\*\s*Creation Date:\s*(\S+)`)
	forgeTagRe = regexp.MustCompile(`YARA-Forge`)
)

// CountRules counts the rules that can match (private rules only serve others).
func CountRules(src []byte) int {
	return len(ruleRe.FindAll(src, -1)) - len(privateRe.FindAll(src, -1))
}

// PackageName reads a YARA Forge package header: "YARA Forge core 2026-11-08".
func PackageName(src []byte) string {
	head := src[:min(len(src), 4096)]
	if !forgeTagRe.Match(head) {
		return ""
	}
	name := "YARA Forge"
	if m := pkgNameRe.FindSubmatch(head); m != nil {
		name += " " + string(m[1])
	}
	if m := pkgDateRe.FindSubmatch(head); m != nil {
		name += " " + string(m[1])
	}
	return name
}

// ParseOutput reads yara's output with -e: one "namespace:rule path" line per match.
func ParseOutput(out []byte, path string) []Match {
	ms := []Match{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSuffix(strings.TrimSpace(sc.Text()), " "+path)
		if line == "" || strings.ContainsAny(line, " \t") {
			continue
		}
		ns, rule, ok := strings.Cut(line, ":")
		if !ok {
			ns, rule = "", line
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		ms = append(ms, Match{Namespace: ns, Rule: rule})
	}
	return ms
}

// Scan runs the rules over a file on disk.
func (s *Service) Scan(ctx context.Context, path string) ([]Match, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.sem }()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.compiled == "" {
		return nil, errors.New("no rules loaded")
	}
	secs := int(s.cfg.ScanTimeout / time.Second)
	cctx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout+10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, s.cfg.Yara, "-C", "-e", "-w", "-f", "-a", strconv.Itoa(max(secs, 1)), s.compiled, path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return ParseOutput(stdout.Bytes(), path), nil
}

// Status returns the current state.
func (s *Service) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Handler serves the HTTP API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !s.Status().OK {
			http.Error(w, "no rules loaded", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /scan", s.handleScan)
	return mux
}

func (s *Service) handleScan(w http.ResponseWriter, r *http.Request) {
	f, err := os.CreateTemp(s.tmpDir(), "scan-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	n, err := io.Copy(f, io.LimitReader(r.Body, s.cfg.MaxBytes+1))
	if err == nil {
		err = f.Close()
	}
	switch {
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read upload: " + err.Error()})
		return
	case n > s.cfg.MaxBytes:
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("file larger than %d bytes", s.cfg.MaxBytes)})
		return
	}
	ms, err := s.Scan(r.Context(), f.Name())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ScanResult{Matches: ms})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
