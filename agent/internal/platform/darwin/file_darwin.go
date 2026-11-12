//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/globs"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// File sensor volume controls.
const (
	fileEventsPerSec = 200             // sustained rate; bursts up to fileBurst
	fileBurst        = 1000            //
	changeDedupe     = 2 * time.Second // repeated writes to one file are reported once
)

// fileEvents are the eslogger events of the file sensor; "close" is reported only when
// the file was written.
var fileEvents = []string{"create", "rename", "unlink", "close"}

// fileExcludes are left out by default: caches and logs that change constantly.
var fileExcludes = []string{"/Users/*/Library/Caches", "/Users/*/Library/Logs", "/private/var/folders",
	// Xcode's build output and simulator devices (thousands of changes a minute while
	// building or running a simulator), and the system's own activity databases.
	"/Users/*/Library/Developer", "/Users/*/Library/Biome",
	"/Users/*/Library/Containers/*/Data/Library/Caches", "*.sqlite-wal", "*.sqlite-shm", "*.db-wal", "*.db-shm", ".DS_Store",
	// Chromium and Electron apps' caches (browsers, Slack, VS Code, Claude) under
	// Application Support.
	"/Users/**/Cache/Cache_Data", "/Users/**/Code Cache", "/Users/**/GPUCache", "/Users/**/DawnGraphiteCache",
	"/Users/**/DawnWebGPUCache", "/Users/**/Service Worker/CacheStorage", "/Users/**/Service Worker/ScriptCache"}

// fileSensor reports file creation, change, deletion and rename under the configured
// directories, with the process that made the change. eslogger reports every file
// system change on the host; lines outside the directories are dropped before they are
// decoded.
type fileSensor struct {
	sensorState
	env     platform.Env
	roots   []string
	needles [][]byte // each root, plain and with JSON-escaped slashes, for the prefilter
	exclude *globs.Set

	limiter tokenBucket
	dedupe  map[string]time.Time
	dmu     sync.Mutex
}

func newFileSensor(cfg api.FileSensorConfig, defaults []string, env platform.Env) *fileSensor {
	roots := cfg.Paths
	if len(roots) == 0 {
		roots = defaults
	}
	s := &fileSensor{sensorState: sensorState{name: "file"}, env: env,
		limiter: tokenBucket{rate: fileEventsPerSec, burst: fileBurst}, dedupe: map[string]time.Time{}}
	seen := map[string]bool{}
	add := func(r string) {
		if r == "" || !filepath.IsAbs(r) || seen[r] {
			return
		}
		seen[r] = true
		s.roots = append(s.roots, r)
		s.needles = append(s.needles, []byte(r+"/"), []byte(strings.ReplaceAll(r+"/", "/", `\/`)))
	}
	for _, r := range roots {
		r = filepath.Clean(r)
		add(r)
		// Endpoint Security reports real paths: /tmp is /private/tmp, /etc is /private/etc.
		if real, err := filepath.EvalSymlinks(r); err == nil {
			add(real)
		}
	}
	ex := globs.New(cfg.Exclude...)
	if len(cfg.Exclude) == 0 {
		for _, p := range fileExcludes {
			ex.Add(p)
		}
	}
	if env.DataDir != "" {
		ex.Add(filepath.Clean(env.DataDir))
		if real, err := filepath.EvalSymlinks(env.DataDir); err == nil {
			ex.Add(real)
		}
	}
	s.exclude = ex
	return s
}

func (s *fileSensor) wanted(p string) bool {
	if s.exclude.Match(p) {
		return false
	}
	for _, r := range s.roots {
		if globs.Under(p, r) {
			return true
		}
	}
	return false
}

// mentionsRoot is the cheap check before decoding a line.
func (s *fileSensor) mentionsRoot(line []byte) bool {
	for _, n := range s.needles {
		if bytes.Contains(line, n) {
			return true
		}
	}
	return false
}

// Run streams eslogger file events.
func (s *fileSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	if len(s.roots) == 0 {
		s.set(event.ModuleESLogger, api.SensorDegraded, "no paths configured")
		<-ctx.Done()
		return nil
	}
	s.set(event.ModuleESLogger, api.SensorRunning, "")
	self := int64(os.Getpid())
	m := newESMapper(s.env.EntityID, nil, users.name, self)
	go s.gc(ctx)
	err := runESLogger(ctx, fileEvents, func(line []byte) {
		if !s.mentionsRoot(line) {
			return
		}
		msg, name, raw, err := parseESLine(line)
		if err != nil || msg.Process.AuditToken.PID == self {
			return
		}
		c, ok := fileChange(name, raw)
		if !ok || !s.wanted(c.Path) {
			return
		}
		if c.Action == "modified" && !s.fresh(c.Path) {
			return
		}
		if !s.limiter.allow() {
			return
		}
		ev := s.changeEvent(c, msg.msgTime())
		ev.Process = m.proc(&msg.Process)
		out.Emit(ev)
	})
	if err != nil && isUnavailable(err) {
		// No fallback: FSEvents needs cgo and reports no process. FIM still covers the
		// configured integrity paths.
		s.set(event.ModuleESLogger, api.SensorFailed, err.Error())
	}
	return err
}

// fresh reports whether a modified file was not already reported within changeDedupe.
func (s *fileSensor) fresh(p string) bool {
	now := time.Now()
	s.dmu.Lock()
	defer s.dmu.Unlock()
	if last, ok := s.dedupe[p]; ok && now.Sub(last) < changeDedupe {
		return false
	}
	s.dedupe[p] = now
	return true
}

func (s *fileSensor) changeEvent(c esFileChange, ts time.Time) *event.Event {
	f := &event.File{Path: c.Path, Name: baseName(c.Path), Directory: dirName(c.Path), OldPath: c.OldPath, Type: "file"}
	if ext := filepath.Ext(c.Path); ext != "" {
		f.Extension = strings.ToLower(ext[1:])
	}
	if c.Type != event.TypeDeletion {
		if fi, err := os.Lstat(c.Path); err == nil {
			f.Type = fsutil.FileType(fi.Mode())
			f.Mode = fsutil.ModeString(fi.Mode())
			if fi.Mode().IsRegular() {
				f.Size = fi.Size()
			}
			mt := fi.ModTime().UTC()
			f.MTime = &mt
			if m := fsutil.StatMeta(fi); m.HasOwner {
				f.Owner, f.Group = users.name(m.UID), fsutil.GroupName(m.GID)
			}
		}
	}
	return &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryFile}, Type: []string{c.Type},
			Action: c.Action, Outcome: event.OutcomeSuccess, Module: event.ModuleESLogger, Dataset: "file",
		},
		Message: "file " + c.Action + ": " + c.Path,
		File:    f,
	}
}

func (s *fileSensor) gc(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.dmu.Lock()
			for p, at := range s.dedupe {
				if time.Since(at) > changeDedupe {
					delete(s.dedupe, p)
				}
			}
			s.dmu.Unlock()
			s.limiter.mu.Lock()
			if d := s.limiter.dropped; d > 0 && time.Since(s.limiter.warned) > time.Minute {
				s.env.Log.Warn("file sensor: rate limit reached, events dropped", "dropped", d)
				s.limiter.dropped, s.limiter.warned = 0, time.Now()
			}
			s.limiter.mu.Unlock()
		}
	}
}

// tokenBucket is a simple rate limiter.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
	dropped uint64
	warned  time.Time
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.last.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	b.dropped++
	return false
}
