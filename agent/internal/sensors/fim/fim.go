// Package fim is the cross-platform file integrity monitoring sensor. It periodically
// walks the configured paths, hashes regular files (up to max_file_size), compares the
// result with the baseline stored in the data dir and emits creation, change and deletion
// events (event.module=fim). The first scan of a path only records the baseline.
package fim

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/globs"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Limits that keep a misconfigured FIM path (say "/") from exhausting memory.
const (
	MaxEntries       = 200000
	MaxEventsPerScan = 20000
)

// Entry is the recorded state of one path.
type Entry struct {
	Type   string `json:"t"` // file, dir, symlink
	Size   int64  `json:"s,omitempty"`
	Mode   string `json:"m"`
	UID    uint32 `json:"u,omitempty"`
	GID    uint32 `json:"g,omitempty"`
	Owner  bool   `json:"o,omitempty"` // UID/GID valid
	MTime  int64  `json:"mt"`
	CTime  int64  `json:"ct,omitempty"`
	Inode  uint64 `json:"i,omitempty"`
	SHA256 string `json:"h,omitempty"`
	Target string `json:"l,omitempty"` // symlink target
}

// Baseline is the persisted scan result.
type Baseline struct {
	Roots   []string         `json:"roots"`
	Entries map[string]Entry `json:"entries"`
}

// Sensor implements platform.Sensor.
type Sensor struct {
	cfg      api.FIMConfig
	roots    []string
	exclude  *globs.Set
	file     string
	log      *slog.Logger
	interval time.Duration

	mu      sync.Mutex
	lastErr string
	events  uint64
}

// New builds the FIM sensor. defaults are used when cfg.Paths is empty; dataDir is
// always excluded and holds the baseline.
func New(cfg api.FIMConfig, defaults []string, dataDir string, log *slog.Logger) *Sensor {
	roots := cfg.Paths
	if len(roots) == 0 {
		roots = defaults
	}
	var clean []string
	for _, r := range roots {
		if r != "" {
			clean = append(clean, filepath.Clean(r))
		}
	}
	ex := globs.New(cfg.Exclude...)
	if dataDir != "" {
		ex.Add(filepath.Clean(dataDir))
	}
	iv := time.Duration(cfg.IntervalSec) * time.Second
	if iv < time.Minute {
		iv = time.Hour
	}
	return &Sensor{
		cfg: cfg, roots: clean, exclude: ex, log: log, interval: iv,
		file: filepath.Join(dataDir, "fim", "baseline.json"),
	}
}

// SetInterval overrides the scan interval (tests).
func (s *Sensor) SetInterval(d time.Duration) { s.interval = d }

// Name returns "fim".
func (s *Sensor) Name() string { return "fim" }

// Status reports health.
func (s *Sensor) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := api.SensorStatus{Name: "fim", Impl: event.ModuleFIM, State: api.SensorRunning, Error: s.lastErr, Events: s.events}
	if s.lastErr != "" {
		st.State = api.SensorDegraded
	}
	return st
}

// Run scans immediately (comparing against a baseline left by a previous run, so changes
// made while the agent was stopped are reported), then every interval.
func (s *Sensor) Run(ctx context.Context, out platform.Emitter) error {
	if len(s.roots) == 0 {
		<-ctx.Done()
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.file), 0o700); err != nil {
		return err
	}
	var base Baseline
	if err := fsutil.ReadJSON(s.file, &base); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("fim: baseline unreadable, starting over", "err", err)
		base = Baseline{}
	}
	for {
		next, err := s.ScanOnce(ctx, &base, out)
		if ctx.Err() != nil {
			return nil
		}
		s.mu.Lock()
		if err != nil {
			s.lastErr = err.Error()
		} else {
			s.lastErr = ""
		}
		s.mu.Unlock()
		base = next
		if err := fsutil.WriteJSONAtomic(s.file, base, 0o600); err != nil {
			s.log.Warn("fim: save baseline", "err", err)
		}
		t := time.NewTimer(s.interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// ScanOnce walks the roots, emits differences against old and returns the new baseline.
// Roots that were not in the old baseline are recorded without events.
func (s *Sensor) ScanOnce(ctx context.Context, old *Baseline, out platform.Emitter) (Baseline, error) {
	start := time.Now()
	cur := Baseline{Roots: slices.Clone(s.roots), Entries: map[string]Entry{}}
	var scanErr error
	for _, root := range s.roots {
		if err := s.walk(ctx, root, old, cur.Entries); err != nil {
			scanErr = err
		}
		if ctx.Err() != nil {
			return *old, ctx.Err()
		}
	}
	known := func(p string) bool {
		for _, r := range old.Roots {
			if globs.Under(p, r) {
				return true
			}
		}
		return false
	}
	var emitted int
	emit := func(e *event.Event) {
		if emitted < MaxEventsPerScan {
			out.Emit(e)
			s.mu.Lock()
			s.events++
			s.mu.Unlock()
		}
		emitted++
	}
	paths := make([]string, 0, len(cur.Entries))
	for p := range cur.Entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		ne := cur.Entries[p]
		oe, had := old.Entries[p]
		switch {
		case !had && known(p):
			emit(s.makeEvent(p, ne, nil, nil, event.TypeCreation, "created"))
		case had:
			if changed := diff(oe, ne); len(changed) > 0 {
				action := "updated"
				if !slices.Contains(changed, "sha256") && !slices.Contains(changed, "size") && !slices.Contains(changed, "type") && !slices.Contains(changed, "target") {
					action = "attributes_modified"
				}
				prev := oe
				emit(s.makeEvent(p, ne, &prev, changed, event.TypeChange, action))
			}
		}
	}
	var gone []string
	truncated := errors.Is(scanErr, errTooMany)
	for p, oe := range old.Entries {
		if _, ok := cur.Entries[p]; ok || !s.inRoots(p) || s.exclude.Match(p) {
			continue
		}
		if truncated {
			// The walk stopped early, so absence proves nothing: keep the old entry.
			cur.Entries[p] = oe
			continue
		}
		gone = append(gone, p)
	}
	sort.Strings(gone)
	for _, p := range gone {
		oe := old.Entries[p]
		emit(s.makeEvent(p, oe, nil, nil, event.TypeDeletion, "deleted"))
	}
	if emitted > MaxEventsPerScan {
		s.log.Warn("fim: too many changes in one scan, some were not reported", "changes", emitted, "reported", MaxEventsPerScan)
	}
	s.log.Debug("fim scan done", "entries", len(cur.Entries), "changes", emitted, "took", time.Since(start).Round(time.Millisecond))
	return cur, scanErr
}

func (s *Sensor) inRoots(p string) bool {
	for _, r := range s.roots {
		if globs.Under(p, r) {
			return true
		}
	}
	return false
}

var errTooMany = errors.New("fim: too many files under the configured paths; scan truncated")

func (s *Sensor) walk(ctx context.Context, root string, old *Baseline, into map[string]Entry) error {
	maxSize := s.cfg.MaxFileSize
	if maxSize <= 0 {
		maxSize = 64 << 20
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// Unreadable directory or vanished file: skip it, keep scanning.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if s.exclude.Match(p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if len(into) >= MaxEntries {
			return errTooMany
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		e, ok := entryFor(p, fi)
		if !ok {
			return nil
		}
		if e.Type == "file" && e.Size <= maxSize {
			// Reuse the old hash only if size, mtime, ctime and inode are all unchanged.
			// (A same-size rewrite within one kernel timestamp tick, a few ms, would go
			// unnoticed until the next change; every FIM tool that avoids rehashing
			// everything shares this limit.)
			if oe, had := old.Entries[p]; had && oe.SHA256 != "" && oe.Size == e.Size && oe.MTime == e.MTime &&
				oe.CTime == e.CTime && oe.Inode == e.Inode {
				e.SHA256 = oe.SHA256
			} else if h, err := fsutil.SHA256File(p, maxSize); err == nil {
				e.SHA256 = h
			}
		}
		into[p] = e
		return nil
	})
}

func entryFor(p string, fi os.FileInfo) (Entry, bool) {
	t := fsutil.FileType(fi.Mode())
	if t == "other" {
		return Entry{}, false
	}
	m := fsutil.StatMeta(fi)
	e := Entry{
		Type: t, Mode: fsutil.ModeString(fi.Mode()), MTime: fi.ModTime().UnixNano(),
		UID: m.UID, GID: m.GID, Owner: m.HasOwner, Inode: m.Inode,
	}
	if !m.CTime.IsZero() {
		e.CTime = m.CTime.UnixNano()
	}
	switch t {
	case "file":
		e.Size = fi.Size()
	case "symlink":
		e.Target, _ = os.Readlink(p)
	case "dir":
		// Directory mtimes change whenever an entry is added or removed; those changes are
		// already reported per file, so only permissions and ownership are compared.
		e.MTime, e.CTime = 0, 0
	}
	return e, true
}

// diff lists the attributes that changed. Inode and ctime changes alone are not
// reported (they also change on harmless metadata updates).
func diff(a, b Entry) []string {
	var out []string
	if a.Type != b.Type {
		out = append(out, "type")
	}
	if a.SHA256 != b.SHA256 && a.SHA256 != "" && b.SHA256 != "" {
		out = append(out, "sha256")
	}
	if a.Size != b.Size {
		out = append(out, "size")
	}
	if a.Mode != b.Mode {
		out = append(out, "mode")
	}
	if a.Owner && b.Owner && (a.UID != b.UID || a.GID != b.GID) {
		out = append(out, "owner")
	}
	if a.Target != b.Target {
		out = append(out, "target")
	}
	if len(out) == 0 && a.Type == "file" && a.SHA256 == "" && b.SHA256 == "" && a.MTime != b.MTime {
		// Too large to hash: fall back to the modification time.
		out = append(out, "mtime")
	}
	return out
}

func (s *Sensor) makeEvent(p string, e Entry, prev *Entry, changed []string, typ, action string) *event.Event {
	f := fileFields(p, e)
	ev := &event.Event{
		Timestamp: time.Now().UTC(),
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryFile}, Type: []string{typ},
			Action: action, Module: event.ModuleFIM, Dataset: "fim.event", Outcome: event.OutcomeSuccess,
		},
		Message: "fim: " + p + " " + action,
		File:    f,
	}
	if prev != nil {
		ev.Data = map[string]any{
			"fim.changed": changed,
			"fim.previous": map[string]any{
				"sha256": prev.SHA256, "size": prev.Size, "mode": prev.Mode,
				"uid": prev.UID, "gid": prev.GID, "target": prev.Target,
			},
		}
	}
	return ev
}

func fileFields(p string, e Entry) *event.File {
	f := &event.File{
		Path: p, Name: filepath.Base(p), Directory: filepath.Dir(p), Type: e.Type, Size: e.Size,
		Mode: e.Mode, TargetPath: e.Target,
	}
	if ext := filepath.Ext(p); ext != "" && e.Type == "file" {
		f.Extension = lower(ext[1:])
	}
	if e.Owner {
		f.Owner = fsutil.UserName(e.UID)
		f.Group = fsutil.GroupName(e.GID)
	}
	if e.MTime != 0 {
		t := time.Unix(0, e.MTime).UTC()
		f.MTime = &t
	}
	if e.CTime != 0 {
		t := time.Unix(0, e.CTime).UTC()
		f.CTime = &t
	}
	if e.SHA256 != "" {
		f.Hash = &event.Hash{SHA256: e.SHA256}
	}
	return f
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
