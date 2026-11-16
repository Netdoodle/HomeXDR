// Package decoy places decoy (honeypot) files on the host and reports anything that
// touches them. The files look like forgotten password lists and credentials in user
// folders; nothing legitimate has a reason to open, change, rename or delete them, while
// ransomware and attackers looking for credentials go for exactly such files first.
//
// Decoys are created only where the folder exists and no file is in the way, and the
// agent never changes or removes a file it did not create (the state file in the data dir
// lists what it created, with the SHA-256 of each). Every check interval each decoy is
// stat'ed, and hashed when its size or modification time changed; on Linux inotify also
// reports opens, reads and changes as they happen. Events use event.module=decoy.
package decoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// StateFile is the decoy state inside the data dir.
const StateFile = "decoys.json"

// Dataset and event types.
const (
	Dataset    = "decoy.event"
	TypeRename = "rename"
	// rateWindow: at most one event per decoy and event type in this window.
	rateWindow = time.Minute
)

// tracked holds the paths of the decoys this agent manages, so other sensors that read
// files (FIM) skip them: on Linux reading a decoy is an alert.
var tracked sync.Map

// IsDecoy reports whether p is a decoy file this agent manages.
func IsDecoy(p string) bool {
	_, ok := tracked.Load(filepath.Clean(p))
	return ok
}

// record is one decoy the agent created.
type record struct {
	Path       string    `json:"path"`
	Base       string    `json:"base"`
	Dirs       []string  `json:"dirs,omitempty"`
	Name       string    `json:"name"`
	MakeDir    bool      `json:"make_dir,omitempty"`
	CreatedDir bool      `json:"created_dir,omitempty"` // the agent created the folder too
	Extra      bool      `json:"extra,omitempty"`       // from DecoyConfig.Extra
	User       string    `json:"user,omitempty"`
	UID        int       `json:"uid,omitempty"`
	GID        int       `json:"gid,omitempty"`
	HasOwner   bool      `json:"has_owner,omitempty"`
	Kind       string    `json:"kind"`
	Created    time.Time `json:"created"`
	// At creation.
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
	// What the last check saw at the path.
	CurType   string `json:"cur_type,omitempty"` // "" for a regular file, else symlink, dir, other
	CurSize   int64  `json:"cur_size"`
	CurMTime  int64  `json:"cur_mtime"`
	CurSHA256 string `json:"cur_sha256,omitempty"`
	Dev       uint64 `json:"dev,omitempty"`
	Inode     uint64 `json:"inode,omitempty"`
	// Missing: the deletion or rename was reported; the decoy is recreated when possible.
	Missing bool `json:"missing,omitempty"`
	// Unavailable: the decoy's folder is gone (profile removed, home not mounted), so its
	// absence is not reported.
	Unavailable bool `json:"unavailable,omitempty"`

	// pendingChange: a real-time event already reported a change the next check will see.
	pendingChange bool
}

func (r *record) target() target {
	return target{
		Base: r.Base, Dirs: r.Dirs, Name: r.Name, MakeDir: r.MakeDir, User: r.User,
		UID: r.UID, GID: r.GID, HasOwner: r.HasOwner, OwnerFromParent: r.Extra, Kind: r.Kind,
	}
}

func (r *record) present() bool { return !r.Missing && !r.Unavailable && r.CurType == "" }

type stateFile struct {
	// Canary is this host's marker, written into every decoy.
	Canary string    `json:"canary"`
	Decoys []*record `json:"decoys"`
}

// Sensor implements platform.Sensor.
type Sensor struct {
	cfg        api.DecoyConfig
	dataDir    string
	file       string
	log        *slog.Logger
	layout     layout
	interval   time.Duration
	now        func() time.Time
	newWatcher func(func(string, watchKind), *slog.Logger) (watcher, error)

	mu       sync.Mutex
	st       stateFile
	byPath   map[string]*record
	out      platform.Emitter
	w        watcher
	lastEmit map[string]time.Time
	noted    map[string]string // path -> last placement problem logged
	events   uint64
	watchErr string
	left     int // when off: decoys left in place
	dirty    bool
}

// New builds the decoy sensor for this OS. The state is kept in dataDir.
func New(cfg api.DecoyConfig, dataDir string, log *slog.Logger) *Sensor {
	return newSensor(cfg, dataDir, layout{goos: runtime.GOOS, lookupOwner: systemOwner}, log)
}

func newSensor(cfg api.DecoyConfig, dataDir string, l layout, log *slog.Logger) *Sensor {
	iv := time.Duration(cfg.CheckIntervalSec) * time.Second
	switch {
	case cfg.CheckIntervalSec <= 0:
		iv = api.DecoyDefaultIntervalSec * time.Second
	case cfg.CheckIntervalSec < api.DecoyMinIntervalSec:
		iv = api.DecoyMinIntervalSec * time.Second
	}
	return &Sensor{
		cfg: cfg, dataDir: dataDir, file: filepath.Join(dataDir, StateFile), log: log,
		layout: l, interval: iv, now: time.Now, newWatcher: newWatcher,
		byPath: map[string]*record{}, lastEmit: map[string]time.Time{}, noted: map[string]string{},
	}
}

// Name returns "decoy".
func (s *Sensor) Name() string { return "decoy" }

func plural(n int) string {
	if n == 1 {
		return "1 decoy file"
	}
	return strconv.Itoa(n) + " decoy files"
}

// Status reports health and how many decoys are in place.
func (s *Sensor) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := api.SensorStatus{Name: "decoy", Impl: event.ModuleDecoy, State: api.SensorRunning, Events: s.events}
	if !s.cfg.Enabled {
		st.State = api.SensorDisabled
		if s.left > 0 {
			st.Message = plural(s.left) + " left in place because someone changed them"
		}
		return st
	}
	n := 0
	for _, r := range s.st.Decoys {
		if r.present() {
			n++
		}
	}
	st.Message = plural(n)
	if s.watchErr != "" {
		st.State, st.Error = api.SensorDegraded, s.watchErr
	}
	return st
}

// Run creates and watches the decoys, or, when the sensor is off, removes the decoys the
// agent created that nobody changed.
func (s *Sensor) Run(ctx context.Context, out platform.Emitter) error {
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	s.out = out
	s.load()
	s.mu.Unlock()
	if !s.cfg.Enabled {
		s.cleanup()
		s.save()
		<-ctx.Done()
		return nil
	}
	if s.newWatcher != nil {
		w, err := s.newWatcher(s.onWatch, s.log)
		s.mu.Lock()
		if err != nil {
			s.watchErr = "real-time notifications unavailable, checking every " + s.interval.String() + ": " + err.Error()
		}
		s.w = w
		s.mu.Unlock()
		if w != nil {
			defer func() {
				s.mu.Lock()
				s.w = nil
				s.mu.Unlock()
				w.close()
			}()
		}
	}
	defer s.save()
	for {
		s.checkOnce()
		s.save()
		t := time.NewTimer(s.interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// load reads the state file (s.mu held). A missing file is a first start.
func (s *Sensor) load() {
	var st stateFile
	if err := fsutil.ReadJSON(s.file, &st); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The decoys listed there are no longer known and stay where they are.
		s.log.Warn("decoy: state file unreadable, starting over", "err", err)
		st = stateFile{}
	}
	s.st = stateFile{Canary: st.Canary}
	s.byPath = map[string]*record{}
	for _, r := range st.Decoys {
		if r == nil || r.Path == "" || r.Base == "" || r.Name == "" || r.target().path() != r.Path || s.byPath[r.Path] != nil {
			continue
		}
		s.st.Decoys = append(s.st.Decoys, r)
		s.byPath[r.Path] = r
		tracked.Store(r.Path, true)
	}
	if s.st.Canary == "" {
		s.st.Canary = newCanary()
		s.dirty = true
	}
}

func (s *Sensor) save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return
	}
	slices.SortFunc(s.st.Decoys, func(a, b *record) int { return strings.Compare(a.Path, b.Path) })
	if err := fsutil.WriteJSONAtomic(s.file, s.st, 0o600); err != nil {
		s.log.Warn("decoy: save state", "err", err)
		return
	}
	s.dirty = false
}

// checkOnce checks every known decoy, then places decoys where they are missing.
func (s *Sensor) checkOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, t := range s.lastEmit {
		if now.Sub(t) >= rateWindow {
			delete(s.lastEmit, k)
		}
	}
	extras := map[string]target{}
	for _, x := range s.cfg.Extra {
		if t, ok := extraTarget(x, s.dataDir); ok {
			extras[t.path()] = t
		} else {
			s.note(x, "not an absolute file path outside the agent's data folder")
		}
	}
	keep := s.st.Decoys[:0]
	for _, r := range s.st.Decoys {
		if _, ok := extras[r.Path]; r.Extra && !ok {
			s.retire(r) // no longer configured
			continue
		}
		s.checkRecord(r)
		keep = append(keep, r)
	}
	s.st.Decoys = keep
	targets := s.layout.targets()
	for _, t := range extras {
		targets = append(targets, t)
	}
	s.place(targets)
}

// retire stops tracking a decoy, removing it when nobody changed it (s.mu held).
func (s *Sensor) retire(r *record) {
	s.unwatch(r)
	delete(s.byPath, r.Path)
	tracked.Delete(r.Path)
	s.dirty = true
	if removed, _ := removeFile(r.target(), r.SHA256, r.CreatedDir); removed {
		s.log.Info("decoy removed", "path", r.Path)
	} else if _, err := statPath(r.Path); err == nil {
		s.log.Info("decoy no longer configured; left in place because it was changed", "path", r.Path)
	}
}

func (s *Sensor) note(path, msg string) {
	if s.noted[path] == msg {
		return
	}
	s.noted[path] = msg
	s.log.Warn("decoy: cannot place decoy file", "path", path, "reason", msg)
}

// place creates the decoys of targets that are not tracked yet (s.mu held).
func (s *Sensor) place(targets []target) {
	for _, t := range targets {
		p := t.path()
		if _, ok := s.byPath[p]; ok {
			continue
		}
		if len(s.st.Decoys) >= maxDecoys {
			s.note("*", fmt.Sprintf("limit of %d decoys reached", maxDecoys))
			return
		}
		if _, err := statPath(p); err == nil {
			continue // something is already there: leave it alone
		}
		data := content(t.Kind, t.User, s.st.Canary)
		c, err := createFile(t, data, s.backdate())
		switch {
		case err == nil:
		case errors.Is(err, errExists), errors.Is(err, errNoFolder):
			continue
		default:
			s.note(p, err.Error())
			continue
		}
		r := &record{Path: p, Base: t.Base, Dirs: slices.Clone(t.Dirs), Name: t.Name, MakeDir: t.MakeDir,
			Extra: t.OwnerFromParent, User: t.User, UID: t.UID, GID: t.GID, HasOwner: t.HasOwner, Kind: t.Kind}
		s.adopt(r, c, data)
		s.st.Decoys = append(s.st.Decoys, r)
		s.byPath[p] = r
		tracked.Store(p, true)
		delete(s.noted, p)
		s.log.Info("decoy file created", "path", p)
		s.watch(r)
	}
}

// adopt records a decoy just written.
func (s *Sensor) adopt(r *record, c created, data []byte) {
	sum := sha256Hex(data)
	r.Created = s.now().UTC()
	r.Size, r.MTime, r.SHA256 = int64(len(data)), c.st.MTime, sum
	r.CurType, r.CurSize, r.CurMTime, r.CurSHA256 = "", int64(len(data)), c.st.MTime, sum
	r.Dev, r.Inode = c.st.Dev, c.st.Inode
	r.CreatedDir = r.CreatedDir || c.createdDir
	if c.hasOwner {
		r.UID, r.GID, r.HasOwner = c.uid, c.gid, true
		if r.User == "" {
			r.User = userName(c.uid)
		}
	}
	r.Missing, r.Unavailable, r.pendingChange = false, false, false
	s.dirty = true
}

// backdate is the modification time given to a new decoy: one to twelve months ago, so
// it does not stand out as the newest file in the folder.
func (s *Sensor) backdate() time.Time {
	days := 30 + randInt(335)
	return s.now().Add(-time.Duration(days)*24*time.Hour - time.Duration(randInt(86400))*time.Second)
}

func (s *Sensor) watch(r *record) {
	if s.w == nil || !r.present() {
		return
	}
	if err := s.w.add(r.Path); err != nil {
		s.watchErr = "real-time notifications unavailable for some decoys: " + err.Error()
	}
}

func (s *Sensor) unwatch(r *record) {
	if s.w != nil {
		s.w.remove(r.Path)
	}
}

// checkRecord compares one decoy with what the last check saw (s.mu held).
func (s *Sensor) checkRecord(r *record) {
	t := r.target()
	fs, err := statPath(r.Path)
	if errors.Is(err, os.ErrNotExist) {
		if folderOK(t, t.need()) != nil {
			if !r.Unavailable {
				r.Unavailable = true
				s.dirty = true
				s.unwatch(r)
				s.log.Info("decoy folder is gone; the decoy is not checked until it is back", "path", r.Path)
			}
			return
		}
		if r.Unavailable {
			r.Unavailable = false
			s.dirty = true
		}
		if !r.Missing {
			s.unwatch(r)
			s.reportGone(r)
		}
		s.recreate(r)
		return
	}
	if err != nil {
		s.log.Debug("decoy: stat", "path", r.Path, "err", err)
		return
	}
	if r.Unavailable {
		r.Unavailable = false
		s.dirty = true
	}
	if fs.Type != "file" {
		if r.CurType != fs.Type {
			s.unwatch(r)
			s.emit(r, event.TypeChange, "replaced", "Decoy file was replaced by a "+fs.Type+": "+r.Path, &fs, "", nil)
			r.CurType, r.CurSHA256, r.Missing, r.pendingChange = fs.Type, "", false, false
			s.dirty = true
		}
		return
	}
	if r.CurType == "" && !r.Missing && fs.Size == r.CurSize && fs.MTime == r.CurMTime {
		if fs.Inode != r.Inode || fs.Dev != r.Dev {
			// Same size and time but another file (or a remount): follow it.
			r.Dev, r.Inode = fs.Dev, fs.Inode
			s.dirty = true
			s.unwatch(r)
		}
		r.pendingChange = false
		s.watch(r)
		return
	}
	// Size or time changed: hash it. The watch is removed first so the agent's own read
	// is not reported as an access.
	s.unwatch(r)
	sum, _, herr := hashPath(r.Path)
	if herr != nil {
		sum = ""
	}
	if sum == "" || sum != r.CurSHA256 || r.Missing || r.CurType != "" {
		if !r.pendingChange {
			action, msg := "modified", "Decoy file was modified: "+r.Path
			if r.Missing || r.CurType != "" {
				action, msg = "replaced", "Decoy file was replaced: "+r.Path
			}
			s.emit(r, event.TypeChange, action, msg, &fs, sum, map[string]any{"decoy.previous_sha256": r.CurSHA256})
		}
	}
	r.CurType, r.CurSize, r.CurMTime, r.CurSHA256 = "", fs.Size, fs.MTime, sum
	r.Dev, r.Inode = fs.Dev, fs.Inode
	r.Missing, r.pendingChange = false, false
	s.dirty = true
	s.watch(r)
}

// reportGone reports a decoy that is no longer at its path, as renamed when a file in the
// same folder is the same file or carries its name with an added extension.
func (s *Sensor) reportGone(r *record) {
	if to := s.findRenamed(r); to != "" {
		s.emit(r, TypeRename, "renamed", "Decoy file was renamed: "+r.Path+" -> "+to, nil, "", map[string]any{"decoy.renamed_to": to})
	} else {
		s.emit(r, event.TypeDeletion, "deleted", "Decoy file was deleted: "+r.Path, nil, "", nil)
	}
	r.Missing = true
	s.dirty = true
}

func (s *Sensor) findRenamed(r *record) string {
	dir := filepath.Dir(r.Path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	prefix, byName := "", strings.ToLower(r.Name)+"."
	for i, e := range ents {
		if i >= maxDirScan {
			break
		}
		name := e.Name()
		if name == r.Name || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, name)
		if r.Inode != 0 {
			if fs, err := statPath(p); err == nil && fs.Inode == r.Inode && fs.Dev == r.Dev {
				return p
			}
		}
		if prefix == "" && strings.HasPrefix(strings.ToLower(name), byName) {
			prefix = p
		}
	}
	return prefix
}

// recreate puts a missing decoy back, after its absence was reported (s.mu held).
func (s *Sensor) recreate(r *record) {
	data := content(r.Kind, r.User, s.st.Canary)
	c, err := createFile(r.target(), data, s.backdate())
	if err != nil {
		if !errors.Is(err, errExists) {
			s.note(r.Path, "recreate: "+err.Error())
		}
		return
	}
	delete(s.noted, r.Path)
	s.adopt(r, c, data)
	s.log.Info("decoy file recreated", "path", r.Path)
	s.watch(r)
}

// onWatch handles a real-time notification (Linux).
func (s *Sensor) onWatch(path string, k watchKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.byPath[path]
	if r == nil || !r.present() {
		return
	}
	switch k {
	case watchAccess:
		s.emit(r, event.TypeAccess, "opened", "Decoy file was opened: "+path, nil, "", nil)
	case watchModify:
		s.emit(r, event.TypeChange, "modified", "Decoy file was modified: "+path, nil, "", nil)
		r.pendingChange = true
	case watchAttrib:
		fs, err := statPath(path)
		if err != nil || fs.Inode != r.Inode {
			return // being deleted or replaced: those events follow
		}
		s.emit(r, event.TypeChange, "attributes_modified", "Decoy file permissions, owner or times were changed: "+path, &fs, "", nil)
		r.pendingChange = true
	case watchMove:
		s.unwatch(r) // the watch follows the file to its new name
		s.reportGone(r)
	case watchDelete:
		s.unwatch(r)
		if fs, err := statPath(path); err == nil {
			// Another file took its place (an editor saving through a temporary file).
			s.emit(r, event.TypeChange, "replaced", "Decoy file was replaced: "+path, &fs, "", nil)
			r.pendingChange = true
			return
		}
		s.reportGone(r)
	}
}

// emit sends one event unless the same decoy reported the same type within rateWindow.
func (s *Sensor) emit(r *record, typ, action, msg string, fs *fileState, sum string, data map[string]any) bool {
	now := s.now()
	key := r.Path + "\x00" + typ
	if last, ok := s.lastEmit[key]; ok && now.Sub(last) < rateWindow {
		return false
	}
	s.lastEmit[key] = now
	f := &event.File{Path: r.Path, Name: filepath.Base(r.Path), Directory: filepath.Dir(r.Path), Type: "file"}
	if ext := filepath.Ext(r.Path); ext != "" {
		f.Extension = strings.ToLower(ext[1:])
	}
	if fs != nil {
		f.Type, f.Size = fs.Type, fs.Size
		mt := time.Unix(0, fs.MTime).UTC()
		f.MTime = &mt
	}
	if sum != "" {
		f.Hash = &event.Hash{SHA256: sum}
	}
	if data == nil {
		data = map[string]any{}
	}
	data["decoy.created"] = r.Created.Format(time.RFC3339)
	data["decoy.sha256"] = r.SHA256
	ev := &event.Event{
		Timestamp: now.UTC(),
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryFile}, Type: []string{typ},
			Action: action, Module: event.ModuleDecoy, Dataset: Dataset, Outcome: event.OutcomeSuccess,
		},
		Message: msg,
		Labels:  map[string]string{"decoy": "true"},
		File:    f,
		Data:    data,
	}
	if r.User != "" {
		ev.User = &event.User{Name: r.User}
		if r.HasOwner {
			ev.User.ID = strconv.Itoa(r.UID)
		}
	}
	s.events++
	if s.out != nil {
		s.out.Emit(ev)
	}
	return true
}

// cleanup runs when decoys are off: it removes every decoy the agent created whose
// content is unchanged, and keeps tracking the rest, which stay where they are.
func (s *Sensor) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keep []*record
	for _, r := range s.st.Decoys {
		t := r.target()
		fs, err := statPath(r.Path)
		if errors.Is(err, os.ErrNotExist) {
			if folderOK(t, t.need()) != nil {
				keep = append(keep, r) // cannot tell while its folder is missing
			} else {
				tracked.Delete(r.Path)
			}
			continue
		}
		if err == nil && fs.Type == "file" {
			removed, rerr := removeFile(t, r.SHA256, r.CreatedDir)
			if removed {
				tracked.Delete(r.Path)
				s.log.Info("decoys off: decoy removed", "path", r.Path)
				continue
			}
			if rerr != nil {
				s.log.Warn("decoys off: cannot remove decoy; left in place", "path", r.Path, "err", rerr)
				keep = append(keep, r)
				continue
			}
			// Changed by someone else: note what it is now, so turning decoys back on
			// does not report the same change again.
			if sum, _, herr := hashPath(r.Path); herr == nil {
				r.CurType, r.CurSize, r.CurMTime, r.CurSHA256 = "", fs.Size, fs.MTime, sum
			}
		}
		s.log.Info("decoys off: decoy left in place because it was changed", "path", r.Path)
		keep = append(keep, r)
	}
	s.st.Decoys = keep
	s.byPath = map[string]*record{}
	for _, r := range keep {
		s.byPath[r.Path] = r
	}
	s.left = len(keep)
	s.dirty = true
}
