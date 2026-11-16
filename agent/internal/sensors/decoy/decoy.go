// Package decoy places decoy (honeypot) files on the host and reports anything that
// touches them. The files look like forgotten password lists and credentials in user
// folders; nothing legitimate has a reason to open, change, rename or delete them, while
// ransomware and attackers looking for credentials go for exactly such files first.
//
// Where decoys go is configured per OS (api.DecoyConfig.Files): absolute paths, and paths
// starting with {home} that are expanded to every real user's home folder. Decoys are
// created only where the folder exists (or its parent does: then just the last folder is
// created) and no file is in the way, and the agent never changes or removes a file it
// did not create (the state file in the data dir lists what it created, with the SHA-256
// of each). Every check interval each decoy is
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
	Path       string   `json:"path"`
	Base       string   `json:"base"`
	Dirs       []string `json:"dirs,omitempty"`
	Name       string   `json:"name"`
	MakeDir    bool     `json:"make_dir,omitempty"`
	CreatedDir bool     `json:"created_dir,omitempty"` // the agent created the folder too
	// Extra: the file takes its folder's owner. Set for absolute paths from the config
	// (the name dates from when those were "extra decoy paths").
	Extra bool `json:"extra,omitempty"`
	// Entry is the configured path the decoy comes from ({home}\Documents\Passwords.xlsx),
	// and Home whether it was expanded from {home}. Both are empty for decoys created
	// before decoy paths were configurable (see entryKey).
	Entry string `json:"entry,omitempty"`
	Home  bool   `json:"home,omitempty"`
	// Hidden: the agent set the hidden attribute (Windows) or flag (macOS).
	Hidden bool `json:"hidden,omitempty"`
	// Retired: no longer configured, and left in place because someone changed it (or its
	// folder is unavailable, see Unavailable). It is not checked; it is removed if it
	// turns out unchanged, forgotten once it is gone, and checked again if its entry is
	// configured again. Kept: when it was left, the file looked like CurSize and CurMTime
	// and its content was not what the agent wrote.
	Retired  bool      `json:"retired,omitempty"`
	Kept     bool      `json:"kept,omitempty"`
	User     string    `json:"user,omitempty"`
	UID      int       `json:"uid,omitempty"`
	GID      int       `json:"gid,omitempty"`
	HasOwner bool      `json:"has_owner,omitempty"`
	Kind     string    `json:"kind"`
	Created  time.Time `json:"created"`
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
	// wantHidden is the entry's Hidden option, set every check.
	wantHidden bool
}

func (r *record) target() target {
	return target{
		Base: r.Base, Dirs: r.Dirs, Name: r.Name, MakeDir: r.MakeDir, User: r.User,
		UID: r.UID, GID: r.GID, HasOwner: r.HasOwner, OwnerFromParent: r.Extra, Kind: r.Kind,
		Entry: r.Entry, Home: r.Home, Hidden: r.wantHidden,
	}
}

func (r *record) present() bool {
	return !r.Retired && !r.Missing && !r.Unavailable && r.CurType == ""
}

// legacyHome reports whether a decoy created before decoy paths were configurable was in
// a user's folder: those had a user folder and at least one folder below it, while the
// shared ones (ProgramData\Backup, /var/backups) and extra paths had one folder.
func (r *record) legacyHome() bool { return r.Entry == "" && !r.Extra && len(r.Dirs) >= 2 }

func (r *record) isHome() bool { return r.Home || r.legacyHome() }

// entryKey is the configured {home} path a home decoy comes from.
func (r *record) entryKey(goos string) string {
	if r.Entry != "" || !r.legacyHome() {
		return r.Entry
	}
	sep := api.DecoySeparator(goos)
	return api.DecoyHome + sep + strings.Join(append(slices.Clone(r.Dirs[1:]), r.Name), sep)
}

// unchanged reports whether the decoy is as the agent wrote it, by the last check.
func (r *record) unchanged() bool {
	return r.present() && r.CurSHA256 == r.SHA256 && r.CurSize == r.Size && r.CurMTime == r.MTime
}

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
	n, kept := 0, 0
	for _, r := range s.st.Decoys {
		switch {
		case r.present():
			n++
		case r.Retired && !r.Unavailable:
			kept++
		}
	}
	st.Message = plural(n)
	switch {
	case kept == 1:
		st.Message += "; 1 decoy file no longer in the list was left in place because someone changed it"
	case kept > 1:
		st.Message += fmt.Sprintf("; %d decoy files no longer in the list were left in place because someone changed them", kept)
	}
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

// checkOnce checks every known decoy, retires the ones no longer configured, then places
// decoys where they are missing.
func (s *Sensor) checkOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, t := range s.lastEmit {
		if now.Sub(t) >= rateWindow {
			delete(s.lastEmit, k)
		}
	}
	goos := s.layout.goos
	targets := s.layout.targets(s.cfg.Files, s.dataDir, s.note)
	byPath := make(map[string]target, len(targets))
	for _, t := range targets {
		if _, dup := byPath[t.path()]; !dup {
			byPath[t.path()] = t
		}
	}
	// The {home} entries for this OS, with their Hidden option: a home decoy stays wanted
	// while its entry is configured, even when its user is not listed right now (profile
	// removed, home folder not mounted).
	homeEntries := map[string]bool{}
	for _, f := range s.cfg.Files {
		if p := strings.TrimSpace(f.Path); f.OS == goos && strings.HasPrefix(p, api.DecoyHome) {
			homeEntries[p] = f.Hidden && goos != api.DecoyOSLinux
		}
	}
	keep := s.st.Decoys[:0]
	for _, r := range s.st.Decoys {
		t, ok := byPath[r.Path]
		if !ok && r.isHome() {
			if hidden, configured := homeEntries[r.entryKey(goos)]; configured {
				t, ok = target{Entry: r.entryKey(goos), Home: true, Hidden: hidden}, true
			}
		}
		if !ok {
			if !s.retire(r) {
				keep = append(keep, r)
			}
			continue
		}
		if r.Retired {
			r.Retired, r.Kept, r.Unavailable = false, false, false
			tracked.Store(r.Path, true)
			s.log.Info("decoy is configured again", "path", r.Path)
		}
		if r.Entry != t.Entry || r.Home != t.Home {
			r.Entry, r.Home = t.Entry, t.Home
			s.dirty = true
		}
		r.wantHidden = t.Hidden
		s.checkRecord(r)
		s.syncHidden(r)
		keep = append(keep, r)
	}
	s.st.Decoys = keep
	s.place(targets)
}

// retire handles a decoy that is no longer configured (s.mu held): it removes the file
// when nobody changed it; otherwise the file stays where it is and the record is kept,
// marked Retired, so the status can say so. It reports whether the record can go.
func (s *Sensor) retire(r *record) bool {
	if !r.Retired {
		s.unwatch(r)
		tracked.Delete(r.Path)
		r.Retired, r.Kept, r.pendingChange = true, false, false
		s.dirty = true
	}
	t := r.target()
	fs, err := statPath(r.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if folderOK(t, t.need()) != nil {
			if !r.Unavailable {
				r.Unavailable = true // decided once the folder is back
				s.dirty = true
			}
			return false
		}
		s.forget(r)
		return true
	case err != nil:
		return false
	case fs.Type != "file":
		s.forget(r) // something else is there now: not the agent's file
		return true
	}
	if r.Unavailable {
		r.Unavailable = false
		s.dirty = true
	}
	if r.Kept && fs.Size == r.CurSize && fs.MTime == r.CurMTime {
		return false // changed, and not touched since it was left
	}
	if fs.Size == r.Size {
		removed, sum, rerr := removeFile(t, r.SHA256, r.CreatedDir)
		switch {
		case removed:
			s.log.Info("decoy no longer configured: removed", "path", r.Path)
			s.forget(r)
			return true
		case rerr != nil || sum == "":
			if rerr != nil {
				s.note(r.Path, "remove: "+rerr.Error())
			}
			return false // try again at the next check
		}
	}
	r.CurType, r.CurSize, r.CurMTime, r.Kept = "", fs.Size, fs.MTime, true
	s.dirty = true
	s.log.Info("decoy no longer configured: left in place because it was changed", "path", r.Path)
	return false
}

// forget drops a decoy from the state (s.mu held); the caller removes it from the list.
func (s *Sensor) forget(r *record) {
	s.unwatch(r)
	delete(s.byPath, r.Path)
	delete(s.noted, r.Path)
	tracked.Delete(r.Path)
	s.dirty = true
}

// syncHidden applies the entry's Hidden option to a decoy nobody changed (s.mu held); a
// decoy someone changed is left exactly as it is. The attribute is not part of what the
// checks compare (size, modification time, content), so setting it raises no event.
func (s *Sensor) syncHidden(r *record) {
	if !hiddenSupported || r.Hidden == r.wantHidden || !r.unchanged() {
		return
	}
	s.unwatch(r)
	err := setHidden(r.target(), r.Dev, r.Inode, r.wantHidden)
	s.watch(r)
	if err != nil {
		s.note(r.Path, "set the hidden attribute: "+err.Error())
		return
	}
	r.Hidden = r.wantHidden
	s.dirty = true
	s.log.Info("decoy hidden attribute changed", "path", r.Path, "hidden", r.Hidden)
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
			Extra: t.OwnerFromParent, Entry: t.Entry, Home: t.Home, User: t.User, UID: t.UID, GID: t.GID,
			HasOwner: t.HasOwner, Kind: t.Kind, wantHidden: t.Hidden}
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
	r.Hidden, r.Kept = c.hidden, false
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
			removed, sum, rerr := removeFile(t, r.SHA256, r.CreatedDir)
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
			r.CurType, r.CurSize, r.CurMTime, r.CurSHA256 = "", fs.Size, fs.MTime, sum
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
