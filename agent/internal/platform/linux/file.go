//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
	"github.com/Doodlebug12/homexdr/agent/internal/globs"
	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
	"golang.org/x/sys/unix"
)

// moduleInotify is the Impl name of the inotify fallback. shared/event has no constant
// for it yet.
const moduleInotify = "inotify"

// File sensor volume controls.
const (
	fileEventsPerSec = 200             // sustained rate; bursts up to fileBurst
	fileBurst        = 1000            //
	changeDedupe     = 2 * time.Second // repeated writes to one file are reported once
	maxInotifyWatch  = 8192
)

// fileSensor reports file creation, change, deletion and rename under the configured
// directories. With root it uses fanotify filesystem marks, which also report the PID
// that made the change; otherwise (or for file systems fanotify cannot mark, such as
// tmpfs before 6.7) recursive inotify watches without process attribution.
type fileSensor struct {
	sensorState
	env     platform.Env
	roots   []string
	exclude *globs.Set
	self    int64

	limiter tokenBucket
	dedupe  map[string]time.Time
	dmu     sync.Mutex
	procs   *lru[string, procSummary]
}

func newFileSensor(cfg api.FileSensorConfig, defaults []string, env platform.Env) *fileSensor {
	roots := cfg.Paths
	if len(roots) == 0 {
		roots = defaults
	}
	var clean []string
	for _, r := range roots {
		if r = filepath.Clean(r); r != "" && filepath.IsAbs(r) {
			clean = append(clean, r)
		}
	}
	ex := globs.New(cfg.Exclude...)
	ex.Add("/proc")
	ex.Add("/sys")
	if env.DataDir != "" {
		ex.Add(filepath.Clean(env.DataDir))
	}
	return &fileSensor{
		sensorState: sensorState{name: "file"}, env: env, roots: clean, exclude: ex,
		self: int64(os.Getpid()), limiter: tokenBucket{rate: fileEventsPerSec, burst: fileBurst},
		dedupe: map[string]time.Time{}, procs: newLRU[string, procSummary](4096),
	}
}

// Name returns "file".
func (s *fileSensor) Name() string { return "file" }

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

// Run starts fanotify for the roots it can mark and inotify for the rest.
func (s *fileSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	var existing []string
	for _, r := range s.roots {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			existing = append(existing, r)
		}
	}
	if len(existing) == 0 {
		s.set(moduleInotify, api.SensorDegraded, "none of the configured paths exist")
		<-ctx.Done()
		return nil
	}
	fa, rest, faErr := openFanotify(existing)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	switch {
	case fa != nil && len(rest) == 0:
		s.set(event.ModuleFanotify, api.SensorRunning, "")
	case fa != nil:
		s.set(event.ModuleFanotify, api.SensorRunning, "")
		s.env.Log.Info("file sensor: using inotify for paths fanotify cannot mark", "paths", rest)
	default:
		msg := "fanotify unavailable"
		if faErr != nil {
			msg += ": " + faErr.Error()
		}
		s.env.Log.Warn("file sensor: "+msg+"; using inotify (no process attribution)", "paths", rest)
		s.set(moduleInotify, api.SensorDegraded, msg)
	}
	if fa != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.runFanotify(ctx, fa, out)
		}()
	}
	if len(rest) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.runInotify(ctx, rest, out)
		}()
	}
	go s.gcDedupe(ctx)
	wg.Wait()
	close(errs)
	var all []error
	for err := range errs {
		if err != nil {
			all = append(all, err)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(all...)
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

func (s *fileSensor) gcDedupe(ctx context.Context) {
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

// fileChange is one observed change before it becomes an event.
type fileChange struct {
	Path    string
	OldPath string
	Type    string // event.TypeCreation, TypeChange, TypeDeletion
	Action  string // created, modified, deleted, renamed
	IsDir   bool
	PID     int64
	Module  string
}

func (s *fileSensor) emit(c fileChange, out platform.Emitter) {
	if (c.PID != 0 && c.PID == s.self) || !s.wanted(c.Path) {
		return
	}
	now := time.Now()
	if c.Type != event.TypeDeletion {
		s.dmu.Lock()
		last, ok := s.dedupe[c.Path]
		s.dedupe[c.Path] = now
		s.dmu.Unlock()
		if ok && c.Action == "modified" && now.Sub(last) < changeDedupe {
			return
		}
	}
	if !s.limiter.allow() {
		return
	}
	out.Emit(s.changeEvent(c, now.UTC()))
}

func (s *fileSensor) changeEvent(c fileChange, ts time.Time) *event.Event {
	f := &event.File{Path: c.Path, Name: filepath.Base(c.Path), Directory: filepath.Dir(c.Path), OldPath: c.OldPath, Type: "file"}
	if c.IsDir {
		f.Type = "dir"
	} else if ext := filepath.Ext(c.Path); ext != "" {
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
	ev := &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryFile}, Type: []string{c.Type},
			Action: c.Action, Outcome: event.OutcomeSuccess, Module: c.Module, Dataset: "file",
		},
		Message: "file " + c.Action + ": " + c.Path,
		File:    f,
	}
	if c.PID > 0 {
		ev.Process = s.process(c.PID)
	}
	return ev
}

// process describes the PID that made a change (read from /proc right away).
func (s *fileSensor) process(pid int64) *event.Process {
	p := &event.Process{PID: pid}
	st, err := readStat(pid)
	if err != nil {
		return p
	}
	p.EntityID = s.env.EntityID(pid, st.StartTick)
	p.Name = st.Comm
	if sum, ok := s.procs.get(p.EntityID); ok {
		p.Name, p.Executable, p.CommandLine = sum.Name, sum.Executable, sum.CommandLine
		return p
	}
	p.Executable = readLink(pid, "exe")
	if p.Executable != "" {
		p.Name = filepath.Base(p.Executable)
	}
	p.CommandLine = joinArgs(readCmdline(pid))
	s.procs.put(p.EntityID, procSummary{Name: p.Name, Executable: p.Executable, CommandLine: p.CommandLine})
	return p
}

// ---- fanotify ----

type fanotify struct {
	f      *os.File
	mounts map[[2]int32]int // fsid -> fd on that file system (for open_by_handle_at)
	dirs   *lru[string, dirPath]
}

type dirPath struct {
	path string
	at   time.Time
}

const dirCacheTTL = 30 * time.Second

// openFanotify marks the file systems holding roots. It returns the roots it could not
// cover (to be watched with inotify instead).
func openFanotify(roots []string) (*fanotify, []string, error) {
	if os.Geteuid() != 0 {
		return nil, roots, errors.New("requires root")
	}
	// FID mode (5.1+) with directory FID + name (5.9+) is what reports create, delete and
	// rename events; it carries no open fd, so we resolve paths from file handles.
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, roots, fmt.Errorf("fanotify_init: %w", err)
	}
	fa := &fanotify{mounts: map[[2]int32]int{}, dirs: newLRU[string, dirPath](8192)}
	base := uint64(unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_CLOSE_WRITE | unix.FAN_ONDIR)
	var rest []string
	for _, r := range roots {
		var sfs unix.Statfs_t
		if err := unix.Statfs(r, &sfs); err != nil {
			rest = append(rest, r)
			continue
		}
		fsid := [2]int32{sfs.Fsid.Val[0], sfs.Fsid.Val[1]}
		if _, ok := fa.mounts[fsid]; ok {
			continue // file system already marked
		}
		if fsid == [2]int32{} {
			rest = append(rest, r) // no fsid (e.g. tmpfs before 6.7): FID mode cannot work
			continue
		}
		// FAN_RENAME (5.17+) reports old and new name in one event; fall back to the
		// separate MOVED_FROM / MOVED_TO events on older kernels.
		err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, base|unix.FAN_RENAME, unix.AT_FDCWD, r)
		if err != nil {
			err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, base|unix.FAN_MOVED_FROM|unix.FAN_MOVED_TO, unix.AT_FDCWD, r)
		}
		if err != nil {
			rest = append(rest, r)
			continue
		}
		mfd, err := unix.Open(r, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			rest = append(rest, r)
			continue
		}
		fa.mounts[fsid] = mfd
	}
	if len(fa.mounts) == 0 {
		unix.Close(fd)
		return nil, rest, errors.New("no file system could be marked")
	}
	fa.f = os.NewFile(uintptr(fd), "fanotify")
	return fa, rest, nil
}

func (fa *fanotify) close() {
	fa.f.Close()
	for _, fd := range fa.mounts {
		unix.Close(fd)
	}
}

// fanInfo is one decoded info record.
type fanInfo struct {
	typ    uint8
	fsid   [2]int32
	htype  int32
	handle []byte
	name   string
}

// fanEvent is one decoded fanotify event.
type fanEvent struct {
	mask  uint64
	pid   int32
	infos []fanInfo
}

// parseFanotify decodes a read buffer of fanotify events in FID mode.
func parseFanotify(b []byte) []fanEvent {
	le := binary.NativeEndian
	var out []fanEvent
	for len(b) >= unix.FAN_EVENT_METADATA_LEN {
		evLen := int(le.Uint32(b[0:]))
		metaLen := int(le.Uint16(b[6:]))
		if evLen < unix.FAN_EVENT_METADATA_LEN || evLen > len(b) || metaLen > evLen {
			break
		}
		ev := fanEvent{mask: le.Uint64(b[8:]), pid: int32(le.Uint32(b[20:]))}
		info := b[metaLen:evLen]
		for len(info) >= 4 {
			typ := info[0]
			l := int(le.Uint16(info[2:]))
			if l < 4 || l > len(info) {
				break
			}
			rec := info[:l]
			switch typ {
			case unix.FAN_EVENT_INFO_TYPE_FID, unix.FAN_EVENT_INFO_TYPE_DFID, unix.FAN_EVENT_INFO_TYPE_DFID_NAME,
				unix.FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, unix.FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
				// header(4) fsid(8) file_handle{handle_bytes u32, handle_type i32, f_handle[]} [name\0]
				if len(rec) >= 20 {
					fi := fanInfo{typ: typ, fsid: [2]int32{int32(le.Uint32(rec[4:])), int32(le.Uint32(rec[8:]))}}
					hb := int(le.Uint32(rec[12:]))
					fi.htype = int32(le.Uint32(rec[16:]))
					if 20+hb <= len(rec) {
						fi.handle = append([]byte(nil), rec[20:20+hb]...)
						if typ != unix.FAN_EVENT_INFO_TYPE_FID && typ != unix.FAN_EVENT_INFO_TYPE_DFID {
							fi.name = cstr(rec[20+hb:])
						}
						ev.infos = append(ev.infos, fi)
					}
				}
			}
			info = info[l:]
		}
		out = append(out, ev)
		b = b[evLen:]
	}
	return out
}

// resolve turns a directory handle plus name into a path.
func (fa *fanotify) resolve(fi fanInfo) (string, bool) {
	key := fmt.Sprintf("%d:%d:%d:%x", fi.fsid[0], fi.fsid[1], fi.htype, fi.handle)
	dir, ok := fa.dirs.get(key)
	if !ok || time.Since(dir.at) > dirCacheTTL {
		mfd, ok := fa.mounts[fi.fsid]
		if !ok {
			return "", false
		}
		fd, err := unix.OpenByHandleAt(mfd, unix.NewFileHandle(fi.htype, fi.handle), unix.O_PATH|unix.O_CLOEXEC)
		if err != nil {
			return "", false // e.g. ESTALE: the directory is already gone
		}
		p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		unix.Close(fd)
		if err != nil {
			return "", false
		}
		dir = dirPath{path: p, at: time.Now()}
		fa.dirs.put(key, dir)
	}
	if fi.name == "" || fi.name == "." {
		return dir.path, true
	}
	return filepath.Join(dir.path, fi.name), true
}

func (s *fileSensor) runFanotify(ctx context.Context, fa *fanotify, out platform.Emitter) error {
	defer fa.close()
	go func() {
		<-ctx.Done()
		fa.f.Close()
	}()
	s.env.Log.Info("file sensor running", "impl", "fanotify", "roots", s.roots)
	buf := make([]byte, 256<<10)
	for {
		n, err := fa.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("fanotify read: %w", err)
		}
		for _, ev := range parseFanotify(buf[:n]) {
			if ev.mask&unix.FAN_Q_OVERFLOW != 0 {
				s.env.Log.Warn("file sensor: fanotify queue overflow, events lost")
				continue
			}
			if int64(ev.pid) == s.self {
				continue
			}
			s.handleFan(fa, ev, out)
		}
	}
}

func (s *fileSensor) handleFan(fa *fanotify, ev fanEvent, out platform.Emitter) {
	isDir := ev.mask&unix.FAN_ONDIR != 0
	pid := int64(ev.pid)
	if ev.mask&unix.FAN_RENAME != 0 {
		var oldP, newP string
		for _, fi := range ev.infos {
			switch fi.typ {
			case unix.FAN_EVENT_INFO_TYPE_OLD_DFID_NAME:
				oldP, _ = fa.resolve(fi)
			case unix.FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
				newP, _ = fa.resolve(fi)
			}
		}
		if isDir {
			fa.dirs = newLRU[string, dirPath](8192) // cached paths below it are stale
		}
		if newP != "" && (s.wanted(newP) || s.wanted(oldP)) {
			s.emit(fileChange{Path: newP, OldPath: oldP, Type: event.TypeChange, Action: "renamed", IsDir: isDir, PID: pid, Module: event.ModuleFanotify}, out)
		}
		return
	}
	var p string
	for _, fi := range ev.infos {
		if fi.typ == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			var ok bool
			if p, ok = fa.resolve(fi); !ok {
				return
			}
			break
		}
	}
	if p == "" {
		return
	}
	c := fileChange{Path: p, IsDir: isDir, PID: pid, Module: event.ModuleFanotify}
	switch {
	case ev.mask&unix.FAN_CREATE != 0:
		c.Type, c.Action = event.TypeCreation, "created"
	case ev.mask&unix.FAN_DELETE != 0:
		c.Type, c.Action = event.TypeDeletion, "deleted"
	case ev.mask&unix.FAN_MOVED_TO != 0:
		c.Type, c.Action = event.TypeCreation, "renamed"
	case ev.mask&unix.FAN_MOVED_FROM != 0:
		c.Type, c.Action = event.TypeDeletion, "renamed"
		if isDir {
			fa.dirs = newLRU[string, dirPath](8192)
		}
	case ev.mask&unix.FAN_CLOSE_WRITE != 0:
		if isDir {
			return
		}
		c.Type, c.Action = event.TypeChange, "modified"
	default:
		return
	}
	s.emit(c, out)
}

// ---- inotify ----

const inotifyMask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_ONLYDIR | unix.IN_DONT_FOLLOW | unix.IN_EXCL_UNLINK

type inotify struct {
	fd    int
	f     *os.File
	wds   map[int32]string
	byDir map[string]int32
	max   int
	full  bool
}

func maxWatches() int {
	if b, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n/2 < maxInotifyWatch {
			return max(n/2, 128)
		}
	}
	return maxInotifyWatch
}

func (in *inotify) addTree(root string, skip func(string) bool) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if skip(p) {
			return filepath.SkipDir
		}
		if len(in.wds) >= in.max {
			in.full = true
			return filepath.SkipAll
		}
		if _, ok := in.byDir[p]; ok {
			return nil
		}
		wd, err := unix.InotifyAddWatch(in.fd, p, inotifyMask)
		if err != nil {
			return nil
		}
		in.wds[int32(wd)] = p
		in.byDir[p] = int32(wd)
		return nil
	})
}

type inEvent struct {
	wd     int32
	mask   uint32
	cookie uint32
	name   string
}

func parseInotify(b []byte) []inEvent {
	le := binary.NativeEndian
	var out []inEvent
	for len(b) >= unix.SizeofInotifyEvent {
		n := int(le.Uint32(b[12:]))
		if unix.SizeofInotifyEvent+n > len(b) {
			break
		}
		out = append(out, inEvent{
			wd: int32(le.Uint32(b[0:])), mask: le.Uint32(b[4:]), cookie: le.Uint32(b[8:]),
			name: cstr(b[unix.SizeofInotifyEvent : unix.SizeofInotifyEvent+n]),
		})
		b = b[unix.SizeofInotifyEvent+n:]
	}
	return out
}

func (s *fileSensor) runInotify(ctx context.Context, roots []string, out platform.Emitter) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	in := &inotify{fd: fd, f: os.NewFile(uintptr(fd), "inotify"), wds: map[int32]string{}, byDir: map[string]int32{}, max: maxWatches()}
	defer in.f.Close()
	skip := func(p string) bool { return s.exclude.Match(p) }
	for _, r := range roots {
		in.addTree(r, skip)
	}
	if in.full {
		s.env.Log.Warn("file sensor: inotify watch limit reached; some directories are not watched", "watches", len(in.wds))
	}
	go func() {
		<-ctx.Done()
		in.f.Close()
	}()
	s.env.Log.Info("file sensor running", "impl", "inotify", "roots", roots, "watches", len(in.wds))
	buf := make([]byte, 128<<10)
	for {
		n, err := in.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("inotify read: %w", err)
		}
		pendingFrom := map[uint32]string{}
		for _, ev := range parseInotify(buf[:n]) {
			if ev.mask&unix.IN_Q_OVERFLOW != 0 {
				s.env.Log.Warn("file sensor: inotify queue overflow, events lost")
				continue
			}
			dir, ok := in.wds[ev.wd]
			if !ok {
				continue
			}
			if ev.mask&unix.IN_IGNORED != 0 {
				delete(in.byDir, dir)
				delete(in.wds, ev.wd)
				continue
			}
			p := filepath.Join(dir, ev.name)
			isDir := ev.mask&unix.IN_ISDIR != 0
			c := fileChange{Path: p, IsDir: isDir, Module: moduleInotify}
			switch {
			case ev.mask&unix.IN_CREATE != 0:
				c.Type, c.Action = event.TypeCreation, "created"
				if isDir {
					in.addTree(p, skip)
				}
			case ev.mask&unix.IN_DELETE != 0:
				c.Type, c.Action = event.TypeDeletion, "deleted"
			case ev.mask&unix.IN_CLOSE_WRITE != 0:
				c.Type, c.Action = event.TypeChange, "modified"
			case ev.mask&unix.IN_MOVED_FROM != 0:
				pendingFrom[ev.cookie] = p
				continue
			case ev.mask&unix.IN_MOVED_TO != 0:
				c.Type, c.Action = event.TypeChange, "renamed"
				if old, ok := pendingFrom[ev.cookie]; ok {
					c.OldPath = old
					delete(pendingFrom, ev.cookie)
				} else {
					c.Type = event.TypeCreation // moved in from an unwatched directory
				}
				if isDir {
					in.addTree(p, skip)
				}
			default:
				continue
			}
			s.emit(c, out)
		}
		// Moved out of the watched trees.
		for _, p := range pendingFrom {
			s.emit(fileChange{Path: p, Type: event.TypeDeletion, Action: "renamed", Module: moduleInotify}, out)
		}
	}
}
