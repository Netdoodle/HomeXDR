//go:build linux

package linux

import (
	"container/list"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// maxHashBytes caps executable hashing.
const maxHashBytes = 128 << 20

// lru is a small fixed-size LRU map.
type lru[K comparable, V any] struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	k K
	v V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, ll: list.New(), m: map[K]*list.Element{}}
}

func (c *lru[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).v, true
	}
	var zero V
	return zero, false
}

func (c *lru[K, V]) put(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		el.Value.(*lruEntry[K, V]).v = v
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&lruEntry[K, V]{k, v})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*lruEntry[K, V]).k)
	}
}

// fileKey identifies file content cheaply: if none of these changed, the hash did not.
type fileKey struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

func keyOf(fi os.FileInfo) (fileKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}, true
}

// procSummary is what we remember about recently seen processes, to describe parents.
type procSummary struct {
	Name, Executable, CommandLine string
}

// procInfo is a process as seen at exec time.
type procInfo struct {
	PID, PPID       int64
	StartKey        uint64
	ParentStartKey  uint64
	HasParentKey    bool
	UID, GID, EUID  uint32
	HasCreds        bool
	Comm            string
	Exe, Filename   string
	Args            []string
	ArgsTruncated   bool
	Cwd             string
	ProcessAccessed bool // /proc/<pid> could be read at event time
}

// enricher turns raw process data into events, with hash and parent caches.
type enricher struct {
	env    platform.Env
	module string
	hashes *lru[fileKey, string]
	procs  *lru[string, procSummary]
	hashQ  chan hashJob
	self   int64
}

type hashJob struct {
	f   *os.File
	key fileKey
	ev  *event.Event
	out platform.Emitter
}

func newEnricher(env platform.Env, module string) *enricher {
	return &enricher{
		env: env, module: module,
		hashes: newLRU[fileKey, string](4096),
		procs:  newLRU[string, procSummary](16384),
		self:   int64(os.Getpid()),
	}
}

// startHashers runs workers that hash executables off the event-reading path.
func (en *enricher) startHashers(n int, done <-chan struct{}) {
	en.hashQ = make(chan hashJob, 512)
	for range n {
		go func() {
			for {
				select {
				case <-done:
					return
				case j := <-en.hashQ:
					if h, err := fsutil.SHA256Open(j.f, maxHashBytes); err == nil {
						en.hashes.put(j.key, h)
						j.ev.Process.Hash = &event.Hash{SHA256: h}
					}
					j.f.Close()
					j.out.Emit(j.ev)
				}
			}
		}()
	}
}

// fillFromProc reads what /proc still has about a process. It must run as soon as
// possible after the event, before a short-lived process exits.
func (en *enricher) fillFromProc(pi *procInfo) {
	if pi.Exe == "" {
		pi.Exe = readLink(pi.PID, "exe")
	}
	if pi.Cwd == "" {
		pi.Cwd = readLink(pi.PID, "cwd")
	}
	if len(pi.Args) == 0 {
		pi.Args = readCmdline(pi.PID)
	}
	if !pi.HasCreds {
		if st, err := readStatus(pi.PID); err == nil {
			pi.UID, pi.GID, pi.EUID, pi.HasCreds = st.UID, st.GID, st.EUID, true
			if pi.Comm == "" {
				pi.Comm = st.Name
			}
		}
	}
	if !pi.HasParentKey && pi.PPID > 0 {
		if k, err := startKey(pi.PPID); err == nil {
			pi.ParentStartKey, pi.HasParentKey = k, true
		}
	}
	pi.ProcessAccessed = pi.Exe != ""
}

func (en *enricher) parent(pi *procInfo) *event.Process {
	if pi.PPID <= 0 {
		return nil
	}
	p := &event.Process{PID: pi.PPID}
	if pi.HasParentKey {
		p.EntityID = en.env.EntityID(pi.PPID, pi.ParentStartKey)
		if s, ok := en.procs.get(p.EntityID); ok {
			p.Name, p.Executable, p.CommandLine = s.Name, s.Executable, s.CommandLine
			return p
		}
	}
	// Not seen by us (started before the agent): read it from /proc.
	p.Executable = readLink(pi.PPID, "exe")
	if args := readCmdline(pi.PPID); len(args) > 0 {
		p.CommandLine = joinArgs(args)
	}
	if p.Executable != "" {
		p.Name = filepath.Base(p.Executable)
	} else if st, err := readStat(pi.PPID); err == nil {
		p.Name = st.Comm
	}
	return p
}

// execEvent builds a process start event.
func (en *enricher) execEvent(pi *procInfo, ts time.Time) *event.Event {
	exe := pi.Exe
	if exe == "" {
		exe = pi.Filename
		if exe != "" && !filepath.IsAbs(exe) && pi.Cwd != "" {
			exe = filepath.Join(pi.Cwd, exe)
		}
	}
	name := pi.Comm
	if exe != "" {
		name = filepath.Base(exe)
	}
	p := &event.Process{
		EntityID:         en.env.EntityID(pi.PID, pi.StartKey),
		PID:              pi.PID,
		Name:             name,
		Executable:       exe,
		Args:             pi.Args,
		CommandLine:      joinArgs(pi.Args),
		WorkingDirectory: pi.Cwd,
		Parent:           en.parent(pi),
	}
	if st := startTimeFromTicks(pi.StartKey); !st.IsZero() {
		p.Start = &st
	}
	if pi.HasCreds {
		p.User = &event.User{ID: strconv.FormatUint(uint64(pi.UID), 10), Name: users.name(pi.UID)}
		elevated := pi.EUID == 0
		p.Elevated = &elevated
	}
	en.procs.put(p.EntityID, procSummary{Name: p.Name, Executable: p.Executable, CommandLine: p.CommandLine})
	ev := &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart},
			Action: "exec", Outcome: event.OutcomeSuccess, Module: en.module, Dataset: "process",
		},
		Message: "process started: " + p.CommandLine,
		Process: p,
	}
	if pi.ArgsTruncated {
		ev.Tags = append(ev.Tags, "args_truncated")
	}
	return ev
}

// emitExec emits a start event, hashing the executable first if requested. Cached hashes
// are added synchronously; uncached ones are computed by a worker from an fd opened now,
// so the hash is right even if the process exits or the file is replaced meanwhile.
func (en *enricher) emitExec(ev *event.Event, pid int64, hash bool, out platform.Emitter) {
	if !hash || ev.Process.Executable == "" {
		out.Emit(ev)
		return
	}
	exeLink := procPath(pid, "exe")
	fi, err := os.Stat(exeLink)
	if err != nil && filepath.IsAbs(ev.Process.Executable) {
		// The process already exited (common for short-lived commands): hash the file
		// it executed by path instead.
		exeLink = ev.Process.Executable
		fi, err = os.Stat(exeLink)
	}
	if err != nil || !fi.Mode().IsRegular() {
		out.Emit(ev)
		return
	}
	key, ok := keyOf(fi)
	if ok {
		if h, hit := en.hashes.get(key); hit {
			ev.Process.Hash = &event.Hash{SHA256: h}
			out.Emit(ev)
			return
		}
	}
	if !ok || en.hashQ == nil || fi.Size() > maxHashBytes {
		out.Emit(ev)
		return
	}
	f, err := os.Open(exeLink)
	if err != nil {
		out.Emit(ev)
		return
	}
	select {
	case en.hashQ <- hashJob{f: f, key: key, ev: ev, out: out}:
	default:
		f.Close() // hashers are saturated: send without hash rather than block
		out.Emit(ev)
	}
}

// decodeExit splits a raw wait status (task->exit_code) into an exit code and signal.
// A process killed by signal N gets exit code 128+N, like a shell reports it.
func decodeExit(status uint32) (code int64, signal int) {
	if sig := status & 0x7f; sig != 0 {
		return 128 + int64(sig), int(sig)
	}
	return int64((status >> 8) & 0xff), 0
}

// exitEvent builds a process end event.
func (en *enricher) exitEvent(pid int64, start uint64, comm string, status uint32, hasStatus bool, ts time.Time) *event.Event {
	id := en.env.EntityID(pid, start)
	p := &event.Process{EntityID: id, PID: pid, Name: comm, End: &ts}
	if s, ok := en.procs.get(id); ok {
		p.Name, p.Executable, p.CommandLine = s.Name, s.Executable, s.CommandLine
	}
	if st := startTimeFromTicks(start); !st.IsZero() {
		p.Start = &st
	}
	ev := &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeEnd},
			Action: "exit", Module: en.module, Dataset: "process",
		},
		Message: "process exited: " + p.Name,
		Process: p,
	}
	if hasStatus {
		code, sig := decodeExit(status)
		p.ExitCode = &code
		if sig != 0 {
			ev.Data = map[string]any{"exit_signal": sig}
		}
	}
	return ev
}
