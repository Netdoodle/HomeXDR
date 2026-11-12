//go:build darwin

package darwin

import (
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"golang.org/x/sys/unix"
)

// maxHashBytes caps executable hashing.
const maxHashBytes = 128 << 20

// kproc is one entry of the kernel process table.
type kproc struct {
	PID, PPID  int64
	Start      uint64 // p_starttime in microseconds since the Unix epoch
	Comm       string
	UID, RUID  uint32
	Terminated bool // zombie
}

func fromKinfo(k *unix.KinfoProc) kproc {
	tv := k.Proc.P_starttime
	return kproc{
		PID: int64(k.Proc.P_pid), PPID: int64(k.Eproc.Ppid),
		Start: uint64(tv.Sec)*1_000_000 + uint64(tv.Usec),
		Comm:  unix.ByteSliceToString(k.Proc.P_comm[:]),
		UID:   k.Eproc.Ucred.Uid, RUID: k.Eproc.Pcred.P_ruid,
		Terminated: k.Proc.P_stat == 5, // SZOMB
	}
}

// listProcs returns the process table (sysctl kern.proc.all), without PID 0.
func listProcs() ([]kproc, error) {
	ks, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]kproc, 0, len(ks))
	for i := range ks {
		if ks[i].Proc.P_pid > 0 {
			out = append(out, fromKinfo(&ks[i]))
		}
	}
	return out, nil
}

// procByPID returns one process (sysctl kern.proc.pid).
func procByPID(pid int64) (kproc, error) {
	if pid <= 0 {
		return kproc{}, unix.ESRCH
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return kproc{}, err
	}
	if int64(k.Proc.P_pid) != pid {
		return kproc{}, unix.ESRCH
	}
	return fromKinfo(k), nil
}

// procArgs returns a process's executable path and argv (sysctl kern.procargs2; root
// can read every process's).
func procArgs(pid int64) (string, []string, error) {
	b, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return "", nil, err
	}
	return parseProcArgs(b)
}

// userCache maps UIDs to names (Directory Services lookups are not free).
type userCache struct {
	mu sync.Mutex
	m  map[uint32]string
}

var users = &userCache{m: map[uint32]string{}}

func (c *userCache) name(uid uint32) string {
	c.mu.Lock()
	n, ok := c.m[uid]
	c.mu.Unlock()
	if ok {
		return n
	}
	n = fsutil.UserName(uid)
	if n == "" {
		n = strconv.FormatUint(uint64(uid), 10)
	}
	c.mu.Lock()
	if len(c.m) > 4096 {
		c.m = map[uint32]string{}
	}
	c.m[uid] = n
	c.mu.Unlock()
	return n
}

// fileKey identifies file content cheaply: if none of these changed, the hash did not.
type fileKey struct {
	dev   int64
	ino   uint64
	size  int64
	mtime int64
}

func keyOf(fi os.FileInfo) (fileKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{dev: int64(st.Dev), ino: st.Ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}, true
}

// fileHash hashes a file, with a cache keyed on its identity and modification time.
func fileHash(hc *lru[fileKey, string], p string) string {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxHashBytes {
		return ""
	}
	key, ok := keyOf(fi)
	if ok {
		if h, hit := hc.get(key); hit {
			return h
		}
	}
	h, err := fsutil.SHA256File(p, maxHashBytes)
	if err == nil && ok {
		hc.put(key, h)
	}
	return h
}
