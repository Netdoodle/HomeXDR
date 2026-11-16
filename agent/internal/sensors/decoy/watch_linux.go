//go:build linux

package decoy

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const decoyMask = unix.IN_OPEN | unix.IN_ACCESS | unix.IN_MODIFY | unix.IN_ATTRIB |
	unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

const realtime = true

type inotifyWatcher struct {
	fd   int
	f    *os.File
	cb   func(path string, k watchKind)
	log  *slog.Logger
	done chan struct{}

	mu     sync.Mutex
	wds    map[int32]string
	byPath map[string]int32
}

// newWatcher starts an inotify instance that reports events on the watched decoys to cb.
func newWatcher(cb func(path string, k watchKind), log *slog.Logger) (watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	w := &inotifyWatcher{
		fd: fd, f: os.NewFile(uintptr(fd), "decoy-inotify"), cb: cb, log: log,
		done: make(chan struct{}), wds: map[int32]string{}, byPath: map[string]int32{},
	}
	go w.loop()
	return w, nil
}

func (w *inotifyWatcher) add(p string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.byPath[p]; ok {
		return nil
	}
	// IN_DONT_FOLLOW: a link at the path is watched as itself, never its target.
	wd, err := unix.InotifyAddWatch(w.fd, p, decoyMask|unix.IN_DONT_FOLLOW)
	if err != nil {
		return err
	}
	if old, ok := w.wds[int32(wd)]; ok && old != p {
		delete(w.byPath, old) // the same file under two paths: keep the newer name
	}
	w.wds[int32(wd)] = p
	w.byPath[p] = int32(wd)
	return nil
}

func (w *inotifyWatcher) remove(p string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	wd, ok := w.byPath[p]
	if !ok {
		return
	}
	delete(w.byPath, p)
	delete(w.wds, wd)
	// Events still queued for wd are dropped by the reader, which no longer knows it.
	_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
}

func (w *inotifyWatcher) close() {
	w.f.Close()
	<-w.done
}

func (w *inotifyWatcher) loop() {
	defer close(w.done)
	buf := make([]byte, 64<<10)
	le := binary.NativeEndian
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			return // closed
		}
		b := buf[:n]
		for len(b) >= unix.SizeofInotifyEvent {
			wd := int32(le.Uint32(b[0:]))
			mask := le.Uint32(b[4:])
			nl := int(le.Uint32(b[12:]))
			if unix.SizeofInotifyEvent+nl > len(b) {
				break
			}
			b = b[unix.SizeofInotifyEvent+nl:]
			if mask&unix.IN_Q_OVERFLOW != 0 {
				w.log.Warn("decoy: inotify queue overflow, some real-time events were lost")
				continue
			}
			w.mu.Lock()
			p, ok := w.wds[wd]
			if ok && mask&unix.IN_IGNORED != 0 {
				delete(w.wds, wd)
				if w.byPath[p] == wd {
					delete(w.byPath, p)
				}
				ok = false
			}
			w.mu.Unlock()
			if !ok {
				continue
			}
			switch {
			case mask&unix.IN_MOVE_SELF != 0:
				w.cb(p, watchMove)
			case mask&unix.IN_DELETE_SELF != 0:
				w.cb(p, watchDelete)
			case mask&unix.IN_MODIFY != 0:
				w.cb(p, watchModify)
			case mask&unix.IN_ATTRIB != 0:
				w.cb(p, watchAttrib)
			case mask&(unix.IN_OPEN|unix.IN_ACCESS) != 0:
				w.cb(p, watchAccess)
			}
		}
	}
}
