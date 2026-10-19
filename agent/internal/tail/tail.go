// Package tail follows log files by glob, line by line, surviving rotation (rename and
// re-create, or copy-truncate) and agent restarts (offsets are persisted).
package tail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
)

// MaxLine caps one line; the rest of a longer line is discarded.
const MaxLine = 64 << 10

// Offsets persists read positions per path.
type Offsets struct {
	mu    sync.Mutex
	path  string
	m     map[string]Offset
	dirty bool
}

// Offset is a saved position. Dev/Inode identify the file on Unix (zero elsewhere).
type Offset struct {
	Offset int64  `json:"offset"`
	Dev    uint64 `json:"dev,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
}

// LoadOffsets reads the offsets file (missing is fine). An empty path keeps offsets in
// memory only.
func LoadOffsets(path string) *Offsets {
	o := &Offsets{path: path, m: map[string]Offset{}}
	if path != "" {
		_ = fsutil.ReadJSON(path, &o.m)
	}
	return o
}

func (o *Offsets) get(p string) (Offset, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[p]
	return v, ok
}

func (o *Offsets) set(p string, v Offset) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m[p] != v {
		o.m[p] = v
		o.dirty = true
	}
}

func (o *Offsets) remove(p string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.m[p]; ok {
		delete(o.m, p)
		o.dirty = true
	}
}

// Save writes the offsets if they changed.
func (o *Offsets) Save() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.dirty || o.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
		return err
	}
	if err := fsutil.WriteJSONAtomic(o.path, o.m, 0o600); err != nil {
		return err
	}
	o.dirty = false
	return nil
}

// Tailer follows files matching Patterns.
type Tailer struct {
	Patterns []string
	Poll     time.Duration // default 1s
	// FromStart reads files found at startup from the beginning when no offset is saved.
	// By default they are read from the end, so old history is not re-sent.
	FromStart bool
	Offsets   *Offsets
	Log       *slog.Logger
}

type file struct {
	path    string
	f       *os.File
	fi      os.FileInfo
	off     int64 // position after the last complete line
	readPos int64 // position of the next byte to read
	partial []byte
	skip    bool // discarding the rest of an over-long line
}

// Run follows the files and calls fn for every complete line until ctx ends.
func (t *Tailer) Run(ctx context.Context, fn func(path string, line []byte)) error {
	poll := t.Poll
	if poll <= 0 {
		poll = time.Second
	}
	if t.Offsets == nil {
		t.Offsets = LoadOffsets("")
	}
	if t.Log == nil {
		t.Log = slog.Default()
	}
	files := map[string]*file{}
	defer func() {
		for _, f := range files {
			t.save(f)
			f.f.Close()
		}
		_ = t.Offsets.Save()
	}()
	first := true
	tick := time.NewTicker(poll)
	defer tick.Stop()
	lastSave := time.Now()
	lastGlob := time.Time{}
	for {
		if time.Since(lastGlob) >= 10*poll || first {
			lastGlob = time.Now()
			for _, pat := range t.Patterns {
				matches, err := filepath.Glob(pat)
				if err != nil {
					return err
				}
				for _, p := range matches {
					if _, ok := files[p]; ok {
						continue
					}
					if f := t.open(p, first && !t.FromStart); f != nil {
						files[p] = f
					}
				}
			}
			first = false
		}
		for p, f := range files {
			if !t.step(f, fn) {
				f.f.Close()
				delete(files, p)
				t.Offsets.remove(p)
			}
		}
		if time.Since(lastSave) > 5*time.Second {
			for _, f := range files {
				t.save(f)
			}
			if err := t.Offsets.Save(); err != nil {
				t.Log.Warn("tail: save offsets", "err", err)
			}
			lastSave = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func (t *Tailer) save(f *file) {
	m := fsutil.StatMeta(f.fi)
	t.Offsets.set(f.path, Offset{Offset: f.off, Dev: m.Dev, Inode: m.Inode})
}

// open starts following p. Without a saved offset for the same file it starts at the end
// (atEnd) or the beginning.
func (t *Tailer) open(p string, atEnd bool) *file {
	fh, err := os.Open(p)
	if err != nil {
		return nil
	}
	fi, err := fh.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		fh.Close()
		return nil
	}
	f := &file{path: p, f: fh, fi: fi}
	m := fsutil.StatMeta(fi)
	if saved, ok := t.Offsets.get(p); ok && saved.Dev == m.Dev && saved.Inode == m.Inode && saved.Offset <= fi.Size() {
		f.off = saved.Offset
	} else if atEnd {
		f.off = fi.Size()
	}
	if _, err := fh.Seek(f.off, io.SeekStart); err != nil {
		fh.Close()
		return nil
	}
	f.readPos = f.off
	return f
}

// step reads new lines and handles rotation. It returns false when the file is gone.
func (t *Tailer) step(f *file, fn func(string, []byte)) bool {
	t.drain(f, fn)
	cur, err := os.Stat(f.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Renamed or deleted: we already read the old file to EOF.
		t.flushPartial(f, fn)
		return false
	case err != nil:
		return true
	case !os.SameFile(cur, f.fi):
		// Rotated: finish the old file, then follow the new one from the start.
		t.drain(f, fn)
		t.flushPartial(f, fn)
		f.f.Close()
		nf := t.open(f.path, false)
		if nf == nil {
			return false
		}
		nf.off, nf.readPos = 0, 0
		nf.f.Seek(0, io.SeekStart)
		*f = *nf
		t.drain(f, fn)
	default:
		if cur.Size() < f.readPos {
			// Truncated in place (copytruncate): start over.
			f.partial, f.skip = nil, false
			f.off, f.readPos = 0, 0
			f.f.Seek(0, io.SeekStart)
			t.drain(f, fn)
		}
		f.fi = cur
	}
	return true
}

func (t *Tailer) drain(f *file, fn func(string, []byte)) {
	buf := make([]byte, 64<<10)
	for {
		n, err := f.f.Read(buf)
		if n > 0 {
			base := f.readPos
			f.readPos += int64(n)
			t.consume(f, buf[:n], base, fn)
		}
		if err != nil || n == 0 {
			return
		}
	}
}

// consume splits data (which starts at file offset base) into lines. f.off advances to
// just after each complete line, so a saved offset never splits a line.
func (t *Tailer) consume(f *file, data []byte, base int64, fn func(string, []byte)) {
	pos := 0
	for pos < len(data) {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			f.appendPartial(data[pos:])
			return
		}
		f.appendPartial(data[pos : pos+i])
		emit(fn, f.path, f.partial)
		f.partial, f.skip = f.partial[:0], false
		pos += i + 1
		f.off = base + int64(pos)
	}
}

// appendPartial buffers part of a line, keeping at most MaxLine bytes.
func (f *file) appendPartial(b []byte) {
	if f.skip {
		return
	}
	room := MaxLine - len(f.partial)
	if len(b) > room {
		b = b[:room]
		f.skip = true
	}
	f.partial = append(f.partial, b...)
}

func emit(fn func(string, []byte), path string, line []byte) {
	line = bytes.TrimRight(line, "\r")
	if len(line) == 0 {
		return
	}
	fn(path, line)
}

// flushPartial emits a final line without a newline when its file goes away.
func (t *Tailer) flushPartial(f *file, fn func(string, []byte)) {
	if len(f.partial) > 0 {
		emit(fn, f.path, f.partial)
		f.partial = nil
	}
}
