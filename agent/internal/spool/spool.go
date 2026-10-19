// Package spool is the agent's on-disk event queue. Events are appended as NDJSON lines
// to segment files in the data dir; the sender reads batches from the oldest segment and
// commits them once the server has accepted them. A cursor file records the committed
// position, so the queue survives restarts. When the spool exceeds its size limit the
// oldest segments are dropped and the dropped events are counted.
//
// Durability: appends are buffered and flushed every second (and on Close), so a clean
// shutdown loses nothing; a crash can lose at most the last unflushed second.
package spool

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Doodlebug12/homexdr/agent/internal/fsutil"
)

const (
	segExt     = ".seg"
	cursorFile = "cursor.json"
	// MaxSegmentBytes caps one segment file.
	MaxSegmentBytes = 4 << 20
	minSegmentBytes = 64 << 10
)

type segment struct {
	seq    uint64
	size   int64 // bytes written, including still-buffered bytes for the active segment
	events int64
}

type cursor struct {
	Seq uint64 `json:"seq"`
	Off int64  `json:"off"`
	N   int64  `json:"n"` // events consumed in segment Seq
}

// Spool is safe for concurrent use: many appenders, one reader (the sender).
type Spool struct {
	dir string
	log *slog.Logger

	mu        sync.Mutex
	maxBytes  int64
	segs      []*segment // ascending seq; the last one is active
	w         *os.File
	bw        *bufio.Writer
	cur       cursor
	total     int64 // bytes in all segments
	queued    int64 // events after the cursor
	dropped   uint64
	threshold int64
	ready     chan struct{}
	closed    bool
}

// Open opens or creates a spool in dir with a size limit.
func Open(dir string, maxBytes int64, log *slog.Logger) (*Spool, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, log: log, maxBytes: maxBytes, threshold: 500, ready: make(chan struct{}, 1)}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, segExt) {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(name, segExt), 16, 64)
		if err != nil {
			continue
		}
		seg, err := s.scan(seq)
		if err != nil {
			log.Warn("spool: unreadable segment, removing", "segment", name, "err", err)
			os.Remove(s.path(seq))
			continue
		}
		s.segs = append(s.segs, seg)
	}
	slices.SortFunc(s.segs, func(a, b *segment) int {
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		}
		return 0
	})
	_ = fsutil.ReadJSON(filepath.Join(dir, cursorFile), &s.cur)
	s.fixCursor()
	var events int64
	for _, g := range s.segs {
		s.total += g.size
		events += g.events
	}
	s.queued = events - s.cur.N
	if s.queued < 0 {
		s.queued = 0
	}
	// Always start a fresh active segment; old ones are only read.
	next := uint64(1)
	if n := len(s.segs); n > 0 {
		next = s.segs[n-1].seq + 1
	}
	if err := s.openSegment(next); err != nil {
		return nil, err
	}
	if len(s.segs) == 1 {
		s.cur = cursor{Seq: next}
	}
	return s, nil
}

func (s *Spool) path(seq uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%016x%s", seq, segExt))
}

// scan counts the complete lines of a segment, truncating a partial last line left by a
// crash.
func (s *Spool) scan(seq uint64) (*segment, error) {
	f, err := os.OpenFile(s.path(seq), os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256<<10)
	var off, lastNL, n int64
	for {
		chunk, err := r.ReadSlice('\n')
		off += int64(len(chunk))
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			n++
			lastNL = off
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if lastNL != off {
		if err := f.Truncate(lastNL); err != nil {
			return nil, err
		}
	}
	return &segment{seq: seq, size: lastNL, events: n}, nil
}

// fixCursor makes the cursor point into the oldest existing segment.
func (s *Spool) fixCursor() {
	if len(s.segs) == 0 {
		s.cur = cursor{}
		return
	}
	for _, g := range s.segs {
		if g.seq == s.cur.Seq {
			if s.cur.Off > g.size || s.cur.Off < 0 || s.cur.N > g.events {
				s.cur = cursor{Seq: g.seq}
			}
			// Segments before the cursor were fully consumed; remove them.
			for len(s.segs) > 0 && s.segs[0].seq < s.cur.Seq {
				os.Remove(s.path(s.segs[0].seq))
				s.segs = s.segs[1:]
			}
			return
		}
	}
	s.cur = cursor{Seq: s.segs[0].seq}
}

func (s *Spool) segMax() int64 {
	m := int64(MaxSegmentBytes)
	if s.maxBytes > 0 && s.maxBytes/8 < m {
		m = s.maxBytes / 8
	}
	return max(m, minSegmentBytes)
}

func (s *Spool) openSegment(seq uint64) error {
	f, err := os.OpenFile(s.path(seq), os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	s.w = f
	s.bw = bufio.NewWriterSize(f, 64<<10)
	s.segs = append(s.segs, &segment{seq: seq})
	return nil
}

func (s *Spool) active() *segment { return s.segs[len(s.segs)-1] }

// SetMaxBytes changes the size limit.
func (s *Spool) SetMaxBytes(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxBytes = n
	s.enforceLocked()
}

// SetThreshold sets how many queued events signal Ready.
func (s *Spool) SetThreshold(n int) {
	s.mu.Lock()
	s.threshold = int64(max(n, 1))
	s.mu.Unlock()
}

// Ready is signalled when at least the threshold of events is queued.
func (s *Spool) Ready() <-chan struct{} { return s.ready }

// ErrClosed is returned after Close.
var ErrClosed = errors.New("spool closed")

// Append adds one NDJSON line (without a trailing newline).
func (s *Spool) Append(line []byte) error {
	if bytes.IndexByte(line, '\n') >= 0 {
		return errors.New("spool: line contains a newline")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, err := s.bw.Write(line); err != nil {
		return err
	}
	if err := s.bw.WriteByte('\n'); err != nil {
		return err
	}
	a := s.active()
	n := int64(len(line) + 1)
	a.size += n
	a.events++
	s.total += n
	s.queued++
	if a.size >= s.segMax() {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	s.enforceLocked()
	if s.queued >= s.threshold {
		select {
		case s.ready <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *Spool) rotateLocked() error {
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if err := s.w.Close(); err != nil {
		return err
	}
	return s.openSegment(s.active().seq + 1)
}

// enforceLocked drops the oldest sealed segments while the spool is over its limit.
func (s *Spool) enforceLocked() {
	for s.maxBytes > 0 && s.total > s.maxBytes && len(s.segs) > 1 {
		g := s.segs[0]
		lost := g.events
		if g.seq == s.cur.Seq {
			lost -= s.cur.N
		}
		os.Remove(s.path(g.seq))
		s.segs = s.segs[1:]
		s.total -= g.size
		s.queued -= lost
		s.dropped += uint64(max(lost, 0))
		s.cur = cursor{Seq: s.segs[0].seq}
		s.saveCursorLocked()
		s.log.Warn("spool full: dropped oldest events", "events", lost, "limit_bytes", s.maxBytes)
	}
}

func (s *Spool) saveCursorLocked() {
	if err := fsutil.WriteJSONAtomic(filepath.Join(s.dir, cursorFile), s.cur, 0o600); err != nil {
		s.log.Warn("spool: save cursor", "err", err)
	}
}

// Flush writes buffered lines to the OS.
func (s *Spool) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.bw.Flush()
}

// Close flushes, syncs and closes the active segment and saves the cursor.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.bw.Flush()
	if serr := s.w.Sync(); err == nil {
		err = serr
	}
	if cerr := s.w.Close(); err == nil {
		err = cerr
	}
	s.saveCursorLocked()
	return err
}

// Stats are queue counters.
type Stats struct {
	Events  int64
	Bytes   int64
	Dropped uint64
}

// Stats returns the current queue depth and drop count.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Events: s.queued, Bytes: max(s.total-s.cur.Off, 0), Dropped: s.dropped}
}

// Batch is a run of lines from one segment, starting at the cursor.
type Batch struct {
	s     *Spool
	seq   uint64
	start int64
	Lines [][]byte
	ends  []int64 // file offset after each line
	done  int
}

// Next returns up to maxEvents lines (at most maxBytes in total, but always at least one
// line) from the cursor, or nil if the spool is empty. Lines stay queued until Commit.
func (s *Spool) Next(maxEvents int, maxBytes int64) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	for {
		if len(s.segs) == 0 {
			return nil, nil
		}
		g := s.segs[0]
		if g.seq != s.cur.Seq {
			s.cur = cursor{Seq: g.seq}
		}
		if s.cur.Off < g.size {
			break
		}
		if len(s.segs) == 1 {
			return nil, nil // caught up with the active segment
		}
		// Fully consumed sealed segment.
		os.Remove(s.path(g.seq))
		s.segs = s.segs[1:]
		s.total -= g.size
		s.cur = cursor{Seq: s.segs[0].seq}
		s.saveCursorLocked()
	}
	g := s.segs[0]
	if len(s.segs) == 1 {
		if err := s.bw.Flush(); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(s.path(g.seq))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(s.cur.Off, io.SeekStart); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, g.size-s.cur.Off), 256<<10)
	b := &Batch{s: s, seq: g.seq, start: s.cur.Off}
	off := s.cur.Off
	var bytesIn int64
	for len(b.Lines) < maxEvents {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			break // EOF (complete lines only)
		}
		if len(b.Lines) > 0 && bytesIn+int64(len(line)) > maxBytes {
			break
		}
		off += int64(len(line))
		bytesIn += int64(len(line))
		b.Lines = append(b.Lines, line[:len(line)-1])
		b.ends = append(b.ends, off)
		if err != nil {
			break
		}
	}
	if len(b.Lines) == 0 {
		return nil, nil
	}
	return b, nil
}

// Commit marks the first n lines of the batch as delivered. It may be called repeatedly
// with growing n. If the segment was dropped meanwhile, Commit does nothing.
func (b *Batch) Commit(n int) {
	if n <= b.done || n > len(b.Lines) {
		return
	}
	s := b.s
	s.mu.Lock()
	defer s.mu.Unlock()
	pos := b.start
	if b.done > 0 {
		pos = b.ends[b.done-1]
	}
	if s.cur.Seq != b.seq || s.cur.Off != pos {
		b.done = n
		return
	}
	k := int64(n - b.done)
	s.cur.Off = b.ends[n-1]
	s.cur.N += k
	s.queued -= k
	if s.queued < 0 {
		s.queued = 0
	}
	b.done = n
	s.saveCursorLocked()
}

// Inspect reports the approximate queued bytes of a spool directory without opening it
// for writing (used by `homexdr-agent status`).
func Inspect(dir string) (bytesQueued int64, segments int) {
	var cur cursor
	_ = fsutil.ReadJSON(filepath.Join(dir, cursorFile), &cur)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), segExt) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			bytesQueued += fi.Size()
			segments++
		}
	}
	return max(bytesQueued-cur.Off, 0), segments
}
