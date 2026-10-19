package spool

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func line(i int) []byte { return []byte(fmt.Sprintf(`{"id":"%04d","pad":"%0200d"}`, i, i)) }

func drain(t *testing.T, s *Spool, max int) []string {
	t.Helper()
	var out []string
	for {
		b, err := s.Next(max, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if b == nil {
			return out
		}
		for _, l := range b.Lines {
			out = append(out, string(l[:13]))
		}
		b.Commit(len(b.Lines))
	}
}

func TestAppendNextCommit(t *testing.T) {
	s, err := Open(t.TempDir(), 64<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 10 {
		if err := s.Append(line(i)); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.Stats(); st.Events != 10 {
		t.Fatalf("queued %d", st.Events)
	}
	b, err := s.Next(4, 1<<20)
	if err != nil || b == nil || len(b.Lines) != 4 {
		t.Fatalf("first batch: %v %v", b, err)
	}
	b.Commit(2) // partial commit, e.g. after a 413 split
	if st := s.Stats(); st.Events != 8 {
		t.Fatalf("after partial commit: %d", st.Events)
	}
	got := drain(t, s, 100)
	if len(got) != 8 || got[0] != `{"id":"0002",` {
		t.Fatalf("drain after partial commit: %v", got)
	}
	if s.Stats().Events != 0 {
		t.Fatal("expected empty spool")
	}
	if err := s.Append([]byte("a\nb")); err == nil {
		t.Fatal("newline in line must be rejected")
	}
}

func TestSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 64<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		s.Append(line(i))
	}
	b, _ := s.Next(5, 1<<20)
	b.Commit(5)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, 64<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if st := s2.Stats(); st.Events != 15 {
		t.Fatalf("after restart queued %d, want 15", st.Events)
	}
	s2.Append(line(20))
	got := drain(t, s2, 7)
	if len(got) != 16 || got[0] != `{"id":"0005",` || got[15] != `{"id":"0020",` {
		t.Fatalf("after restart: %v", got)
	}
}

func TestTruncatesPartialLine(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 64<<20, quiet)
	s.Append(line(1))
	s.Close()
	// Simulate a crash in the middle of a write.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == segExt {
			f, _ := os.OpenFile(filepath.Join(dir, e.Name()), os.O_APPEND|os.O_WRONLY, 0o600)
			f.WriteString(`{"id":"broken`)
			f.Close()
		}
	}
	s2, err := Open(dir, 64<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := drain(t, s2, 10); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestDropsOldestWhenFull(t *testing.T) {
	// 16 MiB limit -> 2 MiB segments; write ~40 MiB.
	s, err := Open(t.TempDir(), 16<<20, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	big := make([]byte, 64<<10)
	for i := range big {
		big[i] = 'x'
	}
	n := 640
	for i := range n {
		l := append([]byte(fmt.Sprintf(`{"id":"%04d","p":"`, i)), big...)
		l = append(l, '"', '}')
		if err := s.Append(l); err != nil {
			t.Fatal(err)
		}
	}
	st := s.Stats()
	if st.Dropped == 0 {
		t.Fatal("expected drops")
	}
	if int64(st.Dropped)+st.Events != int64(n) {
		t.Fatalf("dropped %d + queued %d != %d", st.Dropped, st.Events, n)
	}
	if st.Bytes > 16<<20+MaxSegmentBytes {
		t.Fatalf("spool holds %d bytes, over the limit", st.Bytes)
	}
	got := drain(t, s, 1000)
	if int64(len(got)) != st.Events || got[len(got)-1] != fmt.Sprintf(`{"id":"%04d",`, n-1) {
		t.Fatalf("kept %d events, last %q", len(got), got[len(got)-1])
	}
}

func TestStaleCommitIgnored(t *testing.T) {
	s, _ := Open(t.TempDir(), 64<<20, quiet)
	defer s.Close()
	for i := range 5 {
		s.Append(line(i))
	}
	b1, _ := s.Next(5, 1<<20)
	b1.Commit(3)
	b1.Commit(3) // idempotent
	b1.Commit(2) // going backwards is ignored
	if s.Stats().Events != 2 {
		t.Fatalf("queued %d", s.Stats().Events)
	}
}

func TestInspect(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 64<<20, quiet)
	for i := range 3 {
		s.Append(line(i))
	}
	s.Close()
	b, segs := Inspect(dir)
	if b == 0 || segs == 0 {
		t.Fatalf("inspect: %d bytes %d segments", b, segs)
	}
}
