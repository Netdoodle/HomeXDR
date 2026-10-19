package tail

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

type lines struct {
	mu sync.Mutex
	l  []string
}

func (c *lines) add(_ string, b []byte) {
	c.mu.Lock()
	c.l = append(c.l, string(b))
	c.mu.Unlock()
}

func (c *lines) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.l)
}

func waitFor(t *testing.T, c *lines, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.get(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out: have %v, want %d lines", c.get(), n)
	return nil
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
}

func run(t *testing.T, tl *Tailer, c *lines) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tl.Run(ctx, c.add)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

func TestFollowRotateTruncate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename-while-open rotation is a Unix pattern")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendTo(t, p, "old history\n")
	tl := &Tailer{Patterns: []string{filepath.Join(dir, "*.log")}, Poll: 20 * time.Millisecond}
	c := &lines{}
	stop := run(t, tl, c)
	defer stop()
	time.Sleep(100 * time.Millisecond)

	appendTo(t, p, "one\ntw")
	time.Sleep(100 * time.Millisecond)
	appendTo(t, p, "o\n")
	waitFor(t, c, 2)

	// Rotation by rename: the tail of the old file and the new file are both read.
	appendTo(t, p, "three\n")
	os.Rename(p, p+".1")
	appendTo(t, p, "four\n")
	waitFor(t, c, 4)

	// Truncation in place.
	time.Sleep(100 * time.Millisecond)
	os.Truncate(p, 0)
	time.Sleep(100 * time.Millisecond)
	appendTo(t, p, "five\n")
	got := waitFor(t, c, 5)
	want := []string{"one", "two", "three", "four", "five"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q (history must not be re-read)", got, want)
	}
}

func TestOffsetsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	off := filepath.Join(dir, "state", "offsets.json")
	appendTo(t, p, "")
	c := &lines{}
	stop := run(t, &Tailer{Patterns: []string{p}, Poll: 20 * time.Millisecond, Offsets: LoadOffsets(off)}, c)
	time.Sleep(100 * time.Millisecond)
	appendTo(t, p, "a\nb\n")
	waitFor(t, c, 2)
	stop()

	appendTo(t, p, "c\n") // written while the agent was stopped
	c2 := &lines{}
	stop = run(t, &Tailer{Patterns: []string{p}, Poll: 20 * time.Millisecond, Offsets: LoadOffsets(off)}, c2)
	defer stop()
	got := waitFor(t, c2, 1)
	time.Sleep(100 * time.Millisecond)
	if got = c2.get(); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("after restart got %q, want [c]", got)
	}
}

func TestLongLineTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	appendTo(t, p, "")
	c := &lines{}
	stop := run(t, &Tailer{Patterns: []string{p}, Poll: 20 * time.Millisecond}, c)
	defer stop()
	time.Sleep(100 * time.Millisecond)
	long := make([]byte, MaxLine*2)
	for i := range long {
		long[i] = 'x'
	}
	appendTo(t, p, string(long)+"\nshort\n")
	got := waitFor(t, c, 2)
	if len(got[0]) != MaxLine || got[1] != "short" {
		t.Fatalf("lengths %d, second %q", len(got[0]), got[1])
	}
}
