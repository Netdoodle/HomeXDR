//go:build linux

package decoy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// waitFor collects events until want of them arrived or the timeout passed.
func waitFor(c *collector, want int, d time.Duration) []*event.Event {
	var got []*event.Event
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		got = append(got, c.take()...)
		if len(got) >= want {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

func types(evs []*event.Event) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Event.Type[0]]++
	}
	return m
}

func TestInotifyRealtimeAndOwnActivity(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "home/alice/Documents")
	s, c, ck := testSensor(t, "linux", root, t.TempDir(), on())
	w, err := newWatcher(s.onWatch, quiet())
	if err != nil {
		t.Skip("inotify unavailable:", err)
	}
	defer w.close()
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()

	s.checkOnce() // creates the decoys and watches them
	s.checkOnce()
	if evs := waitFor(c, 1, 300*time.Millisecond); len(evs) != 0 {
		t.Fatalf("own creation and checks reported: %v", types(evs))
	}
	p := filepath.Join(root, "home", "alice", "Documents", "passwords.txt")

	// Someone reads it.
	if _, err := os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	evs := waitFor(c, 1, 2*time.Second)
	if n := types(evs)[event.TypeAccess]; n != 1 || len(evs) != 1 {
		t.Fatalf("read: %v", types(evs))
	}
	if evs[0].File.Path != p || evs[0].User == nil || evs[0].User.Name != "alice" {
		t.Errorf("access event %+v", evs[0].File)
	}

	// Someone appends to it: reported at once, and the check that hashes the file
	// afterwards reports neither its own read nor the same change again.
	ck.add(2 * time.Minute)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("more\n")
	f.Close()
	evs = waitFor(c, 2, 2*time.Second)
	if m := types(evs); m[event.TypeChange] != 1 {
		t.Fatalf("write: %v", m)
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := waitFor(c, 1, 300*time.Millisecond); len(evs) != 0 {
		t.Fatalf("own hash after a change reported: %v", types(evs))
	}

	// Deletion in real time, then the check recreates it without reporting it again.
	ck.add(2 * time.Minute)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	evs = waitFor(c, 1, 2*time.Second)
	if m := types(evs); m[event.TypeDeletion] != 1 || len(evs) != 1 {
		t.Fatalf("delete: %v", m)
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	if !exists(p) {
		t.Fatal("not recreated")
	}
	if evs := waitFor(c, 1, 300*time.Millisecond); len(evs) != 0 {
		t.Fatalf("recreation reported: %v", types(evs))
	}

	// Rename in real time.
	ck.add(2 * time.Minute)
	if err := os.Rename(p, p+".enc"); err != nil {
		t.Fatal(err)
	}
	evs = waitFor(c, 1, 2*time.Second)
	if len(evs) != 1 || evs[0].Event.Type[0] != TypeRename || evs[0].Data["decoy.renamed_to"] != p+".enc" {
		t.Fatalf("rename: %v", types(evs))
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := waitFor(c, 1, 300*time.Millisecond); len(evs) != 0 || !exists(p) {
		t.Fatalf("after rename: %v, recreated %v", types(evs), exists(p))
	}
	// The renamed file is no longer watched.
	os.ReadFile(p + ".enc")
	if evs := waitFor(c, 1, 300*time.Millisecond); len(evs) != 0 {
		t.Fatalf("renamed file still watched: %v", types(evs))
	}
}
