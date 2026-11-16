package decoy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) Emit(e *event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, e)
}

func (c *collector) take() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.evs
	c.evs = nil
	return out
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testSensor builds a sensor for goos's layout below root, with the state in dataDir and
// without real-time notifications.
func testSensor(t *testing.T, goos, root, dataDir string, cfg api.DecoyConfig) (*Sensor, *collector, *clock) {
	t.Helper()
	l := layout{goos: goos, root: root, lookupOwner: func(_ string, fi os.FileInfo) (owner, bool) {
		return owner{UID: 4242, GID: 4242, Name: fi.Name()}, true
	}}
	s := newSensor(cfg, dataDir, l, quiet())
	s.newWatcher = nil
	ck := &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	s.now = ck.now
	c := &collector{}
	s.mu.Lock()
	s.out = c
	s.load()
	s.mu.Unlock()
	return s, c, ck
}

func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func on() api.DecoyConfig { return api.DecoyConfig{Enabled: true, CheckIntervalSec: 60} }

// windowsRoot builds a Windows-like tree: bob (Documents with a file of his own where a
// decoy would go, Desktop), carol (Documents only), dave (no registry hive), Public.
func windowsRoot(t *testing.T) string {
	root := t.TempDir()
	mkdirs(t, root, "Users/bob/Documents", "Users/bob/Desktop", "Users/carol/Documents",
		"Users/dave/Documents", "Users/dave/Desktop", "Users/Public/Documents", "Users/Public/Desktop", "ProgramData")
	write(t, filepath.Join(root, "Users", "bob", "NTUSER.DAT"), "hive")
	write(t, filepath.Join(root, "Users", "carol", "NTUSER.DAT"), "hive")
	write(t, filepath.Join(root, "Users", "Public", "NTUSER.DAT"), "hive")
	write(t, filepath.Join(root, "Users", "bob", "Documents", "Passwords.xlsx"), "bob's own file")
	return root
}

func TestPlacementWindowsLayout(t *testing.T) {
	root := windowsRoot(t)
	s, c, _ := testSensor(t, "windows", root, t.TempDir(), on())
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("placing decoys emitted %d events", len(evs))
	}
	u := func(p ...string) string { return filepath.Join(append([]string{root, "Users"}, p...)...) }
	want := []string{
		u("bob", "Desktop", "backup-codes.txt"),
		u("carol", "Documents", "Passwords.xlsx"),
		filepath.Join(root, "ProgramData", "Backup", "credentials.csv"),
	}
	for _, p := range want {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("decoy %s not created: %v", p, err)
		}
		if !strings.Contains(string(b), s.st.Canary) {
			t.Errorf("%s lacks the canary marker", p)
		}
	}
	for _, p := range []string{
		u("carol", "Desktop", "backup-codes.txt"),  // no Desktop folder: not created
		u("dave", "Documents", "Passwords.xlsx"),   // no NTUSER.DAT
		u("Public", "Documents", "Passwords.xlsx"), // skipped profile
	} {
		if exists(p) {
			t.Errorf("%s should not exist", p)
		}
	}
	if exists(u("carol", "Desktop")) {
		t.Error("created a missing user folder")
	}
	if b, _ := os.ReadFile(u("bob", "Documents", "Passwords.xlsx")); string(b) != "bob's own file" {
		t.Errorf("overwrote a user's file: %q", b)
	}
	if len(s.st.Decoys) != len(want) {
		t.Fatalf("tracking %d decoys, want %d", len(s.st.Decoys), len(want))
	}
	if r := s.byPath[want[2]]; r == nil || !r.CreatedDir || r.User != "" {
		t.Errorf("ProgramData decoy record: %+v", r)
	}
	if r := s.byPath[want[0]]; r == nil || r.User != "bob" || r.SHA256 == "" || r.Size == 0 {
		t.Errorf("bob's decoy record: %+v", r)
	}
	if st := s.Status(); st.Message != "3 decoy files" || st.State != api.SensorRunning {
		t.Errorf("status %+v", st)
	}
	// A second pass changes nothing and reports nothing.
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 || len(s.st.Decoys) != 3 {
		t.Fatalf("second pass: %d events, %d decoys", len(evs), len(s.st.Decoys))
	}
}

func TestPlacementLinuxAndMacLayouts(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "home/alice/Documents", "home/bob", "root", "var/backups")
	s, _, _ := testSensor(t, "linux", root, t.TempDir(), on())
	s.checkOnce()
	for _, p := range []string{"home/alice/Documents/passwords.txt", "home/alice/.aws/credentials.bak",
		"home/bob/.aws/credentials.bak", "root/.aws/credentials.bak", "var/backups/db-credentials.sql"} {
		if !exists(filepath.Join(root, filepath.FromSlash(p))) {
			t.Errorf("%s not created", p)
		}
	}
	for _, p := range []string{"home/bob/Documents", "root/Documents"} {
		if exists(filepath.Join(root, filepath.FromSlash(p))) {
			t.Errorf("%s should not have been created", p)
		}
	}
	if r := s.byPath[filepath.Join(root, "home", "alice", ".aws", "credentials.bak")]; r == nil || !r.CreatedDir || r.User != "alice" {
		t.Errorf("alice's aws decoy: %+v", r)
	}

	mroot := t.TempDir()
	mkdirs(t, mroot, "Users/eve/Documents", "Users/eve/Desktop", "Users/Shared/Documents", "Users/.hidden/Documents")
	m, _, _ := testSensor(t, "darwin", mroot, t.TempDir(), on())
	m.checkOnce()
	if len(m.st.Decoys) != 2 || !exists(filepath.Join(mroot, "Users", "eve", "Documents", "Passwords.txt")) ||
		!exists(filepath.Join(mroot, "Users", "eve", "Desktop", "backup-codes.txt")) {
		t.Errorf("macOS decoys: %d", len(m.st.Decoys))
	}
}

func TestStateRoundTrip(t *testing.T) {
	root := windowsRoot(t)
	data := t.TempDir()
	s, _, _ := testSensor(t, "windows", root, data, on())
	s.checkOnce()
	s.save()
	fi, err := os.Stat(filepath.Join(data, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("state file mode %v", fi.Mode().Perm())
	}
	s2, c2, _ := testSensor(t, "windows", root, data, on())
	if s2.st.Canary != s.st.Canary || len(s2.st.Decoys) != len(s.st.Decoys) {
		t.Fatalf("reloaded canary %q decoys %d, want %q %d", s2.st.Canary, len(s2.st.Decoys), s.st.Canary, len(s.st.Decoys))
	}
	for _, r := range s.st.Decoys {
		r2 := s2.byPath[r.Path]
		if r2 == nil || r2.SHA256 != r.SHA256 || r2.Size != r.Size || r2.MTime != r.MTime || r2.User != r.User || r2.CreatedDir != r.CreatedDir {
			t.Errorf("record %s did not round-trip: %+v vs %+v", r.Path, r2, r)
		}
	}
	s2.checkOnce()
	if evs := c2.take(); len(evs) != 0 || len(s2.st.Decoys) != len(s.st.Decoys) {
		t.Fatalf("re-adopting: %d events, %d decoys", len(evs), len(s2.st.Decoys))
	}
	// A corrupt state file starts over without touching the existing decoys.
	write(t, filepath.Join(data, StateFile), "{not json")
	s3, _, _ := testSensor(t, "windows", root, data, on())
	if len(s3.st.Decoys) != 0 || s3.st.Canary == "" {
		t.Fatalf("corrupt state: %d decoys", len(s3.st.Decoys))
	}
	s3.checkOnce()
	if len(s3.st.Decoys) != 0 {
		t.Fatalf("adopted files it cannot prove it created: %d", len(s3.st.Decoys))
	}
}

func TestDetectChangeDeleteRename(t *testing.T) {
	root := windowsRoot(t)
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), on())
	s.checkOnce()
	c.take()
	codes := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	sheet := filepath.Join(root, "Users", "carol", "Documents", "Passwords.xlsx")
	csv := filepath.Join(root, "ProgramData", "Backup", "credentials.csv")

	// Change.
	write(t, codes, "encrypted garbage")
	future := time.Now().Add(time.Hour)
	os.Chtimes(codes, future, future)
	ck.add(2 * time.Minute)
	s.checkOnce()
	evs := c.take()
	if len(evs) != 1 {
		t.Fatalf("change: %d events", len(evs))
	}
	e := evs[0]
	if e.Event.Module != event.ModuleDecoy || e.Event.Dataset != Dataset || e.Event.Type[0] != event.TypeChange ||
		e.Event.Category[0] != event.CategoryFile || e.File.Path != codes || e.Labels["decoy"] != "true" ||
		e.User == nil || e.User.Name != "bob" || e.Message != "Decoy file was modified: "+codes {
		t.Errorf("change event: %+v %+v %+v", e.Event, e.File, e.Message)
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("unchanged after a change: %d events", len(evs))
	}

	// Deletion, then the decoy is put back without an event of its own.
	os.Remove(sheet)
	ck.add(2 * time.Minute)
	s.checkOnce()
	evs = c.take()
	if len(evs) != 1 || evs[0].Event.Type[0] != event.TypeDeletion || evs[0].File.Path != sheet {
		t.Fatalf("deletion: %+v", evs)
	}
	if !exists(sheet) {
		t.Fatal("deleted decoy not recreated")
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("after recreation: %d events", len(evs))
	}

	// Rename.
	if err := os.Rename(csv, csv+".locked"); err != nil {
		t.Fatal(err)
	}
	ck.add(2 * time.Minute)
	s.checkOnce()
	evs = c.take()
	if len(evs) != 1 || evs[0].Event.Type[0] != TypeRename || evs[0].Data["decoy.renamed_to"] != csv+".locked" {
		t.Fatalf("rename: %+v", evs)
	}
	if !exists(csv) {
		t.Fatal("renamed decoy not recreated")
	}

	// A folder that disappears is not reported (profile removed, home not mounted).
	os.RemoveAll(filepath.Join(root, "Users", "carol"))
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("removed profile: %d events", len(evs))
	}
	if r := s.byPath[sheet]; r == nil || !r.Unavailable || exists(sheet) {
		t.Fatalf("removed profile record: %+v", r)
	}
	if st := s.Status(); st.Message != "2 decoy files" {
		t.Errorf("status %q", st.Message)
	}
}

func TestRateLimit(t *testing.T) {
	root := windowsRoot(t)
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), on())
	s.checkOnce()
	c.take()
	p := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	s.onWatch(p, watchAccess)
	s.onWatch(p, watchAccess)
	ck.add(30 * time.Second)
	s.onWatch(p, watchAccess)
	s.onWatch(p, watchModify) // another type has its own limit
	if evs := c.take(); len(evs) != 2 || evs[0].Event.Type[0] != event.TypeAccess || evs[1].Event.Type[0] != event.TypeChange {
		t.Fatalf("within a minute: %d events", len(evs))
	}
	other := filepath.Join(root, "Users", "carol", "Documents", "Passwords.xlsx")
	s.onWatch(other, watchAccess) // another decoy has its own limit
	ck.add(31 * time.Second)
	s.onWatch(p, watchAccess)
	if evs := c.take(); len(evs) != 2 {
		t.Fatalf("after a minute: %d events", len(evs))
	}
	s.onWatch(filepath.Join(root, "not-a-decoy"), watchAccess)
	if evs := c.take(); len(evs) != 0 {
		t.Fatal("event for an unknown path")
	}
}

func TestDisableRemovesOnlyUnchanged(t *testing.T) {
	root := windowsRoot(t)
	data := t.TempDir()
	s, _, _ := testSensor(t, "windows", root, data, on())
	s.checkOnce()
	s.save()
	codes := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	sheet := filepath.Join(root, "Users", "carol", "Documents", "Passwords.xlsx")
	csv := filepath.Join(root, "ProgramData", "Backup", "credentials.csv")
	write(t, codes, "someone edited this")

	off, c, _ := testSensor(t, "windows", root, data, api.DecoyConfig{Enabled: false})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- off.Run(ctx, c) }()
	deadline := time.Now().Add(5 * time.Second)
	for exists(sheet) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if exists(sheet) || exists(csv) {
		t.Error("unchanged decoys not removed")
	}
	if exists(filepath.Join(root, "ProgramData", "Backup")) {
		t.Error("empty folder the agent created not removed")
	}
	if b, _ := os.ReadFile(codes); string(b) != "someone edited this" {
		t.Error("removed or changed a decoy someone changed")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "Users", "bob", "Documents", "Passwords.xlsx")); string(b) != "bob's own file" {
		t.Error("touched a user's file")
	}
	st := off.Status()
	if st.State != api.SensorDisabled || st.Message != "1 decoy file left in place because someone changed them" {
		t.Errorf("status %+v", st)
	}
	if len(c.take()) != 0 {
		t.Error("cleanup emitted events")
	}
	// The kept decoy stays in the state file.
	again, _, _ := testSensor(t, "windows", root, data, on())
	if len(again.st.Decoys) != 1 || again.st.Decoys[0].Path != codes {
		t.Fatalf("state after cleanup: %d decoys", len(again.st.Decoys))
	}
}

func TestExtraDecoys(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "agentdata")
	mkdirs(t, root, "srv/share", "agentdata")
	extra := filepath.Join(root, "srv", "share", "payroll.csv")
	cfg := on()
	cfg.Extra = []string{extra, "relative/file.txt", filepath.Join(data, "x.txt"), filepath.Join(root, "nofolder", "a.txt")}
	s, c, _ := testSensor(t, "none", root, data, cfg)
	s.checkOnce()
	if len(s.st.Decoys) != 1 || s.st.Decoys[0].Path != extra || !s.st.Decoys[0].Extra || s.st.Decoys[0].Kind != kindCSV {
		t.Fatalf("extra decoys: %+v", s.st.Decoys)
	}
	if exists(filepath.Join(data, "x.txt")) || exists(filepath.Join(root, "nofolder")) {
		t.Error("wrote where it should not")
	}
	if !IsDecoy(extra) {
		t.Error("decoy not registered for other sensors to skip")
	}
	// Removing it from the config removes the (unchanged) file.
	s.cfg.Extra = nil
	s.checkOnce()
	if len(s.st.Decoys) != 0 || exists(extra) || len(c.take()) != 0 || IsDecoy(extra) {
		t.Errorf("unconfigured extra decoy: %d tracked, exists %v", len(s.st.Decoys), exists(extra))
	}
}

func TestExtraTargetValidation(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "a", "b.txt")
	if _, ok := extraTarget(abs, ""); !ok {
		t.Error("absolute path rejected")
	}
	for _, p := range []string{"", "b.txt", "../b.txt", filepath.Join(t.TempDir(), "*.txt")} {
		if _, ok := extraTarget(p, ""); ok {
			t.Errorf("%q accepted", p)
		}
	}
	if k := kindForName("db.SQL"); k != kindSQL {
		t.Errorf("kind %s", k)
	}
}
