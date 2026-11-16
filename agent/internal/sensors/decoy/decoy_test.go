package decoy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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

// on is the default decoy config.
func on() api.DecoyConfig {
	return api.DecoyConfig{Enabled: true, CheckIntervalSec: 60, Files: api.DefaultDecoyFiles()}
}

// desktopCodes is a Windows entry the defaults no longer have.
var desktopCodes = api.DecoyFile{OS: api.DecoyOSWindows, Path: `{home}\Desktop\backup-codes.txt`}

// withDesktop is the default config plus backup codes on each Windows Desktop.
func withDesktop() api.DecoyConfig {
	c := on()
	c.Files = append(c.Files, desktopCodes)
	return c
}

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

func TestPlacementWindowsDefaults(t *testing.T) {
	root := windowsRoot(t)
	s, c, _ := testSensor(t, "windows", root, t.TempDir(), on())
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("placing decoys emitted %d events", len(evs))
	}
	u := func(p ...string) string { return filepath.Join(append([]string{root, "Users"}, p...)...) }
	want := []string{
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
		u("bob", "Desktop", "backup-codes.txt"),    // no Desktop decoys by default
		u("dave", "Documents", "Passwords.xlsx"),   // no NTUSER.DAT
		u("Public", "Documents", "Passwords.xlsx"), // skipped profile
	} {
		if exists(p) {
			t.Errorf("%s should not exist", p)
		}
	}
	if b, _ := os.ReadFile(u("bob", "Documents", "Passwords.xlsx")); string(b) != "bob's own file" {
		t.Errorf("overwrote a user's file: %q", b)
	}
	if len(s.st.Decoys) != len(want) {
		t.Fatalf("tracking %d decoys, want %d", len(s.st.Decoys), len(want))
	}
	if r := s.byPath[want[1]]; r == nil || !r.CreatedDir || !r.Extra || r.Kind != kindSheet || r.Home || r.Entry != `C:\ProgramData\Backup\credentials.csv` {
		t.Errorf("ProgramData decoy record: %+v", r)
	}
	if r := s.byPath[want[0]]; r == nil || r.User != "carol" || r.SHA256 == "" || r.Size == 0 || !r.Home || r.Entry != `{home}\Documents\Passwords.xlsx` {
		t.Errorf("carol's decoy record: %+v", r)
	}
	if st := s.Status(); st.Message != "2 decoy files" || st.State != api.SensorRunning {
		t.Errorf("status %+v", st)
	}
	// A second pass changes nothing and reports nothing.
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 || len(s.st.Decoys) != 2 {
		t.Fatalf("second pass: %d events, %d decoys", len(evs), len(s.st.Decoys))
	}
}

func TestPlacementLinuxAndMacDefaults(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "home/alice/Documents", "home/bob", "root", "var/backups")
	s, _, _ := testSensor(t, "linux", root, t.TempDir(), on())
	s.checkOnce()
	for _, p := range []string{"home/alice/Documents/passwords.txt", "home/alice/.aws/credentials.bak",
		"home/bob/Documents/passwords.txt", "home/bob/.aws/credentials.bak", "root/.aws/credentials.bak",
		"root/Documents/passwords.txt", "var/backups/db-credentials.sql"} {
		if !exists(filepath.Join(root, filepath.FromSlash(p))) {
			t.Errorf("%s not created", p)
		}
	}
	aws := s.byPath[filepath.Join(root, "home", "alice", ".aws", "credentials.bak")]
	if aws == nil || !aws.CreatedDir || aws.User != "alice" || aws.Kind != kindAWS || aws.UID != 4242 || !aws.HasOwner {
		t.Errorf("alice's aws decoy: %+v", aws)
	}
	if r := s.byPath[filepath.Join(root, "root", ".aws", "credentials.bak")]; r == nil || r.User != "root" || r.HasOwner || r.Entry != "{home}/.aws/credentials.bak" {
		t.Errorf("root's aws decoy: %+v", r)
	}
	if r := s.byPath[filepath.Join(root, "var", "backups", "db-credentials.sql")]; r == nil || r.Kind != kindSQL || r.CreatedDir || !r.Extra {
		t.Errorf("/var/backups decoy: %+v", r)
	}

	mroot := t.TempDir()
	mkdirs(t, mroot, "Users/eve/Documents", "Users/eve/Desktop", "Users/Shared/Documents", "Users/.hidden/Documents")
	m, _, _ := testSensor(t, "darwin", mroot, t.TempDir(), on())
	m.checkOnce()
	if len(m.st.Decoys) != 1 || !exists(filepath.Join(mroot, "Users", "eve", "Documents", "Passwords.txt")) ||
		exists(filepath.Join(mroot, "Users", "eve", "Desktop", "backup-codes.txt")) {
		t.Errorf("macOS decoys: %d", len(m.st.Decoys))
	}
}

// {home} is expanded to each real user's home folder, by each OS's rules.
func TestHomeExpansion(t *testing.T) {
	files := []api.DecoyFile{
		{OS: api.DecoyOSWindows, Path: `{home}\AppData\keys.txt`, Hidden: true},
		{OS: api.DecoyOSLinux, Path: "{home}/.ssh/old_id.txt", Hidden: true},
		{OS: api.DecoyOSDarwin, Path: "{home}/notes.txt"},
	}
	noBad := func(p, msg string) { t.Errorf("%s: %s", p, msg) }
	paths := func(ts []target) []string {
		var out []string
		for _, t := range ts {
			out = append(out, t.path())
		}
		slices.Sort(out)
		return out
	}
	owner4242 := func(_ string, fi os.FileInfo) (owner, bool) {
		if fi.Name() == "svc" {
			return owner{UID: 0, Name: "root"}, true // owned by root: not a user's home
		}
		if fi.Name() == "ghost" {
			return owner{}, false // no such user
		}
		return owner{UID: 4242, GID: 4243, Name: fi.Name()}, true
	}

	w := windowsRoot(t)
	wl := layout{goos: "windows", root: w, lookupOwner: owner4242}
	got := wl.targets(files, "", noBad)
	want := []string{filepath.Join(w, "Users", "bob", "AppData", "keys.txt"), filepath.Join(w, "Users", "carol", "AppData", "keys.txt")}
	if !slices.Equal(paths(got), want) {
		t.Errorf("windows: %v, want %v", paths(got), want)
	}
	for _, x := range got {
		if !x.Hidden || !x.Home || !x.MakeDir || x.Base != filepath.Join(w, "Users") || len(x.Dirs) != 2 || x.HasOwner || x.Kind != kindText {
			t.Errorf("windows target %+v", x)
		}
	}

	l := t.TempDir()
	mkdirs(t, l, "home/alice", "home/svc", "home/ghost", "home/lost+found", "root")
	ll := layout{goos: "linux", root: l, lookupOwner: owner4242}
	got = ll.targets(files, "", noBad)
	want = []string{filepath.Join(l, "home", "alice", ".ssh", "old_id.txt"), filepath.Join(l, "root", ".ssh", "old_id.txt")}
	if !slices.Equal(paths(got), want) {
		t.Errorf("linux: %v, want %v", paths(got), want)
	}
	for _, x := range got {
		if x.Hidden {
			t.Errorf("Linux target hidden: %+v", x)
		}
		if x.Dirs[0] == "alice" && (!x.HasOwner || x.UID != 4242 || x.GID != 4243 || x.User != "alice") {
			t.Errorf("alice's target %+v", x)
		}
		if x.Dirs[0] == "root" && (x.HasOwner || x.User != "root" || x.Base != l) {
			t.Errorf("root's target %+v", x)
		}
	}

	m := t.TempDir()
	mkdirs(t, m, "Users/eve", "Users/Shared", "Users/.localized")
	ml := layout{goos: "darwin", root: m, lookupOwner: owner4242}
	got = ml.targets(files, "", noBad)
	if len(got) != 1 || got[0].path() != filepath.Join(m, "Users", "eve", "notes.txt") || got[0].MakeDir || got[0].need() != 1 {
		t.Errorf("darwin: %+v", got)
	}
}

// A decoy is created when its folder exists, or when the folder's parent exists: then
// just that last folder is created. A home folder itself is never created.
func TestFolderRule(t *testing.T) {
	root := windowsRoot(t)
	mkdirs(t, root, "srv")
	cfg := on()
	cfg.Files = []api.DecoyFile{
		desktopCodes, // carol has no Desktop: created
		{OS: api.DecoyOSWindows, Path: `{home}\a\b\deep.txt`},  // a is missing: nothing
		{OS: api.DecoyOSWindows, Path: `C:\srv\new\x.txt`},     // srv exists: new is created
		{OS: api.DecoyOSWindows, Path: `C:\nope\deeper\y.txt`}, // nope is missing: nothing
	}
	s, c, _ := testSensor(t, "windows", root, t.TempDir(), cfg)
	s.checkOnce()
	u := func(p ...string) string { return filepath.Join(append([]string{root, "Users"}, p...)...) }
	for _, p := range []string{u("carol", "Desktop", "backup-codes.txt"), u("bob", "Desktop", "backup-codes.txt"), filepath.Join(root, "srv", "new", "x.txt")} {
		if !exists(p) {
			t.Errorf("%s not created", p)
		}
	}
	for _, p := range []string{u("bob", "a"), u("carol", "a"), filepath.Join(root, "nope")} {
		if exists(p) {
			t.Errorf("%s created", p)
		}
	}
	if r := s.byPath[u("carol", "Desktop", "backup-codes.txt")]; r == nil || !r.CreatedDir || r.Kind != kindCodes {
		t.Errorf("carol's Desktop decoy %+v", r)
	}
	if r := s.byPath[u("bob", "Desktop", "backup-codes.txt")]; r == nil || r.CreatedDir {
		t.Errorf("bob's Desktop decoy %+v", r)
	}
	if len(s.st.Decoys) != 3 || len(c.take()) != 0 {
		t.Fatalf("%d decoys", len(s.st.Decoys))
	}
	// A deleted folder the agent created is not reported while its parent is there: the
	// deletion of the decoy is, and both come back.
	os.RemoveAll(filepath.Join(root, "srv", "new"))
	s.checkOnce()
	if evs := c.take(); len(evs) != 1 || evs[0].Event.Type[0] != event.TypeDeletion || !exists(filepath.Join(root, "srv", "new", "x.txt")) {
		t.Fatalf("deleted folder: %d events", len(evs))
	}

	// Removing the entries removes the decoys and the folders the agent created for them,
	// but not folders that were there before.
	s.cfg.Files = nil
	s.checkOnce()
	if len(s.st.Decoys) != 0 || len(c.take()) != 0 {
		t.Fatalf("after removing the entries: %d decoys", len(s.st.Decoys))
	}
	for _, p := range []string{u("carol", "Desktop"), filepath.Join(root, "srv", "new")} {
		if exists(p) {
			t.Errorf("%s not removed", p)
		}
	}
	if !exists(u("bob", "Desktop")) || !exists(u("carol")) {
		t.Error("removed a folder the agent did not create")
	}
}

func TestStateRoundTrip(t *testing.T) {
	root := windowsRoot(t)
	data := t.TempDir()
	s, _, _ := testSensor(t, "windows", root, data, withDesktop())
	s.checkOnce()
	s.save()
	fi, err := os.Stat(filepath.Join(data, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("state file mode %v", fi.Mode().Perm())
	}
	s2, c2, _ := testSensor(t, "windows", root, data, withDesktop())
	if s2.st.Canary != s.st.Canary || len(s2.st.Decoys) != len(s.st.Decoys) {
		t.Fatalf("reloaded canary %q decoys %d, want %q %d", s2.st.Canary, len(s2.st.Decoys), s.st.Canary, len(s.st.Decoys))
	}
	for _, r := range s.st.Decoys {
		r2 := s2.byPath[r.Path]
		if r2 == nil || r2.SHA256 != r.SHA256 || r2.Size != r.Size || r2.MTime != r.MTime || r2.User != r.User ||
			r2.CreatedDir != r.CreatedDir || r2.Entry != r.Entry || r2.Home != r.Home || r2.Hidden != r.Hidden {
			t.Errorf("record %s did not round-trip: %+v vs %+v", r.Path, r2, r)
		}
	}
	s2.checkOnce()
	if evs := c2.take(); len(evs) != 0 || len(s2.st.Decoys) != len(s.st.Decoys) {
		t.Fatalf("re-adopting: %d events, %d decoys", len(evs), len(s2.st.Decoys))
	}
	// A corrupt state file starts over without touching the existing decoys.
	write(t, filepath.Join(data, StateFile), "{not json")
	s3, _, _ := testSensor(t, "windows", root, data, withDesktop())
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
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), withDesktop())
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

	// A folder that disappears is not reported (profile removed, home not mounted), and
	// the decoy stays configured while its user is not listed.
	os.RemoveAll(filepath.Join(root, "Users", "carol"))
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("removed profile: %d events", len(evs))
	}
	if r := s.byPath[sheet]; r == nil || !r.Unavailable || r.Retired || exists(sheet) {
		t.Fatalf("removed profile record: %+v", r)
	}
	// carol had two decoys: in Documents, and on the Desktop the agent created.
	if st := s.Status(); st.Message != "2 decoy files" {
		t.Errorf("status %q", st.Message)
	}
}

func TestRateLimit(t *testing.T) {
	root := windowsRoot(t)
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), withDesktop())
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
	s, _, _ := testSensor(t, "windows", root, data, withDesktop())
	s.checkOnce()
	s.save()
	codes := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	sheet := filepath.Join(root, "Users", "carol", "Documents", "Passwords.xlsx")
	csv := filepath.Join(root, "ProgramData", "Backup", "credentials.csv")
	write(t, codes, "someone edited this")

	cfg := withDesktop()
	cfg.Enabled = false
	off, c, _ := testSensor(t, "windows", root, data, cfg)
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
	again, _, _ := testSensor(t, "windows", root, data, withDesktop())
	if len(again.st.Decoys) != 1 || again.st.Decoys[0].Path != codes {
		t.Fatalf("state after cleanup: %d decoys", len(again.st.Decoys))
	}
}

// Entries removed from the list: unchanged decoys are removed, changed ones are left in
// place and the status says so, without events.
func TestRemovedEntries(t *testing.T) {
	root := windowsRoot(t)
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), withDesktop())
	s.checkOnce()
	bob := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	carol := filepath.Join(root, "Users", "carol", "Desktop", "backup-codes.txt")
	if !exists(bob) || !exists(carol) {
		t.Fatal("Desktop decoys not created")
	}
	write(t, bob, "bob wrote his own codes here")
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 1 {
		t.Fatalf("change: %d events", len(evs))
	}

	s.cfg = on() // the defaults: no Desktop decoys
	ck.add(2 * time.Minute)
	s.checkOnce()
	if exists(carol) || exists(filepath.Dir(carol)) {
		t.Error("unchanged Desktop decoy (or the folder the agent made) not removed")
	}
	if b, _ := os.ReadFile(bob); string(b) != "bob wrote his own codes here" {
		t.Error("changed Desktop decoy removed or modified")
	}
	if IsDecoy(bob) || IsDecoy(carol) {
		t.Error("retired decoys still registered as decoys")
	}
	want := "2 decoy files; 1 decoy file no longer in the list was left in place because someone changed it"
	if st := s.Status(); st.Message != want {
		t.Errorf("status %q", st.Message)
	}
	// Nothing about a retired decoy is reported, and it is not hashed again while it
	// stays as it is.
	write(t, bob, "and changed again")
	s.onWatch(bob, watchModify)
	ck.add(2 * time.Minute)
	s.checkOnce()
	s.checkOnce()
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("retired decoy: %d events", len(evs))
	}
	// Once it is gone, it is forgotten.
	os.Remove(bob)
	s.checkOnce()
	if s.byPath[bob] != nil || len(s.st.Decoys) != 2 || len(c.take()) != 0 {
		t.Fatalf("deleted retired decoy still tracked: %d", len(s.st.Decoys))
	}
	if st := s.Status(); st.Message != "2 decoy files" {
		t.Errorf("status %q", st.Message)
	}
}

// A retired decoy whose entry comes back is checked again.
func TestRetiredDecoyConfiguredAgain(t *testing.T) {
	root := windowsRoot(t)
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), withDesktop())
	s.checkOnce()
	bob := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	write(t, bob, "changed")
	ck.add(2 * time.Minute)
	s.checkOnce()
	c.take()
	s.cfg = on()
	s.checkOnce()
	if r := s.byPath[bob]; r == nil || !r.Retired {
		t.Fatalf("not retired: %+v", r)
	}
	s.cfg = withDesktop()
	s.checkOnce()
	if r := s.byPath[bob]; r == nil || r.Retired || !r.present() || !IsDecoy(bob) {
		t.Fatalf("not checked again: %+v", r)
	}
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("re-adding: %d events", len(evs))
	}
	os.Remove(bob)
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 1 || evs[0].Event.Type[0] != event.TypeDeletion {
		t.Fatalf("deletion after re-adding: %d events", len(evs))
	}
}

// Decoys created before decoy paths were configurable have no entry in the state file.
// After the upgrade the Desktop ones are removed (if unchanged) and the others are kept.
func TestUpgradeFromFixedPlacements(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "Users/bob/Documents", "Users/bob/Desktop", "ProgramData")
	write(t, filepath.Join(root, "Users", "bob", "NTUSER.DAT"), "hive")
	data := t.TempDir()
	s, _, _ := testSensor(t, "windows", root, data, withDesktop())
	s.checkOnce()
	if len(s.st.Decoys) != 3 {
		t.Fatalf("%d decoys", len(s.st.Decoys))
	}
	for _, r := range s.st.Decoys { // as the previous version wrote them
		r.Entry, r.Home, r.Extra = "", false, false
		if r.Name == "credentials.csv" {
			r.Kind = kindCSV
		}
	}
	s.dirty = true
	s.save()

	n, c, _ := testSensor(t, "windows", root, data, on())
	n.checkOnce()
	codes := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	if exists(codes) || !exists(filepath.Dir(codes)) {
		t.Error("old Desktop decoy not removed, or the user's Desktop removed")
	}
	if len(n.st.Decoys) != 2 || len(c.take()) != 0 {
		t.Fatalf("after the upgrade: %d decoys", len(n.st.Decoys))
	}
	if r := n.byPath[filepath.Join(root, "Users", "bob", "Documents", "Passwords.xlsx")]; r == nil || r.Entry != `{home}\Documents\Passwords.xlsx` || !r.Home {
		t.Errorf("Documents decoy %+v", r)
	}
	if r := n.byPath[filepath.Join(root, "ProgramData", "Backup", "credentials.csv")]; r == nil || r.Entry != `C:\ProgramData\Backup\credentials.csv` || r.Home {
		t.Errorf("ProgramData decoy %+v", r)
	}
	// An old home decoy whose profile is not listed right now stays while its entry is
	// configured.
	os.Remove(filepath.Join(root, "Users", "bob", "NTUSER.DAT"))
	r := n.byPath[filepath.Join(root, "Users", "bob", "Documents", "Passwords.xlsx")]
	r.Entry, r.Home = "", false
	n.checkOnce()
	if r.Retired || !exists(r.Path) {
		t.Errorf("home decoy of an unlisted user retired: %+v", r)
	}
}

func TestAbsoluteEntries(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "agentdata")
	mkdirs(t, root, "srv/share", "agentdata")
	payroll := filepath.Join(root, "srv", "share", "payroll.csv")
	cfg := on()
	cfg.Files = []api.DecoyFile{
		{OS: api.DecoyOSLinux, Path: "/srv/share/payroll.csv"},
		{OS: api.DecoyOSLinux, Path: "/agentdata/x.txt"},          // the agent's data folder
		{OS: api.DecoyOSLinux, Path: "relative/file.txt"},         // invalid
		{OS: api.DecoyOSDarwin, Path: "/srv/share/mac.txt"},       // another OS
		{OS: api.DecoyOSWindows, Path: `C:\srv\share\win.txt`},    // another OS
		{OS: api.DecoyOSLinux, Path: "/srv/share/payroll.csv"},    // twice
		{OS: api.DecoyOSLinux, Path: "/nofolder/sub/a.txt"},       // no parent folder
		{OS: api.DecoyOSLinux, Path: "/srv/share/.hidden-db.sql"}, // dot file
	}
	s, c, _ := testSensor(t, "linux", root, data, cfg)
	s.checkOnce()
	if len(s.st.Decoys) != 2 {
		t.Fatalf("decoys: %d", len(s.st.Decoys))
	}
	if r := s.byPath[payroll]; r == nil || !r.Extra || r.Kind != kindSheet || r.Home {
		t.Fatalf("payroll decoy: %+v", r)
	}
	if r := s.byPath[filepath.Join(root, "srv", "share", ".hidden-db.sql")]; r == nil || r.Kind != kindSQL {
		t.Fatalf("dot-file decoy: %+v", r)
	}
	for _, p := range []string{filepath.Join(data, "x.txt"), filepath.Join(root, "nofolder"), filepath.Join(root, "srv", "share", "mac.txt"), filepath.Join(root, "srv", "share", "win.txt")} {
		if exists(p) {
			t.Errorf("wrote %s", p)
		}
	}
	if !IsDecoy(payroll) {
		t.Error("decoy not registered for other sensors to skip")
	}
	if s.noted["relative/file.txt"] == "" {
		t.Errorf("invalid entry not noted: %v", s.noted)
	}
	// Removing it from the config removes the (unchanged) file.
	s.cfg.Files = nil
	s.checkOnce()
	if len(s.st.Decoys) != 0 || exists(payroll) || len(c.take()) != 0 || IsDecoy(payroll) {
		t.Errorf("unconfigured decoy: %d tracked, exists %v", len(s.st.Decoys), exists(payroll))
	}
}

func TestKindFor(t *testing.T) {
	for _, c := range []struct {
		dirs []string
		name string
		want string
	}{
		{nil, "Passwords.xlsx", kindSheet},
		{nil, "creds.CSV", kindSheet},
		{nil, "db.SQL", kindSQL},
		{[]string{".aws"}, "credentials.bak", kindAWS},
		{[]string{"backup"}, "credentials.bak", kindText},
		{nil, "backup-codes.txt", kindCodes},
		{nil, "notes.txt", kindText},
	} {
		if got := kindFor(c.dirs, c.name); got != c.want {
			t.Errorf("%v %s: %s, want %s", c.dirs, c.name, got, c.want)
		}
	}
}
