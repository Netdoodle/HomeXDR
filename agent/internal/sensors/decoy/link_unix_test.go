//go:build unix

package decoy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

// A link anywhere on an absolute path (here two folders above the decoy) refuses it, and
// a path that became linked later refuses removal. Neither raises an event; the sensor
// message names the path.
func TestLinkAtGrandparentRefused(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "srv/real/share", "srv/a/share")
	if err := os.Symlink(filepath.Join(root, "srv", "real"), filepath.Join(root, "srv", "link")); err != nil {
		t.Fatal(err)
	}
	cfg := on()
	cfg.Files = []api.DecoyFile{
		{OS: api.DecoyOSLinux, Path: "/srv/link/share/keys.txt"}, // its folder exists through the link
		{OS: api.DecoyOSLinux, Path: "/srv/link/new/keys.txt"},   // would create real/new
		{OS: api.DecoyOSLinux, Path: "/srv/a/share/x.txt"},
	}
	s, c, _ := testSensor(t, "linux", root, t.TempDir(), cfg)
	s.checkOnce()
	if ents, _ := os.ReadDir(filepath.Join(root, "srv", "real")); len(ents) != 1 {
		t.Errorf("wrote through the link: %v", ents)
	}
	if ents, _ := os.ReadDir(filepath.Join(root, "srv", "real", "share")); len(ents) != 0 {
		t.Errorf("wrote through the link: %v", ents)
	}
	x := filepath.Join(root, "srv", "a", "share", "x.txt")
	if len(s.st.Decoys) != 1 || s.byPath[x] == nil {
		t.Fatalf("decoys: %d", len(s.st.Decoys))
	}
	want := "1 decoy file; decoy path refused: " + filepath.Join(root, "srv", "link", "new", "keys.txt") + " goes through a link (and 1 more)"
	if st := s.Status(); st.Message != want || st.State != api.SensorRunning {
		t.Errorf("status %+v, want %q", st, want)
	}

	// srv/a becomes a link; the entry is then removed: the decoy is not removed through it.
	a := filepath.Join(root, "srv", "a")
	if err := os.Rename(a, a+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a+".moved", a); err != nil {
		t.Fatal(err)
	}
	r := s.byPath[x]
	if removed, _, err := removeFile(r.target(), r.SHA256, r.CreatedDir); removed || err != errUnsafe {
		t.Errorf("removal through a link: removed=%v err=%v", removed, err)
	}
	s.cfg.Files = s.cfg.Files[:2]
	s.checkOnce()
	if !exists(filepath.Join(a+".moved", "share", "x.txt")) {
		t.Error("removed the decoy through a link")
	}
	if st := s.Status(); !strings.Contains(st.Message, "decoy path refused: "+x+" goes through a link") {
		t.Errorf("status %q", st.Message)
	}
	if evs := c.take(); len(evs) != 0 {
		t.Errorf("refusals raised %d events", len(evs))
	}
}

// The known root-level system links are resolved, other root-level links are not, and
// tests (with a root) never resolve anything.
func TestRootLinks(t *testing.T) {
	l := layout{goos: "darwin"}
	if got := l.resolve([]string{"srv", "x"}); strings.Join(got, "/") != "srv/x" {
		t.Errorf("not a known link: %v", got)
	}
	if got := (layout{goos: "darwin", root: "/tmp/x"}).resolve([]string{"var", "x"}); strings.Join(got, "/") != "var/x" {
		t.Errorf("resolved below a test root: %v", got)
	}
	if fi, err := os.Lstat("/var"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if to, _ := os.Readlink("/var"); strings.TrimPrefix(to, "/") == "private/var" {
			if got := l.resolve([]string{"var", "backups"}); strings.Join(got, "/") != "private/var/backups" {
				t.Errorf("macOS /var: %v", got)
			}
		}
	}
}
