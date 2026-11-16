//go:build windows

package decoy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

// junction creates a directory junction (mklink /J), or skips the test if it cannot.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v %s", err, out)
	}
}

// A junction in the middle of a path refuses the decoy, and one that appears later
// refuses its removal; neither raises an event.
func TestJunctionInPathRefused(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "srv/real/share", "srv/a/share")
	junction(t, filepath.Join(root, "srv", "junc"), filepath.Join(root, "srv", "real"))
	cfg := on()
	cfg.Files = []api.DecoyFile{
		{OS: api.DecoyOSWindows, Path: `C:\srv\junc\share\keys.txt`}, // its folder exists through the junction
		{OS: api.DecoyOSWindows, Path: `C:\srv\junc\new\keys.txt`},   // would create real\new
		{OS: api.DecoyOSWindows, Path: `C:\srv\a\share\x.txt`},
	}
	s, c, _ := testSensor(t, "windows", root, t.TempDir(), cfg)
	s.checkOnce()
	if ents, _ := os.ReadDir(filepath.Join(root, "srv", "real")); len(ents) != 1 {
		t.Errorf("wrote through the junction: %v", ents)
	}
	if ents, _ := os.ReadDir(filepath.Join(root, "srv", "real", "share")); len(ents) != 0 {
		t.Errorf("wrote through the junction: %v", ents)
	}
	x := filepath.Join(root, "srv", "a", "share", "x.txt")
	if len(s.st.Decoys) != 1 || s.byPath[x] == nil {
		t.Fatalf("decoys: %d", len(s.st.Decoys))
	}
	want := "1 decoy file; decoy path refused: " + filepath.Join(root, "srv", "junc", "new", "keys.txt") + " goes through a link (and 1 more)"
	if st := s.Status(); st.Message != want {
		t.Errorf("status %q, want %q", st.Message, want)
	}

	// srv\a becomes a junction; the entry is then removed: nothing is removed through it.
	a := filepath.Join(root, "srv", "a")
	if err := os.Rename(a, a+".moved"); err != nil {
		t.Fatal(err)
	}
	junction(t, a, a+".moved")
	r := s.byPath[x]
	if removed, _, err := removeFile(r.target(), r.SHA256, r.CreatedDir); removed || err != errUnsafe {
		t.Errorf("removal through a junction: removed=%v err=%v", removed, err)
	}
	s.cfg.Files = s.cfg.Files[:2]
	s.checkOnce()
	if !exists(filepath.Join(a+".moved", "share", "x.txt")) {
		t.Error("removed the decoy through a junction")
	}
	if st := s.Status(); !strings.Contains(st.Message, "decoy path refused: "+x+" goes through a link") {
		t.Errorf("status %q", st.Message)
	}
	if evs := c.take(); len(evs) != 0 {
		t.Errorf("refusals raised %d events", len(evs))
	}
}
