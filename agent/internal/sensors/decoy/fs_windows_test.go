//go:build windows

package decoy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

func hiddenAt(t *testing.T, p string) bool {
	t.Helper()
	h, err := isHidden(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The Hidden option sets FILE_ATTRIBUTE_HIDDEN when a decoy is created, adds or removes
// it when the option changes, never on a decoy someone changed, and none of it is
// reported as tampering.
func TestHiddenAttribute(t *testing.T) {
	root := windowsRoot(t)
	cfg := on()
	cfg.Files = []api.DecoyFile{
		{OS: api.DecoyOSWindows, Path: `{home}\Documents\Passwords.xlsx`, Hidden: true},
		desktopCodes,
	}
	s, c, ck := testSensor(t, "windows", root, t.TempDir(), cfg)
	s.checkOnce()
	sheet := filepath.Join(root, "Users", "carol", "Documents", "Passwords.xlsx")
	codes := filepath.Join(root, "Users", "bob", "Desktop", "backup-codes.txt")
	if !hiddenAt(t, sheet) || hiddenAt(t, codes) {
		t.Fatalf("on creation: sheet hidden %v, codes hidden %v", hiddenAt(t, sheet), hiddenAt(t, codes))
	}
	if r := s.byPath[sheet]; r == nil || !r.Hidden {
		t.Fatalf("sheet record %+v", r)
	}
	if hiddenAt(t, filepath.Join(root, "Users", "bob", "Documents", "Passwords.xlsx")) {
		t.Fatal("hid bob's own file")
	}
	before, _ := os.Lstat(sheet)

	// Turn it off for the sheet and on for the codes.
	s.cfg.Files[0].Hidden, s.cfg.Files[1].Hidden = false, true
	ck.add(2 * time.Minute)
	s.checkOnce()
	if hiddenAt(t, sheet) || !hiddenAt(t, codes) {
		t.Fatalf("after the toggle: sheet hidden %v, codes hidden %v", hiddenAt(t, sheet), hiddenAt(t, codes))
	}
	after, _ := os.Lstat(sheet)
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Errorf("the attribute change touched the file: %v %d -> %v %d", before.ModTime(), before.Size(), after.ModTime(), after.Size())
	}
	for i := 0; i < 2; i++ {
		ck.add(2 * time.Minute)
		s.checkOnce()
	}
	if evs := c.take(); len(evs) != 0 {
		t.Fatalf("the agent's own attribute changes raised %d events: %+v", len(evs), evs[0])
	}

	// A decoy someone changed is left as it is.
	write(t, sheet, "changed by someone")
	ck.add(2 * time.Minute)
	s.checkOnce()
	c.take()
	s.cfg.Files[0].Hidden = true
	s.checkOnce()
	if hiddenAt(t, sheet) {
		t.Error("changed the attributes of a decoy someone changed")
	}

	// A deleted decoy comes back hidden.
	os.Remove(codes)
	ck.add(2 * time.Minute)
	s.checkOnce()
	if evs := c.take(); len(evs) != 1 || !hiddenAt(t, codes) {
		t.Fatalf("recreated decoy: %d events, hidden %v", len(evs), hiddenAt(t, codes))
	}

	// The attribute is only changed on the agent's own file, not on one put in its place.
	r := s.byPath[codes]
	os.Remove(codes)
	write(t, codes, "someone else's file")
	if err := setHidden(r.target(), r.Dev, r.Inode, false); err != errNotOurs {
		t.Errorf("setHidden on another file: %v", err)
	}
	if hiddenAt(t, codes) {
		t.Error("the other file was changed")
	}
}
