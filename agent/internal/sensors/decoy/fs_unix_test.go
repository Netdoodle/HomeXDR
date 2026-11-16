//go:build unix

package decoy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSymlinkedParentRefused(t *testing.T) {
	root := t.TempDir()
	elsewhere := filepath.Join(root, "elsewhere")
	mkdirs(t, root, "home/alice", "home/bob", "elsewhere", "elsewhere2", "srv/real")
	// alice's Documents and bob's .aws point somewhere else.
	if err := os.Symlink(elsewhere, filepath.Join(root, "home", "alice", "Documents")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "elsewhere2"), filepath.Join(root, "home", "bob", ".aws")); err != nil {
		t.Fatal(err)
	}
	// An extra decoy whose folder is a link.
	if err := os.Symlink(filepath.Join(root, "srv", "real"), filepath.Join(root, "srv", "link")); err != nil {
		t.Fatal(err)
	}
	cfg := on()
	cfg.Extra = []string{filepath.Join(root, "srv", "link", "keys.txt")}
	s, _, _ := testSensor(t, "linux", root, t.TempDir(), cfg)
	s.checkOnce()
	for _, d := range []string{"elsewhere", "elsewhere2", "srv/real"} {
		ents, _ := os.ReadDir(filepath.Join(root, filepath.FromSlash(d)))
		if len(ents) != 0 {
			t.Errorf("wrote through a symlinked folder into %s", d)
		}
	}
	// alice's .aws was fine.
	if !exists(filepath.Join(root, "home", "alice", ".aws", "credentials.bak")) {
		t.Error("alice's .aws decoy missing")
	}
	for p := range s.byPath {
		if filepath.Dir(p) == filepath.Join(root, "home", "alice", "Documents") || filepath.Dir(p) == filepath.Join(root, "home", "bob", ".aws") {
			t.Errorf("tracked a decoy behind a link: %s", p)
		}
	}

	// A folder replaced by a link after the decoy was created: removal is refused.
	aws := filepath.Join(root, "home", "alice", ".aws")
	r := s.byPath[filepath.Join(aws, "credentials.bak")]
	if err := os.Rename(aws, aws+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(aws+".moved", aws); err != nil {
		t.Fatal(err)
	}
	if removed, err := removeFile(r.target(), r.SHA256, r.CreatedDir); removed || err != errUnsafe {
		t.Errorf("removal through a link: removed=%v err=%v", removed, err)
	}
	if !exists(filepath.Join(aws+".moved", "credentials.bak")) {
		t.Error("file behind the link was removed")
	}
}

func TestDecoyOwnershipAndMode(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "home/alice")
	s, _, _ := testSensor(t, "linux", root, t.TempDir(), on())
	s.checkOnce()
	dir := filepath.Join(root, "home", "alice", ".aws")
	di, err := os.Lstat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf(".aws: %v %v", di, err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "credentials.bak"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("decoy: %v %v", fi, err)
	}
	if os.Getuid() == 0 {
		if r := s.byPath[filepath.Join(dir, "credentials.bak")]; r == nil || !r.HasOwner || r.UID != 4242 {
			t.Errorf("not chowned to the profile's owner: %+v", r)
		}
	}
}
