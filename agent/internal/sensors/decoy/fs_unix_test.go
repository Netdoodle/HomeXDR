//go:build unix

package decoy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
	"golang.org/x/sys/unix"
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
	cfg.Files = append(cfg.Files, api.DecoyFile{OS: api.DecoyOSLinux, Path: "/srv/link/keys.txt"})
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
	if removed, _, err := removeFile(r.target(), r.SHA256, r.CreatedDir); removed || err != errUnsafe {
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
	// The folder rule also created alice's Documents, private to her.
	if di, err := os.Lstat(filepath.Join(root, "home", "alice", "Documents")); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("Documents: %v %v", di, err)
	}
	if os.Getuid() == 0 {
		if r := s.byPath[filepath.Join(dir, "credentials.bak")]; r == nil || !r.HasOwner || r.UID != 4242 {
			t.Errorf("not chowned to the profile's owner: %+v", r)
		}
		for _, d := range []string{dir, filepath.Join(root, "home", "alice", "Documents")} {
			var st unix.Stat_t
			if err := unix.Lstat(d, &st); err != nil || st.Uid != 4242 {
				t.Errorf("%s not owned by the profile's owner: %v", d, err)
			}
		}
	}
}

// A folder created for an absolute path takes the owner of the folder it is created in.
func TestCreatedFolderInheritsOwner(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "srv/share")
	cfg := on()
	cfg.Files = []api.DecoyFile{{OS: api.DecoyOSLinux, Path: "/srv/share/new/keys.txt"}}
	s, _, _ := testSensor(t, "linux", root, t.TempDir(), cfg)
	s.checkOnce()
	newDir := filepath.Join(root, "srv", "share", "new")
	var parent, made unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, "srv", "share"), &parent); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lstat(newDir, &made); err != nil || made.Mode&0o777 != 0o700 || made.Uid != parent.Uid {
		t.Fatalf("created folder: mode %o uid %d (parent %d) %v", made.Mode&0o777, made.Uid, parent.Uid, err)
	}
	if r := s.byPath[filepath.Join(newDir, "keys.txt")]; r == nil || !r.CreatedDir {
		t.Fatalf("record %+v", r)
	}
}
