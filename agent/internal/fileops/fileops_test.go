package fileops

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestQuarantineRestore(t *testing.T) {
	work := t.TempDir()
	data := t.TempDir()
	p := filepath.Join(work, "evil.sh")
	content := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	s := NewStore(filepath.Join(data, "quarantine"), data)
	res, err := s.Quarantine(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.Size != int64(len(content)) || res.OriginalPath != p {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("original still present")
	}
	q := filepath.Join(data, "quarantine", res.ID, dataName)
	st, err := os.Stat(q)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0 {
		t.Errorf("quarantined file mode %o, want 0", st.Mode().Perm())
	}
	list, _ := s.List()
	if len(list) != 1 || list[0].ID != res.ID {
		t.Fatalf("list %+v", list)
	}

	// Restore refuses to overwrite.
	os.WriteFile(p, []byte("other"), 0o644)
	if _, err := s.Restore(res.ID); err == nil {
		t.Fatal("restore overwrote an existing file")
	}
	os.Remove(p)
	if _, err := s.Restore(res.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != string(content) {
		t.Fatal("content changed")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o755 {
			t.Errorf("restored mode %o", st.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(data, "quarantine", res.ID)); !os.IsNotExist(err) {
		t.Error("quarantine entry not removed")
	}
	if _, err := s.Restore(res.ID); err == nil {
		t.Error("restoring twice succeeded")
	}
}

func TestQuarantineRefusals(t *testing.T) {
	data := t.TempDir()
	work := t.TempDir()
	cfg := filepath.Join(work, "agent.json")
	os.WriteFile(cfg, []byte("{}"), 0o600)
	s := NewStore(filepath.Join(data, "quarantine"), data, cfg)
	inData := filepath.Join(data, "agent.key")
	os.WriteFile(inData, []byte("k"), 0o600)
	for name, p := range map[string]string{
		"data dir":  inData,
		"config":    cfg,
		"relative":  "relative/file",
		"directory": work,
		"missing":   filepath.Join(work, "nope"),
	} {
		if _, err := s.Quarantine(p); err == nil {
			t.Errorf("%s: quarantine succeeded", name)
		}
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(work, "t")
		os.WriteFile(target, []byte("t"), 0o644)
		link := filepath.Join(work, "l")
		if os.Symlink(target, link) == nil {
			if _, err := s.Quarantine(link); err == nil {
				t.Error("symlink quarantined")
			}
		}
	}
	if _, err := s.Restore("../../etc"); err == nil {
		t.Error("path traversal id accepted")
	}
}

func TestHashAndGet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("abc"), 0o644)
	h, err := Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	if h.MD5 != "900150983cd24fb0d6963f7d28e17f72" || h.SHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" ||
		h.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || h.Size != 3 {
		t.Fatalf("hash %+v", h)
	}
	f, n, err := Get(p, 2)
	if err == nil {
		f.Close()
		t.Fatal("max_bytes not enforced")
	}
	f, n, err = Get(p, 0)
	if err != nil || n != 3 {
		t.Fatalf("get: %v %d", err, n)
	}
	f.Close()
}
