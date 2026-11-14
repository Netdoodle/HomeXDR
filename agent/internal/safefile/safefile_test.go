package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	os.WriteFile(small, []byte("hello"), 0o600)
	if b, err := Read(small, 16); err != nil || string(b) != "hello" {
		t.Fatalf("small file: %q, %v", b, err)
	}
	if _, err := Read(small, 5); err != nil {
		t.Fatalf("a file of exactly the limit: %v", err)
	}
	big := filepath.Join(dir, "big")
	os.WriteFile(big, []byte(strings.Repeat("x", 100)), 0o600)
	if _, err := Read(big, 99); err == nil {
		t.Fatal("read a file over the limit")
	}
	if _, err := Read(dir, 16); err == nil {
		t.Fatal("read a directory")
	}
	if runtime.GOOS != "windows" {
		// An endless device behind a link must not be read.
		link := filepath.Join(dir, "zero")
		if err := os.Symlink("/dev/zero", link); err == nil {
			if _, err := Read(link, 16); err == nil {
				t.Fatal("read a device through a link")
			}
		}
	}
}
