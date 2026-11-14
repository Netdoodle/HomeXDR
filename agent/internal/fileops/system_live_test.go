package fileops

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestLiveQuarantineSystemFiles asks quarantine for real operating-system files on this
// host, with the host's own list of system trees. Every request must be refused and the
// file must stay where it is. If the check were broken this would move a system file, so
// it needs HOMEXDR_LIVE_QUARANTINE=1; only run it on a test machine.
func TestLiveQuarantineSystemFiles(t *testing.T) {
	if os.Getenv("HOMEXDR_LIVE_QUARANTINE") != "1" {
		t.Skip("set HOMEXDR_LIVE_QUARANTINE=1 on a test machine")
	}
	s := NewStore(filepath.Join(t.TempDir(), "quarantine"))

	var targets []string
	allowedDir := ""
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			t.Fatal("SystemRoot is not set")
		}
		targets = []string{
			filepath.Join(root, "System32", "notepad.exe"),
			filepath.Join(root, "System32", "drivers", "etc", "hosts"),
			strings.ToUpper(filepath.Join(root, "System32", "notepad.exe")),
			strings.ReplaceAll(filepath.Join(root, "System32", "notepad.exe"), `\`, "/"),
			filepath.Join(root, "Temp", "..", "System32", "notepad.exe"),
		}
		allowedDir = filepath.Join(root, "Temp")
	case "darwin":
		targets = []string{"/bin/sh", "/usr/bin/true", "/etc/hosts", "/usr/local/../bin/ls"}
	default:
		targets = []string{"/bin/sh", "/usr/bin/env", "/etc/passwd", "/etc/cron.d/../passwd"}
	}

	refused := func(p string) {
		t.Helper()
		before, statErr := os.Stat(p)
		_, err := s.Quarantine(p)
		if err == nil || !strings.Contains(err.Error(), "operating-system file") {
			t.Errorf("%s: want an operating-system refusal, got %v", p, err)
		}
		if statErr == nil {
			if after, err := os.Stat(p); err != nil || after.Size() != before.Size() {
				t.Errorf("%s: the file changed (%v)", p, err)
			}
		}
	}
	for _, p := range targets {
		refused(p)
	}

	// A linked directory does not get around the check.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Dir(targets[0]), link); err != nil {
		t.Logf("no linked-directory check: %v", err)
	} else {
		refused(filepath.Join(link, filepath.Base(targets[0])))
	}

	// A remote or device path to the same file is refused too (for another reason).
	if runtime.GOOS == "windows" {
		for _, p := range []string{`\\?\` + targets[0], `\\localhost\C$\Windows\System32\notepad.exe`} {
			if _, err := s.Quarantine(p); err == nil {
				t.Errorf("%s was quarantined", p)
			}
		}
		if _, err := os.Stat(targets[0]); err != nil {
			t.Errorf("%s is gone: %v", targets[0], err)
		}
	}

	// The temp folder inside the system tree can still be cleaned up.
	if allowedDir != "" {
		drop := filepath.Join(allowedDir, "homexdr-live-quarantine.bin")
		if err := os.WriteFile(drop, []byte("harmless test file"), 0o644); err != nil {
			t.Fatalf("write %s: %v", drop, err)
		}
		defer os.Remove(drop)
		res, err := s.Quarantine(drop)
		if err != nil {
			t.Fatalf("%s: %v", drop, err)
		}
		if _, err := s.Restore(res.ID); err != nil {
			t.Errorf("restore %s: %v", drop, err)
		}
	}
}
