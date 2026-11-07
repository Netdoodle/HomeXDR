//go:build windows

package windows

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestHandlerStopsOnRequest(t *testing.T) {
	ran := make(chan struct{})
	h := &handler{fn: func(ctx context.Context) error {
		close(ran)
		<-ctx.Done()
		return nil
	}}
	req := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 10)
	type result struct {
		ssec bool
		code uint32
	}
	done := make(chan result, 1)
	go func() {
		ssec, code := h.Execute(nil, req, status)
		done <- result{ssec, code}
	}()
	<-ran
	req <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case r := <-done:
		if r.ssec || r.code != 0 || h.err != nil {
			t.Fatalf("stop: got ssec=%v code=%d err=%v, want a clean stop", r.ssec, r.code, h.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after Stop")
	}
	var states []svc.State
	for len(status) > 0 {
		states = append(states, (<-status).State)
	}
	want := []svc.State{svc.StartPending, svc.Running, svc.StopPending}
	if len(states) != len(want) {
		t.Fatalf("states = %v, want %v", states, want)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("states = %v, want %v", states, want)
		}
	}
}

func TestHandlerExitsWithErrorWhenAgentStops(t *testing.T) {
	boom := errors.New("agent updated; restart required")
	h := &handler{fn: func(context.Context) error { return boom }}
	ssec, code := h.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 10))
	if !ssec || code == 0 {
		t.Fatalf("got ssec=%v code=%d, want a service-specific error so the SCM restarts it", ssec, code)
	}
	if !errors.Is(h.err, boom) {
		t.Fatalf("err = %v", h.err)
	}
}

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	r := &rotatingFile{path: path, max: 100}
	line := []byte(strings.Repeat("x", 39) + "\n")
	for i := 0; i < 6; i++ {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.f.Close()
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) > 100 || len(old) > 100 || len(cur)+len(old) < 160 {
		t.Fatalf("current %d bytes, rotated %d bytes", len(cur), len(old))
	}
	// Reopening a full file rotates it before writing.
	r2 := &rotatingFile{path: path, max: int64(len(cur))}
	if _, err := r2.Write(line); err != nil {
		t.Fatal(err)
	}
	_ = r2.f.Close()
	if b, _ := os.ReadFile(path); len(b) != len(line) {
		t.Fatalf("after reopen: %d bytes, want %d", len(b), len(line))
	}
}

// TestProtectPath checks that the data dir ends up readable only by SYSTEM and
// Administrators, with nothing inherited from the parent, and that a file that already
// existed inside picks up the same ACEs. It runs unelevated: the owner keeps the right to
// read and rewrite the DACL, which the cleanup uses to give access back.
func TestProtectPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(child, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreOwnerAccess(t, dir) })
	if err := (&Platform{}).ProtectPath(dir); err != nil {
		t.Fatal(err)
	}
	// Windows adds the auto-inherited flag ("D:PAI"); what matters is P and the ACEs.
	if got := daclSDDL(t, dir); !strings.HasPrefix(got, "D:P") || !strings.HasSuffix(got, "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") || strings.Count(got, "(") != 2 {
		t.Errorf("dir DACL = %s, want %s", got, dirSDDL)
	}
	got := daclSDDL(t, child)
	for _, ace := range []string{"(A;ID;FA;;;SY)", "(A;ID;FA;;;BA)"} {
		if !strings.Contains(got, ace) {
			t.Errorf("child DACL = %s, missing %s", got, ace)
		}
	}
	if strings.Count(got, "(") != 2 {
		t.Errorf("child DACL = %s, want only the SYSTEM and Administrators entries", got)
	}
}

func daclSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func restoreOwnerAccess(t *testing.T, dir string) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Log(err)
		return
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;" + u.User.Sid.String() + ")")
	if err != nil {
		t.Log(err)
		return
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Log("restore access:", err)
	}
}
