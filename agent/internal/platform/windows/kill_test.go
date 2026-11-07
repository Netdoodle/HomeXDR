//go:build windows

package windows

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"golang.org/x/sys/windows"
)

func TestKillProcessTree(t *testing.T) {
	env := testEnv(t)
	r := responder{env: env}
	// cmd.exe runs ping.exe for a minute: a parent and a child.
	cmd := exec.Command("cmd.exe", "/c", "ping -n 60 127.0.0.1 >NUL")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pid := int64(cmd.Process.Pid)
	var child int64
	for deadline := time.Now().Add(10 * time.Second); child == 0 && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		pairs, _ := newWinProcs().list()
		for _, p := range pairs {
			if p.PPID == pid && strings.EqualFold(p.Name, "ping.exe") {
				child = p.PID
			}
		}
	}
	if child == 0 {
		t.Fatal("ping.exe child did not start")
	}
	created, err := processCreated(pid)
	if err != nil {
		t.Fatal(err)
	}
	// A stale entity ID (PID reused) kills nothing.
	if _, err := r.KillProcess(context.Background(), api.KillParams{PID: pid, EntityID: "not-this-one", Tree: true}); err == nil ||
		!strings.Contains(err.Error(), "entity ID mismatch") {
		t.Fatalf("mismatched entity: err = %v", err)
	}
	res, err := r.KillProcess(context.Background(), api.KillParams{PID: pid, EntityID: env.EntityID(pid, filetimeKey(created)), Tree: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Killed, pid) || !slices.Contains(res.Killed, child) {
		t.Fatalf("killed %v, want %d and %d", res.Killed, pid, child)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cmd.exe still running")
	}
	// Termination is asynchronous: the process object lingers briefly after it.
	for deadline := time.Now().Add(5 * time.Second); stillActive(child); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("ping.exe still running")
		}
	}
}

func stillActive(pid int64) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259
}

func TestKillRefusesCritical(t *testing.T) {
	r := responder{env: testEnv(t)}
	pairs, err := newWinProcs().list()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pairs {
		if strings.EqualFold(p.Name, "services.exe") {
			if _, err := r.KillProcess(context.Background(), api.KillParams{PID: p.PID}); err == nil || !strings.Contains(err.Error(), "refusing") {
				t.Fatalf("services.exe: err = %v", err)
			}
			return
		}
	}
	t.Skip("services.exe not found")
}
