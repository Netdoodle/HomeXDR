//go:build !windows

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

// shutdownCommand returns the program and arguments that schedule the action.
func shutdownCommand(shutdown bool, p api.HostPowerParams) (string, []string) {
	argv := unixShutdownArgv(shutdown, p.DelaySec, p.Message)
	// On Linux -h may only halt (sysvinit, as on Unraid); -P always powers off.
	if shutdown && runtime.GOOS == "linux" {
		argv[0] = "-P"
	}
	return findShutdown(), argv
}

func findShutdown() string {
	if p, err := exec.LookPath("shutdown"); err == nil {
		return p
	}
	for _, p := range []string{"/sbin/shutdown", "/usr/sbin/shutdown", "/bin/shutdown", "/usr/bin/shutdown"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return "shutdown"
}

// execShutdown runs the command and waits for the OS to accept it. BSD shutdown (macOS)
// forks into the background and leaves the output pipe open, so waiting for the pipe
// is bounded.
func execShutdown(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 3 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return fmt.Errorf("shutdown: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
