//go:build windows

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

// shutdownCommand returns the program and arguments that schedule the action.
func shutdownCommand(shutdown bool, p api.HostPowerParams) (string, []string) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "shutdown.exe"), windowsShutdownArgv(shutdown, p.DelaySec, p.Message)
}

// execShutdown runs shutdown.exe and waits for Windows to accept the request.
func execShutdown(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 3 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return fmt.Errorf("shutdown.exe: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
