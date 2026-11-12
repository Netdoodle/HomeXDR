//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// launchdService runs the agent as a launchd daemon.
type launchdService struct{}

func launchctl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Install writes the job definition and loads it into the system domain, which starts
// the agent.
func (launchdService) Install(exe string) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the service requires root (sudo)")
	}
	if err := os.MkdirAll(serviceLogDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(servicePlist, []byte(launchdPlist(exe)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(newsyslogConf, []byte(newsyslogLine), 0o644); err != nil {
		// Rotation is a convenience; the agent works without it.
		fmt.Fprintf(os.Stderr, "homexdr: cannot install log rotation (%v)\n", err)
	}
	// Reinstalling: unload the old definition first (an error just means it was not loaded).
	_, _ = launchctl("bootout", "system/"+serviceLabel)
	_, _ = launchctl("enable", "system/"+serviceLabel)
	if _, err := launchctl("bootstrap", "system", servicePlist); err != nil {
		return err
	}
	return nil
}

// Uninstall stops the job and removes its definition.
func (launchdService) Uninstall() error {
	if _, err := os.Stat(servicePlist); errors.Is(err, os.ErrNotExist) {
		return platform.ErrUnsupported // nothing installed
	}
	if os.Geteuid() != 0 {
		return errors.New("removing the service requires root (sudo)")
	}
	var errs []error
	if out, err := launchctl("bootout", "system/"+serviceLabel); err != nil && !strings.Contains(string(out), "No such process") &&
		!strings.Contains(string(out), "Could not find") {
		errs = append(errs, err)
	}
	if err := os.Remove(servicePlist); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	_ = os.Remove(newsyslogConf)
	return errors.Join(errs...)
}

// Status reports the job's state.
func (launchdService) Status() (string, error) {
	if _, err := os.Stat(servicePlist); err != nil {
		return "not installed", nil
	}
	out, err := launchctl("print", "system/"+serviceLabel)
	if err != nil {
		return "installed, not loaded", nil
	}
	if st := parseLaunchctlState(out); st != "" {
		return st, nil
	}
	return "loaded", nil
}

// RunAsService: launchd runs the agent as a plain foreground process that stops on
// SIGTERM, so there is nothing special to do.
func (launchdService) RunAsService(func(context.Context) error) (bool, error) { return false, nil }
