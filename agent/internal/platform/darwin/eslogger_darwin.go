//go:build darwin

package darwin

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const esloggerPath = "/usr/bin/eslogger"

var (
	esEventsOnce sync.Once
	esEvents     map[string]bool
	esEventsErr  error
)

// esSupported returns the event names this macOS's eslogger knows (`--list-events`);
// newer events (sudo, od_*, tcc_modify, ...) only exist on newer releases.
func esSupported() (map[string]bool, error) {
	esEventsOnce.Do(func() {
		if _, err := os.Stat(esloggerPath); err != nil {
			esEventsErr = errors.New("eslogger not found (it needs macOS 13 or later)")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, esloggerPath, "--list-events").Output()
		if err != nil {
			esEventsErr = fmt.Errorf("eslogger --list-events: %w", err)
			return
		}
		esEvents = map[string]bool{}
		for _, f := range strings.Fields(string(out)) {
			esEvents[f] = true
		}
	})
	return esEvents, esEventsErr
}

// lockedBuffer collects up to 8 KiB of a child's stderr.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := 8192 - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(l.b.String())
}

// runESLogger runs eslogger for the wanted events this macOS supports and calls handle
// for each line until ctx is cancelled. It returns an errUnavailable when eslogger is
// missing or exits before producing anything (not root, no Full Disk Access).
func runESLogger(ctx context.Context, want []string, handle func(line []byte)) error {
	sup, err := esSupported()
	if err != nil {
		return unavailable(err)
	}
	var events []string
	for _, e := range want {
		if sup[e] {
			events = append(events, e)
		}
	}
	if len(events) == 0 {
		return unavailable(errors.New("eslogger supports none of the needed events"))
	}
	cmd := exec.CommandContext(ctx, esloggerPath, events...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return unavailable(fmt.Errorf("start eslogger: %w", err))
	}
	r := bufio.NewReaderSize(stdout, 1<<20)
	got := false
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			got = true
			handle(line)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				_ = cmd.Process.Kill()
			}
			break
		}
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	msg := stderr.String()
	if !got {
		return unavailable(fmt.Errorf("eslogger exited (%v): %s%s", werr, msg, esHint(msg)))
	}
	return fmt.Errorf("eslogger exited (%v): %s", werr, msg)
}

// esHint explains the usual reasons eslogger refuses to start.
func esHint(msg string) string {
	m := strings.ToUpper(msg)
	switch {
	case strings.Contains(m, "NOT_PERMITTED") || strings.Contains(m, "TCC") || strings.Contains(m, "FULL DISK"):
		exe, _ := os.Executable()
		return fmt.Sprintf(" (grant Full Disk Access to %s in System Settings > Privacy & Security > Full Disk Access, then restart the agent)", exe)
	case strings.Contains(m, "NOT_PRIVILEGED"):
		return " (eslogger must run as root)"
	}
	return ""
}
