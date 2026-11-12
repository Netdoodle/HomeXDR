//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/authparse"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// authEvents are the eslogger events of the auth sensor. Those a release does not have
// (sudo, su and the od_* account events arrived in macOS 14) are left out at start.
var authEvents = []string{
	"openssh_login", "openssh_logout", "login_login", "login_logout",
	"lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock",
	"screensharing_attach", "screensharing_detach", "authentication", "sudo", "su",
	"od_create_user", "od_delete_user", "od_disable_user", "od_enable_user", "od_modify_password",
	"od_create_group", "od_delete_group", "od_group_add", "od_group_remove",
}

// unifiedLogPredicate selects the sshd and sudo messages the fallback parses.
const unifiedLogPredicate = `process == "sshd" OR process == "sshd-session" OR process == "sudo" OR process == "su"`

// authSensor reports logons, screen locks, sudo/su and account changes: Endpoint
// Security through eslogger, else sshd and sudo messages from the unified log.
type authSensor struct {
	sensorState
	env platform.Env
}

func newAuthSensor(env platform.Env) *authSensor {
	return &authSensor{sensorState: sensorState{name: "auth"}, env: env}
}

// Run tries eslogger, then `log stream`.
func (s *authSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(event.ModuleESLogger, api.SensorRunning, "")
	m := newESMapper(s.env.EntityID, nil, users.name, int64(os.Getpid()))
	err := runESLogger(ctx, authEvents, func(line []byte) {
		msg, name, raw, err := parseESLine(line)
		if err != nil {
			return
		}
		if ev := m.mapAuth(msg, name, raw); ev != nil {
			out.Emit(ev)
		}
	})
	if err == nil || !isUnavailable(err) {
		return err
	}
	s.env.Log.Warn("auth sensor: eslogger unavailable, reading sshd and sudo from the unified log", "err", err)
	s.set(event.ModuleUnifiedLog, api.SensorDegraded, "eslogger unavailable: "+err.Error())
	return s.runUnifiedLog(ctx, out)
}

func (s *authSensor) runUnifiedLog(ctx context.Context, out platform.Emitter) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", unifiedLogPredicate)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start log stream: %w", err)
	}
	r := bufio.NewReaderSize(stdout, 256<<10)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if m, ok := parseUnifiedLogLine(line); ok {
				if e := authparse.Parse(m); e != nil {
					e.Event.Module, e.Event.Dataset = event.ModuleUnifiedLog, "macos.auth"
					out.Emit(e)
				}
			}
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
	return fmt.Errorf("log stream exited (%v): %s", werr, stderr.String())
}
