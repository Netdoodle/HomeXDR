//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/agent/internal/sensors/logtail"
	"github.com/Doodlebug12/homexdr/agent/internal/tail"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// authLogFiles are the classic syslog destinations for the auth facilities.
var authLogFiles = []string{"/var/log/auth.log", "/var/log/secure"}

// authSensor reports logins (sshd), privilege changes (sudo, su) and account changes
// (useradd, usermod, ...) from journald, or from /var/log/auth.log or /var/log/secure.
type authSensor struct {
	sensorState
	env platform.Env
}

func newAuthSensor(env platform.Env) *authSensor {
	return &authSensor{sensorState: sensorState{name: "auth"}, env: env}
}

// Name returns "auth".
func (s *authSensor) Name() string { return "auth" }

func journalAvailable() (string, bool) {
	p, err := exec.LookPath("journalctl")
	if err != nil {
		return "", false
	}
	if _, err := os.Stat("/run/systemd/journal"); err != nil {
		return "", false
	}
	return p, true
}

// Run follows journald when it is running, else the auth log file.
func (s *authSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	if jc, ok := journalAvailable(); ok {
		s.set(event.ModuleAuthLog, api.SensorRunning, "")
		err := s.runJournal(ctx, jc, out)
		if ctx.Err() != nil {
			return nil
		}
		s.env.Log.Warn("auth sensor: journalctl failed, trying log files", "err", err)
	}
	var files []string
	for _, f := range authLogFiles {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return errors.New("no auth log source: journald is not running and neither /var/log/auth.log nor /var/log/secure exists")
	}
	s.set(event.ModuleAuthLog, api.SensorRunning, "")
	s.env.Log.Info("auth sensor running", "source", files)
	t := &tail.Tailer{
		Patterns: files,
		Offsets:  tail.LoadOffsets(filepath.Join(s.env.DataDir, "auth", "offsets.json")),
		Log:      s.env.Log,
	}
	return t.Run(ctx, func(_ string, line []byte) {
		p, ok := logtail.ParseSyslog(string(line), time.Now())
		if !ok {
			return
		}
		ts := p.Time
		if ts.IsZero() {
			ts = time.Now()
		}
		if e := parseAuth(authMsg{App: p.App, PID: p.PID, Msg: p.Message, Time: ts.UTC()}); e != nil {
			out.Emit(e)
		}
	})
}

// journalEntry is the subset of `journalctl -o json` fields we read.
type journalEntry struct {
	Message    json.RawMessage `json:"MESSAGE"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	PID        string          `json:"_PID"`
	UID        string          `json:"_UID"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
	Cursor     string          `json:"__CURSOR"`
}

// journalString decodes MESSAGE, which journald exports as a JSON string, or as an array
// of byte values when it is not valid UTF-8.
func journalString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return string(b)
	}
	return ""
}

func parseJournalLine(line []byte) (authMsg, string, bool) {
	var j journalEntry
	if json.Unmarshal(line, &j) != nil {
		return authMsg{}, "", false
	}
	m := authMsg{App: j.Identifier, Msg: journalString(j.Message)}
	m.PID, _ = strconv.ParseInt(j.PID, 10, 64)
	if us, err := strconv.ParseInt(j.Realtime, 10, 64); err == nil {
		m.Time = time.UnixMicro(us).UTC()
	}
	if j.UID != "" {
		if uid, err := strconv.ParseUint(j.UID, 10, 32); err == nil {
			m.Actor = users.name(uint32(uid))
		}
	}
	return m, j.Cursor, true
}

func (s *authSensor) runJournal(ctx context.Context, journalctl string, out platform.Emitter) error {
	cursorFile := filepath.Join(s.env.DataDir, "auth", "journal.cursor")
	_ = os.MkdirAll(filepath.Dir(cursorFile), 0o700)
	for attempt := 0; attempt < 2; attempt++ {
		cursor := ""
		if b, err := os.ReadFile(cursorFile); err == nil {
			cursor = strings.TrimSpace(string(b))
		}
		// SYSLOG_FACILITY 4 is auth and 10 is authpriv: sshd, sudo, su, PAM and the
		// shadow tools (useradd, ...) log there. Matches on one field are ORed.
		args := []string{"--follow", "--output=json", "--no-pager", "--quiet", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"}
		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		} else {
			args = append(args, "--lines=0")
		}
		started := time.Now()
		err := s.follow(ctx, journalctl, args, cursorFile, out)
		if ctx.Err() != nil {
			return nil
		}
		if cursor != "" && time.Since(started) < 5*time.Second {
			// Most likely the saved cursor is no longer in the journal: start fresh.
			os.Remove(cursorFile)
			continue
		}
		return err
	}
	return errors.New("journalctl exited")
}

func (s *authSensor) follow(ctx context.Context, journalctl string, args []string, cursorFile string, out platform.Emitter) error {
	cmd := exec.CommandContext(ctx, journalctl, args...)
	cmd.Stderr = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.env.Log.Info("auth sensor running", "source", "journald")
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var cursor string
	lastSave := time.Now()
	save := func() {
		if cursor != "" {
			_ = os.WriteFile(cursorFile, []byte(cursor+"\n"), 0o600)
		}
	}
	defer save()
	for sc.Scan() {
		m, c, ok := parseJournalLine(sc.Bytes())
		if !ok {
			continue
		}
		cursor = c
		if e := parseAuth(m); e != nil {
			out.Emit(e)
		}
		if time.Since(lastSave) > 5*time.Second {
			save()
			lastSave = time.Now()
		}
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if werr != nil {
		return fmt.Errorf("journalctl: %w", werr)
	}
	return errors.New("journalctl stopped")
}
