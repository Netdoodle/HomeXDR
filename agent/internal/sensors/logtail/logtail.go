// Package logtail forwards lines of the log files listed in the central config
// (AgentConfig.Logs) as events (event.module=logfile). Files are matched by glob and
// followed across rotation; read offsets are kept in the data dir.
package logtail

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/agent/internal/tail"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// Sensor implements platform.Sensor.
type Sensor struct {
	sources []api.LogSource
	offsets string
	log     *slog.Logger

	mu     sync.Mutex
	events uint64
}

// New returns the log tailing sensor; offsets are stored under dataDir.
func New(sources []api.LogSource, dataDir string, log *slog.Logger) *Sensor {
	return &Sensor{sources: sources, offsets: filepath.Join(dataDir, "logtail", "offsets.json"), log: log}
}

// Name returns "logs".
func (s *Sensor) Name() string { return "logs" }

// Status reports health.
func (s *Sensor) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return api.SensorStatus{Name: "logs", Impl: event.ModuleLogfile, State: api.SensorRunning, Events: s.events}
}

// Run follows all sources until ctx ends.
func (s *Sensor) Run(ctx context.Context, out platform.Emitter) error {
	if len(s.sources) == 0 {
		<-ctx.Done()
		return nil
	}
	offsets := tail.LoadOffsets(s.offsets)
	var wg sync.WaitGroup
	for _, src := range s.sources {
		if strings.TrimSpace(src.Path) == "" {
			continue
		}
		wg.Add(1)
		go func(src api.LogSource) {
			defer wg.Done()
			t := &tail.Tailer{Patterns: []string{src.Path}, Offsets: offsets, Log: s.log}
			err := t.Run(ctx, func(path string, line []byte) {
				out.Emit(Parse(src, path, line))
				s.mu.Lock()
				s.events++
				s.mu.Unlock()
			})
			if err != nil {
				s.log.Warn("log source failed", "path", src.Path, "err", err)
			}
		}(src)
	}
	wg.Wait()
	return offsets.Save()
}

// Parse turns one line into an event according to the source format.
func Parse(src api.LogSource, path string, line []byte) *event.Event {
	ds := src.Dataset
	if ds == "" {
		ds = "logfile"
	}
	e := &event.Event{
		Timestamp: time.Now().UTC(),
		Event:     event.Meta{Kind: event.KindEvent, Module: event.ModuleLogfile, Dataset: ds},
		Log:       &event.Log{FilePath: path},
	}
	text := string(line)
	switch strings.ToLower(src.Format) {
	case "json":
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			e.Data = m
			for _, k := range []string{"message", "msg", "MESSAGE", "log"} {
				if v, ok := m[k].(string); ok {
					e.Message = v
					break
				}
			}
			for _, k := range []string{"level", "lvl", "severity"} {
				if v, ok := m[k].(string); ok {
					e.Log.Level = strings.ToLower(v)
					break
				}
			}
			if e.Message == "" {
				e.Message = text
			}
			return e
		}
		e.Message = text
	case "syslog":
		if p, ok := ParseSyslog(text, time.Now()); ok {
			e.Message = p.Message
			e.Log.AppName = p.App
			if !p.Time.IsZero() {
				e.Timestamp = p.Time.UTC()
			}
			if p.PID != 0 {
				e.Process = &event.Process{PID: p.PID, Name: p.App}
			}
			e.Event.Original = text
			return e
		}
		e.Message = text
	default:
		e.Message = text
	}
	return e
}

// SyslogLine is a parsed syslog file line.
type SyslogLine struct {
	Time    time.Time
	Host    string
	App     string
	PID     int64
	Message string
}

var (
	// "Oct 19 12:34:56 host app[123]: message" (RFC 3164 style, as written by rsyslog's
	// traditional file format).
	reBSD = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^\s\[:]+)(?:\[(\d+)\])?: ?(.*)$`)
	// "2025-10-19T12:34:56.123456+00:00 host app[123]: message" (rsyslog's high-precision
	// default on newer distributions).
	reISO = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (\S+) ([^\s\[:]+)(?:\[(\d+)\])?: ?(.*)$`)
)

// ParseSyslog parses a syslog-formatted file line. now supplies the year for RFC 3164
// timestamps, which have none.
func ParseSyslog(s string, now time.Time) (SyslogLine, bool) {
	if m := reISO.FindStringSubmatch(s); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			t, _ = time.Parse("2006-01-02T15:04:05.999999999-0700", m[1])
		}
		pid, _ := strconv.ParseInt(m[4], 10, 64)
		return SyslogLine{Time: t, Host: m[2], App: m[3], PID: pid, Message: m[5]}, true
	}
	if m := reBSD.FindStringSubmatch(s); m != nil {
		t, err := time.ParseInLocation("Jan _2 15:04:05", m[1], time.Local)
		if err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			// A December line read in January belongs to the previous year.
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
		}
		pid, _ := strconv.ParseInt(m[4], 10, 64)
		return SyslogLine{Time: t, Host: m[2], App: m[3], PID: pid, Message: m[5]}, true
	}
	return SyslogLine{}, false
}
