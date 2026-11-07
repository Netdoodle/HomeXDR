//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	// channelRecheck is how often an unavailable channel (disabled, unreadable) is
	// tried again; a channel that is not installed at all is checked less often.
	channelRecheck = time.Minute
	missingRecheck = 5 * time.Minute
	// readRetryMax caps the backoff after a channel's subscription fails while reading.
	readRetryMax = time.Minute
)

// eventlogSensor forwards records from the Event Log channels in the central config
// (Settings → agent config → Windows Event Log). Each channel has its own subscription
// and bookmark, so a restart resumes where it stopped, and a channel that is missing or
// disabled does not hold up the others.
type eventlogSensor struct {
	sensorState
	env       platform.Env
	cfg       api.EventLogConfig
	processOn bool // the process sensor reports 4688/4689 and Sysmon 1/5

	chMu     sync.Mutex
	problems map[string]string // channel → why it is not being read ("" = reading)
}

func newEventLogSensor(cfg api.EventLogConfig, processOn bool, env platform.Env) *eventlogSensor {
	return &eventlogSensor{sensorState: sensorState{name: "eventlog"}, env: env, cfg: cfg, processOn: processOn}
}

// Name returns "eventlog".
func (s *eventlogSensor) Name() string { return "eventlog" }

// Run reads every configured channel until ctx is cancelled.
func (s *eventlogSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	chans := normalizeChannels(s.cfg.Channels)
	s.problems = make(map[string]string, len(chans))
	if len(chans) == 0 {
		s.set(event.ModuleEventLog, api.SensorRunning, "no channels configured")
		<-ctx.Done()
		return nil
	}
	s.set(event.ModuleEventLog, api.SensorRunning, "")
	var wg sync.WaitGroup
	for _, ch := range chans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runChannel(ctx, ch, out)
		}()
	}
	wg.Wait()
	return nil
}

func (s *eventlogSensor) runChannel(ctx context.Context, ch string, out platform.Emitter) {
	query := channelQuery(ch, s.processOn)
	bm := bookmarkFile(s.env.DataDir, "eventlog", ch)
	readRetry := 5 * time.Second
	for {
		problem, wait := "", channelRecheck
		enabled, err := channelEnabled(ch)
		switch {
		case errors.Is(err, errChannelNotFound):
			problem, wait = "not installed", missingRecheck
		case errors.Is(err, errAccessDenied):
			problem = "access denied (the agent service runs as SYSTEM)"
		case err != nil:
			problem = err.Error()
		case !enabled:
			problem = "disabled"
		default:
			sub, err := subscribe(subscribeOptions{Channel: ch, Query: query, BookmarkFile: bm, Log: s.env.Log})
			if err != nil {
				problem = err.Error()
				break
			}
			s.setProblem(ch, "")
			started := time.Now()
			err = sub.run(ctx, func(r *Record) { out.Emit(mapEventLogRecord(r)) })
			sub.Close()
			if ctx.Err() != nil {
				return
			}
			if time.Since(started) > readRetryMax {
				readRetry = 5 * time.Second
			}
			problem, wait = fmt.Sprintf("read failed: %v", err), readRetry
			readRetry = min(readRetry*2, readRetryMax)
			s.env.Log.Warn("eventlog sensor: channel read failed", "channel", ch, "err", err, "retry_in", wait)
		}
		s.setProblem(ch, problem)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// setProblem records a channel's state and recomputes the sensor status. Channels that
// are not installed (Sysmon on most PCs) only get a note; anything else that stops a
// listed channel from being read makes the sensor degraded.
func (s *eventlogSensor) setProblem(ch, problem string) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	if old, ok := s.problems[ch]; ok && old == problem {
		return
	}
	if problem != "" && problem != "not installed" {
		s.env.Log.Warn("eventlog sensor: channel not read", "channel", ch, "reason", problem)
	}
	s.problems[ch] = problem
	var notes, faults []string
	for c, p := range s.problems {
		switch p {
		case "":
		case "not installed":
			notes = append(notes, c)
		default:
			faults = append(faults, c+" ("+p+")")
		}
	}
	sort.Strings(notes)
	sort.Strings(faults)
	var msg []string
	state := api.SensorRunning
	if len(faults) > 0 {
		state = api.SensorDegraded
		msg = append(msg, "not read: "+strings.Join(faults, "; "))
	}
	if len(notes) > 0 {
		msg = append(msg, "not installed: "+strings.Join(notes, ", "))
	}
	s.set(event.ModuleEventLog, state, strings.Join(msg, ". "))
}

// normalizeChannels trims, drops empties and removes case-insensitive duplicates.
func normalizeChannels(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		k := strings.ToLower(c)
		if c == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

// channelQuery leaves out records another sensor already reports (process creation and
// exit, when the process sensor is on) and a few that flood their log with little
// detection value: Windows Filtering Platform connections (5156-5158, which the network
// sensor will cover), Credential Manager reads (5379, logged constantly on Windows 11)
// and PowerShell console startup notices.
func channelQuery(channel string, processOn bool) string {
	var skip []int
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "security":
		skip = []int{5156, 5157, 5158, 5379}
		if processOn {
			skip = append(skip, 4688, 4689)
		}
	case strings.ToLower(sysmonChannel):
		if processOn {
			skip = []int{1, 5}
		}
	case "microsoft-windows-powershell/operational":
		// Console startup notices, three per PowerShell session.
		skip = []int{40961, 40962, 53504}
	}
	if len(skip) == 0 {
		return "*"
	}
	parts := make([]string, len(skip))
	for i, id := range skip {
		parts[i] = fmt.Sprintf("EventID!=%d", id)
	}
	return "*[System[(" + strings.Join(parts, " and ") + ")]]"
}
