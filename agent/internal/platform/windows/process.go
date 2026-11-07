//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// maxHashBytes caps executable hashing (the same limit as the Linux sensor).
const maxHashBytes = 128 << 20

// policyCheckInterval is how often the sensor re-reads the audit policy and checks
// whether Sysmon appeared or went away.
const policyCheckInterval = time.Minute

// processSource is where process events come from.
type processSource int

const (
	sourceSysmon processSource = iota + 1
	sourceSecurity
)

func (s processSource) String() string {
	if s == sourceSysmon {
		return "sysmon"
	}
	return "security"
}

// processSensor reports process start and exit from the Windows Event Log. Sources,
// best first: Sysmon (Microsoft-Windows-Sysmon/Operational, events 1 and 5; standalone
// Sysmon or the Windows Sysmon feature), then the Security log (4688 and 4689), which
// needs "Audit Process Creation" and, for command lines, "Include command line in
// process creation events". The sensor reads the audit policy but never changes it.
type processSensor struct {
	sensorState
	env platform.Env
	cfg api.ProcessSensorConfig

	// sawCmdLine is set once a 4688 record with a command line arrives, which proves
	// the policy is on even if it could not be read.
	sawCmdLine atomic.Bool
}

func newProcessSensor(cfg api.ProcessSensorConfig, env platform.Env) *processSensor {
	return &processSensor{sensorState: sensorState{name: "process"}, env: env, cfg: cfg}
}

// Name returns "process".
func (s *processSensor) Name() string { return "process" }

// Run streams process events until ctx is cancelled. It returns an error only when no
// source can be read (for example, the agent is not running as SYSTEM or an
// administrator).
func (s *processSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(event.ModuleEventLog, api.SensorRunning, "")
	pe := newPECache()
	m := newProcMapper(s.env, newWinProcs(), pe.lookup)
	n, err := m.loadSnapshot()
	if err != nil {
		s.env.Log.Warn("process sensor: process snapshot incomplete", "err", err)
	}
	s.env.Log.Debug("process sensor: loaded running processes", "count", n)

	var h *hasher
	if s.cfg.HashExecutables {
		h = newHasher(2)
		defer h.stop()
	}
	for {
		sub, src, fb, err := s.open()
		if err != nil {
			s.set(event.ModuleEventLog, api.SensorFailed, err.Error())
			return err
		}
		inner, cancel := context.WithCancel(ctx)
		go s.watch(inner, cancel, src, fb)
		s.env.Log.Info("process sensor running", "impl", event.ModuleEventLog, "source", src.String(), "resumed", sub.resumed)
		err = sub.run(inner, func(r *Record) {
			if src == sourceSecurity && r.EventID == 4688 && r.Data["CommandLine"] != "" {
				s.sawCmdLine.Store(true)
			}
			if ev := m.handle(r); ev != nil {
				s.emit(ev, h, out)
			}
		})
		cancel()
		sub.Close()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		s.env.Log.Info("process sensor: switching source", "from", src.String())
	}
}

// fallback describes why the Security log is in use.
type fallback struct {
	// note explains it in the status message; empty when Sysmon is simply not
	// installed.
	note string
	// sysmonBroken is true when the Sysmon log exists but could not be subscribed to;
	// the sensor then does not switch back on its own, to avoid retrying every minute.
	sysmonBroken bool
}

// open subscribes to the best available source.
func (s *processSensor) open() (*subscription, processSource, fallback, error) {
	var fb fallback
	ok, err := channelEnabled(sysmonChannel)
	switch {
	case err == nil && ok:
		sub, err := subscribe(subscribeOptions{Channel: sysmonChannel, Query: sysmonQuery,
			BookmarkFile: bookmarkFile(s.env.DataDir, "process", sysmonChannel), Log: s.env.Log})
		if err == nil {
			// The other source's position is stale now; dropping it keeps a later
			// fallback from replaying the whole Security log.
			s.removeBookmark(securityChannel)
			s.set(event.ModuleEventLog, api.SensorRunning, "")
			return sub, sourceSysmon, fb, nil
		}
		fb = fallback{note: "the Sysmon log cannot be read (" + err.Error() + ")", sysmonBroken: true}
		s.env.Log.Warn("process sensor: cannot read the Sysmon log, using the Security log", "err", err)
	case err == nil:
		fb.note = "the Sysmon log is disabled"
	case !errors.Is(err, errChannelNotFound):
		fb = fallback{note: "the Sysmon log cannot be read (" + err.Error() + ")", sysmonBroken: true}
	}
	sub, err := subscribe(subscribeOptions{Channel: securityChannel, Query: securityQuery,
		BookmarkFile: bookmarkFile(s.env.DataDir, "process", securityChannel), Log: s.env.Log})
	if err != nil {
		if errors.Is(err, errAccessDenied) {
			err = fmt.Errorf("%w: reading the Security log needs SYSTEM or administrator rights (the agent service runs as SYSTEM)", err)
		}
		if fb.note != "" {
			err = fmt.Errorf("%s; %w", fb.note, err)
		}
		return nil, 0, fb, err
	}
	s.removeBookmark(sysmonChannel)
	s.updateSecurityStatus(fb.note)
	return sub, sourceSecurity, fb, nil
}

func (s *processSensor) removeBookmark(channel string) {
	if f := bookmarkFile(s.env.DataDir, "process", channel); f != "" {
		_ = os.Remove(f)
	}
}

// watch re-checks the audit policy (Security source) and whether Sysmon appeared or
// disappeared; a change of source cancels the current subscription.
func (s *processSensor) watch(ctx context.Context, cancel context.CancelFunc, src processSource, fb fallback) {
	t := time.NewTicker(policyCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ok, err := channelEnabled(sysmonChannel)
		sysmon := err == nil && ok
		switch {
		case src == sourceSecurity && sysmon && !fb.sysmonBroken:
			s.env.Log.Info("process sensor: Sysmon is now available")
			cancel()
			return
		case src == sourceSysmon && !sysmon:
			s.env.Log.Warn("process sensor: the Sysmon log is gone", "err", err)
			cancel()
			return
		case src == sourceSecurity:
			s.updateSecurityStatus(fb.note)
		}
	}
}

func (s *processSensor) updateSecurityStatus(note string) {
	pol, err := QueryProcessAudit()
	state, msg := securityStatus(pol, err, s.sawCmdLine.Load())
	if note != "" {
		if msg == "" {
			msg = note + "; using the Security log"
		} else {
			msg = note + "; " + msg
		}
	}
	s.set(event.ModuleEventLog, state, msg)
}

// securityStatus is the sensor state when process events come from the Security log.
func securityStatus(pol ProcessAudit, polErr error, sawCmdLine bool) (state, msg string) {
	const install = ", or install Sysmon"
	exits := ""
	if polErr == nil && pol.Termination&AuditSuccess == 0 {
		exits = ` ("Audit Process Termination" is off too, so process exits are not reported)`
	}
	switch {
	case polErr != nil && sawCmdLine:
		return api.SensorRunning, ""
	case polErr != nil:
		return api.SensorDegraded, "process events come from the Security log, but the audit policy could not be read (" +
			polErr.Error() + `): check that "Audit Process Creation" is on and "Include command line in process creation events" is enabled` + install
	case pol.Creation&AuditSuccess == 0:
		return api.SensorDegraded, `Sysmon is not installed and "Audit Process Creation" is off, so Windows logs no process starts: ` +
			`turn on "Audit Process Creation" (success) and "Include command line in process creation events"` + install + exits
	case !pol.CommandLine && !sawCmdLine:
		return api.SensorDegraded, `Sysmon is not installed and process starts in the Security log have no command lines: ` +
			`enable "Include command line in process creation events" (registry value ProcessCreationIncludeCmdLine_Enabled = 1)` + install + exits
	}
	return api.SensorRunning, ""
}

// emit sends an event, hashing the executable of a start event first when configured
// and the source gave no SHA-256.
func (s *processSensor) emit(ev *event.Event, h *hasher, out platform.Emitter) {
	p := ev.Process
	if h == nil || ev.Event.Action != "exec" || p == nil || !filepath.IsAbs(p.Executable) || (p.Hash != nil && p.Hash.SHA256 != "") {
		out.Emit(ev)
		return
	}
	h.submit(ev, out)
}

// hasher computes executable SHA-256s off the event-reading path, with a cache, like
// the Linux sensor.
type hasher struct {
	cache    *lru[fileKey, string]
	q        chan hashJob
	wg       sync.WaitGroup
	stopping atomic.Bool
}

type hashJob struct {
	f   *os.File
	key fileKey
	ev  *event.Event
	out platform.Emitter
}

func newHasher(workers int) *hasher {
	h := &hasher{cache: newLRU[fileKey, string](4096), q: make(chan hashJob, 512)}
	for range workers {
		h.wg.Add(1)
		go h.work()
	}
	return h
}

func (h *hasher) work() {
	defer h.wg.Done()
	for j := range h.q {
		if !h.stopping.Load() {
			if sum, err := fsutil.SHA256Open(j.f, maxHashBytes); err == nil {
				h.cache.put(j.key, sum)
				setSHA256(j.ev, sum)
			}
		}
		j.f.Close()
		j.out.Emit(j.ev)
	}
}

// submit adds the hash from the cache, or queues the event for a worker. The file is
// opened now, so the hash is of what ran even if the file is replaced meanwhile. When
// the workers are saturated the event goes out without a hash rather than blocking.
func (h *hasher) submit(ev *event.Event, out platform.Emitter) {
	path := ev.Process.Executable
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		out.Emit(ev)
		return
	}
	key := fileKeyOf(path, fi)
	if sum, ok := h.cache.get(key); ok {
		setSHA256(ev, sum)
		out.Emit(ev)
		return
	}
	if fi.Size() > maxHashBytes {
		out.Emit(ev)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		out.Emit(ev)
		return
	}
	select {
	case h.q <- hashJob{f: f, key: key, ev: ev, out: out}:
	default:
		f.Close()
		out.Emit(ev)
	}
}

// stop sends queued events without hashing them and waits for the workers.
func (h *hasher) stop() {
	h.stopping.Store(true)
	close(h.q)
	h.wg.Wait()
}

func setSHA256(ev *event.Event, sum string) {
	if ev.Process.Hash == nil {
		ev.Process.Hash = &event.Hash{}
	}
	ev.Process.Hash.SHA256 = sum
}
