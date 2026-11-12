//go:build darwin

package darwin

import (
	"context"
	"os"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// processEvents are the eslogger events the process sensor subscribes to. Besides exec
// and exit it takes the low-volume security events that have no sensor of their own:
// launch item (persistence) changes, XProtect detections, Gatekeeper overrides, privacy
// permission (TCC) changes and configuration profiles.
var processEvents = []string{
	"exec", "exit",
	"btm_launch_item_add", "btm_launch_item_remove",
	"xp_malware_detected", "xp_malware_remediated",
	"gatekeeper_user_override", "tcc_modify", "profile_add", "profile_remove",
}

// processSensor reports process start and exit: Endpoint Security through eslogger
// (exec with argv and code signing, exit with status), else sysctl polling, which misses
// processes shorter than a second.
type processSensor struct {
	sensorState
	env    platform.Env
	cfg    api.ProcessSensorConfig
	hashes *lru[fileKey, string]
	hashQ  chan hashJob
}

type hashJob struct {
	f   *os.File
	key fileKey
	ev  *event.Event
	out platform.Emitter
}

func newProcessSensor(cfg api.ProcessSensorConfig, env platform.Env) *processSensor {
	return &processSensor{sensorState: sensorState{name: "process"}, env: env, cfg: cfg,
		hashes: newLRU[fileKey, string](4096)}
}

// Run tries eslogger, then polling.
func (s *processSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	if s.cfg.HashExecutables {
		s.startHashers(ctx, 2)
	}
	s.set(event.ModuleESLogger, api.SensorRunning, "")
	m := s.mapper()
	s.env.Log.Info("process sensor starting", "impl", "eslogger")
	err := runESLogger(ctx, processEvents, func(line []byte) {
		msg, name, raw, err := parseESLine(line)
		if err != nil {
			return
		}
		if ev := m.mapProcess(msg, name, raw); ev != nil {
			s.emit(ev, out)
		}
	})
	if err == nil || !isUnavailable(err) {
		return err
	}
	s.env.Log.Warn("process sensor: eslogger unavailable, polling the process table", "err", err)
	s.set(event.ModuleSysctl, api.SensorDegraded, "eslogger unavailable: "+err.Error())
	return s.runPoll(ctx, m, out)
}

// mapper builds the eslogger mapper with live parent lookups.
func (s *processSensor) mapper() *esMapper {
	m := newESMapper(s.env.EntityID, nil, users.name, int64(os.Getpid()))
	m.parent = func(ppid int64) *event.Process { return describe(s.env, m.procs, ppid) }
	return m
}

// describe reads a running process from the kernel, for parents and polling.
func describe(env platform.Env, cache *lru[string, procSummary], pid int64) *event.Process {
	k, err := procByPID(pid)
	if err != nil {
		return &event.Process{PID: pid}
	}
	p := &event.Process{PID: pid, EntityID: env.EntityID(pid, k.Start), Name: k.Comm}
	if s, ok := cache.get(p.EntityID); ok {
		p.Name, p.Executable, p.CommandLine = s.Name, s.Executable, s.CommandLine
		return p
	}
	if exe, args, err := procArgs(pid); err == nil {
		p.Executable, p.Args, p.CommandLine = exe, args, joinArgs(args)
		if exe != "" {
			p.Name = baseName(exe)
		}
	}
	cache.put(p.EntityID, procSummary{Name: p.Name, Executable: p.Executable, CommandLine: p.CommandLine})
	return p
}

func (s *processSensor) startHashers(ctx context.Context, n int) {
	s.hashQ = make(chan hashJob, 512)
	for range n {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-s.hashQ:
					if h, err := fsutil.SHA256Open(j.f, maxHashBytes); err == nil {
						s.hashes.put(j.key, h)
						j.ev.Process.Hash = &event.Hash{SHA256: h}
					}
					j.f.Close()
					j.out.Emit(j.ev)
				}
			}
		}()
	}
}

// emit sends an event, hashing a started process's executable first when configured.
func (s *processSensor) emit(ev *event.Event, out platform.Emitter) {
	if s.hashQ == nil || ev.Event.Action != "exec" || ev.Process == nil || ev.Process.Executable == "" {
		out.Emit(ev)
		return
	}
	fi, err := os.Stat(ev.Process.Executable)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxHashBytes {
		out.Emit(ev)
		return
	}
	key, ok := keyOf(fi)
	if ok {
		if h, hit := s.hashes.get(key); hit {
			ev.Process.Hash = &event.Hash{SHA256: h}
			out.Emit(ev)
			return
		}
	}
	f, err := os.Open(ev.Process.Executable)
	if err != nil || !ok {
		if f != nil {
			f.Close()
		}
		out.Emit(ev)
		return
	}
	select {
	case s.hashQ <- hashJob{f: f, key: key, ev: ev, out: out}:
	default:
		f.Close() // hashers are saturated: send without hash rather than block
		out.Emit(ev)
	}
}

// runPoll compares process table snapshots every second. Processes that live shorter
// than that are missed, and exit codes are unknown.
func (s *processSensor) runPoll(ctx context.Context, m *esMapper, out platform.Emitter) error {
	type key struct {
		pid   int64
		start uint64
	}
	snapshot := func() map[key]kproc {
		ps, _ := listProcs()
		cur := make(map[key]kproc, len(ps))
		for _, p := range ps {
			cur[key{p.PID, p.Start}] = p
		}
		return cur
	}
	self := int64(os.Getpid())
	prev := snapshot()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		now := time.Now().UTC()
		cur := snapshot()
		for k, p := range cur {
			if _, ok := prev[k]; ok || p.PPID == self || p.Terminated {
				continue
			}
			s.emit(s.pollExec(m, p, now), out)
		}
		for k, p := range prev {
			if _, ok := cur[k]; ok || p.PPID == self {
				continue
			}
			id := s.env.EntityID(k.pid, k.start)
			ep := &event.Process{EntityID: id, PID: k.pid, Name: p.Comm, End: &now}
			if sum, ok := m.procs.get(id); ok {
				ep.Name, ep.Executable, ep.CommandLine = sum.Name, sum.Executable, sum.CommandLine
				m.procs.remove(id)
			}
			if st := startTimeFromMicros(k.start); !st.IsZero() {
				ep.Start = &st
			}
			out.Emit(&event.Event{
				Timestamp: now,
				Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeEnd},
					Action: "exit", Module: event.ModuleSysctl, Dataset: "process"},
				Message: "process exited: " + ep.Name,
				Process: ep,
			})
		}
		prev = cur
	}
}

func (s *processSensor) pollExec(m *esMapper, k kproc, now time.Time) *event.Event {
	p := describe(s.env, m.procs, k.PID)
	if p.EntityID == "" {
		p.EntityID = s.env.EntityID(k.PID, k.Start)
	}
	if st := startTimeFromMicros(k.Start); !st.IsZero() {
		p.Start = &st
	}
	p.User = &event.User{ID: itoa(k.RUID), Name: users.name(k.RUID)}
	elevated := k.UID == 0
	p.Elevated = &elevated
	if k.PPID > 0 {
		p.Parent = describe(s.env, m.procs, k.PPID)
	}
	return &event.Event{
		Timestamp: now,
		Event: event.Meta{Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart},
			Action: "exec", Outcome: event.OutcomeSuccess, Module: event.ModuleSysctl, Dataset: "process"},
		Message: "process started: " + p.CommandLine,
		Process: p,
	}
}
