// Package supervisor runs sensors, restarts them with backoff when they fail, restarts
// them when their part of the central config changes, and reports their status.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/backoff"
	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// Spec is a sensor plus a fingerprint of the config it was built from. A sensor is
// restarted when its fingerprint changes.
type Spec struct {
	Sensor platform.Sensor
	Key    string
}

// Supervisor owns the running sensors.
type Supervisor struct {
	log *slog.Logger
	out platform.Emitter

	mu       sync.Mutex
	runners  map[string]*runner
	disabled []api.SensorStatus
}

type runner struct {
	sensor platform.Sensor
	key    string
	cancel context.CancelFunc
	done   chan struct{}
	events atomic.Uint64

	mu      sync.Mutex
	failed  bool
	lastErr string
}

// New returns a supervisor emitting into out.
func New(out platform.Emitter, log *slog.Logger) *Supervisor {
	return &Supervisor{log: log, out: out, runners: map[string]*runner{}}
}

// Apply reconciles running sensors with specs: sensors whose name disappeared or whose
// key changed are stopped, new ones are started, unchanged ones keep running (their new
// Sensor instance is discarded). disabled lists sensors to report as not running.
func (s *Supervisor) Apply(ctx context.Context, specs []Spec, disabled []api.SensorStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]Spec{}
	for _, sp := range specs {
		if sp.Sensor == nil {
			continue
		}
		want[sp.Sensor.Name()] = sp
	}
	var stopping []*runner
	for name, r := range s.runners {
		if sp, ok := want[name]; !ok || sp.Key != r.key {
			r.cancel()
			stopping = append(stopping, r)
			delete(s.runners, name)
			if ok {
				s.log.Info("restarting sensor for new config", "sensor", name)
			} else {
				s.log.Info("stopping sensor", "sensor", name)
			}
		}
	}
	waitAll(stopping, 15*time.Second, s.log)
	for name, sp := range want {
		if _, ok := s.runners[name]; ok {
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		r := &runner{sensor: sp.Sensor, key: sp.Key, cancel: cancel, done: make(chan struct{})}
		s.runners[name] = r
		go s.run(rctx, r)
	}
	s.disabled = slices.Clone(disabled)
}

func waitAll(rs []*runner, timeout time.Duration, log *slog.Logger) {
	deadline := time.After(timeout)
	for _, r := range rs {
		select {
		case <-r.done:
		case <-deadline:
			log.Warn("sensor did not stop in time", "sensor", r.sensor.Name())
			return
		}
	}
}

// Stop stops all sensors and waits for them.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	var rs []*runner
	for name, r := range s.runners {
		r.cancel()
		rs = append(rs, r)
		delete(s.runners, name)
	}
	s.mu.Unlock()
	waitAll(rs, 15*time.Second, s.log)
}

type countingEmitter struct {
	r   *runner
	out platform.Emitter
}

func (c countingEmitter) Emit(e *event.Event) {
	c.r.events.Add(1)
	c.out.Emit(e)
}

func (s *Supervisor) run(ctx context.Context, r *runner) {
	defer close(r.done)
	name := r.sensor.Name()
	var bo backoff.Backoff
	for ctx.Err() == nil {
		start := time.Now()
		s.log.Info("starting sensor", "sensor", name)
		err := safeRun(ctx, r.sensor, countingEmitter{r: r, out: s.out})
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("sensor stopped unexpectedly")
		}
		if time.Since(start) > 5*time.Minute {
			bo.Reset()
		}
		d := bo.Next()
		r.mu.Lock()
		r.failed, r.lastErr = true, err.Error()
		r.mu.Unlock()
		s.log.Warn("sensor failed", "sensor", name, "err", err, "retry_in", d.Round(time.Second))
		if !backoff.SleepCtx(ctx, d) {
			return
		}
		r.mu.Lock()
		r.failed = false
		r.mu.Unlock()
	}
}

func safeRun(ctx context.Context, sn platform.Sensor, out platform.Emitter) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v\n%s", p, debug.Stack())
		}
	}()
	return sn.Run(ctx, out)
}

// Statuses reports every sensor, including disabled ones, sorted by name.
func (s *Supervisor) Statuses() []api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]api.SensorStatus, 0, len(s.runners)+len(s.disabled))
	for name, r := range s.runners {
		st := r.sensor.Status()
		if st.Name == "" {
			st.Name = name
		}
		if st.State == "" {
			st.State = api.SensorRunning
		}
		st.Events = max(st.Events, r.events.Load())
		r.mu.Lock()
		if r.failed {
			st.State, st.Error = api.SensorFailed, r.lastErr
		}
		r.mu.Unlock()
		out = append(out, st)
	}
	for _, d := range s.disabled {
		if _, ok := s.runners[d.Name]; !ok {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
