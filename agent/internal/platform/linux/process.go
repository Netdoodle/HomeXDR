//go:build linux

package linux

import (
	"context"
	"errors"
	"sync"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// errUnavailable marks an implementation that cannot run here (no BTF, too old a kernel,
// missing privileges); the sensor then tries the next one.
type errUnavailable struct{ err error }

func (e errUnavailable) Error() string { return e.err.Error() }
func (e errUnavailable) Unwrap() error { return e.err }

func unavailable(err error) error { return errUnavailable{err} }

func isUnavailable(err error) bool {
	var u errUnavailable
	return errors.As(err, &u)
}

// sensorState is the shared status bookkeeping of the Linux sensors.
type sensorState struct {
	mu     sync.Mutex
	name   string
	impl   string
	state  string
	errMsg string
	events uint64
}

func (s *sensorState) set(impl, state, msg string) {
	s.mu.Lock()
	s.impl, s.state, s.errMsg = impl, state, msg
	s.mu.Unlock()
}

func (s *sensorState) count() {
	s.mu.Lock()
	s.events++
	s.mu.Unlock()
}

// Status reports health.
func (s *sensorState) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	if st == "" {
		st = api.SensorRunning
	}
	return api.SensorStatus{Name: s.name, Impl: s.impl, State: st, Error: s.errMsg, Events: s.events}
}

// countingEmitter counts events into the sensor's status.
type countingEmitter struct {
	s   *sensorState
	out platform.Emitter
}

func (c countingEmitter) Emit(e *event.Event) {
	c.s.count()
	c.out.Emit(e)
}

// processSensor reports process start and exit. Implementations, best first:
// eBPF (exec with argv, exit with code), netlink proc connector (needs CAP_NET_ADMIN;
// argv and exe read from /proc, so very short-lived processes lose detail), and /proc
// polling (misses short-lived processes entirely).
type processSensor struct {
	sensorState
	env platform.Env
	cfg api.ProcessSensorConfig
}

func newProcessSensor(cfg api.ProcessSensorConfig, env platform.Env) *processSensor {
	return &processSensor{sensorState: sensorState{name: "process"}, env: env, cfg: cfg}
}

// Name returns "process".
func (s *processSensor) Name() string { return "process" }

// Run tries the implementations in order.
func (s *processSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(event.ModuleEBPF, api.SensorRunning, "")
	err := s.runEBPF(ctx, out)
	if err == nil || !isUnavailable(err) {
		return err
	}
	reason := "eBPF unavailable: " + err.Error()
	s.env.Log.Warn("process sensor: eBPF unavailable, using the netlink proc connector", "err", err)
	s.set(event.ModuleProcConn, api.SensorDegraded, reason)
	err = s.runProcConn(ctx, out)
	if err == nil || !isUnavailable(err) {
		return err
	}
	s.env.Log.Warn("process sensor: proc connector unavailable, polling /proc", "err", err)
	s.set(event.ModuleProcfs, api.SensorDegraded, reason+"; proc connector unavailable: "+err.Error())
	return s.runPoll(ctx, out)
}
