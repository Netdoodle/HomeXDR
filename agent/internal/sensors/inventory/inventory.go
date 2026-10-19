// Package inventory periodically snapshots host inventory by running the read-only
// collectors system.info, software.list, users.list and services.list, and emits every
// row as a state event (event.kind=state, event.module=inventory,
// event.dataset=inventory.<artifact>, the row in data).
package inventory

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
)

// Artifacts are the collectors run for inventory, in order.
var Artifacts = []string{"system.info", "software.list", "users.list", "services.list"}

// LastRun persists when inventory last ran, so restarts do not re-send it.
type LastRun interface {
	LastInventory() time.Time
	SetLastInventory(time.Time) error
}

// Sensor implements platform.Sensor.
type Sensor struct {
	collectors map[string]platform.Collector
	interval   time.Duration
	last       LastRun
	log        *slog.Logger
	// StartDelay postpones the first run after start, so a booting host is not loaded
	// further. Tests set it to zero.
	StartDelay time.Duration

	mu      sync.Mutex
	events  uint64
	lastErr string
}

// New returns the inventory sensor.
func New(collectors map[string]platform.Collector, intervalSec int, last LastRun, log *slog.Logger) *Sensor {
	iv := time.Duration(intervalSec) * time.Second
	if iv < 5*time.Minute {
		iv = 6 * time.Hour
	}
	return &Sensor{collectors: collectors, interval: iv, last: last, log: log, StartDelay: 30 * time.Second}
}

// Name returns "inventory".
func (s *Sensor) Name() string { return "inventory" }

// Status reports health.
func (s *Sensor) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := api.SensorStatus{Name: "inventory", Impl: event.ModuleInventory, State: api.SensorRunning, Events: s.events, Error: s.lastErr}
	if s.lastErr != "" {
		st.State = api.SensorDegraded
	}
	return st
}

// Run emits inventory every interval.
func (s *Sensor) Run(ctx context.Context, out platform.Emitter) error {
	wait := s.StartDelay
	if s.last != nil {
		if last := s.last.LastInventory(); !last.IsZero() {
			if due := time.Until(last.Add(s.interval)); due > wait {
				wait = due
			}
		}
	}
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		s.RunOnce(ctx, out)
		if s.last != nil {
			if err := s.last.SetLastInventory(time.Now().UTC()); err != nil {
				s.log.Warn("inventory: save last run", "err", err)
			}
		}
		wait = s.interval
	}
}

// RunOnce runs every available inventory collector once.
func (s *Sensor) RunOnce(ctx context.Context, out platform.Emitter) {
	var errs []string
	total := 0
	for _, name := range Artifacts {
		coll, ok := s.collectors[name]
		if !ok {
			continue
		}
		n := 0
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := coll(cctx, defaults(name), func(r platform.Row) error {
			out.Emit(rowEvent(name, r))
			n++
			return nil
		})
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			s.log.Warn("inventory collector failed", "artifact", name, "err", err)
		}
		total += n
		s.mu.Lock()
		s.events += uint64(n)
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.lastErr = ""
	if len(errs) > 0 {
		s.lastErr = fmt.Sprint(errs)
	}
	s.mu.Unlock()
	s.log.Info("inventory snapshot sent", "rows", total)
}

func defaults(name string) map[string]string {
	out := map[string]string{}
	if def, ok := api.FindArtifact(name); ok {
		for _, a := range def.Params {
			if a.Default != "" {
				out[a.Name] = a.Default
			}
		}
	}
	return out
}

func str(r platform.Row, k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// rowEvent maps an inventory row to a state event, filling the ECS object that fits.
func rowEvent(artifact string, r platform.Row) *event.Event {
	e := &event.Event{
		Timestamp: time.Now().UTC(),
		Event: event.Meta{
			Kind: event.KindState, Module: event.ModuleInventory, Dataset: "inventory." + artifact,
			Type: []string{event.TypeInfo},
		},
		Data: map[string]any(r),
	}
	switch artifact {
	case "system.info":
		e.Event.Category = []string{event.CategoryHost}
		e.Message = "inventory: system " + str(r, "os_name") + " " + str(r, "os_version")
	case "software.list":
		e.Event.Category = []string{event.CategoryPackage}
		e.Package = &event.Package{Name: str(r, "name"), Version: str(r, "version"), Vendor: str(r, "vendor"), Type: str(r, "type")}
		e.Message = "inventory: package " + str(r, "name") + " " + str(r, "version")
	case "users.list":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeUser, event.TypeInfo}
		e.User = &event.User{Name: str(r, "name"), ID: str(r, "id")}
		e.Message = "inventory: user " + str(r, "name")
	case "services.list":
		e.Event.Category = []string{event.CategoryConfiguration}
		e.Service = &event.Service{
			Name: str(r, "name"), DisplayName: str(r, "display_name"), State: str(r, "state"),
			StartType: str(r, "start_type"), Path: str(r, "path"), Account: str(r, "account"),
		}
		e.Message = "inventory: service " + str(r, "name")
	}
	return e
}
