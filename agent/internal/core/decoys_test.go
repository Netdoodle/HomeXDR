package core

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/state"
	"github.com/Netdoodle/homexdr/agent/internal/supervisor"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// noSensorPlatform runs no platform sensors.
type noSensorPlatform struct{ platform.Platform }

func (noSensorPlatform) Name() string                                              { return "test" }
func (noSensorPlatform) Paths() platform.Paths                                     { return platform.Paths{} }
func (noSensorPlatform) Sensors(api.SensorsConfig, platform.Env) []platform.Sensor { return nil }

// fakeDecoy stands in for the decoy sensor, which would place real files.
type fakeDecoy struct{ cfg api.DecoyConfig }

func (f *fakeDecoy) Name() string { return "decoy" }
func (f *fakeDecoy) Run(ctx context.Context, _ platform.Emitter) error {
	<-ctx.Done()
	return nil
}
func (f *fakeDecoy) Status() api.SensorStatus {
	st := api.SensorStatus{Name: "decoy", State: api.SensorRunning}
	if !f.cfg.Enabled {
		st.State = api.SensorDisabled
	}
	return st
}

func TestHeartbeatDecoySwitch(t *testing.T) {
	dir := t.TempDir()
	stPath := filepath.Join(dir, state.FileName)
	st, err := state.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.DefaultAgentConfig()
	cfg.FIM.Enabled = false
	if err := st.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var built []api.DecoyConfig
	a := &Agent{
		plat: noSensorPlatform{}, st: st, log: quiet, dataDir: dir,
		sup: supervisor.New(platform.EmitterFunc(func(*event.Event) {}), quiet),
		decoySensor: func(c api.DecoyConfig) platform.Sensor {
			mu.Lock()
			built = append(built, c)
			mu.Unlock()
			return &fakeDecoy{cfg: c}
		},
	}
	defer a.sup.Stop()
	ctx := context.Background()
	decoyState := func() string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, s := range a.sup.Statuses() {
				if s.Name == "decoy" && s.State != "" {
					return s.State
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("no decoy sensor status")
		return ""
	}
	a.applySensors(ctx, st.Config())
	if s := decoyState(); s != api.SensorRunning {
		t.Fatalf("Global on, no host value: %s", s)
	}

	// The server says off for this host (its group): the decoy sensor restarts off.
	off, on := false, true
	a.applyDecoysEnabled(ctx, &off)
	if s := decoyState(); s != api.SensorDisabled {
		t.Fatalf("host off: %s", s)
	}
	// The same value again changes nothing.
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(built) }
	n := count()
	a.applyDecoysEnabled(ctx, &off)
	if count() != n {
		t.Errorf("unchanged value rebuilt the sensors")
	}
	// It is kept across restarts, so the agent does not place decoys before the first
	// heartbeat of its next run.
	st2, err := state.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	if v := st2.DecoysEnabled(); v == nil || *v {
		t.Fatalf("persisted value %v", v)
	}
	if decoyConfig(st2.Config().Decoys, st2.DecoysEnabled()).Enabled {
		t.Fatal("restarted agent would place decoys")
	}

	// On for the host although the config says off.
	cfg.Decoys.Enabled = false
	cfg.Version++
	if err := st.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	a.applyDecoysEnabled(ctx, &on)
	if s := decoyState(); s != api.SensorRunning {
		t.Fatalf("host on over Global off: %s", s)
	}
	// An older server sends nothing: the config's switch applies again.
	a.applyDecoysEnabled(ctx, nil)
	if s := decoyState(); s != api.SensorDisabled {
		t.Fatalf("no host value, Global off: %s", s)
	}
	mu.Lock()
	last := built[len(built)-1]
	mu.Unlock()
	if last.Enabled || len(last.Files) != len(api.DefaultDecoyFiles()) {
		t.Errorf("last decoy config %+v", last)
	}
}
