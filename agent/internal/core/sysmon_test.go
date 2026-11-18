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

// sysmonPlatform is a platform that manages Sysmon, with a fake sensor that only records
// the switch it was built with.
type sysmonPlatform struct {
	noSensorPlatform
	mu    sync.Mutex
	built []bool
}

func (p *sysmonPlatform) SysmonSensor(enabled bool, _ platform.Env) platform.Sensor {
	p.mu.Lock()
	p.built = append(p.built, enabled)
	p.mu.Unlock()
	return &fakeSysmon{on: enabled}
}

func (p *sysmonPlatform) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.built)
}

type fakeSysmon struct{ on bool }

func (f *fakeSysmon) Name() string { return "sysmon" }
func (f *fakeSysmon) Run(ctx context.Context, _ platform.Emitter) error {
	<-ctx.Done()
	return nil
}
func (f *fakeSysmon) Status() api.SensorStatus {
	st := api.SensorStatus{Name: "sysmon", State: api.SensorRunning}
	if !f.on {
		st.State = api.SensorDisabled
	}
	return st
}

func TestHeartbeatSysmonSwitch(t *testing.T) {
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
	plat := &sysmonPlatform{}
	a := &Agent{
		plat: plat, st: st, log: quiet, dataDir: dir,
		sup:         supervisor.New(platform.EmitterFunc(func(*event.Event) {}), quiet),
		decoySensor: func(c api.DecoyConfig) platform.Sensor { return &fakeDecoy{cfg: c} },
	}
	defer a.sup.Stop()
	ctx := context.Background()
	sysmonState := func() string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, s := range a.sup.Statuses() {
				if s.Name == "sysmon" && s.State != "" {
					return s.State
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("no sysmon sensor status")
		return ""
	}

	a.applySensors(ctx, st.Config())
	if s := sysmonState(); s != api.SensorRunning {
		t.Fatalf("default config (on), no host value: %s", s)
	}

	off, on := false, true
	a.applySysmonEnabled(ctx, &off)
	if s := sysmonState(); s != api.SensorDisabled {
		t.Fatalf("host off: %s", s)
	}
	n := plat.count()
	a.applySysmonEnabled(ctx, &off)
	if plat.count() != n {
		t.Error("an unchanged value rebuilt the sensors")
	}
	// The decoy switch does not touch Sysmon (the decoy sensor's key changes, Sysmon's
	// does not, so the running Sysmon sensor is kept).
	a.applyDecoysEnabled(ctx, &off)
	if s := sysmonState(); s != api.SensorDisabled {
		t.Fatalf("after the decoy switch: %s", s)
	}

	// Kept across restarts.
	st2, err := state.Open(stPath)
	if err != nil {
		t.Fatal(err)
	}
	if v := st2.SysmonEnabled(); v == nil || *v {
		t.Fatalf("persisted value %v", v)
	}
	if sysmonEnabled(st2.Config().Sysmon, st2.SysmonEnabled()) {
		t.Fatal("a restarted agent would set Sysmon up")
	}

	// On for the host although the config says off; then an older server that sends
	// nothing leaves the config in charge.
	cfg.Sysmon.Enabled = false
	cfg.Version++
	if err := st.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	a.applySysmonEnabled(ctx, &on)
	if s := sysmonState(); s != api.SensorRunning {
		t.Fatalf("host on over Global off: %s", s)
	}
	a.applySysmonEnabled(ctx, nil)
	if s := sysmonState(); s != api.SensorDisabled {
		t.Fatalf("no host value, Global off: %s", s)
	}
}

// Platforms without Sysmon management get no sysmon sensor.
func TestNoSysmonSensorElsewhere(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, state.FileName))
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		plat: noSensorPlatform{}, st: st, log: quiet, dataDir: dir,
		sup:         supervisor.New(platform.EmitterFunc(func(*event.Event) {}), quiet),
		decoySensor: func(c api.DecoyConfig) platform.Sensor { return &fakeDecoy{cfg: c} },
	}
	defer a.sup.Stop()
	a.applySensors(context.Background(), st.Config())
	for _, s := range a.sup.Statuses() {
		if s.Name == "sysmon" {
			t.Fatalf("unexpected sysmon status %+v", s)
		}
	}
}
