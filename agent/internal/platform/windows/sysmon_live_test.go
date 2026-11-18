//go:build windows

package windows

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Netdoodle/homexdr/shared/api"
)

// TestSysmonLive reads the real Sysmon install, feature state and schema. With
// HOMEXDR_LIVE_SYSMON=apply on a machine whose Sysmon has no rules, it also applies
// HomeXDR's configuration and undoes it again (back to Sysmon's defaults). Needs an
// elevated prompt; only run it on a test machine.
func TestSysmonLive(t *testing.T) {
	mode := os.Getenv("HOMEXDR_LIVE_SYSMON")
	if mode != "1" && mode != "apply" {
		t.Skip("set HOMEXDR_LIVE_SYSMON=1 (read only) or apply on a test machine")
	}
	ctx := context.Background()
	h := newWinSysmonHost()
	inst, err := h.probe()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("install: %+v", inst)
	fs, err := h.feature(ctx)
	t.Logf("feature: %d, %v", fs, err)
	if inst == nil {
		return
	}
	if inst.Binary == "" {
		t.Fatalf("binary not runnable: %s", inst.ImagePath)
	}
	v, err := h.schema(ctx, inst.Binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("schema: %s", v)
	if mode != "apply" {
		return
	}
	dir := t.TempDir()
	m := newSysmonManager(dir)
	m.backupPath = filepath.Join(dir, sysmonBackupName)
	if r := m.classify(inst, nil); r != rulesNone {
		t.Fatalf("Sysmon has rules (%s): not touching it", r)
	}
	resetSysmonGlobals(t)
	r := m.ensure(ctx)
	t.Logf("ensure: %+v", r)
	after, _ := h.probe()
	t.Logf("after ensure: %+v", after)
	ok := r.state == api.SensorRunning && after != nil && after.HasRules && sysmonHashMatches(after.ConfigHash, mustRead(t, m.configPath))
	if again := m.ensure(ctx); again != r {
		t.Errorf("second ensure: %+v", again)
	}
	u, did := m.undo(ctx)
	t.Logf("undo: %+v %q", u, did)
	back, _ := h.probe()
	t.Logf("after undo: %+v", back)
	if !ok {
		t.Error("HomeXDR's configuration was not applied")
	}
	if u.state != api.SensorDisabled || back == nil || back.HasRules || back.ConfigHash != "" {
		t.Error("Sysmon is not back to its defaults")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
