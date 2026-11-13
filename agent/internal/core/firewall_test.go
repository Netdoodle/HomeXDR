package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Netdoodle/homexdr/agent/internal/config"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/state"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// fwPlatform records what reaches the platform's firewall.
type fwPlatform struct {
	platform.Platform // nil: only the firewall methods are used
	applied           []hostfw.Set
	fail              error
}

func (p *fwPlatform) Name() string { return "test" }

func (p *fwPlatform) ApplyFirewall(_ context.Context, _ platform.Env, _ string, s hostfw.Set) (string, string, error) {
	if p.fail != nil {
		return "fake", "", p.fail
	}
	p.applied = append(p.applied, s)
	return "fake", "ok", nil
}

func (p *fwPlatform) RemoveFirewall(context.Context, platform.Env) error { return nil }

func fwAgent(t *testing.T, plat platform.Platform) *Agent {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(filepath.Join(dir, state.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{plat: plat, dataDir: dir, log: quiet, st: st,
		local: config.Local{ServerURL: "https://198.51.100.20:8443"}}
}

func TestApplyFirewallRefusesServerAddress(t *testing.T) {
	ctx := context.Background()
	plat := &fwPlatform{}
	a := fwAgent(t, plat)
	for _, cidr := range []string{"198.51.100.20", "198.51.100.0/24"} {
		_, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: "v1", Rules: []api.FirewallRule{{CIDR: "203.0.113.1"}, {CIDR: cidr}}})
		if err == nil || !strings.Contains(err.Error(), "HomeXDR server") {
			t.Fatalf("%s: err = %v", cidr, err)
		}
	}
	if len(plat.applied) != 0 {
		t.Fatal("a refused set reached the firewall")
	}
	if _, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: "bad version", Rules: nil}); err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestApplyFirewallSavesAndReapplies(t *testing.T) {
	ctx := context.Background()
	plat := &fwPlatform{}
	a := fwAgent(t, plat)
	res, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: "fw-1", Rules: []api.FirewallRule{
		{CIDR: "203.0.113.0/24"}, {CIDR: "203.0.113.9"}, {CIDR: "2001:db8::1", Direction: api.FirewallOut}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "fw-1" || res.Rules != 2 || res.Backend != "fake" || len(plat.applied) != 1 {
		t.Fatalf("result = %+v, applied %d", res, len(plat.applied))
	}
	if _, err := os.Stat(filepath.Join(a.dataDir, FirewallStateFile)); err != nil {
		t.Fatal("rule set not saved:", err)
	}
	// After a restart the saved set is applied again.
	a.reapplyFirewall(ctx)
	if len(plat.applied) != 2 || len(plat.applied[1].Out) != 2 {
		t.Fatalf("reapplied = %+v", plat.applied)
	}
	// An empty set removes the saved file; a restart then applies nothing.
	if _, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: "none"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(a.dataDir, FirewallStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty set left the saved file:", err)
	}
	a.reapplyFirewall(ctx)
	if len(plat.applied) != 3 {
		t.Fatalf("applies = %d", len(plat.applied))
	}
	// A failure keeps the previous saved state untouched and reports the error.
	plat.fail = errors.New("nft missing")
	if _, err := a.ApplyFirewall(ctx, api.FirewallParams{Version: "fw-2", Rules: []api.FirewallRule{{CIDR: "203.0.113.1"}}}); err == nil {
		t.Fatal("platform error swallowed")
	}
	if _, err := os.Stat(filepath.Join(a.dataDir, FirewallStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed apply was saved")
	}
}

type plainPlatform struct{ platform.Platform }

func (plainPlatform) Name() string { return "plain" }

func TestApplyFirewallUnsupported(t *testing.T) {
	a := fwAgent(t, plainPlatform{})
	if _, err := a.ApplyFirewall(context.Background(), api.FirewallParams{Version: "v"}); err == nil || !strings.Contains(err.Error(), "not supported on plain") {
		t.Fatalf("err = %v", err)
	}
}
