//go:build windows

package windows

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/hostfw"
)

// TestHostFirewallLive blocks two public addresses in Windows Firewall, swaps the set,
// and removes it. Needs an elevated prompt and HOMEXDR_LIVE_FIREWALL=1.
func TestHostFirewallLive(t *testing.T) {
	if os.Getenv("HOMEXDR_LIVE_FIREWALL") != "1" {
		t.Skip("set HOMEXDR_LIVE_FIREWALL=1 on a test machine")
	}
	ctx := context.Background()
	p := &Platform{}
	env := platform.Env{}
	dial := func(addr string) error {
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	rules := func() string {
		out, _ := runPowerShell(ctx, `@(Get-NetFirewallRule -Group HomeXDR -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName + ' ' + $_.Direction + ' ' + $_.Action }) -join '; '`)
		return strings.TrimSpace(string(out))
	}
	apply := func(version string, rs ...api.FirewallRule) {
		t.Helper()
		s, err := hostfw.Normalize(rs, nil)
		if err != nil {
			t.Fatal(err)
		}
		be, msg, err := p.ApplyFirewall(ctx, env, version, s)
		t.Logf("apply %s: backend=%s msg=%q err=%v rules=[%s]", version, be, msg, err, rules())
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := p.RemoveFirewall(ctx, env); err != nil {
			t.Errorf("remove: %v", err)
		}
	}()
	if err := dial("1.1.1.1:443"); err != nil {
		t.Fatalf("1.1.1.1 unreachable before: %v", err)
	}
	apply("fw-live1", api.FirewallRule{CIDR: "1.1.1.1"})
	if err := dial("1.1.1.1:443"); err == nil {
		t.Error("1.1.1.1 reachable while blocked")
	}
	if err := dial("1.0.0.1:443"); err != nil {
		t.Errorf("1.0.0.1 blocked but not listed: %v", err)
	}
	apply("fw-live1", api.FirewallRule{CIDR: "1.1.1.1"}) // unchanged
	apply("fw-live2", api.FirewallRule{CIDR: "1.0.0.1", Direction: api.FirewallOut})
	if err := dial("1.1.1.1:443"); err != nil {
		t.Errorf("1.1.1.1 still blocked after the swap: %v", err)
	}
	if err := dial("1.0.0.1:443"); err == nil {
		t.Error("1.0.0.1 reachable while blocked")
	}
	if err := p.RemoveFirewall(ctx, env); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if r := rules(); r != "" {
		t.Errorf("rules left after remove: %s", r)
	}
	if err := dial("1.0.0.1:443"); err != nil {
		t.Errorf("1.0.0.1 blocked after remove: %v", err)
	}
}
