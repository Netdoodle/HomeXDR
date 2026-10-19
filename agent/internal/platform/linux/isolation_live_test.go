//go:build linux

package linux

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// TestIsolationLiveInNetns applies real isolation and checks what it lets through. It
// must run inside a throwaway network namespace that can reach a host-side listener;
// scripts/isolation-netns-test.sh sets that up. Opt-in: HOMEXDR_ISOLATION_LIVE=1 and
// HOMEXDR_ISOLATION_SERVER=<listener IP>. It refuses to run in the initial namespace, so
// it can never cut off the machine running it.
func TestIsolationLiveInNetns(t *testing.T) {
	server := os.Getenv("HOMEXDR_ISOLATION_SERVER")
	if os.Getenv("HOMEXDR_ISOLATION_LIVE") != "1" || server == "" || os.Geteuid() != 0 {
		t.Skip("run through scripts/isolation-netns-test.sh as root")
	}
	self, err1 := os.Readlink("/proc/self/ns/net")
	initial, err2 := os.Readlink("/proc/1/ns/net")
	if err1 != nil || err2 != nil || self == initial {
		t.Fatal("refusing to isolate the initial network namespace")
	}
	const allowedPort, blockedPort = 8443, 9999
	dial := func(port int) error {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(server, strconv.Itoa(port)), 2*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	ctx := context.Background()
	r := &responder{env: platform.Env{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	// HOMEXDR_ISOLATION_FW=iptables exercises the fallback even where nft is installed.
	if os.Getenv("HOMEXDR_ISOLATION_FW") == "iptables" {
		v4, err := exec.LookPath("iptables")
		if err != nil {
			t.Skip("iptables not installed")
		}
		v6, _ := exec.LookPath("ip6tables")
		r.fw = iptFirewall{v4: v4, v6: v6}
	}
	t.Cleanup(func() { _ = r.Release(ctx) })

	if err := dial(blockedPort); err != nil {
		t.Fatalf("before isolation, port %d should be reachable: %v", blockedPort, err)
	}
	iso := platform.Isolation{ServerIPs: []netip.Addr{netip.MustParseAddr(server)}, ServerPort: allowedPort}
	if err := r.Isolate(ctx, iso); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if !r.Isolated() {
		t.Fatal("Isolated() = false after Isolate")
	}
	if err := dial(allowedPort); err != nil {
		t.Fatalf("server port %d must stay reachable while isolated: %v", allowedPort, err)
	}
	if err := dial(blockedPort); err == nil {
		t.Fatalf("port %d reachable while isolated", blockedPort)
	}
	if err := r.Isolate(ctx, iso); err != nil {
		t.Fatalf("second Isolate (idempotence): %v", err)
	}
	if err := dial(allowedPort); err != nil {
		t.Fatalf("server port unreachable after re-applying isolation: %v", err)
	}
	if err := r.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if r.Isolated() {
		t.Fatal("Isolated() = true after Release")
	}
	if err := dial(blockedPort); err != nil {
		t.Fatalf("port %d still blocked after release: %v", blockedPort, err)
	}
	if err := r.Release(ctx); err != nil {
		t.Fatalf("Release when not isolated must succeed: %v", err)
	}
}
