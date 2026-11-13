//go:build windows

package windows

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

func TestWFPStructLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout")
	}
	// Sizes from the Windows SDK headers on x64.
	for name, got := range map[string]uintptr{
		"FWPM_FILTER0":           unsafe.Sizeof(fwpmFilter0{}),
		"FWPM_FILTER_CONDITION0": unsafe.Sizeof(fwpmFilterCondition0{}),
		"FWPM_SUBLAYER0":         unsafe.Sizeof(fwpmSubLayer0{}),
		"FWPM_PROVIDER0":         unsafe.Sizeof(fwpmProvider0{}),
	} {
		want := map[string]uintptr{"FWPM_FILTER0": 200, "FWPM_FILTER_CONDITION0": 40, "FWPM_SUBLAYER0": 72, "FWPM_PROVIDER0": 64}[name]
		if got != want {
			t.Errorf("%s: size %d, want %d", name, got, want)
		}
	}
	if o := unsafe.Offsetof(fwpmFilter0{}.providerContext); o != 152 {
		t.Errorf("providerContext offset %d, want 152", o)
	}
	if o := unsafe.Offsetof(fwpmFilter0{}.filterID); o != 176 {
		t.Errorf("filterID offset %d, want 176", o)
	}
}

func TestIsolationRules(t *testing.T) {
	if _, err := isolationRules(platform.Isolation{}, nil); err == nil {
		t.Fatal("no server: want error")
	}
	iso := platform.Isolation{
		ServerIPs:  []netip.Addr{netip.MustParseAddr("192.168.20.20"), netip.MustParseAddr("fd00::20")},
		ServerPort: 8443,
		Allow:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24"), netip.MustParsePrefix("::ffff:10.1.1.1/128")},
	}
	rules, err := isolationRules(iso, []netip.Addr{netip.MustParseAddr("192.168.20.1")})
	if err != nil {
		t.Fatal(err)
	}
	var blocks, permits int
	seen := map[string]wfpRule{}
	for i, r := range rules {
		seen[r.name] = r
		if r.permit {
			permits++
			if blocks > 0 {
				t.Errorf("permit %q after a block (index %d)", r.name, i)
			}
		} else {
			blocks++
			if r.remote.IsValid() || r.proto != 0 || r.loopback {
				t.Errorf("block %q has conditions", r.name)
			}
		}
	}
	if blocks != 4 {
		t.Errorf("blocks = %d, want 4", blocks)
	}
	s := seen["HomeXDR server 192.168.20.20"]
	if s.layer != layerConnectV4 || s.remotePort != 8443 || s.proto != protoTCP || s.remote.Bits() != 32 {
		t.Errorf("server rule = %+v", s)
	}
	if s6 := seen["HomeXDR server fd00::20"]; s6.layer != layerConnectV6 || s6.remote.Bits() != 128 {
		t.Errorf("v6 server rule = %+v", s6)
	}
	if a := seen["allow 10.1.1.1/32 in"]; a.layer != layerAcceptV4 {
		t.Errorf("mapped allow not treated as IPv4: %+v", a)
	}
	if _, ok := seen["DNS 192.168.20.1"]; !ok {
		t.Error("no DNS rule")
	}
	for i := range 300 {
		iso.Allow = append(iso.Allow, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)}), 32))
	}
	if _, err := isolationRules(iso, nil); err != nil {
		t.Errorf("300 allow entries: %v", err)
	}
	for i := range 1100 {
		iso.Allow = append(iso.Allow, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 8, byte(i >> 8), byte(i)}), 32))
	}
	if _, err := isolationRules(iso, nil); err == nil {
		t.Error("too many filters: want error")
	}
}

func TestIsoFilterKeys(t *testing.T) {
	if isoFilterKey(0) == isoFilterKey(1) || isoFilterKey(1) == isoFilterKey(257) {
		t.Fatal("filter keys collide")
	}
	if isoFilterKey(0) == isoSubLayerKey || isoFilterKey(0) == isoProviderKey {
		t.Fatal("filter key collides with provider or sublayer")
	}
}

func TestDNSServers(t *testing.T) {
	for _, d := range dnsServers() {
		if !d.IsValid() || d.IsLoopback() {
			t.Errorf("bad resolver %v", d)
		}
	}
}

// TestIsolationLive isolates this machine for a few seconds and checks what still
// connects. It needs an elevated prompt and HOMEXDR_LIVE_ISOLATION=1, plus
// HOMEXDR_LIVE_SERVER=ip:port (must stay reachable), HOMEXDR_LIVE_BLOCKED=ip:port (must
// not) and optionally HOMEXDR_LIVE_ALLOW=cidr (e.g. the SSH client).
func TestIsolationLive(t *testing.T) {
	if os.Getenv("HOMEXDR_LIVE_ISOLATION") != "1" {
		t.Skip("set HOMEXDR_LIVE_ISOLATION=1 on a test machine")
	}
	srv := netip.MustParseAddrPort(os.Getenv("HOMEXDR_LIVE_SERVER"))
	blocked := os.Getenv("HOMEXDR_LIVE_BLOCKED")
	iso := platform.Isolation{ServerIPs: []netip.Addr{srv.Addr()}, ServerPort: int(srv.Port())}
	if a := os.Getenv("HOMEXDR_LIVE_ALLOW"); a != "" {
		iso.Allow = []netip.Prefix{netip.MustParsePrefix(a)}
	}
	dial := func(addr string) error {
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	r := responder{}
	ctx := context.Background()
	if err := dial(blocked); err != nil {
		t.Fatalf("before isolation %s is unreachable: %v", blocked, err)
	}
	t.Logf("resolvers: %v", dnsServers())
	if err := r.Isolate(ctx, iso); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	defer func() {
		if err := r.Release(ctx); err != nil {
			t.Errorf("release: %v", err)
		}
	}()
	if !r.Isolated() {
		t.Error("Isolated() = false after Isolate")
	}
	if err := r.Isolate(ctx, iso); err != nil {
		t.Errorf("isolate again (idempotent): %v", err)
	}
	if err := dial(srv.String()); err != nil {
		t.Errorf("server %s blocked while isolated: %v", srv, err)
	}
	if err := dial(blocked); err == nil {
		t.Errorf("%s reachable while isolated", blocked)
	} else {
		t.Logf("%s while isolated: %v", blocked, err)
	}
	if _, err := net.LookupHost("example.com"); err != nil {
		t.Errorf("DNS while isolated: %v", err)
	}
	if err := r.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if r.Isolated() {
		t.Error("Isolated() = true after Release")
	}
	if err := dial(blocked); err != nil {
		t.Errorf("after release %s unreachable: %v", blocked, err)
	}
	if err := r.Release(ctx); err != nil {
		t.Errorf("release again: %v", err)
	}
}
