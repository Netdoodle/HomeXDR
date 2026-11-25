//go:build darwin

package darwin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type collectEmitter struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collectEmitter) Emit(e *event.Event) { c.mu.Lock(); c.evs = append(c.evs, e); c.mu.Unlock() }
func (c *collectEmitter) n() int              { c.mu.Lock(); defer c.mu.Unlock(); return len(c.evs) }

func TestDNSSensorRunsOverCapturedFrames(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	env := platform.Env{AgentID: "a", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s := newDNSSensor(env)
	var once sync.Once
	s.open = func(iface string) (*bpfDevice, error) {
		var dev *bpfDevice
		once.Do(func() { dev = &bpfDevice{f: r, dlt: dltNull, size: 1 << 16} })
		if dev == nil {
			return nil, errors.New("busy")
		}
		return dev, nil
	}
	out := &collectEmitter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()

	now := time.Now()
	q := ipv4Pkt(protoUDP, "127.0.0.1", "192.0.2.53", 40000, 53, dnsQueryMsg(5, "example.org", dnsTypeA))
	a := ipv4Pkt(protoUDP, "192.0.2.53", "127.0.0.1", 53, 40000, dnsAnswerMsg(5, "example.org", dnsTypeA, 0, "192.0.2.7"))
	rec := append(bpfRecord(int32(now.Unix()), 0, nullHdr(2, q)), bpfRecord(int32(now.Unix()), 1000, nullHdr(2, a))...)
	if _, err := w.Write(rec); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200 && out.n() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if out.n() != 1 {
		t.Fatalf("%d events", out.n())
	}
	e := out.evs[0]
	if e.DNS == nil || e.DNS.Question.Name != "example.org" || e.DNS.ResolvedIP[0] != "192.0.2.7" || e.Event.Module != "bpf" {
		t.Fatalf("%+v", e)
	}
	if st := s.Status(); st.Impl != "bpf" || st.State != api.SensorDegraded || st.Events != 1 {
		t.Fatalf("%+v", st)
	}
	w.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestDNSSensorUnavailableWithoutBPF(t *testing.T) {
	env := platform.Env{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s := newDNSSensor(env)
	s.open = func(string) (*bpfDevice, error) { return nil, unavailable(errors.New("permission denied")) }
	err := s.Run(context.Background(), &collectEmitter{})
	if !isUnavailable(err) || s.Status().State != api.SensorFailed {
		t.Fatalf("%v %+v", err, s.Status())
	}
}

// TestLiveDNSCapture captures a real lookup. It needs root (/dev/bpf*):
// sudo go test -run TestLiveDNSCapture -v ./internal/platform/darwin/
func TestLiveDNSCapture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for /dev/bpf")
	}
	s := newDNSSensor(testEnv(t))
	out := &collectEmitter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	time.Sleep(2 * time.Second) // let the readers open their devices
	// Ask the first resolver in /etc/resolv.conf directly over UDP port 53: the system
	// resolver may use encrypted DNS (DoH/DoT, for example when the router advertises it),
	// which never touches port 53.
	server := ""
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
				server = f[1]
				break
			}
		}
	}
	if server == "" {
		t.Skip("no nameserver in /etc/resolv.conf")
	}
	name := "hx-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "-") + ".example.org"
	if out, err := exec.Command("/usr/bin/dig", "+tries=1", "+time=3", "@"+server, name, "A").CombinedOutput(); err != nil {
		t.Logf("dig: %v: %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out.mu.Lock()
		for _, e := range out.evs {
			if e.DNS != nil && e.DNS.Question.Name == name {
				t.Logf("captured %s: type %s, code %s, transport %s", name, e.DNS.Type, e.DNS.ResponseCode, e.Network.Transport)
				out.mu.Unlock()
				t.Logf("status: %+v", s.Status())
				return
			}
		}
		out.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no event for %s; %d other events; status %+v", name, out.n(), s.Status())
}
