//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/Netdoodle/homexdr/agent/internal/backoff"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"golang.org/x/sys/unix"
)

const (
	dnsBPFBuffer   = 1 << 20          // read buffer of each BPF device
	dnsReadTimeout = time.Second      // a read returns after this long even when idle
	dnsIfaceScan   = 30 * time.Second // how often new interfaces are picked up
	dnsPacketQueue = 4096             // frames waiting for the tracker; more are dropped
	dnsMaxBPFDev   = 256              // /dev/bpf0 ... /dev/bpf255
)

// dnsSensor reports the host's DNS queries over UDP and TCP port 53 with their answers,
// from a BPF capture on the network interfaces. Process names are not in the packets, so
// events carry no process and the sensor reports itself as degraded. Reading /dev/bpf
// needs root, which the agent has under launchd. mDNSResponder's unified-log messages
// would name the requesting process, but its query names and answers are redacted
// (<private>) in the log, so they cannot be used.
type dnsSensor struct {
	sensorState
	env platform.Env
	// open is replaceable in tests.
	open func(iface string) (*bpfDevice, error)
}

func newDNSSensor(env platform.Env) *dnsSensor {
	return &dnsSensor{sensorState: sensorState{name: "dns"}, env: env, open: openBPFDevice}
}

// Name returns "dns".
func (s *dnsSensor) Name() string { return "dns" }

// bpfFrame is a captured frame and the link type it came from.
type bpfFrame struct {
	ts    time.Time
	dlt   int
	frame []byte
}

// Run captures until ctx ends. A failing interface capture is reopened with backoff.
func (s *dnsSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(moduleBPF, api.SensorDegraded, "packet capture without process attribution")

	ctx, cancel := context.WithCancel(ctx)
	frames := make(chan bpfFrame, dnsPacketQueue)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	type reader struct {
		running bool
		bo      backoff.Backoff
		retryAt time.Time
	}
	var mu sync.Mutex
	readers := map[string]*reader{}
	opened := 0
	var lastErr error
	exited := make(chan string, 64)

	start := func(name string) {
		mu.Lock()
		r := readers[name]
		if r == nil {
			r = &reader{}
			readers[name] = r
		}
		if r.running || time.Now().Before(r.retryAt) {
			mu.Unlock()
			return
		}
		mu.Unlock()
		dev, err := s.open(name)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			lastErr = err
			r.retryAt = time.Now().Add(r.bo.Next())
			if isUnavailable(err) {
				s.env.Log.Warn("dns sensor: cannot open BPF device", "iface", name, "err", err)
			}
			return
		}
		r.running = true
		opened++
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			err := dev.readLoop(ctx, frames)
			dev.Close()
			mu.Lock()
			r.running = false
			if time.Since(t0) > time.Minute {
				r.bo.Reset()
			}
			r.retryAt = time.Now().Add(r.bo.Next())
			mu.Unlock()
			if err != nil && ctx.Err() == nil {
				s.env.Log.Warn("dns sensor: capture stopped, will reopen", "iface", name, "err", err)
			}
			select {
			case exited <- name:
			default:
			}
		}()
	}
	scan := func() {
		ifs, err := net.Interfaces()
		if err != nil {
			return
		}
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp != 0 && dnsCaptureInterface(ifc.Name) {
				start(ifc.Name)
			}
		}
	}
	scan()
	mu.Lock()
	none := opened == 0
	err := lastErr
	mu.Unlock()
	if none && err != nil {
		msg := "BPF capture unavailable (needs root): " + err.Error()
		s.set(moduleBPF, api.SensorFailed, msg)
		return unavailable(errors.New(msg))
	}
	s.env.Log.Info("dns sensor running", "impl", moduleBPF)

	tr := newDNSTracker(moduleBPF, out.Emit)
	defer tr.flush()
	var local localAddrs
	sweep := time.NewTicker(dnsSweepEvery)
	defer sweep.Stop()
	rescan := time.NewTicker(dnsIfaceScan)
	defer rescan.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-frames:
			p, ok := parseDNSFrame(f.frame, f.dlt)
			if !ok || !local.has(p.Local.Addr(), f.ts) {
				continue
			}
			p.TS = f.ts
			tr.handle(p)
		case now := <-sweep.C:
			tr.sweep(now.UTC())
		case <-rescan.C:
			scan()
		case <-exited:
			scan()
		}
	}
}

// bpfDevice is an open /dev/bpf bound to an interface with the DNS filter.
type bpfDevice struct {
	f    *os.File
	dlt  int
	size int
}

// Close closes the device.
func (d *bpfDevice) Close() { d.f.Close() }

func ioctlPtr(fd int, req uint, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}

// openBPFDevice opens the first free /dev/bpfN, attaches it to the interface and loads
// the DNS filter for the interface's link type.
func openBPFDevice(iface string) (*bpfDevice, error) {
	if len(iface) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name %q too long", iface)
	}
	var f *os.File
	var err error
	for i := 0; i < dnsMaxBPFDev; i++ {
		f, err = os.OpenFile("/dev/bpf"+strconv.Itoa(i), os.O_RDWR, 0)
		if err == nil {
			break
		}
		if errors.Is(err, unix.EBUSY) {
			continue
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, unavailable(fmt.Errorf("open /dev/bpf%d: %w", i, err))
		}
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		return nil, err
	}
	if f == nil || err != nil {
		return nil, fmt.Errorf("no free /dev/bpf device: %v", err)
	}
	fd := int(f.Fd()) // blocking mode: reads return after the read timeout
	fail := func(what string, err error) (*bpfDevice, error) {
		f.Close()
		return nil, fmt.Errorf("bpf %s %s: %w", iface, what, err)
	}
	// The buffer size must be set before the interface is bound.
	blen := uint32(dnsBPFBuffer)
	if err := ioctlPtr(fd, unix.BIOCSBLEN, unsafe.Pointer(&blen)); err != nil {
		return fail("set buffer size", err)
	}
	var ifr [32]byte // struct ifreq: the name, then the union
	copy(ifr[:], iface)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); err != nil {
		return fail("bind interface", err)
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fail("link type", err)
	}
	insns := dnsFilter(dlt)
	if insns == nil {
		return fail("link type", fmt.Errorf("unsupported type %d", dlt))
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: (*unix.BpfInsn)(unsafe.Pointer(&insns[0]))}
	if err := ioctlPtr(fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil {
		return fail("attach filter", err)
	}
	one := uint32(1)
	if err := ioctlPtr(fd, unix.BIOCIMMEDIATE, unsafe.Pointer(&one)); err != nil {
		return fail("immediate mode", err)
	}
	_ = ioctlPtr(fd, unix.BIOCSSEESENT, unsafe.Pointer(&one)) // the default; outgoing queries are the point
	tv := unix.Timeval{Sec: int64(dnsReadTimeout / time.Second)}
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fail("read timeout", err)
	}
	size, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil || size <= 0 {
		size = 4096
	}
	return &bpfDevice{f: f, dlt: dlt, size: size}, nil
}

// readLoop sends the captured frames to out (dropping them when it is full) until ctx
// ends or the device fails, for instance because the interface went away.
func (d *bpfDevice) readLoop(ctx context.Context, out chan<- bpfFrame) error {
	fd := int(d.f.Fd())
	buf := make([]byte, d.size)
	for ctx.Err() == nil {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return err
		}
		forEachBPFRecord(buf[:n], func(ts time.Time, frame []byte) {
			select {
			case out <- bpfFrame{ts: ts, dlt: d.dlt, frame: append([]byte(nil), frame...)}:
			default:
			}
		})
	}
	return nil
}
