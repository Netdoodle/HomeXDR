//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/platform/linux/bpf"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// net_event layout from bpf/network.bpf.c.
const (
	netConnect       = 1
	netAccept        = 2
	netConnectFailed = 3
	netEventSize     = 80
)

type netRecord struct {
	Type          uint32
	PID, TID, UID uint32
	StartNS       uint64
	Family        uint16
	SPort, DPort  uint16
	Local, Remote netip.Addr
	Comm          string
}

func parseNetRecord(b []byte) (netRecord, error) {
	if len(b) < netEventSize {
		return netRecord{}, fmt.Errorf("net record: %d bytes", len(b))
	}
	le := binary.NativeEndian
	r := netRecord{
		Type: le.Uint32(b[0:]), PID: le.Uint32(b[4:]), TID: le.Uint32(b[8:]), UID: le.Uint32(b[12:]),
		StartNS: le.Uint64(b[16:]), Family: le.Uint16(b[24:]), SPort: le.Uint16(b[26:]), DPort: le.Uint16(b[28:]),
		Comm: cstr(b[64:80]),
	}
	switch r.Family {
	case 2: // AF_INET
		r.Local = netip.AddrFrom4([4]byte(b[32:36]))
		r.Remote = netip.AddrFrom4([4]byte(b[48:52]))
	case 10: // AF_INET6
		r.Local = netip.AddrFrom16([16]byte(b[32:48])).Unmap()
		r.Remote = netip.AddrFrom16([16]byte(b[48:64])).Unmap()
	default:
		return r, fmt.Errorf("family %d", r.Family)
	}
	return r, nil
}

// networkSensor reports TCP connections: eBPF with process attribution, or /proc/net
// polling as a fallback.
type networkSensor struct {
	sensorState
	env   platform.Env
	self  uint32
	execs *lru[string, string] // entity ID -> executable
}

func newNetworkSensor(env platform.Env) *networkSensor {
	return &networkSensor{sensorState: sensorState{name: "network"}, env: env, self: uint32(os.Getpid()),
		execs: newLRU[string, string](8192)}
}

// Name returns "network".
func (s *networkSensor) Name() string { return "network" }

// Run uses eBPF, falling back to polling.
func (s *networkSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(event.ModuleEBPF, api.SensorRunning, "")
	err := s.runEBPF(ctx, out)
	if err == nil || !isUnavailable(err) {
		return err
	}
	s.env.Log.Warn("network sensor: eBPF unavailable, polling /proc/net", "err", err)
	s.set(event.ModuleProcfs, api.SensorDegraded, "eBPF unavailable: "+err.Error())
	return s.runPoll(ctx, out)
}

func (s *networkSensor) runEBPF(ctx context.Context, out platform.Emitter) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return unavailable(fmt.Errorf("memlock rlimit: %w", err))
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return unavailable(errors.New("kernel BTF not available"))
	}
	objs := &bpf.NetworkObjects{}
	if err := loadObjects(bpf.LoadNetwork, objs); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return unavailable(fmt.Errorf("verifier: %v", ve))
		}
		return unavailable(fmt.Errorf("load: %w", err))
	}
	defer objs.Close()
	tl, err := link.AttachTracing(link.TracingOptions{Program: objs.HxSetState})
	if err != nil {
		return unavailable(fmt.Errorf("attach inet_sock_set_state: %w", err))
	}
	defer tl.Close()
	if kl, err := link.Kretprobe("inet_csk_accept", objs.HxAccept, nil); err != nil {
		// Outbound connections still work; inbound ones are not reported.
		s.env.Log.Warn("network sensor: cannot attach accept probe; inbound connections not reported", "err", err)
		s.set(event.ModuleEBPF, api.SensorDegraded, "accept probe unavailable: "+err.Error())
	} else {
		defer kl.Close()
	}
	rd, err := ringbuf.NewReader(objs.NetworkEvents)
	if err != nil {
		return unavailable(fmt.Errorf("ring buffer: %w", err))
	}
	defer rd.Close()
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	s.env.Log.Info("network sensor running", "impl", "ebpf")
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ring buffer read: %w", err)
		}
		r, err := parseNetRecord(rec.RawSample)
		if err != nil || r.PID == s.self {
			continue // the agent's own server traffic is not reported
		}
		out.Emit(s.eventFromRecord(r, time.Now().UTC()))
	}
}

func (s *networkSensor) eventFromRecord(r netRecord, ts time.Time) *event.Event {
	pid := int64(r.PID)
	entity := s.env.EntityID(pid, StartKeyFromNS(r.StartNS))
	exe, ok := s.execs.get(entity)
	if !ok {
		exe = readLink(pid, "exe")
		if exe != "" {
			s.execs.put(entity, exe)
		}
	}
	name := r.Comm
	if exe != "" {
		name = filepath.Base(exe)
	}
	proc := &event.Process{
		EntityID: entity, PID: pid, Name: name, Executable: exe,
		User: &event.User{ID: strconv.FormatUint(uint64(r.UID), 10), Name: users.name(r.UID)},
	}
	local := netip.AddrPortFrom(r.Local, r.SPort)
	remote := netip.AddrPortFrom(r.Remote, r.DPort)
	switch r.Type {
	case netAccept:
		return connEvent("tcp", event.DirectionInbound, "connection_accepted", event.OutcomeSuccess, local, remote, proc, event.ModuleEBPF, ts)
	case netConnectFailed:
		return connEvent("tcp", event.DirectionOutbound, "connection_failed", event.OutcomeFailure, local, remote, proc, event.ModuleEBPF, ts)
	default:
		return connEvent("tcp", event.DirectionOutbound, "connection_attempted", event.OutcomeSuccess, local, remote, proc, event.ModuleEBPF, ts)
	}
}

// connEvent builds a network connection event. For inbound connections the remote end
// is the source; for outbound ones the local end is. community_id is left to the server.
func connEvent(transport, dir, action, outcome string, local, remote netip.AddrPort, proc *event.Process, module string, ts time.Time) *event.Event {
	src, dst := local, remote
	if dir == event.DirectionInbound {
		src, dst = remote, local
	}
	typ := "ipv4"
	if local.Addr().Is6() {
		typ = "ipv6"
	}
	types := []string{event.TypeConnection, event.TypeStart}
	if outcome == event.OutcomeFailure {
		types = []string{event.TypeConnection}
	}
	msg := fmt.Sprintf("%s %s %s -> %s", transport, action, src, dst)
	if proc != nil && proc.Name != "" {
		msg += " (" + proc.Name + ")"
	}
	return &event.Event{
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryNetwork}, Type: types,
			Action: action, Outcome: outcome, Module: module, Dataset: "network",
		},
		Message:     msg,
		Network:     &event.Network{Transport: transport, Type: typ, Direction: dir},
		Source:      &event.Endpoint{IP: src.Addr().String(), Port: int(src.Port())},
		Destination: &event.Endpoint{IP: dst.Addr().String(), Port: int(dst.Port())},
		Process:     proc,
	}
}

// runPoll compares /proc/net/tcp{,6} snapshots every few seconds and reports new
// established connections. Connections shorter than the interval are missed; the owning
// process is found by socket inode when it still holds the socket.
func (s *networkSensor) runPoll(ctx context.Context, out platform.Emitter) error {
	type key struct {
		l, r  netip.AddrPort
		inode uint64
	}
	seen := map[key]bool{}
	for _, e := range readSockets("tcp", "tcp6") {
		if e.State == stateEstablished {
			seen[key{e.Local, e.Remote, e.Inode}] = true
		}
	}
	s.env.Log.Info("network sensor running", "impl", "procfs")
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		entries := readSockets("tcp", "tcp6")
		listening := map[uint16]bool{}
		for _, e := range entries {
			if e.State == stateListen {
				listening[e.Local.Port()] = true
			}
		}
		cur := map[key]bool{}
		var fresh []sockEntry
		want := map[uint64]bool{}
		for _, e := range entries {
			if e.State != stateEstablished {
				continue
			}
			k := key{e.Local, e.Remote, e.Inode}
			cur[k] = true
			if !seen[k] {
				fresh = append(fresh, e)
				if e.Inode != 0 {
					want[e.Inode] = true
				}
			}
		}
		seen = cur
		if len(fresh) == 0 {
			continue
		}
		owners := socketOwners(want)
		now := time.Now().UTC()
		for _, e := range fresh {
			var proc *event.Process
			if pid, ok := owners[e.Inode]; ok {
				if pid == int64(s.self) {
					continue
				}
				proc = &event.Process{PID: pid, Executable: readLink(pid, "exe")}
				if k, err := startKey(pid); err == nil {
					proc.EntityID = s.env.EntityID(pid, k)
				}
				if proc.Executable != "" {
					proc.Name = filepath.Base(proc.Executable)
				}
			}
			dir := event.DirectionOutbound
			if listening[e.Local.Port()] {
				dir = event.DirectionInbound
			}
			action := "connection_attempted"
			if dir == event.DirectionInbound {
				action = "connection_accepted"
			}
			ev := connEvent("tcp", dir, action, event.OutcomeSuccess, e.Local, e.Remote, proc, event.ModuleProcfs, now)
			if proc != nil {
				proc.User = &event.User{ID: strconv.FormatUint(uint64(e.UID), 10), Name: users.name(e.UID)}
			}
			out.Emit(ev)
		}
	}
}
