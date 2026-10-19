//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
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

// dns_event layout from bpf/dns.bpf.c.
const (
	dnsEvSend       = 1
	dnsEvRecv       = 2
	dnsEvPayloadOff = 96
	dnsEvPayloadMax = 512
	dnsEvSize       = dnsEvPayloadOff + dnsEvPayloadMax
)

// parseDNSRecord decodes a struct dns_event. The payload aliases b.
func parseDNSRecord(b []byte) (dnsPacket, error) {
	if len(b) < dnsEvSize {
		return dnsPacket{}, fmt.Errorf("dns record: %d bytes", len(b))
	}
	le := binary.NativeEndian
	typ := le.Uint32(b[0:])
	if typ != dnsEvSend && typ != dnsEvRecv {
		return dnsPacket{}, fmt.Errorf("dns record type %d", typ)
	}
	pr := &dnsProc{
		PID: le.Uint32(b[4:]), TID: le.Uint32(b[8:]), PPID: le.Uint32(b[12:]), UID: le.Uint32(b[16:]),
		StartNS: le.Uint64(b[32:]), ParentNS: le.Uint64(b[40:]), Comm: cstr(b[80:96]),
	}
	family := le.Uint16(b[20:])
	lport, rport := le.Uint16(b[22:]), le.Uint16(b[24:])
	n := min(int(le.Uint16(b[26:])), dnsEvPayloadMax)
	orig := int(le.Uint32(b[28:]))
	var local, remote netip.Addr
	switch family {
	case 2: // AF_INET
		local = netip.AddrFrom4([4]byte(b[48:52]))
		remote = netip.AddrFrom4([4]byte(b[64:68]))
	case 10: // AF_INET6; dual-stack sockets use IPv4-mapped addresses
		local = netip.AddrFrom16([16]byte(b[48:64])).Unmap()
		remote = netip.AddrFrom16([16]byte(b[64:80])).Unmap()
	default:
		return dnsPacket{}, fmt.Errorf("family %d", family)
	}
	return dnsPacket{
		Query:     typ == dnsEvSend,
		Local:     netip.AddrPortFrom(local, lport),
		Remote:    netip.AddrPortFrom(remote, rport),
		Payload:   b[dnsEvPayloadOff : dnsEvPayloadOff+n],
		Truncated: orig > n,
		Proc:      pr,
	}, nil
}

// dnsHook attaches one program of bpf/dns.bpf.c.
type dnsHook struct {
	prog   string // program name in the object
	fn     string // kernel function
	kind   string // "tracing", "kprobe" or "kretprobe"
	ipv6   bool
	attach func(*ebpf.Program) (link.Link, error)
}

func tracingHook(prog, fn string, ipv6 bool) dnsHook {
	return dnsHook{prog: prog, fn: fn, kind: "tracing", ipv6: ipv6, attach: func(p *ebpf.Program) (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{Program: p})
	}}
}

func kprobeHook(prog, fn string, ipv6, ret bool) dnsHook {
	h := dnsHook{prog: prog, fn: fn, kind: "kprobe", ipv6: ipv6, attach: func(p *ebpf.Program) (link.Link, error) {
		return link.Kprobe(fn, p, nil)
	}}
	if ret {
		h.kind = "kretprobe"
		h.attach = func(p *ebpf.Program) (link.Link, error) { return link.Kretprobe(fn, p, nil) }
	}
	return h
}

// dnsHookSet is one way of attaching the programs; the sets are tried in order.
type dnsHookSet struct {
	name  string
	hooks []dnsHook
	// optionalV6: the IPv6 hooks may fail to attach (reported as degraded).
	optionalV6 bool
}

var (
	dnsTracingV4 = []dnsHook{
		tracingHook(bpf.DnsProgHxDnsSend4, "udp_sendmsg", false),
		tracingHook(bpf.DnsProgHxDnsRecv4, "udp_recvmsg", false),
		tracingHook(bpf.DnsProgHxDnsRecv4Ret, "udp_recvmsg", false),
	}
	dnsTracingV6 = []dnsHook{
		tracingHook(bpf.DnsProgHxDnsSend6, "udpv6_sendmsg", true),
		tracingHook(bpf.DnsProgHxDnsRecv6, "udpv6_recvmsg", true),
		tracingHook(bpf.DnsProgHxDnsRecv6Ret, "udpv6_recvmsg", true),
	}
	dnsHookSets = []dnsHookSet{
		// BPF trampolines: no instance limit, low overhead (x86-64 5.5+, arm64 6.0+).
		{name: "fentry", hooks: append(append([]dnsHook{}, dnsTracingV4...), dnsTracingV6...)},
		// The IPv6 functions are not in the kernel's BTF (IPv6 compiled out or its module
		// not loaded).
		{name: "fentry, IPv4 only", hooks: dnsTracingV4},
		// kprobes. A kretprobe has a bounded pool of instances, held while a thread
		// blocks in recvmsg; answers can be missed if many threads do.
		{name: "kprobe", optionalV6: true, hooks: []dnsHook{
			kprobeHook(bpf.DnsProgHxDnsKsend4, "udp_sendmsg", false, false),
			kprobeHook(bpf.DnsProgHxDnsKrecv4, "udp_recvmsg", false, false),
			kprobeHook(bpf.DnsProgHxDnsKrecv4Ret, "udp_recvmsg", false, true),
			kprobeHook(bpf.DnsProgHxDnsKsend6, "udpv6_sendmsg", true, false),
			kprobeHook(bpf.DnsProgHxDnsKrecv6, "udpv6_recvmsg", true, false),
			kprobeHook(bpf.DnsProgHxDnsKrecv6Ret, "udpv6_recvmsg", true, true),
		}},
	}
)

// ipv6Enabled reports whether the kernel has IPv6 (so IPv6 DNS can happen).
func ipv6Enabled() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

// dnsBPF is a loaded and attached DNS collection.
type dnsBPF struct {
	coll  *ebpf.Collection
	links []link.Link
	mode  string // the hook set used
	// note explains reduced coverage (IPv6 not hooked); "" when complete.
	note string
}

func (d *dnsBPF) Close() {
	for _, l := range d.links {
		l.Close()
	}
	d.coll.Close()
}

// loadDNSBPF loads the programs of the first hook set that loads and attaches.
func loadDNSBPF() (*dnsBPF, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, unavailable(fmt.Errorf("memlock rlimit: %w", err))
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, unavailable(errors.New("kernel BTF (/sys/kernel/btf/vmlinux) not available"))
	}
	sets := dnsHookSets
	if ipv6Enabled() {
		// Prefer kprobes that also cover IPv6 over IPv4-only trampolines.
		sets = []dnsHookSet{dnsHookSets[0], dnsHookSets[2], dnsHookSets[1]}
	}
	var errs []string
	for _, set := range sets {
		d, err := loadDNSHookSet(set)
		if err == nil {
			return d, nil
		}
		errs = append(errs, set.name+": "+err.Error())
	}
	return nil, unavailable(errors.New(strings.Join(errs, "; ")))
}

func loadDNSHookSet(set dnsHookSet) (*dnsBPF, error) {
	spec, err := bpf.LoadDns()
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, h := range set.hooks {
		keep[h.prog] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	if v, ok := spec.Variables[bpf.DnsVarTargetPidns]; ok {
		ino, err := pidNamespaceInode()
		if err != nil {
			return nil, fmt.Errorf("pid namespace: %w", err)
		}
		if err := v.Set(ino); err != nil {
			return nil, fmt.Errorf("set target_pidns: %w", err)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %v", ve)
		}
		return nil, fmt.Errorf("load: %w", err)
	}
	d := &dnsBPF{coll: coll, mode: set.name}
	var v6Errs []string
	for _, h := range set.hooks {
		l, err := h.attach(coll.Programs[h.prog])
		if err != nil {
			if set.optionalV6 && h.ipv6 {
				v6Errs = append(v6Errs, fmt.Sprintf("%s %s: %v", h.kind, h.fn, err))
				continue
			}
			d.Close()
			return nil, fmt.Errorf("attach %s %s: %w", h.kind, h.fn, err)
		}
		d.links = append(d.links, l)
	}
	if !ipv6Enabled() {
		return d, nil
	}
	if len(v6Errs) > 0 {
		d.note = "IPv6 DNS not covered: " + strings.Join(v6Errs, "; ")
	} else if !hasIPv6Hooks(set.hooks) {
		d.note = "IPv6 DNS not covered: the kernel's udpv6 functions cannot be traced"
	}
	return d, nil
}

func hasIPv6Hooks(hs []dnsHook) bool {
	for _, h := range hs {
		if h.ipv6 {
			return true
		}
	}
	return false
}

func (s *dnsSensor) runEBPF(ctx context.Context, out platform.Emitter) error {
	d, err := s.loadBPF()
	if err != nil {
		return err
	}
	defer d.Close()
	rd, err := ringbuf.NewReader(d.coll.Maps[bpf.DnsMapDnsEvents])
	if err != nil {
		return unavailable(fmt.Errorf("ring buffer: %w", err))
	}
	defer rd.Close()
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	if d.note != "" {
		s.env.Log.Warn("dns sensor: reduced coverage", "note", d.note)
		s.set(event.ModuleEBPF, api.SensorDegraded, d.note)
	}
	s.env.Log.Info("dns sensor running", "impl", "ebpf", "hooks", d.mode)

	tr := s.newTracker(event.ModuleEBPF, out)
	defer tr.flush()
	var rec ringbuf.Record
	for {
		rd.SetDeadline(time.Now().Add(dnsSweepEvery))
		err := rd.ReadInto(&rec)
		now := time.Now().UTC()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				tr.sweep(now)
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ring buffer read: %w", err)
		}
		p, err := parseDNSRecord(rec.RawSample)
		if err != nil || p.Proc.PID == s.self {
			continue // the agent's own lookups (its server's name) are not reported
		}
		p.TS = now
		tr.handle(p)
	}
}
