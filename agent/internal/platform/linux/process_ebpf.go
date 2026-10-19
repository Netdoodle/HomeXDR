//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/platform/linux/bpf"
	"github.com/Netdoodle/homexdr/shared/event"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Event layouts from bpf/process.bpf.c.
const (
	evExec = 1
	evExit = 2

	execArgsOff     = 328
	execArgsMax     = 4096
	execEventSize   = execArgsOff + execArgsMax
	exitEventSize   = 40
	execCommOff     = 56
	execFilenameOff = 72
)

// execRecord is the decoded struct exec_event.
type execRecord struct {
	PID, TID, PPID    uint32
	UID, GID, EUID    uint32
	StartNS, ParentNS uint64
	Comm, Filename    string
	Args              []string
	Truncated         bool
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func parseExecRecord(b []byte) (execRecord, error) {
	if len(b) < execEventSize {
		return execRecord{}, fmt.Errorf("exec record: %d bytes", len(b))
	}
	le := binary.NativeEndian
	r := execRecord{
		PID: le.Uint32(b[4:]), TID: le.Uint32(b[8:]), PPID: le.Uint32(b[12:]),
		UID: le.Uint32(b[16:]), GID: le.Uint32(b[20:]), EUID: le.Uint32(b[24:]),
		StartNS: le.Uint64(b[32:]), ParentNS: le.Uint64(b[40:]),
		Truncated: le.Uint32(b[48:]) != 0,
		Comm:      cstr(b[execCommOff : execCommOff+16]),
		Filename:  cstr(b[execFilenameOff : execFilenameOff+256]),
	}
	n := int(le.Uint32(b[28:]))
	if n > execArgsMax {
		n = execArgsMax
	}
	r.Args = splitNul(b[execArgsOff : execArgsOff+n])
	return r, nil
}

type exitRecord struct {
	PID, PPID uint32
	Status    uint32
	StartNS   uint64
	Comm      string
}

func parseExitRecord(b []byte) (exitRecord, error) {
	if len(b) < exitEventSize {
		return exitRecord{}, fmt.Errorf("exit record: %d bytes", len(b))
	}
	le := binary.NativeEndian
	return exitRecord{
		PID: le.Uint32(b[4:]), PPID: le.Uint32(b[8:]), Status: le.Uint32(b[12:]),
		StartNS: le.Uint64(b[16:]), Comm: cstr(b[24:40]),
	}, nil
}

// pidNamespaceInode returns the inode of the agent's PID namespace, which the BPF
// programs use to report PIDs as the agent sees them (see bpf/hx_pidns.h).
func pidNamespaceInode() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, err
	}
	return uint32(st.Ino), nil
}

// loadObjects loads a bpf2go collection with target_pidns set.
func loadObjects(load func() (*ebpf.CollectionSpec, error), objs any) error {
	spec, err := load()
	if err != nil {
		return err
	}
	if v, ok := spec.Variables["target_pidns"]; ok {
		ino, err := pidNamespaceInode()
		if err != nil {
			return fmt.Errorf("pid namespace: %w", err)
		}
		if err := v.Set(ino); err != nil {
			return fmt.Errorf("set target_pidns: %w", err)
		}
	}
	return spec.LoadAndAssign(objs, nil)
}

// loadProcessBPF loads and attaches the process programs. Any failure here means eBPF
// cannot be used on this host.
func loadProcessBPF() (*bpf.ProcessObjects, []link.Link, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, unavailable(fmt.Errorf("memlock rlimit: %w", err))
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, nil, unavailable(errors.New("kernel BTF (/sys/kernel/btf/vmlinux) not available"))
	}
	objs := &bpf.ProcessObjects{}
	if err := loadObjects(bpf.LoadProcess, objs); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, nil, unavailable(fmt.Errorf("verifier: %v", ve))
		}
		return nil, nil, unavailable(fmt.Errorf("load: %w", err))
	}
	var links []link.Link
	for _, p := range []*ebpf.Program{objs.HxExec, objs.HxExit} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, nil, unavailable(fmt.Errorf("attach: %w", err))
		}
		links = append(links, l)
	}
	return objs, links, nil
}

func (s *processSensor) runEBPF(ctx context.Context, out platform.Emitter) error {
	objs, links, err := loadProcessBPF()
	if err != nil {
		return err
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}()
	rd, err := ringbuf.NewReader(objs.ProcessEvents)
	if err != nil {
		return unavailable(fmt.Errorf("ring buffer: %w", err))
	}
	defer rd.Close()
	go func() {
		<-ctx.Done()
		rd.Close() // unblocks Read
	}()

	done := make(chan struct{})
	defer close(done)
	en := newEnricher(s.env, event.ModuleEBPF)
	if s.cfg.HashExecutables {
		en.startHashers(2, done)
	}
	s.env.Log.Info("process sensor running", "impl", "ebpf")
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ring buffer read: %w", err)
		}
		s.handleRecord(en, rec.RawSample, out)
	}
}

func (s *processSensor) handleRecord(en *enricher, raw []byte, out platform.Emitter) {
	if len(raw) < 4 {
		return
	}
	now := time.Now().UTC()
	switch binary.NativeEndian.Uint32(raw) {
	case evExec:
		r, err := parseExecRecord(raw)
		if err != nil {
			return
		}
		pi := &procInfo{
			PID: int64(r.PID), PPID: int64(r.PPID),
			StartKey: StartKeyFromNS(r.StartNS), ParentStartKey: StartKeyFromNS(r.ParentNS), HasParentKey: r.PPID != 0,
			UID: r.UID, GID: r.GID, EUID: r.EUID, HasCreds: true,
			Comm: r.Comm, Filename: r.Filename, Args: r.Args, ArgsTruncated: r.Truncated,
		}
		en.fillFromProc(pi)
		en.emitExec(en.execEvent(pi, now), pi.PID, s.cfg.HashExecutables, out)
	case evExit:
		r, err := parseExitRecord(raw)
		if err != nil {
			return
		}
		out.Emit(en.exitEvent(int64(r.PID), StartKeyFromNS(r.StartNS), r.Comm, r.Status, true, now))
	}
}
