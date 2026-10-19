//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/event"
	"golang.org/x/sys/unix"
)

// Netlink proc connector constants (include/uapi/linux/connector.h, cn_proc.h).
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1

	procEventExec = 0x00000002
	procEventExit = 0x80000000

	nlmsgHdrLen = 16
	cnMsgLen    = 20
	// proc_event header: what u32, cpu u32, timestamp_ns u64.
	procEventHdrLen = 16
)

// procConnMsg is one decoded proc connector event.
type procConnMsg struct {
	What                 uint32
	PID, TGID            uint32
	ExitCode, ExitSignal uint32
}

// parseProcConn decodes one netlink datagram (which may hold several messages).
func parseProcConn(b []byte) []procConnMsg {
	var out []procConnMsg
	le := binary.NativeEndian
	for len(b) >= nlmsgHdrLen {
		msgLen := int(le.Uint32(b[0:]))
		if msgLen < nlmsgHdrLen || msgLen > len(b) {
			break
		}
		payload := b[nlmsgHdrLen:msgLen]
		if len(payload) >= cnMsgLen+procEventHdrLen+8 {
			idx, val := le.Uint32(payload[0:]), le.Uint32(payload[4:])
			if idx == cnIdxProc && val == cnValProc {
				ev := payload[cnMsgLen:]
				m := procConnMsg{What: le.Uint32(ev[0:])}
				data := ev[procEventHdrLen:]
				m.PID, m.TGID = le.Uint32(data[0:]), le.Uint32(data[4:])
				if m.What == procEventExit && len(data) >= 16 {
					m.ExitCode, m.ExitSignal = le.Uint32(data[8:]), le.Uint32(data[12:])
				}
				out = append(out, m)
			}
		}
		// Messages are 4-byte aligned.
		adv := (msgLen + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

func listenMsg() []byte {
	le := binary.NativeEndian
	b := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	le.PutUint32(b[0:], uint32(len(b)))       // nlmsg_len
	le.PutUint16(b[4:], unix.NLMSG_DONE)      // nlmsg_type
	le.PutUint16(b[6:], 0)                    // flags
	le.PutUint32(b[8:], 0)                    // seq
	le.PutUint32(b[12:], uint32(os.Getpid())) // pid
	le.PutUint32(b[16:], cnIdxProc)           // cn_msg.id.idx
	le.PutUint32(b[20:], cnValProc)           // cn_msg.id.val
	le.PutUint16(b[32:], 4)                   // cn_msg.len
	le.PutUint32(b[36:], procCnMcastListen)   // op
	return b
}

// initPIDNSInode is PROC_PID_INIT_INO, the inode of the initial PID namespace.
const initPIDNSInode = 0xEFFFFFFC

func openProcConn() (*os.File, error) {
	// The kernel ignores PROC_CN_MCAST_LISTEN from outside the initial user and PID
	// namespaces (cn_proc.c), so in a container or a WSL distribution the subscription
	// would silently receive nothing.
	if ino, err := pidNamespaceInode(); err == nil && ino != initPIDNSInode {
		return nil, unavailable(errors.New("the proc connector only works in the initial PID namespace"))
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, unavailable(fmt.Errorf("netlink socket: %w", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		unix.Close(fd)
		return nil, unavailable(fmt.Errorf("bind proc connector: %w", err))
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if err := unix.Sendto(fd, listenMsg(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, unavailable(fmt.Errorf("subscribe to proc events (needs CAP_NET_ADMIN): %w", err))
	}
	// A non-blocking fd wrapped in os.File uses the runtime poller, so Close unblocks Read.
	return os.NewFile(uintptr(fd), "proc-connector"), nil
}

func (s *processSensor) runProcConn(ctx context.Context, out platform.Emitter) error {
	f, err := openProcConn()
	if err != nil {
		return err
	}
	defer f.Close()
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	done := make(chan struct{})
	defer close(done)
	en := newEnricher(s.env, event.ModuleProcConn)
	if s.cfg.HashExecutables {
		en.startHashers(2, done)
	}
	// Remember start keys of processes we saw exec, for their exit events (the proc
	// connector does not carry start times and /proc is gone by then).
	starts := newLRU[uint32, uint64](65536)
	if pids, err := listPIDs(); err == nil {
		for _, pid := range pids {
			if k, err := startKey(pid); err == nil {
				starts.put(uint32(pid), k)
			}
		}
	}
	s.env.Log.Info("process sensor running", "impl", "procconn")
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == unix.ENOBUFS {
				s.env.Log.Warn("process sensor: proc connector overrun, events lost")
				continue
			}
			return fmt.Errorf("proc connector read: %w", err)
		}
		now := time.Now().UTC()
		for _, m := range parseProcConn(buf[:n]) {
			switch m.What {
			case procEventExec:
				pid := int64(m.TGID)
				st, err := readStat(pid)
				if err != nil {
					continue // already gone
				}
				pi := &procInfo{PID: pid, PPID: st.PPID, StartKey: st.StartTick, Comm: st.Comm}
				en.fillFromProc(pi)
				starts.put(m.TGID, st.StartTick)
				en.emitExec(en.execEvent(pi, now), pid, s.cfg.HashExecutables, out)
			case procEventExit:
				if m.PID != m.TGID {
					continue // a thread, not the process
				}
				start, ok := starts.get(m.TGID)
				if !ok {
					continue // started before us and never seen; no reliable entity ID
				}
				out.Emit(en.exitEvent(int64(m.TGID), start, "", m.ExitCode, true, now))
			}
		}
	}
}
