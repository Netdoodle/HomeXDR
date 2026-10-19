//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"golang.org/x/sys/unix"
)

// The DNS sensor's fallback: an AF_PACKET socket in cooked mode (SOCK_DGRAM, so every
// packet starts at its IP header whatever the link type) with a classic BPF filter that
// passes only UDP datagrams leaving with destination port 53 or arriving with source
// port 53. It needs CAP_NET_RAW, sees only the agent's network namespace, and cannot
// tell which process sent a query.

// Ancillary loads of classic BPF (include/uapi/linux/filter.h); not in x/sys/unix.
const (
	skfAdOff      = 0xfffff000 // SKF_AD_OFF (-0x1000)
	skfAdProtocol = 0          // skb->protocol, host order
	skfAdPktType  = 4          // skb->pkt_type
)

func bpfStmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// dnsPacketFilter accepts outgoing UDP to port 53 and incoming UDP from port 53, IPv4
// (first fragments only) and IPv6 (without extension headers).
var dnsPacketFilter = []unix.SockFilter{
	/* 0 */ bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, skfAdOff+skfAdProtocol),
	/* 1 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.ETH_P_IP, 0, 11), // IPv6 at 13
	// IPv4
	/* 2 */ bpfStmt(unix.BPF_LD|unix.BPF_B|unix.BPF_ABS, 9), // protocol
	/* 3 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.IPPROTO_UDP, 0, 19),
	/* 4 */ bpfStmt(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 6), // flags, fragment offset
	/* 5 */ bpfJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, 0x1fff, 17, 0),
	/* 6 */ bpfStmt(unix.BPF_LDX|unix.BPF_B|unix.BPF_MSH, 0), // X = IP header length
	/* 7 */ bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, skfAdOff+skfAdPktType),
	/* 8 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.PACKET_OUTGOING, 2, 0),
	/* 9 */ bpfStmt(unix.BPF_LD|unix.BPF_H|unix.BPF_IND, 0), // incoming: source port
	/* 10 */ bpfStmt(unix.BPF_JMP|unix.BPF_JA, 1),
	/* 11 */ bpfStmt(unix.BPF_LD|unix.BPF_H|unix.BPF_IND, 2), // outgoing: destination port
	/* 12 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 53, 9, 10),
	// IPv6
	/* 13 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.ETH_P_IPV6, 0, 9),
	/* 14 */ bpfStmt(unix.BPF_LD|unix.BPF_B|unix.BPF_ABS, 6), // next header
	/* 15 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.IPPROTO_UDP, 0, 7),
	/* 16 */ bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, skfAdOff+skfAdPktType),
	/* 17 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.PACKET_OUTGOING, 2, 0),
	/* 18 */ bpfStmt(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 40), // incoming: source port
	/* 19 */ bpfStmt(unix.BPF_JMP|unix.BPF_JA, 1),
	/* 20 */ bpfStmt(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 42), // outgoing: destination port
	/* 21 */ bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 53, 0, 1),
	/* 22 */ bpfStmt(unix.BPF_RET|unix.BPF_K, 0xffff), // accept
	/* 23 */ bpfStmt(unix.BPF_RET|unix.BPF_K, 0), // drop
}

// hton16 converts a 16-bit value to network byte order.
func hton16(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func openDNSPacketSocket() (*os.File, error) {
	// Protocol 0 receives nothing until bind, so no unfiltered packet slips in before
	// the filter is attached.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, unavailable(fmt.Errorf("packet socket (needs CAP_NET_RAW): %w", err))
	}
	prog := unix.SockFprog{Len: uint16(len(dnsPacketFilter)), Filter: &dnsPacketFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return nil, unavailable(fmt.Errorf("attach packet filter: %w", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: hton16(unix.ETH_P_ALL)}); err != nil {
		unix.Close(fd)
		return nil, unavailable(fmt.Errorf("bind packet socket: %w", err))
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 2<<20)
	// A non-blocking fd wrapped in os.File uses the runtime poller: Close and read
	// deadlines unblock reads.
	return os.NewFile(uintptr(fd), "dns-packet"), nil
}

// parseDNSIPPacket extracts a DNS message from an IPv4 or IPv6 packet with a UDP
// header. outgoing says which end is local.
func parseDNSIPPacket(b []byte, outgoing bool) (dnsPacket, bool) {
	if len(b) < 1 {
		return dnsPacket{}, false
	}
	var src, dst netip.Addr
	var udp []byte
	be := binary.BigEndian
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return dnsPacket{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(be.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) || b[9] != unix.IPPROTO_UDP || be.Uint16(b[6:])&0x1fff != 0 {
			return dnsPacket{}, false
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		udp = b[ihl:total]
	case 6:
		if len(b) < 40 || b[6] != unix.IPPROTO_UDP {
			return dnsPacket{}, false
		}
		plen := int(be.Uint16(b[4:]))
		if 40+plen > len(b) {
			return dnsPacket{}, false
		}
		src, dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		udp = b[40 : 40+plen]
	default:
		return dnsPacket{}, false
	}
	if len(udp) < 8 {
		return dnsPacket{}, false
	}
	sport, dport := be.Uint16(udp[0:]), be.Uint16(udp[2:])
	ulen := int(be.Uint16(udp[4:]))
	if ulen < 8 || ulen > len(udp) {
		return dnsPacket{}, false
	}
	p := dnsPacket{Payload: udp[8:ulen]}
	srcAP, dstAP := netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)
	if outgoing {
		p.Query, p.Local, p.Remote = true, srcAP, dstAP
	} else {
		p.Local, p.Remote = dstAP, srcAP
	}
	if (p.Query && dport != 53) || (!p.Query && sport != 53) {
		return dnsPacket{}, false
	}
	return p, true
}

// localAddrs is the set of the host's addresses, refreshed now and then. Packets whose
// local end is not one of them were forwarded by this host (a router, or DNAT to a
// container) and are not its own DNS traffic.
type localAddrs struct {
	set     map[netip.Addr]bool
	refresh time.Time
}

func (l *localAddrs) has(a netip.Addr, now time.Time) bool {
	if a.IsLoopback() {
		return true
	}
	if l.set == nil || now.Sub(l.refresh) > 30*time.Second {
		l.refresh = now
		if addrs, err := net.InterfaceAddrs(); err == nil {
			l.set = map[netip.Addr]bool{}
			for _, ia := range addrs {
				if n, ok := ia.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(n.IP); ok {
						l.set[ip.Unmap()] = true
					}
				}
			}
		}
	}
	return l.set == nil || l.set[a]
}

func (s *dnsSensor) runPacket(ctx context.Context, out platform.Emitter) error {
	f, err := s.openPacket()
	if err != nil {
		return err
	}
	defer f.Close()
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	rc, err := f.SyscallConn()
	if err != nil {
		return unavailable(fmt.Errorf("packet socket: %w", err))
	}
	s.env.Log.Info("dns sensor running", "impl", moduleAFPacket)
	tr := s.newTracker(moduleAFPacket, out)
	defer tr.flush()
	var local localAddrs
	buf := make([]byte, 65536)
	for {
		var (
			n    int
			from unix.Sockaddr
			rerr error
		)
		f.SetReadDeadline(time.Now().Add(dnsSweepEvery))
		err := rc.Read(func(fd uintptr) bool {
			n, from, rerr = unix.Recvfrom(int(fd), buf, 0)
			return rerr != unix.EAGAIN
		})
		now := time.Now().UTC()
		if err == nil {
			err = rerr
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				tr.sweep(now)
				continue
			}
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
				continue
			}
			return fmt.Errorf("packet socket read: %w", err)
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || n > len(buf) {
			continue
		}
		p, ok := parseDNSIPPacket(buf[:n], ll.Pkttype == unix.PACKET_OUTGOING)
		if !ok || !local.has(p.Local.Addr(), now) {
			continue
		}
		p.TS = now
		tr.handle(p)
	}
}
