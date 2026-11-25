package darwin

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// The DNS sensor's capture: a BPF device per network interface with a classic BPF
// filter that passes IPv4 and IPv6 UDP and TCP segments whose source or destination
// port is 53. Which end is the local host, and so which packets are the host's own
// queries and the answers to them, is decided in user space.

// Link-layer types (net/bpf.h) the sensor can read.
const (
	dltNull    = 0 // BSD loopback and tunnel interfaces: a 4-byte address family
	dltEN10MB  = 1 // Ethernet
	bpfSnapLen = 65535
)

// Classic BPF opcodes (net/bpf.h).
const (
	bpfLdW    = 0x20 // BPF_LD|BPF_W|BPF_ABS
	bpfLdH    = 0x28 // BPF_LD|BPF_H|BPF_ABS
	bpfLdB    = 0x30 // BPF_LD|BPF_B|BPF_ABS
	bpfLdIndH = 0x48 // BPF_LD|BPF_H|BPF_IND
	bpfLdxMsh = 0xb1 // BPF_LDX|BPF_B|BPF_MSH
	bpfJa     = 0x05
	bpfJeq    = 0x15 // BPF_JMP|BPF_JEQ|BPF_K
	bpfJset   = 0x45 // BPF_JMP|BPF_JSET|BPF_K
	bpfRet    = 0x06 // BPF_RET|BPF_K
)

// bpfInsn is one classic BPF instruction (struct bpf_insn).
type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// asmIns is an instruction whose jump targets are labels; "" falls through.
type asmIns struct {
	code   uint16
	k      uint32
	jt, jf string
	label  string // defined at this instruction
}

// assembleBPF resolves labels into relative jump offsets (forward jumps only).
func assembleBPF(prog []asmIns) ([]bpfInsn, error) {
	at := map[string]int{}
	for i, in := range prog {
		if in.label != "" {
			at[in.label] = i
		}
	}
	out := make([]bpfInsn, len(prog))
	off := func(from int, label string) (uint8, error) {
		if label == "" {
			return 0, nil
		}
		to, ok := at[label]
		if !ok || to <= from || to-from-1 > 255 {
			return 0, errors.New("bpf: bad jump to " + label)
		}
		return uint8(to - from - 1), nil
	}
	for i, in := range prog {
		o := bpfInsn{Code: in.code, K: in.k}
		var err error
		switch in.code {
		case bpfJeq, bpfJset:
			if o.Jt, err = off(i, in.jt); err != nil {
				return nil, err
			}
			if o.Jf, err = off(i, in.jf); err != nil {
				return nil, err
			}
		case bpfJa:
			to, ok := at[in.jt]
			if !ok || to <= i {
				return nil, errors.New("bpf: bad jump to " + in.jt)
			}
			o.K = uint32(to - i - 1)
		}
		out[i] = o
	}
	return out, nil
}

// dnsFilter builds the capture filter for a link type, or nil if the type is not
// supported. IPv4 fragments other than the first and IPv6 packets with extension
// headers are not matched.
func dnsFilter(dlt int) []bpfInsn {
	var head []asmIns
	var base uint32
	switch dlt {
	case dltEN10MB:
		base = 14
		head = []asmIns{
			{code: bpfLdH, k: 12},
			{code: bpfJeq, k: 0x0800, jt: "v4", jf: ""},
			{code: bpfJeq, k: 0x86dd, jt: "v6", jf: "drop"},
		}
	case dltNull:
		// The family is in host byte order, little endian on every supported Mac:
		// AF_INET 2 and AF_INET6 30 read big endian as below.
		base = 4
		head = []asmIns{
			{code: bpfLdW, k: 0},
			{code: bpfJeq, k: 0x02000000, jt: "v4", jf: ""},
			{code: bpfJeq, k: 0x1e000000, jt: "v6", jf: "drop"},
		}
	default:
		return nil
	}
	prog := append(head, []asmIns{
		// IPv4: UDP or TCP, not a later fragment, either port 53.
		{label: "v4", code: bpfLdB, k: base + 9},
		{code: bpfJeq, k: 17, jt: "v4p", jf: ""},
		{code: bpfJeq, k: 6, jt: "v4p", jf: "drop"},
		{label: "v4p", code: bpfLdH, k: base + 6},
		{code: bpfJset, k: 0x1fff, jt: "drop", jf: ""},
		{code: bpfLdxMsh, k: base},
		{code: bpfLdIndH, k: base},
		{code: bpfJeq, k: 53, jt: "accept", jf: ""},
		{code: bpfLdIndH, k: base + 2},
		{code: bpfJeq, k: 53, jt: "accept", jf: "drop"},
		// IPv6: UDP or TCP directly after the fixed header, either port 53.
		{label: "v6", code: bpfLdB, k: base + 6},
		{code: bpfJeq, k: 17, jt: "v6p", jf: ""},
		{code: bpfJeq, k: 6, jt: "v6p", jf: "drop"},
		{label: "v6p", code: bpfLdH, k: base + 40},
		{code: bpfJeq, k: 53, jt: "accept", jf: ""},
		{code: bpfLdH, k: base + 42},
		{code: bpfJeq, k: 53, jt: "accept", jf: "drop"},
		{label: "accept", code: bpfRet, k: bpfSnapLen},
		{label: "drop", code: bpfRet, k: 0},
	}...)
	out, err := assembleBPF(prog)
	if err != nil {
		panic(err) // a programming error, caught by the tests
	}
	return out
}

// bpfWordAlign rounds up to the BPF record alignment (4 bytes on macOS).
func bpfWordAlign(n int) int { return (n + 3) &^ 3 }

// forEachBPFRecord calls fn for every captured frame in a read from a BPF device:
// records of a struct bpf_hdr (timeval32, caplen, datalen, hdrlen) followed by the data,
// each padded to a word. Malformed trailing data ends the walk.
func forEachBPFRecord(buf []byte, fn func(ts time.Time, frame []byte)) {
	const minHdr = 18
	for len(buf) >= minHdr {
		sec := int32(binary.NativeEndian.Uint32(buf[0:]))
		usec := int32(binary.NativeEndian.Uint32(buf[4:]))
		caplen := int(binary.NativeEndian.Uint32(buf[8:]))
		hdrlen := int(binary.NativeEndian.Uint16(buf[16:]))
		if hdrlen < minHdr || hdrlen > len(buf) || caplen < 0 || caplen > len(buf)-hdrlen {
			return
		}
		fn(time.Unix(int64(sec), int64(usec)*1000).UTC(), buf[hdrlen:hdrlen+caplen])
		next := bpfWordAlign(hdrlen + caplen)
		if next > len(buf) {
			return
		}
		buf = buf[next:]
	}
}

// parseDNSFrame extracts a DNS message from a captured frame of the given link type.
// Whether it is a query or an answer is decided from the ports: a segment to port 53
// is a query from its source (the local end), one from port 53 an answer to its
// destination. The caller checks that the local end is a local address.
func parseDNSFrame(frame []byte, dlt int) (dnsPacket, bool) {
	var ip []byte
	switch dlt {
	case dltEN10MB:
		if len(frame) < 14 {
			return dnsPacket{}, false
		}
		ip = frame[14:]
	case dltNull:
		if len(frame) < 4 {
			return dnsPacket{}, false
		}
		ip = frame[4:]
	default:
		return dnsPacket{}, false
	}
	return parseDNSIPPacket(ip)
}

const (
	protoTCP = 6
	protoUDP = 17
)

// parseDNSIPPacket reads an IPv4 or IPv6 packet carrying UDP or TCP to or from port 53.
// TCP messages are read from the first segment only (the 2-byte length prefix and what
// follows it); a message that continues in later segments is marked Truncated.
func parseDNSIPPacket(b []byte) (dnsPacket, bool) {
	if len(b) < 1 {
		return dnsPacket{}, false
	}
	var src, dst netip.Addr
	var proto byte
	var l4 []byte
	be := binary.BigEndian
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return dnsPacket{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(be.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) || be.Uint16(b[6:])&0x1fff != 0 {
			return dnsPacket{}, false
		}
		proto = b[9]
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		l4 = b[ihl:total]
	case 6:
		if len(b) < 40 {
			return dnsPacket{}, false
		}
		plen := int(be.Uint16(b[4:]))
		if 40+plen > len(b) {
			return dnsPacket{}, false
		}
		proto = b[6]
		src, dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		l4 = b[40 : 40+plen]
	default:
		return dnsPacket{}, false
	}
	var p dnsPacket
	var sport, dport uint16
	switch proto {
	case protoUDP:
		if len(l4) < 8 {
			return dnsPacket{}, false
		}
		sport, dport = be.Uint16(l4[0:]), be.Uint16(l4[2:])
		ulen := int(be.Uint16(l4[4:]))
		if ulen < 8 || ulen > len(l4) {
			return dnsPacket{}, false
		}
		p.Payload = l4[8:ulen]
	case protoTCP:
		if len(l4) < 20 {
			return dnsPacket{}, false
		}
		sport, dport = be.Uint16(l4[0:]), be.Uint16(l4[2:])
		off := int(l4[12]>>4) * 4
		if off < 20 || off > len(l4) {
			return dnsPacket{}, false
		}
		data := l4[off:]
		if len(data) < 2+dnsHeaderLen {
			return dnsPacket{}, false
		}
		n := int(be.Uint16(data))
		data = data[2:]
		if n < dnsHeaderLen {
			return dnsPacket{}, false
		}
		if n > len(data) {
			p.Truncated = true
		} else {
			data = data[:n]
		}
		p.TCP, p.Payload = true, data
	default:
		return dnsPacket{}, false
	}
	srcAP, dstAP := netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)
	switch {
	case dport == 53 && sport != 53:
		p.Query, p.Local, p.Remote = true, srcAP, dstAP
	case sport == 53 && dport != 53:
		p.Local, p.Remote = dstAP, srcAP
	default:
		return dnsPacket{}, false
	}
	return p, true
}

// localAddrs is the set of the host's addresses, refreshed now and then. Packets whose
// local end is not one of them were forwarded by this host (Internet Sharing) or
// belong to a DNS server running here, and are not its own lookups.
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
	return l.set == nil || l.set[a.WithZone("")]
}

// dnsCaptureInterface says whether an interface carries the host's own DNS traffic:
// Ethernet and Wi-Fi, bridges, VPN and other tunnels, PPP and loopback. Peer-to-peer
// Wi-Fi (awdl, llw), the access-point and other virtual interfaces are left out.
func dnsCaptureInterface(name string) bool {
	for _, p := range []string{"en", "bridge", "utun", "ppp", "lo"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
