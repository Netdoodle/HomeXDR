//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tcpStates names the kernel TCP states (include/net/tcp_states.h) as /proc/net shows
// them in hex.
var tcpStates = map[uint8]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
	6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
	12: "NEW_SYN_RECV",
}

const (
	stateEstablished = 1
	stateListen      = 10
	stateClose       = 7
)

// sockEntry is one line of /proc/net/{tcp,tcp6,udp,udp6}.
type sockEntry struct {
	Transport  string // tcp, udp
	Local      netip.AddrPort
	Remote     netip.AddrPort
	State      uint8
	UID        uint32
	Inode      uint64
	IPv6Family bool
}

// parseHexAddr decodes /proc/net address notation. The kernel prints each 32-bit word of
// the network-order address as a host-order integer ("%08X"), so on little-endian hosts
// every word's bytes appear reversed.
func parseHexAddr(s string) (netip.AddrPort, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		w := binary.BigEndian.Uint32(raw[i:])
		binary.NativeEndian.PutUint32(out[i:], w)
	}
	addr, _ := netip.AddrFromSlice(out)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

func parseProcNet(b []byte, transport string, v6 bool) []sockEntry {
	var out []sockEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	first := true
	for sc.Scan() {
		if first {
			first = false // header
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		l, err1 := parseHexAddr(f[1])
		r, err2 := parseHexAddr(f[2])
		st, err3 := strconv.ParseUint(f[3], 16, 8)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		uid, _ := strconv.ParseUint(f[7], 10, 32)
		ino, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, sockEntry{Transport: transport, Local: l, Remote: r, State: uint8(st), UID: uint32(uid), Inode: ino, IPv6Family: v6})
	}
	return out
}

// readSockets reads the given /proc/net tables ("tcp", "tcp6", "udp", "udp6").
func readSockets(tables ...string) []sockEntry {
	var out []sockEntry
	for _, t := range tables {
		b, err := os.ReadFile(filepath.Join(procRoot, "net", t))
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(b, strings.TrimSuffix(t, "6"), strings.HasSuffix(t, "6"))...)
	}
	return out
}

// socketOwners maps socket inodes to the PIDs that hold them, by scanning /proc/*/fd.
// When want is non-nil only those inodes are looked up.
func socketOwners(want map[uint64]bool) map[uint64]int64 {
	out := map[uint64]int64{}
	pids, _ := listPIDs()
	for _, pid := range pids {
		dir := procPath(pid, "fd")
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			l, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 64)
			if err != nil || (want != nil && !want[ino]) {
				continue
			}
			if _, ok := out[ino]; !ok {
				out[ino] = pid
			}
		}
		if want != nil && len(out) == len(want) {
			break
		}
	}
	return out
}
