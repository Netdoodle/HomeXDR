package darwin

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ---- lsof ----

// sockEntry is one socket from `lsof -F`.
type sockEntry struct {
	PID       int64
	Command   string
	UID       uint32
	Transport string // tcp, udp
	State     string // ESTABLISHED, LISTEN, ... ("" for UDP)
	Local     netip.AddrPort
	Remote    netip.AddrPort // invalid when not connected
}

// lsofArgs lists Internet sockets in the field output format: one field per line, the
// first character naming it (p PID, c command, u UID, f file descriptor, P protocol,
// n name, T TCP info such as ST=ESTABLISHED).
var lsofArgs = []string{"-nP", "-i", "-Ts", "-FpcufPnT", "+c0"}

// parseLsof parses `lsof -F pcufPnT` output.
func parseLsof(b []byte) []sockEntry {
	var out []sockEntry
	var pid int64
	var cmd string
	var uid uint32
	var cur *sockEntry
	flush := func() {
		if cur != nil && cur.Local.IsValid() {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			flush()
			pid, _ = strconv.ParseInt(v, 10, 64)
			cmd, uid = "", 0
		case 'c':
			cmd = v
		case 'u':
			n, _ := strconv.ParseUint(v, 10, 32)
			uid = uint32(n)
		case 'f':
			flush()
			cur = &sockEntry{PID: pid, Command: cmd, UID: uid}
		case 'P':
			if cur != nil {
				cur.Transport = strings.ToLower(v)
			}
		case 'n':
			if cur != nil {
				cur.Local, cur.Remote = parseLsofName(v)
			}
		case 'T':
			if cur != nil && strings.HasPrefix(v, "ST=") {
				cur.State = v[3:]
			}
		}
	}
	flush()
	return out
}

// parseLsofName parses "10.0.0.2:51515->1.2.3.4:443", "[::1]:631", "*:22" or
// "*:*" (an unbound UDP socket).
func parseLsofName(s string) (local, remote netip.AddrPort) {
	l, r, _ := strings.Cut(s, "->")
	local = parseLsofAddr(l)
	if r != "" {
		remote = parseLsofAddr(r)
	}
	return local, remote
}

func parseLsofAddr(s string) netip.AddrPort {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}
	}
	host, port := s[:i], s[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		if port != "*" {
			return netip.AddrPort{}
		}
		p = 0
	}
	var a netip.Addr
	if host == "*" {
		a = netip.IPv4Unspecified()
		if strings.HasPrefix(s, "[") {
			a = netip.IPv6Unspecified()
		}
	} else {
		if z := strings.IndexByte(host, '%'); z >= 0 {
			host = host[:z]
		}
		var err error
		if a, err = netip.ParseAddr(host); err != nil {
			return netip.AddrPort{}
		}
		// The BSD kernel embeds the interface index in the second word of link-local
		// addresses (fe80:4::1 is fe80::1 on interface 4).
		if a.Is6() && a.IsLinkLocalUnicast() {
			b := a.As16()
			b[2], b[3] = 0, 0
			a = netip.AddrFrom16(b)
		}
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(p))
}

// ---- kern.procargs2 ----

// parseProcArgs parses a kern.procargs2 buffer: argc (int32), the executable path, NUL
// padding, then argc NUL-terminated arguments, then the environment (ignored).
func parseProcArgs(b []byte) (exe string, args []string, err error) {
	if len(b) < 4 {
		return "", nil, errors.New("short procargs")
	}
	argc := int(binary.LittleEndian.Uint32(b))
	b = b[4:]
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), nil, nil
	}
	exe = string(b[:i])
	b = b[i:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	for n := 0; n < argc && len(b) > 0; n++ {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			args = append(args, string(b))
			break
		}
		args = append(args, string(b[:j]))
		b = b[j+1:]
	}
	return exe, args, nil
}

// ---- who ----

// whoEntry is one line of `who`.
type whoEntry struct {
	User, Line, Host string
	Time             time.Time
}

// parseWho parses `who` output: "alex  console  Nov 12 09:14" or
// "alex  ttys001  Nov 12 10:02  (192.168.1.20)". who prints no year; the most recent
// matching date not in the future is used.
func parseWho(b []byte, now time.Time) []whoEntry {
	var out []whoEntry
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		e := whoEntry{User: f[0], Line: f[1]}
		if t, err := time.ParseInLocation("Jan 2 15:04", f[2]+" "+f[3]+" "+f[4], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			e.Time = t
		}
		if len(f) >= 6 && strings.HasPrefix(f[5], "(") {
			e.Host = strings.Trim(f[5], "()")
		}
		out = append(out, e)
	}
	return out
}

// ---- dscacheutil ----

// parseDSCache parses `dscacheutil -q user` / `-q group` output: blank-line-separated
// records of "key: value" lines.
func parseDSCache(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// ---- launchctl ----

// parseLaunchctlList parses `launchctl list`: "PID\tStatus\tLabel" lines, "-" for none.
func parseLaunchctlList(b []byte) map[string]int64 {
	out := map[string]int64{}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 3 || i == 0 && f[0] == "PID" {
			continue
		}
		pid, _ := strconv.ParseInt(f[0], 10, 64)
		out[f[2]] = pid
	}
	return out
}

// parseLaunchctlState returns the "state = ..." value from `launchctl print`.
func parseLaunchctlState(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " = "); ok && k == "state" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---- ioreg ----

// parseIOPlatformUUID finds "IOPlatformUUID" = "..." in `ioreg -rd1 -c IOPlatformExpertDevice`.
func parseIOPlatformUUID(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.Contains(k, `"IOPlatformUUID"`) {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// ---- resolv.conf ----

// parseResolvConf returns the nameserver addresses.
func parseResolvConf(b []byte) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			h := f[1]
			if z := strings.IndexByte(h, '%'); z >= 0 {
				h = h[:z]
			}
			if a, err := netip.ParseAddr(h); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}
