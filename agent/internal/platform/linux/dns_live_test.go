//go:build linux

package linux

// Live tests of the DNS sensor against the running kernel. They need root and are
// skipped otherwise: `sudo go test -run DNS ./internal/platform/linux/`. A throwaway DNS
// server on 127.0.0.77:53 (and [::1]:53 when free) answers the test queries, so they
// need no network; TestDNSSensorGetent also resolves example.com through the host's
// configured resolver.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform/linux/bpf"
	"github.com/Netdoodle/homexdr/shared/event"
	"github.com/cilium/ebpf/ringbuf"
)

const fakeDNS4 = "127.0.0.77:53"

// fakeDNSAnswer answers any A/AAAA query: 192.0.2.1 / 2001:db8::1, or NXDOMAIN for
// names starting with "nx-". Names starting with "drop-" get no answer.
func fakeDNSAnswer(q []byte) []byte {
	m, err := parseDNS(q)
	if err != nil || m.Response || len(m.Questions) == 0 || strings.HasPrefix(m.Questions[0].Name, "drop-") {
		return nil
	}
	qn := m.Questions[0]
	_, end, err := readDNSName(q, 12)
	if err != nil || end+4 > len(q) {
		return nil
	}
	b := append([]byte{}, q[:2]...)
	flags := uint16(0x8180)
	var rdata []byte
	switch {
	case strings.HasPrefix(qn.Name, "nx-"):
		flags |= 3
	case qn.Type == dnsTypeA:
		rdata = []byte{192, 0, 2, 1}
	case qn.Type == dnsTypeAAAA:
		rdata = netip.MustParseAddr("2001:db8::1").AsSlice()
	}
	an := 0
	if rdata != nil {
		an = 1
	}
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, uint16(an))
	b = append(b, 0, 0, 0, 0)
	b = append(b, q[12:end+4]...)
	if rdata != nil {
		b = append(b, dnsRRBytes(ptrQName, qn.Type, 60, rdata)...)
	}
	return b
}

// startFakeDNS serves fakeDNSAnswer on addr until the test ends.
func startFakeDNS(t *testing.T, network, addr string) bool {
	c, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Logf("fake DNS server on %s: %v", addr, err)
		return false
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := fakeDNSAnswer(buf[:n]); r != nil {
				c.WriteTo(r, from)
			}
		}
	}()
	return true
}

// exchange sends q on c (connected when to is nil) and waits briefly for an answer.
func exchange(t *testing.T, c net.PacketConn, to net.Addr, q []byte) []byte {
	t.Helper()
	var err error
	if to == nil {
		_, err = c.(net.Conn).Write(q)
	} else {
		_, err = c.WriteTo(q, to)
	}
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	var n int
	if to == nil {
		n, err = c.(net.Conn).Read(buf)
	} else {
		n, _, err = c.ReadFrom(buf)
	}
	if err != nil {
		return nil
	}
	return buf[:n]
}

func dialUDP(t *testing.T, network, addr string) net.PacketConn {
	t.Helper()
	c, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(net.PacketConn)
}

func listenUDP(t *testing.T, network, addr string) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func localPort(c net.PacketConn) uint16 { return uint16(c.LocalAddr().(*net.UDPAddr).Port) }

// TestDNSEBPFRecords checks the raw records of the BPF programs, for each way of
// attaching them (trampolines, IPv4-only trampolines, kprobes): one per query and one
// per answer, in the right process, for connected and unconnected sockets, IPv4, IPv6
// and a dual-stack socket talking to an IPv4 server (which passes through both the IPv6
// and the IPv4 send paths but must be reported once).
func TestDNSEBPFRecords(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if d, err := loadDNSBPF(); err != nil {
		t.Skipf("eBPF unavailable: %v", err)
	} else {
		t.Logf("preferred hooks: %s %s", d.mode, d.note)
		d.Close()
	}
	if !startFakeDNS(t, "udp4", fakeDNS4) {
		t.Skip("cannot bind the fake DNS server")
	}
	server4 := netip.MustParseAddrPort(fakeDNS4)
	v6 := startFakeDNS(t, "udp6", "[::1]:53")

	type tc struct {
		name   string
		conn   net.PacketConn
		to     net.Addr // nil: connected socket
		server netip.AddrPort
		query  []byte
		v6sock bool // an AF_INET6 socket (its receive path is udpv6_recvmsg)
	}
	addr4, _ := net.ResolveUDPAddr("udp4", fakeDNS4)
	cases := []tc{
		{"connected v4", dialUDP(t, "udp4", fakeDNS4), nil, server4, dnsQueryMsg(0x1001, "conn-v4.example", dnsTypeA), false},
		{"unconnected v4", listenUDP(t, "udp4", "127.0.0.1:0"), addr4, server4, dnsQueryMsg(0x1002, "unconn-v4.example", dnsTypeA), false},
		{"dual-stack to v4", listenUDP(t, "udp", "[::]:0"), addr4, server4, dnsQueryMsg(0x1003, "mapped.example", dnsTypeA), true},
		// More than the 512 bytes the programs copy: the record is marked truncated.
		{"long query", dialUDP(t, "udp4", fakeDNS4), nil, server4, append(dnsQueryMsg(0x1004, "long.example", dnsTypeA), make([]byte, 700)...), false},
	}
	if v6 {
		cases = append(cases,
			tc{"connected v6", dialUDP(t, "udp6", "[::1]:53"), nil, netip.MustParseAddrPort("[::1]:53"), dnsQueryMsg(0x1005, "conn-v6.example", dnsTypeAAAA), true})
	}
	for _, set := range dnsHookSets {
		t.Run(set.name, func(t *testing.T) {
			d, err := loadDNSHookSet(set)
			if err != nil {
				t.Skipf("not available here: %v", err)
			}
			defer d.Close()
			rd, err := ringbuf.NewReader(d.coll.Maps[bpf.DnsMapDnsEvents])
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()
			for _, c := range cases {
				if c.v6sock && !hasIPv6Hooks(set.hooks) {
					continue // not covered without the udpv6 hooks
				}
				t.Run(c.name, func(t *testing.T) { checkDNSRecords(t, rd, c.conn, c.to, c.server, c.query) })
			}
		})
	}
}

// checkDNSRecords exchanges query with the fake server (through to, or on a connected
// conn when to is nil) and expects exactly one send and one receive record for it, from
// this process.
func checkDNSRecords(t *testing.T, rd *ringbuf.Reader, conn net.PacketConn, to net.Addr, server netip.AddrPort, query []byte) {
	pid := uint32(os.Getpid())
	selfKey, _ := startKey(int64(pid))
	parentKey, _ := startKey(int64(os.Getppid()))
	ans := exchange(t, conn, to, query)
	if ans == nil {
		t.Fatal("no answer from the fake server")
	}
	id := binary.BigEndian.Uint16(query)
	var sends, recvs []dnsPacket
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p, err := parseDNSRecord(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if p.Proc.PID != pid || binary.BigEndian.Uint16(p.Payload) != id {
			continue
		}
		p.Payload = bytes.Clone(p.Payload)
		if p.Query {
			sends = append(sends, p)
		} else {
			recvs = append(recvs, p)
		}
		if len(sends) == 1 && len(recvs) == 1 {
			rd.SetDeadline(time.Now().Add(300 * time.Millisecond)) // look for duplicates
		}
	}
	if len(sends) != 1 || len(recvs) != 1 {
		t.Fatalf("%d send and %d receive records, want 1 each", len(sends), len(recvs))
	}
	lport := localPort(conn)
	for _, p := range []dnsPacket{sends[0], recvs[0]} {
		if p.Remote != server || p.Local.Port() != lport {
			t.Errorf("addresses: local %v remote %v, want port %d remote %v", p.Local, p.Remote, lport, server)
		}
		if p.Proc.TID == 0 || p.Proc.PPID != uint32(os.Getppid()) || p.Proc.Comm == "" ||
			StartKeyFromNS(p.Proc.StartNS) != selfKey || StartKeyFromNS(p.Proc.ParentNS) != parentKey {
			t.Errorf("process %+v (start keys: self %d parent %d)", p.Proc, selfKey, parentKey)
		}
	}
	if want := query[:min(len(query), dnsEvPayloadMax)]; !bytes.Equal(sends[0].Payload, want) || sends[0].Truncated != (len(query) > dnsEvPayloadMax) {
		t.Errorf("query payload: %d bytes truncated=%v", len(sends[0].Payload), sends[0].Truncated)
	}
	if !bytes.Equal(recvs[0].Payload, ans) || recvs[0].Truncated {
		t.Errorf("answer payload: %x, want %x", recvs[0].Payload, ans)
	}
}

// runDNSSensor starts the sensor (reporting the test's own lookups, with a 1 s answer
// wait) and returns its output once it is attached.
func runDNSSensor(t *testing.T, run func(*dnsSensor, context.Context, *sink) error) (*dnsSensor, *sink) {
	t.Helper()
	s := newDNSSensor(testEnv(t))
	s.self = 0
	s.wait = time.Second
	out := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(s, ctx, out) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	time.Sleep(1500 * time.Millisecond) // let it attach
	select {
	case err := <-done:
		done <- err
		t.Skipf("sensor stopped: %v", err)
	default:
	}
	return s, out
}

func dnsEventFor(name string) func(*event.Event) bool {
	return func(e *event.Event) bool { return e.DNS != nil && e.DNS.Question.Name == name }
}

// TestDNSSensorLive runs the whole sensor and checks the events end to end.
func TestDNSSensorLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !startFakeDNS(t, "udp4", fakeDNS4) {
		t.Skip("cannot bind the fake DNS server")
	}
	s, out := runDNSSensor(t, func(s *dnsSensor, ctx context.Context, out *sink) error { return s.Run(ctx, out) })
	st := s.Status()
	t.Logf("dns sensor impl=%s state=%s %s", st.Impl, st.State, st.Error)
	if st.Impl != event.ModuleEBPF {
		t.Skipf("eBPF unavailable: %s", st.Error)
	}
	env := s.env
	pid := int64(os.Getpid())
	tag := strconv.Itoa(os.Getpid())

	// An answered query on a connected socket, name in mixed case.
	c := dialUDP(t, "udp4", fakeDNS4)
	name := "hxtest-" + tag + ".example"
	if exchange(t, c, nil, dnsQueryMsg(0x2001, "HxTest-"+tag+".Example.", dnsTypeA)) == nil {
		t.Fatal("no answer")
	}
	e := waitEvent(t, out, "answered query", dnsEventFor(name))
	key, _ := startKey(pid)
	ppid := int64(os.Getppid())
	pkey, _ := startKey(ppid)
	if e.Process == nil || e.Process.PID != pid || e.Process.EntityID != env.EntityID(pid, key) || e.Process.Executable == "" ||
		e.Process.Parent == nil || e.Process.Parent.PID != ppid || e.Process.Parent.EntityID != env.EntityID(ppid, pkey) {
		t.Errorf("process %+v parent %+v", e.Process, e.Process.Parent)
	}
	if e.Event.Kind != event.KindEvent || !slices.Equal(e.Event.Category, []string{event.CategoryNetwork}) || !slices.Equal(e.Event.Type, []string{event.TypeProtocol}) ||
		e.Event.Module != event.ModuleEBPF || e.Event.Outcome != event.OutcomeSuccess || e.Event.Duration <= 0 {
		t.Errorf("meta %+v", e.Event)
	}
	if e.Network.Transport != "udp" || e.Network.Protocol != "dns" || e.Destination.IP != "127.0.0.77" || e.Destination.Port != 53 ||
		e.Source.Port != int(localPort(c)) || e.Source.IP != "127.0.0.1" {
		t.Errorf("network %+v src %+v dst %+v", e.Network, e.Source, e.Destination)
	}
	if e.DNS.Type != "answer" || e.DNS.Question.Type != "A" || e.DNS.ResponseCode != "NOERROR" || !slices.Equal(e.DNS.ResolvedIP, []string{"192.0.2.1"}) {
		t.Errorf("dns %+v", e.DNS)
	}

	// NXDOMAIN on an unconnected socket.
	u := listenUDP(t, "udp4", "127.0.0.1:0")
	to, _ := net.ResolveUDPAddr("udp4", fakeDNS4)
	nx := "nx-" + tag + ".example"
	exchange(t, u, to, dnsQueryMsg(0x2002, nx, dnsTypeAAAA))
	e = waitEvent(t, out, "NXDOMAIN", dnsEventFor(nx))
	if e.DNS.ResponseCode != "NXDOMAIN" || e.Event.Outcome != event.OutcomeFailure || e.DNS.Question.Type != "AAAA" || e.Process == nil || e.Process.PID != pid {
		t.Errorf("nxdomain %+v %+v", e.DNS, e.Event)
	}

	// No answer: reported as a query after the wait.
	drop := "drop-" + tag + ".example"
	c.(net.Conn).Write(dnsQueryMsg(0x2003, drop, dnsTypeA))
	e = waitEvent(t, out, "unanswered query", dnsEventFor(drop))
	if e.DNS.Type != "query" || e.DNS.ResponseCode != "" || e.Event.Outcome != event.OutcomeUnknown {
		t.Errorf("unanswered %+v %+v", e.DNS, e.Event)
	}

	// The same question twice in a row is reported once.
	dup := "dup-" + tag + ".example"
	exchange(t, c, nil, dnsQueryMsg(0x2004, dup, dnsTypeA))
	exchange(t, u, to, dnsQueryMsg(0x2005, dup, dnsTypeA))
	waitEvent(t, out, "deduplicated query", dnsEventFor(dup))
	time.Sleep(2 * time.Second)
	n := 0
	out.mu.Lock()
	for _, e := range out.evs {
		if dnsEventFor(dup)(e) {
			n++
		}
	}
	out.mu.Unlock()
	if n != 1 {
		t.Errorf("%d events for a repeated query, want 1", n)
	}
}

// TestDNSSensorGetent resolves example.com with getent(1), whose glibc stub resolver
// sends the query itself when nsswitch.conf uses "dns", and expects the event to name
// getent's process. It needs the host's resolver to be reachable only for the answer;
// the query is reported either way.
func TestDNSSensorGetent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	getent, err := exec.LookPath("getent")
	if err != nil {
		t.Skip("getent not installed")
	}
	ns, _ := os.ReadFile("/etc/nsswitch.conf")
	usesDNS := false
	for _, l := range strings.Split(string(ns), "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "hosts:" {
			i, j := slices.Index(f, "dns"), slices.Index(f, "resolve")
			usesDNS = i > 0 && (j < 0 || i < j)
		}
	}
	if !usesDNS {
		t.Skip(`nsswitch.conf does not send host lookups to "dns" first`)
	}
	s, out := runDNSSensor(t, func(s *dnsSensor, ctx context.Context, out *sink) error { return s.Run(ctx, out) })
	if st := s.Status(); st.Impl != event.ModuleEBPF {
		t.Skipf("eBPF unavailable: %s", st.Error)
	}
	cmd := exec.Command(getent, "ahostsv4", "example.com")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := int64(cmd.Process.Pid)
	res := cmd.Wait()
	e := waitEvent(t, out, "getent lookup", func(e *event.Event) bool {
		return e.DNS != nil && e.DNS.Question.Name == "example.com" && e.Process != nil && e.Process.PID == pid
	})
	t.Logf("getent (%v): %s", res, e.Message)
	if e.Process.Name != "getent" || !strings.HasSuffix(e.Process.Executable, "/getent") || e.DNS.Question.Type != "A" {
		t.Errorf("%+v %+v", e.Process, e.DNS)
	}
}

// TestDNSPacketFallback runs the AF_PACKET implementation against the fake server.
func TestDNSPacketFallback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !startFakeDNS(t, "udp4", fakeDNS4) {
		t.Skip("cannot bind the fake DNS server")
	}
	v6 := startFakeDNS(t, "udp6", "[::1]:53")
	_, out := runDNSSensor(t, func(s *dnsSensor, ctx context.Context, out *sink) error { return s.runPacket(ctx, out) })
	tag := strconv.Itoa(os.Getpid())
	c := dialUDP(t, "udp4", fakeDNS4)
	name := "pkt-" + tag + ".example"
	if exchange(t, c, nil, dnsQueryMsg(0x3001, name, dnsTypeA)) == nil {
		t.Fatal("no answer")
	}
	e := waitEvent(t, out, "captured answer", dnsEventFor(name))
	if e.Event.Module != moduleAFPacket || e.Process != nil || e.DNS.Type != "answer" || !slices.Equal(e.DNS.ResolvedIP, []string{"192.0.2.1"}) ||
		e.Source.IP != "127.0.0.1" || e.Source.Port != int(localPort(c)) || e.Destination.IP != "127.0.0.77" {
		t.Errorf("%+v %+v %+v %+v", e.Event, e.DNS, e.Source, e.Destination)
	}
	if v6 {
		c6 := dialUDP(t, "udp6", "[::1]:53")
		name6 := "pkt6-" + tag + ".example"
		exchange(t, c6, nil, dnsQueryMsg(0x3002, name6, dnsTypeAAAA))
		e := waitEvent(t, out, "captured IPv6 answer", dnsEventFor(name6))
		if e.Network.Type != "ipv6" || !slices.Equal(e.DNS.ResolvedIP, []string{"2001:db8::1"}) {
			t.Errorf("%+v %+v", e.Network, e.DNS)
		}
	}
}
