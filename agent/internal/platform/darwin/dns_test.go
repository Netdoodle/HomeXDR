package darwin

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// --- DNS message builders ---

func dnsWireName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func dnsHdr(id, flags uint16, qd, an, ns, ar int) []byte {
	b := make([]byte, 12)
	be := binary.BigEndian
	be.PutUint16(b[0:], id)
	be.PutUint16(b[2:], flags)
	be.PutUint16(b[4:], uint16(qd))
	be.PutUint16(b[6:], uint16(an))
	be.PutUint16(b[8:], uint16(ns))
	be.PutUint16(b[10:], uint16(ar))
	return b
}

func dnsQ(name string, qtype uint16) []byte {
	b := dnsWireName(name)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, qtype), 1)
}

// dnsRRBytes is a resource record whose owner is the given (already encoded) name.
func dnsRRBytes(owner []byte, typ uint16, ttl uint32, rdata []byte) []byte {
	b := slices.Clone(owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func dnsQueryMsg(id uint16, name string, qtype uint16) []byte {
	return append(dnsHdr(id, 0x0100, 1, 0, 0, 0), dnsQ(name, qtype)...)
}

var ptrQName = []byte{0xc0, 12} // the question's name, right after the header

// dnsAnswerMsg answers name/qtype with A or AAAA records for ips (rcode in flags).
func dnsAnswerMsg(id uint16, name string, qtype uint16, rcode uint16, ips ...string) []byte {
	b := append(dnsHdr(id, 0x8180|rcode, 1, len(ips), 0, 0), dnsQ(name, qtype)...)
	for _, s := range ips {
		a := netip.MustParseAddr(s)
		typ := uint16(dnsTypeA)
		if a.Is6() {
			typ = dnsTypeAAAA
		}
		b = append(b, dnsRRBytes(ptrQName, typ, 300, a.AsSlice())...)
	}
	return b
}

// --- parser ---

func TestParseDNSQuery(t *testing.T) {
	m, err := parseDNS(dnsQueryMsg(0xbeef, "WWW.Example.COM.", dnsTypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0xbeef || m.Response || m.Opcode != 0 || len(m.Questions) != 1 || len(m.Answers) != 0 {
		t.Fatalf("%+v", m)
	}
	if q := m.Questions[0]; q.Name != "www.example.com" || q.Type != dnsTypeAAAA || q.Class != 1 {
		t.Fatalf("%+v", q)
	}
	if dnsTypeName(m.Questions[0].Type) != "AAAA" || dnsTypeName(4242) != "TYPE4242" || dnsRCodeName(3) != "NXDOMAIN" || dnsRCodeName(23) != "RCODE23" {
		t.Fatal("names")
	}
	// The root name.
	m, err = parseDNS(append(dnsHdr(1, 0, 1, 0, 0, 0), 0, 0, 2, 0, 1))
	if err != nil || m.Questions[0].Name != "." || m.Questions[0].Type != dnsTypeNS {
		t.Fatalf("root: %+v %v", m, err)
	}
}

func TestParseDNSCompressedAnswers(t *testing.T) {
	// www.example.com A -> CNAME edge.cdn.example.com (suffix compressed against the
	// question) -> two A records owned by the CNAME target (a pointer to a pointer).
	msg := append(dnsHdr(7, 0x8180, 1, 3, 0, 0), dnsQ("www.example.com", dnsTypeA)...)
	// The CNAME's RDATA follows its owner pointer (2 bytes) and fixed fields (10); it is
	// "edge.cdn" plus a pointer to "example.com" at offset 16.
	cnameAt := len(msg) + 12
	target := append([]byte{4, 'e', 'd', 'g', 'e', 3, 'c', 'd', 'n'}, 0xc0, 16)
	msg = append(msg, dnsRRBytes(ptrQName, dnsTypeCNAME, 60, target)...)
	cptr := []byte{0xc0 | byte(cnameAt>>8), byte(cnameAt)}
	msg = append(msg, dnsRRBytes(cptr, dnsTypeA, 20, []byte{192, 0, 2, 1})...)
	msg = append(msg, dnsRRBytes(cptr, dnsTypeA, 20, []byte{192, 0, 2, 2})...)

	m, err := parseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Response || m.RCode != 0 || m.Partial || len(m.Answers) != 3 {
		t.Fatalf("%+v", m)
	}
	want := []dnsRR{
		{Name: "www.example.com", Type: dnsTypeCNAME, Class: 1, TTL: 60, Data: "edge.cdn.example.com"},
		{Name: "edge.cdn.example.com", Type: dnsTypeA, Class: 1, TTL: 20, Data: "192.0.2.1"},
		{Name: "edge.cdn.example.com", Type: dnsTypeA, Class: 1, TTL: 20, Data: "192.0.2.2"},
	}
	if !slices.Equal(m.Answers, want) {
		t.Fatalf("answers\n got %+v\nwant %+v", m.Answers, want)
	}
}

func TestParseDNSMultipleAnswersAndNXDOMAIN(t *testing.T) {
	m, err := parseDNS(dnsAnswerMsg(9, "v6.example", dnsTypeAAAA, 0, "2001:db8::1", "2001:db8::2"))
	if err != nil || len(m.Answers) != 2 || m.Answers[1].Data != "2001:db8::2" || m.Answers[0].Type != dnsTypeAAAA {
		t.Fatalf("%+v %v", m, err)
	}
	m, err = parseDNS(dnsAnswerMsg(10, "nope.example", dnsTypeA, 3))
	if err != nil || !m.Response || m.RCode != 3 || len(m.Answers) != 0 || m.Questions[0].Name != "nope.example" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestParseDNSRData(t *testing.T) {
	q := append(dnsHdr(1, 0x8180, 1, 7, 0, 0), dnsQ("example.com", dnsTypeANYForTest)...)
	mx := append([]byte{0, 10}, 0xc0, 12)
	txt := []byte{5, 'h', 'e', '"', 'l', 0x07, 3, 'a', 'b', 'c'}
	srv := append([]byte{0, 1, 0, 2, 0x01, 0xbb}, dnsWireName("svc.example.com")...)
	caa := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
	https := append([]byte{0, 1}, 0) // priority 1, target "."
	for _, rr := range []struct {
		typ uint16
		rd  []byte
	}{{dnsTypeMX, mx}, {dnsTypeTXT, txt}, {dnsTypeSRV, srv}, {dnsTypeCAA, caa}, {dnsTypeHTTPS, https}, {4242, []byte{1, 2, 0xff}}, {dnsTypeA, []byte{1, 2, 3}}} {
		q = append(q, dnsRRBytes(ptrQName, rr.typ, 1, rr.rd)...)
	}
	m, err := parseDNS(q)
	if err != nil || len(m.Answers) != 7 {
		t.Fatalf("%+v %v", m, err)
	}
	want := []string{
		"10 example.com",
		`"he\"l\007" "abc"`,
		"1 2 443 svc.example.com",
		`0 issue "letsencrypt.org"`,
		"1 .",
		`\# 3 0102ff`,
		`\# 3 010203`, // an A record of the wrong size
	}
	for i, w := range want {
		if m.Answers[i].Data != w {
			t.Errorf("answer %d (%s): %q, want %q", i, dnsTypeName(m.Answers[i].Type), m.Answers[i].Data, w)
		}
	}
}

const dnsTypeANYForTest = 255

func TestParseDNSNameEscaping(t *testing.T) {
	// Labels with a dot, a backslash, a space, a control byte and upper case.
	name := []byte{5, 'a', '.', 'B', '\\', ' ', 2, 0x07, 'Z', 3, 'c', 'o', 'm', 0}
	msg := append(dnsHdr(1, 0, 1, 0, 0, 0), name...)
	msg = append(msg, 0, 1, 0, 1)
	m, err := parseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Questions[0].Name; got != `a\.b\\\032.\007z.com` {
		t.Fatalf("%q", got)
	}
}

func TestParseDNSMalformed(t *testing.T) {
	hdr := dnsHdr(1, 0x8180, 1, 1, 0, 0)
	cases := map[string][]byte{
		"empty":            nil,
		"short header":     hdr[:11],
		"no question":      dnsHdr(1, 0, 0, 0, 0, 0),
		"self pointer":     append(slices.Clone(hdr), 0xc0, 12, 0, 1, 0, 1),
		"pointer loop":     append(slices.Clone(hdr), 1, 'a', 0xc0, 12, 0, 1, 0, 1),
		"label type":       append(slices.Clone(hdr), 0x41, 0, 0, 1, 0, 1),
		"label past end":   append(slices.Clone(hdr), 10, 'a', 'b'),
		"pointer past end": append(slices.Clone(hdr), 0xc0, 0xff, 0, 1, 0, 1),
		"no qtype":         append(slices.Clone(hdr), 0),
	}
	long := slices.Clone(hdr)
	for range 5 {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'x'}, 63)...)
	}
	cases["name over 255"] = append(append(long, 0), 0, 1, 0, 1)
	for name, b := range cases {
		if m, err := parseDNS(b); err == nil {
			t.Errorf("%s: accepted: %+v", name, m)
		}
	}
	// A damaged answer section keeps the question and is marked partial.
	b := append(dnsAnswerMsg(1, "ok.example", dnsTypeA, 0, "192.0.2.1"), 0xc0)
	binary.BigEndian.PutUint16(b[6:], 2)
	m, err := parseDNS(b)
	if err != nil || !m.Partial || len(m.Answers) != 1 || m.Questions[0].Name != "ok.example" {
		t.Fatalf("%+v %v", m, err)
	}
	// Absurd counts with a short body.
	b = dnsAnswerMsg(1, "ok.example", dnsTypeA, 0)
	binary.BigEndian.PutUint16(b[4:], 0xffff)
	binary.BigEndian.PutUint16(b[6:], 0xffff)
	if m, err := parseDNS(b); err != nil || !m.Partial || len(m.Questions) != 1 {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestParseDNSTruncated(t *testing.T) {
	full := dnsAnswerMsg(5, "trunc.example.org", dnsTypeA, 0, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	qEnd := 12 + len(dnsQ("trunc.example.org", dnsTypeA))
	for n := 0; n <= len(full); n++ {
		m, err := parseDNS(full[:n])
		switch {
		case n < qEnd:
			if err == nil {
				t.Fatalf("len %d: accepted", n)
			}
		case n < len(full):
			if err != nil || !m.Partial || len(m.Answers) >= 3 || m.Questions[0].Name != "trunc.example.org" {
				t.Fatalf("len %d: %+v %v", n, m, err)
			}
		default:
			if err != nil || m.Partial || len(m.Answers) != 3 {
				t.Fatalf("full: %+v %v", m, err)
			}
		}
	}
}

func FuzzParseDNS(f *testing.F) {
	f.Add(dnsQueryMsg(1, "example.com", dnsTypeA))
	f.Add(dnsAnswerMsg(2, "example.com", dnsTypeAAAA, 0, "2001:db8::1", "192.0.2.1"))
	f.Add(append(dnsHdr(1, 0x8180, 1, 1, 0, 0), 0xc0, 12, 0, 1, 0, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseDNS(b)
		if err == nil && len(m.Questions) == 0 {
			t.Fatal("no error without a question")
		}
	})
}

// --- tracker ---

type evSink struct{ evs []*event.Event }

func (s *evSink) emit(e *event.Event) { s.evs = append(s.evs, e) }

func testTracker() (*dnsTracker, *evSink) {
	s := &evSink{}
	return newDNSTracker(moduleBPF, s.emit), s
}

var (
	tServer = netip.MustParseAddrPort("192.0.2.53:53")
	tT0     = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	tLocalA = netip.MustParseAddrPort("192.0.2.10:40000")
	tLocalB = netip.MustParseAddrPort("192.0.2.10:40001")
)

func qPkt(local netip.AddrPort, at time.Duration, msg []byte) dnsPacket {
	return dnsPacket{Query: true, Local: local, Remote: tServer, Payload: msg, TS: tT0.Add(at)}
}

func aPkt(local netip.AddrPort, at time.Duration, msg []byte) dnsPacket {
	return dnsPacket{Local: local, Remote: tServer, Payload: msg, TS: tT0.Add(at)}
}

func TestDNSTrackerQueryAnswer(t *testing.T) {
	tr, out := testTracker()
	tr.handle(qPkt(tLocalA, 0, dnsQueryMsg(1, "Example.COM", dnsTypeA)))
	if len(out.evs) != 0 {
		t.Fatal("query reported before its answer")
	}
	tr.handle(aPkt(tLocalA, 30*time.Millisecond, dnsAnswerMsg(1, "example.com", dnsTypeA, 0, "192.0.2.10", "192.0.2.11")))
	if len(out.evs) != 1 {
		t.Fatalf("%d events", len(out.evs))
	}
	e := out.evs[0]
	if e.Event.Kind != event.KindEvent || !slices.Equal(e.Event.Category, []string{"network"}) || !slices.Equal(e.Event.Type, []string{"protocol"}) ||
		e.Event.Module != "bpf" || e.Event.Dataset != "dns" || e.Event.Action != "dns_query" || e.Event.Outcome != event.OutcomeSuccess ||
		e.Event.Duration != int64(30*time.Millisecond) || !e.Timestamp.Equal(tT0) {
		t.Errorf("meta %+v ts %v", e.Event, e.Timestamp)
	}
	if e.Network.Transport != "udp" || e.Network.Protocol != "dns" || e.Network.Type != "ipv4" ||
		e.Source.IP != "192.0.2.10" || e.Source.Port != 40000 || e.Destination.IP != "192.0.2.53" || e.Destination.Port != 53 {
		t.Errorf("network %+v %+v %+v", e.Network, e.Source, e.Destination)
	}
	if e.DNS.Type != "answer" || e.DNS.Question.Name != "example.com" || e.DNS.Question.Type != "A" || e.DNS.ResponseCode != "NOERROR" ||
		!slices.Equal(e.DNS.ResolvedIP, []string{"192.0.2.10", "192.0.2.11"}) || len(e.DNS.Answers) != 2 || e.DNS.Answers[0].TTL != 300 {
		t.Errorf("dns %+v", e.DNS)
	}
	if e.Process != nil {
		t.Errorf("process %+v", e.Process)
	}
	if e.Message != "dns answer A example.com -> 192.0.2.10, 192.0.2.11" {
		t.Errorf("message %q", e.Message)
	}
	// The same answer seen on a second interface is not reported again.
	tr.handle(aPkt(tLocalA, 31*time.Millisecond, dnsAnswerMsg(1, "example.com", dnsTypeA, 0, "192.0.2.10")))
	if len(out.evs) != 1 {
		t.Fatal("duplicate answer reported")
	}
}

func TestDNSTrackerDedup(t *testing.T) {
	tr, out := testTracker()
	// The same question twice within the window (a retry from another port, or the same
	// frame on a bridge and its member): one event.
	tr.handle(qPkt(tLocalA, 0, dnsQueryMsg(1, "d.example.org", dnsTypeA)))
	tr.handle(qPkt(tLocalB, 100*time.Millisecond, dnsQueryMsg(2, "d.example.org", dnsTypeA)))
	tr.handle(aPkt(tLocalB, 120*time.Millisecond, dnsAnswerMsg(2, "d.example.org", dnsTypeA, 0, "192.0.2.1")))
	tr.handle(aPkt(tLocalA, 130*time.Millisecond, dnsAnswerMsg(1, "d.example.org", dnsTypeA, 0, "192.0.2.1")))
	if len(out.evs) != 1 {
		t.Fatalf("%d events, want 1", len(out.evs))
	}
	// After the window the same question is a new event.
	tr.handle(qPkt(tLocalA, 3*time.Second, dnsQueryMsg(3, "d.example.org", dnsTypeA)))
	tr.handle(aPkt(tLocalA, 3*time.Second+time.Millisecond, dnsAnswerMsg(3, "d.example.org", dnsTypeA, 0, "192.0.2.1")))
	if len(out.evs) != 2 {
		t.Fatalf("%d events, want 2", len(out.evs))
	}
}

func TestDNSTrackerUnansweredNXDomainAndTCP(t *testing.T) {
	tr, out := testTracker()
	tr.handle(qPkt(tLocalA, 0, dnsQueryMsg(7, "gone.example.org", dnsTypeAAAA)))
	tr.sweep(tT0.Add(time.Second))
	if len(out.evs) != 0 {
		t.Fatal("reported before the wait")
	}
	tr.sweep(tT0.Add(dnsAnswerWait + time.Second))
	if len(out.evs) != 1 || out.evs[0].DNS.Type != "query" || out.evs[0].Event.Outcome != event.OutcomeUnknown ||
		out.evs[0].Message != "dns query AAAA gone.example.org" {
		t.Fatalf("%+v", out.evs)
	}
	tr.handle(qPkt(tLocalB, 10*time.Second, dnsQueryMsg(8, "nx.example.org", dnsTypeA)))
	tr.handle(aPkt(tLocalB, 10*time.Second+time.Millisecond, dnsAnswerMsg(8, "nx.example.org", dnsTypeA, 3)))
	e := out.evs[1]
	if e.DNS.ResponseCode != "NXDOMAIN" || e.Event.Outcome != event.OutcomeFailure || e.Message != "dns answer A nx.example.org [NXDOMAIN]" {
		t.Fatalf("%+v %q", e.DNS, e.Message)
	}
	// Queries that were received and answers that were sent (a DNS server here) are ignored.
	n := len(out.evs)
	tr.handle(dnsPacket{Local: tLocalA, Remote: tServer, Payload: dnsQueryMsg(9, "s.example.org", dnsTypeA), TS: tT0.Add(20 * time.Second)})
	tr.handle(dnsPacket{Query: true, Local: tLocalA, Remote: tServer, Payload: dnsAnswerMsg(9, "s.example.org", dnsTypeA, 0), TS: tT0.Add(21 * time.Second)})
	tr.handle(dnsPacket{Query: true, Local: tLocalA, Remote: tServer, Payload: []byte{1, 2, 3}, TS: tT0.Add(22 * time.Second)})
	tr.sweep(tT0.Add(time.Minute))
	if len(out.evs) != n {
		t.Fatalf("ignored traffic reported: %d events", len(out.evs))
	}
	// TCP.
	q := qPkt(tLocalA, time.Minute, dnsQueryMsg(10, "t.example.org", dnsTypeA))
	q.TCP = true
	tr.handle(q)
	tr.flush()
	if last := out.evs[len(out.evs)-1]; last.Network.Transport != "tcp" {
		t.Fatalf("%+v", last.Network)
	}
}

func TestDNSTrackerBounded(t *testing.T) {
	tr, _ := testTracker()
	for i := 0; i < 3*dnsMaxFlows; i++ {
		l := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(1024+i%60000))
		tr.handle(qPkt(l, time.Duration(i)*time.Microsecond, dnsQueryMsg(uint16(i), "n"+strings.Repeat("x", i%20)+string(rune('a'+i%26))+".example.org", dnsTypeA)))
	}
	if len(tr.flows) > dnsMaxFlows || len(tr.recent) > dnsMaxFlows {
		t.Fatalf("flows %d recent %d", len(tr.flows), len(tr.recent))
	}
}

// --- capture ---

func ipv4Pkt(proto byte, src, dst string, sport, dport uint16, payload []byte) []byte {
	var l4 []byte
	l4 = binary.BigEndian.AppendUint16(l4, sport)
	l4 = binary.BigEndian.AppendUint16(l4, dport)
	if proto == protoUDP {
		l4 = binary.BigEndian.AppendUint16(l4, uint16(8+len(payload)))
		l4 = append(l4, 0, 0)
	} else {
		l4 = append(l4, make([]byte, 8)...) // seq, ack
		l4 = append(l4, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0)
	}
	l4 = append(l4, payload...)
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	h[8], h[9] = 64, proto
	copy(h[12:], netip.MustParseAddr(src).AsSlice())
	copy(h[16:], netip.MustParseAddr(dst).AsSlice())
	return append(h, l4...)
}

func ipv6Pkt(proto byte, src, dst string, sport, dport uint16, payload []byte) []byte {
	l4 := ipv4Pkt(proto, "0.0.0.0", "0.0.0.0", sport, dport, payload)[20:]
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	h[6], h[7] = proto, 64
	copy(h[8:], netip.MustParseAddr(src).AsSlice())
	copy(h[24:], netip.MustParseAddr(dst).AsSlice())
	return append(h, l4...)
}

func ether(etype uint16, ip []byte) []byte {
	return append(binary.BigEndian.AppendUint16(make([]byte, 12), etype), ip...)
}

func nullHdr(family byte, ip []byte) []byte {
	return append([]byte{family, 0, 0, 0}, ip...) // host order, little endian
}

func tcpMsg(m []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...) }

// runCBPF interprets the subset of classic BPF used by dnsFilter, as the kernel runs it.
func runCBPF(t *testing.T, prog []bpfInsn, pkt []byte) uint32 {
	var a, x uint32
	load := func(off uint32, size int) (uint32, bool) {
		if int(off)+size > len(pkt) {
			return 0, false
		}
		switch size {
		case 1:
			return uint32(pkt[off]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(pkt[off:])), true
		}
		return binary.BigEndian.Uint32(pkt[off:]), true
	}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		var ok bool
		switch in.Code {
		case bpfLdW:
			a, ok = load(in.K, 4)
		case bpfLdH:
			a, ok = load(in.K, 2)
		case bpfLdB:
			a, ok = load(in.K, 1)
		case bpfLdIndH:
			a, ok = load(x+in.K, 2)
		case bpfLdxMsh:
			var v uint32
			v, ok = load(in.K, 1)
			x = 4 * (v & 0xf)
		case bpfJa:
			pc += int(in.K)
			ok = true
		case bpfJeq, bpfJset:
			hit := a == in.K
			if in.Code == bpfJset {
				hit = a&in.K != 0
			}
			if hit {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			ok = true
		case bpfRet:
			return in.K
		default:
			t.Fatalf("instruction %d: unexpected code %#x", pc, in.Code)
		}
		if !ok {
			return 0 // an out-of-bounds load drops the packet
		}
	}
	t.Fatal("ran off the end of the filter")
	return 0
}

func TestDNSFilter(t *testing.T) {
	q := dnsQueryMsg(1, "f.example.org", dnsTypeA)
	frag := ipv4Pkt(protoUDP, "192.0.2.1", "192.0.2.2", 40000, 53, q)
	binary.BigEndian.PutUint16(frag[6:], 0x0020)
	// IHL 6: a 24-byte header with 4 option bytes before the UDP header.
	opts := append([]byte{0x46}, ipv4Pkt(protoUDP, "192.0.2.1", "192.0.2.2", 40000, 53, q)[1:]...)
	opts = append(opts[:20], append([]byte{1, 1, 1, 1}, opts[20:]...)...)
	cases := []struct {
		name   string
		ip     []byte
		v6     bool
		accept bool
	}{
		{"v4 udp query", ipv4Pkt(protoUDP, "192.0.2.1", "192.0.2.2", 40000, 53, q), false, true},
		{"v4 udp answer", ipv4Pkt(protoUDP, "192.0.2.2", "192.0.2.1", 53, 40000, q), false, true},
		{"v4 tcp", ipv4Pkt(protoTCP, "192.0.2.1", "192.0.2.2", 40000, 53, tcpMsg(q)), false, true},
		{"v4 options", opts, false, true},
		{"v4 other port", ipv4Pkt(protoUDP, "192.0.2.1", "192.0.2.2", 40000, 443, q), false, false},
		{"v4 icmp", ipv4Pkt(1, "192.0.2.1", "192.0.2.2", 40000, 53, q), false, false},
		{"v4 fragment", frag, false, false},
		{"v4 truncated", ipv4Pkt(protoUDP, "192.0.2.1", "192.0.2.2", 40000, 53, q)[:21], false, false},
		{"v6 udp query", ipv6Pkt(protoUDP, "2001:db8::1", "2001:db8::2", 40000, 53, q), true, true},
		{"v6 udp answer", ipv6Pkt(protoUDP, "2001:db8::2", "2001:db8::1", 53, 40000, q), true, true},
		{"v6 tcp", ipv6Pkt(protoTCP, "2001:db8::1", "2001:db8::2", 40000, 53, tcpMsg(q)), true, true},
		{"v6 other port", ipv6Pkt(protoUDP, "2001:db8::1", "2001:db8::2", 40000, 123, q), true, false},
	}
	eth, null := dnsFilter(dltEN10MB), dnsFilter(dltNull)
	if eth == nil || null == nil || dnsFilter(12) != nil {
		t.Fatal("filter availability")
	}
	for _, c := range cases {
		etype, fam := uint16(0x0800), byte(2)
		if c.v6 {
			etype, fam = 0x86dd, 30
		}
		if got := runCBPF(t, eth, ether(etype, c.ip)) != 0; got != c.accept {
			t.Errorf("ethernet %s: accept=%v, want %v", c.name, got, c.accept)
		}
		if got := runCBPF(t, null, nullHdr(fam, c.ip)) != 0; got != c.accept {
			t.Errorf("null %s: accept=%v, want %v", c.name, got, c.accept)
		}
	}
	if runCBPF(t, eth, ether(0x0806, make([]byte, 28))) != 0 {
		t.Error("arp accepted")
	}
	if runCBPF(t, null, nullHdr(18, make([]byte, 28))) != 0 {
		t.Error("other family accepted")
	}
	if runCBPF(t, eth, nil) != 0 {
		t.Error("empty frame accepted")
	}
}

func TestParseDNSIPPacket(t *testing.T) {
	q := dnsQueryMsg(1, "pkt.example.org", dnsTypeA)
	p, ok := parseDNSIPPacket(ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, q))
	if !ok || !p.Query || p.TCP || p.Local.String() != "192.0.2.10:40000" || p.Remote.String() != "192.0.2.1:53" || !bytes.Equal(p.Payload, q) {
		t.Fatalf("%+v %v", p, ok)
	}
	p, ok = parseDNSIPPacket(ipv6Pkt(protoUDP, "2001:db8::53", "2001:db8::10", 53, 40000, q))
	if !ok || p.Query || p.Local.String() != "[2001:db8::10]:40000" || p.Remote.String() != "[2001:db8::53]:53" {
		t.Fatalf("%+v %v", p, ok)
	}
	p, ok = parseDNSIPPacket(ipv4Pkt(protoTCP, "192.0.2.10", "192.0.2.1", 40000, 53, tcpMsg(q)))
	if !ok || !p.TCP || p.Truncated || !p.Query || !bytes.Equal(p.Payload, q) {
		t.Fatalf("tcp %+v %v", p, ok)
	}
	// A TCP message that continues in the next segment.
	cut := append(binary.BigEndian.AppendUint16(nil, uint16(len(q)+40)), q...)
	p, ok = parseDNSIPPacket(ipv4Pkt(protoTCP, "192.0.2.1", "192.0.2.10", 53, 40000, cut))
	if !ok || !p.TCP || !p.Truncated || p.Query {
		t.Fatalf("tcp cut %+v %v", p, ok)
	}
	frag := ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, q)
	binary.BigEndian.PutUint16(frag[6:], 0x0010) // a non-first fragment
	bad := map[string][]byte{
		"both ports 53":   ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 53, 53, q),
		"other ports":     ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 443, q),
		"fragment":        frag,
		"short":           ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, q)[:25],
		"bad version":     {0x15, 0, 0},
		"empty":           nil,
		"bad udp len":     ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, nil)[:27],
		"v6 short":        ipv6Pkt(protoUDP, "2001:db8::10", "2001:db8::53", 40000, 53, q)[:44],
		"tcp no payload":  ipv4Pkt(protoTCP, "192.0.2.10", "192.0.2.1", 40000, 53, nil),
		"tcp tiny length": ipv4Pkt(protoTCP, "192.0.2.10", "192.0.2.1", 40000, 53, append([]byte{0, 2}, q...)),
		"icmp":            ipv4Pkt(1, "192.0.2.10", "192.0.2.1", 40000, 53, q),
	}
	for name, b := range bad {
		if _, ok := parseDNSIPPacket(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
	// Link headers.
	if p, ok := parseDNSFrame(ether(0x0800, ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, q)), dltEN10MB); !ok || !p.Query {
		t.Error("ethernet frame")
	}
	if p, ok := parseDNSFrame(nullHdr(2, ipv4Pkt(protoUDP, "192.0.2.10", "192.0.2.1", 40000, 53, q)), dltNull); !ok || !p.Query {
		t.Error("null frame")
	}
	if _, ok := parseDNSFrame([]byte{1, 2, 3}, dltEN10MB); ok {
		t.Error("short ethernet frame")
	}
	if _, ok := parseDNSFrame(nullHdr(2, nil), 12); ok {
		t.Error("unsupported link type")
	}
}

func bpfRecord(sec, usec int32, frame []byte) []byte {
	const hdrlen = 18
	b := make([]byte, hdrlen)
	binary.NativeEndian.PutUint32(b[0:], uint32(sec))
	binary.NativeEndian.PutUint32(b[4:], uint32(usec))
	binary.NativeEndian.PutUint32(b[8:], uint32(len(frame)))
	binary.NativeEndian.PutUint32(b[12:], uint32(len(frame)))
	binary.NativeEndian.PutUint16(b[16:], hdrlen)
	b = append(b, frame...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestForEachBPFRecord(t *testing.T) {
	buf := append(bpfRecord(1000, 500000, []byte("abc")), bpfRecord(1001, 1, []byte("defgh"))...)
	var got []string
	var ts []time.Time
	forEachBPFRecord(buf, func(at time.Time, f []byte) { got = append(got, string(f)); ts = append(ts, at) })
	if !slices.Equal(got, []string{"abc", "defgh"}) || !ts[0].Equal(time.Unix(1000, 500000000)) {
		t.Fatalf("%q %v", got, ts)
	}
	// Truncated or hostile buffers end the walk without panicking.
	for n := 0; n < len(buf); n++ {
		forEachBPFRecord(buf[:n], func(time.Time, []byte) {})
	}
	bad := bpfRecord(1, 1, []byte("xy"))
	binary.NativeEndian.PutUint32(bad[8:], 1<<31) // caplen beyond the buffer
	forEachBPFRecord(bad, func(time.Time, []byte) { t.Fatal("record with a bad caplen") })
	binary.NativeEndian.PutUint32(bad[8:], 2)
	binary.NativeEndian.PutUint16(bad[16:], 4) // header length below the minimum
	forEachBPFRecord(bad, func(time.Time, []byte) { t.Fatal("record with a bad header length") })
}

func TestDNSCaptureInterface(t *testing.T) {
	for name, want := range map[string]bool{"en0": true, "bridge100": true, "utun3": true, "lo0": true, "awdl0": false, "llw0": false, "ap1": false, "gif0": false, "anpi0": false} {
		if dnsCaptureInterface(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}
