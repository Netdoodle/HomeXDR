//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/unix"
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
	t := newDNSTracker(event.ModuleEBPF, s.emit)
	t.resolve = func(p *dnsProc) *event.Process {
		return &event.Process{PID: int64(p.PID), Name: p.Comm, EntityID: "e-" + p.Comm}
	}
	return t, s
}

var (
	tStub   = netip.MustParseAddrPort("127.0.0.53:53")
	tT0     = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	tCurl   = &dnsProc{PID: 100, Comm: "curl"}
	tWget   = &dnsProc{PID: 200, Comm: "wget"}
	tLocalA = netip.MustParseAddrPort("127.0.0.1:40000")
	tLocalB = netip.MustParseAddrPort("0.0.0.0:40001")
)

func qPkt(proc *dnsProc, local netip.AddrPort, at time.Duration, msg []byte) dnsPacket {
	return dnsPacket{Query: true, Local: local, Remote: tStub, Payload: msg, Proc: proc, TS: tT0.Add(at)}
}

func aPkt(proc *dnsProc, local netip.AddrPort, at time.Duration, msg []byte) dnsPacket {
	return dnsPacket{Local: local, Remote: tStub, Payload: msg, Proc: proc, TS: tT0.Add(at)}
}

func TestDNSTrackerQueryAnswer(t *testing.T) {
	tr, out := testTracker()
	tr.handle(qPkt(tCurl, tLocalA, 0, dnsQueryMsg(1, "Example.COM", dnsTypeA)))
	if len(out.evs) != 0 {
		t.Fatal("query reported before its answer")
	}
	tr.handle(aPkt(tCurl, tLocalA, 30*time.Millisecond, dnsAnswerMsg(1, "example.com", dnsTypeA, 0, "192.0.2.10", "192.0.2.11")))
	if len(out.evs) != 1 {
		t.Fatalf("%d events", len(out.evs))
	}
	e := out.evs[0]
	if e.Event.Kind != event.KindEvent || !slices.Equal(e.Event.Category, []string{"network"}) || !slices.Equal(e.Event.Type, []string{"protocol"}) ||
		e.Event.Module != event.ModuleEBPF || e.Event.Outcome != event.OutcomeSuccess || e.Event.Duration != int64(30*time.Millisecond) || !e.Timestamp.Equal(tT0) {
		t.Errorf("meta %+v ts %v", e.Event, e.Timestamp)
	}
	if e.Network.Transport != "udp" || e.Network.Protocol != "dns" || e.Network.Type != "ipv4" ||
		e.Source.IP != "127.0.0.1" || e.Source.Port != 40000 || e.Destination.IP != "127.0.0.53" || e.Destination.Port != 53 {
		t.Errorf("network %+v %+v %+v", e.Network, e.Source, e.Destination)
	}
	if e.DNS.Type != "answer" || e.DNS.Question.Name != "example.com" || e.DNS.Question.Type != "A" || e.DNS.ResponseCode != "NOERROR" ||
		!slices.Equal(e.DNS.ResolvedIP, []string{"192.0.2.10", "192.0.2.11"}) || len(e.DNS.Answers) != 2 || e.DNS.Answers[0].TTL != 300 {
		t.Errorf("dns %+v", e.DNS)
	}
	if e.Process == nil || e.Process.PID != 100 || e.Process.EntityID != "e-curl" {
		t.Errorf("process %+v", e.Process)
	}
	if e.Message != "dns answer A example.com -> 192.0.2.10, 192.0.2.11 (curl)" {
		t.Errorf("message %q", e.Message)
	}
	// The same answer read again (MSG_PEEK first, then the real read) is not reported.
	tr.handle(aPkt(tCurl, tLocalA, 31*time.Millisecond, dnsAnswerMsg(1, "example.com", dnsTypeA, 0, "192.0.2.10")))
	if len(out.evs) != 1 {
		t.Fatal("duplicate answer reported")
	}
}

func TestDNSTrackerDedup(t *testing.T) {
	tr, out := testTracker()
	// Same process, name and type twice within a second (different sockets and IDs):
	// one event, completed by the first answer.
	tr.handle(qPkt(tCurl, tLocalA, 0, dnsQueryMsg(1, "dup.example", dnsTypeA)))
	tr.handle(qPkt(tCurl, tLocalB, 200*time.Millisecond, dnsQueryMsg(2, "dup.example", dnsTypeA)))
	tr.handle(aPkt(tCurl, tLocalB, 210*time.Millisecond, dnsAnswerMsg(2, "dup.example", dnsTypeA, 0, "192.0.2.2")))
	tr.handle(aPkt(tCurl, tLocalA, 220*time.Millisecond, dnsAnswerMsg(1, "dup.example", dnsTypeA, 0, "192.0.2.1")))
	// Another type, another process: separate events.
	tr.handle(qPkt(tCurl, tLocalA, 300*time.Millisecond, dnsQueryMsg(3, "dup.example", dnsTypeAAAA)))
	tr.handle(qPkt(tWget, tLocalA, 300*time.Millisecond, dnsQueryMsg(4, "dup.example", dnsTypeA)))
	// After the window: a new event.
	tr.handle(qPkt(tCurl, tLocalA, 1500*time.Millisecond, dnsQueryMsg(5, "dup.example", dnsTypeA)))
	tr.sweep(tT0.Add(10 * time.Second))
	if len(out.evs) != 4 {
		for _, e := range out.evs {
			t.Log(e.Message, e.Process.PID)
		}
		t.Fatalf("%d events, want 4", len(out.evs))
	}
	if e := out.evs[0]; e.DNS.Type != "answer" || !slices.Equal(e.DNS.ResolvedIP, []string{"192.0.2.2"}) || e.Event.Duration != int64(210*time.Millisecond) {
		t.Errorf("first %+v %d", e.DNS, e.Event.Duration)
	}
	for _, e := range out.evs[1:] {
		if e.DNS.Type != "query" || e.Event.Outcome != event.OutcomeUnknown || e.DNS.ResponseCode != "" {
			t.Errorf("unanswered %+v %+v", e.Event, e.DNS)
		}
	}
}

func TestDNSTrackerUnansweredAndLate(t *testing.T) {
	tr, out := testTracker()
	tr.wait = time.Second
	tr.handle(qPkt(tCurl, tLocalA, 0, dnsQueryMsg(1, "slow.example", dnsTypeA)))
	tr.sweep(tT0.Add(900 * time.Millisecond))
	if len(out.evs) != 0 {
		t.Fatal("reported before the wait")
	}
	tr.sweep(tT0.Add(1100 * time.Millisecond))
	if len(out.evs) != 1 || out.evs[0].DNS.Type != "query" || out.evs[0].Message != "dns query A slow.example (curl)" {
		t.Fatalf("%+v", out.evs)
	}
	// A late answer is reported on its own.
	tr.handle(aPkt(tCurl, tLocalA, 1500*time.Millisecond, dnsAnswerMsg(1, "slow.example", dnsTypeA, 2)))
	if len(out.evs) != 2 || out.evs[1].DNS.ResponseCode != "SERVFAIL" || out.evs[1].Event.Outcome != event.OutcomeFailure {
		t.Fatalf("%+v", out.evs)
	}
	// Flush on shutdown reports what is still open.
	tr.handle(qPkt(tCurl, tLocalA, 2*time.Second, dnsQueryMsg(2, "open.example", dnsTypeA)))
	tr.flush()
	if len(out.evs) != 3 || out.evs[2].DNS.Question.Name != "open.example" {
		t.Fatalf("%d events", len(out.evs))
	}
}

func TestDNSTrackerUnmatchedAndIgnored(t *testing.T) {
	tr, out := testTracker()
	// An answer without its query: reported with the receiving process, once.
	tr.handle(aPkt(tWget, tLocalA, 0, dnsAnswerMsg(9, "nx.example", dnsTypeA, 3)))
	tr.handle(aPkt(tWget, tLocalA, time.Millisecond, dnsAnswerMsg(9, "nx.example", dnsTypeA, 3)))
	if len(out.evs) != 1 || out.evs[0].DNS.ResponseCode != "NXDOMAIN" || out.evs[0].Process.PID != 200 || out.evs[0].Event.Duration != 0 ||
		out.evs[0].Message != "dns answer A nx.example [NXDOMAIN] (wget)" {
		t.Fatalf("%+v", out.evs)
	}
	// An answer whose question differs from the query with the same ID is not paired.
	tr.handle(qPkt(tCurl, tLocalB, 2*time.Second, dnsQueryMsg(7, "one.example", dnsTypeA)))
	tr.handle(aPkt(tCurl, tLocalB, 2*time.Second, dnsAnswerMsg(7, "two.example", dnsTypeA, 0, "192.0.2.7")))
	if len(out.evs) != 2 || out.evs[1].DNS.Question.Name != "two.example" {
		t.Fatalf("%d events", len(out.evs))
	}
	// A received query or a sent answer (a local DNS server's traffic) and garbage are
	// ignored.
	tr.handle(aPkt(tCurl, tLocalA, 3*time.Second, dnsQueryMsg(8, "server.example", dnsTypeA)))
	tr.handle(qPkt(tCurl, tLocalA, 3*time.Second, dnsAnswerMsg(8, "server.example", dnsTypeA, 0)))
	tr.handle(qPkt(tCurl, tLocalA, 3*time.Second, []byte("not dns at all")))
	tr.sweep(tT0.Add(time.Minute))
	if len(out.evs) != 3 || out.evs[2].DNS.Question.Name != "one.example" {
		t.Fatalf("%d events", len(out.evs))
	}
	if len(tr.flows) != 0 || len(tr.recent) != 0 {
		t.Fatalf("state left: %d flows %d recent", len(tr.flows), len(tr.recent))
	}
}

func TestDNSTrackerBounded(t *testing.T) {
	tr, out := testTracker()
	for i := range dnsMaxFlows + 10 {
		tr.handle(qPkt(&dnsProc{PID: uint32(i + 1)}, tLocalA, 0, dnsQueryMsg(uint16(i), "many.example", dnsTypeA)))
	}
	if len(tr.flows) > dnsMaxFlows || len(out.evs) != 10 {
		t.Fatalf("%d flows, %d events", len(tr.flows), len(out.evs))
	}
}

func TestDNSEventIPv6AndUnspecifiedSource(t *testing.T) {
	tr, out := testTracker()
	tr.module = moduleAFPacket
	p := dnsPacket{Query: true, Local: netip.MustParseAddrPort("[::]:5000"), Remote: netip.MustParseAddrPort("[2001:db8::53]:53"),
		Payload: dnsQueryMsg(1, "six.example", dnsTypeAAAA), TS: tT0}
	tr.handle(p)
	tr.flush()
	e := out.evs[0]
	if e.Network.Type != "ipv6" || e.Source.IP != "" || e.Source.Port != 5000 || e.Destination.IP != "2001:db8::53" || e.Process != nil || e.Event.Module != moduleAFPacket {
		t.Fatalf("%+v %+v %+v", e.Network, e.Source, e.Destination)
	}
}

// --- sensor ---

func TestDNSSensorFallbackStatus(t *testing.T) {
	env := testEnv(t)
	sensors := New().Sensors(api.SensorsConfig{DNS: api.ToggleConfig{Enabled: true}}, env)
	if len(sensors) != 1 || sensors[0].Name() != "dns" {
		t.Fatalf("Sensors() = %v", sensors)
	}
	if len(New().Sensors(api.SensorsConfig{}, env)) != 0 {
		t.Fatal("dns sensor returned while disabled")
	}
	noBPF := func() (*dnsBPF, error) { return nil, unavailable(errors.New("no BTF here")) }
	discard := platform.EmitterFunc(func(*event.Event) {})

	// eBPF unavailable: packet capture, reported as degraded. A unix socket pair stands in
	// for the AF_PACKET socket (which needs CAP_NET_RAW).
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	s := newDNSSensor(env)
	s.loadBPF = noBPF
	s.openPacket = func() (*os.File, error) { return os.NewFile(uintptr(fds[0]), "fake-packet"), nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, discard) }()
	time.Sleep(300 * time.Millisecond)
	st := s.Status()
	if st.Name != "dns" || st.Impl != moduleAFPacket || st.State != api.SensorDegraded || !strings.Contains(st.Error, "no BTF here") {
		t.Errorf("degraded status %+v", st)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Nothing works: Run fails with both reasons, and the status says so.
	s = newDNSSensor(env)
	s.loadBPF = noBPF
	s.openPacket = func() (*os.File, error) { return nil, unavailable(errors.New("no CAP_NET_RAW")) }
	err = s.Run(context.Background(), discard)
	st = s.Status()
	if err == nil || st.State != api.SensorFailed || st.Impl != moduleAFPacket ||
		!strings.Contains(st.Error, "no BTF here") || !strings.Contains(st.Error, "no CAP_NET_RAW") || err.Error() != st.Error {
		t.Errorf("failed status %+v, err %v", st, err)
	}
}

// --- eBPF record ---

func TestParseDNSRecord(t *testing.T) {
	b := make([]byte, dnsEvSize)
	le := binary.NativeEndian
	le.PutUint32(b[0:], dnsEvRecv)
	le.PutUint32(b[4:], 4242)
	le.PutUint32(b[8:], 4243)
	le.PutUint32(b[12:], 1)
	le.PutUint32(b[16:], 1000)
	le.PutUint16(b[20:], 10) // AF_INET6
	le.PutUint16(b[22:], 40000)
	le.PutUint16(b[24:], 53)
	msg := dnsAnswerMsg(3, "rec.example", dnsTypeA, 0, "192.0.2.3")
	le.PutUint16(b[26:], uint16(len(msg)))
	le.PutUint32(b[28:], 900)
	le.PutUint64(b[32:], 123_450_000_000)
	le.PutUint64(b[40:], 5_000_000_000)
	copy(b[48:], netip.MustParseAddr("::").AsSlice())
	copy(b[64:], netip.MustParseAddr("::ffff:192.0.2.53").AsSlice()) // a dual-stack socket
	copy(b[80:], "curl\x00")
	copy(b[96:], msg)
	p, err := parseDNSRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Query || p.Proc.PID != 4242 || p.Proc.TID != 4243 || p.Proc.PPID != 1 || p.Proc.UID != 1000 || p.Proc.Comm != "curl" ||
		StartKeyFromNS(p.Proc.StartNS) != 12345 || StartKeyFromNS(p.Proc.ParentNS) != 500 {
		t.Fatalf("%+v %+v", p, p.Proc)
	}
	if p.Local.String() != "[::]:40000" || p.Remote.String() != "192.0.2.53:53" || !bytes.Equal(p.Payload, msg) || !p.Truncated {
		t.Fatalf("%v %v %d %v", p.Local, p.Remote, len(p.Payload), p.Truncated)
	}
	le.PutUint16(b[20:], 2) // AF_INET
	copy(b[48:], []byte{127, 0, 0, 1})
	copy(b[64:], []byte{127, 0, 0, 53})
	le.PutUint32(b[28:], uint32(len(msg)))
	if p, err = parseDNSRecord(b); err != nil || p.Local.String() != "127.0.0.1:40000" || p.Remote != tStub || p.Truncated {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parseDNSRecord(b[:100]); err == nil {
		t.Error("short record accepted")
	}
	le.PutUint32(b[0:], 9)
	if _, err := parseDNSRecord(b); err == nil {
		t.Error("bad type accepted")
	}
}

// --- packet capture ---

func ipv4UDP(src, dst string, sport, dport uint16, payload []byte) []byte {
	u := binary.BigEndian.AppendUint16(nil, sport)
	u = binary.BigEndian.AppendUint16(u, dport)
	u = binary.BigEndian.AppendUint16(u, uint16(8+len(payload)))
	u = append(u, 0, 0)
	u = append(u, payload...)
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(u)))
	h[8], h[9] = 64, unix.IPPROTO_UDP
	copy(h[12:], netip.MustParseAddr(src).AsSlice())
	copy(h[16:], netip.MustParseAddr(dst).AsSlice())
	return append(h, u...)
}

func ipv6UDP(src, dst string, sport, dport uint16, payload []byte) []byte {
	u := ipv4UDP("0.0.0.0", "0.0.0.0", sport, dport, payload)[20:]
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(u)))
	h[6], h[7] = unix.IPPROTO_UDP, 64
	copy(h[8:], netip.MustParseAddr(src).AsSlice())
	copy(h[24:], netip.MustParseAddr(dst).AsSlice())
	return append(h, u...)
}

func TestParseDNSIPPacket(t *testing.T) {
	q := dnsQueryMsg(1, "pkt.example", dnsTypeA)
	p, ok := parseDNSIPPacket(ipv4UDP("192.168.1.10", "192.168.1.1", 40000, 53, q), true)
	if !ok || !p.Query || p.Local.String() != "192.168.1.10:40000" || p.Remote.String() != "192.168.1.1:53" || !bytes.Equal(p.Payload, q) {
		t.Fatalf("%+v %v", p, ok)
	}
	p, ok = parseDNSIPPacket(ipv6UDP("2001:db8::53", "2001:db8::10", 53, 40000, q), false)
	if !ok || p.Query || p.Local.String() != "[2001:db8::10]:40000" || p.Remote.String() != "[2001:db8::53]:53" {
		t.Fatalf("%+v %v", p, ok)
	}
	frag := ipv4UDP("192.168.1.10", "192.168.1.1", 40000, 53, q)
	binary.BigEndian.PutUint16(frag[6:], 0x0010) // a non-first fragment
	bad := map[string][]byte{
		"server reply": ipv4UDP("192.168.1.1", "192.168.1.10", 53, 40000, q), // outgoing from port 53
		"fragment":     frag,
		"short":        ipv4UDP("192.168.1.10", "192.168.1.1", 40000, 53, q)[:25],
		"bad version":  {0x15, 0, 0},
		"empty":        nil,
		"bad udp len":  ipv4UDP("192.168.1.10", "192.168.1.1", 40000, 53, nil)[:27],
		"v6 short":     ipv6UDP("2001:db8::10", "2001:db8::53", 40000, 53, q)[:44],
	}
	for name, b := range bad {
		if _, ok := parseDNSIPPacket(b, true); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// runCBPF interprets the subset of classic BPF used by dnsPacketFilter, as the kernel
// runs it on a cooked AF_PACKET socket (data starts at the network header).
func runCBPF(t *testing.T, prog []unix.SockFilter, pkt []byte, proto uint16, pkttype uint32) uint32 {
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
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch in.K {
			case skfAdOff + skfAdProtocol:
				a, ok = uint32(proto), true
			case skfAdOff + skfAdPktType:
				a, ok = pkttype, true
			default:
				a, ok = load(in.K, 4)
			}
		case unix.BPF_LD | unix.BPF_H | unix.BPF_ABS:
			a, ok = load(in.K, 2)
		case unix.BPF_LD | unix.BPF_B | unix.BPF_ABS:
			a, ok = load(in.K, 1)
		case unix.BPF_LD | unix.BPF_H | unix.BPF_IND:
			a, ok = load(x+in.K, 2)
		case unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH:
			var v uint32
			v, ok = load(in.K, 1)
			x = 4 * (v & 0xf)
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(in.K)
			ok = true
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			hit := a == in.K
			if in.Code&0xf0 == unix.BPF_JSET {
				hit = a&in.K != 0
			}
			if hit {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			ok = true
		case unix.BPF_RET | unix.BPF_K:
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

func TestDNSPacketFilter(t *testing.T) {
	q := dnsQueryMsg(1, "f.example", dnsTypeA)
	tcp := ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 53, q)
	tcp[9] = unix.IPPROTO_TCP
	frag := ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 53, q)
	binary.BigEndian.PutUint16(frag[6:], 0x0020)
	// IHL 6: a 24-byte header with 4 option bytes before the UDP header.
	opts := append([]byte{0x46}, ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 53, q)[1:]...)
	opts = append(opts[:20], append([]byte{1, 1, 1, 1}, opts[20:]...)...)
	const in, out = 0, unix.PACKET_OUTGOING
	cases := []struct {
		name    string
		pkt     []byte
		proto   uint16
		pkttype uint32
		accept  bool
	}{
		{"v4 query out", ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 53, q), unix.ETH_P_IP, out, true},
		{"v4 answer in", ipv4UDP("192.0.2.2", "192.0.2.1", 53, 40000, q), unix.ETH_P_IP, in, true},
		{"v4 query in (we are the server)", ipv4UDP("192.0.2.2", "192.0.2.1", 40000, 53, q), unix.ETH_P_IP, in, false},
		{"v4 answer out (we are the server)", ipv4UDP("192.0.2.1", "192.0.2.2", 53, 40000, q), unix.ETH_P_IP, out, false},
		{"v4 options", opts, unix.ETH_P_IP, out, true},
		{"v4 other port", ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 443, q), unix.ETH_P_IP, out, false},
		{"v4 tcp", tcp, unix.ETH_P_IP, out, false},
		{"v4 fragment", frag, unix.ETH_P_IP, out, false},
		{"v6 query out", ipv6UDP("2001:db8::1", "2001:db8::2", 40000, 53, q), unix.ETH_P_IPV6, out, true},
		{"v6 answer in", ipv6UDP("2001:db8::2", "2001:db8::1", 53, 40000, q), unix.ETH_P_IPV6, in, true},
		{"v6 query in", ipv6UDP("2001:db8::2", "2001:db8::1", 40000, 53, q), unix.ETH_P_IPV6, in, false},
		{"v6 answer out", ipv6UDP("2001:db8::1", "2001:db8::2", 53, 40000, q), unix.ETH_P_IPV6, out, false},
		{"arp", make([]byte, 28), unix.ETH_P_ARP, in, false},
		{"truncated", ipv4UDP("192.0.2.1", "192.0.2.2", 40000, 53, q)[:21], unix.ETH_P_IP, out, false},
	}
	for _, c := range cases {
		got := runCBPF(t, dnsPacketFilter, c.pkt, c.proto, c.pkttype) != 0
		if got != c.accept {
			t.Errorf("%s: accept=%v, want %v", c.name, got, c.accept)
		}
	}
}
