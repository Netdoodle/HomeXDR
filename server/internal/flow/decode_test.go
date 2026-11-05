package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

var (
	testNow    = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	exportSecs = uint32(testNow.Unix())
)

// Byte builders. Each returns big-endian wire bytes, so the fixtures read like the RFCs.

func u8(v uint8) []byte   { return []byte{v} }
func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func ip4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return a[:]
}
func ip6(s string) []byte {
	a := netip.MustParseAddr(s).As16()
	return a[:]
}
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// set wraps a body in a set header.
func set(id uint16, body ...[]byte) []byte {
	b := cat(body...)
	return cat(u16(id), u16(uint16(len(b)+4)), b)
}

func v9Packet(uptime uint32, sourceID uint32, sets ...[]byte) []byte {
	return cat(u16(9), u16(uint16(len(sets))), u32(uptime), u32(exportSecs), u32(1), u32(sourceID), cat(sets...))
}

func ipfixPacket(domain uint32, sets ...[]byte) []byte {
	b := cat(sets...)
	return cat(u16(10), u16(uint16(len(b)+16)), u32(exportSecs), u32(1), u32(domain), b)
}

// tmpl is a template record body: id, count, then (type, length) pairs.
func tmpl(id uint16, fields ...uint16) []byte {
	out := cat(u16(id), u16(uint16(len(fields)/2)))
	for _, f := range fields {
		out = append(out, u16(f)...)
	}
	return out
}

// A typical v9 template: addresses, ports, protocol, flags, counters, uptime times.
var v9Fields = []uint16{
	ianaSrcIPv4, 4, ianaDstIPv4, 4, ianaSrcPort, 2, ianaDstPort, 2, ianaProtocol, 1, ianaTCPFlags, 1,
	ianaOctetDelta, 4, ianaPacketDelta, 4, ianaStartUptime, 4, ianaEndUptime, 4, ianaInIf, 2, ianaOutIf, 2,
}

func v9Record(src, dst string, sport, dport uint16, octets, pkts, first, last uint32) []byte {
	return cat(ip4(src), ip4(dst), u16(sport), u16(dport), u8(6), u8(0x1b), u32(octets), u32(pkts), u32(first), u32(last), u16(3), u16(7))
}

func TestV5(t *testing.T) {
	rec := func(src, dst string, sport, dport uint16, pkts, octets, first, last uint32, proto uint8) []byte {
		return cat(ip4(src), ip4(dst), ip4("0.0.0.0"), u16(1), u16(2), u32(pkts), u32(octets), u32(first), u32(last),
			u16(sport), u16(dport), u8(0), u8(0x12), u8(proto), u8(0), u16(0), u16(0), u8(24), u8(0), u16(0))
	}
	pkt := cat(u16(5), u16(2), u32(100000), u32(exportSecs), u32(0), u32(9), u8(0), u8(0), u16(0),
		rec("192.168.20.5", "1.1.1.1", 50000, 443, 10, 1500, 90000, 95000, 6),
		rec("1.1.1.1", "192.168.20.5", 443, 50000, 8, 900, 90500, 95500, 6))
	res, err := NewDecoder().Decode("fw", pkt, testNow)
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("records %d err %v", len(res.Records), err)
	}
	r := res.Records[0]
	if r.Version != 5 || r.Src.String() != "192.168.20.5" || r.Dst.String() != "1.1.1.1" || r.SrcPort != 50000 || r.DstPort != 443 ||
		r.Proto != 6 || r.Bytes != 1500 || r.Packets != 10 || r.InIf != 1 || r.OutIf != 2 || r.TCPFlags != 0x12 {
		t.Fatalf("record %+v", r)
	}
	if want := testNow.Add(-10 * time.Second); !r.Start.Equal(want) {
		t.Errorf("start %s want %s", r.Start, want)
	}
	if want := testNow.Add(-5 * time.Second); !r.End.Equal(want) {
		t.Errorf("end %s want %s", r.End, want)
	}
	// A count that promises more records than arrived is malformed.
	if _, err := NewDecoder().Decode("fw", pkt[:len(pkt)-1], testNow); err != ErrMalformed {
		t.Errorf("truncated: %v", err)
	}
}

func TestV9TemplateThenData(t *testing.T) {
	d := NewDecoder()
	res, err := d.Decode("fw", v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...))), testNow)
	if err != nil || len(res.Records) != 0 || d.Templates("fw") != 1 {
		t.Fatalf("template: %+v %v", res, err)
	}
	res, err = d.Decode("fw", v9Packet(100000, 1, set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1500, 10, 90000, 99000), v9Record("192.168.20.6", "8.8.8.8", 50001, 53, 80, 1, 99000, 99000))), testNow)
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("data: %+v %v", res, err)
	}
	r := res.Records[0]
	if r.Version != 9 || r.Src.String() != "192.168.20.5" || r.DstPort != 443 || r.Bytes != 1500 || r.Packets != 10 || r.Proto != 6 || r.TCPFlags != 0x1b {
		t.Fatalf("record %+v", r)
	}
	if want := testNow.Add(-10 * time.Second); !r.Start.Equal(want) {
		t.Errorf("start %s", r.Start)
	}
	if want := testNow.Add(-time.Second); !r.End.Equal(want) {
		t.Errorf("end %s", r.End)
	}
}

func TestTemplateArrivingAfterData(t *testing.T) {
	data := v9Packet(100000, 1, set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1500, 10, 90000, 99000)))
	tpl := v9Packet(200000, 1, set(v9TemplateSet, tmpl(300, v9Fields...)))
	d := NewDecoder()
	res, err := d.Decode("fw", data, testNow)
	if err != nil || len(res.Records) != 0 || res.Waiting != 1 {
		t.Fatalf("data first: %+v %v", res, err)
	}
	res, err = d.Decode("fw", tpl, testNow)
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("template later: %+v %v", res, err)
	}
	// Decoded with the data packet's own clock, not the template packet's.
	if want := testNow.Add(-10 * time.Second); !res.Records[0].Start.Equal(want) {
		t.Errorf("start %s", res.Records[0].Start)
	}
	// Nothing left waiting.
	if res, _ = d.Decode("fw", tpl, testNow); len(res.Records) != 0 {
		t.Errorf("replayed twice: %+v", res)
	}

	// Template later in the same packet.
	d = NewDecoder()
	res, err = d.Decode("fw", v9Packet(100000, 1,
		set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1500, 10, 90000, 99000)),
		set(v9TemplateSet, tmpl(300, v9Fields...))), testNow)
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("same packet: %+v %v", res, err)
	}

	// IPFIX too.
	d = NewDecoder()
	ifx := []uint16{ianaSrcIPv4, 4, ianaDstIPv4, 4, ianaOctetDelta, 8}
	res, _ = d.Decode("fw", ipfixPacket(1, set(400, ip4("192.168.20.5"), ip4("1.1.1.1"), u64(5))), testNow)
	if res.Waiting != 1 {
		t.Fatalf("ipfix data first: %+v", res)
	}
	res, err = d.Decode("fw", ipfixPacket(1, set(ipfixTemplateSet, tmpl(400, ifx...))), testNow)
	if err != nil || len(res.Records) != 1 || res.Records[0].Bytes != 5 {
		t.Fatalf("ipfix template later: %+v %v", res, err)
	}
}

func TestPendingIsBoundedAndExpires(t *testing.T) {
	d := NewDecoder()
	data := v9Packet(100000, 1, set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1, 1, 1, 1)))
	waiting, discarded := 0, 0
	for range maxPendingPerKey + 5 {
		res, _ := d.Decode("fw", data, testNow)
		waiting += res.Waiting
		discarded += res.Discarded
	}
	if waiting != maxPendingPerKey || discarded != 5 {
		t.Fatalf("waiting %d discarded %d", waiting, discarded)
	}
	// Many template IDs still stop at the per-exporter limit.
	total := maxPendingPerKey
	for id := uint16(301); id < 301+maxPendingSets; id++ {
		res, _ := d.Decode("fw", v9Packet(100000, 1, set(id, v9Record("192.168.20.5", "1.1.1.1", 1, 2, 1, 1, 1, 1))), testNow)
		total += res.Waiting
	}
	if total != maxPendingSets {
		t.Fatalf("total waiting %d", total)
	}
	// Old sets are dropped, not decoded.
	later := testNow.Add(pendingMaxAge + time.Minute)
	if res, _ := d.Decode("fw", v9Packet(100000, 1, set(900, v9Record("192.168.20.5", "1.1.1.1", 1, 2, 1, 1, 1, 1))), later); res.Waiting != 1 {
		t.Fatalf("after expiry: %+v", res)
	}
	if res, _ := d.Decode("fw", v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...))), later); len(res.Records) != 0 {
		t.Fatalf("expired sets came back: %+v", res)
	}
}

func TestTemplatesArePerExporterAndDomain(t *testing.T) {
	d := NewDecoder()
	d.Decode("fw", v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...))), testNow)
	data := set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1, 1, 1, 1))
	if res, _ := d.Decode("other", v9Packet(100000, 1, data), testNow); res.Waiting != 1 {
		t.Errorf("another exporter used the template: %+v", res)
	}
	if res, _ := d.Decode("fw", v9Packet(100000, 2, data), testNow); res.Waiting != 1 {
		t.Errorf("another source ID used the template: %+v", res)
	}
	if res, _ := d.Decode("fw", v9Packet(100000, 1, data), testNow); len(res.Records) != 1 {
		t.Errorf("right exporter failed: %+v", res)
	}
}

func TestV9OptionsAndPadding(t *testing.T) {
	d := NewDecoder()
	// Options template, then its data, which holds no flows and is not "waiting".
	opt := cat(u16(280), u16(4), u16(8), u16(1), u16(4), u16(34), u16(4), u16(36), u16(2))
	res, err := d.Decode("fw", v9Packet(100000, 1, set(v9OptionsSet, opt, u16(0))), testNow)
	if err != nil {
		t.Fatal(err)
	}
	res, err = d.Decode("fw", v9Packet(100000, 1, set(280, u32(1), u32(1), u16(1))), testNow)
	if err != nil || len(res.Records) != 0 || res.Waiting != 0 {
		t.Fatalf("options data: %+v %v", res, err)
	}
	// A data set padded to a 4-byte boundary.
	d.Decode("fw", v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, ianaSrcIPv4, 4, ianaDstIPv4, 4, ianaProtocol, 1))), testNow)
	res, err = d.Decode("fw", v9Packet(100000, 1, set(300, ip4("192.168.20.5"), ip4("1.1.1.1"), u8(17), []byte{0, 0, 0})), testNow)
	if err != nil || len(res.Records) != 1 || res.Records[0].Proto != 17 {
		t.Fatalf("padded: %+v %v", res, err)
	}
}

func TestIPFIX(t *testing.T) {
	d := NewDecoder()
	v6 := []uint16{ianaSrcIPv6, 16, ianaDstIPv6, 16, ianaSrcPort, 2, ianaDstPort, 2, ianaProtocol, 1, ianaOctetTotal, 8, ianaPacketTotal, 8, ianaStartMillis, 8, ianaEndMillis, 8}
	if _, err := d.Decode("fw", ipfixPacket(7, set(ipfixTemplateSet, tmpl(400, v6...))), testNow); err != nil {
		t.Fatal(err)
	}
	startMs := uint64(testNow.Add(-time.Minute).UnixMilli())
	res, err := d.Decode("fw", ipfixPacket(7, set(400, ip6("fd00::5"), ip6("2001:db8::1"), u16(50000), u16(443), u8(6), u64(7000), u64(70), u64(startMs), u64(startMs+5000))), testNow)
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	r := res.Records[0]
	if r.Version != 10 || r.Src.String() != "fd00::5" || r.Dst.String() != "2001:db8::1" || r.Bytes != 7000 || r.Packets != 70 ||
		!r.Start.Equal(testNow.Add(-time.Minute)) || !r.End.Equal(testNow.Add(-55*time.Second)) {
		t.Fatalf("record %+v", r)
	}

	// Enterprise fields are skipped, variable-length fields move the offset, and short
	// counters and deltas decode.
	ent := cat(u16(401), u16(6),
		u16(ianaSrcIPv4), u16(4), u16(ianaDstIPv4), u16(4),
		u16(0x8000|12), u16(4), u32(29305), // an enterprise field that would be dstIP if read as IANA
		u16(82), u16(variableLength), // interfaceName
		u16(ianaOctetDelta), u16(2),
		u16(ianaStartDeltaUs), u16(4))
	if _, err := d.Decode("fw", ipfixPacket(7, set(ipfixTemplateSet, ent)), testNow); err != nil {
		t.Fatal(err)
	}
	long := make([]byte, 300)
	res, err = d.Decode("fw", ipfixPacket(7, set(401,
		ip4("192.168.20.5"), ip4("1.1.1.1"), ip4("9.9.9.9"), u8(4), []byte("igb0"), u16(1234), u32(2_000_000),
		ip4("192.168.20.6"), ip4("1.1.1.2"), ip4("9.9.9.9"), u8(255), u16(300), long, u16(99), u32(0),
	)), testNow)
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	r = res.Records[0]
	if r.Dst.String() != "1.1.1.1" || r.Bytes != 1234 || !r.Start.Equal(testNow.Add(-2*time.Second)) {
		t.Fatalf("record %+v", r)
	}
	if res.Records[1].Src.String() != "192.168.20.6" || res.Records[1].Bytes != 99 {
		t.Fatalf("second record %+v", res.Records[1])
	}

	// Uptime fields with the exporter's boot time; a record with no time uses the export time.
	boot := uint64(testNow.Add(-time.Hour).UnixMilli())
	up := []uint16{ianaSrcIPv4, 4, ianaDstIPv4, 4, ianaSystemInitMs, 8, ianaStartUptime, 4, ianaEndUptime, 4}
	d.Decode("fw", ipfixPacket(7, set(ipfixTemplateSet, tmpl(402, up...), tmpl(403, ianaSrcIPv4, 4, ianaDstIPv4, 4))), testNow)
	res, _ = d.Decode("fw", ipfixPacket(7, set(402, ip4("192.168.20.5"), ip4("1.1.1.1"), u64(boot), u32(1000), u32(2000)), set(403, ip4("192.168.20.5"), ip4("1.1.1.1"))), testNow)
	if len(res.Records) != 2 || !res.Records[0].Start.Equal(testNow.Add(-time.Hour+time.Second)) || !res.Records[1].Start.Equal(testNow) {
		t.Fatalf("times %+v", res.Records)
	}

	// An IPFIX options template hides its data; withdrawing a template forgets it.
	optT := cat(u16(410), u16(2), u16(1), u16(149), u16(4), u16(41), u16(8))
	d.Decode("fw", ipfixPacket(7, set(ipfixOptionsSet, optT)), testNow)
	if res, _ = d.Decode("fw", ipfixPacket(7, set(410, u32(1), u64(2))), testNow); res.Waiting != 0 || len(res.Records) != 0 {
		t.Fatalf("options data %+v", res)
	}
	d.Decode("fw", ipfixPacket(7, set(ipfixTemplateSet, cat(u16(403), u16(0)))), testNow)
	if res, _ = d.Decode("fw", ipfixPacket(7, set(403, ip4("192.168.20.5"), ip4("1.1.1.1"))), testNow); res.Waiting != 1 {
		t.Fatalf("withdrawn template still used: %+v", res)
	}
}

func TestMalformedPackets(t *testing.T) {
	d := NewDecoder()
	cases := map[string][]byte{
		"empty":          nil,
		"short":          {0},
		"v5 short":       u16(5),
		"v9 short":       cat(u16(9), u16(1)),
		"ipfix short":    cat(u16(10), u16(1)),
		"ipfix length":   cat(u16(10), u16(9000), u32(1), u32(1), u32(1)),
		"set too long":   v9Packet(1, 1, cat(u16(300), u16(4000))),
		"set too short":  v9Packet(1, 1, cat(u16(300), u16(2), u32(0))),
		"template cut":   v9Packet(1, 1, set(v9TemplateSet, cat(u16(300), u16(9), u16(8)))),
		"template id":    v9Packet(1, 1, set(v9TemplateSet, tmpl(5, ianaSrcIPv4, 4))),
		"zero length":    v9Packet(1, 1, set(v9TemplateSet, tmpl(300, ianaSrcIPv4, 0))),
		"v9 variable":    v9Packet(1, 1, set(v9TemplateSet, tmpl(300, ianaSrcIPv4, variableLength))),
		"enterprise cut": ipfixPacket(1, set(ipfixTemplateSet, cat(u16(400), u16(1), u16(0x8001), u16(4)))),
		"options cut":    v9Packet(1, 1, set(v9OptionsSet, cat(u16(300), u16(40), u16(40)))),
	}
	for name, pkt := range cases {
		if _, err := d.Decode("fw", pkt, testNow); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := d.Decode("fw", u16(1), testNow); err != ErrUnknownVersion {
		t.Errorf("version: %v", err)
	}

	// Every truncation of valid packets must decode without panicking.
	good := [][]byte{
		v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...)), set(300, v9Record("192.168.20.5", "1.1.1.1", 1, 2, 3, 4, 5, 6))),
		ipfixPacket(1, set(ipfixTemplateSet, cat(u16(400), u16(2), u16(ianaSrcIPv4), u16(4), u16(82), u16(variableLength))), set(400, ip4("192.168.20.5"), u8(255), u16(500), []byte("x"))),
	}
	for _, pkt := range good {
		for i := range pkt {
			NewDecoder().Decode("fw", pkt[:i], testNow)
			flipped := append([]byte(nil), pkt...)
			flipped[i] ^= 0xff
			NewDecoder().Decode("fw", flipped, testNow)
		}
	}
	// A variable-length record that runs off the end stops the set, without error.
	dv := NewDecoder()
	dv.Decode("fw", ipfixPacket(1, set(ipfixTemplateSet, cat(u16(400), u16(3), u16(ianaSrcIPv4), u16(4), u16(ianaDstIPv4), u16(4), u16(82), u16(variableLength)))), testNow)
	if res, err := dv.Decode("fw", ipfixPacket(1, set(400, ip4("192.168.20.5"), ip4("1.1.1.1"), u8(200), []byte("x"))), testNow); err != nil || len(res.Records) != 0 {
		t.Errorf("%+v %v", res, err)
	}
}

func TestTooManyExporters(t *testing.T) {
	d := NewDecoder()
	pkt := v9Packet(1, 1, set(v9TemplateSet, tmpl(300, ianaSrcIPv4, 4)))
	for i := range maxExporters {
		if _, err := d.Decode(string(rune('a'+i)), pkt, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Decode("one too many", pkt, testNow); err != ErrTooManyExporters {
		t.Fatalf("err %v", err)
	}
}

func TestRecordEvent(t *testing.T) {
	start := testNow.Add(-time.Minute)
	r := &Record{
		Version: 9, Src: netip.MustParseAddr("192.168.20.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SrcPort: 50000, DstPort: 443, Proto: 6, TCPFlags: 0x12, Bytes: 1500, Packets: 10, Start: start, End: testNow, InIf: 3,
	}
	ev := recordEvent(r, testNow)
	if ev.Event.Module != event.ModuleNetFlow || ev.Event.Dataset != "netflow.flow" || !ev.Timestamp.Equal(start) {
		t.Fatalf("meta %+v at %s", ev.Event, ev.Timestamp)
	}
	if ev.Source.IP != "192.168.20.5" || ev.Source.Port != 50000 || ev.Destination.IP != "1.1.1.1" || ev.Destination.Port != 443 {
		t.Fatalf("endpoints %+v %+v", ev.Source, ev.Destination)
	}
	n := ev.Network
	if n.Transport != "tcp" || n.Bytes != 1500 || n.Packets != 10 || n.Direction != event.DirectionOutbound || n.CommunityID == "" || n.Type != "ipv4" {
		t.Fatalf("network %+v", n)
	}
	if ev.Event.Duration != time.Minute.Nanoseconds() || ev.Data["tcp_flags"] != "SA" || ev.Data["flow_end"] == nil {
		t.Fatalf("details %+v %+v", ev.Event, ev.Data)
	}
	// A reply is inbound and a flow without times takes the time it arrived.
	rev := recordEvent(&Record{Src: r.Dst, Dst: r.Src, Proto: 17}, testNow)
	if rev.Network.Direction != event.DirectionInbound || rev.Network.Transport != "udp" || !rev.Timestamp.Equal(testNow) {
		t.Fatalf("reply %+v at %s", rev.Network, rev.Timestamp)
	}
	if got := transportName(99); got != "99" {
		t.Errorf("transport %s", got)
	}
}
