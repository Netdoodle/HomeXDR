// Package flow receives NetFlow v5, NetFlow v9 and IPFIX over UDP and stores each flow
// record as an event. Flow records name the real device on the LAN side of NAT, which the
// firewall's own logs usually cannot.
package flow

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Record is one decoded flow.
type Record struct {
	Version          int
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	TCPFlags         uint8
	Bytes, Packets   uint64
	Start, End       time.Time
	InIf, OutIf      uint32
}

// Result is what one packet produced.
type Result struct {
	Records []Record
	// Waiting counts data sets kept until their template arrives.
	Waiting int
	// Discarded counts data sets that were thrown away: no room to keep them.
	Discarded int
}

// Limits that keep a broken or hostile exporter from using much memory.
const (
	maxExporters     = 64
	maxTemplates     = 256 // per exporter
	maxPendingPerKey = 16  // data sets waiting for one template
	maxPendingSets   = 64  // data sets waiting per exporter
	pendingMaxAge    = 10 * time.Minute
	variableLength   = 65535
	v5HeaderLen      = 24
	v5RecordLen      = 48
	v9HeaderLen      = 20
	ipfixHeaderLen   = 16
	setHeaderLen     = 4
	firstDataSetID   = 256
	v9TemplateSet    = 0
	v9OptionsSet     = 1
	ipfixTemplateSet = 2
	ipfixOptionsSet  = 3
	enterpriseBit    = 0x8000
	fieldIDMask      = 0x7fff
	ianaOctetDelta   = 1
	ianaPacketDelta  = 2
	ianaProtocol     = 4
	ianaTCPFlags     = 6
	ianaSrcPort      = 7
	ianaSrcIPv4      = 8
	ianaInIf         = 10
	ianaDstPort      = 11
	ianaDstIPv4      = 12
	ianaOutIf        = 14
	ianaEndUptime    = 21
	ianaStartUptime  = 22
	ianaPostOctet    = 23
	ianaPostPacket   = 24
	ianaSrcIPv6      = 27
	ianaDstIPv6      = 28
	ianaOctetTotal   = 85
	ianaPacketTotal  = 86
	ianaStartSeconds = 150
	ianaEndSeconds   = 151
	ianaStartMillis  = 152
	ianaEndMillis    = 153
	ianaStartDeltaUs = 158
	ianaEndDeltaUs   = 159
	ianaSystemInitMs = 160
)

// ErrMalformed reports a packet that does not parse.
var ErrMalformed = errors.New("flow: malformed packet")

// ErrUnknownVersion reports a packet that is not NetFlow v5, v9 or IPFIX.
var ErrUnknownVersion = errors.New("flow: unknown version")

// ErrTooManyExporters reports a packet from an exporter past the limit.
var ErrTooManyExporters = errors.New("flow: too many exporters")

type templateKey struct {
	version uint16
	domain  uint32
	id      uint16
}

type field struct {
	id         uint16
	length     uint16
	enterprise bool
}

type template struct {
	fields []field
	minLen int
}

// header is the part of a packet's header that data records depend on.
type header struct {
	version  uint16
	uptimeMs uint32 // v9
	unixSecs uint32
}

type pendingSet struct {
	hdr  header
	data []byte
	at   time.Time
}

type exporter struct {
	templates map[templateKey]*template
	// options remembers options templates, whose data carries no flows.
	options  map[templateKey]bool
	pending  map[templateKey][]pendingSet
	npending int
}

// Decoder parses packets and caches templates per exporter. One goroutine uses it.
type Decoder struct {
	exporters map[string]*exporter
}

// NewDecoder returns an empty decoder.
func NewDecoder() *Decoder { return &Decoder{exporters: map[string]*exporter{}} }

// Templates returns how many templates are cached for an exporter.
func (d *Decoder) Templates(exporterID string) int {
	if e := d.exporters[exporterID]; e != nil {
		return len(e.templates)
	}
	return 0
}

// Decode parses one packet from an exporter. It keeps data sets whose template has not
// arrived yet and decodes them when it does, so their records come back later.
func (d *Decoder) Decode(exporterID string, pkt []byte, now time.Time) (Result, error) {
	if len(pkt) < 2 {
		return Result{}, ErrMalformed
	}
	switch binary.BigEndian.Uint16(pkt) {
	case 5:
		return decodeV5(pkt)
	case 9, 10:
	default:
		return Result{}, ErrUnknownVersion
	}
	e := d.exporters[exporterID]
	if e == nil {
		if len(d.exporters) >= maxExporters {
			return Result{}, ErrTooManyExporters
		}
		e = &exporter{templates: map[templateKey]*template{}, options: map[templateKey]bool{}, pending: map[templateKey][]pendingSet{}}
		d.exporters[exporterID] = e
	}
	if binary.BigEndian.Uint16(pkt) == 9 {
		return e.decodeV9(pkt, now)
	}
	return e.decodeIPFIX(pkt, now)
}

func decodeV5(pkt []byte) (Result, error) {
	if len(pkt) < v5HeaderLen {
		return Result{}, ErrMalformed
	}
	count := int(binary.BigEndian.Uint16(pkt[2:]))
	if len(pkt) < v5HeaderLen+count*v5RecordLen {
		return Result{}, ErrMalformed
	}
	h := header{version: 5, uptimeMs: binary.BigEndian.Uint32(pkt[4:]), unixSecs: binary.BigEndian.Uint32(pkt[8:])}
	res := Result{Records: make([]Record, 0, count)}
	for i := 0; i < count; i++ {
		b := pkt[v5HeaderLen+i*v5RecordLen:]
		var src, dst [4]byte
		copy(src[:], b[0:4])
		copy(dst[:], b[4:8])
		res.Records = append(res.Records, Record{
			Version: 5,
			Src:     netip.AddrFrom4(src), Dst: netip.AddrFrom4(dst),
			InIf: uint32(binary.BigEndian.Uint16(b[12:])), OutIf: uint32(binary.BigEndian.Uint16(b[14:])),
			Packets: uint64(binary.BigEndian.Uint32(b[16:])), Bytes: uint64(binary.BigEndian.Uint32(b[20:])),
			Start:   h.uptimeTime(binary.BigEndian.Uint32(b[24:])),
			End:     h.uptimeTime(binary.BigEndian.Uint32(b[28:])),
			SrcPort: binary.BigEndian.Uint16(b[32:]), DstPort: binary.BigEndian.Uint16(b[34:]),
			TCPFlags: b[37], Proto: b[38],
		})
	}
	return res, nil
}

// uptimeTime converts milliseconds since the exporter booted to a clock time.
func (h header) uptimeTime(ms uint32) time.Time {
	if h.unixSecs == 0 {
		return time.Time{}
	}
	behind := int64(int32(h.uptimeMs - ms)) // survives the 49-day wrap of the counter
	return time.UnixMilli(int64(h.unixSecs)*1000 - behind).UTC()
}

func (e *exporter) decodeV9(pkt []byte, now time.Time) (Result, error) {
	if len(pkt) < v9HeaderLen {
		return Result{}, ErrMalformed
	}
	h := header{version: 9, uptimeMs: binary.BigEndian.Uint32(pkt[4:]), unixSecs: binary.BigEndian.Uint32(pkt[8:])}
	domain := binary.BigEndian.Uint32(pkt[16:])
	return e.decodeSets(pkt[v9HeaderLen:], h, domain, now)
}

func (e *exporter) decodeIPFIX(pkt []byte, now time.Time) (Result, error) {
	if len(pkt) < ipfixHeaderLen {
		return Result{}, ErrMalformed
	}
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if total < ipfixHeaderLen || total > len(pkt) {
		return Result{}, ErrMalformed
	}
	h := header{version: 10, unixSecs: binary.BigEndian.Uint32(pkt[4:])}
	domain := binary.BigEndian.Uint32(pkt[12:])
	return e.decodeSets(pkt[ipfixHeaderLen:total], h, domain, now)
}

// decodeSets walks a v9 or IPFIX packet's sets. Sets are handled in order, so a template
// later in a packet still decodes data earlier in the same packet.
func (e *exporter) decodeSets(b []byte, h header, domain uint32, now time.Time) (Result, error) {
	var res Result
	for len(b) >= setHeaderLen {
		id := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < setHeaderLen || n > len(b) {
			return res, ErrMalformed
		}
		body := b[setHeaderLen:n]
		b = b[n:]
		var err error
		switch {
		case h.version == 9 && id == v9TemplateSet:
			err = e.readTemplates(body, h, domain, false, &res)
		case h.version == 9 && id == v9OptionsSet:
			err = e.readV9Options(body, domain, &res)
		case h.version == 10 && id == ipfixTemplateSet:
			err = e.readTemplates(body, h, domain, false, &res)
		case h.version == 10 && id == ipfixOptionsSet:
			err = e.readTemplates(body, h, domain, true, &res)
		case id >= firstDataSetID:
			e.readData(templateKey{h.version, domain, id}, body, h, now, &res)
		}
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// readTemplates reads a v9 or IPFIX template set; withOptions is the IPFIX options form,
// with its extra scope count. Trailing padding, shorter than a template header, is ignored.
func (e *exporter) readTemplates(b []byte, h header, domain uint32, withOptions bool, res *Result) error {
	head := 4
	if withOptions {
		head = 6
	}
	for len(b) >= head {
		id := binary.BigEndian.Uint16(b)
		count := int(binary.BigEndian.Uint16(b[2:]))
		if id == 0 && count == 0 {
			return nil // padding
		}
		b = b[head:]
		key := templateKey{h.version, domain, id}
		if count == 0 { // IPFIX withdrawal
			delete(e.templates, key)
			delete(e.options, key)
			continue
		}
		if id < firstDataSetID {
			return ErrMalformed
		}
		t := &template{}
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				return ErrMalformed
			}
			f := field{id: binary.BigEndian.Uint16(b), length: binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if h.version == 10 && f.id&enterpriseBit != 0 {
				if len(b) < 4 {
					return ErrMalformed
				}
				f.id &= fieldIDMask
				f.enterprise = true
				b = b[4:]
			}
			switch {
			case f.length != variableLength:
				t.minLen += int(f.length)
			case h.version == 10:
				t.minLen++
			default:
				return ErrMalformed // v9 has no variable-length fields
			}
			t.fields = append(t.fields, f)
		}
		if t.minLen == 0 {
			return ErrMalformed
		}
		if withOptions {
			e.options[key] = true
			delete(e.templates, key)
			delete(e.pending, key)
			continue
		}
		delete(e.options, key)
		if _, known := e.templates[key]; !known && len(e.templates) >= maxTemplates {
			continue
		}
		e.templates[key] = t
		e.replay(key, t, res)
	}
	return nil
}

// readV9Options notes the template IDs of a v9 options template set.
func (e *exporter) readV9Options(b []byte, domain uint32, _ *Result) error {
	for len(b) >= 6 {
		id := binary.BigEndian.Uint16(b)
		scope := int(binary.BigEndian.Uint16(b[2:]))
		opts := int(binary.BigEndian.Uint16(b[4:]))
		if id == 0 && scope == 0 && opts == 0 {
			return nil // padding
		}
		if id < firstDataSetID || len(b) < 6+scope+opts {
			return ErrMalformed
		}
		key := templateKey{9, domain, id}
		e.options[key] = true
		delete(e.templates, key)
		delete(e.pending, key)
		b = b[6+scope+opts:]
	}
	return nil
}

func (e *exporter) readData(key templateKey, b []byte, h header, now time.Time, res *Result) {
	if e.options[key] {
		return
	}
	t := e.templates[key]
	if t == nil {
		e.keep(key, b, h, now, res)
		return
	}
	t.decode(b, h, res)
}

// keep holds a data set until its template arrives. Exporters send templates only every
// so often, so after a restart of either side data usually comes first.
func (e *exporter) keep(key templateKey, b []byte, h header, now time.Time, res *Result) {
	for k, sets := range e.pending {
		kept := sets[:0]
		for _, s := range sets {
			if now.Sub(s.at) < pendingMaxAge {
				kept = append(kept, s)
			}
		}
		e.npending -= len(sets) - len(kept)
		if len(kept) == 0 {
			delete(e.pending, k)
		} else {
			e.pending[k] = kept
		}
	}
	if e.npending >= maxPendingSets || len(e.pending[key]) >= maxPendingPerKey {
		res.Discarded++
		return
	}
	e.pending[key] = append(e.pending[key], pendingSet{hdr: h, data: append([]byte(nil), b...), at: now})
	e.npending++
	res.Waiting++
}

func (e *exporter) replay(key templateKey, t *template, res *Result) {
	sets := e.pending[key]
	if len(sets) == 0 {
		return
	}
	delete(e.pending, key)
	e.npending -= len(sets)
	for _, s := range sets {
		t.decode(s.data, s.hdr, res)
	}
}

// decode reads every record in a data set. What is left over shorter than a record is padding.
func (t *template) decode(b []byte, h header, res *Result) {
	for len(b) >= t.minLen {
		r, n := t.record(b, h)
		if n == 0 {
			return
		}
		b = b[n:]
		if r.Src.IsValid() && r.Dst.IsValid() {
			res.Records = append(res.Records, r)
		}
	}
}

// record parses one record and returns the bytes it used, or 0 when it runs off the end.
func (t *template) record(b []byte, h header) (Record, int) {
	r := Record{Version: int(h.version)}
	var octets, packets, totalOctets, totalPackets, postOctets, postPackets uint64
	var startUp, endUp, startDelta, endDelta, sysInit uint64
	var hasStartUp, hasEndUp, hasStartDelta, hasEndDelta bool
	off := 0
	for _, f := range t.fields {
		n := int(f.length)
		if f.length == variableLength {
			if off >= len(b) {
				return r, 0
			}
			n = int(b[off])
			off++
			if n == 255 {
				if off+2 > len(b) {
					return r, 0
				}
				n = int(binary.BigEndian.Uint16(b[off:]))
				off += 2
			}
		}
		if off+n > len(b) {
			return r, 0
		}
		v := b[off : off+n]
		off += n
		if f.enterprise {
			continue
		}
		switch f.id {
		case ianaOctetDelta:
			octets = beUint(v)
		case ianaPacketDelta:
			packets = beUint(v)
		case ianaOctetTotal:
			totalOctets = beUint(v)
		case ianaPacketTotal:
			totalPackets = beUint(v)
		case ianaPostOctet:
			postOctets = beUint(v)
		case ianaPostPacket:
			postPackets = beUint(v)
		case ianaProtocol:
			r.Proto = uint8(beUint(v))
		case ianaTCPFlags:
			r.TCPFlags = uint8(beUint(v))
		case ianaSrcPort:
			r.SrcPort = uint16(beUint(v))
		case ianaDstPort:
			r.DstPort = uint16(beUint(v))
		case ianaInIf:
			r.InIf = uint32(beUint(v))
		case ianaOutIf:
			r.OutIf = uint32(beUint(v))
		case ianaSrcIPv4:
			setAddr(&r.Src, v, 4)
		case ianaDstIPv4:
			setAddr(&r.Dst, v, 4)
		case ianaSrcIPv6:
			setAddr(&r.Src, v, 16)
		case ianaDstIPv6:
			setAddr(&r.Dst, v, 16)
		case ianaStartUptime:
			startUp, hasStartUp = beUint(v), true
		case ianaEndUptime:
			endUp, hasEndUp = beUint(v), true
		case ianaStartSeconds:
			r.Start = time.Unix(int64(beUint(v)), 0).UTC()
		case ianaEndSeconds:
			r.End = time.Unix(int64(beUint(v)), 0).UTC()
		case ianaStartMillis:
			r.Start = time.UnixMilli(int64(beUint(v))).UTC()
		case ianaEndMillis:
			r.End = time.UnixMilli(int64(beUint(v))).UTC()
		case ianaStartDeltaUs:
			startDelta, hasStartDelta = beUint(v), true
		case ianaEndDeltaUs:
			endDelta, hasEndDelta = beUint(v), true
		case ianaSystemInitMs:
			sysInit = beUint(v)
		}
	}
	if off == 0 {
		return r, 0
	}
	r.Bytes = firstNonZero(octets, totalOctets, postOctets)
	r.Packets = firstNonZero(packets, totalPackets, postPackets)
	switch {
	case h.version == 9:
		if hasStartUp {
			r.Start = h.uptimeTime(uint32(startUp))
		}
		if hasEndUp {
			r.End = h.uptimeTime(uint32(endUp))
		}
	case sysInit != 0:
		if hasStartUp {
			r.Start = time.UnixMilli(int64(sysInit + startUp)).UTC()
		}
		if hasEndUp {
			r.End = time.UnixMilli(int64(sysInit + endUp)).UTC()
		}
	}
	export := time.Unix(int64(h.unixSecs), 0).UTC()
	if hasStartDelta {
		r.Start = export.Add(-time.Duration(startDelta) * time.Microsecond)
	}
	if hasEndDelta {
		r.End = export.Add(-time.Duration(endDelta) * time.Microsecond)
	}
	if h.unixSecs != 0 {
		if r.End.IsZero() {
			r.End = export
		}
		if r.Start.IsZero() {
			r.Start = r.End
		}
	}
	return r, off
}

func setAddr(dst *netip.Addr, v []byte, size int) {
	if len(v) != size {
		return
	}
	a, ok := netip.AddrFromSlice(v)
	if !ok || a.IsUnspecified() {
		return
	}
	*dst = a.Unmap()
}

func beUint(v []byte) uint64 {
	var n uint64
	for _, c := range v {
		n = n<<8 | uint64(c)
	}
	return n
}

func firstNonZero(vals ...uint64) uint64 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
