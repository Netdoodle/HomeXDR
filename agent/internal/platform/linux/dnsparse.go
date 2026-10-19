//go:build linux

package linux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// A small, defensive DNS message parser (RFC 1035) for the DNS sensor. It reads the
// header, the question and the answer section; it never panics and bounds every read, so
// truncated captures and hostile packets are fine. Names are lowercased, printed without
// the trailing dot ("." for the root) and escaped like zone files (\. \\ \DDD), so they
// cannot smuggle control characters into logs.

const (
	dnsHeaderLen     = 12
	dnsMaxQuestions  = 4   // questions kept (real queries have one)
	dnsMaxAnswers    = 64  // answer records parsed
	dnsMaxPointers   = 64  // compression pointers followed per name, against loops
	dnsMaxNameWire   = 255 // RFC 1035 2.3.4, including the root label
	dnsMaxDataLen    = 512 // characters of rendered RDATA kept
	dnsMaxGenericHex = 64  // RDATA bytes shown for types without a text form
)

var (
	errDNSShort   = errors.New("dns: message truncated")
	errDNSName    = errors.New("dns: name too long")
	errDNSLabel   = errors.New("dns: unsupported label type")
	errDNSPointer = errors.New("dns: too many compression pointers")
	errDNSNoQuery = errors.New("dns: no question")
)

// dnsMessage is the part of a DNS message the sensor reports.
type dnsMessage struct {
	ID        uint16
	Response  bool
	Opcode    uint8
	RCode     uint8 // header RCODE (the EDNS extension bits are not read)
	Truncated bool  // TC: the server truncated the answer; the client retries over TCP
	Questions []dnsQuestion
	Answers   []dnsRR
	// Partial is set when the input ended (or was malformed) inside the question or
	// answer sections; what was read before that is kept.
	Partial bool
}

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string // presentation form of the RDATA ("" if it could not be decoded)
}

// Record types with a presentation form.
const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
	dnsTypeDNAME = 39
	dnsTypeSVCB  = 64
	dnsTypeHTTPS = 65
	dnsTypeSPF   = 99
	dnsTypeCAA   = 257
)

var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
	17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV",
	35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS",
	44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
	50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP", 59: "CDS",
	60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
	99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR",
	252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}

// dnsTypeName returns the mnemonic of a record type, or "TYPE<n>" (RFC 3597).
func dnsTypeName(t uint16) string {
	if n, ok := dnsTypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

var dnsRCodeNames = [...]string{
	"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
	"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
}

// dnsRCodeName returns the mnemonic of a response code, or "RCODE<n>".
func dnsRCodeName(c uint8) string {
	if int(c) < len(dnsRCodeNames) {
		return dnsRCodeNames[c]
	}
	return "RCODE" + strconv.Itoa(int(c))
}

// parseDNS parses a DNS message. It fails only when the header or the first question
// cannot be read; later damage sets Partial.
func parseDNS(b []byte) (dnsMessage, error) {
	var m dnsMessage
	if len(b) < dnsHeaderLen {
		return m, errDNSShort
	}
	be := binary.BigEndian
	m.ID = be.Uint16(b[0:])
	flags := be.Uint16(b[2:])
	m.Response = flags&0x8000 != 0
	m.Opcode = uint8(flags>>11) & 0xf
	m.Truncated = flags&0x0200 != 0
	m.RCode = uint8(flags & 0xf)
	qd, an := int(be.Uint16(b[4:])), int(be.Uint16(b[6:]))

	off := dnsHeaderLen
	for i := 0; i < qd; i++ {
		name, next, err := readDNSName(b, off)
		if err == nil && next+4 > len(b) {
			err = errDNSShort
		}
		if err != nil {
			if len(m.Questions) == 0 {
				return m, err
			}
			m.Partial = true
			return m, nil
		}
		if len(m.Questions) < dnsMaxQuestions {
			m.Questions = append(m.Questions, dnsQuestion{Name: name, Type: be.Uint16(b[next:]), Class: be.Uint16(b[next+2:])})
		}
		off = next + 4
	}
	if len(m.Questions) == 0 {
		return m, errDNSNoQuery
	}
	for i := 0; i < an && i < dnsMaxAnswers; i++ {
		rr, next, err := readDNSRR(b, off)
		if err != nil {
			m.Partial = true
			break
		}
		m.Answers = append(m.Answers, rr)
		off = next
	}
	return m, nil
}

// readDNSName reads a possibly compressed name at off. It returns the name and the
// offset just past it (past the first pointer, if any).
func readDNSName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	wire := 1 // the root label
	ptrs := 0
	for {
		if off < 0 || off >= len(b) {
			return "", 0, errDNSShort
		}
		c := int(b[off])
		switch c & 0xc0 {
		case 0x00:
			if c == 0 {
				if next < 0 {
					next = off + 1
				}
				if sb.Len() == 0 {
					return ".", next, nil
				}
				return sb.String(), next, nil
			}
			if wire += c + 1; wire > dnsMaxNameWire {
				return "", 0, errDNSName
			}
			if off+1+c > len(b) {
				return "", 0, errDNSShort
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			writeDNSLabel(&sb, b[off+1:off+1+c])
			off += 1 + c
		case 0xc0:
			if off+2 > len(b) {
				return "", 0, errDNSShort
			}
			if next < 0 {
				next = off + 2
			}
			if ptrs++; ptrs > dnsMaxPointers {
				return "", 0, errDNSPointer
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
		default: // 0x40 (extended label types, RFC 6891) and 0x80 are not in use
			return "", 0, errDNSLabel
		}
	}
}

// writeDNSLabel appends a label in lowercase presentation form.
func writeDNSLabel(sb *strings.Builder, l []byte) {
	for _, c := range l {
		switch {
		case c >= 'A' && c <= 'Z':
			sb.WriteByte(c + ('a' - 'A'))
		case c == '.' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c > ' ' && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('\\')
			d := strconv.Itoa(int(c))
			sb.WriteString(strings.Repeat("0", 3-len(d)))
			sb.WriteString(d)
		}
	}
}

func readDNSRR(b []byte, off int) (dnsRR, int, error) {
	name, off, err := readDNSName(b, off)
	if err != nil {
		return dnsRR{}, 0, err
	}
	if off+10 > len(b) {
		return dnsRR{}, 0, errDNSShort
	}
	be := binary.BigEndian
	rr := dnsRR{Name: name, Type: be.Uint16(b[off:]), Class: be.Uint16(b[off+2:]), TTL: be.Uint32(b[off+4:])}
	n := int(be.Uint16(b[off+8:]))
	off += 10
	if off+n > len(b) {
		return dnsRR{}, 0, errDNSShort
	}
	rr.Data = dnsRData(b, off, n, rr.Type)
	return rr, off + n, nil
}

// dnsRData renders RDATA b[off:off+n]. Names inside it may point anywhere earlier in
// the message, so b is the whole message.
func dnsRData(b []byte, off, n int, typ uint16) string {
	rd := b[off : off+n]
	be := binary.BigEndian
	// name reads a name that must start at off+at and end inside the RDATA.
	name := func(at int) (string, int, bool) {
		s, next, err := readDNSName(b, off+at)
		if err != nil || next > off+n {
			return "", 0, false
		}
		return s, next - off, true
	}
	switch typ {
	case dnsTypeA:
		if n == 4 {
			return netip.AddrFrom4([4]byte(rd)).String()
		}
	case dnsTypeAAAA:
		if n == 16 {
			return netip.AddrFrom16([16]byte(rd)).String()
		}
	case dnsTypeCNAME, dnsTypeNS, dnsTypePTR, dnsTypeDNAME:
		if s, _, ok := name(0); ok {
			return s
		}
		return ""
	case dnsTypeMX:
		if n >= 3 {
			if s, _, ok := name(2); ok {
				return strconv.Itoa(int(be.Uint16(rd))) + " " + s
			}
		}
		return ""
	case dnsTypeSRV:
		if n >= 7 {
			if s, _, ok := name(6); ok {
				return strconv.Itoa(int(be.Uint16(rd))) + " " + strconv.Itoa(int(be.Uint16(rd[2:]))) + " " +
					strconv.Itoa(int(be.Uint16(rd[4:]))) + " " + s
			}
		}
		return ""
	case dnsTypeSVCB, dnsTypeHTTPS:
		// Priority and target; the SvcParams are not rendered.
		if n >= 3 {
			if s, _, ok := name(2); ok {
				return strconv.Itoa(int(be.Uint16(rd))) + " " + s
			}
		}
		return ""
	case dnsTypeSOA:
		mname, at, ok := name(0)
		if !ok {
			return ""
		}
		rname, at2, ok := name(at)
		if !ok || at2+20 > n {
			return ""
		}
		f := rd[at2:]
		return mname + " " + rname + " " + strconv.FormatUint(uint64(be.Uint32(f)), 10) + " " +
			strconv.FormatUint(uint64(be.Uint32(f[4:])), 10) + " " + strconv.FormatUint(uint64(be.Uint32(f[8:])), 10) + " " +
			strconv.FormatUint(uint64(be.Uint32(f[12:])), 10) + " " + strconv.FormatUint(uint64(be.Uint32(f[16:])), 10)
	case dnsTypeTXT, dnsTypeSPF:
		var parts []string
		for i := 0; i < n; {
			l := int(rd[i])
			if i+1+l > n {
				break
			}
			parts = append(parts, dnsQuote(rd[i+1:i+1+l]))
			i += 1 + l
		}
		return clip(strings.Join(parts, " "))
	case dnsTypeCAA:
		if n >= 2 {
			tl := int(rd[1])
			if 2+tl <= n {
				return clip(strconv.Itoa(int(rd[0])) + " " + dnsEscape(rd[2:2+tl]) + " " + dnsQuote(rd[2+tl:]))
			}
		}
		return ""
	}
	// RFC 3597 generic form.
	h := rd
	if len(h) > dnsMaxGenericHex {
		h = h[:dnsMaxGenericHex]
	}
	s := `\# ` + strconv.Itoa(n)
	if len(h) > 0 {
		s += " " + hex.EncodeToString(h)
	}
	return s
}

// dnsQuote renders a character-string in double quotes (see dnsEscape).
func dnsQuote(s []byte) string { return `"` + dnsEscape(s) + `"` }

// dnsEscape escapes '"', '\' and non-printable bytes (as \DDD).
func dnsEscape(s []byte) string {
	var sb strings.Builder
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c >= ' ' && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('\\')
			d := strconv.Itoa(int(c))
			sb.WriteString(strings.Repeat("0", 3-len(d)))
			sb.WriteString(d)
		}
	}
	return sb.String()
}

func clip(s string) string {
	if len(s) > dnsMaxDataLen {
		return s[:dnsMaxDataLen]
	}
	return s
}
