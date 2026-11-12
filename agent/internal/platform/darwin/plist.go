package darwin

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// A minimal property list decoder for launchd jobs, app bundles and package receipts.
// It reads the XML and binary (bplist00) formats into Go values: map[string]any,
// []any, string, int64, float64, bool, time.Time and []byte.

// appleEpoch is the reference date of plist dates (2001-01-01 UTC).
var appleEpoch = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// decodePlist decodes an XML or binary property list.
func decodePlist(b []byte) (any, error) {
	if bytes.HasPrefix(b, []byte("bplist00")) {
		return decodeBinaryPlist(b)
	}
	return decodeXMLPlist(b)
}

// ---- XML ----

func decodeXMLPlist(b []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return nil, errors.New("plist: no value")
			}
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return xmlValue(d, se, 0)
		}
	}
}

func xmlValue(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("plist: too deep")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		var key string
		haveKey := false
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					s, err := xmlText(d)
					if err != nil {
						return nil, err
					}
					key, haveKey = s, true
					continue
				}
				v, err := xmlValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				if haveKey {
					m[key] = v
					haveKey = false
				}
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	s, err := xmlText(d)
	if err != nil {
		return nil, err
	}
	switch se.Name.Local {
	case "string":
		return s, nil
	case "integer":
		s = strings.TrimSpace(s)
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			return n, nil
		}
		if n, err := strconv.ParseUint(s, 0, 64); err == nil {
			return int64(n), nil
		}
		return nil, fmt.Errorf("plist: bad integer %q", s)
	case "real":
		return strconv.ParseFloat(strings.TrimSpace(s), 64)
	case "date":
		return time.Parse(time.RFC3339, strings.TrimSpace(s))
	case "data":
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	}
	return s, nil
}

// xmlText reads character data up to the end of the current element.
func xmlText(d *xml.Decoder) (string, error) {
	var b strings.Builder
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return b.String(), nil
			}
			depth--
		}
	}
}

// ---- binary ----

type bplist struct {
	b         []byte
	offsets   []uint64
	refSize   int
	seenStack map[uint64]bool
}

func decodeBinaryPlist(b []byte) (any, error) {
	if len(b) < 8+32 {
		return nil, errors.New("bplist: too short")
	}
	tr := b[len(b)-32:]
	offSize, refSize := int(tr[6]), int(tr[7])
	numObj := binary.BigEndian.Uint64(tr[8:])
	top := binary.BigEndian.Uint64(tr[16:])
	tableOff := binary.BigEndian.Uint64(tr[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObj == 0 || numObj > 1<<24 ||
		tableOff >= uint64(len(b)) || tableOff+numObj*uint64(offSize) > uint64(len(b)-32) || top >= numObj {
		return nil, errors.New("bplist: bad trailer")
	}
	p := &bplist{b: b, refSize: refSize, seenStack: map[uint64]bool{}}
	p.offsets = make([]uint64, numObj)
	for i := range p.offsets {
		o := tableOff + uint64(i*offSize)
		p.offsets[i] = beUint(b[o : o+uint64(offSize)])
	}
	return p.object(top)
}

func beUint(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		n = n<<8 | uint64(c)
	}
	return n
}

// count returns the length in the low nibble, or the following int object when it is 0xF,
// and the offset after it.
func (p *bplist) count(off uint64, low byte) (uint64, uint64, error) {
	if low != 0x0F {
		return uint64(low), off + 1, nil
	}
	if off+1 >= uint64(len(p.b)) {
		return 0, 0, errors.New("bplist: truncated count")
	}
	m := p.b[off+1]
	if m>>4 != 0x1 {
		return 0, 0, errors.New("bplist: bad count")
	}
	n := uint64(1) << (m & 0x0F)
	start := off + 2
	if start+n > uint64(len(p.b)) {
		return 0, 0, errors.New("bplist: truncated count")
	}
	return beUint(p.b[start : start+n]), start + n, nil
}

func (p *bplist) ref(off uint64, i uint64) (uint64, error) {
	s := off + i*uint64(p.refSize)
	if s+uint64(p.refSize) > uint64(len(p.b)) {
		return 0, errors.New("bplist: truncated reference")
	}
	return beUint(p.b[s : s+uint64(p.refSize)]), nil
}

func (p *bplist) object(idx uint64) (any, error) {
	if idx >= uint64(len(p.offsets)) {
		return nil, errors.New("bplist: bad object reference")
	}
	if p.seenStack[idx] {
		return nil, errors.New("bplist: reference cycle")
	}
	p.seenStack[idx] = true
	defer delete(p.seenStack, idx)
	off := p.offsets[idx]
	if off >= uint64(len(p.b)) {
		return nil, errors.New("bplist: bad offset")
	}
	m := p.b[off]
	hi, low := m>>4, m&0x0F
	need := func(n uint64) ([]byte, error) {
		if off+1+n > uint64(len(p.b)) {
			return nil, errors.New("bplist: truncated object")
		}
		return p.b[off+1 : off+1+n], nil
	}
	switch hi {
	case 0x0:
		switch m {
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		}
		return nil, nil
	case 0x1:
		v, err := need(1 << low)
		if err != nil {
			return nil, err
		}
		return int64(beUint(v)), nil
	case 0x2:
		v, err := need(1 << low)
		if err != nil {
			return nil, err
		}
		if len(v) == 4 {
			return float64(math.Float32frombits(binary.BigEndian.Uint32(v))), nil
		}
		if len(v) == 8 {
			return math.Float64frombits(binary.BigEndian.Uint64(v)), nil
		}
		return nil, errors.New("bplist: bad real")
	case 0x3:
		v, err := need(8)
		if err != nil {
			return nil, err
		}
		secs := math.Float64frombits(binary.BigEndian.Uint64(v))
		return appleEpoch.Add(time.Duration(secs * float64(time.Second))), nil
	case 0x4, 0x5, 0x6:
		n, start, err := p.count(off, low)
		if err != nil {
			return nil, err
		}
		size := n
		if hi == 0x6 {
			size = n * 2
		}
		if start+size > uint64(len(p.b)) {
			return nil, errors.New("bplist: truncated data")
		}
		raw := p.b[start : start+size]
		switch hi {
		case 0x4:
			return append([]byte(nil), raw...), nil
		case 0x5:
			return string(raw), nil
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u)), nil
	case 0x8:
		v, err := need(uint64(low) + 1)
		if err != nil {
			return nil, err
		}
		return int64(beUint(v)), nil
	case 0xA:
		n, start, err := p.count(off, low)
		if err != nil {
			return nil, err
		}
		a := make([]any, 0, min(n, 4096))
		for i := uint64(0); i < n; i++ {
			r, err := p.ref(start, i)
			if err != nil {
				return nil, err
			}
			v, err := p.object(r)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case 0xD:
		n, start, err := p.count(off, low)
		if err != nil {
			return nil, err
		}
		d := map[string]any{}
		for i := uint64(0); i < n; i++ {
			kr, err := p.ref(start, i)
			if err != nil {
				return nil, err
			}
			vr, err := p.ref(start, n+i)
			if err != nil {
				return nil, err
			}
			k, err := p.object(kr)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errors.New("bplist: non-string key")
			}
			v, err := p.object(vr)
			if err != nil {
				return nil, err
			}
			d[ks] = v
		}
		return d, nil
	}
	return nil, fmt.Errorf("bplist: unknown object type 0x%x", m)
}

// ---- accessors ----

func plistString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func plistBool(m map[string]any, key string) (bool, bool) {
	b, ok := m[key].(bool)
	return b, ok
}

func plistStrings(m map[string]any, key string) []string {
	a, _ := m[key].([]any)
	out := make([]string, 0, len(a))
	for _, v := range a {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// launchdJob is the part of a launchd job definition the collectors use.
type launchdJob struct {
	Label     string
	Program   string   // Program, or ProgramArguments[0]
	Args      []string // ProgramArguments
	User      string
	Disabled  bool
	RunAtLoad bool
	KeepAlive bool
	// Triggers lists what else starts the job: StartInterval, StartCalendarInterval,
	// WatchPaths, QueueDirectories, Sockets, MachServices.
	Triggers []string
}

// parseLaunchdJob decodes a LaunchDaemons / LaunchAgents plist.
func parseLaunchdJob(b []byte) (launchdJob, error) {
	v, err := decodePlist(b)
	if err != nil {
		return launchdJob{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return launchdJob{}, errors.New("launchd job is not a dictionary")
	}
	j := launchdJob{Label: plistString(m, "Label"), Program: plistString(m, "Program"),
		Args: plistStrings(m, "ProgramArguments"), User: plistString(m, "UserName")}
	if j.Program == "" && len(j.Args) > 0 {
		j.Program = j.Args[0]
	}
	j.Disabled, _ = plistBool(m, "Disabled")
	j.RunAtLoad, _ = plistBool(m, "RunAtLoad")
	switch ka := m["KeepAlive"].(type) {
	case bool:
		j.KeepAlive = ka
	case map[string]any:
		j.KeepAlive = len(ka) > 0
	}
	for _, k := range []string{"StartInterval", "StartCalendarInterval", "WatchPaths", "QueueDirectories", "Sockets", "MachServices", "StartOnMount"} {
		if _, ok := m[k]; ok {
			j.Triggers = append(j.Triggers, k)
		}
	}
	return j, nil
}

// command renders the job's command line.
func (j launchdJob) command() string {
	if len(j.Args) > 0 {
		args := append([]string(nil), j.Args...)
		if j.Program != "" && j.Program != args[0] {
			args[0] = j.Program
		}
		return joinArgs(args)
	}
	return j.Program
}
