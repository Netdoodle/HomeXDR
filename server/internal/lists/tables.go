package lists

// The tables are sorted, pointer-free slices searched by bisection. A million domains in a Go
// map costs well over 100 MB and work for the garbage collector on every cycle; here they take
// about 8 bytes each plus their text, and the collector does not look inside.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	maxUnpacked = 256 << 20 // largest file taken out of an archive
	utf8BOM     = "\xef\xbb\xbf"
)

// tables are the lists currently answering. Each swaps atomically, so lookups never block.
type tables struct {
	ranks      atomic.Pointer[domainTable]
	categories atomic.Pointer[domainTable]
	newDomains atomic.Pointer[domainTable]
	asn        atomic.Pointer[asnTable]
	oui        atomic.Pointer[ouiTable]
}

// domainTable maps domains to a number. Domains are concatenated in sorted order.
type domainTable struct {
	blob []byte
	off  []uint32 // start of each domain; one extra at the end
	val  []uint32 // nil when there is nothing to store
}

func (t *domainTable) size() int { return len(t.off) - 1 }

// compareBytesString is bytes.Compare without allocating a conversion.
func compareBytesString(b []byte, s string) int {
	n := min(len(b), len(s))
	for i := range n {
		if b[i] != s[i] {
			if b[i] < s[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(b) < len(s):
		return -1
	case len(b) > len(s):
		return 1
	}
	return 0
}

// get finds a domain.
func (t *domainTable) get(name string) (uint32, bool) {
	if t == nil {
		return 0, false
	}
	lo, hi := 0, t.size()
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch compareBytesString(t.blob[t.off[mid]:t.off[mid+1]], name) {
		case 0:
			if t.val == nil {
				return 0, true
			}
			return t.val[mid], true
		case -1:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return 0, false
}

// domainRec points at a domain in the text being parsed, so a million domains are sorted
// without a million strings.
type domainRec struct {
	off uint32
	n   uint32
	val uint32
}

// buildDomainTable sorts records over data. On a duplicate, the lowest value wins, which is
// the best rank or the category that comes first in the precedence order.
func buildDomainTable(data []byte, recs []domainRec, withValues bool) *domainTable {
	slices.SortFunc(recs, func(a, b domainRec) int {
		if c := bytes.Compare(data[a.off:a.off+a.n], data[b.off:b.off+b.n]); c != 0 {
			return c
		}
		return int(int64(a.val) - int64(b.val))
	})
	size := 0
	kept := 0
	for i := range recs {
		if i > 0 && bytes.Equal(data[recs[i].off:recs[i].off+recs[i].n], data[recs[i-1].off:recs[i-1].off+recs[i-1].n]) {
			continue
		}
		size += int(recs[i].n)
		kept++
	}
	t := &domainTable{blob: make([]byte, 0, size), off: make([]uint32, 0, kept+1)}
	if withValues {
		t.val = make([]uint32, 0, kept)
	}
	for i := range recs {
		if i > 0 && bytes.Equal(data[recs[i].off:recs[i].off+recs[i].n], data[recs[i-1].off:recs[i-1].off+recs[i-1].n]) {
			continue
		}
		t.off = append(t.off, uint32(len(t.blob)))
		t.blob = append(t.blob, data[recs[i].off:recs[i].off+recs[i].n]...)
		if withValues {
			t.val = append(t.val, recs[i].val)
		}
	}
	t.off = append(t.off, uint32(len(t.blob)))
	return t
}

// lowerASCII lowers a domain in place. Domains in these lists are ASCII.
func lowerASCII(b []byte) {
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

// looksLikeDomain rejects comments, addresses with paths and stray HTML.
func looksLikeDomain(b []byte) bool {
	if len(b) < 3 || len(b) > 253 || bytes.IndexByte(b, '.') < 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// readUnzipped returns the first file in a zip archive, within a size limit.
func readUnzipped(path string) ([]byte, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readLimited(rc)
	}
	return nil, errors.New("the archive is empty")
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxUnpacked+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxUnpacked {
		return nil, errors.New("the file is larger than expected")
	}
	return b, nil
}

// parseTranco reads "rank,domain" lines.
func parseTranco(data []byte) (*domainTable, error) {
	recs := make([]domainRec, 0, len(data)/20)
	for pos := 0; pos < len(data); {
		end := bytes.IndexByte(data[pos:], '\n')
		if end < 0 {
			end = len(data) - pos
		}
		line := data[pos : pos+end]
		start := pos
		pos += end + 1
		line = bytes.TrimRight(line, "\r")
		comma := bytes.IndexByte(line, ',')
		if comma <= 0 {
			continue
		}
		rank, err := strconv.ParseUint(string(line[:comma]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("a line does not start with a rank: %.60q", line)
		}
		dom := line[comma+1:]
		if !looksLikeDomain(dom) {
			continue
		}
		lowerASCII(dom)
		recs = append(recs, domainRec{off: uint32(start + comma + 1), n: uint32(len(dom)), val: uint32(rank)})
	}
	return buildDomainTable(data, recs, true), nil
}

// appendDomainLines collects one domain per line, skipping anything else.
func appendDomainLines(data []byte, base uint32, val uint32, recs []domainRec) []domainRec {
	for pos := 0; pos < len(data); {
		end := bytes.IndexByte(data[pos:], '\n')
		if end < 0 {
			end = len(data) - pos
		}
		line := data[pos : pos+end]
		start := pos
		pos += end + 1
		trimmed := bytes.TrimRight(line, "\r \t")
		if !looksLikeDomain(trimmed) {
			continue
		}
		lowerASCII(trimmed)
		recs = append(recs, domainRec{off: base + uint32(start), n: uint32(len(trimmed)), val: val})
	}
	return recs
}

// readTarDomains takes every <category>/domains file out of a UT1 archive.
func readTarDomains(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "domains" {
			continue
		}
		b, err := readLimited(tr)
		if err != nil {
			return nil, err
		}
		out = append(append(out, b...), '\n')
	}
}

// asRange types hold no pointers, so the collector skips them.
type v4Range struct{ start, end, as uint32 }

type v6Range struct {
	start, end [16]byte
	as         uint32
}

type asEntry struct {
	asn     uint32
	nameOff uint32
	nameLen uint16
	cc      [2]byte
}

// asnTable maps address ranges to networks.
type asnTable struct {
	v4    []v4Range
	v6    []v6Range
	as    []asEntry
	names []byte
}

func (t *asnTable) entries() int { return len(t.v4) + len(t.v6) }

// parseIPToASN reads iptoasn's start, end, AS number, country and name, tab separated.
// Unrouted ranges have AS number 0 and are left out.
func parseIPToASN(r io.Reader) (*asnTable, error) {
	t := &asnTable{}
	type key struct {
		asn uint32
		cc  [2]byte
		n   string
	}
	seen := map[key]uint32{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 5)
		if len(f) < 5 {
			continue
		}
		asn, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("a line has no AS number: %.60q", sc.Text())
		}
		if asn == 0 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("a line has no address range: %.60q", sc.Text())
		}
		var cc [2]byte
		if len(f[3]) == 2 {
			copy(cc[:], f[3])
		}
		k := key{uint32(asn), cc, f[4]}
		idx, ok := seen[k]
		if !ok {
			idx = uint32(len(t.as))
			seen[k] = idx
			t.as = append(t.as, asEntry{asn: uint32(asn), cc: cc, nameOff: uint32(len(t.names)), nameLen: uint16(min(len(f[4]), 65535))})
			t.names = append(t.names, f[4][:min(len(f[4]), 65535)]...)
		}
		if start.Is4() && end.Is4() {
			s, e := start.As4(), end.As4()
			t.v4 = append(t.v4, v4Range{beUint32(s), beUint32(e), idx})
		} else {
			t.v6 = append(t.v6, v6Range{start.As16(), end.As16(), idx})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(t.v4, func(a, b v4Range) int {
		switch {
		case a.start < b.start:
			return -1
		case a.start > b.start:
			return 1
		}
		return 0
	})
	slices.SortFunc(t.v6, func(a, b v6Range) int { return bytes.Compare(a.start[:], b.start[:]) })
	return t, nil
}

func beUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// find returns the network holding an address.
func (t *asnTable) find(addr netip.Addr) (asEntry, bool) {
	if t == nil {
		return asEntry{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		v := beUint32(addr.As4())
		i, _ := slices.BinarySearchFunc(t.v4, v, func(r v4Range, target uint32) int {
			switch {
			case r.start <= target:
				return -1
			}
			return 1
		})
		if i > 0 && t.v4[i-1].end >= v {
			return t.as[t.v4[i-1].as], true
		}
		return asEntry{}, false
	}
	v := addr.As16()
	i, _ := slices.BinarySearchFunc(t.v6, v, func(r v6Range, target [16]byte) int {
		if bytes.Compare(r.start[:], target[:]) <= 0 {
			return -1
		}
		return 1
	})
	if i > 0 && bytes.Compare(t.v6[i-1].end[:], v[:]) >= 0 {
		return t.as[t.v6[i-1].as], true
	}
	return asEntry{}, false
}

func (t *asnTable) name(e asEntry) string {
	return string(t.names[e.nameOff : e.nameOff+uint32(e.nameLen)])
}

// ouiTable maps the first three bytes of a MAC address to a vendor.
type ouiTable struct {
	prefix  []uint32 // sorted
	off     []uint32 // start of each vendor; one extra at the end
	vendors []byte
}

func (t *ouiTable) size() int { return len(t.prefix) }

func (t *ouiTable) get(prefix uint32) (string, bool) {
	if t == nil {
		return "", false
	}
	i, ok := slices.BinarySearch(t.prefix, prefix)
	if !ok {
		return "", false
	}
	return string(t.vendors[t.off[i]:t.off[i+1]]), true
}

type ouiRec struct {
	prefix uint32
	vendor string
}

func buildOUI(recs []ouiRec) *ouiTable {
	slices.SortStableFunc(recs, func(a, b ouiRec) int {
		switch {
		case a.prefix < b.prefix:
			return -1
		case a.prefix > b.prefix:
			return 1
		}
		return 0
	})
	t := &ouiTable{}
	for i, r := range recs {
		if i > 0 && recs[i-1].prefix == r.prefix {
			continue
		}
		t.prefix = append(t.prefix, r.prefix)
		t.off = append(t.off, uint32(len(t.vendors)))
		t.vendors = append(t.vendors, r.vendor...)
	}
	t.off = append(t.off, uint32(len(t.vendors)))
	return t
}

// parseOUICSV reads IEEE's oui.csv: Registry,Assignment,Organization Name,Organization Address.
func parseOUICSV(r io.Reader) (*ouiTable, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header := true
	var recs []ouiRec
	for {
		f, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header {
			header = false
			if len(f) < 3 || !strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(f[0], utf8BOM)), "Registry") {
				return nil, fmt.Errorf("this does not look like an OUI list: %.60q", strings.Join(f, ","))
			}
			continue
		}
		if len(f) < 3 || f[0] != "MA-L" || len(f[1]) != 6 {
			continue
		}
		p, err := strconv.ParseUint(f[1], 16, 32)
		if err != nil {
			continue
		}
		recs = append(recs, ouiRec{uint32(p), strings.TrimSpace(f[2])})
	}
	return buildOUI(recs), nil
}

// parseManuf reads Wireshark's manuf file: 00:00:0C<tab>Short<tab>Long name. Longer prefixes
// with a mask are left out, since one vendor per three bytes is all this table holds.
func parseManuf(r io.Reader) (*ouiTable, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var recs []ouiRec
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		mac := strings.TrimSpace(f[0])
		if len(mac) != 8 {
			continue
		}
		p, err := strconv.ParseUint(strings.ReplaceAll(mac, ":", ""), 16, 32)
		if err != nil {
			continue
		}
		vendor := strings.TrimSpace(f[1])
		if len(f) >= 3 && strings.TrimSpace(f[2]) != "" {
			vendor = strings.TrimSpace(f[2])
		}
		recs = append(recs, ouiRec{uint32(p), vendor})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return buildOUI(recs), nil
}

// loadTranco reads the zip in dir.
func loadTranco(dir string) (*domainTable, error) {
	data, err := readUnzipped(filepath.Join(dir, trancoFile))
	if err != nil {
		return nil, err
	}
	return parseTranco(data)
}

// loadCategories merges the UT1 archives, in precedence order: a domain on two lists keeps
// the one that comes first.
func loadCategories(dir string) (*domainTable, error) {
	var data []byte
	var recs []domainRec
	for i, cat := range ut1Categories {
		b, err := readTarDomains(filepath.Join(dir, ut1File(cat.id)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cat.id, err)
		}
		base := uint32(len(data))
		data = append(data, b...)
		recs = appendDomainLines(b, base, uint32(i), recs)
	}
	// Lowering happened on the copies in b; data needs the same text.
	lowerASCII(data)
	return buildDomainTable(data, recs, true), nil
}

// loadNewDomains merges the daily newly registered domain files in dir.
func loadNewDomains(dir string) (*domainTable, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var data []byte
	var recs []domainRec
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		base := uint32(len(data))
		data = append(data, b...)
		recs = appendDomainLines(b, base, 0, recs)
	}
	lowerASCII(data)
	return buildDomainTable(data, recs, false), nil
}

func loadASN(dir string) (*asnTable, error) {
	f, err := os.Open(filepath.Join(dir, asnFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return parseIPToASN(io.LimitReader(gz, maxUnpacked))
}

func loadOUI(dir string) (*ouiTable, error) {
	if f, err := os.Open(filepath.Join(dir, ouiFile)); err == nil {
		defer f.Close()
		return parseOUICSV(f)
	}
	f, err := os.Open(filepath.Join(dir, manufFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseManuf(f)
}
