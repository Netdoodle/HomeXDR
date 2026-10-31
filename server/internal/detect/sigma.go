// Package detect implements a Sigma rule engine over HomeXDR events.
//
// Supported: field matching with the modifiers contains, startswith, endswith, all, re
// (with i/m/s), cidr, base64, base64offset, utf16le/utf16be/utf16/wide, windash, exists,
// cased, gt/gte/lt/lte, plain wildcards (* ?), null values, keyword lists, and conditions
// with and/or/not, parentheses, "1 of X*", "all of X*", "any of", "of them".
// Not supported (rules using them fail to compile): aggregations ("| count()"),
// correlation rules, placeholders ("%name%" with |expand) and field references (|fieldref).
package detect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

// Rule is a parsed and compiled Sigma rule.
type Rule struct {
	ID             string    `yaml:"id"`
	Title          string    `yaml:"title"`
	Status         string    `yaml:"status"`
	Description    string    `yaml:"description"`
	References     []string  `yaml:"references"`
	Author         string    `yaml:"author"`
	Date           string    `yaml:"date"`
	Modified       string    `yaml:"modified"`
	Tags           []string  `yaml:"tags"`
	LogSource      LogSource `yaml:"logsource"`
	Detection      yaml.Node `yaml:"detection"`
	FalsePositives []string  `yaml:"falsepositives"`
	Level          string    `yaml:"level"`

	// YAML is the source text.
	YAML string `yaml:"-"`

	cond      condNode
	logsource *logsourceFilter
}

// LogSource is the Sigma logsource block.
type LogSource struct {
	Category string `yaml:"category" json:"category,omitempty"`
	Product  string `yaml:"product" json:"product,omitempty"`
	Service  string `yaml:"service" json:"service,omitempty"`
}

// ParseRule parses and compiles one Sigma rule document.
func ParseRule(src []byte) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(src, &r); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	r.YAML = string(src)
	if strings.TrimSpace(r.Title) == "" {
		return nil, errors.New("rule has no title")
	}
	if strings.TrimSpace(r.ID) == "" {
		return nil, errors.New("rule has no id")
	}
	r.Level = strings.ToLower(strings.TrimSpace(r.Level))
	switch r.Level {
	case "informational", "low", "medium", "high", "critical":
	case "":
		r.Level = "medium"
	default:
		return nil, fmt.Errorf("unknown level %q", r.Level)
	}
	if err := r.compile(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ParseRules parses a file that may hold several YAML documents. Documents that are not
// rules are skipped; the first rule that fails is returned as the error.
func ParseRules(src []byte) ([]*Rule, error) {
	docs, err := ParseDocuments(src)
	var out []*Rule
	for _, d := range docs {
		if d.Err != nil {
			return out, d.Err
		}
		out = append(out, d.Rule)
	}
	return out, err
}

// Document is one Sigma rule document in a file: the metadata read from it, and the
// compiled rule or why it cannot run.
type Document struct {
	ID        string
	Title     string
	Status    string // lower case; "" when the rule has none
	Level     string // lower case; "medium" when the rule has none
	LogSource LogSource
	Rule      *Rule // nil when Err is set
	Err       error
}

// ParseDocuments parses every rule document in a file and reports each one's result, so
// one rule the engine cannot run does not hide the others in the file. Documents that are
// not Sigma rules (no detection or correlation) are skipped. The error is for YAML the
// decoder cannot read; documents before it are returned.
func ParseDocuments(src []byte) ([]Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var out []Document
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, fmt.Errorf("yaml: %w", err)
		}
		b, err := yaml.Marshal(&node)
		if err != nil {
			return out, err
		}
		var probe struct {
			ID          any       `yaml:"id"`
			Title       any       `yaml:"title"`
			Status      any       `yaml:"status"`
			Level       any       `yaml:"level"`
			LogSource   LogSource `yaml:"logsource"`
			Detection   any       `yaml:"detection"`
			Correlation any       `yaml:"correlation"`
		}
		_ = yaml.Unmarshal(b, &probe)
		if probe.Detection == nil && probe.Correlation == nil {
			continue
		}
		d := Document{
			ID: scalar(probe.ID), Title: scalar(probe.Title), LogSource: probe.LogSource,
			Status: strings.ToLower(scalar(probe.Status)), Level: strings.ToLower(scalar(probe.Level)),
		}
		if d.Level == "" {
			d.Level = "medium"
		}
		if probe.Correlation != nil {
			d.Err = errors.New("correlation rules are not supported")
		} else {
			d.Rule, d.Err = ParseRule(b)
		}
		out = append(out, d)
	}
}

// scalar renders a YAML scalar decoded into an any ("" for anything else).
func scalar(v any) string {
	switch v.(type) {
	case string, int, float64, bool:
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}

// Match evaluates the rule against a document.
func (r *Rule) Match(d *Doc) bool {
	if r.logsource != nil && !r.logsource.match(d) {
		return false
	}
	return r.cond.eval(d)
}

func (r *Rule) compile() error {
	if r.Detection.Kind != yaml.MappingNode {
		return errors.New("detection must be a mapping")
	}
	searches := map[string]matcher{}
	var condition []string
	for i := 0; i+1 < len(r.Detection.Content); i += 2 {
		key := r.Detection.Content[i].Value
		val := r.Detection.Content[i+1]
		if key == "condition" {
			switch val.Kind {
			case yaml.ScalarNode:
				condition = []string{val.Value}
			case yaml.SequenceNode:
				for _, c := range val.Content {
					condition = append(condition, c.Value)
				}
			default:
				return errors.New("condition must be a string or list")
			}
			continue
		}
		if key == "timeframe" {
			return errors.New("timeframe/aggregation rules are not supported")
		}
		m, err := compileSearch(val)
		if err != nil {
			return fmt.Errorf("search %q: %w", key, err)
		}
		searches[key] = m
	}
	if len(condition) == 0 {
		return errors.New("detection has no condition")
	}
	var conds []condNode
	for _, c := range condition {
		if strings.Contains(c, "|") {
			return errors.New("aggregation conditions are not supported")
		}
		n, err := parseCondition(c, searches)
		if err != nil {
			return fmt.Errorf("condition %q: %w", c, err)
		}
		conds = append(conds, n)
	}
	if len(conds) == 1 {
		r.cond = conds[0]
	} else {
		r.cond = orCond(conds)
	}
	ls, err := compileLogsource(r.LogSource)
	if err != nil {
		return err
	}
	r.logsource = ls
	return nil
}

// matcher evaluates a search identifier.
type matcher interface {
	match(d *Doc) bool
}

type allOf []matcher

func (a allOf) match(d *Doc) bool {
	for _, m := range a {
		if !m.match(d) {
			return false
		}
	}
	return true
}

type anyOf []matcher

func (a anyOf) match(d *Doc) bool {
	for _, m := range a {
		if m.match(d) {
			return true
		}
	}
	return false
}

func compileSearch(n *yaml.Node) (matcher, error) {
	switch n.Kind {
	case yaml.MappingNode:
		return compileMap(n)
	case yaml.SequenceNode:
		// A list of maps is OR of maps; a list of scalars is a keyword search.
		var ms anyOf
		var keywords []*yaml.Node
		for _, c := range n.Content {
			switch c.Kind {
			case yaml.MappingNode:
				m, err := compileMap(c)
				if err != nil {
					return nil, err
				}
				ms = append(ms, m)
			case yaml.ScalarNode:
				keywords = append(keywords, c)
			default:
				return nil, errors.New("unsupported list item")
			}
		}
		if len(keywords) > 0 {
			km, err := compileKeywords(keywords)
			if err != nil {
				return nil, err
			}
			ms = append(ms, km)
		}
		return ms, nil
	case yaml.ScalarNode:
		return compileKeywords([]*yaml.Node{n})
	}
	return nil, errors.New("unsupported search type")
}

func compileMap(n *yaml.Node) (matcher, error) {
	var all allOf
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		fm, err := compileField(key, n.Content[i+1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		all = append(all, fm)
	}
	return all, nil
}

// valueMatcher tests one string value.
type valueMatcher func(v string) bool

type fieldMatcher struct {
	field    string
	matchAll bool // "all" modifier: every value matcher must match
	vals     []valueMatcher
	exists   *bool // exists modifier or null value
}

func (f *fieldMatcher) match(d *Doc) bool {
	values, present := d.Get(f.field)
	if f.exists != nil {
		return present == *f.exists
	}
	if len(f.vals) == 0 {
		return false
	}
	if f.matchAll {
		for _, vm := range f.vals {
			if !anyValue(values, vm) {
				return false
			}
		}
		return true
	}
	for _, vm := range f.vals {
		if anyValue(values, vm) {
			return true
		}
	}
	return false
}

func anyValue(values []string, vm valueMatcher) bool {
	for _, v := range values {
		if vm(v) {
			return true
		}
	}
	return false
}

func compileField(key string, n *yaml.Node) (matcher, error) {
	parts := strings.Split(key, "|")
	field := parts[0]
	mods := parts[1:]
	fm := &fieldMatcher{field: field}

	var raw []*yaml.Node
	switch n.Kind {
	case yaml.ScalarNode:
		raw = []*yaml.Node{n}
	case yaml.SequenceNode:
		raw = n.Content
	default:
		return nil, errors.New("value must be a scalar or list")
	}

	var (
		op      = "eq"
		cased   bool
		reFlags string
		encode  []string // applied in order: utf16 variants, base64, base64offset
		windash bool
	)
	for _, m := range mods {
		switch strings.ToLower(m) {
		case "contains":
			op = "contains"
		case "startswith":
			op = "startswith"
		case "endswith":
			op = "endswith"
		case "all":
			fm.matchAll = true
		case "re":
			op = "re"
		case "i", "m", "s":
			reFlags += strings.ToLower(m)
		case "cidr":
			op = "cidr"
		case "exists":
			op = "exists"
		case "cased":
			cased = true
		case "gt", "gte", "lt", "lte":
			op = strings.ToLower(m)
		case "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide":
			encode = append(encode, strings.ToLower(m))
		case "windash":
			windash = true
		default:
			return nil, fmt.Errorf("unsupported modifier %q", m)
		}
	}

	if op == "exists" {
		if len(raw) != 1 {
			return nil, errors.New("exists takes one boolean")
		}
		b, err := strconv.ParseBool(raw[0].Value)
		if err != nil {
			return nil, errors.New("exists takes true or false")
		}
		fm.exists = &b
		return fm, nil
	}

	for _, rn := range raw {
		if rn.Kind != yaml.ScalarNode {
			return nil, errors.New("nested values are not supported")
		}
		if rn.Tag == "!!null" {
			f := false
			fm.exists = &f
			continue
		}
		val := rn.Value
		vms, err := buildValueMatchers(val, op, cased, reFlags, encode, windash)
		if err != nil {
			return nil, err
		}
		fm.vals = append(fm.vals, vms...)
	}
	if fm.exists != nil && len(fm.vals) > 0 {
		// "field: [null, x]" means absent OR x.
		ex := fm.exists
		fm.exists = nil
		absent := &fieldMatcher{field: field, exists: ex}
		return anyOf{absent, fm}, nil
	}
	return fm, nil
}

func buildValueMatchers(val, op string, cased bool, reFlags string, encode []string, windash bool) ([]valueMatcher, error) {
	switch op {
	case "re":
		expr := val
		if reFlags != "" {
			expr = "(?" + reFlags + ")" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("bad regex: %w", err)
		}
		return []valueMatcher{re.MatchString}, nil
	case "cidr":
		pfx, err := netip.ParsePrefix(val)
		if err != nil {
			return nil, fmt.Errorf("bad cidr %q", val)
		}
		return []valueMatcher{func(v string) bool {
			a, err := netip.ParseAddr(v)
			return err == nil && pfx.Contains(a.Unmap())
		}}, nil
	case "gt", "gte", "lt", "lte":
		limit, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("%s needs a number", op)
		}
		return []valueMatcher{func(v string) bool {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return false
			}
			switch op {
			case "gt":
				return f > limit
			case "gte":
				return f >= limit
			case "lt":
				return f < limit
			}
			return f <= limit
		}}, nil
	}

	// String matching. Expand the value through windash and encodings into candidates.
	candidates := []string{val}
	if windash {
		candidates = expandWindash(candidates)
	}
	if len(encode) > 0 {
		var err error
		candidates, err = applyEncodings(candidates, encode)
		if err != nil {
			return nil, err
		}
		cased = true // encoded output is case-sensitive
	}
	var out []valueMatcher
	for _, c := range candidates {
		out = append(out, wildcardMatcher(c, op, cased))
	}
	return out, nil
}

// wildcardMatcher compiles a Sigma value (with * and ? wildcards and \ escapes) for op.
func wildcardMatcher(val, op string, cased bool) valueMatcher {
	pattern := val
	switch op {
	case "contains":
		pattern = "*" + val + "*"
	case "startswith":
		pattern = val + "*"
	case "endswith":
		pattern = "*" + val
	}
	// Fast paths when there are no wildcards inside the literal.
	lit, hasWild := sigmaLiteral(val)
	if !hasWild {
		if !cased {
			lit = strings.ToLower(lit)
		}
		norm := func(v string) string {
			if cased {
				return v
			}
			return strings.ToLower(v)
		}
		switch op {
		case "contains":
			return func(v string) bool { return strings.Contains(norm(v), lit) }
		case "startswith":
			return func(v string) bool { return strings.HasPrefix(norm(v), lit) }
		case "endswith":
			return func(v string) bool { return strings.HasSuffix(norm(v), lit) }
		default:
			return func(v string) bool { return norm(v) == lit }
		}
	}
	re := regexp.MustCompile(globToRegex(pattern, cased))
	return re.MatchString
}

// sigmaLiteral unescapes a value and reports whether it has unescaped wildcards.
func sigmaLiteral(s string) (string, bool) {
	var b strings.Builder
	wild := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '*' || c == '?' {
			wild = true
		}
		b.WriteByte(c)
	}
	return b.String(), wild
}

func globToRegex(s string, cased bool) string {
	var b strings.Builder
	if !cased {
		b.WriteString("(?is)")
	} else {
		b.WriteString("(?s)")
	}
	b.WriteString("^")
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(string(s[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// windash variants: a leading "-" or "/" on command-line switches, plus en/em dashes.
var dashes = []string{"-", "/", "–", "—", "―"}

func expandWindash(vals []string) []string {
	var out []string
	for _, v := range vals {
		seen := map[string]bool{}
		for _, d := range dashes {
			r := v
			if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "/") {
				r = d + v[1:]
			}
			r = strings.ReplaceAll(r, " -", " "+d)
			r = strings.ReplaceAll(r, " /", " "+d)
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func applyEncodings(vals []string, encs []string) ([]string, error) {
	out := vals
	for _, e := range encs {
		var next []string
		for _, v := range out {
			switch e {
			case "utf16le", "wide", "utf16":
				next = append(next, string(utf16Bytes(v, false, e == "utf16")))
			case "utf16be":
				next = append(next, string(utf16Bytes(v, true, false)))
			case "base64":
				next = append(next, base64.StdEncoding.EncodeToString([]byte(v)))
			case "base64offset":
				next = append(next, base64Offsets([]byte(v))...)
			}
		}
		out = next
	}
	return out, nil
}

func utf16Bytes(s string, bigEndian, bom bool) []byte {
	u := utf16.Encode([]rune(s))
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, c := range u {
		if bigEndian {
			b = append(b, byte(c>>8), byte(c))
		} else {
			b = append(b, byte(c), byte(c>>8))
		}
	}
	return b
}

// base64Offsets returns the three base64 forms of v at byte offsets 0, 1 and 2 within a
// larger encoded string, trimmed to the stable middle characters (Sigma semantics).
func base64Offsets(v []byte) []string {
	startOff := []int{0, 2, 3}
	endOff := []int{0, -3, -2}
	var out []string
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{' '}, i), v...))
		end := len(enc) + endOff[(len(v)+i)%3]
		if end < startOff[i] {
			continue
		}
		out = append(out, enc[startOff[i]:end])
	}
	return out
}

// keywordMatcher matches values anywhere in the document's free-text fields.
type keywordMatcher struct {
	vals []valueMatcher
}

func (k *keywordMatcher) match(d *Doc) bool {
	for _, text := range d.Keywords() {
		for _, vm := range k.vals {
			if vm(text) {
				return true
			}
		}
	}
	return false
}

func compileKeywords(nodes []*yaml.Node) (matcher, error) {
	km := &keywordMatcher{}
	for _, n := range nodes {
		vms, err := buildValueMatchers(n.Value, "contains", false, "", nil, false)
		if err != nil {
			return nil, err
		}
		km.vals = append(km.vals, vms...)
	}
	return km, nil
}
