package events

// The search pipeline, modelled on Splunk's SPL:
//
//	<filter> | command args | command args ...
//
// The filter is the query language in query.go (plus field=value, field!=value and
// field>N). Commands:
//
//	stats <agg>[ as name], ... [by field, ...]     count, count(f), dc(f), sum, avg/mean, min, max, values
//	timechart [span=5m] [limit=N] <agg> [by f]     must be the last command
//	top [limit=N] f ...  /  rare [limit=N] f ...   most / least common values, with count and percent
//	table f, ...  /  fields f, ...                 a table of those fields
//	sort [N] [-|+]f, ...                           - is descending
//	head [N] / limit N                             first N (default 10)
//	dedup [N] f, ...                               keep the first N per value combination
//	where <expression>                             filter with an expression
//	eval name = <expression>, ...                  computed fields
//	rename f as g, ...
//	rex [field=f] "regex with (?<name>...)"        extract fields (ClickHouse only)
//	search <filter>                                more filtering, before any stats-like command
//
// Expressions: numbers, "strings", field names ('quoted' for odd names), + - * / %,
// "." to join strings, = == != < <= > >=, AND OR NOT, parentheses, and the functions
// if, case, coalesce, lower, upper, len, round, abs, tonumber, tostring, substr, like,
// match (ClickHouse only), isnull, isnotnull, null.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Pipeline is a parsed search: a filter and commands.
type Pipeline struct {
	Filter   string
	Commands []Command
}

// Command is one pipeline stage.
type Command interface{ cmdName() string }

type aggSpec struct {
	Fn    string // count, dc, sum, avg, min, max, values
	Field string // "" for plain count
	As    string // display name
}

type statsCmd struct {
	Aggs []aggSpec
	By   []string
}

type timechartCmd struct {
	Span  time.Duration // 0 = automatic
	Limit int
	Agg   aggSpec
	By    string
}

type topCmd struct {
	Rare   bool
	Limit  int
	Fields []string
}

type tableCmd struct{ Fields []string }

type sortKey struct {
	Field string
	Desc  bool
}

type sortCmd struct {
	Limit int
	Keys  []sortKey
}

type headCmd struct{ N int }

type dedupCmd struct {
	N      int
	Fields []string
}

type whereCmd struct{ Expr Expr }

type evalAssign struct {
	Name string
	Expr Expr
}

type evalCmd struct{ Assigns []evalAssign }

type renameCmd struct{ Pairs [][2]string }

type rexCmd struct {
	Field   string
	Pattern string   // with named groups rewritten for the database
	Names   []string // group names, in order
}

type searchCmd struct{ Query string }

func (statsCmd) cmdName() string     { return "stats" }
func (timechartCmd) cmdName() string { return "timechart" }
func (c topCmd) cmdName() string {
	if c.Rare {
		return "rare"
	}
	return "top"
}
func (tableCmd) cmdName() string  { return "table" }
func (sortCmd) cmdName() string   { return "sort" }
func (headCmd) cmdName() string   { return "head" }
func (dedupCmd) cmdName() string  { return "dedup" }
func (whereCmd) cmdName() string  { return "where" }
func (evalCmd) cmdName() string   { return "eval" }
func (renameCmd) cmdName() string { return "rename" }
func (rexCmd) cmdName() string    { return "rex" }
func (searchCmd) cmdName() string { return "search" }

// Expression nodes.
type (
	// Expr is a where/eval expression.
	Expr   interface{ expr() }
	eLit   struct{ V any } // float64, string, bool or nil
	eField struct{ Name string }
	eUnary struct {
		Op string
		X  Expr
	}
	eBinary struct {
		Op   string
		L, R Expr
	}
	eCall struct {
		Fn   string
		Args []Expr
	}
)

func (eLit) expr()    {}
func (eField) expr()  {}
func (eUnary) expr()  {}
func (eBinary) expr() {}
func (eCall) expr()   {}

// splitPipes splits a search at unquoted, unescaped '|' characters ("||" is OR).
func splitPipes(q string) []string {
	var parts []string
	var b strings.Builder
	inDouble, inSingle := false, false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\\' && i+1 < len(q):
			b.WriteByte(c)
			b.WriteByte(q[i+1])
			i++
			continue
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '\'' && !inDouble && len(parts) > 0: // 'field name' in commands only
			inSingle = !inSingle
		case c == '|' && i+1 < len(q) && q[i+1] == '|': // the || operator
			b.WriteString("||")
			i++
			continue
		case c == '|' && !inDouble && !inSingle:
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	return append(parts, b.String())
}

// ParsePipeline parses a search string. A string without '|' is a plain filter.
func ParsePipeline(q string) (*Pipeline, error) {
	parts := splitPipes(q)
	p := &Pipeline{Filter: strings.TrimSpace(parts[0])}
	if _, err := ParseQuery(p.Filter); err != nil {
		return nil, err
	}
	for i, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty command after | number %d", i+1)
		}
		c, err := parseCommand(part)
		if err != nil {
			return nil, err
		}
		p.Commands = append(p.Commands, c)
	}
	for i, c := range p.Commands {
		if _, ok := c.(timechartCmd); ok && i != len(p.Commands)-1 {
			return nil, errors.New("timechart must be the last command")
		}
	}
	return p, nil
}

// --- lexer ---

type ckind int

const (
	kIdent  ckind = iota // field or keyword
	kNum                 // number
	kStr                 // "string"
	kQField              // 'field name'
	kWord                // other bare words, e.g. 5m
	kPunct               // , ( ) = == != < <= > >= + - * / % . !
)

type ctok struct {
	kind ckind
	s    string
}

func isIdentStart(c rune) bool { return c == '_' || c == '@' || unicode.IsLetter(c) }
func isIdentPart(c rune) bool {
	return c == '_' || c == '@' || c == '.' || unicode.IsLetter(c) || unicode.IsDigit(c)
}

func lexCommand(s string) ([]ctok, error) {
	var out []ctok
	r := []rune(s)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '"' || c == '\'':
			quote := c
			var b strings.Builder
			j := i + 1
			for ; j < len(r) && r[j] != quote; j++ {
				if r[j] == '\\' && j+1 < len(r) && (r[j+1] == quote || r[j+1] == '\\') {
					j++
				}
				b.WriteRune(r[j])
			}
			if j >= len(r) {
				return nil, fmt.Errorf("unterminated quote in %q", s)
			}
			kind := kStr
			if quote == '\'' {
				kind = kQField
			}
			out = append(out, ctok{kind, b.String()})
			i = j + 1
		case unicode.IsDigit(c):
			j := i
			for j < len(r) && (unicode.IsDigit(r[j]) || r[j] == '.') {
				j++
			}
			if j < len(r) && unicode.IsLetter(r[j]) {
				for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j])) {
					j++
				}
				out = append(out, ctok{kWord, string(r[i:j])})
			} else {
				out = append(out, ctok{kNum, string(r[i:j])})
			}
			i = j
		case isIdentStart(c):
			j := i
			for j < len(r) && isIdentPart(r[j]) {
				j++
			}
			out = append(out, ctok{kIdent, strings.TrimRight(string(r[i:j]), ".")})
			if strings.HasSuffix(string(r[i:j]), ".") {
				out = append(out, ctok{kPunct, "."})
			}
			i = j
		default:
			two := ""
			if i+1 < len(r) {
				two = string(r[i : i+2])
			}
			switch two {
			case "==", "!=", "<=", ">=", "&&", "||":
				out = append(out, ctok{kPunct, two})
				i += 2
				continue
			}
			if strings.ContainsRune(",()=<>+-*/%.!", c) {
				out = append(out, ctok{kPunct, string(c)})
				i++
				continue
			}
			return nil, fmt.Errorf("unexpected %q in %q", c, s)
		}
	}
	return out, nil
}

// --- command parser ---

type cparser struct {
	cmd  string
	toks []ctok
	pos  int
}

func (p *cparser) peek() *ctok {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *cparser) done() bool { return p.pos >= len(p.toks) }

func (p *cparser) errf(format string, a ...any) error {
	return fmt.Errorf("%s: %s", p.cmd, fmt.Sprintf(format, a...))
}

func (p *cparser) isPunct(s string) bool {
	t := p.peek()
	return t != nil && t.kind == kPunct && t.s == s
}

func (p *cparser) isKeyword(s string) bool {
	t := p.peek()
	return t != nil && t.kind == kIdent && strings.EqualFold(t.s, s)
}

func (p *cparser) accept(s string) bool {
	if p.isPunct(s) {
		p.pos++
		return true
	}
	return false
}

// fieldName reads a field: ident, 'quoted', or an aggregate-style name like count(x).
func (p *cparser) fieldName() (string, error) {
	t := p.peek()
	if t == nil {
		return "", p.errf("expected a field name")
	}
	switch t.kind {
	case kQField:
		p.pos++
		return t.s, nil
	case kIdent:
		p.pos++
		name := t.s
		if p.isPunct("(") && p.pos+2 < len(p.toks) && p.toks[p.pos+2].kind == kPunct && p.toks[p.pos+2].s == ")" {
			inner := p.toks[p.pos+1]
			if inner.kind == kIdent || inner.kind == kQField {
				name = name + "(" + inner.s + ")"
				p.pos += 3
			}
		}
		return name, nil
	}
	return "", p.errf("expected a field name, got %q", t.s)
}

// newName reads a name for a new column: a field name or a "quoted string".
func (p *cparser) newName() (string, error) {
	if t := p.peek(); t != nil && t.kind == kStr {
		p.pos++
		if t.s == "" {
			return "", p.errf("empty name")
		}
		return t.s, nil
	}
	return p.fieldName()
}

// fieldList reads fields separated by commas or spaces until a keyword in stop.
func (p *cparser) fieldList(stop ...string) ([]string, error) {
	var out []string
	for !p.done() {
		stopHere := false
		for _, s := range stop {
			if p.isKeyword(s) {
				stopHere = true
			}
		}
		if stopHere {
			break
		}
		if p.accept(",") {
			continue
		}
		f, err := p.fieldName()
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// option reads name=value options at the start of a command.
func (p *cparser) option(name string) (string, bool) {
	if p.isKeyword(name) && p.pos+2 < len(p.toks)+1 && p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == kPunct && p.toks[p.pos+1].s == "=" {
		if p.pos+2 >= len(p.toks) {
			return "", false
		}
		v := p.toks[p.pos+2].s
		p.pos += 3
		return v, true
	}
	return "", false
}

func (p *cparser) intArg() (int, bool, error) {
	t := p.peek()
	if t == nil || t.kind != kNum {
		return 0, false, nil
	}
	n, err := strconv.Atoi(t.s)
	if err != nil || n < 1 {
		return 0, false, p.errf("%q is not a positive whole number", t.s)
	}
	p.pos++
	return n, true, nil
}

func positive(p *cparser, name, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, p.errf("%s must be a positive whole number", name)
	}
	return n, nil
}

var aggNames = map[string]string{
	"count": "count", "c": "count", "dc": "dc", "distinct_count": "dc", "sum": "sum", "avg": "avg", "mean": "avg",
	"min": "min", "max": "max", "values": "values",
}

func (p *cparser) agg() (aggSpec, error) {
	t := p.peek()
	if t == nil || t.kind != kIdent {
		return aggSpec{}, p.errf("expected an aggregation such as count or avg(field)")
	}
	fn, ok := aggNames[strings.ToLower(t.s)]
	if !ok {
		return aggSpec{}, p.errf("unknown aggregation %q (use count, dc, sum, avg, min, max or values)", t.s)
	}
	p.pos++
	a := aggSpec{Fn: fn, As: strings.ToLower(t.s)}
	if p.accept("(") {
		f, err := p.fieldName()
		if err != nil {
			return a, err
		}
		if !p.accept(")") {
			return a, p.errf("missing ) after %s(%s", t.s, f)
		}
		a.Field = f
		a.As = strings.ToLower(t.s) + "(" + f + ")"
	} else if fn != "count" {
		return a, p.errf("%s needs a field, e.g. %s(destination.port)", t.s, t.s)
	}
	if p.isKeyword("as") {
		p.pos++
		name, err := p.newName()
		if err != nil {
			return a, err
		}
		a.As = name
	}
	return a, nil
}

var spanRe = regexp.MustCompile(`^(\d+)(s|sec|m|min|h|hr|d|day|w)$`)

func parseSpan(s string) (time.Duration, error) {
	m := spanRe.FindStringSubmatch(strings.ToLower(s))
	if m == nil {
		return 0, fmt.Errorf("span %q: use a number and a unit, e.g. 30s, 5m, 1h, 1d", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"s": time.Second, "sec": time.Second, "m": time.Minute, "min": time.Minute,
		"h": time.Hour, "hr": time.Hour, "d": 24 * time.Hour, "day": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	if n < 1 {
		return 0, fmt.Errorf("span %q must be positive", s)
	}
	return time.Duration(n) * unit, nil
}

func parseCommand(text string) (Command, error) {
	name := text
	rest := ""
	if i := strings.IndexFunc(text, unicode.IsSpace); i >= 0 {
		name, rest = text[:i], strings.TrimSpace(text[i:])
	}
	name = strings.ToLower(name)
	if name == "search" {
		if _, err := ParseQuery(rest); err != nil {
			return nil, fmt.Errorf("search: %w", err)
		}
		return searchCmd{Query: rest}, nil
	}
	toks, err := lexCommand(rest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	p := &cparser{cmd: name, toks: toks}
	var c Command
	switch name {
	case "stats":
		c, err = p.stats()
	case "timechart":
		c, err = p.timechart()
	case "top", "rare":
		c, err = p.top(name == "rare")
	case "table", "fields":
		var fs []string
		fs, err = p.fieldList()
		if err == nil && len(fs) == 0 {
			err = p.errf("name at least one field")
		}
		c = tableCmd{Fields: fs}
	case "sort":
		c, err = p.sort()
	case "head", "limit":
		n, ok, e := p.intArg()
		if !ok && e == nil {
			n = 10
			if name == "limit" {
				e = p.errf("give the number of results, e.g. limit 20")
			}
		}
		c, err = headCmd{N: n}, e
	case "dedup":
		c, err = p.dedup()
	case "where":
		var e Expr
		e, err = p.expression()
		c = whereCmd{Expr: e}
	case "eval":
		c, err = p.eval()
	case "rename":
		c, err = p.rename()
	case "rex":
		c, err = p.rex()
	default:
		return nil, fmt.Errorf("unknown command %q (commands: stats, timechart, top, rare, table, fields, sort, head, limit, dedup, where, eval, rename, rex, search)", name)
	}
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, p.errf("unexpected %q", p.peek().s)
	}
	return c, nil
}

func (p *cparser) stats() (Command, error) {
	var c statsCmd
	for !p.done() && !p.isKeyword("by") {
		if p.accept(",") {
			continue
		}
		a, err := p.agg()
		if err != nil {
			return nil, err
		}
		c.Aggs = append(c.Aggs, a)
	}
	if len(c.Aggs) == 0 {
		return nil, p.errf("name at least one aggregation, e.g. stats count by host")
	}
	if p.isKeyword("by") {
		p.pos++
		by, err := p.fieldList()
		if err != nil {
			return nil, err
		}
		if len(by) == 0 {
			return nil, p.errf("name the fields after by")
		}
		c.By = by
	}
	seen := map[string]bool{}
	for _, n := range append(append([]string{}, c.By...), names(c.Aggs)...) {
		if seen[n] {
			return nil, p.errf("column %q appears twice; rename one with as", n)
		}
		seen[n] = true
	}
	return c, nil
}

func names(aggs []aggSpec) []string {
	out := make([]string, len(aggs))
	for i, a := range aggs {
		out[i] = a.As
	}
	return out
}

func (p *cparser) timechart() (Command, error) {
	var c timechartCmd
	for {
		if v, ok := p.option("span"); ok {
			d, err := parseSpan(v)
			if err != nil {
				return nil, p.errf("%v", err)
			}
			c.Span = d
			continue
		}
		if v, ok := p.option("limit"); ok {
			n, err := positive(p, "limit", v)
			if err != nil {
				return nil, err
			}
			c.Limit = n
			continue
		}
		break
	}
	a, err := p.agg()
	if err != nil {
		return nil, err
	}
	c.Agg = a
	if p.isKeyword("by") {
		p.pos++
		f, err := p.fieldName()
		if err != nil {
			return nil, err
		}
		c.By = f
	}
	return c, nil
}

func (p *cparser) top(rare bool) (Command, error) {
	c := topCmd{Rare: rare, Limit: 10}
	if v, ok := p.option("limit"); ok {
		n, err := positive(p, "limit", v)
		if err != nil {
			return nil, err
		}
		c.Limit = n
	}
	fs, err := p.fieldList()
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, p.errf("name at least one field")
	}
	c.Fields = fs
	return c, nil
}

func (p *cparser) sort() (Command, error) {
	var c sortCmd
	if n, ok, err := p.intArg(); err != nil {
		return nil, err
	} else if ok {
		c.Limit = n
	}
	for !p.done() {
		if p.accept(",") {
			continue
		}
		desc := false
		if p.accept("-") {
			desc = true
		} else {
			p.accept("+")
		}
		f, err := p.fieldName()
		if err != nil {
			return nil, err
		}
		c.Keys = append(c.Keys, sortKey{Field: f, Desc: desc})
	}
	if len(c.Keys) == 0 {
		return nil, p.errf("name at least one field, e.g. sort -count")
	}
	return c, nil
}

func (p *cparser) dedup() (Command, error) {
	c := dedupCmd{N: 1}
	if n, ok, err := p.intArg(); err != nil {
		return nil, err
	} else if ok {
		c.N = n
	}
	fs, err := p.fieldList()
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, p.errf("name at least one field")
	}
	c.Fields = fs
	return c, nil
}

func (p *cparser) eval() (Command, error) {
	var c evalCmd
	for !p.done() {
		if p.accept(",") {
			continue
		}
		name, err := p.newName()
		if err != nil {
			return nil, err
		}
		if !p.accept("=") {
			return nil, p.errf("expected = after %s", name)
		}
		e, err := p.exprOr()
		if err != nil {
			return nil, err
		}
		c.Assigns = append(c.Assigns, evalAssign{Name: name, Expr: e})
	}
	if len(c.Assigns) == 0 {
		return nil, p.errf("expected name = expression")
	}
	return c, nil
}

func (p *cparser) rename() (Command, error) {
	var c renameCmd
	for !p.done() {
		if p.accept(",") {
			continue
		}
		from, err := p.fieldName()
		if err != nil {
			return nil, err
		}
		if !p.isKeyword("as") {
			return nil, p.errf("expected as after %s", from)
		}
		p.pos++
		to, err := p.newName()
		if err != nil {
			return nil, err
		}
		c.Pairs = append(c.Pairs, [2]string{from, to})
	}
	if len(c.Pairs) == 0 {
		return nil, p.errf("expected field as name")
	}
	return c, nil
}

var namedGroupRe = regexp.MustCompile(`\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>`)

func (p *cparser) rex() (Command, error) {
	c := rexCmd{Field: "_raw"}
	if v, ok := p.option("field"); ok {
		c.Field = v
	}
	t := p.peek()
	if t == nil || t.kind != kStr {
		return nil, p.errf(`give the regex in double quotes, e.g. rex field=message "user (?<user>\w+)"`)
	}
	p.pos++
	pattern, groupNames, err := rewriteRegex(t.s)
	if err != nil {
		return nil, p.errf("%v", err)
	}
	c.Pattern, c.Names = pattern, groupNames
	return c, nil
}

// rewriteRegex validates a regex with named groups and rewrites it for RE2-based
// databases: named groups become plain groups, other capturing groups non-capturing,
// so group N is the Nth name.
func rewriteRegex(re string) (string, []string, error) {
	if _, err := regexp.Compile(strings.ReplaceAll(re, "(?<", "(?P<")); err != nil {
		return "", nil, fmt.Errorf("invalid regex: %v", err)
	}
	var names []string
	var b strings.Builder
	inClass := false
	for i := 0; i < len(re); i++ {
		c := re[i]
		switch {
		case c == '\\' && i+1 < len(re):
			b.WriteByte(c)
			b.WriteByte(re[i+1])
			i++
			continue
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			if m := namedGroupRe.FindStringSubmatch(re[i:]); m != nil && strings.HasPrefix(re[i:], m[0]) {
				names = append(names, m[1])
				b.WriteByte('(')
				i += len(m[0]) - 1
				continue
			}
			if i+1 < len(re) && re[i+1] == '?' {
				break // already non-capturing or a flag group
			}
			b.WriteString("(?:")
			continue
		}
		b.WriteByte(c)
	}
	if len(names) == 0 {
		return "", nil, errors.New("the regex needs at least one named group, e.g. (?<user>\\w+)")
	}
	return b.String(), names, nil
}

// --- expressions ---

func (p *cparser) expression() (Expr, error) {
	e, err := p.exprOr()
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, p.errf("unexpected %q", p.peek().s)
	}
	return e, nil
}

func (p *cparser) exprOr() (Expr, error) {
	l, err := p.exprAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("or") || p.isPunct("||") {
		p.pos++
		r, err := p.exprAnd()
		if err != nil {
			return nil, err
		}
		l = eBinary{Op: "OR", L: l, R: r}
	}
	return l, nil
}

func (p *cparser) exprAnd() (Expr, error) {
	l, err := p.exprNot()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("and") || p.isPunct("&&") {
		p.pos++
		r, err := p.exprNot()
		if err != nil {
			return nil, err
		}
		l = eBinary{Op: "AND", L: l, R: r}
	}
	return l, nil
}

func (p *cparser) exprNot() (Expr, error) {
	if p.isKeyword("not") || p.isPunct("!") {
		p.pos++
		x, err := p.exprNot()
		if err != nil {
			return nil, err
		}
		return eUnary{Op: "NOT", X: x}, nil
	}
	return p.exprCmp()
}

var cmpOps = map[string]string{"=": "=", "==": "=", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}

func (p *cparser) exprCmp() (Expr, error) {
	l, err := p.exprConcat()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t != nil && t.kind == kPunct {
		if op, ok := cmpOps[t.s]; ok {
			p.pos++
			r, err := p.exprConcat()
			if err != nil {
				return nil, err
			}
			return eBinary{Op: op, L: l, R: r}, nil
		}
	}
	return l, nil
}

func (p *cparser) exprConcat() (Expr, error) {
	l, err := p.exprAdd()
	if err != nil {
		return nil, err
	}
	for p.isPunct(".") {
		p.pos++
		r, err := p.exprAdd()
		if err != nil {
			return nil, err
		}
		l = eBinary{Op: ".", L: l, R: r}
	}
	return l, nil
}

func (p *cparser) exprAdd() (Expr, error) {
	l, err := p.exprMul()
	if err != nil {
		return nil, err
	}
	for p.isPunct("+") || p.isPunct("-") {
		op := p.peek().s
		p.pos++
		r, err := p.exprMul()
		if err != nil {
			return nil, err
		}
		l = eBinary{Op: op, L: l, R: r}
	}
	return l, nil
}

func (p *cparser) exprMul() (Expr, error) {
	l, err := p.exprUnary()
	if err != nil {
		return nil, err
	}
	for p.isPunct("*") || p.isPunct("/") || p.isPunct("%") {
		op := p.peek().s
		p.pos++
		r, err := p.exprUnary()
		if err != nil {
			return nil, err
		}
		l = eBinary{Op: op, L: l, R: r}
	}
	return l, nil
}

func (p *cparser) exprUnary() (Expr, error) {
	if p.accept("-") {
		x, err := p.exprUnary()
		if err != nil {
			return nil, err
		}
		return eUnary{Op: "-", X: x}, nil
	}
	return p.exprPrimary()
}

func (p *cparser) exprPrimary() (Expr, error) {
	t := p.peek()
	if t == nil {
		return nil, p.errf("expression ends too early")
	}
	switch t.kind {
	case kNum:
		p.pos++
		f, err := strconv.ParseFloat(t.s, 64)
		if err != nil {
			return nil, p.errf("bad number %q", t.s)
		}
		return eLit{V: f}, nil
	case kStr:
		p.pos++
		return eLit{V: t.s}, nil
	case kQField:
		p.pos++
		return eField{Name: t.s}, nil
	case kPunct:
		if t.s == "(" {
			p.pos++
			e, err := p.exprOr()
			if err != nil {
				return nil, err
			}
			if !p.accept(")") {
				return nil, p.errf("missing )")
			}
			return e, nil
		}
	case kIdent:
		p.pos++
		switch strings.ToLower(t.s) {
		case "true":
			return eLit{V: true}, nil
		case "false":
			return eLit{V: false}, nil
		case "null":
			if !p.isPunct("(") {
				return eLit{V: nil}, nil
			}
		}
		if p.accept("(") {
			fn := strings.ToLower(t.s)
			var args []Expr
			for !p.accept(")") {
				if len(args) > 0 && !p.accept(",") {
					return nil, p.errf("expected , or ) in %s()", fn)
				}
				a, err := p.exprOr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.done() {
					return nil, p.errf("missing ) after %s(", fn)
				}
			}
			return eCall{Fn: fn, Args: args}, nil
		}
		return eField{Name: t.s}, nil
	}
	return nil, p.errf("unexpected %q", t.s)
}
