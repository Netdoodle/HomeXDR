package events

// The search query language:
//
//	field:value          case-insensitive equality
//	field:val*  *val*    wildcards (* any run, ? one character)
//	field:"two words"    quoted value, matched literally (* and ? are not wildcards)
//	field:>10  field:<=443   numeric comparison
//	field:*              field is present and non-empty
//	word                 substring match on message, command line and file path
//	a AND b, a OR b, NOT a, -a, (a OR b) c   (adjacent terms are ANDed)
//
// Queries compile to parameterized SQL; user input never becomes SQL text.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Node is a parsed query.
type Node interface{ node() }

// AndNode matches when all children match.
type AndNode struct{ Children []Node }

// OrNode matches when any child matches.
type OrNode struct{ Children []Node }

// NotNode negates its child.
type NotNode struct{ Child Node }

// TermNode is a single comparison.
type TermNode struct {
	Field string // "" for a bare word
	Op    string // eq, like, gt, gte, lt, lte, exists
	Value string
	// Literal is set for quoted bare words: no wildcard expansion.
	Literal bool
}

func (AndNode) node()  {}
func (OrNode) node()   {}
func (NotNode) node()  {}
func (TermNode) node() {}

var fieldRe = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_@.\-]*$`)

// ParseQuery parses the query language. An empty query returns nil.
func ParseQuery(q string) (Node, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, nil
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos].text)
	}
	return n, nil
}

type tokKind int

const (
	tTerm tokKind = iota
	tAnd
	tOr
	tNot
	tLParen
	tRParen
)

type token struct {
	kind tokKind
	text string
	term TermNode
}

func lex(q string) ([]token, error) {
	var toks []token
	r := []rune(q)
	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(':
			toks = append(toks, token{kind: tLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen, text: ")"})
			i++
		case c == '-' && i+1 < len(r) && !unicode.IsSpace(r[i+1]) && (i == 0 || unicode.IsSpace(r[i-1]) || r[i-1] == '('):
			toks = append(toks, token{kind: tNot, text: "-"})
			i++
		default:
			start := i
			var raw strings.Builder
			inQuote := false
			for i < len(r) {
				c := r[i]
				if c == '\\' && i+1 < len(r) {
					raw.WriteRune(c)
					raw.WriteRune(r[i+1])
					i += 2
					continue
				}
				if c == '"' {
					inQuote = !inQuote
					raw.WriteRune(c)
					i++
					continue
				}
				if !inQuote && (unicode.IsSpace(c) || c == '(' || c == ')') {
					break
				}
				raw.WriteRune(c)
				i++
			}
			if inQuote {
				return nil, errors.New("unterminated quote")
			}
			text := raw.String()
			switch text {
			case "AND", "&&":
				toks = append(toks, token{kind: tAnd, text: text})
				continue
			case "OR", "||":
				toks = append(toks, token{kind: tOr, text: text})
				continue
			case "NOT", "!":
				toks = append(toks, token{kind: tNot, text: text})
				continue
			}
			t, negate, err := parseTerm(text)
			if err != nil {
				return nil, fmt.Errorf("at %d: %w", start, err)
			}
			if negate {
				toks = append(toks, token{kind: tNot, text: "!="})
			}
			toks = append(toks, token{kind: tTerm, text: text, term: t})
		}
	}
	return toks, nil
}

// parseTerm parses one term. It splits at the first unquoted, unescaped operator:
// "field:value" (the original syntax), or Splunk-style "field=value", "field!=value"
// (negate is set), "field>N", "field>=N", "field<N", "field<=N". The Splunk-style forms
// fall back to a bare word when the field or value part does not fit, so words that
// merely contain those characters still search as before.
func parseTerm(text string) (TermNode, bool, error) {
	at, op := -1, ""
	inQuote := false
scan:
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\\':
			i++
			continue
		case c == '"':
			inQuote = !inQuote
			continue
		case inQuote:
			continue
		}
		switch c {
		case ':', '=':
			at, op = i, string(c)
			break scan
		case '!':
			if i+1 < len(text) && text[i+1] == '=' {
				at, op = i, "!="
				break scan
			}
		case '<', '>':
			at, op = i, string(c)
			if i+1 < len(text) && text[i+1] == '=' {
				op += "="
			}
			break scan
		}
	}
	if op == ":" && at > 0 {
		t, err := colonTerm(text[:at], text[at+1:])
		return t, false, err
	}
	if at > 0 && op != ":" {
		field, rawVal := text[:at], text[at+len(op):]
		if fieldRe.MatchString(field) && rawVal != "" {
			switch op {
			case "=", "!=":
				t, err := fieldValue(canonicalField(field), rawVal)
				return t, op == "!=", err
			default:
				if v, _ := unquote(rawVal); isNumber(v) {
					return TermNode{Field: canonicalField(field), Op: compareOps[op], Value: v}, false, nil
				}
			}
		}
	}
	v, quoted := unquote(text)
	if v == "" {
		return TermNode{}, false, errors.New("empty term")
	}
	if quoted {
		return TermNode{Op: "like", Value: unescape(v), Literal: true}, false, nil
	}
	return TermNode{Op: "like", Value: v}, false, nil
}

var compareOps = map[string]string{">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// colonTerm parses the original "field:value" syntax, including field:>N comparisons.
func colonTerm(field, rawVal string) (TermNode, error) {
	if !fieldRe.MatchString(field) {
		return TermNode{}, fmt.Errorf("invalid field name %q", field)
	}
	field = canonicalField(field)
	for _, p := range []struct{ prefix, op string }{{">=", "gte"}, {"<=", "lte"}, {">", "gt"}, {"<", "lt"}} {
		if strings.HasPrefix(rawVal, p.prefix) {
			v, _ := unquote(rawVal[len(p.prefix):])
			if !isNumber(v) {
				return TermNode{}, fmt.Errorf("%s: comparison needs a number, got %q", field, v)
			}
			return TermNode{Field: field, Op: p.op, Value: v}, nil
		}
	}
	return fieldValue(field, rawVal)
}

// fieldValue builds an equality, wildcard or exists term.
func fieldValue(field, rawVal string) (TermNode, error) {
	v, quoted := unquote(rawVal)
	if v == "*" && !quoted {
		return TermNode{Field: field, Op: "exists"}, nil
	}
	if !quoted && hasWildcard(rawVal) {
		return TermNode{Field: field, Op: "like", Value: v}, nil
	}
	return TermNode{Field: field, Op: "eq", Value: unescape(v)}, nil
}

// unquote strips surrounding quotes. Escapes are kept for wildcard handling.
func unquote(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1], true
	}
	return s, false
}

func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// likePattern converts a wildcard value into a LIKE pattern with '\' as the escape.
func likePattern(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch c {
		case '\\':
			if i+1 < len(v) {
				i++
				switch v[i] {
				case '%', '_', '\\':
					b.WriteByte('\\')
				}
				b.WriteByte(v[i])
			}
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		case '%', '_':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// containsPattern is a LIKE pattern matching v anywhere.
func containsPattern(v string) string {
	return "%" + likePattern(strings.ReplaceAll(strings.ReplaceAll(v, "*", `\*`), "?", `\?`)) + "%"
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	children := []Node{left}
	for t := p.peek(); t != nil && t.kind == tOr; t = p.peek() {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return OrNode{Children: children}, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	children := []Node{left}
	for {
		t := p.peek()
		if t == nil || t.kind == tOr || t.kind == tRParen {
			break
		}
		if t.kind == tAnd {
			p.pos++
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return AndNode{Children: children}, nil
}

func (p *parser) parseUnary() (Node, error) {
	t := p.peek()
	if t == nil {
		return nil, errors.New("unexpected end of query")
	}
	switch t.kind {
	case tNot:
		p.pos++
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return NotNode{Child: child}, nil
	case tLParen:
		p.pos++
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if t := p.peek(); t == nil || t.kind != tRParen {
			return nil, errors.New("missing )")
		}
		p.pos++
		return n, nil
	case tTerm:
		p.pos++
		return t.term, nil
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

// dialect adapts SQL generation to a backend.
type dialect interface {
	// column returns the SQL for an indexed column.
	column(c *Column) string
	// jsonString / jsonNumber extract a non-indexed ECS path from the raw JSON.
	jsonString(path []string) (string, []any)
	jsonNumber(path []string) (string, []any)
	// arrayEq / arrayLike test whether any element of an array column matches.
	arrayEq(col string, value string) (string, []any)
	arrayLike(col string, pattern string) (string, []any)
	// like returns a case-insensitive LIKE with '\' escapes.
	like(expr string) string
}

// bareFields are searched by bare words.
var bareFields = []string{"message", "process_command_line", "file_path"}

// compile turns a node into a SQL boolean expression and its arguments.
func compile(n Node, d dialect) (string, []any, error) {
	switch n := n.(type) {
	case nil:
		return "1=1", nil, nil
	case AndNode, OrNode:
		var children []Node
		sep := " AND "
		if a, ok := n.(AndNode); ok {
			children = a.Children
		} else {
			children = n.(OrNode).Children
			sep = " OR "
		}
		parts := make([]string, 0, len(children))
		var args []any
		for _, c := range children {
			s, a, err := compile(c, d)
			if err != nil {
				return "", nil, err
			}
			parts = append(parts, "("+s+")")
			args = append(args, a...)
		}
		return strings.Join(parts, sep), args, nil
	case NotNode:
		s, a, err := compile(n.Child, d)
		if err != nil {
			return "", nil, err
		}
		return "NOT (" + s + ")", a, nil
	case TermNode:
		return compileTerm(n, d)
	}
	return "", nil, fmt.Errorf("unknown node %T", n)
}

func compileTerm(t TermNode, d dialect) (string, []any, error) {
	if t.Field == "" {
		pat := containsPattern(unescape(t.Value))
		if hasWildcard(t.Value) && !t.Literal {
			pat = "%" + likePattern(t.Value) + "%"
		}
		parts := make([]string, len(bareFields))
		args := make([]any, len(bareFields))
		for i, f := range bareFields {
			parts[i] = d.like(f)
			args[i] = pat
		}
		return strings.Join(parts, " OR "), args, nil
	}

	if c, ok := columnByField[t.Field]; ok {
		col := d.column(c)
		switch c.Kind {
		case KArray:
			var s string
			var a []any
			switch t.Op {
			case "exists":
				s, a = d.arrayLike(col, "%")
			case "like":
				s, a = d.arrayLike(col, likePattern(t.Value))
			case "eq":
				s, a = d.arrayEq(col, t.Value)
			}
			if s != "" {
				return s, a, nil
			}
			return "", nil, fmt.Errorf("%s does not support numeric comparison", t.Field)
		case KInt:
			switch t.Op {
			case "exists":
				return col + " != 0", nil, nil
			case "like":
				return "", nil, fmt.Errorf("%s is numeric; wildcards are not supported", t.Field)
			}
			f, err := strconv.ParseFloat(t.Value, 64)
			if err != nil {
				return "1=0", nil, nil
			}
			if t.Op == "lt" || t.Op == "lte" {
				// 0 means "absent" for indexed numeric fields (ports, PIDs).
				return col + " != 0 AND " + col + " " + sqlOp(t.Op) + " ?", []any{int64(f)}, nil
			}
			return col + " " + sqlOp(t.Op) + " ?", []any{int64(f)}, nil
		case KTime:
			return "", nil, fmt.Errorf("use the time range to filter on %s", t.Field)
		default:
			return stringCompare(col, t, d)
		}
	}

	path := jsonPath(t.Field)
	switch t.Op {
	case "gt", "gte", "lt", "lte":
		expr, args := d.jsonNumber(path)
		f, _ := strconv.ParseFloat(t.Value, 64)
		return expr + " " + sqlOp(t.Op) + " ?", append(args, f), nil
	}
	expr, args := d.jsonString(path)
	s, a, err := stringCompare(expr, t, d)
	return s, append(args, a...), err
}

func stringCompare(expr string, t TermNode, d dialect) (string, []any, error) {
	switch t.Op {
	case "exists":
		return expr + " != ''", nil, nil
	case "eq":
		return "lower(" + expr + ") = lower(?)", []any{t.Value}, nil
	case "like":
		return d.like(expr), []any{likePattern(t.Value)}, nil
	case "gt", "gte", "lt", "lte":
		return "", nil, fmt.Errorf("%s is not numeric", t.Field)
	}
	return "", nil, fmt.Errorf("unsupported operator %q", t.Op)
}

func sqlOp(op string) string {
	switch op {
	case "gt":
		return ">"
	case "gte":
		return ">="
	case "lt":
		return "<"
	case "lte":
		return "<="
	}
	return "="
}
