package detect

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
)

// condNode is a compiled Sigma condition.
type condNode interface {
	eval(d *Doc) bool
	alts(s *synth, want bool) []alt // ways to make it true or false (synth.go)
}

type andCond []condNode

func (a andCond) eval(d *Doc) bool {
	for _, c := range a {
		if !c.eval(d) {
			return false
		}
	}
	return true
}

type orCond []condNode

func (o orCond) eval(d *Doc) bool {
	for _, c := range o {
		if c.eval(d) {
			return true
		}
	}
	return false
}

type notCond struct{ c condNode }

func (n notCond) eval(d *Doc) bool { return !n.c.eval(d) }

type searchCond struct{ m matcher }

func (s searchCond) eval(d *Doc) bool { return s.m.match(d) }

// parseCondition parses a condition expression over named searches.
func parseCondition(s string, searches map[string]matcher) (condNode, error) {
	toks, err := lexCondition(s)
	if err != nil {
		return nil, err
	}
	p := &condParser{toks: toks, searches: searches}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}
	return n, nil
}

func lexCondition(s string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(s) {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(s) && !unicode.IsSpace(rune(s[j])) && s[j] != '(' && s[j] != ')' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	if len(toks) == 0 {
		return nil, errors.New("empty condition")
	}
	return toks, nil
}

type condParser struct {
	toks     []string
	pos      int
	searches map[string]matcher
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) parseOr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	out := orCond{left}
	for strings.EqualFold(p.peek(), "or") {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		out = append(out, right)
	}
	if len(out) == 1 {
		return left, nil
	}
	return out, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	out := andCond{left}
	for strings.EqualFold(p.peek(), "and") {
		p.pos++
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		out = append(out, right)
	}
	if len(out) == 1 {
		return left, nil
	}
	return out, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.pos++
		c, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notCond{c}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condNode, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return nil, errors.New("unexpected end of condition")
	case tok == "(":
		p.pos++
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.pos++
		return n, nil
	case tok == ")":
		return nil, errors.New("unexpected )")
	}

	// "1 of X", "all of X", "any of X"
	if p.pos+2 < len(p.toks)+1 && p.pos+1 < len(p.toks) && strings.EqualFold(p.toks[p.pos+1], "of") {
		quant := strings.ToLower(tok)
		if p.pos+2 >= len(p.toks) {
			return nil, errors.New("missing target after 'of'")
		}
		target := p.toks[p.pos+2]
		p.pos += 3
		names := p.matchNames(target)
		if len(names) == 0 {
			return nil, fmt.Errorf("%q matches no search", target)
		}
		var nodes []condNode
		for _, n := range names {
			nodes = append(nodes, searchCond{p.searches[n]})
		}
		switch quant {
		case "all":
			return andCond(nodes), nil
		case "1", "any":
			return orCond(nodes), nil
		}
		return nil, fmt.Errorf("unsupported quantifier %q", quant)
	}

	m, ok := p.searches[tok]
	if !ok {
		return nil, fmt.Errorf("unknown search %q", tok)
	}
	p.pos++
	return searchCond{m}, nil
}

func (p *condParser) matchNames(target string) []string {
	var names []string
	for name := range p.searches {
		if target == "them" {
			if !strings.HasPrefix(name, "_") {
				names = append(names, name)
			}
			continue
		}
		if ok, _ := path.Match(target, name); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
