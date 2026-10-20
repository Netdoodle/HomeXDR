package events

// The planner compiles a Pipeline into SQL for one backend. A relation (rel) is the
// state between commands: a FROM source, WHERE conditions, columns, a pending ORDER BY
// and LIMIT. Commands that need to see the previous stage's output (a filter after
// head, anything after stats) wrap the relation in a subquery first, so the whole
// pipeline runs as one query. As in query.go, user values only ever become arguments;
// SQL text comes from the planner (numbers are formatted from parsed float64s).

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ftype is a value's type during planning.
type ftype int

const (
	fAny  ftype = iota // a raw JSON field: a string that may hold a number
	fStr               // string
	fNum               // number
	fBool              // boolean
	fTime              // timestamp
	fArr               // array of strings
)

func (t ftype) String() string {
	switch t {
	case fNum:
		return "number"
	case fBool:
		return "bool"
	case fTime:
		return "time"
	case fArr:
		return "array"
	}
	return "string"
}

// frag is SQL text with its positional arguments, in text order.
type frag struct {
	s string
	a []any
}

func fr(s string, a ...any) frag { return frag{s: s, a: a} }

// cat concatenates fragments.
func cat(parts ...frag) frag {
	var b strings.Builder
	var a []any
	for _, p := range parts {
		b.WriteString(p.s)
		a = append(a, p.a...)
	}
	return frag{b.String(), a}
}

func joinf(parts []frag, sep string) frag {
	var b strings.Builder
	var a []any
	for i, p := range parts {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p.s)
		a = append(a, p.a...)
	}
	return frag{b.String(), a}
}

// one and two apply a dialect function to fragments. Dialect functions must place
// their inputs in argument order.
func one(f func(string) string, x frag) frag { return frag{f(x.s), x.a} }
func two(f func(string, string) string, x, y frag) frag {
	return frag{f(x.s, y.s), append(append([]any{}, x.a...), y.a...)}
}

// val is a typed SQL expression.
type val struct {
	frag
	typ        ftype
	path       []string // JSON path, for numeric extraction of a raw event field
	zeroAbsent bool     // indexed numeric field: 0 means absent
	null       bool     // the NULL literal
}

// rcol is a named column of a relation.
type rcol struct {
	name string
	v    val
}

type okey struct {
	v    val
	desc bool
}

type rel struct {
	events bool   // rows are events (no transforming command yet)
	from   frag   // FROM source
	conds  []frag // ANDed WHERE conditions
	cols   []rcol // table: the output columns; events: eval/rex/rename fields
	order  []okey
	limit  int // 0 = none
}

// pipeDialect is what the planner needs from a backend beyond the filter dialect.
type pipeDialect interface {
	dialect
	num(x string) string               // number, NULL when x is not one
	float(x string) string             // numeric x as a float, to unify branch types
	str(x string) string               // as a string
	integer(x string) string           // numeric x as an integer
	epoch(ts string) string            // seconds since 1970 as a float
	bucket(ts string, ms int64) string // start of the ms-wide bucket, in Unix milliseconds
	concat(a, b string) string
	div(a, b string) string // NULL on division by zero
	mod(a, b string) string
	strLen(x string) string
	substr(s, start, n string) string // n may be ""
	rexGroup(s string, group int) string
	rexMatch(s string) string // the pattern is the next argument
	ilike(a, b string) string
	arrayStr(a string) string
	arrayHas(arr, v string) string
	arrayNonEmpty(a string) string
	explode(arr, alias string) (expr, join string) // one row per element
	values(x string) string                        // distinct values (at most 100)
	boolean(b bool) string
	plainRef(s string) bool // s names a column of the events table
}

// maxValues caps values() lists.
const maxValues = 100

var aliasRe = regexp.MustCompile(`^_[a-z]+[0-9]+$`)

type planner struct {
	d pipeDialect
	n int
}

func (p *planner) alias(prefix string) string {
	p.n++
	return "_" + prefix + strconv.Itoa(p.n)
}

func numLit(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// base is the relation for the filtered events table.
func (p *planner) base(table string, where frag, asc bool) *rel {
	r := &rel{events: true, from: fr(table), conds: []frag{where}}
	ts, _ := p.resolve(r, "@timestamp")
	id, _ := p.resolve(r, "id")
	r.order = []okey{{ts, !asc}, {id, !asc}}
	return r
}

// resolve looks up a field.
func (p *planner) resolve(r *rel, name string) (val, error) {
	for i := len(r.cols) - 1; i >= 0; i-- {
		if r.cols[i].name == name {
			return r.cols[i].v, nil
		}
	}
	if !r.events {
		for _, c := range r.cols {
			if strings.EqualFold(c.name, name) {
				return c.v, nil
			}
		}
		names := make([]string, len(r.cols))
		for i, c := range r.cols {
			names[i] = c.name
		}
		return val{}, fmt.Errorf("%q is not a column here (columns: %s)", name, strings.Join(names, ", "))
	}
	if name == "_raw" {
		return val{frag: fr("raw"), typ: fStr}, nil
	}
	f := canonicalField(name)
	if c, ok := columnByField[f]; ok {
		v := val{frag: fr(p.d.column(c))}
		switch c.Kind {
		case KInt:
			v.typ, v.zeroAbsent = fNum, true
		case KTime:
			v.typ = fTime
		case KArray:
			v.typ = fArr
		default:
			v.typ = fStr
		}
		return v, nil
	}
	if !fieldRe.MatchString(f) {
		return val{}, fmt.Errorf("invalid field name %q (quote unusual names with single quotes)", name)
	}
	path := jsonPath(f)
	s, a := p.d.jsonString(path)
	return val{frag: frag{s, a}, typ: fAny, path: path}, nil
}

// --- conversions ---

func (p *planner) num(v val) frag {
	switch {
	case v.null, v.typ == fNum, v.typ == fBool:
		return v.frag
	case v.path != nil:
		s, a := p.d.jsonNumber(v.path)
		return frag{s, a}
	case v.typ == fTime:
		return one(p.d.epoch, v.frag)
	case v.typ == fArr:
		return fr("NULL")
	}
	return one(p.d.num, v.frag)
}

func (p *planner) str(v val) frag {
	switch {
	case v.null, v.typ == fStr, v.typ == fAny:
		return v.frag
	case v.typ == fArr:
		return one(p.d.arrayStr, v.frag)
	}
	return one(p.d.str, v.frag)
}

func (p *planner) boolean(v val) (val, error) {
	switch {
	case v.typ == fBool:
		return v, nil
	case v.null:
		return val{frag: fr(p.d.boolean(false)), typ: fBool}, nil
	case v.typ == fNum:
		return val{frag: cat(fr("("), v.frag, fr(" != 0)")), typ: fBool}, nil
	}
	return val{}, errors.New(`expected a true/false expression, e.g. x > 5, x = "a" or like(x, "a%")`)
}

// present is true when a value is there: Splunk drops events without the field from
// by-clauses and per-field aggregates.
func (p *planner) present(v val) frag {
	switch {
	case v.null:
		return fr(p.d.boolean(false))
	case v.typ == fStr || v.typ == fAny:
		return cat(fr("("), v.frag, fr(" != '')"))
	case v.zeroAbsent:
		return cat(fr("("), v.frag, fr(" != 0)"))
	case v.typ == fArr:
		return one(p.d.arrayNonEmpty, v.frag)
	}
	return cat(fr("("), v.frag, fr(" IS NOT NULL)"))
}

func (p *planner) isNull(v val) frag {
	switch {
	case v.null:
		return fr(p.d.boolean(true))
	case v.typ == fStr || v.typ == fAny:
		return cat(fr("("), v.frag, fr(" IS NULL OR "), v.frag, fr(" = '')"))
	case v.zeroAbsent:
		return cat(fr("("), v.frag, fr(" = 0)"))
	case v.typ == fArr:
		return cat(fr("(NOT "), one(p.d.arrayNonEmpty, v.frag), fr(")"))
	}
	return cat(fr("("), v.frag, fr(" IS NULL)"))
}

// unify converts values to one type for CASE branches and coalesce: numbers when all are
// numeric, otherwise strings.
func (p *planner) unify(vs []val) ([]frag, ftype) {
	allNum := true
	for _, v := range vs {
		if !v.null && v.typ != fNum && v.typ != fBool {
			allNum = false
		}
	}
	out := make([]frag, len(vs))
	for i, v := range vs {
		switch {
		case v.null:
			out[i] = v.frag
		case allNum:
			out[i] = one(p.d.float, p.num(v))
		default:
			out[i] = p.str(v)
		}
	}
	if allNum {
		return out, fNum
	}
	return out, fStr
}

// --- expressions ---

func (p *planner) expr(r *rel, e Expr) (val, error) {
	switch e := e.(type) {
	case eLit:
		switch v := e.V.(type) {
		case nil:
			return val{frag: fr("NULL"), null: true}, nil
		case float64:
			if math.IsInf(v, 0) || math.IsNaN(v) {
				return val{}, fmt.Errorf("number out of range")
			}
			return val{frag: fr(numLit(v)), typ: fNum}, nil
		case string:
			return val{frag: fr("?", v), typ: fStr}, nil
		case bool:
			return val{frag: fr(p.d.boolean(v)), typ: fBool}, nil
		}
	case eField:
		return p.resolve(r, e.Name)
	case eUnary:
		x, err := p.expr(r, e.X)
		if err != nil {
			return val{}, err
		}
		if e.Op == "-" {
			return val{frag: cat(fr("(-"), p.num(x), fr(")")), typ: fNum}, nil
		}
		b, err := p.boolean(x)
		if err != nil {
			return val{}, err
		}
		return val{frag: cat(fr("(NOT "), b.frag, fr(")")), typ: fBool}, nil
	case eBinary:
		return p.binary(r, e)
	case eCall:
		return p.call(r, e)
	}
	return val{}, fmt.Errorf("unsupported expression %T", e)
}

func (p *planner) binary(r *rel, e eBinary) (val, error) {
	l, err := p.expr(r, e.L)
	if err != nil {
		return val{}, err
	}
	rv, err := p.expr(r, e.R)
	if err != nil {
		return val{}, err
	}
	switch e.Op {
	case "AND", "OR":
		lb, err := p.boolean(l)
		if err != nil {
			return val{}, err
		}
		rb, err := p.boolean(rv)
		if err != nil {
			return val{}, err
		}
		return val{frag: cat(fr("("), lb.frag, fr(" "+e.Op+" "), rb.frag, fr(")")), typ: fBool}, nil
	case "=", "!=", "<", "<=", ">", ">=":
		return p.compare(e.Op, l, rv), nil
	case ".":
		return val{frag: two(p.d.concat, p.str(l), p.str(rv)), typ: fStr}, nil
	case "+":
		if l.typ == fStr && rv.typ == fStr {
			return val{frag: two(p.d.concat, l.frag, rv.frag), typ: fStr}, nil
		}
		fallthrough
	case "-", "*":
		return val{frag: cat(fr("("), p.num(l), fr(" "+e.Op+" "), p.num(rv), fr(")")), typ: fNum}, nil
	case "/":
		return val{frag: two(p.d.div, p.num(l), p.num(rv)), typ: fNum}, nil
	case "%":
		return val{frag: two(p.d.mod, p.num(l), p.num(rv)), typ: fNum}, nil
	}
	return val{}, fmt.Errorf("unsupported operator %q", e.Op)
}

func (p *planner) compare(op string, l, r val) val {
	b := func(f frag) val { return val{frag: f, typ: fBool} }
	if l.null || r.null {
		other := l
		if l.null {
			other = r
		}
		switch op {
		case "=":
			return b(p.isNull(other))
		case "!=":
			return b(cat(fr("(NOT "), p.isNull(other), fr(")")))
		}
		return b(fr(p.d.boolean(false)))
	}
	if op == "=" || op == "!=" {
		arr, other := l, r
		if r.typ == fArr {
			arr, other = r, l
		}
		if arr.typ == fArr && other.typ != fArr {
			has := two(p.d.arrayHas, arr.frag, p.str(other))
			if op == "!=" {
				has = cat(fr("(NOT "), has, fr(")"))
			}
			return b(has)
		}
	}
	numeric := func(v val) bool { return v.typ == fNum || v.typ == fBool || v.typ == fTime }
	if numeric(l) || numeric(r) {
		return b(cat(fr("("), p.num(l), fr(" "+op+" "), p.num(r), fr(")")))
	}
	if op == "=" || op == "!=" { // strings: case-insensitive, like the search filter
		return b(cat(fr("(lower("), p.str(l), fr(") "+op+" lower("), p.str(r), fr("))")))
	}
	return b(cat(fr("("), p.str(l), fr(" "+op+" "), p.str(r), fr(")")))
}

var exprFuncs = "if, case, coalesce, lower, upper, len, round, abs, tonumber, tostring, substr, like, match, isnull, isnotnull, null"

func (p *planner) call(r *rel, e eCall) (val, error) {
	args := make([]val, len(e.Args))
	for i, a := range e.Args {
		v, err := p.expr(r, a)
		if err != nil {
			return val{}, err
		}
		args[i] = v
	}
	want := func(ns ...int) error {
		for _, n := range ns {
			if len(args) == n {
				return nil
			}
		}
		parts := make([]string, len(ns))
		for i, n := range ns {
			parts[i] = strconv.Itoa(n)
		}
		return fmt.Errorf("%s() takes %s arguments, got %d", e.Fn, strings.Join(parts, " or "), len(args))
	}
	litNum := func(i int) (float64, bool) {
		if l, ok := e.Args[i].(eLit); ok {
			f, ok := l.V.(float64)
			return f, ok
		}
		return 0, false
	}
	switch e.Fn {
	case "if":
		if err := want(3); err != nil {
			return val{}, err
		}
		return p.cases(args[:1], args[1:2], &args[2])
	case "case":
		if len(args) < 2 || len(args)%2 != 0 {
			return val{}, errors.New("case() takes pairs: case(condition, value, condition, value, ...)")
		}
		var conds []val
		var vals []val
		for i := 0; i < len(args); i += 2 {
			conds = append(conds, args[i])
			vals = append(vals, args[i+1])
		}
		return p.cases(conds, vals, nil)
	case "coalesce":
		if len(args) == 0 {
			return val{}, errors.New("coalesce() needs at least one argument")
		}
		frags, typ := p.unify(args)
		for i, v := range args {
			switch {
			case typ == fStr && !v.null:
				frags[i] = cat(fr("nullIf("), frags[i], fr(", '')"))
			case v.zeroAbsent:
				frags[i] = cat(fr("nullIf("), frags[i], fr(", 0)"))
			}
		}
		return val{frag: cat(fr("coalesce("), joinf(frags, ", "), fr(")")), typ: typ}, nil
	case "lower", "upper":
		if err := want(1); err != nil {
			return val{}, err
		}
		return val{frag: cat(fr(e.Fn+"("), p.str(args[0]), fr(")")), typ: fStr}, nil
	case "len":
		if err := want(1); err != nil {
			return val{}, err
		}
		return val{frag: one(p.d.strLen, p.str(args[0])), typ: fNum}, nil
	case "round":
		if err := want(1, 2); err != nil {
			return val{}, err
		}
		digits := 0
		if len(args) == 2 {
			f, ok := litNum(1)
			if !ok || f != math.Trunc(f) || f < 0 || f > 15 {
				return val{}, errors.New("round(x, n): n must be a whole number from 0 to 15")
			}
			digits = int(f)
		}
		return val{frag: cat(fr("round("), p.num(args[0]), fr(", "+strconv.Itoa(digits)+")")), typ: fNum}, nil
	case "abs":
		if err := want(1); err != nil {
			return val{}, err
		}
		return val{frag: cat(fr("abs("), p.num(args[0]), fr(")")), typ: fNum}, nil
	case "tonumber":
		if err := want(1); err != nil {
			return val{}, err
		}
		return val{frag: p.num(args[0]), typ: fNum}, nil
	case "tostring":
		if err := want(1); err != nil {
			return val{}, err
		}
		return val{frag: p.str(args[0]), typ: fStr}, nil
	case "substr":
		if err := want(2, 3); err != nil {
			return val{}, err
		}
		s, start := p.str(args[0]), one(p.d.integer, p.num(args[1]))
		f := frag{s: "", a: append(append([]any{}, s.a...), start.a...)}
		n := ""
		if len(args) == 3 {
			nf := one(p.d.integer, p.num(args[2]))
			n = nf.s
			f.a = append(f.a, nf.a...)
		}
		f.s = p.d.substr(s.s, start.s, n)
		return val{frag: f, typ: fStr}, nil
	case "like":
		if err := want(2); err != nil {
			return val{}, err
		}
		return val{frag: two(p.d.ilike, p.str(args[0]), p.str(args[1])), typ: fBool}, nil
	case "match":
		if err := want(2); err != nil {
			return val{}, err
		}
		lit, ok := e.Args[1].(eLit)
		pattern, isStr := lit.V.(string)
		if !ok || !isStr {
			return val{}, errors.New(`match(x, "regex"): the regex must be a quoted string`)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return val{}, fmt.Errorf("match(): invalid regex: %v", err)
		}
		s := p.str(args[0])
		return val{frag: frag{p.d.rexMatch(s.s), append(append([]any{}, s.a...), pattern)}, typ: fBool}, nil
	case "isnull", "isnotnull":
		if err := want(1); err != nil {
			return val{}, err
		}
		f := p.isNull(args[0])
		if e.Fn == "isnotnull" {
			f = cat(fr("(NOT "), f, fr(")"))
		}
		return val{frag: f, typ: fBool}, nil
	case "null":
		if err := want(0); err != nil {
			return val{}, err
		}
		return val{frag: fr("NULL"), null: true}, nil
	}
	return val{}, fmt.Errorf("unknown function %s() (functions: %s)", e.Fn, exprFuncs)
}

// cases builds CASE WHEN conds[i] THEN vals[i] ... [ELSE els] END.
func (p *planner) cases(conds, vals []val, els *val) (val, error) {
	all := append([]val{}, vals...)
	if els != nil {
		all = append(all, *els)
	}
	frags, typ := p.unify(all)
	parts := []frag{fr("(CASE")}
	for i, c := range conds {
		b, err := p.boolean(c)
		if err != nil {
			return val{}, err
		}
		parts = append(parts, fr(" WHEN "), b.frag, fr(" THEN "), frags[i])
	}
	if els != nil {
		parts = append(parts, fr(" ELSE "), frags[len(frags)-1])
	}
	parts = append(parts, fr(" END)"))
	return val{frag: cat(parts...), typ: typ}, nil
}

// --- relations ---

func (p *planner) whereClause(conds []frag) frag {
	if len(conds) == 0 {
		return frag{}
	}
	return cat(fr(" WHERE "), joinf(conds, " AND "))
}

func (p *planner) orderBy(keys []okey) frag {
	if len(keys) == 0 {
		return frag{}
	}
	parts := make([]frag, len(keys))
	for i, k := range keys {
		dir := " ASC"
		if k.desc {
			dir = " DESC"
		}
		parts[i] = cat(k.v.frag, fr(dir))
	}
	return cat(fr(" ORDER BY "), joinf(parts, ", "))
}

func limitClause(n int) frag {
	if n <= 0 {
		return frag{}
	}
	return fr(" LIMIT " + strconv.Itoa(n))
}

func (p *planner) needsAlias(v val) bool {
	return len(v.a) > 0 || !(aliasRe.MatchString(v.s) || p.d.plainRef(v.s))
}

// wrap turns the relation into a subquery: computed columns and sort keys become plain
// columns of it, and its WHERE, ORDER BY and LIMIT are applied inside.
func (p *planner) wrap(r *rel, extra ...frag) {
	items := []frag{fr("*")}
	for i := range r.cols {
		c := &r.cols[i]
		if p.needsAlias(c.v) {
			a := p.alias("e")
			items = append(items, cat(c.v.frag, fr(" AS "+a)))
			c.v = val{frag: fr(a), typ: c.v.typ, zeroAbsent: c.v.zeroAbsent}
		}
	}
	var tail frag
	if r.limit > 0 {
		tail = cat(p.orderBy(r.order), limitClause(r.limit))
	}
	for i := range r.order {
		k := &r.order[i]
		if p.needsAlias(k.v) {
			a := p.alias("o")
			items = append(items, cat(k.v.frag, fr(" AS "+a)))
			k.v = val{frag: fr(a), typ: k.v.typ}
		}
	}
	items = append(items, extra...)
	q := cat(fr("SELECT "), joinf(items, ", "), fr(" FROM "), r.from, p.whereClause(r.conds), tail)
	r.from = cat(fr("("), q, fr(") AS events"))
	r.conds, r.limit = nil, 0
}

// settle wraps the relation when a LIMIT is pending, so later commands see only those rows.
func (p *planner) settle(r *rel) {
	if r.limit > 0 {
		p.wrap(r)
	}
}

func (p *planner) setCol(r *rel, name string, v val) {
	for i := range r.cols {
		if r.cols[i].name == name {
			r.cols[i].v = v
			return
		}
	}
	r.cols = append(r.cols, rcol{name, v})
}

// groupKey is the GROUP BY / PARTITION BY form of a value: arrays are split into one
// row per element (cond is then empty), and absent values are filtered out.
func (p *planner) groupKey(v val, explode bool) (key, cond frag, join string, typ ftype, err error) {
	if v.typ == fArr && explode {
		if len(v.a) > 0 {
			return key, cond, "", 0, errors.New("cannot split this array expression")
		}
		expr, j := p.d.explode(v.s, p.alias("j"))
		return fr(expr), frag{}, j, fStr, nil
	}
	typ = v.typ
	if typ == fAny {
		typ = fStr
	}
	if typ == fArr {
		return p.str(v), p.present(v), "", fStr, nil
	}
	return v.frag, p.present(v), "", typ, nil
}

func (p *planner) aggregate(r *rel, a aggSpec) (frag, ftype, error) {
	if a.Field == "" {
		return fr("count(*)"), fNum, nil
	}
	v, err := p.resolve(r, a.Field)
	if err != nil {
		return frag{}, 0, err
	}
	when := func(x frag) frag { return cat(fr("CASE WHEN "), p.present(v), fr(" THEN "), x, fr(" END")) }
	switch a.Fn {
	case "count":
		return cat(fr("count("), when(fr("1")), fr(")")), fNum, nil
	case "dc":
		key, _, _, _, _ := p.groupKey(v, false)
		return cat(fr("count(DISTINCT "), when(key), fr(")")), fNum, nil
	case "sum", "avg":
		return cat(fr(a.Fn+"("), when(p.num(v)), fr(")")), fNum, nil
	case "min", "max":
		switch v.typ {
		case fTime:
			return cat(fr(a.Fn+"("), v.frag, fr(")")), fTime, nil
		case fStr:
			return cat(fr(a.Fn+"("), when(v.frag), fr(")")), fStr, nil
		}
		return cat(fr(a.Fn+"("), when(p.num(v)), fr(")")), fNum, nil
	case "values":
		return one(p.d.values, when(p.str(v))), fArr, nil
	}
	return frag{}, 0, fmt.Errorf("unknown aggregation %q", a.Fn)
}

// apply plans one command (timechart is planned by the caller).
func (p *planner) apply(r *rel, c Command) error {
	switch c := c.(type) {
	case searchCmd:
		if !r.events {
			return errors.New("search: use where after stats, top or table")
		}
		p.settle(r)
		n, err := ParseQuery(c.Query)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}
		s, a, err := compile(n, p.d)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}
		r.conds = append(r.conds, frag{"(" + s + ")", a})
	case whereCmd:
		p.settle(r)
		v, err := p.expr(r, c.Expr)
		if err == nil {
			v, err = p.boolean(v)
		}
		if err != nil {
			return fmt.Errorf("where: %w", err)
		}
		r.conds = append(r.conds, v.frag)
	case evalCmd:
		for _, as := range c.Assigns {
			v, err := p.expr(r, as.Expr)
			if err != nil {
				return fmt.Errorf("eval %s: %w", as.Name, err)
			}
			p.setCol(r, as.Name, v)
		}
	case renameCmd:
		for _, pr := range c.Pairs {
			if err := p.rename(r, pr[0], pr[1]); err != nil {
				return fmt.Errorf("rename: %w", err)
			}
		}
	case rexCmd:
		v, err := p.resolve(r, c.Field)
		if err != nil {
			return fmt.Errorf("rex: %w", err)
		}
		s := p.str(v)
		for i, name := range c.Names {
			f := frag{p.d.rexGroup(s.s, i+1), append(append([]any{}, s.a...), c.Pattern)}
			p.setCol(r, name, val{frag: f, typ: fStr})
		}
	case sortCmd:
		p.settle(r)
		var keys []okey
		for _, k := range c.Keys {
			v, err := p.resolve(r, k.Field)
			if err != nil {
				return fmt.Errorf("sort: %w", err)
			}
			switch {
			case v.path != nil: // raw JSON field: numbers numerically, then text
				n := p.num(v)
				keys = append(keys, okey{val{frag: n, typ: fNum}, k.Desc})
			case v.typ == fArr:
				v = val{frag: p.str(v), typ: fStr}
			}
			keys = append(keys, okey{v, k.Desc})
		}
		r.order = keys
		r.limit = c.Limit
	case headCmd:
		if r.limit == 0 || c.N < r.limit {
			r.limit = c.N
		}
	case dedupCmd:
		return p.dedup(r, c)
	case tableCmd:
		var cols []rcol
		seen := map[string]bool{}
		for _, f := range c.Fields {
			if seen[f] {
				continue
			}
			seen[f] = true
			v, err := p.resolve(r, f)
			if err != nil {
				return fmt.Errorf("table: %w", err)
			}
			cols = append(cols, rcol{f, v})
		}
		r.events, r.cols = false, cols
	case statsCmd:
		return p.stats(r, c)
	case topCmd:
		return p.top(r, c)
	case timechartCmd:
		return errors.New("timechart must be the last command")
	default:
		return fmt.Errorf("unsupported command %s", c.cmdName())
	}
	return nil
}

func (p *planner) rename(r *rel, from, to string) error {
	v, err := p.resolve(r, from)
	if err != nil {
		return err
	}
	if r.events {
		for i := range r.cols {
			if r.cols[i].name == from {
				r.cols = append(r.cols[:i], r.cols[i+1:]...)
				break
			}
		}
		p.setCol(r, to, v)
		return nil
	}
	idx := -1
	for i, c := range r.cols {
		if c.name == from || (idx < 0 && strings.EqualFold(c.name, from)) {
			idx = i
		}
	}
	for i, c := range r.cols {
		if i != idx && c.name == to {
			return fmt.Errorf("there is already a column %q", to)
		}
	}
	r.cols[idx].name = to
	return nil
}

func (p *planner) dedup(r *rel, c dedupCmd) error {
	p.settle(r)
	var keys []frag
	for _, f := range c.Fields {
		v, err := p.resolve(r, f)
		if err != nil {
			return fmt.Errorf("dedup: %w", err)
		}
		key, cond, _, _, _ := p.groupKey(v, false)
		keys = append(keys, key)
		r.conds = append(r.conds, cond)
	}
	rn := p.alias("rn")
	item := cat(fr("row_number() OVER (PARTITION BY "), joinf(keys, ", "), p.orderBy(r.order), fr(") AS "+rn))
	p.wrap(r, item)
	r.conds = append(r.conds, fr(rn+" <= "+strconv.Itoa(c.N)))
	return nil
}

// grouped builds SELECT items AS aliases ... GROUP BY for stats-like commands.
type grouped struct {
	items  []frag
	conds  []frag
	joins  string
	groups []string
	cols   []rcol
}

func (p *planner) groupBy(r *rel, g *grouped, fields []string) error {
	for _, f := range fields {
		v, err := p.resolve(r, f)
		if err != nil {
			return err
		}
		key, cond, join, typ, err := p.groupKey(v, true)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		a := p.alias("c")
		g.items = append(g.items, cat(key, fr(" AS "+a)))
		if cond.s != "" {
			g.conds = append(g.conds, cond)
		}
		g.joins += join
		g.groups = append(g.groups, a)
		g.cols = append(g.cols, rcol{f, val{frag: fr(a), typ: typ}})
	}
	return nil
}

func (p *planner) add(g *grouped, name string, f frag, typ ftype) val {
	a := p.alias("c")
	g.items = append(g.items, cat(f, fr(" AS "+a)))
	v := val{frag: fr(a), typ: typ}
	g.cols = append(g.cols, rcol{name, v})
	return v
}

func (p *planner) groupSQL(r *rel, g *grouped) frag {
	q := cat(fr("SELECT "), joinf(g.items, ", "), fr(" FROM "), r.from, fr(g.joins),
		p.whereClause(append(append([]frag{}, r.conds...), g.conds...)))
	if len(g.groups) > 0 {
		q = cat(q, fr(" GROUP BY "+strings.Join(g.groups, ", ")))
	}
	return q
}

func (p *planner) stats(r *rel, c statsCmd) error {
	p.settle(r)
	g := &grouped{}
	if err := p.groupBy(r, g, c.By); err != nil {
		return fmt.Errorf("stats: %w", err)
	}
	var order []okey
	for _, col := range g.cols {
		order = append(order, okey{col.v, false})
	}
	for _, a := range c.Aggs {
		f, typ, err := p.aggregate(r, a)
		if err != nil {
			return fmt.Errorf("stats: %w", err)
		}
		p.add(g, a.As, f, typ)
	}
	*r = rel{from: cat(fr("("), p.groupSQL(r, g), fr(") AS events")), cols: g.cols, order: order}
	return nil
}

func (p *planner) top(r *rel, c topCmd) error {
	p.settle(r)
	g := &grouped{}
	if err := p.groupBy(r, g, c.Fields); err != nil {
		return fmt.Errorf("%s: %w", c.cmdName(), err)
	}
	first := g.cols[0].v
	cnt := p.add(g, "count", fr("count(*)"), fNum)
	p.add(g, "percent", fr("count(*) * 100.0 / sum(count(*)) OVER ()"), fNum)
	*r = rel{
		from:  cat(fr("("), p.groupSQL(r, g), fr(") AS events")),
		cols:  g.cols,
		order: []okey{{cnt, !c.Rare}, {first, false}},
		limit: c.Limit,
	}
	return nil
}
