package detect

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Correlation types.
const (
	CorrEventCount = "event_count" // how many events matched
	CorrValueCount = "value_count" // how many distinct values of a field they had
	CorrTemporal   = "temporal"    // whether all the rules matched (Ordered: in order)
)

// maxThreshold is the highest count a correlation can wait for: a group keeps at most this
// many timestamps or values.
const maxThreshold = 1000

// Correlation is a parsed Sigma correlation (the correlation block of a correlation rule,
// or a rule's own "| count()" aggregation with timeframe).
type Correlation struct {
	Type    string // CorrEventCount, CorrValueCount or CorrTemporal
	Ordered bool   // temporal_ordered: the rules must match in the order listed
	// Rules are the base rules, as written (ids or names).
	Rules    []string
	GroupBy  []string
	Timespan time.Duration
	// Op and Threshold are the condition: gt, gte or eq. For temporal correlations
	// without a condition, the threshold is the number of rules.
	Op        string
	Threshold int
	Field     string // value_count: the field whose distinct values are counted
	// Generate lets the base rules raise their own alerts too. Without it they only feed
	// the correlation (Sigma semantics).
	Generate bool
	// Aliases maps a group-by name to the field each base rule (by reference) holds it in.
	Aliases map[string]map[string]string
	// Aggregation marks a rule's own "| count()" condition: the rule is its own base rule.
	Aggregation bool

	localIDs []string // per Rules entry: the id of the rule in the same file it names
}

// need is how many events, values or rules satisfy the condition.
func (c *Correlation) need() int {
	n := c.Threshold
	if c.Op == "gt" {
		n++
	}
	return max(n, 1)
}

// opSymbol renders the condition for messages.
func (c *Correlation) opSymbol() string {
	switch c.Op {
	case "gt":
		return ">"
	case "eq":
		return "="
	}
	return ">="
}

type correlationYAML struct {
	Type      string                       `yaml:"type"`
	Rules     yaml.Node                    `yaml:"rules"`
	GroupBy   yaml.Node                    `yaml:"group-by"`
	Timespan  string                       `yaml:"timespan"`
	Timeframe string                       `yaml:"timeframe"` // early drafts of the spec
	Condition yaml.Node                    `yaml:"condition"`
	Generate  bool                         `yaml:"generate"`
	Ordered   bool                         `yaml:"ordered"` // early drafts: temporal + ordered
	Aliases   map[string]map[string]string `yaml:"aliases"`
}

// parseCorrelation reads a Sigma correlation block.
func parseCorrelation(n *yaml.Node) (*Correlation, error) {
	fail := func(format string, a ...any) (*Correlation, error) {
		return nil, fmt.Errorf("correlation: "+format, a...)
	}
	if n.Kind != yaml.MappingNode {
		return fail("must be a mapping")
	}
	var raw correlationYAML
	if err := n.Decode(&raw); err != nil {
		return fail("%v", err)
	}
	c := &Correlation{Generate: raw.Generate, Aliases: raw.Aliases}
	switch t := strings.ToLower(strings.TrimSpace(raw.Type)); t {
	case CorrEventCount, CorrValueCount:
		c.Type = t
	case CorrTemporal:
		c.Type, c.Ordered = t, raw.Ordered
	case "temporal_ordered":
		c.Type, c.Ordered = CorrTemporal, true
	case "":
		return fail("type is missing (event_count, value_count, temporal or temporal_ordered)")
	default:
		return fail("type %q is not supported (event_count, value_count, temporal and temporal_ordered are)", t)
	}
	var err error
	if c.Rules, err = stringList(&raw.Rules); err != nil {
		return fail("rules: %v", err)
	}
	if len(c.Rules) == 0 {
		return fail("rules is missing: name the rules it correlates")
	}
	if c.GroupBy, err = stringList(&raw.GroupBy); err != nil {
		return fail("group-by: %v", err)
	}
	span := raw.Timespan
	if span == "" {
		span = raw.Timeframe
	}
	if span == "" {
		return fail("timespan is missing")
	}
	if c.Timespan, err = parseSpan(span); err != nil {
		return fail("timespan: %v", err)
	}
	for alias, m := range c.Aliases {
		for ref := range m {
			if !containsStr(c.Rules, ref) {
				return fail("alias %s names %q, which is not in rules", alias, ref)
			}
		}
	}

	cond := map[string]string{}
	switch raw.Condition.Kind {
	case 0:
	case yaml.MappingNode:
		for i := 0; i+1 < len(raw.Condition.Content); i += 2 {
			cond[strings.ToLower(raw.Condition.Content[i].Value)] = raw.Condition.Content[i+1].Value
		}
	default:
		return fail("condition must be a mapping such as {gte: 10}")
	}
	c.Field = strings.TrimSpace(cond["field"])
	delete(cond, "field")
	if _, ok := cond["lt"]; ok {
		return fail("lt conditions are not supported: \"fewer than\" thresholds need the window to close, which HomeXDR does not evaluate")
	}
	if _, ok := cond["lte"]; ok {
		return fail("lte conditions are not supported: \"fewer than\" thresholds need the window to close, which HomeXDR does not evaluate")
	}
	for k, v := range cond {
		switch k {
		case "gt", "gte", "eq":
		default:
			return fail("condition %q is not supported (gt, gte and eq are)", k)
		}
		if c.Op != "" {
			return fail("condition takes one of gt, gte or eq")
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return fail("condition %s needs a whole number", k)
		}
		c.Op, c.Threshold = k, n
	}

	switch c.Type {
	case CorrEventCount, CorrValueCount:
		if c.Op == "" {
			return fail("condition is missing, such as {gte: 10}")
		}
		if c.Type == CorrValueCount && c.Field == "" {
			return fail("value_count needs condition.field, the field whose distinct values are counted")
		}
		if c.Type == CorrEventCount && c.Field != "" {
			return fail("condition.field is only for value_count")
		}
	case CorrTemporal:
		if c.Field != "" {
			return fail("condition.field is only for value_count")
		}
		if len(c.Rules) < 2 {
			return fail("a temporal correlation needs at least two rules")
		}
		if c.Op == "" {
			c.Op, c.Threshold = "gte", len(c.Rules)
		}
		if c.Ordered && c.need() != len(c.Rules) {
			return fail("temporal_ordered needs every rule to match; leave out the condition")
		}
		if c.need() > len(c.Rules) {
			return fail("condition asks for more rules than it lists")
		}
	}
	if err := c.checkThreshold(); err != nil {
		return nil, fmt.Errorf("correlation: %w", err)
	}
	return c, nil
}

func (c *Correlation) checkThreshold() error {
	if c.Op == "eq" && c.Threshold == 0 {
		return errors.New("a count of 0 can never be reached")
	}
	if c.need() > maxThreshold {
		return fmt.Errorf("thresholds above %d are not supported", maxThreshold)
	}
	return nil
}

// aggRe matches the part of a condition after "|": count([field]) [by f1[, f2]] op N.
var aggRe = regexp.MustCompile(`(?i)^\s*(\w+)\s*\(\s*([^()\s]*)\s*\)\s*(?:by\s+([^<>=!]+?))?\s*(<=|>=|==|!=|<|>|=)\s*(\d+)\s*$`)

// parseAggregation reads a legacy Sigma aggregation ("count() by SourceIp > 10") and the
// rule's timeframe. The caller sets Rules to the rule itself.
func parseAggregation(agg string, timeframe *yaml.Node) (*Correlation, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(agg)), "near") {
		return nil, errors.New("near aggregations are not supported")
	}
	m := aggRe.FindStringSubmatch(agg)
	if m == nil {
		return nil, errors.New("expected an aggregation such as count() by field > 10")
	}
	if fn := strings.ToLower(m[1]); fn != "count" {
		return nil, fmt.Errorf("%s() aggregations are not supported (count() is)", fn)
	}
	c := &Correlation{Type: CorrEventCount, Aggregation: true, Field: m[2]}
	if c.Field != "" {
		c.Type = CorrValueCount
	}
	if by := strings.TrimSpace(m[3]); by != "" {
		for _, f := range strings.Split(by, ",") {
			if f = strings.TrimSpace(f); f == "" || strings.ContainsAny(f, " \t") {
				return nil, fmt.Errorf("bad group-by field list %q", by)
			}
			c.GroupBy = append(c.GroupBy, strings.TrimSpace(f))
		}
	}
	switch m[4] {
	case ">":
		c.Op = "gt"
	case ">=":
		c.Op = "gte"
	case "=", "==":
		c.Op = "eq"
	case "<", "<=":
		return nil, errors.New("\"fewer than\" thresholds (< and <=) are not supported: they need the window to close, which HomeXDR does not evaluate")
	default:
		return nil, fmt.Errorf("operator %s is not supported", m[4])
	}
	n, err := strconv.Atoi(m[5])
	if err != nil {
		return nil, fmt.Errorf("bad count %q", m[5])
	}
	c.Threshold = n
	if err := c.checkThreshold(); err != nil {
		return nil, err
	}
	if timeframe.Kind != yaml.ScalarNode {
		return nil, errors.New("timeframe must be a duration such as 5m")
	}
	if c.Timespan, err = parseSpan(timeframe.Value); err != nil {
		return nil, fmt.Errorf("timeframe: %w", err)
	}
	return c, nil
}

// parseSpan reads a Sigma time span: a whole number and s, m, h or d.
func parseSpan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0, fmt.Errorf("%q is not a duration such as 30s, 5m, 1h or 1d", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a duration such as 30s, 5m, 1h or 1d", s)
	}
	var unit time.Duration
	switch s[len(s)-1] {
	case 's':
		unit = time.Second
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("%q is not a duration such as 30s, 5m, 1h or 1d (months and years are not supported)", s)
	}
	if n > 90*24*int(time.Hour/unit) {
		return 0, fmt.Errorf("%q is longer than 90 days", s)
	}
	return time.Duration(n) * unit, nil
}

// formatSpan renders a duration the way Sigma writes it (5m, 1h, 1d).
func formatSpan(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	case d >= time.Hour && d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	case d >= time.Minute && d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d%time.Second == 0:
		return strconv.Itoa(int(d/time.Second)) + "s"
	}
	return d.String()
}

// stringList reads a YAML string or list of strings.
func stringList(n *yaml.Node) ([]string, error) {
	switch n.Kind {
	case 0:
		return nil, nil
	case yaml.ScalarNode:
		if n.Tag == "!!null" || strings.TrimSpace(n.Value) == "" {
			return nil, nil
		}
		return []string{strings.TrimSpace(n.Value)}, nil
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode || strings.TrimSpace(c.Value) == "" {
				return nil, errors.New("must be a list of names")
			}
			out = append(out, strings.TrimSpace(c.Value))
		}
		return out, nil
	}
	return nil, errors.New("must be a name or a list of names")
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// linkLocal resolves correlation references to rules in the same file, which win over
// rules of the same name elsewhere.
func linkLocal(docs []Document) {
	for _, d := range docs {
		c := corrOf(d.Rule)
		if c == nil {
			continue
		}
		c.localIDs = make([]string, len(c.Rules))
		for i, ref := range c.Rules {
			for _, o := range docs {
				if o.Rule != nil && o.Rule != d.Rule && (o.Rule.ID == ref || o.Rule.Name == ref) {
					c.localIDs[i] = o.Rule.ID
					break
				}
			}
		}
	}
}

// corrOf returns the correlation block of a Sigma correlation rule, or nil for any other
// rule (including one with its own aggregation condition).
func corrOf(r *Rule) *Correlation {
	if r == nil || r.Correlation == nil || r.Correlation.Aggregation {
		return nil
	}
	return r.Correlation
}

// resolver finds the base rules of correlation rules by id, then by name.
type resolver struct {
	rules  []*Rule // each once, in the order given
	byID   map[string]*Rule
	byName map[string][]*Rule
}

func newResolver(sets ...[]*Rule) *resolver {
	rv := &resolver{byID: map[string]*Rule{}, byName: map[string][]*Rule{}}
	seen := map[*Rule]bool{}
	for _, set := range sets {
		for _, r := range set {
			if r == nil || seen[r] {
				continue
			}
			seen[r] = true
			rv.rules = append(rv.rules, r)
			if _, ok := rv.byID[r.ID]; !ok {
				rv.byID[r.ID] = r
			}
			if r.Name != "" {
				rv.byName[r.Name] = append(rv.byName[r.Name], r)
			}
		}
	}
	return rv
}

// bases returns the base rules of r, one per entry of its Rules.
func (rv *resolver) bases(r *Rule) ([]*Rule, error) {
	if r.Correlation == nil {
		return nil, nil
	}
	if r.Correlation.Aggregation {
		return []*Rule{r}, nil
	}
	c := r.Correlation
	out := make([]*Rule, len(c.Rules))
	for i, ref := range c.Rules {
		var b *Rule
		if i < len(c.localIDs) && c.localIDs[i] != "" {
			b = rv.byID[c.localIDs[i]]
		}
		if b == nil {
			b = rv.byID[ref]
		}
		if b == nil {
			switch named := rv.byName[ref]; len(named) {
			case 0:
			case 1:
				b = named[0]
			default:
				return nil, fmt.Errorf("correlation: %d loaded rules are named %q; reference it by id", len(named), ref)
			}
		}
		switch {
		case b == nil:
			return nil, fmt.Errorf("correlation: rule %q is not loaded (no rule has that id or name)", ref)
		case b == r:
			return nil, errors.New("correlation: the rule references itself")
		case b.Correlation != nil:
			return nil, fmt.Errorf("correlation: %q is itself a correlation or aggregation rule, and correlations of correlations are not supported", ref)
		}
		out[i] = b
	}
	return out, nil
}

// ResolveCorrelations checks that the base rules of every correlation rule in rules are
// among rules, by id or name. It returns why for each correlation rule that cannot run.
func ResolveCorrelations(rules []*Rule) map[*Rule]error {
	rv := newResolver(rules)
	out := map[*Rule]error{}
	for _, r := range rv.rules {
		if _, err := rv.bases(r); err != nil {
			out[r] = err
		}
	}
	return out
}
