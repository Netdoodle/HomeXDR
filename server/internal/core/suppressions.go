package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	// suppressionCacheTTL is how long the suppression list is cached. API writes refresh
	// it at once; this is how long the server takes to notice a write by another process.
	suppressionCacheTTL = 30 * time.Second
	// suppressionDefaultExpiry applies when a request does not say when to expire.
	suppressionDefaultExpiry = 90 * 24 * time.Hour

	suppressionMaxConditions = 20
	suppressionMaxValue      = 1024
	suppressionMaxReason     = 500
	suppressionSampleSize    = 5
	suppressionPageSize      = 500

	noiseSettingsKey = "noise_settings"
)

// NoiseSettings are the settings of the alert noise feature.
type NoiseSettings struct {
	// MustAlertRules lists rule IDs that always alert, whatever a suppression says.
	MustAlertRules []string `json:"must_alert_rules"`
}

// LoadNoiseSettings returns the stored settings (empty when none are stored).
func LoadNoiseSettings(ctx context.Context, st *store.Store) (NoiseSettings, error) {
	var n NoiseSettings
	if err := st.GetKV(ctx, noiseSettingsKey, &n); err != nil && !errors.Is(err, store.ErrNotFound) {
		return n, err
	}
	if n.MustAlertRules == nil {
		n.MustAlertRules = []string{}
	}
	return n, nil
}

// SaveNoiseSettings stores the settings and applies them to hits straight away.
func (c *Core) SaveNoiseSettings(ctx context.Context, n NoiseSettings, user string) (NoiseSettings, error) {
	seen := map[string]bool{}
	clean := []string{}
	for _, id := range n.MustAlertRules {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			clean = append(clean, id)
		}
	}
	n.MustAlertRules = clean
	if err := c.State.SetKV(ctx, noiseSettingsKey, n); err != nil {
		return n, err
	}
	c.Suppress.Invalidate()
	c.Audit(ctx, user, "suppression.must_alert", "", strings.Join(clean, ", "))
	return n, nil
}

// SuppressionSpec describes a suppression. The console API and the suppress-apply
// command both take this shape.
type SuppressionSpec struct {
	RuleID     string                       `json:"rule_id"`
	HostID     string                       `json:"host_id"`
	Conditions []store.SuppressionCondition `json:"conditions"`
	Reason     string                       `json:"reason"`
	// ExpiresAt defaults to 90 days from now. NeverExpires asks for no expiry.
	ExpiresAt    *time.Time `json:"expires_at"`
	NeverExpires bool       `json:"never_expires"`
	Enabled      *bool      `json:"enabled"`
	// ConfirmBroad accepts a suppression of a whole rule on every host.
	ConfirmBroad bool `json:"confirm_broad"`
	// Apply also closes the open alerts that match, as suppressed.
	Apply bool `json:"apply"`
}

var conditionField = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func validSuppressionOp(op string) bool {
	switch op {
	case "equals", "contains", "startswith", "endswith":
		return true
	}
	return false
}

// validateSuppressionScope refuses a suppression that would match too much.
func validateSuppressionScope(ruleID, hostID string, conds []store.SuppressionCondition, confirmBroad bool) error {
	if ruleID == "" && len(conds) == 0 {
		return invalid("a suppression needs a rule or at least one condition")
	}
	if len(ruleID) > 256 || len(hostID) > 256 {
		return invalid("rule_id and host_id are too long")
	}
	if len(conds) > suppressionMaxConditions {
		return invalid("a suppression can have at most %d conditions", suppressionMaxConditions)
	}
	for _, cd := range conds {
		switch {
		case !conditionField.MatchString(cd.Field):
			return invalid("condition field %q is not a field name", cd.Field)
		case !validSuppressionOp(cd.Op):
			return invalid("condition op must be equals, contains, startswith or endswith")
		case strings.TrimSpace(cd.Value) == "":
			return invalid("condition on %s has no value", cd.Field)
		case len(cd.Value) > suppressionMaxValue:
			return invalid("condition on %s has a value longer than %d characters", cd.Field, suppressionMaxValue)
		}
	}
	if hostID == "" && len(conds) == 0 && !confirmBroad {
		return invalid("this would suppress the whole rule on every host; set confirm_broad to do that")
	}
	return nil
}

// scope validates only the parts that say what the suppression matches.
func (sp SuppressionSpec) scope() (*store.Suppression, error) {
	sp.RuleID, sp.HostID = strings.TrimSpace(sp.RuleID), strings.TrimSpace(sp.HostID)
	if err := validateSuppressionScope(sp.RuleID, sp.HostID, sp.Conditions, true); err != nil {
		return nil, err
	}
	return &store.Suppression{RuleID: sp.RuleID, HostID: sp.HostID, Conditions: sp.Conditions, Enabled: true}, nil
}

// build validates a full spec and returns the suppression it describes.
func (sp SuppressionSpec) build(user string, now time.Time) (*store.Suppression, error) {
	out, err := sp.scope()
	if err != nil {
		return nil, err
	}
	if err := validateSuppressionScope(out.RuleID, out.HostID, out.Conditions, sp.ConfirmBroad); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(sp.Reason)
	if reason == "" {
		return nil, invalid("a suppression needs a reason")
	}
	if len(reason) > suppressionMaxReason {
		return nil, invalid("the reason is longer than %d characters", suppressionMaxReason)
	}
	out.Reason, out.CreatedBy = reason, user
	if sp.Enabled != nil {
		out.Enabled = *sp.Enabled
	}
	switch {
	case sp.NeverExpires && sp.ExpiresAt != nil:
		return nil, invalid("set either expires_at or never_expires, not both")
	case sp.NeverExpires:
	case sp.ExpiresAt != nil:
		if !sp.ExpiresAt.After(now) {
			return nil, invalid("expires_at is in the past")
		}
		t := sp.ExpiresAt.UTC()
		out.ExpiresAt = &t
	default:
		t := now.Add(suppressionDefaultExpiry)
		out.ExpiresAt = &t
	}
	return out, nil
}

// hitView is a hit or stored alert being compared with suppressions. It flattens the
// event only if a condition needs it, and only once.
type hitView struct {
	ruleID, hostID string
	ev             *event.Event
	doc            *detect.Doc
}

func (h *hitView) get(field string) ([]string, bool) {
	if h.ev == nil {
		return nil, false
	}
	if h.doc == nil {
		h.doc = detect.NewDoc(h.ev)
	}
	return h.doc.Get(field)
}

// matches compares scope and conditions, not whether the suppression is active. Every
// condition must hold. Values compare exactly, including case, so a suppression never
// covers more than what it spells out.
func (h *hitView) matches(sp *store.Suppression) bool {
	if sp.RuleID != "" && sp.RuleID != h.ruleID {
		return false
	}
	if sp.HostID != "" && sp.HostID != h.hostID {
		return false
	}
	for _, cd := range sp.Conditions {
		values, ok := h.get(cd.Field)
		if !ok || !anyValueMatches(values, cd) {
			return false
		}
	}
	return true
}

func anyValueMatches(values []string, cd store.SuppressionCondition) bool {
	for _, v := range values {
		var hit bool
		switch cd.Op {
		case "equals":
			hit = v == cd.Value
		case "contains":
			hit = strings.Contains(v, cd.Value)
		case "startswith":
			hit = strings.HasPrefix(v, cd.Value)
		case "endswith":
			hit = strings.HasSuffix(v, cd.Value)
		}
		if hit {
			return true
		}
	}
	return false
}

// mustAlertWhy says why a hit may not be suppressed, or returns "".
func mustAlertWhy(severity, ruleID string, mustRules map[string]bool) string {
	switch {
	case severity == store.SevCritical:
		return "critical alerts are never suppressed"
	case mustRules[ruleID]:
		return "this rule is on the must-alert list"
	}
	return ""
}

// Suppressor decides whether a hit is suppressed, from a short-lived copy of the list.
type Suppressor struct {
	st  *store.Store
	log *slog.Logger

	mu     sync.Mutex
	loaded time.Time
	list   []*store.Suppression
	must   map[string]bool
}

// NewSuppressor returns a suppressor reading from st.
func NewSuppressor(st *store.Store, log *slog.Logger) *Suppressor {
	return &Suppressor{st: st, log: log}
}

// Invalidate makes the next hit read the list again.
func (s *Suppressor) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.loaded = time.Time{}
	s.mu.Unlock()
}

func (s *Suppressor) snapshot(ctx context.Context) ([]*store.Suppression, map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded.IsZero() && time.Since(s.loaded) < suppressionCacheTTL {
		return s.list, s.must
	}
	// On a read error keep what we have and try again at the next refresh.
	s.loaded = time.Now()
	all, err := s.st.ListSuppressions(ctx)
	if err != nil {
		s.log.Warn("load suppressions", "err", err)
		return s.list, s.must
	}
	n, err := LoadNoiseSettings(ctx, s.st)
	if err != nil {
		s.log.Warn("load noise settings", "err", err)
		return s.list, s.must
	}
	list := make([]*store.Suppression, 0, len(all))
	for _, sp := range all {
		if sp.Enabled {
			list = append(list, sp)
		}
	}
	s.list, s.must = list, mustSet(n)
	return s.list, s.must
}

func mustSet(n NoiseSettings) map[string]bool {
	m := make(map[string]bool, len(n.MustAlertRules))
	for _, id := range n.MustAlertRules {
		m[id] = true
	}
	return m
}

// Check returns the suppression that applies to a hit, or nil. A result with Overridden
// set matched, but the hit must still alert.
func (s *Suppressor) Check(ctx context.Context, in store.AlertInput) *store.AlertSuppression {
	if s == nil {
		return nil
	}
	list, must := s.snapshot(ctx)
	if len(list) == 0 {
		return nil
	}
	now := time.Now()
	h := &hitView{ruleID: in.Rule.ID, hostID: in.Event.Host.ID, ev: in.Event}
	for _, sp := range list {
		if !sp.Active(now) || !h.matches(sp) {
			continue
		}
		ref := &store.AlertSuppression{ID: sp.ID, Reason: sp.Reason}
		if why := mustAlertWhy(in.Severity, in.Rule.ID, must); why != "" {
			ref.Overridden, ref.Why = true, why
		}
		return ref
	}
	return nil
}

// SuppressionSample is an open alert shown in a preview.
type SuppressionSample struct {
	ID          string    `json:"id"`
	RuleTitle   string    `json:"rule_title"`
	Severity    string    `json:"severity"`
	Hostname    string    `json:"hostname"`
	ProcessName string    `json:"process_name,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	Count       int       `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
}

// SuppressionPreview says what a suppression would do to the open alerts.
type SuppressionPreview struct {
	// Matches is how many open alerts it would close, and Hits how many hits they hold.
	Matches int   `json:"matches"`
	Hits    int64 `json:"hits"`
	// Kept is how many more match but stay open because of must-alert.
	Kept   int                 `json:"kept"`
	Sample []SuppressionSample `json:"sample"`

	ids []string
}

// previewSuppression looks through the open alerts for those a suppression matches.
func previewSuppression(ctx context.Context, st *store.Store, sp *store.Suppression, must map[string]bool) (*SuppressionPreview, error) {
	p := &SuppressionPreview{Sample: []SuppressionSample{}}
	after := ""
	for {
		page, err := st.OpenAlertsPage(ctx, sp.RuleID, sp.HostID, after, suppressionPageSize)
		if err != nil {
			return nil, err
		}
		for _, a := range page {
			after = a.ID
			h := &hitView{ruleID: a.Rule.ID, hostID: a.HostID, ev: a.Event}
			if !h.matches(sp) {
				continue
			}
			if mustAlertWhy(a.Severity, a.Rule.ID, must) != "" {
				p.Kept++
				continue
			}
			p.Matches++
			p.Hits += int64(a.Count)
			p.ids = append(p.ids, a.ID)
			if len(p.Sample) < suppressionSampleSize {
				p.Sample = append(p.Sample, SuppressionSample{ID: a.ID, RuleTitle: a.Rule.Title, Severity: a.Severity,
					Hostname: a.Hostname, ProcessName: a.ProcessName, CommandLine: a.CommandLine, Count: a.Count, LastSeen: a.LastSeen})
			}
		}
		if len(page) < suppressionPageSize {
			return p, nil
		}
	}
}

// closeSuppressed closes the alerts a preview found.
func closeSuppressed(ctx context.Context, st *store.Store, sp *store.Suppression, p *SuppressionPreview, user string) (int, error) {
	ref := store.AlertSuppression{ID: sp.ID, Reason: sp.Reason}
	return st.CloseAlertsAsSuppressed(ctx, p.ids, ref, user, "Closed by a suppression: "+sp.Reason)
}

func describeSuppression(sp *store.Suppression) string {
	var b strings.Builder
	if sp.RuleID != "" {
		fmt.Fprintf(&b, "rule=%s ", sp.RuleID)
	}
	if sp.HostID != "" {
		fmt.Fprintf(&b, "host=%s ", sp.HostID)
	}
	for _, cd := range sp.Conditions {
		fmt.Fprintf(&b, "%s %s %q ", cd.Field, cd.Op, cd.Value)
	}
	if sp.ExpiresAt != nil {
		fmt.Fprintf(&b, "expires=%s ", sp.ExpiresAt.UTC().Format("2006-01-02"))
	} else {
		b.WriteString("expires=never ")
	}
	if !sp.Enabled {
		b.WriteString("disabled ")
	}
	b.WriteString("reason=" + sp.Reason)
	return b.String()
}

// SuppressionResult is a created or changed suppression and what applying it did.
type SuppressionResult struct {
	Suppression *store.Suppression `json:"suppression"`
	// Closed is how many open alerts it closed, and Kept how many it left for must-alert.
	Closed int `json:"closed"`
	Kept   int `json:"kept"`
}

// PreviewSuppression says what a spec would do to the open alerts, without changing them.
func (c *Core) PreviewSuppression(ctx context.Context, spec SuppressionSpec) (*SuppressionPreview, error) {
	sp, err := spec.scope()
	if err != nil {
		return nil, err
	}
	n, err := LoadNoiseSettings(ctx, c.State)
	if err != nil {
		return nil, err
	}
	return previewSuppression(ctx, c.State, sp, mustSet(n))
}

// CreateSuppression stores a suppression and, when the spec asks, closes matching alerts.
func (c *Core) CreateSuppression(ctx context.Context, spec SuppressionSpec, user string) (*SuppressionResult, error) {
	res, err := createAndApply(ctx, c.State, spec, user, spec.Apply)
	if err != nil {
		return nil, err
	}
	c.Suppress.Invalidate()
	return res, nil
}

func createAndApply(ctx context.Context, st *store.Store, spec SuppressionSpec, user string, apply bool) (*SuppressionResult, error) {
	sp, err := spec.build(user, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	sp.RuleTitle, sp.Hostname = st.SuppressionNames(ctx, sp.RuleID, sp.HostID)
	if err := st.CreateSuppression(ctx, sp); err != nil {
		return nil, err
	}
	if err := st.Audit(ctx, user, "suppression.create", sp.ID, describeSuppression(sp)); err != nil {
		return nil, err
	}
	res := &SuppressionResult{Suppression: sp}
	if !apply {
		return res, nil
	}
	if err := applySuppression(ctx, st, res, user); err != nil {
		return res, err
	}
	return res, nil
}

func applySuppression(ctx context.Context, st *store.Store, res *SuppressionResult, user string) error {
	n, err := LoadNoiseSettings(ctx, st)
	if err != nil {
		return err
	}
	p, err := previewSuppression(ctx, st, res.Suppression, mustSet(n))
	if err != nil {
		return err
	}
	res.Kept = p.Kept
	res.Closed, err = closeSuppressed(ctx, st, res.Suppression, p, user)
	if err != nil {
		return err
	}
	return st.Audit(ctx, user, "suppression.apply", res.Suppression.ID,
		fmt.Sprintf("closed %d open alerts, kept %d for must-alert", res.Closed, res.Kept))
}

// SuppressionPatch changes a suppression; nil fields stay as they are.
type SuppressionPatch struct {
	RuleID       *string                       `json:"rule_id"`
	HostID       *string                       `json:"host_id"`
	Conditions   *[]store.SuppressionCondition `json:"conditions"`
	Reason       *string                       `json:"reason"`
	ExpiresAt    *time.Time                    `json:"expires_at"`
	NeverExpires *bool                         `json:"never_expires"`
	Enabled      *bool                         `json:"enabled"`
	ConfirmBroad bool                          `json:"confirm_broad"`
}

// UpdateSuppression applies a patch. A change of scope is held to the same rules as a new
// suppression.
func (c *Core) UpdateSuppression(ctx context.Context, id string, p SuppressionPatch, user string) (*store.Suppression, error) {
	sp, err := c.State.GetSuppression(ctx, id)
	if err != nil {
		return nil, err
	}
	scopeChanged := p.RuleID != nil || p.HostID != nil || p.Conditions != nil
	if p.RuleID != nil {
		sp.RuleID = strings.TrimSpace(*p.RuleID)
	}
	if p.HostID != nil {
		sp.HostID = strings.TrimSpace(*p.HostID)
	}
	if p.Conditions != nil {
		sp.Conditions = *p.Conditions
		if sp.Conditions == nil {
			sp.Conditions = []store.SuppressionCondition{}
		}
	}
	if err := validateSuppressionScope(sp.RuleID, sp.HostID, sp.Conditions, p.ConfirmBroad || !scopeChanged); err != nil {
		return nil, err
	}
	if scopeChanged {
		sp.RuleTitle, sp.Hostname = c.State.SuppressionNames(ctx, sp.RuleID, sp.HostID)
	}
	if p.Reason != nil {
		reason := strings.TrimSpace(*p.Reason)
		if reason == "" {
			return nil, invalid("a suppression needs a reason")
		}
		if len(reason) > suppressionMaxReason {
			return nil, invalid("the reason is longer than %d characters", suppressionMaxReason)
		}
		sp.Reason = reason
	}
	switch {
	case p.NeverExpires != nil && *p.NeverExpires && p.ExpiresAt != nil:
		return nil, invalid("set either expires_at or never_expires, not both")
	case p.NeverExpires != nil && *p.NeverExpires:
		sp.ExpiresAt = nil
	case p.ExpiresAt != nil:
		if !p.ExpiresAt.After(time.Now()) {
			return nil, invalid("expires_at is in the past")
		}
		t := p.ExpiresAt.UTC()
		sp.ExpiresAt = &t
	}
	if p.Enabled != nil {
		sp.Enabled = *p.Enabled
	}
	if err := c.State.UpdateSuppression(ctx, sp); err != nil {
		return nil, err
	}
	c.Suppress.Invalidate()
	c.Audit(ctx, user, "suppression.update", sp.ID, describeSuppression(sp))
	return sp, nil
}

// DeleteSuppression removes a suppression.
func (c *Core) DeleteSuppression(ctx context.Context, id, user string) error {
	sp, err := c.State.GetSuppression(ctx, id)
	if err != nil {
		return err
	}
	if err := c.State.DeleteSuppression(ctx, id); err != nil {
		return err
	}
	c.Suppress.Invalidate()
	c.Audit(ctx, user, "suppression.delete", id, describeSuppression(sp))
	return nil
}

// SuppressionFileEntry is what the suppress-apply command did with one listed suppression.
type SuppressionFileEntry struct {
	Spec     SuppressionSpec
	ID       string // set unless this was a dry run of a new suppression
	Existing bool   // the same suppression was already there
	Matches  int
	Kept     int
	Closed   int
}

// SuppressionFileResult totals a suppress-apply run.
type SuppressionFileResult struct {
	Entries []SuppressionFileEntry
	Created int
	// Matches counts each matching open alert once, even if several suppressions match
	// it. Closed is what was actually closed, and stays 0 in a dry run.
	Matches int
	Closed  int
}

// ParseSuppressionFile reads a suppress-apply file: a list of suppressions, an object
// {"suppressions": [...]}, or one suppression.
func ParseSuppressionFile(data []byte) ([]SuppressionSpec, error) {
	trimmed := strings.TrimSpace(string(data))
	var specs []SuppressionSpec
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &specs); err != nil {
			return nil, err
		}
		return specs, nil
	}
	var wrapper struct {
		Suppressions *[]SuppressionSpec `json:"suppressions"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Suppressions != nil {
		return *wrapper.Suppressions, nil
	}
	var one SuppressionSpec
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, err
	}
	return []SuppressionSpec{one}, nil
}

// sameSuppression reports whether an existing suppression has the same scope.
func sameSuppression(a, b *store.Suppression) bool {
	return a.RuleID == b.RuleID && a.HostID == b.HostID && mustJSONString(a.Conditions) == mustJSONString(b.Conditions)
}

func mustJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ApplySuppressionSpecs creates the listed suppressions and closes the open alerts they
// match, or with dryRun only counts them and changes nothing. It checks every spec before
// it changes anything, and re-running it does not create duplicates.
func ApplySuppressionSpecs(ctx context.Context, st *store.Store, specs []SuppressionSpec, user string, dryRun bool) (*SuppressionFileResult, error) {
	if len(specs) == 0 {
		return nil, invalid("the file lists no suppressions")
	}
	now := time.Now().UTC()
	built := make([]*store.Suppression, len(specs))
	for i, spec := range specs {
		sp, err := spec.build(user, now)
		if err != nil {
			return nil, fmt.Errorf("suppression %d: %w", i+1, err)
		}
		built[i] = sp
	}
	existing, err := st.ListSuppressions(ctx)
	if err != nil {
		return nil, err
	}
	n, err := LoadNoiseSettings(ctx, st)
	if err != nil {
		return nil, err
	}
	must := mustSet(n)

	res := &SuppressionFileResult{}
	seen := map[string]bool{}
	for i, spec := range specs {
		sp := built[i]
		entry := SuppressionFileEntry{Spec: spec}
		for _, e := range existing {
			if e.Active(now) && sameSuppression(e, sp) {
				sp, entry.Existing, entry.ID = e, true, e.ID
				break
			}
		}
		p, err := previewSuppression(ctx, st, sp, must)
		if err != nil {
			return nil, err
		}
		entry.Matches, entry.Kept = p.Matches, p.Kept
		for _, id := range p.ids {
			if !seen[id] {
				seen[id] = true
				res.Matches++
			}
		}
		if !dryRun {
			if !entry.Existing {
				sp.RuleTitle, sp.Hostname = st.SuppressionNames(ctx, sp.RuleID, sp.HostID)
				if err := st.CreateSuppression(ctx, sp); err != nil {
					return nil, err
				}
				if err := st.Audit(ctx, user, "suppression.create", sp.ID, describeSuppression(sp)); err != nil {
					return nil, err
				}
				entry.ID = sp.ID
			}
			entry.Closed, err = closeSuppressed(ctx, st, sp, p, user)
			if err != nil {
				return nil, err
			}
			res.Closed += entry.Closed
			if err := st.Audit(ctx, user, "suppression.apply", sp.ID,
				fmt.Sprintf("closed %d open alerts, kept %d for must-alert", entry.Closed, entry.Kept)); err != nil {
				return nil, err
			}
		}
		if !entry.Existing {
			res.Created++
			existing = append(existing, sp) // a later duplicate in the same file reuses this one
		}
		res.Entries = append(res.Entries, entry)
	}
	return res, nil
}
