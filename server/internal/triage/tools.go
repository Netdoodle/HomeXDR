package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Tool is one capability offered to the model. Every investigation tool only reads;
// the one exception is submit_triage, which records the AI's own report.
type Tool struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
	Strict      bool // schema-valid arguments guaranteed by the API
	Run         func(ctx context.Context, input json.RawMessage) (string, error)
}

const (
	maxToolOutput   = 16 << 10 // characters returned to the model per call
	maxStringField  = 400
	maxArrayItems   = 15
	maxSearchEvents = 50
	maxSearchRows   = 100 // table rows from a search pipeline
)

// toolbox builds the tools for one alert investigation.
type toolbox struct {
	st     *store.Store
	ev     events.Store
	alert  *store.Alert
	report *Report // set by submit_triage
}

func (b *toolbox) tools() []Tool {
	return []Tool{
		{
			Name: "search_events",
			Description: `Search stored telemetry (endpoint agents, OPNsense firewall logs, Suricata IDS alerts, syslog).
Use it to look at what else happened on the alert's host, who else talked to an IP or domain, or whether something is routine.
Query language: field:value or field=value (case-insensitive), field!=value, field:val* wildcards, field:"quoted value", field>N / field:>N comparisons, AND / OR / NOT, parentheses; bare words match message, command line and file path. An empty query returns the newest events.
Splunk-style commands can follow the filter with |, and then a table is returned instead of events: stats count, dc(f), sum(f), avg(f), min(f), max(f), values(f) [as name] [by f, ...]; top [limit=N] f; rare f; table f, ...; sort [-]f; head N; dedup f; where <expression>; eval name=<expression>; rex field=f "(?<name>regex)". Example: destination.ip:203.0.113.7 | stats count, dc(host.name) as hosts by event.module.
Useful fields: host.name, host.id, event.category (process, network, file, authentication, dns, registry), event.action, event.outcome, event.module (opnsense, suricata, procconn, fanotify, ...), process.name, process.command_line, process.entity_id, process.parent.name, user.name, file.path, source.ip, destination.ip, destination.port, destination.domain, dns.question.name, network.community_id.
The time window defaults to 24 hours before the alert's first hit until now. Results are newest first and trimmed.`,
			Properties: map[string]any{
				"query":   map[string]any{"type": "string", "description": "Query in the language above, e.g. process.name:curl AND destination.port:443"},
				"host_id": map[string]any{"type": "string", "description": "Only events from this host (agent ID). Omit to search every host."},
				"from":    map[string]any{"type": "string", "description": "Window start, RFC 3339. Default: 24 hours before the alert's first hit."},
				"to":      map[string]any{"type": "string", "description": "Window end, RFC 3339. Default: now."},
				"limit":   map[string]any{"type": "integer", "description": "Events to return, 1-50. Default 20."},
			},
			Required: []string{"query"},
			Run:      b.searchEvents,
		},
		{
			Name:        "get_event",
			Description: "Return one stored event in full (long values trimmed). Use it when a search result needs a closer look.",
			Properties: map[string]any{
				"event_id": map[string]any{"type": "string", "description": "The event's id field."},
			},
			Required: []string{"event_id"},
			Run:      b.getEvent,
		},
		{
			Name:        "get_process_tree",
			Description: "Return a process's lineage on an endpoint: the process itself, its ancestors up to the root, and its children and grandchildren. Use it to see what started a suspicious process and what it ran.",
			Properties: map[string]any{
				"host_id":   map[string]any{"type": "string", "description": "Host (agent ID) the process ran on."},
				"entity_id": map[string]any{"type": "string", "description": "The process.entity_id of the process."},
			},
			Required: []string{"host_id", "entity_id"},
			Run:      b.processTree,
		},
		{
			Name:        "get_host",
			Description: "Return a host's details: OS, IPs, labels, status, agent version, sensors and open alert count.",
			Properties: map[string]any{
				"host_id": map[string]any{"type": "string", "description": "Host (agent ID)."},
			},
			Required: []string{"host_id"},
			Run:      b.getHost,
		},
		{
			Name:        "list_alerts",
			Description: "List recent alerts, optionally for one host, to see whether this alert is part of a pattern or a repeat of something already triaged.",
			Properties: map[string]any{
				"host_id": map[string]any{"type": "string", "description": "Only alerts on this host. Omit for all hosts."},
				"hours":   map[string]any{"type": "integer", "description": "How far back, in hours, 1-720. Default 72."},
				"limit":   map[string]any{"type": "integer", "description": "Alerts to return, 1-50. Default 20."},
			},
			Run: b.listAlerts,
		},
		{
			Name:        "get_network_flow",
			Description: "Return every event about one network flow, joined by its Community ID: the endpoint's connection event, OPNsense firewall log lines and Suricata alerts for the same 5-tuple.",
			Properties: map[string]any{
				"community_id": map[string]any{"type": "string", "description": "The network.community_id value, e.g. 1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
			},
			Required: []string{"community_id"},
			Run:      b.networkFlow,
		},
		{
			Name: "submit_triage",
			Description: `Submit your triage report. Call this exactly once, when you have finished investigating; it ends the investigation.
Cite event IDs you saw in tool results as evidence. Recommendations are for the human analyst; you cannot take any action yourself.`,
			Properties: reportSchema,
			Required: []string{"verdict", "confidence", "severity_assessment", "summary", "analysis", "evidence",
				"mitre", "recommended_actions", "open_questions"},
			Strict: true,
			Run:    b.submit,
		},
	}
}

func obj(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
}

var reportSchema = map[string]any{
	"verdict": map[string]any{"type": "string", "enum": []string{"benign", "suspicious", "malicious", "inconclusive"},
		"description": "benign: expected activity; suspicious: needs a human to look; malicious: likely an attack; inconclusive: not enough data."},
	"confidence":          map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
	"severity_assessment": map[string]any{"type": "string", "enum": []string{"informational", "low", "medium", "high", "critical"}, "description": "Your view of the real severity. It is recorded with the report and does not change the alert."},
	"summary":             map[string]any{"type": "string", "description": "Two to four sentences for the analyst's alert list."},
	"analysis":            map[string]any{"type": "string", "description": "Your reasoning: what happened, what you checked, and why you reached the verdict. Plain text."},
	"evidence": map[string]any{"type": "array", "items": obj(map[string]any{
		"event_id":    map[string]any{"type": "string"},
		"observation": map[string]any{"type": "string"},
	}, "event_id", "observation")},
	"mitre": map[string]any{"type": "array", "items": obj(map[string]any{
		"technique_id": map[string]any{"type": "string", "description": "e.g. T1059.001"},
		"name":         map[string]any{"type": "string"},
	}, "technique_id", "name")},
	"recommended_actions": map[string]any{"type": "array", "items": obj(map[string]any{
		"action": map[string]any{"type": "string", "description": "What the analyst should do, e.g. isolate the host, kill a process, reset a password, close as a false positive, tune the rule."},
		"reason": map[string]any{"type": "string"},
	}, "action", "reason")},
	"open_questions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "What you could not determine from the data."},
}

// Report is the AI analyst's structured result (the submit_triage input).
type Report struct {
	Verdict            string      `json:"verdict"`
	Confidence         string      `json:"confidence"`
	SeverityAssessment string      `json:"severity_assessment"`
	Summary            string      `json:"summary"`
	Analysis           string      `json:"analysis"`
	Evidence           []Evidence  `json:"evidence"`
	Mitre              []Technique `json:"mitre"`
	RecommendedActions []Action    `json:"recommended_actions"`
	OpenQuestions      []string    `json:"open_questions"`
}

// Evidence cites an event.
type Evidence struct {
	EventID     string `json:"event_id"`
	Observation string `json:"observation"`
}

// Technique is a MITRE ATT&CK technique.
type Technique struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
}

// Action is a recommendation for the analyst.
type Action struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func (b *toolbox) submit(_ context.Context, in json.RawMessage) (string, error) {
	var r Report
	if err := json.Unmarshal(in, &r); err != nil {
		return "", fmt.Errorf("invalid report: %v", err)
	}
	switch {
	case !oneOf(r.Verdict, "benign", "suspicious", "malicious", "inconclusive"):
		return "", fmt.Errorf("verdict must be benign, suspicious, malicious or inconclusive")
	case !oneOf(r.Confidence, "low", "medium", "high"):
		return "", fmt.Errorf("confidence must be low, medium or high")
	case !oneOf(r.SeverityAssessment, store.SevInformational, store.SevLow, store.SevMedium, store.SevHigh, store.SevCritical):
		return "", fmt.Errorf("severity_assessment must be a severity level")
	case strings.TrimSpace(r.Summary) == "":
		return "", errors.New("summary is empty")
	}
	b.report = &r
	return "Report recorded. The investigation is complete.", nil
}

// --- helpers ---

// compact prepares an event (or any JSON value) for the model: long strings are cut,
// long arrays shortened and the raw original dropped.
func compact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if k == "original" {
				continue
			}
			out[k] = compact(val)
		}
		return out
	case []any:
		n := len(x)
		if n > maxArrayItems {
			x = x[:maxArrayItems]
		}
		out := make([]any, 0, len(x)+1)
		for _, val := range x {
			out = append(out, compact(val))
		}
		if n > maxArrayItems {
			out = append(out, fmt.Sprintf("... %d more", n-maxArrayItems))
		}
		return out
	case string:
		if len(x) > maxStringField {
			return x[:maxStringField] + "... (truncated)"
		}
		return x
	}
	return v
}

func eventMap(e *event.Event) any {
	b, err := json.Marshal(e)
	if err != nil {
		return map[string]any{"id": e.ID}
	}
	var m any
	_ = json.Unmarshal(b, &m)
	return compact(m)
}

// render marshals a tool result, dropping list items until it fits.
func render(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(b) <= maxToolOutput {
		return string(b), nil
	}
	if m, ok := v.(map[string]any); ok {
		for _, key := range []string{"events", "rows", "alerts", "children"} {
			list, ok := m[key].([]any)
			for ok && len(list) > 1 && len(b) > maxToolOutput {
				list = list[:len(list)*2/3]
				m[key] = list
				m["trimmed"] = "result shortened to fit; narrow the query for more"
				if b, err = json.Marshal(m); err != nil {
					return "", err
				}
			}
		}
	}
	if len(b) > maxToolOutput {
		return string(b[:maxToolOutput]) + "... (truncated)", nil
	}
	return string(b), nil
}

func clampInt(v, def, lo, hi int) int {
	if v == 0 {
		v = def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// --- tools ---

func (b *toolbox) searchEvents(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		Query  string `json:"query"`
		HostID string `json:"host_id"`
		From   string `json:"from"`
		To     string `json:"to"`
		Limit  int    `json:"limit"`
	}
	if err := json.Unmarshal(in, &p); err != nil {
		return "", fmt.Errorf("invalid input: %v", err)
	}
	from := b.alert.FirstSeen.Add(-24 * time.Hour)
	to := time.Now()
	if p.From != "" {
		t, err := time.Parse(time.RFC3339, p.From)
		if err != nil {
			return "", fmt.Errorf("from must be RFC 3339: %v", err)
		}
		from = t
	}
	if p.To != "" {
		t, err := time.Parse(time.RFC3339, p.To)
		if err != nil {
			return "", fmt.Errorf("to must be RFC 3339: %v", err)
		}
		to = t
	}
	res, err := b.ev.Search(ctx, events.SearchQuery{
		Query: p.Query, From: from, To: to, HostID: p.HostID, Limit: clampInt(p.Limit, 20, 1, maxSearchEvents),
	})
	if err != nil {
		return "", err
	}
	window := map[string]string{"from": from.UTC().Format(time.RFC3339), "to": to.UTC().Format(time.RFC3339)}
	if res.Mode == "table" {
		rows := make([]any, 0, min(len(res.Rows), maxSearchRows))
		for _, r := range res.Rows[:min(len(res.Rows), maxSearchRows)] {
			rows = append(rows, r)
		}
		names := make([]string, len(res.Columns))
		for i, c := range res.Columns {
			names[i] = c.Name
		}
		out := map[string]any{"columns": names, "rows": rows, "total_rows": res.Total, "window": window}
		if len(res.Rows) > maxSearchRows || res.Truncated {
			out["trimmed"] = "more rows than returned; sort or filter to see the rest"
		}
		return render(out)
	}
	list := make([]any, len(res.Events))
	for i, e := range res.Events {
		list[i] = eventMap(e)
	}
	return render(map[string]any{
		"total_matching": res.Total, "returned": len(list),
		"window": window,
		"events": list,
	})
}

func (b *toolbox) getEvent(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(in, &p); err != nil || p.EventID == "" {
		return "", errors.New("event_id is required")
	}
	e, err := b.ev.Get(ctx, p.EventID)
	if errors.Is(err, events.ErrNotFound) {
		return "", fmt.Errorf("no event with id %q", p.EventID)
	}
	if err != nil {
		return "", err
	}
	return render(eventMap(e))
}

type procInfo struct {
	EntityID    string     `json:"entity_id"`
	PID         int64      `json:"pid,omitempty"`
	Name        string     `json:"name,omitempty"`
	Executable  string     `json:"executable,omitempty"`
	CommandLine string     `json:"command_line,omitempty"`
	User        string     `json:"user,omitempty"`
	Start       *time.Time `json:"start,omitempty"`
	ParentID    string     `json:"parent_entity_id,omitempty"`
	Children    []any      `json:"children,omitempty"`
}

func procFrom(e *event.Event) *procInfo {
	p := e.Process
	info := &procInfo{EntityID: p.EntityID, PID: p.PID, Name: p.Name, Executable: p.Executable,
		CommandLine: compact(p.CommandLine).(string)}
	if p.User != nil {
		info.User = p.User.Name
	}
	if p.Parent != nil {
		info.ParentID = p.Parent.EntityID
	}
	t := e.Timestamp
	info.Start = &t
	return info
}

// processesByID loads start events for entity IDs.
func (b *toolbox) processesByID(ctx context.Context, hostID string, ids []string) (map[string]*procInfo, error) {
	evs, err := b.ev.ProcessEvents(ctx, hostID, ids)
	if err != nil {
		return nil, err
	}
	out := map[string]*procInfo{}
	for _, e := range evs {
		if e.Process == nil || e.Process.EntityID == "" {
			continue
		}
		if _, seen := out[e.Process.EntityID]; !seen || hasType(e, event.TypeStart) {
			out[e.Process.EntityID] = procFrom(e)
		}
	}
	return out, nil
}

func hasType(e *event.Event, t string) bool {
	for _, v := range e.Event.Type {
		if v == t {
			return true
		}
	}
	return false
}

func (b *toolbox) processTree(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		HostID   string `json:"host_id"`
		EntityID string `json:"entity_id"`
	}
	if err := json.Unmarshal(in, &p); err != nil || p.HostID == "" || p.EntityID == "" {
		return "", errors.New("host_id and entity_id are required")
	}
	procs, err := b.processesByID(ctx, p.HostID, []string{p.EntityID})
	if err != nil {
		return "", err
	}
	target, ok := procs[p.EntityID]
	if !ok {
		return "", fmt.Errorf("no process %s on host %s in the stored events", p.EntityID, p.HostID)
	}
	var ancestors []any
	for cur, depth := target, 0; cur.ParentID != "" && depth < 10; depth++ {
		m, err := b.processesByID(ctx, p.HostID, []string{cur.ParentID})
		if err != nil {
			return "", err
		}
		parent, ok := m[cur.ParentID]
		if !ok {
			ancestors = append(ancestors, map[string]string{"entity_id": cur.ParentID, "note": "not in stored events"})
			break
		}
		ancestors = append(ancestors, parent)
		cur = parent
	}
	children, err := b.ev.Children(ctx, p.HostID, []string{p.EntityID}, 40)
	if err != nil {
		return "", err
	}
	var kids []any
	for _, c := range children {
		if c.Process == nil {
			continue
		}
		kid := procFrom(c)
		grand, err := b.ev.Children(ctx, p.HostID, []string{kid.EntityID}, 10)
		if err == nil {
			for _, g := range grand {
				if g.Process != nil {
					kid.Children = append(kid.Children, procFrom(g))
				}
			}
		}
		kids = append(kids, kid)
	}
	return render(map[string]any{"process": target, "ancestors": ancestors, "children": kids})
}

func (b *toolbox) getHost(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		HostID string `json:"host_id"`
	}
	if err := json.Unmarshal(in, &p); err != nil || p.HostID == "" {
		return "", errors.New("host_id is required")
	}
	h, err := b.st.GetHost(ctx, p.HostID)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("no host %q", p.HostID)
	}
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(h)
	var m any
	_ = json.Unmarshal(raw, &m)
	return render(compact(m))
}

func (b *toolbox) listAlerts(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		HostID string `json:"host_id"`
		Hours  int    `json:"hours"`
		Limit  int    `json:"limit"`
	}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &p); err != nil {
			return "", fmt.Errorf("invalid input: %v", err)
		}
	}
	since := time.Now().Add(-time.Duration(clampInt(p.Hours, 72, 1, 720)) * time.Hour)
	alerts, total, err := b.st.ListAlerts(ctx, store.AlertFilter{HostID: p.HostID, Since: &since, Limit: clampInt(p.Limit, 20, 1, 50)})
	if err != nil {
		return "", err
	}
	list := make([]any, 0, len(alerts))
	for _, a := range alerts {
		item := map[string]any{
			"id": a.ID, "rule": a.Rule.Title, "severity": a.Severity, "status": a.Status, "count": a.Count,
			"host_id": a.HostID, "hostname": a.Hostname, "first_seen": a.FirstSeen, "last_seen": a.LastSeen,
			"process": a.ProcessName, "command_line": compact(a.CommandLine), "user": a.User,
		}
		if a.AITriage != nil && a.AITriage.Verdict != "" {
			item["ai_verdict"] = a.AITriage.Verdict
		}
		if a.ID == b.alert.ID {
			item["note"] = "this is the alert under investigation"
		}
		list = append(list, item)
	}
	return render(map[string]any{"total_matching": total, "alerts": list})
}

func (b *toolbox) networkFlow(ctx context.Context, in json.RawMessage) (string, error) {
	var p struct {
		CommunityID string `json:"community_id"`
	}
	if err := json.Unmarshal(in, &p); err != nil || strings.TrimSpace(p.CommunityID) == "" {
		return "", errors.New("community_id is required")
	}
	q := `network.community_id:"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p.CommunityID) + `"`
	res, err := b.ev.Search(ctx, events.SearchQuery{
		Query: q, From: b.alert.FirstSeen.Add(-7 * 24 * time.Hour), To: time.Now(), Limit: 30, Asc: true,
	})
	if err != nil {
		return "", err
	}
	list := make([]any, len(res.Events))
	for i, e := range res.Events {
		list[i] = eventMap(e)
	}
	return render(map[string]any{"total_matching": res.Total, "events": list})
}
