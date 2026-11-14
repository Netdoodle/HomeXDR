package triage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

type fakeOpenAI struct {
	t         *testing.T
	mu        sync.Mutex
	responses []func(w http.ResponseWriter) // in order
	requests  []map[string]any
	auth      []string
	paths     []string
}

func (f *fakeOpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if r.Method == http.MethodPost {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("bad body: %v", err)
		}
		f.requests = append(f.requests, body)
	}
	if len(f.responses) == 0 {
		w.WriteHeader(500)
		return
	}
	next := f.responses[0]
	f.responses = f.responses[1:]
	next(w)
}

func reply(finish, message string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"served-model","choices":[{"finish_reason":"`+finish+`","message":`+message+`}],`+
			`"usage":{"prompt_tokens":120,"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":20}}}`)
	}
}

func toolCall(id, name, args string) string {
	b, _ := json.Marshal(args)
	return `{"role":"assistant","content":null,"tool_calls":[{"id":"` + id + `","type":"function","function":{"name":"` + name + `","arguments":` + string(b) + `}}]}`
}

func runOpenAI(t *testing.T, f *fixture, fake *fakeOpenAI, providerID string) (*investigation, *openAIProvider, error) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	p := newOpenAICompatible(providerID, srv.URL+"/v1/", "sk-oa-test", "test-model")
	p.retryWait = func(int, string) time.Duration { return 0 }
	box := &toolbox{st: f.st, ev: f.ev, alert: f.alert}
	inv := &investigation{system: systemPrompt, initial: initialMessage(f.alert, []*event.Event{f.hit}), tools: box.tools(),
		box: box, maxToolCalls: 5, byName: map[string]Tool{}}
	for _, tl := range inv.tools {
		inv.byName[tl.Name] = tl
	}
	return inv, p, p.investigate(context.Background(), inv)
}

func TestOpenAILoop(t *testing.T) {
	f := newFixture(t)
	fake := &fakeOpenAI{t: t, responses: []func(http.ResponseWriter){
		func(w http.ResponseWriter) { w.Header().Set("Retry-After", "1"); w.WriteHeader(429) }, // retried
		reply("tool_calls", toolCall("c1", "get_process_tree", `{"host_id":"h1","entity_id":"e-curl"}`)),
		reply("stop", `{"role":"assistant","content":"Looks bad."}`), // no report: nudged
		reply("tool_calls", toolCall("c2", "submit_triage", submitInput)),
	}}
	inv, _, err := runOpenAI(t, f, fake, ProviderOpenAI)
	if err != nil {
		t.Fatal(err)
	}
	if inv.box.report == nil || inv.box.report.Verdict != "suspicious" || inv.servedBy != "served-model" {
		t.Fatalf("report %+v served by %q", inv.box.report, inv.servedBy)
	}
	if len(fake.requests) != 4 || fake.paths[0] != "POST /v1/chat/completions" || fake.auth[0] != "Bearer sk-oa-test" {
		t.Fatalf("requests %d, paths %v, auth %q", len(fake.requests), fake.paths, fake.auth[0])
	}
	first := fake.requests[1]
	if first["model"] != "test-model" || first["tool_choice"] != "auto" {
		t.Fatalf("model/tool_choice %v %v", first["model"], first["tool_choice"])
	}
	strict := map[string]bool{}
	for _, tl := range first["tools"].([]any) {
		fn := tl.(map[string]any)["function"].(map[string]any)
		strict[fn["name"].(string)] = fn["strict"] == true
		if fn["parameters"].(map[string]any)["additionalProperties"] != false {
			t.Fatalf("%v allows additional properties", fn["name"])
		}
	}
	if !strict["submit_triage"] || strict["search_events"] {
		t.Fatalf("strict flags %v", strict)
	}
	msgs1 := fake.requests[2]["messages"].([]any)
	msgs2 := fake.requests[3]["messages"].([]any)
	if len(msgs1) != 4 || len(msgs2) != 6 {
		t.Fatalf("history lengths %d, %d", len(msgs1), len(msgs2))
	}
	b1, _ := json.Marshal(msgs1)
	b2, _ := json.Marshal(msgs2[:4])
	if string(b1) != string(b2) {
		t.Fatal("history was rewritten")
	}
	toolMsg := msgs1[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "c1" || !strings.Contains(toolMsg["content"].(string), "e-bash") {
		t.Fatalf("tool message %v", toolMsg)
	}
	if inv.usage.InputTokens != 300 || inv.usage.CacheReadTokens != 60 || inv.usage.OutputTokens != 24 {
		t.Fatalf("usage %+v", inv.usage)
	}
}

func TestOpenAICompatibleVariants(t *testing.T) {
	f := newFixture(t)
	// Gemini/local servers get no strict flag (some reject unknown fields).
	fake := &fakeOpenAI{t: t, responses: []func(http.ResponseWriter){reply("tool_calls", toolCall("c", "submit_triage", submitInput))}}
	if _, _, err := runOpenAI(t, f, fake, ProviderLocal); err != nil {
		t.Fatal(err)
	}
	for _, tl := range fake.requests[0]["tools"].([]any) {
		if _, has := tl.(map[string]any)["function"].(map[string]any)["strict"]; has {
			t.Fatal("strict sent to a local server")
		}
	}
	// A refusal ends the run as refused.
	fake = &fakeOpenAI{t: t, responses: []func(http.ResponseWriter){reply("stop", `{"role":"assistant","content":null,"refusal":"I can't help with that."}`)}}
	inv, _, err := runOpenAI(t, f, fake, ProviderOpenAI)
	if err != nil || inv.refusal == "" {
		t.Fatalf("refusal %q, %v", inv.refusal, err)
	}
	// Errors are readable.
	fake = &fakeOpenAI{t: t, responses: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided"}}`)
	}}}
	if _, _, err := runOpenAI(t, f, fake, ProviderOpenAI); err == nil || !strings.Contains(err.Error(), "Incorrect API key") {
		t.Fatalf("401 error %v", err)
	}
	// Model listing strips Gemini's models/ prefix.
	fake = &fakeOpenAI{t: t, responses: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		io.WriteString(w, `{"object":"list","data":[{"id":"models/zeta"},{"id":"alpha"}]}`)
	}}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ids, err := newOpenAICompatible(ProviderGemini, srv.URL, "k", "").listModels(context.Background())
	if err != nil || strings.Join(ids, ",") != "alpha,zeta" || fake.paths[0] != "GET /models" {
		t.Fatalf("models %v %v %v", ids, err, fake.paths)
	}
}

func TestProviderSettings(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	// A Claude key stored by the previous version is migrated.
	if err := f.st.SetKV(ctx, SettingsKey, map[string]any{"enabled": true, "provider": "anthropic", "model": "claude-opus-5-5",
		"api_key": "sk-old-claude-key", "min_severity": "medium", "daily_limit": 5, "max_tool_calls": 5}); err != nil {
		t.Fatal(err)
	}
	set := f.svc.Settings(ctx)
	if set.APIKeys[ProviderAnthropic] != "sk-old-claude-key" || set.APIKey != "" {
		t.Fatalf("legacy key not migrated: %+v", set)
	}
	if ok, why := f.svc.Ready(set); !ok {
		t.Fatalf("not ready: %s", why)
	}
	// Local needs a base URL and a model, but no key.
	set.Provider, set.Model = ProviderLocal, ""
	if ok, why := f.svc.Ready(set); ok || why != "no base URL is set" {
		t.Fatalf("local without URL: %v %q", ok, why)
	}
	set.BaseURL = "http://192.168.20.20:11434/v1"
	if ok, why := f.svc.Ready(set); ok || why != "no model is set" {
		t.Fatalf("local without model: %v %q", ok, why)
	}
	set.Model = "qwen-test"
	if ok, why := f.svc.Ready(set); !ok {
		t.Fatalf("local ready: %q", why)
	}
	// OpenAI needs its own key, not Claude's.
	set.Provider, set.BaseURL = ProviderOpenAI, ""
	if ok, why := f.svc.Ready(set); ok || why != "no API key is set" {
		t.Fatalf("openai without key: %v %q", ok, why)
	}
	t.Setenv("HOMEXDR_OPENAI_API_KEY", "sk-env-openai")
	if key, src := f.svc.Key(set); key != "sk-env-openai" || src != "environment" {
		t.Fatalf("env key %q %q", key, src)
	}
	if set.EndpointURL() != "https://api.openai.com/v1" {
		t.Fatalf("endpoint %q", set.EndpointURL())
	}
	// An environment key is not sent to a custom base URL unless HOMEXDR_AI_BASE_URL
	// approves it.
	t.Setenv(EnvBaseURL, "")
	other := set
	other.BaseURL = "https://collector.example/v1"
	if key, _ := KeyFor(other, ProviderOpenAI); key != "" {
		t.Fatalf("env key sent to a custom base URL: %q", key)
	}
	if ok, why := f.svc.Ready(other); ok || !strings.Contains(why, EnvBaseURL) {
		t.Fatalf("held-back key: %v %q", ok, why)
	}
	if key, _ := KeyFor(Settings{Provider: ProviderOpenAI, BaseURL: "https://api.openai.com/v1/"}, ProviderOpenAI); key != "sk-env-openai" {
		t.Fatal("env key not used for the provider's own endpoint")
	}
	t.Setenv(EnvBaseURL, "https://collector.example/v1/")
	if key, src := KeyFor(other, ProviderOpenAI); key != "sk-env-openai" || src != "environment" {
		t.Fatalf("approved base URL: %q %q", key, src)
	}
	t.Setenv("HOMEXDR_ANTHROPIC_API_KEY", "sk-env-claude")
	if key, _ := KeyFor(Settings{Provider: ProviderAnthropic, BaseURL: "https://x.example"}, ProviderAnthropic); key != "sk-env-claude" {
		t.Fatal("Claude env key held back")
	}
	bad := set
	bad.BaseURL = "file:///etc/passwd"
	if err := bad.Validate(); err == nil {
		t.Fatal("non-http base URL accepted")
	}
	// The default provider is built from settings.
	p, err := defaultProvider(set, "k")
	if err != nil || p.name() != ProviderOpenAI || p.model() != "qwen-test" {
		t.Fatalf("provider %v %v", p, err)
	}
}
