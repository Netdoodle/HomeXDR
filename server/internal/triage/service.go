// Package triage is HomeXDR's AI analyst. When an alert at or above a chosen severity
// is created, it asks an AI model to investigate it with read-only tools and stores the
// model's triage report next to the alert. The AI annotates only: it cannot change
// alerts, hosts, rules or settings, and cannot run response actions.
package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Provider IDs.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
	ProviderLocal     = "local"
)

// Trigger kinds.
const (
	TriggerAuto   = "auto"
	TriggerManual = "manual"
)

// ProviderInfo describes a provider for the settings page.
type ProviderInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Available      bool   `json:"available"`
	DefaultBaseURL string `json:"default_base_url,omitempty"` // OpenAI-compatible endpoint
	NeedsKey       bool   `json:"needs_key"`
	NeedsBaseURL   bool   `json:"needs_base_url"`
	KeyEnv         string `json:"key_env"` // environment variable that overrides the stored key
}

// Providers lists the AI services. All but Claude speak the OpenAI-compatible Chat
// Completions API; Gemini through Google's compatibility endpoint.
var Providers = []ProviderInfo{
	{ID: ProviderAnthropic, Name: "Claude (Anthropic)", Available: true, NeedsKey: true, KeyEnv: EnvAnthropicKey},
	{ID: ProviderOpenAI, Name: "OpenAI (ChatGPT)", Available: true, NeedsKey: true, KeyEnv: "HOMEXDR_OPENAI_API_KEY",
		DefaultBaseURL: "https://api.openai.com/v1"},
	{ID: ProviderGemini, Name: "Google Gemini", Available: true, NeedsKey: true, KeyEnv: "HOMEXDR_GEMINI_API_KEY",
		DefaultBaseURL: "https://generativelanguage.googleapis.com/v1beta/openai"},
	{ID: ProviderLocal, Name: "Local model", Available: true, NeedsBaseURL: true, KeyEnv: "HOMEXDR_LOCAL_AI_API_KEY"},
}

func providerInfo(id string) (ProviderInfo, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return ProviderInfo{}, false
}

// DefaultModel is the default Claude model. Other providers have no default: their
// model names change often, so the admin picks one (the console can list them).
const DefaultModel = "claude-opus-5-5"

// EnvAnthropicKey, when set, provides the Claude API key instead of the settings.
const EnvAnthropicKey = "HOMEXDR_ANTHROPIC_API_KEY"

const settingsKey = "ai_triage_settings"

// Settings configure the AI analyst. API keys are write-only through the console API.
type Settings struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// APIKey is the key for the selected provider in console requests. In storage it is
	// folded into APIKeys (an older version stored the Claude key here).
	APIKey  string            `json:"api_key,omitempty"`
	APIKeys map[string]string `json:"api_keys,omitempty"` // per provider
	// BaseURL overrides the provider's OpenAI-compatible endpoint (required for local).
	BaseURL      string `json:"base_url,omitempty"`
	MinSeverity  string `json:"min_severity"` // informational | low | medium | high | critical
	DailyLimit   int    `json:"daily_limit"`  // automatic investigations per day
	MaxToolCalls int    `json:"max_tool_calls"`
	// Engine runs investigations: "api" (the server, through Provider) or "mcp" (an
	// MCP client such as Claude Code claims them with next_investigation).
	Engine string `json:"engine"`
	// MCPEnabled turns on the /mcp endpoint for MCP access tokens.
	MCPEnabled bool `json:"mcp_enabled"`
	// MCPAutoTrigger queues new alerts for MCP investigation (engine "mcp"); the MCP
	// runner starts Claude Code for them. Off: MCP investigations run only on request.
	MCPAutoTrigger bool `json:"mcp_auto_trigger"`
}

// normalize folds a request's (or legacy) APIKey into APIKeys for the selected provider.
func (s *Settings) normalize() {
	if s.APIKeys == nil {
		s.APIKeys = map[string]string{}
	}
	if k := strings.TrimSpace(s.APIKey); k != "" {
		s.APIKeys[s.Provider] = k
	}
	s.APIKey = ""
	for id, k := range s.APIKeys {
		if strings.TrimSpace(k) == "" {
			delete(s.APIKeys, id)
		}
	}
}

// EndpointURL returns the OpenAI-compatible base URL in effect for the provider.
func (s Settings) EndpointURL() string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	info, _ := providerInfo(s.Provider)
	return info.DefaultBaseURL
}

// DefaultSettings: on (it does nothing until an API key is set), Claude, medium and above.
func DefaultSettings() Settings {
	return Settings{Enabled: true, Provider: ProviderAnthropic, Model: DefaultModel, MinSeverity: store.SevMedium,
		DailyLimit: 50, MaxToolCalls: 20, Engine: store.EngineAPI}
}

func severityRank(s string) int {
	switch s {
	case store.SevCritical:
		return 4
	case store.SevHigh:
		return 3
	case store.SevMedium:
		return 2
	case store.SevLow:
		return 1
	case store.SevInformational:
		return 0
	}
	return -1
}

// Validate checks and normalizes settings.
func (s *Settings) Validate() error {
	s.Model = strings.TrimSpace(s.Model)
	s.BaseURL = strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	switch {
	case s.Provider == "":
		s.Provider = ProviderAnthropic
	case !knownProvider(s.Provider):
		return fmt.Errorf("unknown provider %q", s.Provider)
	}
	s.normalize()
	switch s.Engine {
	case "":
		s.Engine = store.EngineAPI
	case store.EngineAPI, store.EngineMCP:
	default:
		return fmt.Errorf("engine must be api or mcp")
	}
	if s.Model == "" && s.Provider == ProviderAnthropic {
		s.Model = DefaultModel
	}
	if s.BaseURL != "" {
		u, err := url.Parse(s.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("base_url must be an http(s) URL such as http://192.168.20.20:11434/v1")
		}
	}
	for _, r := range s.Model {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._:/@", r)) {
			return fmt.Errorf("model name contains %q", r)
		}
	}
	if severityRank(s.MinSeverity) < 0 {
		return fmt.Errorf("min_severity must be informational, low, medium, high or critical")
	}
	if s.DailyLimit < 1 || s.DailyLimit > 10000 {
		return fmt.Errorf("daily_limit must be between 1 and 10000")
	}
	if s.MaxToolCalls < 1 || s.MaxToolCalls > 50 {
		return fmt.Errorf("max_tool_calls must be between 1 and 50")
	}
	return nil
}

func knownProvider(id string) bool {
	for _, p := range Providers {
		if p.ID == id {
			return true
		}
	}
	return false
}

// provider runs investigations with one AI service.
type provider interface {
	name() string
	model() string
	investigate(ctx context.Context, inv *investigation) error
	test(ctx context.Context) (string, error)
}

// ToolCall is one entry of an investigation's transcript (stored for transparency).
type ToolCall struct {
	Tool   string          `json:"tool"`
	Input  json.RawMessage `json:"input"`
	Output string          `json:"output"` // preview
	Error  bool            `json:"error,omitempty"`
	At     time.Time       `json:"at"`
	Ms     int64           `json:"ms"`
}

const transcriptPreview = 600

// investigation is the provider-independent state of one run.
type investigation struct {
	system, initial string
	tools           []Tool
	byName          map[string]Tool
	box             *toolbox
	maxToolCalls    int
	toolCalls       int
	transcript      []ToolCall
	usage           store.TriageUsage
	refusal         string // set when the model declined
	servedBy        string // model that produced the last response
}

// call runs a tool requested by the model. Errors go back to the model as tool errors.
func (inv *investigation) call(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	t, ok := inv.byName[name]
	if !ok {
		return fmt.Sprintf("unknown tool %q", name), true
	}
	if name != "submit_triage" {
		if inv.toolCalls >= inv.maxToolCalls {
			return "Tool budget used up. Call submit_triage now with what you have.", true
		}
		inv.toolCalls++
	}
	start := time.Now()
	out, err := t.Run(ctx, input)
	isErr := err != nil
	if isErr {
		out = "Error: " + err.Error()
	}
	preview := out
	if len(preview) > transcriptPreview {
		preview = preview[:transcriptPreview] + "..."
	}
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	inv.transcript = append(inv.transcript, ToolCall{Tool: name, Input: input, Output: preview, Error: isErr,
		At: start.UTC(), Ms: time.Since(start).Milliseconds()})
	return out, isErr
}

// Service queues and runs investigations.
type Service struct {
	st  *store.Store
	ev  events.Store
	log *slog.Logger

	wake chan struct{}
	// newProvider builds the provider for settings (replaced in tests).
	newProvider func(s Settings, key string) (provider, error)
	// lookup asks threat intelligence services about an indicator (nil: no such tool).
	lookup func(ctx context.Context, indicator string) (string, error)

	mu      sync.Mutex
	running string // alert being investigated

	mcpMu       sync.Mutex
	mcpSessions map[string]*mcpSession // by MCP token ID
	runnerName  string                 // last MCP runner that checked in
	runnerSeen  time.Time
}

// SetIndicatorLookup offers the analyst a tool that looks up indicators in threat
// intelligence services.
func (s *Service) SetIndicatorLookup(fn func(ctx context.Context, indicator string) (string, error)) {
	s.lookup = fn
}

// New returns a service. Call Run to start the worker.
func New(st *store.Store, ev events.Store, log *slog.Logger) *Service {
	return &Service{st: st, ev: ev, log: log, wake: make(chan struct{}, 1), newProvider: defaultProvider,
		mcpSessions: map[string]*mcpSession{}}
}

func defaultProvider(s Settings, key string) (provider, error) {
	switch s.Provider {
	case ProviderAnthropic:
		return newClaude(key, s.Model), nil
	case ProviderOpenAI, ProviderGemini, ProviderLocal:
		if s.EndpointURL() == "" {
			return nil, errors.New("no base URL is set")
		}
		return newOpenAICompatible(s.Provider, s.EndpointURL(), key, s.Model), nil
	}
	return nil, fmt.Errorf("unknown provider %q", s.Provider)
}

// Settings returns the stored settings (defaults when none are stored).
func (s *Service) Settings(ctx context.Context) Settings {
	set := DefaultSettings()
	if err := s.st.GetKV(ctx, settingsKey, &set); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("ai triage: read settings", "err", err)
	}
	if set.Engine == "" { // stored by a version without engines
		set.Engine = store.EngineAPI
	}
	if set.APIKey != "" { // stored by an older version: it was the Claude key
		if set.APIKeys == nil {
			set.APIKeys = map[string]string{}
		}
		if set.APIKeys[ProviderAnthropic] == "" {
			set.APIKeys[ProviderAnthropic] = set.APIKey
		}
		set.APIKey = ""
	}
	return set
}

// SaveSettings validates and stores settings.
func (s *Service) SaveSettings(ctx context.Context, set Settings) (Settings, error) {
	if err := set.Validate(); err != nil {
		return set, err
	}
	return set, s.st.SetKV(ctx, settingsKey, set)
}

// Key returns the API key in effect and where it comes from ("environment",
// "settings" or "").
func (s *Service) Key(set Settings) (key, source string) {
	return KeyFor(set, set.Provider)
}

// KeyFor returns a provider's API key in effect and its source.
func KeyFor(set Settings, providerID string) (key, source string) {
	if info, ok := providerInfo(providerID); ok && info.KeyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(info.KeyEnv)); v != "" {
			return v, "environment"
		}
	}
	if k := set.APIKeys[providerID]; k != "" {
		return k, "settings"
	}
	if providerID == set.Provider && set.APIKey != "" {
		return set.APIKey, "settings"
	}
	return "", ""
}

// Ready reports whether investigations can run with the selected engine, and if not, why.
func (s *Service) Ready(set Settings) (bool, string) {
	if !set.Enabled {
		return false, "the AI analyst is turned off"
	}
	if set.Engine == store.EngineMCP {
		if !set.MCPEnabled {
			return false, "MCP access is turned off"
		}
		return true, ""
	}
	info, known := providerInfo(set.Provider)
	key, _ := s.Key(set)
	switch {
	case !known || !info.Available:
		return false, "the selected provider is not available"
	case info.NeedsKey && key == "":
		return false, "no API key is set"
	case set.Provider != ProviderAnthropic && set.EndpointURL() == "":
		return false, "no base URL is set"
	case set.Model == "":
		return false, "no model is set"
	}
	return true, ""
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// AutoToday counts today's automatic investigations.
func (s *Service) AutoToday(ctx context.Context) int {
	n, _ := s.st.CountTriages(ctx, TriggerAuto, startOfDay(time.Now()))
	return n
}

// AlertCreated queues an automatic investigation of a new alert when the settings
// call for one.
func (s *Service) AlertCreated(ctx context.Context, a *store.Alert) {
	set := s.Settings(ctx)
	if ok, _ := s.Ready(set); !ok || severityRank(a.Severity) < severityRank(set.MinSeverity) {
		return
	}
	if set.Engine == store.EngineMCP && !set.MCPAutoTrigger {
		return // MCP investigations run on request only
	}
	if s.AutoToday(ctx) >= set.DailyLimit {
		if _, err := s.st.SkipTriage(ctx, a.ID, TriggerAuto, set.Engine, fmt.Sprintf("daily limit of %d automatic investigations reached", set.DailyLimit)); err != nil {
			s.log.Warn("ai triage: record skip", "alert", a.ID, "err", err)
		}
		return
	}
	if _, err := s.st.QueueTriage(ctx, a.ID, TriggerAuto, "", set.Engine); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			s.log.Warn("ai triage: queue", "alert", a.ID, "err", err)
		}
		return
	}
	s.poke()
}

// ErrNotReady is returned by Request when the analyst cannot run.
var ErrNotReady = errors.New("AI analyst not ready")

// Request queues a manual investigation (or re-investigation) of an alert.
func (s *Service) Request(ctx context.Context, alertID, user string) (*store.Triage, error) {
	set := s.Settings(ctx)
	if ok, why := s.Ready(set); !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotReady, why)
	}
	if _, err := s.st.GetAlert(ctx, alertID); err != nil {
		return nil, err
	}
	t, err := s.st.QueueTriage(ctx, alertID, TriggerManual, user, set.Engine)
	if err != nil {
		return nil, err
	}
	s.poke()
	return t, nil
}

// Test checks settings by making a minimal request.
func (s *Service) Test(ctx context.Context, set Settings) (string, error) {
	if err := set.Validate(); err != nil {
		return "", err
	}
	if set.Model == "" {
		return "", errors.New("no model is set")
	}
	p, err := s.providerFor(set)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return p.test(ctx)
}

// providerFor builds the provider for (validated) settings.
func (s *Service) providerFor(set Settings) (provider, error) {
	info, _ := providerInfo(set.Provider)
	key, _ := s.Key(set)
	if info.NeedsKey && key == "" {
		return nil, errors.New("no API key is set")
	}
	return s.newProvider(set, key)
}

// modelLister is implemented by providers that can list their models.
type modelLister interface {
	listModels(ctx context.Context) ([]string, error)
}

// ListModels asks the provider which models it offers.
func (s *Service) ListModels(ctx context.Context, set Settings) ([]string, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	p, err := s.providerFor(set)
	if err != nil {
		return nil, err
	}
	l, ok := p.(modelLister)
	if !ok {
		return nil, errors.New("this provider cannot list its models")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return l.listModels(ctx)
}

func (s *Service) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run processes the queue until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if n, err := s.st.RequeueRunningTriages(ctx); err != nil {
		s.log.Warn("ai triage: requeue", "err", err)
	} else if n > 0 {
		s.log.Info("ai triage: resumed interrupted investigations", "count", n)
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		for ctx.Err() == nil {
			t, err := s.st.ClaimTriage(ctx, store.EngineAPI)
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			if err != nil {
				s.log.Warn("ai triage: claim", "err", err)
				break
			}
			s.process(ctx, t)
		}
		if n, err := s.st.FailStaleTriages(ctx, store.EngineMCP, time.Now().Add(-mcpTimeout),
			"the MCP client did not submit a report within "+mcpTimeout.String()); err == nil && n > 0 {
			s.log.Warn("ai triage: MCP investigations timed out", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-tick.C:
		}
	}
}

// investigationTimeout bounds one investigation.
const investigationTimeout = 10 * time.Minute

func (s *Service) process(ctx context.Context, t *store.Triage) {
	s.mu.Lock()
	s.running = t.AlertID
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = ""
		s.mu.Unlock()
	}()
	start := time.Now()
	err := s.investigate(ctx, t)
	if err != nil {
		t.Status, t.Error = store.TriageFailed, err.Error()
		if ctx.Err() != nil {
			return // shutting down: leave it running, it is requeued on start
		}
	}
	if ferr := s.st.FinishTriage(context.WithoutCancel(ctx), t); ferr != nil {
		s.log.Error("ai triage: store result", "alert", t.AlertID, "err", ferr)
		return
	}
	s.log.Info("ai triage finished", "alert", t.AlertID, "status", t.Status, "verdict", t.Verdict,
		"model", t.Model, "tool_calls", t.ToolCalls, "seconds", int(time.Since(start).Seconds()), "err", t.Error)
	details := fmt.Sprintf("%s: %s", t.Status, t.Verdict)
	if t.Error != "" {
		details = t.Status + ": " + t.Error
	}
	_ = s.st.Audit(context.WithoutCancel(ctx), "ai", "ai.triage", t.AlertID, details)
}

func (s *Service) investigate(ctx context.Context, t *store.Triage) error {
	set := s.Settings(ctx)
	if ok, why := s.Ready(set); !ok {
		return errors.New(why)
	}
	key, _ := s.Key(set)
	p, err := s.newProvider(set, key)
	if err != nil {
		return err
	}
	t.Provider, t.Model = p.name(), p.model()
	alert, err := s.st.GetAlert(ctx, t.AlertID)
	if err != nil {
		return fmt.Errorf("load alert: %w", err)
	}
	evs, err := s.ev.GetMany(ctx, firstN(alert.EventIDs, 5))
	if err != nil {
		return fmt.Errorf("load alert events: %w", err)
	}
	box := &toolbox{st: s.st, ev: s.ev, alert: alert, lookup: s.lookup}
	inv := &investigation{
		system: systemPrompt, initial: initialMessage(alert, evs), tools: box.tools(), box: box,
		maxToolCalls: set.MaxToolCalls, byName: map[string]Tool{},
	}
	for _, tool := range inv.tools {
		inv.byName[tool.Name] = tool
	}
	ictx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	err = p.investigate(ictx, inv)
	// Keep what was gathered even when the run failed.
	t.ToolCalls, t.Usage = inv.toolCalls, inv.usage
	if inv.servedBy != "" {
		t.Model = inv.servedBy
	}
	if b, merr := json.Marshal(inv.transcript); merr == nil && len(inv.transcript) > 0 {
		t.Transcript = b
	}
	switch {
	case err != nil:
		return err
	case inv.refusal != "":
		t.Status, t.Error = store.TriageRefused, "the model declined to investigate this alert (category: "+inv.refusal+")"
		return nil
	case box.report == nil:
		return errors.New("no report was submitted")
	}
	rep, _ := json.Marshal(box.report)
	t.Status, t.Report, t.Verdict, t.Confidence = store.TriageDone, rep, box.report.Verdict, box.report.Confidence
	return nil
}

func firstN(ids []string, n int) []string {
	if len(ids) > n {
		return ids[:n]
	}
	return ids
}

// Running returns the alert currently being investigated, if any.
func (s *Service) Running() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
