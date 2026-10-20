package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// openAIProvider investigates through an OpenAI-compatible Chat Completions API:
// OpenAI itself, Google's OpenAI-compatible Gemini endpoint, or a local server such as
// Ollama, LM Studio, vLLM or llama.cpp. All of them take the same tool-calling format.
type openAIProvider struct {
	id      string // provider ID (openai, gemini, local)
	baseURL string // up to and including /v1 (or the provider's equivalent)
	apiKey  string // may be empty for local servers
	modelID string
	strict  bool // send strict function schemas (OpenAI only; others may reject the field)
	hc      *http.Client
	// retryWait is how long to wait before retry n (replaced in tests).
	retryWait func(n int, retryAfter string) time.Duration
}

func newOpenAICompatible(id, baseURL, apiKey, model string) *openAIProvider {
	return &openAIProvider{
		id: id, baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, modelID: model,
		strict: id == ProviderOpenAI,
		hc:     &http.Client{Timeout: 5 * time.Minute}, // local models can be slow
		retryWait: func(n int, retryAfter string) time.Duration {
			if s, err := strconv.Atoi(retryAfter); err == nil && s > 0 && s <= 60 {
				return time.Duration(s) * time.Second
			}
			return time.Duration(2<<n) * time.Second // 2s, 4s, 8s
		},
	}
}

func (p *openAIProvider) name() string  { return p.id }
func (p *openAIProvider) model() string { return p.modelID }

// --- wire types (only the fields used) ---

type oaFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
	Strict      bool           `json:"strict,omitempty"`
}

type oaTool struct {
	Type     string     `json:"type"`
	Function oaFunction `json:"function"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string          `json:"finish_reason"`
		Message      json.RawMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens        int64 `json:"prompt_tokens"`
		CompletionTokens    int64 `json:"completion_tokens"`
		PromptTokensDetails struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

type oaMessage struct {
	Role      string       `json:"role"`
	Content   *string      `json:"content"`
	Refusal   string       `json:"refusal"`
	ToolCalls []oaToolCall `json:"tool_calls"`
}

func (p *openAIProvider) tools(tools []Tool) []oaTool {
	out := make([]oaTool, len(tools))
	for i, t := range tools {
		params := map[string]any{"type": "object", "properties": t.Properties, "additionalProperties": false}
		if len(t.Required) > 0 {
			params["required"] = t.Required
		}
		out[i] = oaTool{Type: "function", Function: oaFunction{
			Name: t.Name, Description: t.Description, Parameters: params, Strict: p.strict && t.Strict,
		}}
	}
	return out
}

// statusError is a non-2xx response from the API.
type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.body) }

// do sends a request, retrying rate limits, server errors and connection failures.
func (p *openAIProvider) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	var lastErr error
	retryAfter := ""
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(p.retryWait(attempt-1, retryAfter)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if p.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.apiKey)
		}
		resp, err := p.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return data, nil
		}
		lastErr = &statusError{code: resp.StatusCode, body: errorText(data)}
		retryAfter = resp.Header.Get("Retry-After")
		if resp.StatusCode != 429 && resp.StatusCode < 500 {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// errorText extracts {"error":{"message":...}} (or a list of them, as Gemini sends).
func errorText(data []byte) string {
	var one struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &one) == nil && one.Error.Message != "" {
		return one.Error.Message
	}
	var many []struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &many) == nil && len(many) > 0 && many[0].Error.Message != "" {
		return many[0].Error.Message
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func (p *openAIProvider) describe(err error) error {
	var se *statusError
	if !errors.As(err, &se) {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return err
		}
		return fmt.Errorf("cannot reach %s: %w", p.baseURL, err)
	}
	switch se.code {
	case 401:
		return fmt.Errorf("the provider rejected the API key (401): %s", se.body)
	case 403:
		return fmt.Errorf("the API key may not use this model (403): %s", se.body)
	case 404:
		return fmt.Errorf("not found (404); check the base URL and model name: %s", se.body)
	case 429:
		return fmt.Errorf("rate limited (429) after retries: %s", se.body)
	}
	return fmt.Errorf("provider error %d: %s", se.code, se.body)
}

func (p *openAIProvider) chat(ctx context.Context, body map[string]any) (*oaResponse, oaMessage, json.RawMessage, error) {
	data, err := p.do(ctx, http.MethodPost, "/chat/completions", body)
	if err != nil {
		return nil, oaMessage{}, nil, p.describe(err)
	}
	var resp oaResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, oaMessage{}, nil, fmt.Errorf("unexpected response from %s: %v", p.baseURL, err)
	}
	if len(resp.Choices) == 0 {
		return nil, oaMessage{}, nil, errors.New("the provider returned no choices")
	}
	raw := resp.Choices[0].Message
	var msg oaMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, oaMessage{}, nil, fmt.Errorf("unexpected message from %s: %v", p.baseURL, err)
	}
	return &resp, msg, raw, nil
}

// investigate runs the tool loop until the model submits its report.
func (p *openAIProvider) investigate(ctx context.Context, inv *investigation) error {
	text := func(s string) *string { return &s }
	messages := []any{
		oaMessage{Role: "system", Content: text(inv.system)},
		oaMessage{Role: "user", Content: text(inv.initial)},
	}
	tools := p.tools(inv.tools)
	nudges := 0
	maxTurns := inv.maxToolCalls + 6
	for turn := 0; turn < maxTurns; turn++ {
		resp, msg, raw, err := p.chat(ctx, map[string]any{
			"model": p.modelID, "messages": messages, "tools": tools, "tool_choice": "auto",
		})
		if err != nil {
			return err
		}
		inv.usage.InputTokens += resp.Usage.PromptTokens - resp.Usage.PromptTokensDetails.CachedTokens
		inv.usage.CacheReadTokens += resp.Usage.PromptTokensDetails.CachedTokens
		inv.usage.OutputTokens += resp.Usage.CompletionTokens
		if resp.Model != "" {
			inv.servedBy = resp.Model
		}
		finish := resp.Choices[0].FinishReason
		if msg.Refusal != "" || finish == "content_filter" {
			inv.refusal = "content_filter"
			if msg.Refusal != "" {
				inv.refusal = msg.Refusal
			}
			return nil
		}
		// Append the assistant message exactly as returned (append-only history).
		messages = append(messages, raw)
		for _, tc := range msg.ToolCalls {
			args := json.RawMessage(tc.Function.Arguments)
			if strings.TrimSpace(tc.Function.Arguments) == "" {
				args = json.RawMessage(`{}`)
			}
			// This format has no error flag on tool results; failures come back as
			// "Error: ..." text, which models handle the same way.
			out := "Error: the arguments are not valid JSON"
			if json.Valid(args) {
				out, _ = inv.call(ctx, tc.Function.Name, args)
			}
			messages = append(messages, map[string]any{"role": "tool", "tool_call_id": tc.ID, "content": out})
		}
		if inv.box.report != nil {
			return nil
		}
		if len(msg.ToolCalls) > 0 {
			continue
		}
		if finish == "length" {
			return errors.New("the model ran out of output tokens before submitting a report")
		}
		if nudges >= 2 {
			return errors.New("the model finished without submitting a report (local models must support tool calling)")
		}
		nudges++
		messages = append(messages, oaMessage{Role: "user", Content: text("Call submit_triage now with your findings so far.")})
	}
	return fmt.Errorf("no report after %d model turns", maxTurns)
}

func (p *openAIProvider) test(ctx context.Context) (string, error) {
	text := "Reply with the single word OK."
	resp, _, _, err := p.chat(ctx, map[string]any{
		"model": p.modelID, "messages": []oaMessage{{Role: "user", Content: &text}},
	})
	if err != nil {
		return "", err
	}
	if resp.Model != "" {
		return resp.Model, nil
	}
	return p.modelID, nil
}

// listModels returns the model IDs the endpoint offers (GET /models).
func (p *openAIProvider) listModels(ctx context.Context) ([]string, error) {
	data, err := p.do(ctx, http.MethodGet, "/models", nil)
	if err != nil {
		return nil, p.describe(err)
	}
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("unexpected model list from %s: %v", p.baseURL, err)
	}
	ids := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		// Gemini's compatible endpoint lists "models/<name>"; requests take the bare name.
		ids = append(ids, strings.TrimPrefix(m.ID, "models/"))
	}
	sort.Strings(ids)
	return ids, nil
}
