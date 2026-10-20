package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

// claudeProvider investigates with the Claude API (Messages API with tool use).
type claudeProvider struct {
	client    anthropic.Client
	modelID   string
	fallbacks bool // server-side refusal fallbacks, see newClaude
}

const claudeMaxTokens = 16000

// newClaude returns a Claude provider. Security triage reads attack content, which
// Claude's safety classifiers sometimes decline; on models that support it, requests
// opt in to server-side fallbacks so a declined turn is re-served by a fallback model
// instead of failing the investigation.
func newClaude(apiKey, model string, opts ...option.RequestOption) *claudeProvider {
	o := append([]option.RequestOption{
		option.WithAPIKey(apiKey),
		option.WithMaxRetries(3), // 408/409/429/5xx and connection errors
		option.WithRequestTimeout(5 * time.Minute),
	}, opts...)
	return &claudeProvider{client: anthropic.NewClient(o...), modelID: model, fallbacks: supportsFallbacks(model)}
}

func (p *claudeProvider) name() string  { return ProviderAnthropic }
func (p *claudeProvider) model() string { return p.modelID }

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// supportsFallbacks: the "default" fallbacks form is offered for these model lines on
// the Claude API. Elsewhere a refusal ends the investigation as "refused".
func supportsFallbacks(model string) bool {
	return hasPrefix(model, "claude-opus-5", "claude-fable-5", "claude-sonnet-5-5")
}

// supportsEffort: the effort parameter exists on these models (it errors on older ones).
func supportsEffort(model string) bool {
	return hasPrefix(model, "claude-opus-5", "claude-fable-5", "claude-mythos-5", "claude-sonnet-5", "claude-haiku-5",
		"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6")
}

func (p *claudeProvider) params(effort anthropic.BetaOutputConfigEffort) anthropic.BetaMessageNewParams {
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(p.modelID),
		MaxTokens: claudeMaxTokens,
		// Thinking is left unset: current models think adaptively by default, and an
		// explicit "disabled" setting is rejected by several of them.
	}
	if supportsEffort(p.modelID) {
		params.OutputConfig = anthropic.BetaOutputConfigParam{Effort: effort}
	}
	if p.fallbacks {
		params.Fallbacks = anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()}
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}
	return params
}

func betaTools(tools []Tool) []anthropic.BetaToolUnionParam {
	out := make([]anthropic.BetaToolUnionParam, 0, len(tools))
	for _, t := range tools {
		tp := anthropic.BetaToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{
				Properties:  t.Properties,
				Required:    t.Required,
				ExtraFields: map[string]any{"additionalProperties": false},
			},
		}
		if t.Strict {
			tp.Strict = anthropic.Bool(true)
		}
		out = append(out, anthropic.BetaToolUnionParam{OfTool: &tp})
	}
	return out
}

// send makes one request. If the API rejects the fallbacks option (an account or
// model without it), it retries once without fallbacks.
func (p *claudeProvider) send(ctx context.Context, params anthropic.BetaMessageNewParams) (*anthropic.BetaMessage, error) {
	resp, err := p.client.Beta.Messages.New(ctx, params)
	var apierr *anthropic.Error
	if err != nil && p.fallbacks && errors.As(err, &apierr) && apierr.StatusCode == 400 &&
		strings.Contains(strings.ToLower(apierr.Error()), "fallback") {
		p.fallbacks = false
		params.Fallbacks = anthropic.BetaFallbacksParamUnion{}
		params.Betas = nil
		return p.client.Beta.Messages.New(ctx, params)
	}
	return resp, err
}

// investigate runs the tool loop until the model submits its report. The message
// history is append-only (each response is appended as returned, then the tool
// results), which keeps the prompt cache warm and replayed thinking valid.
func (p *claudeProvider) investigate(ctx context.Context, inv *investigation) error {
	params := p.params(anthropic.BetaOutputConfigEffortHigh)
	params.System = []anthropic.BetaTextBlockParam{{Text: inv.system}}
	params.Tools = betaTools(inv.tools)
	// Cache the growing conversation: each turn re-reads the previous ones.
	params.CacheControl = anthropic.NewBetaCacheControlEphemeralParam()

	messages := []anthropic.BetaMessageParam{
		anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(inv.initial)),
	}
	nudges := 0
	maxTurns := inv.maxToolCalls + 6
	for turn := 0; turn < maxTurns; turn++ {
		params.Messages = messages
		resp, err := p.send(ctx, params)
		if err != nil {
			return describeAPIError(err)
		}
		inv.usage.InputTokens += resp.Usage.InputTokens + resp.Usage.CacheCreationInputTokens
		inv.usage.OutputTokens += resp.Usage.OutputTokens
		inv.usage.CacheReadTokens += resp.Usage.CacheReadInputTokens
		inv.servedBy = string(resp.Model)

		switch resp.StopReason {
		case anthropic.BetaStopReasonRefusal:
			inv.refusal = string(resp.StopDetails.Category)
			if inv.refusal == "" {
				inv.refusal = "unspecified"
			}
			return nil
		case anthropic.BetaStopReasonModelContextWindowExceeded:
			return errors.New("the investigation exceeded the model's context window")
		}

		messages = append(messages, resp.ToParam())
		var results []anthropic.BetaContentBlockParamUnion
		for _, block := range resp.Content {
			tu, ok := block.AsAny().(anthropic.BetaToolUseBlock)
			if !ok {
				continue
			}
			out, isErr := inv.call(ctx, tu.Name, json.RawMessage(tu.JSON.Input.Raw()))
			results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, out, isErr))
		}
		if inv.box.report != nil {
			return nil // submitted; nothing more to ask
		}
		if len(results) > 0 {
			messages = append(messages, anthropic.NewBetaUserMessage(results...))
			continue
		}
		if resp.StopReason == anthropic.BetaStopReasonMaxTokens {
			return errors.New("the model ran out of output tokens before submitting a report")
		}
		// The model stopped without calling submit_triage (tool use cannot be forced on
		// current models): ask for the report.
		if nudges >= 2 {
			return errors.New("the model finished without submitting a report")
		}
		nudges++
		messages = append(messages, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(
			"Call submit_triage now with your findings so far.")))
	}
	return fmt.Errorf("no report after %d model turns", maxTurns)
}

// test makes a minimal request to check the key and model.
func (p *claudeProvider) test(ctx context.Context) (string, error) {
	params := p.params(anthropic.BetaOutputConfigEffortLow)
	params.MaxTokens = 2048
	params.Messages = []anthropic.BetaMessageParam{
		anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock("Reply with the single word OK.")),
	}
	resp, err := p.send(ctx, params)
	if err != nil {
		return "", describeAPIError(err)
	}
	return string(resp.Model), nil
}

// describeAPIError turns SDK errors into messages an admin can act on.
func describeAPIError(err error) error {
	var apierr *anthropic.Error
	if !errors.As(err, &apierr) {
		return fmt.Errorf("cannot reach the Claude API: %w", err)
	}
	switch apierr.StatusCode {
	case 401:
		return errors.New("the Claude API rejected the API key (401)")
	case 403:
		return errors.New("the API key is not allowed to use this model (403)")
	case 404:
		return errors.New("unknown model (404); check the model name in the AI analyst settings")
	case 429:
		return errors.New("rate limited by the Claude API (429) after retries")
	case 529:
		return errors.New("the Claude API is overloaded (529); try again later")
	}
	return fmt.Errorf("Claude API error %d: %s", apierr.StatusCode, apierr.Error())
}
