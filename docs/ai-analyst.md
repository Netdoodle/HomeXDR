# AI analyst

The AI analyst does first-line triage. It does nothing until a new alert at or above a
chosen severity comes in. Then an AI model investigates that alert with read-only tools and
writes a triage report next to it: a verdict, its confidence, the evidence it relied on, a
MITRE ATT&CK mapping, recommended next steps and open questions. Analysts see the report
on the alert page, and the verdict as a badge in the alert list.

The code is in `server/internal/triage`; the console settings are under
**Settings → AI analyst**.

## What it can and cannot do

- **Annotate only.** The AI makes no changes to the platform. It cannot close, edit or
  re-prioritize alerts, change settings or rules, or run response actions. Its report is
  stored separately from the alert. A future, opt-in setting may let it act on and close
  alerts.
- **Read-only tools.** During an investigation the model can call:

  | Tool | What it returns |
  |---|---|
  | `search_events` | Events matching a query (the console's query language), on one or all hosts, in a time window; newest first, trimmed |
  | `get_event` | One event in full (long values trimmed) |
  | `get_process_tree` | A process, its ancestors and its children/grandchildren |
  | `get_host` | Host details, sensors and open alert count |
  | `list_alerts` | Recent alerts, optionally for one host, with earlier AI verdicts |
  | `get_network_flow` | Every event for one flow by Community ID: endpoint, OPNsense and Suricata |
  | `submit_triage` | Records the report and ends the investigation (strict JSON schema) |

- **Untrusted data.** Command lines, file names, DNS names and log messages can be written
  by an attacker. The model is told never to follow instructions found in that data, and
  because it can only read and write its own report, text planted in logs cannot make it
  change anything. The console shows everything the model wrote as plain text; only event
  IDs become links, built by the console.
- **Audit.** Every investigation is in the audit log as user `ai` (`ai.triage`), and the
  report keeps the list of tool calls the model made, with a preview of each result.

## Settings

| Setting | Choices |
|---|---|
| Provider | **Claude (Anthropic)**, the default and best tested. **OpenAI (ChatGPT)** through the OpenAI API. **Google Gemini** through Google's OpenAI-compatible endpoint. **Local model** through any OpenAI-compatible server (Ollama, LM Studio, vLLM, llama.cpp), so alert data never leaves your network. |
| Model | Claude: `claude-opus-5-5` (default, the most thorough), `claude-sonnet-5-5` (faster and cheaper), `claude-haiku-5-5` (cheapest), or any Claude model ID. Other providers: any model that supports tool (function) calling; **List models** asks the provider what it offers. |
| Endpoint URL | OpenAI and Gemini use their public endpoints unless overridden. Local needs one, e.g. Ollama `http://host:11434/v1`, LM Studio `http://host:1234/v1`, vLLM `http://host:8000/v1`. |
| API key | One per provider (optional for local servers). Stored in the server's state database and never returned by the API, only whether one is set and its last four characters. Environment variables override them: `HOMEXDR_ANTHROPIC_API_KEY`, `HOMEXDR_OPENAI_API_KEY`, `HOMEXDR_GEMINI_API_KEY`, `HOMEXDR_LOCAL_AI_API_KEY`. |
| Which alerts | **Medium and above** (default): skips low and informational alerts to keep the cost down. **High and critical only**: cheapest. **Every new alert**: most coverage, highest cost. |
| Daily limit | Automatic investigations per day (default 50). Later alerts are marked *skipped*; an analyst can still start one by hand. |
| Tool calls per investigation | Default 20. When it is used up the model is asked to report with what it has. |
| Alert data | Sent as-is to the provider for each investigation (hostnames, usernames, IPs, command lines), under the provider's API data terms. Choose the local provider to keep it on your network. Redaction is planned. |

The analyst is on by default but idle until an API key is set. **Test connection** makes a
minimal request with the current form values.

## How an investigation runs

1. A new alert (not a repeat hit folded into an open alert) at or above the threshold is
   queued, unless the daily limit is reached. Analysts can queue any alert with
   **Investigate with AI** / **Investigate again**.
2. One worker processes the queue in order. Investigations interrupted by a restart are
   queued again.
3. The model gets a fixed system prompt, the alert and up to five matching events, and the
   tools. It works in a loop of tool calls until it calls `submit_triage`; if it stops
   without a report it is asked for one (twice at most). Ten minutes is the hard limit.
4. The result is stored with status `done`, `failed`, `refused` or `skipped`.

With Claude: requests use the Messages API with tool use, adaptive thinking, effort
`high`, prompt caching (the system prompt and tools are identical for every investigation,
and each turn re-reads the cached conversation) and an append-only message history.
Security content can trip Claude's safety classifiers; on models that support it,
requests opt in to server-side refusal fallbacks (`fallbacks: "default"`) so a declined
turn is re-served by a fallback model. If the whole chain declines, the investigation is
stored as `refused` with the category. Rate limits and server errors are retried by the
SDK.

With the other providers: requests use the OpenAI-compatible Chat Completions API with
function calling (`tool_choice: "auto"`) and the same tools and append-only history.
`submit_triage` is sent as a strict schema to OpenAI only, since some compatible servers
reject the field; the report is validated on the server either way. Rate limits and
server errors are retried with backoff (honouring `Retry-After`). A refusal
(`message.refusal` or `finish_reason: content_filter`) is stored as `refused`. Local
models vary a lot in how well they call tools: if one finishes without a report, it is
asked for one twice, then the run is stored as failed.

## API

See [api.md](api.md#ai-analyst). Alerts carry `ai_triage: {status, verdict, confidence}`
when they have an investigation.
