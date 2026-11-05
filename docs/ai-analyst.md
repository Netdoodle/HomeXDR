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
  | `search_events` | Events matching a search (the console's [search language](search.md)), on one or all hosts, in a time window; newest first, trimmed. With commands such as `\| stats count by destination.ip` it returns the table instead (up to 100 rows) |
  | `get_event` | One event in full (long values trimmed) |
  | `get_process_tree` | A process, its ancestors and its children/grandchildren |
  | `get_host` | Host details, sensors and open alert count |
  | `list_alerts` | Recent alerts, optionally for one host, with earlier AI verdicts |
  | `get_network_flow` | Every event for one flow by Community ID: endpoint, OPNsense and Suricata |
  | `lookup_indicator` | What threat intelligence services say about a public IP, domain, URL or hash, and where it appears in your events ([details](intel.md)); can be turned off in Settings → Threat intel |
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
| Investigate with | **An AI provider API** (below), or **An MCP client**: any AI tool that speaks MCP, under its own subscription (see [MCP](#mcp-investigating-with-any-mcp-client)). |
| Provider | **Claude (Anthropic)**, the default and best tested. **OpenAI (ChatGPT)** through the OpenAI API. **Google Gemini** through Google's OpenAI-compatible endpoint. **Local model** through any OpenAI-compatible server (Ollama, LM Studio, vLLM, llama.cpp), so alert data never leaves your network. |
| Model | Claude: `claude-opus-5-5` (default, the most thorough), `claude-sonnet-5-5` (faster and cheaper), `claude-haiku-5-5` (cheapest), or any Claude model ID. Other providers: any model that supports tool (function) calling; **List models** asks the provider what it offers. |
| Endpoint URL | OpenAI and Gemini use their public endpoints unless overridden. Local needs one, e.g. Ollama `http://host:11434/v1`, LM Studio `http://host:1234/v1`, vLLM `http://host:8000/v1`. |
| API key | One per provider (optional for local servers). Stored in the server's state database and never returned by the API, only whether one is set and its last four characters. Environment variables override them: `HOMEXDR_ANTHROPIC_API_KEY`, `HOMEXDR_OPENAI_API_KEY`, `HOMEXDR_GEMINI_API_KEY`, `HOMEXDR_LOCAL_AI_API_KEY`. |
| Which alerts | **Medium and above** (default): skips low and informational alerts to keep the cost down. **High and critical only**: cheapest. **Every new alert**: most coverage, highest cost. |
| Daily limit | Automatic investigations per day (default 50). Later alerts are marked *skipped*; an analyst can still start one by hand. Alerts below high may use 80% of it, and the rest is kept for high and critical alerts. |
| Tool calls per investigation | Default 20. When it is used up the model is asked to report with what it has. |
| Alert data | Sent as-is to the provider for each investigation (hostnames, usernames, IPs, command lines), under the provider's API data terms. Choose the local provider to keep it on your network. Redaction is planned. |

The analyst is on by default but idle until an API key is set. **Test connection** makes a
minimal request with the current form values.

## How an investigation runs

1. A new alert (not a repeat hit folded into an open alert) at or above the threshold is
   queued, unless the daily limit is reached. Analysts can queue any alert with
   **Investigate with AI** / **Investigate again**. If the AI called an alert with the same
   rule, host and process shape benign in the last 7 days, the new alert gets a labelled copy
   of that report instead, with no AI call ([alerts.md](alerts.md)). Critical alerts always
   get their own look. Suppressed alerts are never queued automatically.
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

## MCP: investigating with any MCP client

Instead of an API key, investigations can run through any MCP client (Claude Code, Gemini
CLI, Codex CLI, Cursor and others) under that tool's own subscription. HomeXDR serves the
analyst's tools over the Model Context Protocol at `http://<console>/mcp` (Streamable HTTP,
`Authorization: Bearer` header). Choose **Investigate with: An MCP client** in Settings →
AI analyst, turn **MCP access** on and create an **MCP token**.

The MCP server offers the same read-only tools as the built-in analyst, plus:

| Tool | What it does |
|---|---|
| `next_investigation` | Claims the oldest alert waiting for an MCP investigation and returns it, its first matching events and the analyst instructions |
| `get_alert` | One alert, its first matching events and any earlier AI report |
| `submit_triage` | Records a report on an alert (`alert_id` plus the report fields). Annotation only, as with the API |

Connect your client once. For Claude Code (the settings page shows this command with your
URL and token):

```bash
claude mcp add --transport http --scope user homexdr http://192.168.20.20:18080/mcp --header "Authorization: Bearer hxm_..."
```

Other clients take the same URL and header in their own MCP config format. Then ask the
client, for example, "investigate the waiting HomeXDR alerts" or "triage HomeXDR alert
<id>". Reports show on the alert as written by the client it reported (e.g.
`claude-code 2.1.306`) through MCP, with the tool calls it made.

### Automatic investigations: the MCP runner

**Trigger MCP investigations automatically** queues new alerts at the trigger level for
MCP. Something has to start an AI client for them: `homexdr-mcp-runner`, a small program
for a computer where the client is installed and signed in. It currently drives Claude Code;
with another client, ask it to work through the queue yourself or schedule it with that
client's own headless mode. It checks `/mcp/status` every 30
seconds and, when investigations are waiting, runs Claude Code headless:

```
claude -p --mcp-config <homexdr only> --strict-mcp-config --tools "" \
       --allowedTools mcp__homexdr --permission-mode dontAsk --no-session-persistence
```

in an empty temporary directory. `--tools ""` removes every built-in tool (shell, files,
web), so a run can only read HomeXDR data and record reports, which matters because the
alert data can contain attacker-written text. Each run handles up to five alerts.

```bash
cd server
go build -o homexdr-mcp-runner ./cmd/homexdr-mcp-runner     # .exe on Windows
echo hxm_... > mcp-token.txt
./homexdr-mcp-runner -url http://192.168.20.20:18080 -token-file mcp-token.txt
```

Options: `-model sonnet` (default: Claude Code's), `-interval 30s`, `-timeout 30m`,
`-per-run 5`, `-name` (shown in the console), `-log-file`, `-claude` (path to Claude Code),
`-once`. Keep it running with Task Scheduler (Windows), a systemd unit or a user script.

On Windows, build it without a console window and start it at logon. It then starts Claude
Code hidden too. Use a folder outside `AppData` if you set it up from a packaged app's
terminal, which may redirect `AppData` writes where Task Scheduler cannot see them:

```powershell
go build -ldflags "-H=windowsgui" -o $HOME\HomeXDR\homexdr-mcp-runner.exe ./cmd/homexdr-mcp-runner
$a = New-ScheduledTaskAction -Execute "$HOME\HomeXDR\homexdr-mcp-runner.exe" -WorkingDirectory "$HOME\HomeXDR" `
  -Argument "-url http://192.168.20.20:18080 -token-file `"$HOME\HomeXDR\mcp-token.txt`" -claude `"$HOME\.local\bin\claude.exe`" -log-file `"$HOME\HomeXDR\runner.log`""
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask "HomeXDR MCP runner" -Action $a -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME) -Settings $s
``` The settings page shows when the runner last
checked in.

Turning the toggle off stops new alerts being queued; **Investigate with AI** on an alert
still queues one for MCP, and the runner (or a Claude Code session) picks it up. An MCP
investigation with no report after 30 minutes is marked failed. Plan usage limits apply,
and the daily limit counts automatic MCP investigations too.

MCP tokens can read all telemetry and alerts and record AI reports, nothing else. Revoke
one under MCP tokens and clients using it stop working at once. The console serves plain
HTTP, so use MCP on your LAN or over a VPN.

## API

See [api.md](api.md#ai-analyst). Alerts carry `ai_triage: {status, verdict, confidence}`
when they have an investigation.
