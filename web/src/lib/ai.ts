// Labels and settings notes for the AI analyst (docs/ai-analyst.md).

import type { AIEngine, AITriageStatus, AIVerdict, Severity } from '../api/types'

export const VERDICT_LABEL: Record<AIVerdict, string> = {
  benign: 'Benign',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
  inconclusive: 'Inconclusive',
}

export const TRIAGE_STATUS_LABEL: Record<AITriageStatus, string> = {
  queued: 'Queued',
  running: 'Investigating',
  done: 'Done',
  failed: 'Failed',
  refused: 'Declined',
  skipped: 'Skipped',
}

export interface Choice<T extends string = string> {
  value: T
  label: string
  note: string
  /** offered but not built yet */
  planned?: boolean
}

/** Who runs investigations. */
export const ENGINE_CHOICES: Choice<AIEngine>[] = [
  {
    value: 'api',
    label: 'An AI provider API',
    note: 'The server investigates on its own with an API key (Claude, OpenAI, Gemini) or a local model. Pay-as-you-go for cloud providers.',
  },
  {
    value: 'mcp',
    label: 'Claude through MCP (your Claude plan)',
    note: 'Claude Code investigates through the HomeXDR MCP server, under your Claude plan with no API bill. Plan usage limits apply. Needs MCP access on, and the MCP runner for automatic investigations.',
  },
]

/** Notes for the providers the server lists; unknown ones fall back to the name only. */
export const PROVIDER_NOTES: Record<string, string> = {
  anthropic: 'Investigates with the Claude API using an Anthropic API key. The default, and the best tested.',
  openai: 'Investigates with OpenAI models through the OpenAI API, using an OpenAI API key.',
  gemini: "Investigates with Gemini models through Google's OpenAI-compatible endpoint, using a Gemini API key.",
  local:
    'A model on your own hardware through an OpenAI-compatible server such as Ollama, LM Studio, vLLM or llama.cpp. Alert data never leaves your network. Smaller models investigate less thoroughly.',
}

/** Where to get a key, per provider. */
export const KEY_HELP: Record<string, string> = {
  anthropic: 'Create one in the Anthropic Console.',
  openai: 'Create one in the OpenAI platform dashboard.',
  gemini: 'Create one in Google AI Studio.',
  local: 'Only needed if your server requires one.',
}

/** Help for the endpoint URL field, per provider. */
export const BASE_URL_HELP: Record<string, string> = {
  openai: 'Leave empty for the OpenAI API, or point it at an OpenAI-compatible proxy.',
  gemini: "Leave empty for Google's OpenAI-compatible Gemini endpoint.",
  local: 'Required. Ollama: http://host:11434/v1 · LM Studio: http://host:1234/v1 · vLLM: http://host:8000/v1',
}

export const MODEL_CHOICES: Choice[] = [
  { value: 'claude-opus-5-5', label: 'Claude Opus 5.5', note: 'Default. The most thorough investigations.' },
  { value: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5', note: 'Faster and cheaper; good for a high alert volume.' },
  { value: 'claude-haiku-5-5', label: 'Claude Haiku 5.5', note: 'Cheapest and quickest; brief triage.' },
]

/** Which new alerts start an investigation (min_severity). */
export const TRIGGER_CHOICES: Choice<Severity>[] = [
  { value: 'medium', label: 'Medium and above', note: 'Skips low and informational alerts to keep the cost down.' },
  { value: 'high', label: 'High and critical only', note: 'Cheapest; only the alerts that matter most.' },
  { value: 'informational', label: 'Every new alert', note: 'Most coverage, highest cost. Keep a daily limit.' },
]

/** How alert data is sent. Only the first is built; the others are shown as planned. */
export const DATA_CHOICES: Choice[] = [
  { value: 'as-is', label: 'Send as-is', note: 'Best triage quality. The data goes to the provider under its API data terms.' },
  {
    value: 'redact',
    label: 'Redact identifiers',
    note: 'Replace usernames, hostnames and internal IPs with stable placeholders before sending. Somewhat weaker triage.',
    planned: true,
  },
  { value: 'local', label: 'Local model only', note: 'Pick the Local model provider above: investigations then stay on your network.' },
]

/** What the AI may change. Only annotation is built. */
export const AUTONOMY_CHOICES: Choice[] = [
  {
    value: 'annotate',
    label: 'Annotate only',
    note: 'Writes a triage report next to the alert. It makes no changes to the platform: it cannot close or edit alerts, change settings or run response actions. You act on its recommendations.',
  },
  {
    value: 'act',
    label: 'Annotate, act and close',
    note: 'Let the AI run response actions and close alerts it is sure are false positives. Attacker-planted text could try to abuse this, so it will be opt-in.',
    planned: true,
  },
]

/** The MCP endpoint of the console the browser is using. */
export function mcpURL(origin: string = window.location.origin): string {
  return `${origin.replace(/\/$/, '')}/mcp`
}

/** Commands and config for connecting MCP clients; the token is a placeholder unless given. */
export function mcpSnippets(origin: string, token = '<MCP token>') {
  const url = mcpURL(origin)
  return {
    claudeCode: `claude mcp add --transport http --scope user homexdr ${url} --header "Authorization: Bearer ${token}"`,
    json: JSON.stringify({ mcpServers: { homexdr: { type: 'http', url, headers: { Authorization: `Bearer ${token}` } } } }, null, 2),
    runner: `homexdr-mcp-runner -url ${origin.replace(/\/$/, '')} -token-file mcp-token.txt`,
  }
}

/** The trigger choice for a min_severity (anything else is shown as a custom level). */
export function triggerChoice(minSeverity: Severity): Choice<Severity> | undefined {
  return TRIGGER_CHOICES.find((c) => c.value === minSeverity)
}

export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1000) return `${Math.round(n / 1000)}k`
  return String(n)
}

/** Search link for an event ID, over the 30 days before the investigation until now. */
export function eventSearchHref(eventId: string, around: string): string {
  const from = new Date(Date.parse(around) - 30 * 86_400_000).toISOString()
  const to = new Date(Math.max(Date.now(), Date.parse(around) + 86_400_000)).toISOString()
  const q = `id:${JSON.stringify(eventId)}`
  return `/search?${new URLSearchParams({ q, range: 'custom', from, to }).toString()}`
}
