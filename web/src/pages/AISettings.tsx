// Settings → AI analyst: which AI investigates new alerts, when, and what it may do.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api, queryKeys, type AIEngine, type AISettings, type AISettingsUpdate, type MCPToken, type Severity } from '../api'
import { ChoiceCards } from '../components/ChoiceCards'
import { Icon } from '../components/Icon'
import { CopyButton, RelTime } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { plural } from '../lib/format'
import {
  AUTONOMY_CHOICES,
  BASE_URL_HELP,
  DATA_CHOICES,
  ENGINE_CHOICES,
  mcpSnippets,
  mcpURL,
  KEY_HELP,
  MODEL_CHOICES,
  PROVIDER_NOTES,
  TRIGGER_CHOICES,
  triggerChoice,
  type Choice,
} from '../lib/ai'
import { SEVERITY_LABEL } from '../lib/severity'

function Section({ title, help, children }: { title: ReactNode; help?: ReactNode; children: ReactNode }) {
  return (
    <div className="field" style={{ gap: 6 }}>
      <span className="label">{title}</span>
      {help ? <span className="help">{help}</span> : null}
      {children}
    </div>
  )
}

function toUpdate(s: AISettings): AISettingsUpdate {
  return {
    enabled: s.enabled,
    provider: s.provider,
    model: s.model,
    base_url: s.base_url ?? '',
    min_severity: s.min_severity,
    daily_limit: s.daily_limit,
    max_tool_calls: s.max_tool_calls,
    engine: s.engine ?? 'api',
    mcp_enabled: s.mcp_enabled ?? false,
    mcp_auto_trigger: s.mcp_auto_trigger ?? false,
  }
}

export function AIAnalystTab() {
  const q = useQuery({ queryKey: queryKeys.aiSettings, queryFn: api.getAISettings })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <AIAnalystForm settings={q.data} />
}

function AIAnalystForm({ settings }: { settings: AISettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [form, setForm] = useState<AISettingsUpdate>(() => toUpdate(settings))
  const [key, setKey] = useState('')
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null)
  const [models, setModels] = useState<{ list: string[]; error?: string } | null>(null)
  useEffect(() => setForm(toUpdate(settings)), [settings])

  const set = <K extends keyof AISettingsUpdate>(k: K, v: AISettingsUpdate[K]) => {
    setForm((f) => ({ ...f, [k]: v }))
    setTest(null)
  }
  const chooseProvider = (id: string) => {
    if (id === form.provider) return
    // Model names and endpoints belong to a provider; start fresh when switching.
    const back = id === settings.provider
    setForm((f) => ({
      ...f,
      provider: id,
      model: back ? settings.model : id === 'anthropic' ? settings.default_model : '',
      base_url: back ? (settings.base_url ?? '') : '',
    }))
    setKey('')
    setTest(null)
    setModels(null)
  }
  const body = (extra: Partial<AISettingsUpdate> = {}): AISettingsUpdate => ({ ...form, ...(key.trim() ? { api_key: key.trim() } : {}), ...extra })

  const save = useMutation({
    mutationFn: (b: AISettingsUpdate) => api.putAISettings(b),
    onSuccess: (s) => {
      qc.setQueryData(queryKeys.aiSettings, s)
      setKey('')
      toast.success(s.ready ? 'AI analyst settings saved' : `Saved. The AI analyst is not running: ${s.not_ready_reason}`)
    },
    onError: (e) => toast.error(e),
  })
  const runTest = useMutation({
    mutationFn: () => api.testAISettings(body()),
    onSuccess: (r) => setTest(r.ok ? { ok: true, text: `Connected. ${r.model} answered.` } : { ok: false, text: r.error ?? 'Failed' }),
    onError: (e) => toast.error(e),
  })
  const listModels = useMutation({
    mutationFn: () => api.listAIModels(body()),
    onSuccess: (r) => setModels({ list: r.models, error: r.error }),
    onError: (e) => toast.error(e),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate(body())
  }

  const provider = settings.providers.find((p) => p.id === form.provider)
  const isClaude = form.provider === 'anthropic'
  const keyStatus = settings.keys?.[form.provider]
  const customModel = !MODEL_CHOICES.some((c) => c.value === form.model)
  const providers: Choice[] = settings.providers.map((p) => ({
    value: p.id,
    label: p.name,
    note: PROVIDER_NOTES[p.id] ?? '',
    planned: !p.available,
  }))
  const trigger = triggerChoice(form.min_severity)
  const triggers: Choice[] = trigger
    ? TRIGGER_CHOICES
    : [...TRIGGER_CHOICES, { value: form.min_severity, label: `${SEVERITY_LABEL[form.min_severity]} and above`, note: 'Custom level.' }]

  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: 820 }}>
      <section className="panel">
        <div className="panel-header">
          <h2 className="row" style={{ gap: 8 }}>
            <Icon name="sparkle" size={14} /> AI analyst
          </h2>
          <label className="row small" style={{ gap: 8 }}>
            <span className="toggle">
              <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} aria-label="AI analyst on" />
              <span />
            </span>
            {form.enabled ? 'On' : 'Off'}
          </label>
        </div>
        <div className="panel-body stack" style={{ gap: 16 }}>
          <p className="muted small" style={{ margin: 0 }}>
            When a new alert comes in at or above the trigger level, an AI model investigates it with read-only tools (searching events, process
            trees, hosts, related alerts and network flows) and writes a triage report next to the alert: a verdict, its confidence, the evidence
            and recommended next steps. It does nothing until an alert triggers it.
          </p>
          <div className={settings.ready ? 'callout ok' : 'callout warn'}>
            <Icon name={settings.ready ? 'check' : 'warning'} size={14} />
            <div>
              {!settings.ready ? (
                <>Not running: {settings.not_ready_reason}.</>
              ) : settings.engine === 'mcp' ? (
                <>
                  Investigations run through MCP. {plural(settings.mcp.pending, 'alert')} waiting.{' '}
                  {settings.mcp_auto_trigger
                    ? `${settings.auto_today} of ${settings.daily_limit} automatic investigations used today.`
                    : 'Automatic triggering is off: investigations start only when you ask.'}
                </>
              ) : (
                <>
                  Running with {settings.providers.find((p) => p.id === settings.provider)?.name ?? settings.provider} ({settings.model}).{' '}
                  {settings.auto_today} of {settings.daily_limit} automatic investigations used today.
                </>
              )}
            </div>
          </div>

          <Section title="Investigate with">
            <ChoiceCards name="Engine" choices={ENGINE_CHOICES} value={form.engine} onChange={(v) => set('engine', v as AIEngine)} />
          </Section>

          {form.engine === 'mcp' ? (
            <MCPAccess settings={settings} form={form} set={set} />
          ) : (
            <>
          <Section title="Provider">
            <ChoiceCards name="Provider" choices={providers} value={form.provider} onChange={chooseProvider} />
          </Section>

          {!isClaude ? (
            <Section
              title={form.provider === 'local' ? 'Server URL' : 'Endpoint URL'}
              help={BASE_URL_HELP[form.provider] ?? 'An OpenAI-compatible API, up to and including /v1.'}
            >
              <input
                className="input mono"
                value={form.base_url ?? ''}
                placeholder={provider?.default_base_url || 'http://192.168.20.20:11434/v1'}
                onChange={(e) => set('base_url', e.target.value)}
                aria-label="Endpoint URL"
              />
            </Section>
          ) : null}

          <Section
            title={
              <>
                API key{provider && !provider.needs_key ? <span className="muted"> (optional)</span> : null}
              </>
            }
            help={
              keyStatus?.source === 'environment'
                ? `Set by the ${provider?.key_env ?? 'environment'} environment variable, which overrides this setting.`
                : `${KEY_HELP[form.provider] ?? ''} Stored in the server database and never shown again; each provider keeps its own key.`
            }
          >
            <div className="row" style={{ gap: 8 }}>
              <input
                className="input mono"
                type="password"
                autoComplete="off"
                style={{ flex: 1 }}
                placeholder={keyStatus?.set ? `Key set (${keyStatus.hint ?? 'hidden'}); paste a new one to replace it` : 'Paste the API key'}
                value={key}
                onChange={(e) => {
                  setKey(e.target.value)
                  setTest(null)
                }}
                aria-label="API key"
                disabled={keyStatus?.source === 'environment'}
              />
              {keyStatus?.set && keyStatus.source === 'settings' && form.provider === settings.provider ? (
                <button type="button" className="btn" disabled={save.isPending} onClick={() => save.mutate(body({ clear_api_key: true, api_key: undefined }))}>
                  Remove key
                </button>
              ) : null}
            </div>
          </Section>

          <Section title="Model" help={isClaude ? undefined : 'Use a model that supports tool (function) calling. List models asks the provider what it offers.'}>
            {isClaude ? (
              <>
                <ChoiceCards
                  name="Model"
                  choices={[...MODEL_CHOICES, { value: customModel ? form.model : '__custom', label: 'Another model', note: 'Any Claude model ID.' }]}
                  value={form.model}
                  onChange={(v) => set('model', v === '__custom' ? '' : v)}
                />
                {customModel ? (
                  <input className="input mono" placeholder={settings.default_model} value={form.model} onChange={(e) => set('model', e.target.value)} aria-label="Model ID" />
                ) : null}
              </>
            ) : (
              <>
                <div className="row" style={{ gap: 8 }}>
                  <input
                    className="input mono"
                    style={{ flex: 1 }}
                    list="ai-models"
                    placeholder="Model name"
                    value={form.model}
                    onChange={(e) => set('model', e.target.value)}
                    aria-label="Model name"
                  />
                  <button type="button" className="btn" disabled={listModels.isPending} onClick={() => listModels.mutate()}>
                    List models
                  </button>
                </div>
                <datalist id="ai-models">
                  {(models?.list ?? []).map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
                {models?.error ? <span className="error xsmall">{models.error}</span> : null}
                {models && !models.error ? (
                  <span className="help">
                    {models.list.length} {models.list.length === 1 ? 'model' : 'models'} available; pick one from the list or type a name.
                  </span>
                ) : null}
              </>
            )}
          </Section>
            </>
          )}

          <Section title="Which alerts to investigate">
            <ChoiceCards name="Trigger" choices={triggers} value={form.min_severity} onChange={(v) => set('min_severity', v as Severity)} />
            <div className="form-grid" style={{ marginTop: 4 }}>
              <label className="field">
                <span className="label">Daily limit</span>
                <input
                  className="input"
                  type="number"
                  min={1}
                  max={10000}
                  value={form.daily_limit}
                  onChange={(e) => set('daily_limit', Number(e.target.value))}
                />
                <span className="help">Automatic investigations per day; later alerts are marked as skipped. Alerts below high may use 80% of this, so high and critical alerts still get a look late in a noisy day. A repeat of something the AI called benign in the last 7 days reuses that verdict and does not count. You can still start one by hand.</span>
              </label>
              <label className="field">
                <span className="label">Tool calls per investigation</span>
                <input
                  className="input"
                  type="number"
                  min={1}
                  max={50}
                  value={form.max_tool_calls}
                  onChange={(e) => set('max_tool_calls', Number(e.target.value))}
                />
                <span className="help">Caps how much each investigation can look up, and so its cost.</span>
              </label>
            </div>
          </Section>

          <Section
            title="Alert data sent to the provider"
            help={form.engine === 'mcp' ? 'Through MCP, the AI client reads the data under the terms of its own service, as in any session with that tool.' : undefined}
          >
            <ChoiceCards name="Data" choices={DATA_CHOICES} value={form.engine === 'api' && form.provider === 'local' ? 'local' : 'as-is'} />
          </Section>

          <Section title="What the AI may do">
            <ChoiceCards name="Autonomy" choices={AUTONOMY_CHOICES} value="annotate" />
          </Section>

          {test ? (
            <div className={test.ok ? 'callout ok' : 'callout danger'} role="status">
              <Icon name={test.ok ? 'check' : 'warning'} size={14} />
              <div>{test.text}</div>
            </div>
          ) : null}
          <div className="row" style={{ gap: 8 }}>
            <button type="submit" className="btn primary" disabled={save.isPending}>
              Save
            </button>
            {form.engine === 'api' ? (
              <button type="button" className="btn" disabled={runTest.isPending} onClick={() => runTest.mutate()}>
                Test connection
              </button>
            ) : null}
            {save.isPending || runTest.isPending || listModels.isPending ? <Spinner small /> : null}
          </div>
        </div>
      </section>
      {form.engine === 'api' ? <MCPAccess settings={settings} form={form} set={set} /> : null}
    </form>
  )
}

/** MCP access: the endpoint switch, automatic triggering, the runner and tokens. */
function MCPAccess({
  settings,
  form,
  set,
}: {
  settings: AISettings
  form: AISettingsUpdate
  set: <K extends keyof AISettingsUpdate>(k: K, v: AISettingsUpdate[K]) => void
}) {
  const origin = window.location.origin
  const snippets = mcpSnippets(origin)
  const runnerSeen = settings.mcp.runner_seen_at
  const runnerFresh = runnerSeen ? Date.now() - Date.parse(runnerSeen) < 3 * 60_000 : false
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>MCP access</h2>
        <label className="row small" style={{ gap: 8 }}>
          <span className="toggle">
            <input type="checkbox" checked={form.mcp_enabled} onChange={(e) => set('mcp_enabled', e.target.checked)} aria-label="MCP access on" />
            <span />
          </span>
          {form.mcp_enabled ? 'On' : 'Off'}
        </label>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="muted small" style={{ margin: 0 }}>
          Lets any MCP client (Claude Code, Gemini CLI, Codex CLI, Cursor and others) use HomeXDR&apos;s read-only investigation tools at{' '}
          <span className="mono">{mcpURL(origin)}</span>, under that tool&apos;s own subscription. Ask it to investigate any alert, or let the runner
          work through queued ones. Reports are stored next to the alert, as with the API; MCP clients cannot change anything else.
        </p>

        <label className={`choice${form.mcp_auto_trigger ? ' selected' : ''}`}>
          <input
            type="checkbox"
            checked={form.mcp_auto_trigger}
            disabled={!form.mcp_enabled || form.engine !== 'mcp'}
            onChange={(e) => set('mcp_auto_trigger', e.target.checked)}
          />
          <div>
            <div className="choice-title">Trigger MCP investigations automatically</div>
            <div className="choice-note">
              {form.engine !== 'mcp'
                ? 'Choose “An MCP client” above to use this.'
                : 'New alerts at the trigger level are queued, and the MCP runner starts an AI client for them. Off: investigations start only when you click “Investigate with AI” on an alert, or ask your MCP client yourself.'}
            </div>
          </div>
        </label>

        <div className={runnerFresh ? 'callout ok' : 'callout'}>
          <Icon name={runnerFresh ? 'check' : 'info'} size={14} />
          <div>
            {runnerSeen ? (
              <>
                Runner <strong>{settings.mcp.runner_name}</strong> last checked in <RelTime iso={runnerSeen} />.
              </>
            ) : (
              <>No MCP runner has checked in. Queued investigations wait until one does, or until you ask your MCP client to investigate them.</>
            )}{' '}
            {settings.mcp.pending > 0 ? <>{plural(settings.mcp.pending, 'alert')} waiting.</> : null}
          </div>
        </div>

        <MCPTokens origin={origin} />

        <details>
          <summary className="small" style={{ cursor: 'pointer' }}>
            How to connect
          </summary>
          <div className="stack" style={{ gap: 10, marginTop: 8 }}>
            <div className="field">
              <span className="label">Claude Code, for example (create a token below and put it in place of &lt;MCP token&gt;)</span>
              <div className="copy-field">
                <pre className="codeblock wrap">{snippets.claudeCode}</pre>
                <CopyButton text={snippets.claudeCode} small />
              </div>
              <span className="help">
                Then ask it, for example: “Investigate the waiting HomeXDR alerts” or “Triage HomeXDR alert &lt;id&gt;”.
              </span>
            </div>
            <div className="field">
              <span className="label">Other MCP clients (Gemini CLI, Codex CLI, Cursor, ...): an HTTP server with this header; the config format varies by client</span>
              <div className="copy-field">
                <pre className="codeblock wrap">{snippets.json}</pre>
                <CopyButton text={snippets.json} small />
              </div>
            </div>
            <div className="field">
              <span className="label">MCP runner, for automatic investigations (it drives Claude Code for now), on a computer where it is installed and signed in</span>
              <div className="copy-field">
                <pre className="codeblock wrap">{snippets.runner}</pre>
                <CopyButton text={snippets.runner} small />
              </div>
              <span className="help">
                Save the token in mcp-token.txt. The runner checks every 30 seconds and runs Claude Code with only the HomeXDR tools (no shell,
                files or web) when investigations are waiting. Build it with <span className="mono">go build ./cmd/homexdr-mcp-runner</span>; see
                docs/ai-analyst.md.
              </span>
            </div>
          </div>
        </details>
      </div>
    </section>
  )
}

function MCPTokens({ origin }: { origin: string }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [name, setName] = useState('')
  const [created, setCreated] = useState<MCPToken | null>(null)
  const tokens = useQuery({ queryKey: queryKeys.mcpTokens, queryFn: api.listMCPTokens })
  const refresh = () => {
    qc.invalidateQueries({ queryKey: queryKeys.mcpTokens })
    qc.invalidateQueries({ queryKey: queryKeys.aiSettings })
  }
  const create = useMutation({
    mutationFn: () => api.createMCPToken(name.trim()),
    onSuccess: (t) => {
      setCreated(t)
      setName('')
      refresh()
    },
    onError: (e) => toast.error(e),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.deleteMCPToken(id),
    onSuccess: () => {
      toast.success('Token revoked')
      refresh()
    },
    onError: (e) => toast.error(e),
  })
  const list = tokens.data?.tokens ?? []
  return (
    <div className="field" style={{ gap: 8 }}>
      <span className="label">MCP tokens</span>
      <span className="help">Each MCP client or runner uses its own token. A token can read all telemetry and alerts, and record AI reports.</span>
      {created?.token ? (
        <div className="callout ok">
          <Icon name="key" size={14} />
          <div className="stack" style={{ gap: 6, minWidth: 0, flex: 1 }}>
            <span>
              Token <strong>{created.name}</strong> created. Copy it now: it is not shown again.
            </span>
            <div className="copy-field">
              <pre className="codeblock wrap">{created.token}</pre>
              <CopyButton text={created.token} small />
            </div>
            <div className="copy-field">
              <pre className="codeblock wrap">{mcpSnippets(origin, created.token).claudeCode}</pre>
              <CopyButton text={mcpSnippets(origin, created.token).claudeCode} label="Copy Claude Code command" small />
            </div>
            <button type="button" className="linklike xsmall" style={{ alignSelf: 'flex-start' }} onClick={() => setCreated(null)}>
              Done
            </button>
          </div>
        </div>
      ) : null}
      {tokens.isError ? (
        <ErrorState error={tokens.error} onRetry={() => tokens.refetch()} />
      ) : list.length ? (
        <table className="table compact">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Last used</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {list.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td className="small">
                  <RelTime iso={t.created_at} /> by {t.created_by}
                </td>
                <td className="small">{t.last_used_at ? <RelTime iso={t.last_used_at} /> : <span className="faint">never</span>}</td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    type="button"
                    className="btn sm"
                    disabled={revoke.isPending}
                    onClick={() => {
                      if (window.confirm(`Revoke the MCP token "${t.name}"? Clients using it stop working.`)) revoke.mutate(t.id)
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : tokens.isPending ? null : (
        <span className="small faint">No tokens yet.</span>
      )}
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input"
          style={{ flex: 1, maxWidth: 320 }}
          placeholder="Token name, e.g. desktop runner"
          value={name}
          maxLength={80}
          onChange={(e) => setName(e.target.value)}
          aria-label="New token name"
        />
        <button type="button" className="btn" disabled={create.isPending} onClick={() => create.mutate()}>
          <Icon name="plus" size={12} /> Create token
        </button>
      </div>
    </div>
  )
}
