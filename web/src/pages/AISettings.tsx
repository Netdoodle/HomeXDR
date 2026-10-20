// Settings → AI analyst: which AI investigates new alerts, when, and what it may do.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api, queryKeys, type AISettings, type AISettingsUpdate, type Severity } from '../api'
import { Icon } from '../components/Icon'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import {
  AUTONOMY_CHOICES,
  DATA_CHOICES,
  MODEL_CHOICES,
  PROVIDER_NOTES,
  TRIGGER_CHOICES,
  triggerChoice,
  type Choice,
} from '../lib/ai'
import { SEVERITY_LABEL } from '../lib/severity'

function ChoiceCards({
  name,
  choices,
  value,
  onChange,
}: {
  name: string
  choices: Choice[]
  value: string
  onChange?: (v: string) => void
}) {
  return (
    <div className="choice-list" role="radiogroup" aria-label={name}>
      {choices.map((c) => {
        const disabled = !!c.planned || !onChange
        const selected = value === c.value
        return (
          <label key={c.value} className={`choice${selected ? ' selected' : ''}${c.planned ? ' disabled' : ''}`}>
            <input type="radio" name={name} value={c.value} checked={selected} disabled={disabled && !selected} onChange={() => onChange?.(c.value)} />
            <div>
              <div className="choice-title">
                {c.label}
                {c.planned ? (
                  <span className="badge" style={{ marginLeft: 8 }}>
                    Planned
                  </span>
                ) : null}
              </div>
              <div className="choice-note">{c.note}</div>
            </div>
          </label>
        )
      })}
    </div>
  )
}

function Section({ title, help, children }: { title: string; help?: ReactNode; children: ReactNode }) {
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
    min_severity: s.min_severity,
    daily_limit: s.daily_limit,
    max_tool_calls: s.max_tool_calls,
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
  useEffect(() => setForm(toUpdate(settings)), [settings])

  const set = <K extends keyof AISettingsUpdate>(k: K, v: AISettingsUpdate[K]) => {
    setForm((f) => ({ ...f, [k]: v }))
    setTest(null)
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

  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate(body())
  }

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
              {settings.ready ? (
                <>
                  Running. {settings.auto_today} of {settings.daily_limit} automatic investigations used today.
                </>
              ) : (
                <>Not running: {settings.not_ready_reason}.</>
              )}
            </div>
          </div>

          <Section title="Provider">
            <ChoiceCards name="Provider" choices={providers} value={form.provider} onChange={(v) => set('provider', v)} />
          </Section>

          <Section title="Model">
            <ChoiceCards
              name="Model"
              choices={[...MODEL_CHOICES, { value: customModel ? form.model : '__custom', label: 'Another model', note: 'Any Claude model ID.' }]}
              value={form.model}
              onChange={(v) => set('model', v === '__custom' ? '' : v)}
            />
            {customModel ? (
              <input className="input mono" placeholder={settings.default_model} value={form.model} onChange={(e) => set('model', e.target.value)} aria-label="Model ID" />
            ) : null}
          </Section>

          <Section
            title="API key"
            help={
              settings.key_source === 'environment'
                ? 'Set by the HOMEXDR_ANTHROPIC_API_KEY environment variable, which overrides this setting.'
                : 'Stored in the server database and never shown again. Create one in the Anthropic Console.'
            }
          >
            <div className="row" style={{ gap: 8 }}>
              <input
                className="input mono"
                type="password"
                autoComplete="off"
                style={{ flex: 1 }}
                placeholder={settings.key_set ? `Key set (${settings.key_hint ?? 'hidden'}); paste a new one to replace it` : 'sk-ant-...'}
                value={key}
                onChange={(e) => {
                  setKey(e.target.value)
                  setTest(null)
                }}
                aria-label="API key"
                disabled={settings.key_source === 'environment'}
              />
              {settings.key_set && settings.key_source === 'settings' ? (
                <button type="button" className="btn" disabled={save.isPending} onClick={() => save.mutate(body({ clear_api_key: true, api_key: undefined }))}>
                  Remove key
                </button>
              ) : null}
            </div>
          </Section>

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
                <span className="help">Automatic investigations per day; later alerts are marked as skipped. You can still start one by hand.</span>
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

          <Section title="Alert data sent to the provider">
            <ChoiceCards name="Data" choices={DATA_CHOICES} value="as-is" />
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
            <button type="button" className="btn" disabled={runTest.isPending} onClick={() => runTest.mutate()}>
              Test connection
            </button>
            {save.isPending || runTest.isPending ? <Spinner small /> : null}
          </div>
        </div>
      </section>
    </form>
  )
}
