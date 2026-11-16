import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type ReactNode } from 'react'
import { api, errorMessage, queryKeys, type AgentConfig } from '../api'
import { useCan } from '../components/Auth'
import { Icon } from '../components/Icon'
import { ButtonTabs, Toggle } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatBytes, prettyJSON } from '../lib/format'
import { DECOY_DEFAULTS, DECOY_MIN_INTERVAL, validateAgentConfig } from '../lib/agentConfig'

const MiB = 1024 * 1024
const lines = (xs?: string[]) => (xs ?? []).join('\n')
const unlines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean)

function Section({ title, children, hint }: { title: string; children: ReactNode; hint?: string }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
        {hint ? <span className="hint">{hint}</span> : null}
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        {children}
      </div>
    </section>
  )
}

function NumberField({
  id,
  label,
  value,
  onChange,
  help,
  disabled,
  min = 0,
}: {
  id: string
  label: string
  value: number
  onChange: (n: number) => void
  help?: string
  disabled?: boolean
  min?: number
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} className="input" type="number" min={min} value={Number.isFinite(value) ? value : ''} disabled={disabled} onChange={(e) => onChange(e.target.value === '' ? NaN : Number(e.target.value))} />
      {help ? <span className="help">{help}</span> : null}
    </div>
  )
}

function SensorToggle({ label, checked, onChange, disabled, note }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; note?: string }) {
  return (
    <label className="row nowrap" style={{ gap: 10, cursor: disabled ? 'default' : 'pointer' }}>
      <Toggle checked={checked} onChange={onChange} disabled={disabled} label={label} />
      <span>{label}</span>
      {note ? <span className="xsmall muted">{note}</span> : null}
    </label>
  )
}

export function AgentConfigEditor() {
  const isAdmin = useCan('admin')
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: queryKeys.agentConfig, queryFn: api.getAgentConfig })
  const [draft, setDraft] = useState<AgentConfig | null>(null)
  const [mode, setMode] = useState<'form' | 'json'>('form')
  const [json, setJson] = useState('')
  const [jsonError, setJsonError] = useState<string | null>(null)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    if (q.data && draft === null) setDraft(structuredClone(q.data))
  }, [q.data, draft])

  const save = useMutation({
    mutationFn: (c: AgentConfig) => api.putAgentConfig(c),
    onSuccess: (c) => {
      qc.setQueryData(queryKeys.agentConfig, c)
      setDraft(structuredClone(c))
      toast.success(`Agent config saved as version ${c.version}`)
    },
  })

  if (q.isPending || (q.data && !draft)) return <Loading />
  if (q.isError) return <div className="panel"><ErrorState error={q.error} onRetry={() => q.refetch()} /></div>
  const c = draft!
  const ro = !isAdmin
  const dirty = JSON.stringify(c) !== JSON.stringify(q.data)
  const problems = validateAgentConfig(c)
  const dc = c.decoys ?? DECOY_DEFAULTS
  const set = (fn: (d: AgentConfig) => void) => {
    const n = structuredClone(c)
    fn(n)
    setDraft(n)
  }

  const switchMode = (m: string) => {
    if (m === 'json') {
      setJson(prettyJSON(c))
      setJsonError(null)
      setMode('json')
      return
    }
    try {
      const parsed = JSON.parse(json) as AgentConfig
      setDraft(parsed)
      setJsonError(null)
      setMode('form')
    } catch (e) {
      setJsonError(errorMessage(e))
    }
  }

  return (
    <div className="stack">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="small muted">
          Default configuration for agents without a per-host override · version <strong className="mono">{q.data!.version}</strong>
          {ro ? ' · read-only (admin role required to change it)' : ''}
        </div>
        <div className="row">
          {dirty && !ro ? (
            <button type="button" className="btn" onClick={() => setDraft(structuredClone(q.data!))}>
              Discard changes
            </button>
          ) : null}
          {!ro ? (
            <button type="button" className="btn primary" disabled={!dirty || problems.length > 0 || mode === 'json' || save.isPending} onClick={() => setConfirm(true)} title={mode === 'json' ? 'Switch back to the form to apply JSON edits first' : undefined}>
              {save.isPending ? <Spinner small /> : null} Save and push to agents
            </button>
          ) : null}
        </div>
      </div>
      {problems.length ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>{problems.join(' ')}</span>
        </div>
      ) : null}
      {save.isError ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>{errorMessage(save.error)}</span>
        </div>
      ) : null}
      <ButtonTabs
        active={mode}
        onChange={switchMode}
        tabs={[
          { id: 'form', label: 'Form' },
          { id: 'json', label: 'JSON' },
        ]}
      />
      {mode === 'json' ? (
        <section className="panel">
          <div className="panel-body stack" style={{ gap: 8 }}>
            <textarea className={jsonError ? 'textarea code invalid' : 'textarea code'} style={{ width: '100%', minHeight: 520 }} value={json} onChange={(e) => setJson(e.target.value)} readOnly={ro} spellCheck={false} aria-label="Agent config JSON" />
            {jsonError ? <span className="xsmall danger-text">Invalid JSON: {jsonError}</span> : <span className="xsmall muted">Switch back to Form to apply these edits. The version field is set by the server.</span>}
          </div>
        </section>
      ) : (
        <div className="grid grid-2" style={{ alignItems: 'start' }}>
          <div className="stack">
            <Section title="Agent">
              <div className="form-grid">
                <NumberField id="hb" label="Heartbeat interval (s)" value={c.heartbeat_interval_sec} min={5} disabled={ro} onChange={(n) => set((d) => (d.heartbeat_interval_sec = n))} help="A host is offline after 3 missed heartbeats." />
                <NumberField id="inv" label="Inventory interval (s)" value={c.inventory_interval_sec} disabled={ro} onChange={(n) => set((d) => (d.inventory_interval_sec = n))} />
                <NumberField id="bme" label="Batch max events" value={c.batch.max_events} min={1} disabled={ro} onChange={(n) => set((d) => (d.batch.max_events = n))} />
                <NumberField id="bfi" label="Batch flush interval (ms)" value={c.batch.flush_interval_ms} min={100} disabled={ro} onChange={(n) => set((d) => (d.batch.flush_interval_ms = n))} />
                <NumberField
                  id="spool"
                  label="Disk spool limit (MiB)"
                  value={Math.round(c.spool_max_bytes / MiB)}
                  min={16}
                  disabled={ro}
                  onChange={(n) => set((d) => (d.spool_max_bytes = n * MiB))}
                  help={`Oldest events are dropped beyond ${formatBytes(c.spool_max_bytes)}.`}
                />
              </div>
            </Section>
            <Section title="Sensors">
              <SensorToggle label="Process" checked={c.sensors.process.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.process.enabled = v))} />
              <div style={{ paddingLeft: 42 }}>
                <label className="checkbox">
                  <input type="checkbox" checked={c.sensors.process.hash_executables} disabled={ro || !c.sensors.process.enabled} onChange={(e) => set((d) => (d.sensors.process.hash_executables = e.target.checked))} />
                  Hash executables (SHA-256)
                </label>
              </div>
              <SensorToggle label="Network" checked={c.sensors.network.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.network.enabled = v))} />
              <SensorToggle label="DNS" checked={c.sensors.dns.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.dns.enabled = v))} />
              <SensorToggle label="Registry" note="Windows only" checked={c.sensors.registry.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.registry.enabled = v))} />
              <SensorToggle label="Library / DLL loads" note="noisy" checked={c.sensors.library.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.library.enabled = v))} />
              <SensorToggle label="Authentication" note="logons, sudo, ssh" checked={c.sensors.auth.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.auth.enabled = v))} />
              <SensorToggle label="File" checked={c.sensors.file.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.file.enabled = v))} />
              <div className="form-grid" style={{ paddingLeft: 42 }}>
                <div className="field">
                  <label htmlFor="fpaths">Watched paths (one per line)</label>
                  <textarea id="fpaths" className="textarea code" rows={3} value={lines(c.sensors.file.paths)} readOnly={ro} placeholder="empty = platform defaults" onChange={(e) => set((d) => (d.sensors.file.paths = unlines(e.target.value)))} />
                </div>
                <div className="field">
                  <label htmlFor="fexcl">Exclude globs</label>
                  <textarea id="fexcl" className="textarea code" rows={3} value={lines(c.sensors.file.exclude)} readOnly={ro} onChange={(e) => set((d) => (d.sensors.file.exclude = unlines(e.target.value)))} />
                </div>
              </div>
              <SensorToggle label="Windows Event Log" note="Windows only" checked={c.sensors.eventlog.enabled} disabled={ro} onChange={(v) => set((d) => (d.sensors.eventlog.enabled = v))} />
              <div className="field" style={{ paddingLeft: 42 }}>
                <label htmlFor="chans">Channels (one per line)</label>
                <textarea id="chans" className="textarea code" rows={5} value={lines(c.sensors.eventlog.channels)} readOnly={ro} onChange={(e) => set((d) => (d.sensors.eventlog.channels = unlines(e.target.value)))} />
              </div>
            </Section>
          </div>
          <div className="stack">
            <Section title="File integrity monitoring">
              <SensorToggle label="Enabled" checked={c.fim.enabled} disabled={ro} onChange={(v) => set((d) => (d.fim.enabled = v))} />
              <div className="form-grid">
                <NumberField id="fimint" label="Scan interval (s)" value={c.fim.interval_sec} min={60} disabled={ro} onChange={(n) => set((d) => (d.fim.interval_sec = n))} />
                <NumberField id="fimmax" label="Max file size to hash (MiB)" value={Math.round(c.fim.max_file_size / MiB)} disabled={ro} onChange={(n) => set((d) => (d.fim.max_file_size = n * MiB))} />
              </div>
              <div className="form-grid">
                <div className="field">
                  <label htmlFor="fimpaths">Paths</label>
                  <textarea id="fimpaths" className="textarea code" rows={4} value={lines(c.fim.paths)} readOnly={ro} onChange={(e) => set((d) => (d.fim.paths = unlines(e.target.value)))} />
                </div>
                <div className="field">
                  <label htmlFor="fimexcl">Exclude</label>
                  <textarea id="fimexcl" className="textarea code" rows={4} value={lines(c.fim.exclude)} readOnly={ro} onChange={(e) => set((d) => (d.fim.exclude = unlines(e.target.value)))} />
                </div>
              </div>
            </Section>
            <Section title="Decoy files" hint="fake credential files that raise an alert when touched">
              <SensorToggle label="Decoy files" checked={dc.enabled} disabled={ro} onChange={(v) => set((d) => (d.decoys = { ...dc, enabled: v }))} />
              <span className="xsmall muted">
                Agents place a few fake password and credential files in user folders (Documents, Desktop, ~/.aws) and raise a critical alert when one is changed, deleted or renamed; Linux agents also report reads. Turning this off removes the files nobody changed. See docs/decoys.md.
              </span>
              <div className="form-grid">
                <NumberField
                  id="decoyint"
                  label="Check interval (s)"
                  value={dc.check_interval_sec}
                  min={DECOY_MIN_INTERVAL}
                  disabled={ro || !dc.enabled}
                  onChange={(n) => set((d) => (d.decoys = { ...dc, check_interval_sec: n }))}
                  help="Every decoy is checked this often (Linux also in real time)."
                />
              </div>
              <div className="field">
                <label htmlFor="decoyextra">Extra decoy paths (one per line)</label>
                <textarea
                  id="decoyextra"
                  className="textarea code"
                  rows={3}
                  value={lines(dc.extra)}
                  readOnly={ro}
                  disabled={!dc.enabled}
                  placeholder={'/srv/share/passwords.txt\nC:\\Shares\\Finance\\logins.csv'}
                  onChange={(e) => set((d) => (d.decoys = { ...dc, extra: unlines(e.target.value) }))}
                />
                <span className="help">Absolute file paths. Each is created only if its folder exists and no file is there yet.</span>
              </div>
            </Section>
            <Section title="Log files" hint="tailed and forwarded as events">
              {(c.logs ?? []).length === 0 ? <span className="muted small">No log files configured.</span> : null}
              {(c.logs ?? []).map((l, i) => (
                <div key={i} className="row nowrap" style={{ alignItems: 'flex-end' }}>
                  <div className="field grow">
                    {i === 0 ? <label htmlFor={`log-p-${i}`}>Path (globs allowed)</label> : null}
                    <input id={`log-p-${i}`} className="input mono" value={l.path} readOnly={ro} onChange={(e) => set((d) => (d.logs![i].path = e.target.value))} aria-label="Log path" />
                  </div>
                  <div className="field" style={{ width: 100 }}>
                    {i === 0 ? <label htmlFor={`log-f-${i}`}>Format</label> : null}
                    <select id={`log-f-${i}`} className="select" value={l.format ?? 'raw'} disabled={ro} onChange={(e) => set((d) => (d.logs![i].format = e.target.value))} aria-label="Log format">
                      <option value="raw">raw</option>
                      <option value="json">json</option>
                      <option value="syslog">syslog</option>
                    </select>
                  </div>
                  <div className="field" style={{ width: 150 }}>
                    {i === 0 ? <label htmlFor={`log-d-${i}`}>Dataset</label> : null}
                    <input id={`log-d-${i}`} className="input mono" value={l.dataset ?? ''} readOnly={ro} onChange={(e) => set((d) => (d.logs![i].dataset = e.target.value || undefined))} aria-label="Dataset" />
                  </div>
                  {!ro ? (
                    <button type="button" className="btn ghost icon" aria-label="Remove log file" onClick={() => set((d) => d.logs!.splice(i, 1))}>
                      <Icon name="close" size={12} />
                    </button>
                  ) : null}
                </div>
              ))}
              {!ro ? (
                <div>
                  <button type="button" className="btn sm" onClick={() => set((d) => (d.logs = [...(d.logs ?? []), { path: '', format: 'raw' }]))}>
                    <Icon name="plus" size={12} /> Add log file
                  </button>
                </div>
              ) : null}
            </Section>
            <Section title="Agent-side filters" hint="matching events are dropped before they are spooled">
              {(c.filters ?? []).length === 0 ? <span className="muted small">No filters. Every event is sent.</span> : null}
              {(c.filters ?? []).map((f, i) => (
                <div key={i} className="row nowrap" style={{ alignItems: 'flex-end' }}>
                  <div className="field" style={{ width: 110 }}>
                    {i === 0 ? <label>Category</label> : null}
                    <input className="input mono" value={f.category ?? ''} placeholder="any" readOnly={ro} onChange={(e) => set((d) => (d.filters![i].category = e.target.value || undefined))} aria-label="Category" />
                  </div>
                  <div className="field grow">
                    {i === 0 ? <label>Field</label> : null}
                    <input className="input mono" value={f.field} readOnly={ro} onChange={(e) => set((d) => (d.filters![i].field = e.target.value))} aria-label="Field" />
                  </div>
                  <div className="field" style={{ width: 100 }}>
                    {i === 0 ? <label>Op</label> : null}
                    <select className="select" value={f.op} disabled={ro} onChange={(e) => set((d) => (d.filters![i].op = e.target.value))} aria-label="Operator">
                      {['equals', 'prefix', 'suffix', 'contains'].map((o) => (
                        <option key={o} value={o}>
                          {o}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field grow">
                    {i === 0 ? <label>Value</label> : null}
                    <input className="input mono" value={f.value} readOnly={ro} onChange={(e) => set((d) => (d.filters![i].value = e.target.value))} aria-label="Value" />
                  </div>
                  {!ro ? (
                    <button type="button" className="btn ghost icon" aria-label="Remove filter" onClick={() => set((d) => d.filters!.splice(i, 1))}>
                      <Icon name="close" size={12} />
                    </button>
                  ) : null}
                </div>
              ))}
              {!ro ? (
                <div>
                  <button type="button" className="btn sm" onClick={() => set((d) => (d.filters = [...(d.filters ?? []), { field: 'process.executable', op: 'equals', value: '' }]))}>
                    <Icon name="plus" size={12} /> Add filter
                  </button>
                </div>
              ) : null}
            </Section>
          </div>
        </div>
      )}
      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Push the new agent config?"
        confirmLabel="Save and push"
        onConfirm={() => save.mutateAsync(c)}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Save the default agent configuration as version {q.data!.version + 1}.</li>
          <li>Send it to every agent that uses the default config on its next heartbeat (within about {c.heartbeat_interval_sec} seconds).</li>
          <li>Not change which response actions agents allow; that stays in each agent’s local config file.</li>
        </ul>
      </ConfirmDialog>
    </div>
  )
}
