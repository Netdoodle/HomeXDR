// Settings → Threat intel: which services Investigate asks, their API keys, and what stays local.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { api, queryKeys, type IntelSettings, type IntelSettingsUpdate } from '../api'
import { errorMessage } from '../api/client'
import { Icon } from '../components/Icon'
import { Toggle } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { CACHE_CHOICES, KIND_LABEL } from '../lib/intel'

export function ThreatIntelTab() {
  const q = useQuery({ queryKey: queryKeys.intelSettings, queryFn: api.getIntelSettings })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <Form settings={q.data} />
}

type Draft = Record<string, { enabled: boolean; key: string; clear: boolean }>

function draftOf(s: IntelSettings): Draft {
  return Object.fromEntries(s.providers.map((p) => [p.id, { enabled: p.enabled, key: '', clear: false }]))
}

function Form({ settings }: { settings: IntelSettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [draft, setDraft] = useState<Draft>(() => draftOf(settings))
  const [cache, setCache] = useState(settings.cache_hours)
  const [ai, setAI] = useState(settings.ai_access)
  const [domains, setDomains] = useState(settings.internal_domains.join('\n'))
  useEffect(() => setDraft(draftOf(settings)), [settings])
  const save = useMutation({
    mutationFn: (u: IntelSettingsUpdate) => api.putIntelSettings(u),
    onSuccess: (s) => {
      qc.setQueryData(queryKeys.intelSettings, s)
      qc.invalidateQueries({ queryKey: ['intel'] })
      toast.success('Threat intel settings saved')
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const providers: IntelSettingsUpdate['providers'] = {}
    for (const p of settings.providers) {
      const d = draft[p.id]
      providers[p.id] = { enabled: d.enabled, ...(d.key.trim() ? { key: d.key.trim() } : {}), ...(d.clear ? { clear_key: true } : {}) }
    }
    save.mutate({
      providers,
      cache_hours: cache,
      ai_access: ai,
      internal_domains: domains
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter(Boolean),
    })
  }
  const set = (id: string, p: Partial<Draft[string]>) => setDraft((d) => ({ ...d, [id]: { ...d[id], ...p } }))

  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: 980 }}>
      <section className="panel">
        <div className="panel-header">
          <h2>Services</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 4 }}>
          <p className="small muted" style={{ margin: 0 }}>
            A lookup sends the indicator to each service switched on here. Services are only asked when someone investigates an indicator, or when the AI analyst does. API keys are stored
            on the server, sent only to their own service, and never shown again.
          </p>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 64 }}>On</th>
                <th>Service</th>
                <th style={{ width: 320 }}>API key</th>
              </tr>
            </thead>
            <tbody>
              {settings.providers.map((p) => {
                const d = draft[p.id] ?? { enabled: p.enabled, key: '', clear: false }
                return (
                  <tr key={p.id}>
                    <td>
                      <Toggle checked={d.enabled} onChange={(v) => set(p.id, { enabled: v })} label={`${d.enabled ? 'Turn off' : 'Turn on'} ${p.name}`} />
                    </td>
                    <td className="small">
                      <strong>{p.name}</strong>
                      <div className="muted">{p.about}</div>
                      <div className="xsmall muted">
                        {p.kinds.map((k) => KIND_LABEL[k]).join(', ')}
                        {p.free ? ` · ${p.free}` : ''}
                      </div>
                    </td>
                    <td className="small">
                      {p.key_mode === 'none' ? (
                        <span className="muted">No key needed</span>
                      ) : (
                        <div className="stack" style={{ gap: 4 }}>
                          <input
                            className="input mono"
                            type="password"
                            autoComplete="off"
                            value={d.key}
                            onChange={(e) => set(p.id, { key: e.target.value, clear: false })}
                            aria-label={`${p.name} API key`}
                            placeholder={d.clear ? 'Will be removed' : p.key_set ? `Set (${p.key_hint ?? 'hidden'}); type to replace` : p.key_mode === 'required' ? 'Required' : 'Optional: raises the quota'}
                          />
                          <span className="row xsmall" style={{ gap: 10 }}>
                            {p.key_url ? (
                              <a href={p.key_url} target="_blank" rel="noreferrer noopener">
                                Get a free key <Icon name="external" size={10} />
                              </a>
                            ) : null}
                            {p.key_set && !d.clear ? (
                              <button type="button" className="link-button" onClick={() => set(p.id, { clear: true, key: '' })}>
                                Remove key
                              </button>
                            ) : null}
                          </span>
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Lookups</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 14 }}>
          <label className="field">
            <span className="label">Reuse answers for</span>
            <select className="select" style={{ maxWidth: 200 }} value={cache} onChange={(e) => setCache(Number(e.target.value))}>
              {CACHE_CHOICES.some((c) => c.hours === cache) ? null : <option value={cache}>{cache} hours</option>}
              {CACHE_CHOICES.map((c) => (
                <option key={c.hours} value={c.hours}>
                  {c.label}
                </option>
              ))}
            </select>
            <span className="help">Saves your daily quotas. Re-check on the Investigate page always asks again.</span>
          </label>
          <div className="field">
            <span className="label">AI analyst</span>
            <label className="row small" style={{ gap: 8 }}>
              <Toggle checked={ai} onChange={setAI} label="Let the AI analyst look up indicators" />
              Let the AI analyst look up indicators during investigations
            </label>
            <span className="help">
              It can only read: it uses the services above and saved answers, and cannot change anything. Lookups it makes use your quotas and appear in the audit log as ai-analyst.
            </span>
          </div>
          <label className="field">
            <span className="label">Internal domains</span>
            <textarea className="textarea code" rows={3} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.org" spellCheck={false} />
            <span className="help">
              One per line. These domains and their subdomains are never sent to any service, like private addresses and names such as .local and .lan.
            </span>
          </label>
        </div>
      </section>
      {save.isError ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>{errorMessage(save.error)}</span>
        </div>
      ) : null}
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button type="submit" className="btn primary" disabled={save.isPending}>
          {save.isPending ? <Spinner small /> : null} Save
        </button>
      </div>
    </form>
  )
}
