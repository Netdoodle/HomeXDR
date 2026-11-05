// Settings > Notifications: where alerts go, how often, and whether they got there.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState, type FormEvent } from 'react'
import { getNotifySettings, notifyKeys, putNotifySettings, testNotifyChannel, type ChannelKind, type NotifyRoute, type NotifySettings } from '../api/notifications'
import { Icon } from '../components/Icon'
import { RelTime, Toggle } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import {
  CHANNEL_KINDS,
  channelProblem,
  draftFromSettings,
  newChannelDraft,
  ROUTE_LABELS,
  ROUTED_SEVERITIES,
  updateFromDraft,
  type ChannelDraft,
  type NotifyDraft,
} from '../lib/notifications'
import { SEVERITY_LABEL } from '../lib/severity'
import { formatDateTime } from '../lib/time'

export function NotificationsTab() {
  const q = useQuery({ queryKey: notifyKeys.settings, queryFn: getNotifySettings, refetchOnWindowFocus: false })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="stack" style={{ maxWidth: 980 }}>
      <Form settings={q.data} />
      <DeliveryStatus settings={q.data} />
    </div>
  )
}

function Form({ settings }: { settings: NotifySettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [draft, setDraft] = useState<NotifyDraft>(() => draftFromSettings(settings))
  const [savedJson, setSavedJson] = useState(() => JSON.stringify(updateFromDraft(draftFromSettings(settings))))
  const update = useMemo(() => updateFromDraft(draft), [draft])
  const dirty = JSON.stringify(update) !== savedJson

  const save = useMutation({
    mutationFn: () => putNotifySettings(update),
    onSuccess: (s) => {
      qc.setQueryData(notifyKeys.settings, s)
      qc.invalidateQueries({ queryKey: notifyKeys.status })
      const next = draftFromSettings(s) // this also empties the secret fields
      setDraft(next)
      setSavedJson(JSON.stringify(updateFromDraft(next)))
      toast.success('Notification settings saved')
    },
    onError: (e) => toast.error(e),
  })

  const set = (p: Partial<NotifyDraft>) => setDraft((d) => ({ ...d, ...p }))
  const setChannel = (key: string, p: Partial<ChannelDraft>) =>
    setDraft((d) => ({ ...d, channels: d.channels.map((c) => (c.key === key ? { ...c, ...p } : c)) }))
  const rate = Number(draft.ratePerHour)
  const rateValid = Number.isInteger(rate) && rate >= 1 && rate <= 1000
  const problem = draft.channels.map(channelProblem).find(Boolean) ?? (rateValid ? null : 'The rate cap must be between 1 and 1000.')

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!problem) save.mutate()
  }

  return (
    <form className="stack" onSubmit={submit}>
      <section className="panel">
        <div className="panel-header">
          <h2>Channels</h2>
          <span className="hint">Nothing is sent until you add a channel</span>
        </div>
        <div className="panel-body stack">
          {draft.channels.length === 0 ? (
            <p className="small muted" style={{ margin: 0 }}>
              No channels yet, so notifications are off. Add one below.
            </p>
          ) : null}
          {draft.channels.map((c) => (
            <ChannelEditor
              key={c.key}
              channel={c}
              dirty={dirty}
              onChange={(p) => setChannel(c.key, p)}
              onRemove={() => set({ channels: draft.channels.filter((x) => x.key !== c.key) })}
            />
          ))}
          <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {CHANNEL_KINDS.map((k) => (
              <button
                key={k.kind}
                type="button"
                className="btn sm"
                onClick={() => set({ channels: [...draft.channels, newChannelDraft(k.kind as ChannelKind)] })}
              >
                <Icon name="plus" size={12} /> {k.label}
              </button>
            ))}
          </div>
          <p className="xsmall muted" style={{ margin: 0 }}>
            URLs, tokens and passwords are stored on the server and never shown again. Links and addresses in messages are made inert (hxxp, [.]), so nothing from a
            monitored system turns into something you can tap.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Routing</h2>
          <span className="hint">Where each new alert goes. Suppressed alerts never notify.</span>
        </div>
        <div className="panel-body stack">
          <div className="form-grid">
            {ROUTED_SEVERITIES.map((sev) => (
              <div className="field" key={sev}>
                <label htmlFor={`route-${sev}`}>{SEVERITY_LABEL[sev]}</label>
                <RouteSelect
                  id={`route-${sev}`}
                  value={draft.severityRoutes[sev] ?? 'log'}
                  onChange={(v) => set({ severityRoutes: { ...draft.severityRoutes, [sev]: v } })}
                />
              </div>
            ))}
            <div className="field">
              <label htmlFor="notify-rate">Alerts now, at most per hour</label>
              <input
                id="notify-rate"
                className={rateValid ? 'input' : 'input invalid'}
                inputMode="numeric"
                value={draft.ratePerHour}
                onChange={(e) => set({ ratePerHour: e.target.value.trim() })}
              />
              <span className="help">The rest go to the digest, with one message to say so. A flood cannot melt your phone.</span>
            </div>
          </div>
          <div className="field">
            <span className="label">Exceptions by rule ID</span>
            <div className="stack" style={{ gap: 6 }}>
              {draft.ruleRoutes.map((r, i) => (
                <div className="row" style={{ gap: 6 }} key={i}>
                  <input
                    className="input mono small"
                    style={{ flex: '1 1 240px' }}
                    aria-label="Rule ID starts with"
                    placeholder="health:"
                    value={r.prefix}
                    onChange={(e) => set({ ruleRoutes: draft.ruleRoutes.map((x, j) => (j === i ? { ...x, prefix: e.target.value } : x)) })}
                  />
                  <RouteSelect value={r.route} onChange={(v) => set({ ruleRoutes: draft.ruleRoutes.map((x, j) => (j === i ? { ...x, route: v } : x)) })} />
                  <button
                    type="button"
                    className="btn ghost icon sm"
                    aria-label="Remove exception"
                    onClick={() => set({ ruleRoutes: draft.ruleRoutes.filter((_, j) => j !== i) })}
                  >
                    <Icon name="close" size={12} />
                  </button>
                </div>
              ))}
              <div>
                <button type="button" className="btn sm" onClick={() => set({ ruleRoutes: [...draft.ruleRoutes, { prefix: '', route: 'now' }] })}>
                  <Icon name="plus" size={12} /> Add exception
                </button>
              </div>
            </div>
            <span className="help">
              Rules whose ID starts with this go here, whatever their severity. The longest match wins. For example <span className="mono">health:</span> or{' '}
              <span className="mono">net:new-device</span>.
            </span>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Daily digest</h2>
          <span className="row small">
            <Toggle checked={draft.digestEnabled} onChange={(v) => set({ digestEnabled: v })} label="Send a daily digest" />
          </span>
        </div>
        <div className="panel-body stack">
          <p className="small muted" style={{ margin: 0 }}>
            A summary of the last day: counts by rule and severity, what repeated, what was suppressed and what the AI analyst said.
          </p>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="digest-time">Send at</label>
              <input id="digest-time" className="input" type="time" value={draft.digestTime} onChange={(e) => set({ digestTime: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor="digest-zone">Time zone</label>
              <input id="digest-zone" className="input" placeholder="Server's own" value={draft.timezone} onChange={(e) => set({ timezone: e.target.value })} />
              <span className="help">A name like Europe/Prague. Blank uses the server's zone, which in a container is often UTC.</span>
            </div>
            <div className="field">
              <label htmlFor="console-url">Console address</label>
              <input
                id="console-url"
                className="input"
                placeholder="https://xdr.example.com"
                value={draft.consoleUrl}
                onChange={(e) => set({ consoleUrl: e.target.value })}
              />
              <span className="help">Used for the link back to an alert in every message. Blank leaves links out.</span>
            </div>
          </div>
          <label className="row small">
            <input type="checkbox" checked={draft.heartbeat} onChange={(e) => set({ heartbeat: e.target.checked })} />
            <span>Send it even when there is nothing to say, so silence never means something is broken.</span>
          </label>
        </div>
      </section>

      <div className="row">
        <button type="submit" className="btn primary" disabled={!!problem || !dirty || save.isPending}>
          {save.isPending ? <Spinner small /> : null} Save
        </button>
        {problem && dirty ? <span className="small muted">{problem}</span> : null}
      </div>
    </form>
  )
}

function RouteSelect({ id, value, onChange }: { id?: string; value: NotifyRoute; onChange: (v: NotifyRoute) => void }) {
  return (
    <select id={id} className="select" aria-label={id ? undefined : 'Where it goes'} value={value} onChange={(e) => onChange(e.target.value as NotifyRoute)}>
      {ROUTE_LABELS.map((r) => (
        <option key={r.value} value={r.value}>
          {r.label}
        </option>
      ))}
    </select>
  )
}

function ChannelEditor({
  channel: c,
  dirty,
  onChange,
  onRemove,
}: {
  channel: ChannelDraft
  dirty: boolean
  onChange: (p: Partial<ChannelDraft>) => void
  onRemove: () => void
}) {
  const toast = useToast()
  const info = CHANNEL_KINDS.find((k) => k.kind === c.kind)!
  const test = useMutation({
    mutationFn: () => testNotifyChannel(c.id!),
    onSuccess: (r) => {
      if (r.ok) toast.success(`Test message sent to ${c.name}`)
      else toast.error(new Error(r.error ?? 'The test failed'))
    },
    onError: (e) => toast.error(e),
  })
  const fieldId = (f: string) => `${c.key}-${f}`
  return (
    <div className="panel" style={{ padding: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 10 }}>
        <span className="row small" style={{ gap: 8 }}>
          <Toggle checked={c.enabled} onChange={(v) => onChange({ enabled: v })} label={`${c.enabled ? 'Turn off' : 'Turn on'} ${c.name}`} />
          <strong>{info.label}</strong>
          {c.saved?.url_host ? <span className="muted mono xsmall">{c.saved.url_host}</span> : null}
        </span>
        <span className="row" style={{ gap: 6 }}>
          <button
            type="button"
            className="btn sm"
            disabled={!c.id || dirty || test.isPending}
            title={!c.id || dirty ? 'Save first: this tests what is saved' : 'Send a test message now'}
            onClick={() => test.mutate()}
          >
            {test.isPending ? <Spinner small /> : <Icon name="play" size={12} />} Send test
          </button>
          <button type="button" className="btn ghost icon sm" aria-label={`Remove ${c.name}`} onClick={onRemove}>
            <Icon name="trash" size={14} />
          </button>
        </span>
      </div>
      <div className="form-grid">
        <div className="field">
          <label htmlFor={fieldId('name')}>Name</label>
          <input id={fieldId('name')} className="input" value={c.name} onChange={(e) => onChange({ name: e.target.value })} />
        </div>
        {c.kind === 'email' ? (
          <>
            <div className="field">
              <label htmlFor={fieldId('host')}>Mail server</label>
              <input id={fieldId('host')} className="input" placeholder="smtp.example.com" value={c.smtpHost} onChange={(e) => onChange({ smtpHost: e.target.value })} />
              <span className="help">It must offer STARTTLS. HomeXDR will not send mail in the clear.</span>
            </div>
            <div className="field">
              <label htmlFor={fieldId('port')}>Port</label>
              <input id={fieldId('port')} className="input" inputMode="numeric" value={c.smtpPort} onChange={(e) => onChange({ smtpPort: e.target.value.trim() })} />
            </div>
            <div className="field">
              <label htmlFor={fieldId('user')}>Username</label>
              <input id={fieldId('user')} className="input" autoComplete="off" placeholder="Optional" value={c.smtpUser} onChange={(e) => onChange({ smtpUser: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor={fieldId('password')}>Password</label>
              <input
                id={fieldId('password')}
                className="input"
                type="password"
                autoComplete="new-password"
                placeholder={c.clearPassword ? 'Will be removed' : c.saved?.password_set ? 'Saved; type to replace' : 'Optional'}
                value={c.password}
                onChange={(e) => onChange({ password: e.target.value, clearPassword: false })}
              />
              {c.saved?.password_set && !c.clearPassword ? (
                <button type="button" className="link-button xsmall" style={{ alignSelf: 'flex-start' }} onClick={() => onChange({ clearPassword: true, password: '' })}>
                  Remove password
                </button>
              ) : null}
            </div>
            <div className="field">
              <label htmlFor={fieldId('from')}>From</label>
              <input id={fieldId('from')} className="input" placeholder="homexdr@example.com" value={c.from} onChange={(e) => onChange({ from: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor={fieldId('to')}>To</label>
              <input id={fieldId('to')} className="input" placeholder="you@example.com, other@example.com" value={c.to} onChange={(e) => onChange({ to: e.target.value })} />
            </div>
          </>
        ) : (
          <>
            <div className="field" style={{ gridColumn: 'span 2' }}>
              <label htmlFor={fieldId('url')}>{info.urlLabel}</label>
              <input
                id={fieldId('url')}
                className="input mono"
                type="password"
                autoComplete="off"
                placeholder={c.saved?.url_set ? 'Saved; type to replace' : 'https://'}
                value={c.url}
                onChange={(e) => onChange({ url: e.target.value })}
              />
              <span className="help">{info.urlHelp}</span>
            </div>
            {c.kind !== 'discord' ? (
              <div className="field">
                <label htmlFor={fieldId('token')}>Bearer token</label>
                <input
                  id={fieldId('token')}
                  className="input mono"
                  type="password"
                  autoComplete="off"
                  placeholder={c.clearToken ? 'Will be removed' : c.saved?.token_set ? 'Saved; type to replace' : 'Optional'}
                  value={c.token}
                  onChange={(e) => onChange({ token: e.target.value, clearToken: false })}
                />
                {c.saved?.token_set && !c.clearToken ? (
                  <button type="button" className="link-button xsmall" style={{ alignSelf: 'flex-start' }} onClick={() => onChange({ clearToken: true, token: '' })}>
                    Remove token
                  </button>
                ) : null}
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  )
}

function DeliveryStatus({ settings }: { settings: NotifySettings }) {
  const q = useQuery({
    queryKey: notifyKeys.status,
    queryFn: async () => (await getNotifySettings()).status,
    initialData: settings.status,
    refetchInterval: 30_000,
  })
  const s = q.data
  const names = new Map(settings.channels.map((c) => [c.id, c.name]))
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Delivery status</h2>
      </div>
      <div className="panel-body stack">
        <div className="stats">
          <div className="stat">
            <span className="label">Sent, last 24 hours</span>
            <span className="value">{formatNumber(s.sent_24h)}</span>
            <span className="sub">{s.last_sent_at ? <>Last <RelTime iso={s.last_sent_at} /></> : 'Nothing sent yet'}</span>
          </div>
          <div className="stat">
            <span className="label">Waiting to send</span>
            <span className="value">{formatNumber(s.pending)}</span>
            <span className="sub">Retried for about four hours</span>
          </div>
          <div className="stat">
            <span className="label">Gave up, last 24 hours</span>
            <span className="value">{formatNumber(s.failed_24h)}</span>
            <span className="sub">After every retry failed</span>
          </div>
          <div className="stat">
            <span className="label">Over the cap, last hour</span>
            <span className="value">{formatNumber(s.overflow_1h)}</span>
            <span className="sub">Going to the digest</span>
          </div>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Next digest: {s.next_digest_at ? formatDateTime(s.next_digest_at) : 'none scheduled'}. Last digest check:{' '}
          {s.last_digest_at ? formatDateTime(s.last_digest_at) : 'not yet'}.
        </p>
        {s.recent_failures.length > 0 ? (
          <div className="table-wrap">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Message</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {s.recent_failures.map((f) => (
                  <tr key={f.id}>
                    <td>{names.get(f.channel_id) ?? f.channel_id}</td>
                    <td style={{ overflowWrap: 'anywhere' }}>
                      {f.title}
                      <div className="xsmall faint">
                        <RelTime iso={f.created_at} />
                      </div>
                    </td>
                    <td>{f.status === 'pending' ? `Retrying, ${f.attempts} tried` : `Gave up after ${f.attempts}`}</td>
                    <td className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>
                      {f.last_error}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>
            No recent failures.
          </p>
        )}
      </div>
    </section>
  )
}
