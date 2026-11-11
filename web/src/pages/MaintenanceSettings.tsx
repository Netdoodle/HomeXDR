// Settings → Maintenance: name the SSH keys used for maintenance, and quiet the alerts
// raised by their sessions and by container updates.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import { errorMessage } from '../api/client'
import { noiseKeys } from '../api/noise'
import { getMaintenance, maintenanceKeys, putMaintenance, type MaintenanceInput, type MaintenanceView } from '../api/maintenance'
import { useCan } from '../components/Auth'
import { CopyButton, RelTime, Toggle } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { formatDateTime } from '../lib/time'

export function MaintenanceTab() {
  const q = useQuery({ queryKey: maintenanceKeys.view, queryFn: getMaintenance })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <MaintenanceForm key={JSON.stringify(q.data)} view={q.data} />
}

const DURATIONS: { label: string; hours: number }[] = [
  { label: 'Until turned off', hours: 0 },
  { label: 'For 1 hour', hours: 1 },
  { label: 'For 8 hours', hours: 8 },
  { label: 'For 24 hours', hours: 24 },
  { label: 'For 7 days', hours: 168 },
]

type Row = { maintenance: boolean; hours: number; expires_at?: string }

const searchFor = (field: string, value: string) => `/search?q=${encodeURIComponent(`${field}:"${value}"`)}`

function Until({ row, onChange, disabled }: { row: Row; onChange: (r: Row) => void; disabled: boolean }) {
  if (!row.maintenance) return null
  return (
    <select
      className="input"
      style={{ width: 'auto' }}
      value={row.expires_at && row.hours === -1 ? -1 : row.hours}
      disabled={disabled}
      onChange={(e) => onChange({ ...row, hours: Number(e.target.value) })}
      aria-label="How long"
    >
      {row.expires_at ? <option value={-1}>Until {formatDateTime(row.expires_at)}</option> : null}
      {DURATIONS.map((d) => (
        <option key={d.hours} value={d.hours}>
          {d.label}
        </option>
      ))}
    </select>
  )
}

const endOf = (r: Row): string | undefined => {
  if (!r.maintenance) return undefined
  if (r.hours === -1) return r.expires_at
  if (r.hours === 0) return undefined
  return new Date(Date.now() + r.hours * 3600_000).toISOString()
}

function MaintenanceForm({ view }: { view: MaintenanceView }) {
  const qc = useQueryClient()
  const toast = useToast()
  const isAdmin = useCan('admin')
  const [names, setNames] = useState<Record<string, string>>(() => Object.fromEntries(view.ssh_keys.map((k) => [k.fingerprint, k.name])))
  const [keys, setKeys] = useState<Record<string, Row>>(() =>
    Object.fromEntries(view.ssh_keys.map((k) => [k.fingerprint, { maintenance: k.maintenance, hours: k.expires_at ? -1 : 0, expires_at: k.expires_at }])),
  )
  const [sources, setSources] = useState<Record<string, Row>>(() =>
    Object.fromEntries(view.sources.map((s) => [s.id, { maintenance: s.maintenance, hours: s.expires_at ? -1 : 0, expires_at: s.expires_at }])),
  )
  const [minutes, setMinutes] = useState(view.container_start_minutes)

  const save = useMutation({
    mutationFn: () => {
      const input: MaintenanceInput = {
        ssh_keys: view.ssh_keys.map((k) => ({
          fingerprint: k.fingerprint,
          name: names[k.fingerprint] ?? '',
          maintenance: keys[k.fingerprint].maintenance,
          expires_at: endOf(keys[k.fingerprint]),
        })),
        sources: view.sources.map((s) => ({ id: s.id, maintenance: sources[s.id].maintenance, expires_at: endOf(sources[s.id]) })),
        container_start_minutes: minutes,
      }
      return putMaintenance(input)
    },
    onSuccess: (v) => {
      qc.setQueryData(maintenanceKeys.view, v)
      qc.invalidateQueries({ queryKey: noiseKeys.suppressions })
      toast.success('Maintenance settings saved')
    },
  })

  return (
    <div className="stack" style={{ gap: 16 }}>
      <section className="panel">
        <div className="panel-header">
          <h2>SSH keys</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 12 }}>
          <p className="small muted" style={{ margin: 0 }}>
            Agents tag every command with the SSH session it came from and the key that session logged in with. Name the keys you use for maintenance,
            such as a backup job or an automation account. Its commands then show the name as <code>labels.ssh_key_name</code>. Turn on maintenance to
            close the alerts its sessions raise. This is an ordinary suppression on that key, listed under{' '}
            <Link to="/settings/suppressions">Suppressions</Link>. Must-alert rules and critical alerts still alert.
          </p>
          {view.ssh_keys.length === 0 ? (
            <div className="callout small">
              No key logins in the last {view.days} days. Keys appear here after a key login on a host whose agent reads its SSH log (Linux auth log or
              syslog, Windows OpenSSH/Operational).
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Name</th>
                    <th>Seen</th>
                    <th>Maintenance</th>
                  </tr>
                </thead>
                <tbody>
                  {view.ssh_keys.map((k) => {
                    const row = keys[k.fingerprint]
                    return (
                      <tr key={k.fingerprint}>
                        <td style={{ maxWidth: 260 }}>
                          <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                            <span className="mono xsmall" style={{ wordBreak: 'break-all' }}>
                              {k.fingerprint}
                            </span>
                            <CopyButton text={k.fingerprint} label="" small />
                          </div>
                          <Link className="xsmall" to={searchFor('labels.ssh_key', k.fingerprint)}>
                            Its commands
                          </Link>
                        </td>
                        <td>
                          <input
                            className="input"
                            value={names[k.fingerprint] ?? ''}
                            placeholder="Name this key"
                            maxLength={80}
                            disabled={!isAdmin}
                            onChange={(e) => setNames({ ...names, [k.fingerprint]: e.target.value })}
                          />
                        </td>
                        <td className="small">
                          <div>
                            {formatNumber(k.logins)} logins{k.last_login ? <>, last <RelTime iso={k.last_login} /></> : null}
                          </div>
                          <div className="muted xsmall">
                            {(k.users ?? []).join(', ')} on {(k.hosts ?? []).join(', ') || 'unknown'} from {(k.sources ?? []).join(', ') || 'unknown'}
                          </div>
                        </td>
                        <td>
                          <div className="stack" style={{ gap: 6 }}>
                            <span className="row" style={{ gap: 8, flexWrap: 'nowrap' }}>
                              <Toggle
                                checked={row.maintenance}
                                onChange={(on) => setKeys({ ...keys, [k.fingerprint]: { ...row, maintenance: on } })}
                                label="Quiet the alerts from this key's sessions"
                                disabled={!isAdmin}
                              />
                              <span className="small">{row.maintenance ? 'Quiet its alerts' : 'Off'}</span>
                            </span>
                            <Until row={row} disabled={!isAdmin} onChange={(r) => setKeys({ ...keys, [k.fingerprint]: r })} />
                            {k.maintenance ? <span className="xsmall muted">{formatNumber(k.suppressed)} alerts suppressed</span> : null}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Container updates</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 14 }}>
          <p className="small muted" style={{ margin: 0 }}>
            Updating or restarting containers runs scripts that look like attacks: edits under <code>/etc</code>, downloads into <code>/tmp</code>,
            background jobs. Agents tag what Unraid's Docker manager and the appdata backup start (<code>labels.maintenance</code>), and HomeXDR tags
            the first minutes of every new container. Quiet each one here.
          </p>
          {view.sources.map((s) => {
            const row = sources[s.id]
            return (
              <div key={s.id} className="stack" style={{ gap: 6 }}>
                <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
                  <Toggle checked={row.maintenance} onChange={(on) => setSources({ ...sources, [s.id]: { ...row, maintenance: on } })} label={s.title} disabled={!isAdmin} />
                  <strong className="small">{s.title}</strong>
                  <Until row={row} disabled={!isAdmin} onChange={(r) => setSources({ ...sources, [s.id]: r })} />
                  {s.maintenance ? <span className="xsmall muted">{formatNumber(s.suppressed)} alerts suppressed</span> : null}
                  <Link className="xsmall" to={searchFor('labels.maintenance', s.id)}>
                    Tagged events
                  </Link>
                </div>
                <span className="xsmall muted">{s.help}</span>
              </div>
            )
          })}
          <label className="field" style={{ maxWidth: 260 }}>
            <span className="label">Container start-up lasts (minutes)</span>
            <input className="input" type="number" min={1} max={120} value={minutes} disabled={!isAdmin} onChange={(e) => setMinutes(Number(e.target.value))} />
          </label>
        </div>
      </section>

      {save.isError ? <div className="callout danger small">{errorMessage(save.error)}</div> : null}
      {isAdmin ? (
        <div>
          <button className="btn primary" type="button" disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? <Spinner /> : null} Save
          </button>
        </div>
      ) : (
        <p className="small muted">Changing these needs the admin role.</p>
      )}
    </div>
  )
}
