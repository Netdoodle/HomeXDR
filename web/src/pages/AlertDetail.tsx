import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router'
import { ALERT_STATUSES, api, isApiError, queryKeys, type Alert, type AlertPatch, type AlertStatus } from '../api'
import { useCan, useMe, useUser } from '../components/Auth'
import { AITriagePanel } from '../components/AITriage'
import { AlertStatusBadge, MitreTag, OsLabel, RiskScore, SeverityBadge, StatusDot, Tags } from '../components/Badges'
import { EventTable } from '../components/EventTable'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { ExpandableText, KV, RelTime } from '../components/Misc'
import { ResponseButtons } from '../components/ResponseButtons'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { hasRole } from '../lib/roles'
import { ALERT_STATUS_LABEL } from '../lib/severity'
import { formatDateTime } from '../lib/time'

export function AlertDetailPage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: queryKeys.alert(id), queryFn: () => api.getAlert(id) })
  useDocumentTitle(q.data?.rule.title ?? 'Alert')

  if (q.isPending) return <Loading />
  if (q.isError) {
    return (
      <div className="panel">
        {isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState title="Alert not found" action={<Link to="/alerts">Back to alerts</Link>} />
        ) : (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        )}
      </div>
    )
  }
  return <AlertView alert={q.data} />
}

function AlertView({ alert: a }: { alert: Alert }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canTriage = useCan('analyst')
  const user = useUser()
  const hostQ = useQuery({ queryKey: queryKeys.host(a.host_id), queryFn: () => api.getHost(a.host_id) })

  const patch = useMutation({
    mutationFn: (p: AlertPatch) => api.patchAlert(a.id, p),
    onSuccess: (updated) => {
      qc.setQueryData(queryKeys.alert(a.id), (old: Alert | undefined) => ({ ...updated, events: old?.events ?? updated.events }))
      qc.invalidateQueries({ queryKey: queryKeys.alerts() })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
    onError: (e) => toast.error(e),
  })

  const ev = a.event ?? a.events?.[0]
  const treeHref = a.process_entity_id ? `/hosts/${encodeURIComponent(a.host_id)}/process/${encodeURIComponent(a.process_entity_id)}` : undefined

  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/alerts">Alerts</Link>
        <Icon name="chevronRight" size={10} />
        <span className="mono">{a.id}</span>
      </div>
      <PageHeader
        title={
          <span className="row" style={{ gap: 10 }}>
            <SeverityBadge severity={a.severity} />
            <span>{a.rule.title}</span>
          </span>
        }
        subtitle={
          <span className="row" style={{ gap: 14 }}>
            <span>
              on <Link to={`/hosts/${encodeURIComponent(a.host_id)}`}>{a.hostname}</Link>
            </span>
            <span>
              {formatNumber(a.count)} {a.count === 1 ? 'hit' : 'hits'}
            </span>
            <span>
              first <RelTime iso={a.first_seen} />, last <RelTime iso={a.last_seen} />
            </span>
            <RiskScore score={a.risk_score} />
          </span>
        }
        actions={
          <>
            {treeHref ? (
              <Link className="btn" to={treeHref}>
                <Icon name="tree" size={14} /> View process tree
              </Link>
            ) : null}
            {hostQ.data ? (
              <ResponseButtons
                host={hostQ.data}
                process={{ pid: ev?.process?.pid, entity_id: a.process_entity_id, name: a.process_name, ended: !!ev?.process?.end }}
              />
            ) : null}
          </>
        }
      />

      <div className="grid grid-sidebar" style={{ alignItems: 'start' }}>
        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Triage</h2>
              {patch.isPending ? <Spinner small /> : null}
            </div>
            <div className="panel-body">
              <div className="row" style={{ gap: 16, alignItems: 'flex-end' }}>
                <div className="field">
                  <span className="label">Status</span>
                  {canTriage ? (
                    <div className="btn-group" role="group" aria-label="Status">
                      {ALERT_STATUSES.map((s) => (
                        <button
                          key={s}
                          type="button"
                          className={a.status === s ? 'btn sm active' : 'btn sm'}
                          disabled={patch.isPending}
                          aria-pressed={a.status === s}
                          onClick={() => a.status !== s && patch.mutate({ status: s as AlertStatus })}
                        >
                          {ALERT_STATUS_LABEL[s]}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <AlertStatusBadge status={a.status} />
                  )}
                </div>
                <AssigneeControl alert={a} canEdit={canTriage} onSave={(assignee) => patch.mutate({ assignee })} me={user.username} pending={patch.isPending} />
              </div>
            </div>
          </section>

          <AITriagePanel alertId={a.id} />

          <section className="panel">
            <div className="panel-header">
              <h2>Rule</h2>
              <Link to={`/rules/${encodeURIComponent(a.rule.id)}`} className="small">
                Open rule
              </Link>
            </div>
            <div className="panel-body stack" style={{ gap: 10 }}>
              {a.rule.description ? <p style={{ margin: 0 }}>{a.rule.description}</p> : null}
              <KV
                items={[
                  ['Level', <SeverityBadge key="l" severity={a.rule.level} />],
                  ['Tags', <Tags key="t" tags={a.rule.tags} />],
                  [
                    'False positives',
                    a.rule.false_positives?.length ? (
                      <ul key="fp" className="effect-list" style={{ margin: 0 }}>
                        {a.rule.false_positives.map((f) => (
                          <li key={f}>{f}</li>
                        ))}
                      </ul>
                    ) : undefined,
                  ],
                  [
                    'References',
                    a.rule.references?.length ? (
                      <div key="r" className="stack" style={{ gap: 2 }}>
                        {a.rule.references.map((r) => (
                          <a key={r} href={r} target="_blank" rel="noreferrer noopener" className="truncate-inline">
                            {r}
                          </a>
                        ))}
                      </div>
                    ) : undefined,
                  ],
                ]}
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>MITRE ATT&amp;CK</h2>
            </div>
            {a.mitre.length === 0 ? (
              <EmptyState title="No ATT&CK mapping on this rule" compact />
            ) : (
              <div className="table-wrap">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Tactic</th>
                      <th>Technique</th>
                      <th>Name</th>
                    </tr>
                  </thead>
                  <tbody>
                    {a.mitre.map((m, i) => (
                      <tr key={i}>
                        <td>{m.tactic ?? '—'}</td>
                        <td>
                          <MitreTag m={{ technique_id: m.technique_id, tactic: m.tactic }} />
                        </td>
                        <td>{m.technique ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Triggering events</h2>
              <span className="hint">
                {a.events?.length ?? 0} of {formatNumber(a.event_ids.length)} shown · click a value to search for it
              </span>
            </div>
            {a.events?.length ? (
              <EventTable events={a.events} showHost={false} initiallyOpen={a.events[0].id} />
            ) : ev ? (
              <EventTable events={[ev]} initiallyOpen={ev.id} />
            ) : (
              <EmptyState title="No events attached" compact />
            )}
          </section>
        </div>

        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Host</h2>
              <Link to={`/hosts/${encodeURIComponent(a.host_id)}`} className="small">
                Open host
              </Link>
            </div>
            <div className="panel-body">
              {hostQ.isPending ? (
                <Loading compact />
              ) : hostQ.isError ? (
                <ErrorState error={hostQ.error} compact />
              ) : (
                <KV
                  items={[
                    ['Hostname', hostQ.data.hostname],
                    ['Status', <StatusDot key="s" status={hostQ.data.status} label />],
                    ['OS', <OsLabel key="o" os={hostQ.data.os} />],
                    ['IPs', hostQ.data.ips.join(', ')],
                    ['Labels', <Tags key="l" tags={hostQ.data.labels} />],
                    ['Last seen', <RelTime key="ls" iso={hostQ.data.last_seen} />],
                  ]}
                />
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Process</h2>
              {treeHref ? (
                <Link to={treeHref} className="small">
                  Process tree
                </Link>
              ) : null}
            </div>
            <div className="panel-body">
              {a.process_name || ev?.process ? (
                <KV
                  items={[
                    ['Name', <span key="n" className="mono">{a.process_name ?? ev?.process?.name}</span>],
                    ['PID', ev?.process?.pid],
                    ['User', a.user ?? ev?.process?.user?.name],
                    ['Parent', ev?.process?.parent?.name ? <span className="mono">{ev.process.parent.name} ({ev.process.parent.pid})</span> : undefined],
                    ['Started', ev?.process?.start ? formatDateTime(ev.process.start) : undefined],
                    ['Command line', <ExpandableText key="c" text={a.command_line ?? ev?.process?.command_line} max={220} />],
                    ['SHA-256', ev?.process?.hash?.sha256 ? <span className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>{ev.process.hash.sha256}</span> : undefined],
                  ]}
                />
              ) : (
                <EmptyState title="No process attached" compact>
                  This alert came from a network or log event.
                </EmptyState>
              )}
            </div>
          </section>

          <NotesPanel alert={a} />
        </div>
      </div>
    </>
  )
}

function AssigneeControl({
  alert: a,
  canEdit,
  onSave,
  me,
  pending,
}: {
  alert: Alert
  canEdit: boolean
  onSave: (assignee: string) => void
  me: string
  pending: boolean
}) {
  const [draft, setDraft] = useState<string | null>(null)
  const meQ = useMe()
  // The user list is admin-only; analysts can still type a name or take it themselves.
  const usersQ = useQuery({
    queryKey: queryKeys.users,
    queryFn: api.listUsers,
    enabled: hasRole(meQ.data, 'admin'),
    staleTime: 5 * 60_000,
  })
  if (!canEdit) {
    return (
      <div className="field">
        <span className="label">Assignee</span>
        <span>{a.assignee ?? <span className="muted">Unassigned</span>}</span>
      </div>
    )
  }
  const value = draft ?? a.assignee ?? ''
  const dirty = draft !== null && draft !== (a.assignee ?? '')
  return (
    <form
      className="field"
      onSubmit={(e: FormEvent) => {
        e.preventDefault()
        if (dirty) onSave(value.trim())
        setDraft(null)
      }}
    >
      <label htmlFor="assignee">Assignee</label>
      <div className="row nowrap">
        <input
          id="assignee"
          className="input"
          style={{ width: 160 }}
          list="assignee-users"
          placeholder="Unassigned"
          value={value}
          onChange={(e) => setDraft(e.target.value)}
        />
        <datalist id="assignee-users">
          {usersQ.data?.users.map((u) => (
            <option key={u.id} value={u.username} />
          ))}
        </datalist>
        {dirty ? (
          <button type="submit" className="btn sm primary" disabled={pending}>
            Save
          </button>
        ) : a.assignee !== me ? (
          <button type="button" className="btn sm" disabled={pending} onClick={() => onSave(me)}>
            Assign to me
          </button>
        ) : (
          <button type="button" className="btn sm ghost" disabled={pending} onClick={() => onSave('')}>
            Unassign
          </button>
        )}
      </div>
    </form>
  )
}

function NotesPanel({ alert: a }: { alert: Alert }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canTriage = useCan('analyst')
  const [text, setText] = useState('')
  const add = useMutation({
    mutationFn: () => api.addAlertNote(a.id, text.trim()),
    onSuccess: (updated) => {
      qc.setQueryData(queryKeys.alert(a.id), (old: Alert | undefined) => ({ ...updated, events: old?.events ?? updated.events }))
      setText('')
    },
    onError: (e) => toast.error(e),
  })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Notes</h2>
        <span className="hint">{a.notes.length}</span>
      </div>
      <div className="panel-body stack" style={{ gap: 10 }}>
        {a.notes.length === 0 ? <span className="muted small">No notes yet.</span> : null}
        <div className="notes">
          {a.notes.map((n, i) => (
            <div key={i} className="note">
              <div className="note-meta">
                <strong>{n.author}</strong> · <RelTime iso={n.at} />
              </div>
              <div className="note-text">{n.text}</div>
            </div>
          ))}
        </div>
        {canTriage ? (
          <form
            className="stack"
            style={{ gap: 6 }}
            onSubmit={(e) => {
              e.preventDefault()
              if (text.trim()) add.mutate()
            }}
          >
            <textarea
              className="textarea"
              rows={3}
              placeholder="Add a note for the next person who looks at this…"
              value={text}
              onChange={(e) => setText(e.target.value)}
              aria-label="New note"
            />
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <button type="submit" className="btn sm primary" disabled={!text.trim() || add.isPending}>
                {add.isPending ? <Spinner small /> : null} Add note
              </button>
            </div>
          </form>
        ) : null}
      </div>
    </section>
  )
}
