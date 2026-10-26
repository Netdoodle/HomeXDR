import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { api, isApiError, queryKeys, type Host, type TimelineFilter } from '../api'
import { useCan } from '../components/Auth'
import { AlertCount, AlertStatusBadge, OsLabel, SeverityBadge, StatusDot, Tags, UpdateBadge } from '../components/Badges'
import { EventTable } from '../components/EventTable'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { KV, LabelEditor, LinkTabs, RelTime } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { EmptyState, ErrorState, Loading, QueryView, Spinner } from '../components/States'
import { TimeRangePicker } from '../components/TimeRangePicker'
import { useToast } from '../components/Toast'
import { canUpdateNow, certState, ruleLabel, shortVersion, UPDATE_STATE_LABEL } from '../lib/agents'
import { formatBytes, formatNumber } from '../lib/format'
import { useDocumentTitle, useUrlState } from '../lib/hooks'
import { HOST_STATUS_LABEL } from '../lib/severity'
import { formatDateTime, formatDurationSec, rangeFromParams, rangeToParams, resolveRange } from '../lib/time'
import { HostActions } from './HostActions'
import { HostCommands } from './HostCommands'

const TABS = [
  { id: 'overview', label: 'Overview', icon: 'info' as const },
  { id: 'timeline', label: 'Timeline', icon: 'clock' as const },
  { id: 'alerts', label: 'Alerts', icon: 'alert' as const },
  { id: 'commands', label: 'Commands', icon: 'terminal' as const },
  { id: 'actions', label: 'Actions', icon: 'isolate' as const },
]

export function HostDetailPage() {
  const { id = '' } = useParams()
  const [sp] = useUrlState()
  const tab = TABS.some((t) => t.id === sp.get('tab')) ? sp.get('tab')! : 'overview'
  const q = useQuery({ queryKey: queryKeys.host(id), queryFn: () => api.getHost(id), refetchInterval: 30_000 })
  useDocumentTitle(q.data?.hostname ?? 'Host')

  if (q.isPending) return <Loading />
  if (q.isError) {
    return (
      <div className="panel">
        {isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState title="Host not found" action={<Link to="/hosts">Back to hosts</Link>} />
        ) : (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        )}
      </div>
    )
  }
  const h = q.data
  const tabs = TABS.map((t) =>
    t.id === 'alerts' && h.open_alerts ? { ...t, label: <>Alerts <span className="badge count alerts">{h.open_alerts}</span></> } : t,
  )

  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/hosts">Hosts</Link>
        <Icon name="chevronRight" size={10} />
        <span>{h.hostname}</span>
      </div>
      <PageHeader
        title={
          <span className="row" style={{ gap: 10 }}>
            <StatusDot status={h.status} />
            {h.hostname}
            {h.isolated ? <span className="badge" style={{ borderColor: 'var(--status-isolated)' }}>Isolated</span> : null}
          </span>
        }
        subtitle={
          <span className="row" style={{ gap: 14 }}>
            <OsLabel os={h.os} />
            <span>{HOST_STATUS_LABEL[h.status]}</span>
            <span>
              last seen <RelTime iso={h.last_seen} />
            </span>
            <span className="mono">{h.ips[0]}</span>
          </span>
        }
      />
      <LinkTabs tabs={tabs} active={tab} href={(t) => `/hosts/${encodeURIComponent(h.id)}${t === 'overview' ? '' : `?tab=${t}`}`} />
      {tab === 'overview' ? <Overview host={h} /> : null}
      {tab === 'timeline' ? <Timeline host={h} /> : null}
      {tab === 'alerts' ? <HostAlerts host={h} /> : null}
      {tab === 'commands' ? <HostCommands host={h} /> : null}
      {tab === 'actions' ? <HostActions host={h} /> : null}
    </>
  )
}

function Overview({ host: h }: { host: Host }) {
  const qc = useQueryClient()
  const toast = useToast()
  const navigate = useNavigate()
  const canEdit = useCan('analyst')
  const isAdmin = useCan('admin')
  const [revokeOpen, setRevokeOpen] = useState(false)
  const all = useQuery({ queryKey: queryKeys.hosts({}), queryFn: () => api.listHosts({}), staleTime: 60_000 })
  const suggestions = useMemo(() => [...new Set((all.data?.hosts ?? []).flatMap((x) => x.labels))].sort(), [all.data])

  const labels = useMutation({
    mutationFn: (l: string[]) => api.updateHostLabels(h.id, l),
    onSuccess: (updated) => {
      qc.setQueryData(queryKeys.host(h.id), updated)
      qc.invalidateQueries({ queryKey: queryKeys.hosts() })
    },
    onError: (e) => toast.error(e),
  })

  const uptime = h.boot_time ? (Date.now() - Date.parse(h.boot_time)) / 1000 : undefined
  const sensors = h.sensors ?? []

  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <div className="stack">
        {h.kind === 'endpoint' ? <AgentPanel host={h} isAdmin={isAdmin} /> : null}
        <section className="panel">
          <div className="panel-header">
            <h2>Host information</h2>
          </div>
          <div className="panel-body">
            <KV
              items={[
                ['Hostname', h.hostname],
                ['Agent ID', <span key="id" className="mono small">{h.id}</span>],
                ['Kind', h.kind === 'network' ? 'Network device (syslog source)' : 'Endpoint agent'],
                ['Operating system', <OsLabel key="os" os={h.os} />],
                ['Kernel', h.os.kernel],
                ['Architecture', h.arch],
                ['IP addresses', h.ips.length ? <span className="mono">{h.ips.join(', ')}</span> : undefined],
                ['MAC addresses', h.macs?.length ? <span className="mono">{h.macs.join(', ')}</span> : undefined],
                ['Agent version', h.agent_version],
                ['CPUs / memory', h.cpus ? `${h.cpus} CPUs · ${formatBytes(h.memory_bytes)}` : undefined],
                ['Booted', h.boot_time ? `${formatDateTime(h.boot_time)} (up ${formatDurationSec(uptime!)})` : undefined],
                ['Enrolled', formatDateTime(h.enrolled_at)],
                ['Last seen', <RelTime key="ls" iso={h.last_seen} />],
                ['Spooled events', h.queue_events !== undefined ? formatNumber(h.queue_events) : undefined],
                ['Open alerts', <AlertCount key="a" n={h.open_alerts} />],
              ]}
            />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Labels</h2>
            {labels.isPending ? <Spinner small /> : <span className="hint">Used to target hunts and filter hosts</span>}
          </div>
          <div className="panel-body">
            <LabelEditor labels={h.labels} canEdit={canEdit} saving={labels.isPending} onSave={(l) => labels.mutate(l)} suggestions={suggestions} />
          </div>
        </section>
      </div>
      <div className="stack">
        <section className="panel">
          <div className="panel-header">
            <h2>Sensor health</h2>
            {sensors.length ? (
              <span className="hint">
                {sensors.filter((s) => s.state === 'running').length} of {sensors.length} running
              </span>
            ) : null}
          </div>
          <div className="panel-body" style={{ paddingTop: 4, paddingBottom: 4 }}>
            {h.kind === 'network' ? (
              <EmptyState title="No agent sensors" compact>
                This device sends syslog to the server; see Settings → Integrations for intake stats.
              </EmptyState>
            ) : sensors.length === 0 ? (
              <EmptyState title="No sensor status reported yet" compact />
            ) : (
              <div className="sensor-list">
                {sensors.map((s) => (
                  <div key={s.name} className="sensor-row">
                    <span className={`dot ${s.state}`} aria-hidden="true" />
                    <span className="mono">{s.name}</span>
                    <span className="muted small">{s.impl}</span>
                    <span className="small" style={{ minWidth: 0 }}>
                      <span className={s.state === 'failed' ? 'danger-text' : s.state === 'running' ? '' : 'muted'}>{s.state}</span>
                      {s.error ? <div className="muted xsmall" style={{ overflowWrap: 'anywhere' }}>{s.error}</div> : null}
                    </span>
                    <span className="num small muted right">{formatNumber(s.events)} ev</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
        {h.kind === 'endpoint' ? (
          <section className="panel">
            <div className="panel-header">
              <h2>Local response policy</h2>
              <span className="hint">set in the agent's config file; the server cannot change it</span>
            </div>
            <div className="panel-body">
              {h.allowed_actions === undefined ? (
                <span className="muted small">Not reported yet.</span>
              ) : h.allowed_actions.length === 0 ? (
                <span className="muted small">This agent accepts no response actions.</span>
              ) : (
                <Tags tags={h.allowed_actions} />
              )}
            </div>
          </section>
        ) : null}
        {isAdmin && h.status !== 'revoked' ? (
          <section className="panel">
            <div className="panel-header">
              <h2>Danger zone</h2>
            </div>
            {h.kind === 'endpoint' && h.status !== 'decommissioned' ? (
              <div className="panel-body row" style={{ gap: 12 }}>
                <span className="small muted grow">
                  Decommission: hide this agent from host lists and counts now. It is restored automatically when it reconnects.
                </span>
                <DecommissionButton host={h} />
              </div>
            ) : null}
            <div className="panel-body row" style={{ gap: 12 }}>
              <span className="small muted grow">Revoke the agent certificate. The agent can no longer send events or receive commands and must re-enroll.</span>
              <button type="button" className="btn danger" onClick={() => setRevokeOpen(true)}>
                <Icon name="trash" size={14} /> Revoke agent
              </button>
            </div>
          </section>
        ) : null}
      </div>
      <ConfirmDialog
        open={revokeOpen}
        onClose={() => setRevokeOpen(false)}
        title={`Revoke ${h.hostname}?`}
        danger
        confirmLabel="Revoke agent"
        onConfirm={async () => {
          await api.revokeHost(h.id)
          qc.invalidateQueries({ queryKey: queryKeys.hosts() })
          qc.invalidateQueries({ queryKey: queryKeys.host(h.id) })
          toast.success(`${h.hostname} revoked`)
          navigate('/hosts')
        }}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Revoke the client certificate of {h.hostname}; it is rejected on its next connection.</li>
          <li>Stop event collection and response actions for this host. Stored events and alerts are kept.</li>
          <li>Leave the agent installed on the machine. To use it again, uninstall it and re-enroll with a new token.</li>
        </ul>
      </ConfirmDialog>
    </div>
  )
}

const TIMELINE_CATEGORIES = ['process', 'network', 'file', 'registry', 'authentication', 'configuration', 'intrusion_detection']

function Timeline({ host: h }: { host: Host }) {
  const [sp, patch] = useUrlState()
  const range = rangeFromParams(sp, '24h')
  const category = sp.get('category') ?? ''
  const [limit, setLimit] = useState(200)
  // Resolve relative ranges once per selection so the query key stays stable.
  const rangeKey = JSON.stringify(range)
  const { from, to } = useMemo(() => resolveRange(JSON.parse(rangeKey)), [rangeKey])
  const filter: TimelineFilter = { from, to, category: category || undefined, limit }
  const q = useQuery({
    queryKey: queryKeys.hostTimeline(h.id, { category: filter.category, limit, from: rangeKey }),
    queryFn: () => api.hostTimeline(h.id, filter),
    placeholderData: keepPreviousData,
  })
  return (
    <section className="panel">
      <div className="panel-header">
        <div className="chips" role="group" aria-label="Category">
          <button type="button" className="chip" aria-pressed={!category} onClick={() => patch({ category: undefined })}>
            All
          </button>
          {TIMELINE_CATEGORIES.map((c) => (
            <button key={c} type="button" className="chip" aria-pressed={category === c} onClick={() => patch({ category: category === c ? undefined : c })}>
              {c}
            </button>
          ))}
        </div>
        <div className="row">
          {q.isFetching && !q.isPending ? <Spinner small /> : null}
          <TimeRangePicker value={range} onChange={(r) => patch({ range: undefined, from: undefined, to: undefined, ...rangeToParams(r) })} />
          <Link
            className="btn sm"
            to={`/search?q=${encodeURIComponent(`host.id:${h.id}${category ? ` AND event.category:${category}` : ''}`)}&${new URLSearchParams(rangeToParams(range))}`}
          >
            <Icon name="search" size={12} /> Open in search
          </Link>
        </div>
      </div>
      <QueryView
        query={q}
        isEmpty={(d) => d.events.length === 0}
        empty={<EmptyState title="No events in this range">Try a longer time range or another category.</EmptyState>}
      >
        {(d) => (
          <>
            <EventTable events={d.events} />
            {d.events.length >= limit ? (
              <div className="pager">
                <span>Showing the newest {formatNumber(d.events.length)} events</span>
                <button type="button" className="btn sm" onClick={() => setLimit(Math.min(1000, limit + 200))} disabled={limit >= 1000}>
                  Load more
                </button>
              </div>
            ) : null}
          </>
        )}
      </QueryView>
    </section>
  )
}

function HostAlerts({ host: h }: { host: Host }) {
  const navigate = useNavigate()
  const filter = { host_id: h.id, limit: 200 }
  const q = useQuery({ queryKey: queryKeys.alerts(filter), queryFn: () => api.listAlerts(filter) })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Alerts on {h.hostname}</h2>
        <Link to={`/alerts?host=${encodeURIComponent(h.id)}&status=all`} className="small">
          Open in alert queue
        </Link>
      </div>
      <QueryView query={q} isEmpty={(d) => d.alerts.length === 0} empty={<EmptyState title="No alerts for this host" />}>
        {(d) => (
          <div className="table-wrap">
            <table className="table fixed" style={{ minWidth: 700 }}>
              <colgroup>
                <col style={{ width: 96 }} />
                <col />
                <col style={{ width: '28%' }} />
                <col style={{ width: 112 }} />
                <col style={{ width: 96 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Process</th>
                  <th>Status</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {d.alerts.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => navigate(`/alerts/${encodeURIComponent(a.id)}`)}>
                    <td>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="truncate" title={a.rule.title}>
                      <Link to={`/alerts/${encodeURIComponent(a.id)}`} onClick={(e) => e.stopPropagation()}>
                        {a.rule.title}
                      </Link>
                    </td>
                    <td className="truncate cmd" title={a.command_line}>
                      {a.process_name ?? '—'}
                    </td>
                    <td>
                      <AlertStatusBadge status={a.status} />
                    </td>
                    <td>
                      <RelTime iso={a.last_seen} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
    </section>
  )
}

/** Agent version, update policy status and certificate, with the lifecycle actions. */
function AgentPanel({ host: h, isAdmin }: { host: Host; isAdmin: boolean }) {
  const qc = useQueryClient()
  const toast = useToast()
  const u = h.update
  const cert = certState(h.cert_expires)
  const done = (updated: Host, msg: string) => {
    qc.setQueryData(queryKeys.host(h.id), updated)
    qc.invalidateQueries({ queryKey: queryKeys.hosts() })
    toast.success(msg)
  }
  const updateNow = useMutation({
    mutationFn: () => api.updateHostNow(h.id),
    onSuccess: (x) => done(x, 'The agent updates when it next checks in'),
    onError: (e) => toast.error(e),
  })
  const restore = useMutation({
    mutationFn: () => api.recommissionHost(h.id),
    onSuccess: (x) => done(x, `${h.hostname} restored`),
    onError: (e) => toast.error(e),
  })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Agent</h2>
        {u ? <UpdateBadge update={u} /> : null}
      </div>
      <div className="panel-body stack" style={{ gap: 10 }}>
        {h.decommissioned_at ? (
          <div className="callout warn">
            <Icon name="info" size={14} />
            <div className="grow">
              Decommissioned <RelTime iso={h.decommissioned_at} />. It is hidden from host lists and is restored automatically when the agent
              reconnects.
            </div>
            {isAdmin ? (
              <button type="button" className="btn sm" disabled={restore.isPending} onClick={() => restore.mutate()}>
                Restore now
              </button>
            ) : null}
          </div>
        ) : null}
        <KV
          items={[
            ['Version', h.agent_version ? <span key="v" className="mono small" title={h.agent_version}>{shortVersion(h.agent_version)}</span> : undefined],
            [
              'Update policy',
              u ? (
                <span key="p">
                  {ruleLabel(u.rule)}
                  <span className="muted">{u.source === 'default' ? ' (default)' : ` (label ${u.source})`}</span>
                </span>
              ) : undefined,
            ],
            ['Target', u?.target && u.target !== h.agent_version ? <span key="t" className="mono small" title={u.target}>{shortVersion(u.target)}</span> : undefined],
            ['Status', u ? <span key="s">{UPDATE_STATE_LABEL[u.state]}{u.reason ? <span className="muted"> · {u.reason}</span> : null}</span> : undefined],
            ['Last update error', h.update_error ? <span key="e" className="error small">{h.update_error}</span> : undefined],
            [
              'Certificate',
              cert ? (
                <span key="c" className={cert.level === 'ok' ? undefined : cert.level === 'warn' ? 'warn-text' : 'error'}>
                  {cert.text}
                </span>
              ) : undefined,
            ],
          ]}
        />
        {isAdmin && canUpdateNow(u) && !h.update_now_at ? (
          <div className="row" style={{ gap: 8 }}>
            <button type="button" className="btn sm" disabled={updateNow.isPending} onClick={() => updateNow.mutate()}>
              <Icon name="refresh" size={12} /> Update now
            </button>
            <span className="xsmall muted">Installs {u?.target ? shortVersion(u.target) : 'the target'} at the next check-in, outside the window and staging.</span>
          </div>
        ) : null}
        {h.update_now_at && u?.state !== 'current' ? (
          <span className="small muted">
            Update requested <RelTime iso={h.update_now_at} />.
          </span>
        ) : null}
      </div>
    </section>
  )
}

function DecommissionButton({ host: h }: { host: Host }) {
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.decommissionHost(h.id),
    onSuccess: (x) => {
      qc.setQueryData(queryKeys.host(h.id), x)
      qc.invalidateQueries({ queryKey: queryKeys.hosts() })
      toast.success(`${h.hostname} decommissioned`)
    },
    onError: (e) => toast.error(e),
  })
  return (
    <button type="button" className="btn" disabled={m.isPending} onClick={() => m.mutate()}>
      Decommission
    </button>
  )
}
