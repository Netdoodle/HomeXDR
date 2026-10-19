import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, queryKeys, SEVERITIES, type Overview } from '../api'
import { AlertStatusBadge, SeverityBadge } from '../components/Badges'
import { BarList, ColumnChart } from '../components/Charts'
import { PageHeader } from '../components/Layout'
import { RelTime } from '../components/Misc'
import { EmptyState, ErrorState, Loading, QueryView } from '../components/States'
import { formatCount, formatNumber } from '../lib/format'
import { formatTerm } from '../lib/query'
import { SEVERITY_LABEL } from '../lib/severity'
import { fillHourlyBuckets } from '../lib/time'

const WINDOWS = [
  { hours: 24, label: '24h' },
  { hours: 72, label: '3d' },
  { hours: 168, label: '7d' },
]

export function DashboardPage() {
  const [hours, setHours] = useState(24)
  const q = useQuery({
    queryKey: queryKeys.overview(hours),
    queryFn: () => api.overview(hours),
    refetchInterval: 30_000,
  })

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={q.dataUpdatedAt ? <>Updated <RelTime iso={new Date(q.dataUpdatedAt).toISOString()} /></> : 'Fleet overview'}
        actions={
          <div className="btn-group" role="group" aria-label="Window">
            {WINDOWS.map((w) => (
              <button key={w.hours} type="button" className={w.hours === hours ? 'btn active' : 'btn'} onClick={() => setHours(w.hours)}>
                {w.label}
              </button>
            ))}
          </div>
        }
      />
      {q.isPending ? (
        <div className="panel">
          <Loading />
        </div>
      ) : q.isError ? (
        <div className="panel">
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        </div>
      ) : (
        <DashboardBody o={q.data} hours={hours} />
      )}
    </>
  )
}

function DashboardBody({ o, hours }: { o: Overview; hours: number }) {
  const navigate = useNavigate()
  const sevTotal = SEVERITIES.reduce((n, s) => n + (o.alerts_by_severity[s] ?? 0), 0)
  const windowLabel = hours === 24 ? '24h' : hours === 72 ? '3 days' : '7 days'
  const eventsTl = fillHourlyBuckets(o.events_timeline, hours)
  const alertsTl = fillHourlyBuckets(o.alerts_timeline, hours)
  const offline = o.hosts_total - o.hosts_online

  return (
    <div className="stack">
      <div className="stats">
        <Link className="stat" to="/hosts">
          <span className="label">Hosts online</span>
          <span className="value">
            {formatNumber(o.hosts_online)} <small>/ {formatNumber(o.hosts_total)}</small>
          </span>
          <span className="sub">{offline > 0 ? `${offline} offline` : 'All hosts reporting'}</span>
        </Link>
        <Link className="stat" to="/hosts?status=isolated">
          <span className="label">Isolated</span>
          <span className="value">{formatNumber(o.hosts_isolated)}</span>
          <span className="sub">{o.hosts_isolated ? 'Network access restricted' : 'No hosts isolated'}</span>
        </Link>
        <Link className="stat" to="/alerts">
          <span className="label">Open alerts</span>
          <span className="value">{formatNumber(o.alerts_open)}</span>
          <span className="sev-strip" aria-hidden="true">
            {SEVERITIES.map((s) =>
              o.alerts_by_severity[s] ? (
                <span key={s} style={{ flex: o.alerts_by_severity[s], background: `var(--sev-${s})` }} title={`${SEVERITY_LABEL[s]}: ${o.alerts_by_severity[s]}`} />
              ) : null,
            )}
            {sevTotal === 0 ? <span style={{ flex: 1 }} /> : null}
          </span>
        </Link>
        <Link className="stat" to="/search">
          <span className="label">Events ({windowLabel})</span>
          <span className="value">{formatCount(o.events_total)}</span>
          <span className="sub">{formatNumber(Math.round(o.events_total / hours))} per hour on average</span>
        </Link>
      </div>

      <div className="stats" aria-label="Open alerts by severity">
        {SEVERITIES.map((s) => (
          <Link key={s} className="stat" to={`/alerts?severity=${s}`} style={{ boxShadow: `inset 3px 0 0 var(--sev-${s})` }}>
            <span className="label">{SEVERITY_LABEL[s]}</span>
            <span className="value">{formatNumber(o.alerts_by_severity[s] ?? 0)}</span>
            <span className="sub">open</span>
          </Link>
        ))}
      </div>

      <div className="grid grid-2">
        <section className="panel">
          <div className="panel-header">
            <h2>Events per hour</h2>
            <span className="hint">last {windowLabel}</span>
          </div>
          <div className="panel-body">
            {o.events_total === 0 ? <EmptyState title="No events in this window" compact /> : <ColumnChart data={eventsTl} unit="events" />}
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Alert hits per hour</h2>
            <span className="hint">last {windowLabel}</span>
          </div>
          <div className="panel-body">
            {alertsTl.every((b) => b.count === 0) ? (
              <EmptyState title="No alert hits in this window" compact />
            ) : (
              <ColumnChart data={alertsTl} unit="hits" alt />
            )}
          </div>
        </section>
      </div>

      <div className="grid grid-3">
        <section className="panel">
          <div className="panel-header">
            <h2>Top rules</h2>
            <Link to="/rules" className="small">
              All rules
            </Link>
          </div>
          <div className="panel-body" style={{ padding: 8 }}>
            {o.top_rules.length === 0 ? (
              <EmptyState title="No detections" compact />
            ) : (
              <BarList
                items={o.top_rules.map((r) => ({
                  key: r.rule_id,
                  href: `/rules/${encodeURIComponent(r.rule_id)}`,
                  title: r.title,
                  value: r.count,
                  color: `var(--sev-${r.severity})`,
                  label: (
                    <span className="row nowrap" style={{ gap: 6 }}>
                      <SeverityBadge severity={r.severity} />
                      <span className="truncate-inline">{r.title}</span>
                    </span>
                  ),
                }))}
              />
            )}
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Top hosts by alerts</h2>
            <Link to="/hosts" className="small">
              All hosts
            </Link>
          </div>
          <div className="panel-body" style={{ padding: 8 }}>
            {o.top_hosts.length === 0 ? (
              <EmptyState title="No alerts" compact />
            ) : (
              <BarList
                items={o.top_hosts.map((h) => ({
                  key: h.host_id,
                  href: `/hosts/${encodeURIComponent(h.host_id)}?tab=alerts`,
                  label: h.hostname,
                  value: h.alerts,
                }))}
              />
            )}
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Events by category</h2>
          </div>
          <div className="panel-body" style={{ padding: 8 }}>
            {o.events_by_category.length === 0 ? (
              <EmptyState title="No events" compact />
            ) : (
              <BarList
                items={o.events_by_category.map((c) => ({
                  key: c.category,
                  href: `/search?q=${encodeURIComponent(formatTerm('event.category', c.category))}&range=${hours <= 24 ? '24h' : '7d'}`,
                  label: c.category,
                  value: c.count,
                }))}
              />
            )}
          </div>
        </section>
      </div>

      <RecentAlerts onOpen={(id) => navigate(`/alerts/${encodeURIComponent(id)}`)} />
    </div>
  )
}

function RecentAlerts({ onOpen }: { onOpen: (id: string) => void }) {
  const filter = { status: 'new,in_progress', limit: 8 }
  const q = useQuery({ queryKey: queryKeys.alerts(filter), queryFn: () => api.listAlerts(filter), refetchInterval: 30_000 })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Latest open alerts</h2>
        <Link to="/alerts" className="small">
          Triage queue
        </Link>
      </div>
      <QueryView query={q} isEmpty={(d) => d.alerts.length === 0} empty={<EmptyState title="No open alerts" compact>Nothing needs attention.</EmptyState>} compact>
        {(d) => (
          <div className="table-wrap">
            <table className="table fixed" style={{ minWidth: 760 }}>
              <colgroup>
                <col style={{ width: 100 }} />
                <col />
                <col style={{ width: 160 }} />
                <col style={{ width: 130 }} />
                <col style={{ width: 110 }} />
                <col style={{ width: 100 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Host</th>
                  <th>Process</th>
                  <th>Status</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {d.alerts.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => onOpen(a.id)}>
                    <td>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="truncate" title={a.rule.title}>
                      <Link to={`/alerts/${encodeURIComponent(a.id)}`} onClick={(e) => e.stopPropagation()}>
                        {a.rule.title}
                      </Link>
                    </td>
                    <td className="truncate">{a.hostname}</td>
                    <td className="truncate mono">{a.process_name ?? '—'}</td>
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
