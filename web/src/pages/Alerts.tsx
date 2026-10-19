import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { ALERT_STATUSES, api, queryKeys, SEVERITIES, type AlertFilter, type AlertStatus } from '../api'
import { useCan, useUser } from '../components/Auth'
import { AlertStatusBadge, MitreTag, SeverityBadge } from '../components/Badges'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { Pager, RelTime } from '../components/Misc'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber, plural } from '../lib/format'
import { useDebounced, useDocumentTitle, useUrlState } from '../lib/hooks'
import { ALERT_STATUS_LABEL, OPEN_ALERT_STATUSES, SEVERITY_LABEL } from '../lib/severity'

const LIMIT = 50

function toggleIn(list: string[], v: string): string[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v]
}

export function AlertsPage() {
  useDocumentTitle('Alerts')
  const [sp, patch] = useUrlState()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const user = useUser()
  const canTriage = useCan('analyst')

  // status: absent = open (new + in_progress); "all" = no filter
  const statusParam = sp.get('status')
  const statuses = statusParam === 'all' ? [] : statusParam ? statusParam.split(',') : [...OPEN_ALERT_STATUSES]
  const severities = sp.get('severity')?.split(',').filter(Boolean) ?? []
  const hostId = sp.get('host') ?? ''
  const ruleId = sp.get('rule') ?? ''
  const offset = Number(sp.get('offset') ?? 0) || 0
  const [text, setText] = useState(sp.get('q') ?? '')
  const debounced = useDebounced(text, 350)
  const appliedQ = useRef(debounced)
  useEffect(() => {
    if (debounced !== appliedQ.current) {
      appliedQ.current = debounced
      patch({ q: debounced, offset: undefined })
    }
  }, [debounced, patch])

  const filter: AlertFilter = {
    status: statuses.join(',') || undefined,
    severity: severities.join(',') || undefined,
    host_id: hostId || undefined,
    rule_id: ruleId || undefined,
    q: sp.get('q') || undefined,
    limit: LIMIT,
    offset,
  }
  const alertsQ = useQuery({
    queryKey: queryKeys.alerts(filter),
    queryFn: () => api.listAlerts(filter),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  const hostsQ = useQuery({ queryKey: queryKeys.hosts({}), queryFn: () => api.listHosts({}), staleTime: 60_000 })

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const pageIds = useMemo(() => alertsQ.data?.alerts.map((a) => a.id) ?? [], [alertsQ.data])
  useEffect(() => {
    // drop selections that are no longer visible
    setSelected((s) => new Set([...s].filter((id) => pageIds.includes(id))))
  }, [pageIds])
  const allSelected = pageIds.length > 0 && pageIds.every((id) => selected.has(id))

  const bulk = useMutation({
    mutationFn: (p: { status?: AlertStatus; assignee?: string }) => api.bulkAlerts([...selected], p),
    onSuccess: (res, vars) => {
      toast.success(
        vars.status
          ? `${plural(res.updated, 'alert')} set to ${ALERT_STATUS_LABEL[vars.status]}`
          : `${plural(res.updated, 'alert')} assigned to ${vars.assignee || 'nobody'}`,
      )
      setSelected(new Set())
      qc.invalidateQueries({ queryKey: queryKeys.alerts() })
      qc.invalidateQueries({ queryKey: ['alert'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
    onError: (e) => toast.error(e),
  })

  const setStatuses = (next: string[]) => {
    const isDefault = next.length === OPEN_ALERT_STATUSES.length && OPEN_ALERT_STATUSES.every((s) => next.includes(s))
    patch({ status: next.length === 0 ? 'all' : isDefault ? undefined : next.join(','), offset: undefined })
  }

  const total = alertsQ.data?.total

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle={total !== undefined ? `${formatNumber(total)} matching` : 'Detections from Sigma rules and network sensors'}
        actions={
          alertsQ.isFetching && !alertsQ.isPending ? <Spinner small /> : null
        }
      />
      <div className="filters">
        <input
          type="search"
          className="input"
          placeholder="Filter by rule, host, process, MITRE…"
          value={text}
          onChange={(e) => setText(e.target.value)}
          aria-label="Filter alerts"
        />
        <div className="chips" role="group" aria-label="Status">
          {ALERT_STATUSES.map((s) => (
            <button key={s} type="button" className="chip" aria-pressed={statuses.includes(s)} onClick={() => setStatuses(toggleIn(statuses, s))}>
              {ALERT_STATUS_LABEL[s]}
            </button>
          ))}
        </div>
        <div className="chips" role="group" aria-label="Severity">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              className="chip"
              aria-pressed={severities.includes(s)}
              onClick={() => patch({ severity: toggleIn(severities, s).join(','), offset: undefined })}
            >
              <span className="dot" style={{ background: `var(--sev-${s})` }} aria-hidden="true" />
              {SEVERITY_LABEL[s]}
            </button>
          ))}
        </div>
        <select className="select" value={hostId} onChange={(e) => patch({ host: e.target.value, offset: undefined })} aria-label="Host">
          <option value="">All hosts</option>
          {hostsQ.data?.hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.hostname}
            </option>
          ))}
        </select>
        {ruleId ? (
          <span className="tag" title={ruleId}>
            Rule: {alertsQ.data?.alerts[0]?.rule.id === ruleId ? alertsQ.data.alerts[0].rule.title : ruleId.slice(0, 8)}
            <button type="button" aria-label="Clear rule filter" onClick={() => patch({ rule: undefined, offset: undefined })}>
              ×
            </button>
          </span>
        ) : null}
        {statusParam || severities.length || hostId || ruleId || sp.get('q') ? (
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => {
              setText('')
              patch({ status: undefined, severity: undefined, host: undefined, rule: undefined, q: undefined, offset: undefined })
            }}
          >
            Reset filters
          </button>
        ) : null}
      </div>

      <section className="panel">
        {selected.size > 0 && canTriage ? (
          <div className="bulkbar" role="toolbar" aria-label="Bulk actions">
            <strong>{plural(selected.size, 'alert')} selected</strong>
            <span className="muted small">Set status:</span>
            {ALERT_STATUSES.map((s) => (
              <button key={s} type="button" className="btn sm" disabled={bulk.isPending} onClick={() => bulk.mutate({ status: s })}>
                {ALERT_STATUS_LABEL[s]}
              </button>
            ))}
            <button type="button" className="btn sm" disabled={bulk.isPending} onClick={() => bulk.mutate({ assignee: user.username })}>
              <Icon name="user" size={12} /> Assign to me
            </button>
            {bulk.isPending ? <Spinner small /> : null}
            <span className="grow" />
            <button type="button" className="btn ghost sm" onClick={() => setSelected(new Set())}>
              Clear selection
            </button>
          </div>
        ) : null}
        {alertsQ.isPending ? (
          <Loading />
        ) : alertsQ.isError ? (
          <ErrorState error={alertsQ.error} onRetry={() => alertsQ.refetch()} />
        ) : alertsQ.data.alerts.length === 0 ? (
          <EmptyState title="No alerts match these filters">
            {statusParam ? 'Try including more statuses.' : 'No open alerts. Resolved and false-positive alerts are hidden by default.'}
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table fixed" style={{ minWidth: 1020 }}>
                <colgroup>
                  {canTriage ? <col style={{ width: 34 }} /> : null}
                  <col style={{ width: 96 }} />
                  <col style={{ width: '30%' }} />
                  <col style={{ width: 140 }} />
                  <col />
                  <col style={{ width: 56 }} />
                  <col style={{ width: 112 }} />
                  <col style={{ width: 90 }} />
                  <col style={{ width: 86 }} />
                </colgroup>
                <thead>
                  <tr>
                    {canTriage ? (
                      <th className="check">
                        <input
                          type="checkbox"
                          aria-label="Select all on this page"
                          checked={allSelected}
                          onChange={() => setSelected(allSelected ? new Set() : new Set(pageIds))}
                        />
                      </th>
                    ) : null}
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Host</th>
                    <th>Process / command line</th>
                    <th className="right">Hits</th>
                    <th>Status</th>
                    <th>Assignee</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {alertsQ.data.alerts.map((a) => {
                    const sel = selected.has(a.id)
                    return (
                      <tr
                        key={a.id}
                        className={sel ? 'clickable selected' : 'clickable'}
                        onClick={() => navigate(`/alerts/${encodeURIComponent(a.id)}`)}
                      >
                        {canTriage ? (
                          <td className="check" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              aria-label={`Select ${a.rule.title} on ${a.hostname}`}
                              checked={sel}
                              onChange={() =>
                                setSelected((s) => {
                                  const n = new Set(s)
                                  if (n.has(a.id)) n.delete(a.id)
                                  else n.add(a.id)
                                  return n
                                })
                              }
                            />
                          </td>
                        ) : null}
                        <td>
                          <SeverityBadge severity={a.severity} />
                        </td>
                        <td className="truncate">
                          <Link to={`/alerts/${encodeURIComponent(a.id)}`} onClick={(e) => e.stopPropagation()} title={a.rule.title}>
                            {a.rule.title}
                          </Link>
                          <div className="row nowrap" style={{ gap: 4, marginTop: 3, overflow: 'hidden' }}>
                            {a.mitre.slice(0, 2).map((m, i) => (
                              <MitreTag key={i} m={m} />
                            ))}
                          </div>
                        </td>
                        <td className="truncate">
                          <Link to={`/hosts/${encodeURIComponent(a.host_id)}`} onClick={(e) => e.stopPropagation()}>
                            {a.hostname}
                          </Link>
                          {a.user ? <div className="muted xsmall truncate-inline">{a.user}</div> : null}
                        </td>
                        <td className="truncate" title={a.command_line}>
                          <span className="mono">{a.process_name ?? '—'}</span>
                          {a.command_line ? <div className="cmd xsmall truncate-inline">{a.command_line}</div> : null}
                        </td>
                        <td className="right num">{formatNumber(a.count)}</td>
                        <td>
                          <AlertStatusBadge status={a.status} />
                        </td>
                        <td className="truncate">{a.assignee ?? <span className="empty-cell">—</span>}</td>
                        <td>
                          <RelTime iso={a.last_seen} />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={LIMIT} total={total} shown={alertsQ.data.alerts.length} onChange={(o) => patch({ offset: o || undefined })} />
          </>
        )}
      </section>
    </>
  )
}
