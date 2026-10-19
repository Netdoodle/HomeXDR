import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, queryKeys, type HostFilter } from '../api'
import { AlertCount, OsLabel, StatusDot, Tags } from '../components/Badges'
import { PageHeader } from '../components/Layout'
import { RelTime } from '../components/Misc'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { plural } from '../lib/format'
import { useDebounced, useDocumentTitle, useUrlState } from '../lib/hooks'

export function HostsPage() {
  useDocumentTitle('Hosts')
  const [sp, patch] = useUrlState()
  const navigate = useNavigate()
  const [text, setText] = useState(sp.get('q') ?? '')
  const debounced = useDebounced(text, 300)
  const appliedQ = useRef(debounced)
  useEffect(() => {
    if (debounced !== appliedQ.current) {
      appliedQ.current = debounced
      patch({ q: debounced })
    }
  }, [debounced, patch])

  const filter: HostFilter = {
    q: sp.get('q') || undefined,
    status: sp.get('status') || undefined,
    label: sp.get('label') || undefined,
    platform: sp.get('platform') || undefined,
  }
  const q = useQuery({
    queryKey: queryKeys.hosts(filter),
    queryFn: () => api.listHosts(filter),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  // Unfiltered list just for the label dropdown.
  const all = useQuery({ queryKey: queryKeys.hosts({}), queryFn: () => api.listHosts({}), staleTime: 60_000 })
  const labels = useMemo(() => [...new Set((all.data?.hosts ?? []).flatMap((h) => h.labels))].sort(), [all.data])

  return (
    <>
      <PageHeader
        title="Hosts"
        subtitle={q.data ? plural(q.data.total, 'host') : 'Enrolled agents and syslog sources'}
        actions={
          <>
            {q.isFetching && !q.isPending ? <Spinner small /> : null}
            <Link className="btn" to="/settings/tokens">
              Enroll a host
            </Link>
          </>
        }
      />
      <div className="filters">
        <input type="search" className="input" placeholder="Hostname or IP" value={text} onChange={(e) => setText(e.target.value)} aria-label="Filter hosts" />
        <select className="select" value={filter.status ?? ''} onChange={(e) => patch({ status: e.target.value })} aria-label="Status">
          <option value="">Any status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="isolated">Isolated</option>
          <option value="revoked">Revoked</option>
        </select>
        <select className="select" value={filter.platform ?? ''} onChange={(e) => patch({ platform: e.target.value })} aria-label="Platform">
          <option value="">Any platform</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="darwin">macOS</option>
          <option value="network">Network device</option>
        </select>
        <select className="select" value={filter.label ?? ''} onChange={(e) => patch({ label: e.target.value })} aria-label="Label">
          <option value="">Any label</option>
          {labels.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </div>
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : q.data.hosts.length === 0 ? (
          filter.q || filter.status || filter.label || filter.platform ? (
            <EmptyState title="No hosts match these filters" />
          ) : (
            <EmptyState title="No hosts enrolled yet" action={<Link to="/settings/tokens">Create an enrollment token</Link>}>
              Install the agent on a machine, or point a firewall's syslog at the server.
            </EmptyState>
          )
        ) : (
          <div className="table-wrap">
            <table className="table fixed" style={{ minWidth: 900 }}>
              <colgroup>
                <col style={{ width: 100 }} />
                <col style={{ width: '18%' }} />
                <col style={{ width: '20%' }} />
                <col style={{ width: '16%' }} />
                <col />
                <col style={{ width: 80 }} />
                <col style={{ width: 96 }} />
                <col style={{ width: 70 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Hostname</th>
                  <th>OS</th>
                  <th>IP addresses</th>
                  <th>Labels</th>
                  <th>Agent</th>
                  <th>Last seen</th>
                  <th className="right">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {q.data.hosts.map((h) => (
                  <tr key={h.id} className="clickable" onClick={() => navigate(`/hosts/${encodeURIComponent(h.id)}`)}>
                    <td>
                      <StatusDot status={h.status} label />
                    </td>
                    <td className="truncate">
                      <Link to={`/hosts/${encodeURIComponent(h.id)}`} onClick={(e) => e.stopPropagation()}>
                        {h.hostname}
                      </Link>
                      {h.kind === 'network' ? <div className="xsmall muted">syslog source</div> : null}
                    </td>
                    <td className="truncate">
                      <OsLabel os={h.os} />
                    </td>
                    <td className="truncate mono" title={h.ips.join(', ')}>
                      {h.ips.join(', ') || '—'}
                    </td>
                    <td className="truncate">
                      <Tags tags={h.labels} max={4} />
                    </td>
                    <td className="truncate mono small">{h.agent_version ?? (h.kind === 'network' ? '—' : '?')}</td>
                    <td>
                      <RelTime iso={h.last_seen} />
                    </td>
                    <td className="right">
                      <AlertCount n={h.open_alerts} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
