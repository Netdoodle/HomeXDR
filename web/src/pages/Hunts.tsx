import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router'
import { api, queryKeys, type Hunt } from '../api'
import { useCan } from '../components/Auth'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { RelTime } from '../components/Misc'
import { EmptyState, QueryView } from '../components/States'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { describeTarget } from '../lib/hunts'

export function HuntProgress({ hunt: h }: { hunt: Hunt }) {
  const s = h.stats
  const total = Math.max(1, s.scheduled)
  return (
    <div className="stack" style={{ gap: 3 }}>
      <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={s.scheduled} aria-valuenow={s.completed + s.failed} aria-label="Hunt progress">
        {s.completed ? <span className="p-ok" style={{ width: `${(s.completed / total) * 100}%` }} /> : null}
        {s.failed ? <span className="p-fail" style={{ width: `${(s.failed / total) * 100}%` }} /> : null}
      </div>
      <span className="xsmall muted num">
        {s.completed}/{s.scheduled} done{s.failed ? ` · ${s.failed} failed` : ''}
      </span>
    </div>
  )
}

export function HuntStatusBadge({ status }: { status: Hunt['status'] }) {
  const cls = status === 'running' ? 'badge cmd-status running' : status === 'completed' ? 'badge cmd-status completed' : 'badge cmd-status expired'
  return <span className={cls}>{status === 'running' ? 'Running' : status === 'completed' ? 'Completed' : 'Stopped'}</span>
}

export function HuntsPage() {
  useDocumentTitle('Hunts')
  const navigate = useNavigate()
  const canCreate = useCan('analyst')
  const q = useQuery({
    queryKey: queryKeys.hunts,
    queryFn: api.listHunts,
    refetchInterval: (query) => (query.state.data?.hunts.some((h) => h.status === 'running') ? 5000 : 30_000),
  })
  return (
    <>
      <PageHeader
        title="Hunts"
        subtitle="Run one artifact across many hosts, including hosts that come online later"
        actions={
          canCreate ? (
            <Link className="btn primary" to="/hunts/new">
              <Icon name="plus" size={14} /> New hunt
            </Link>
          ) : null
        }
      />
      <section className="panel">
        <QueryView
          query={q}
          isEmpty={(d) => d.hunts.length === 0}
          empty={
            <EmptyState title="No hunts yet" action={canCreate ? <Link to="/hunts/new">Start a hunt</Link> : undefined}>
              A hunt collects an artifact such as persistence.autoruns from every matching host.
            </EmptyState>
          }
        >
          {(d) => (
            <div className="table-wrap">
              <table className="table fixed" style={{ minWidth: 920 }}>
                <colgroup>
                  <col style={{ width: '18%' }} />
                  <col />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: 96 }} />
                  <col style={{ width: 150 }} />
                  <col style={{ width: 70 }} />
                  <col style={{ width: 90 }} />
                  <col style={{ width: 96 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Artifact</th>
                    <th>Description</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th className="right">Rows</th>
                    <th>By</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {d.hunts.map((h) => (
                    <tr key={h.id} className="clickable" onClick={() => navigate(`/hunts/${encodeURIComponent(h.id)}`)}>
                      <td className="truncate mono">
                        <Link to={`/hunts/${encodeURIComponent(h.id)}`} onClick={(e) => e.stopPropagation()}>
                          {h.artifact}
                        </Link>
                      </td>
                      <td className="truncate" title={h.description}>
                        {h.description || <span className="empty-cell">—</span>}
                      </td>
                      <td className="truncate">{describeTarget(h.target)}</td>
                      <td>
                        <HuntStatusBadge status={h.status} />
                      </td>
                      <td>
                        <HuntProgress hunt={h} />
                      </td>
                      <td className="right num">{formatNumber(h.stats.rows)}</td>
                      <td className="truncate">{h.created_by}</td>
                      <td>
                        <RelTime iso={h.created_at} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>
    </>
  )
}
