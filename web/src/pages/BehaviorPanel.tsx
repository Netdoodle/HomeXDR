// The behaviour detectors' status, shown on the Devices page.

import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { behaviorStatus, networkKeys, type DetectorStatus } from '../api/network'
import { RelTime } from '../components/Misc'
import { QueryView } from '../components/States'
import { stateDot, STATE_LABEL } from '../lib/network'
import { formatDateTime } from '../lib/time'

function Detail({ d }: { d: DetectorStatus }) {
  if (d.status === 'error') return <span>{d.error}</span>
  const parts: string[] = []
  if (d.status === 'learning' && d.learning_until) parts.push(`Learning what is normal until ${formatDateTime(d.learning_until)}. Nothing is reported until then.`)
  if (d.data_needed) parts.push(d.status === 'needs_data' ? `Needs ${d.data_needed}` : d.data_needed)
  return parts.length ? <span>{parts.join(' ')}</span> : null
}

export function BehaviorPanel() {
  const q = useQuery({ queryKey: networkKeys.behaviorStatus, queryFn: behaviorStatus, refetchInterval: 60_000 })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Behaviour detection</h2>
        <Link className="small" to="/settings/network">
          Toggles and thresholds
        </Link>
      </div>
      <QueryView query={q}>
        {(data) => (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 760 }}>
              <thead>
                <tr>
                  <th>Detector</th>
                  <th>Status</th>
                  <th>Last run</th>
                  <th className="right" title="Last run, and since it began">
                    Findings
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.detectors.map((d) => (
                  <tr key={d.id}>
                    <td className="small">
                      <strong>{d.title}</strong>
                      <div className="muted">{d.about}</div>
                    </td>
                    <td className="small" style={{ minWidth: 240 }}>
                      <span className="row" style={{ gap: 6 }}>
                        <span className={`dot ${stateDot(d.status)}`} aria-hidden="true" />
                        {STATE_LABEL[d.status]}
                      </span>
                      <div className="xsmall muted">
                        <Detail d={d} />
                      </div>
                    </td>
                    <td className="small" style={{ whiteSpace: 'nowrap' }}>
                      {d.last_run ? <RelTime iso={d.last_run} /> : <span className="muted">—</span>}
                    </td>
                    <td className="right num small">
                      {d.last_finding_count}
                      <span className="muted"> / {d.total_finding_count}</span>
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
