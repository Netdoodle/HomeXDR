// The noisiest shapes among open alerts, with a one-click path into the suppress dialog.

import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '../api'
import { noiseKeys, topRepeating, type RepeatingShape } from '../api/noise'
import { formatNumber } from '../lib/format'
import { formFromAlert, type SuppressForm } from '../lib/suppressions'
import { useCan } from './Auth'
import { SeverityBadge } from './Badges'
import { Icon } from './Icon'
import { RelTime } from './Misc'
import { Spinner } from './States'
import { SuppressDialog } from './SuppressDialog'
import { useToast } from './Toast'

/** The panel starts open when something is repeating this much. */
const OPEN_FROM_HITS = 20

export function TopRepeatingPanel() {
  const canSuppress = useCan('admin')
  const toast = useToast()
  const [form, setForm] = useState<SuppressForm | null>(null)
  const q = useQuery({ queryKey: noiseKeys.shapes, queryFn: topRepeating, refetchInterval: 60_000 })
  const open = useMutation({
    mutationFn: (s: RepeatingShape) => api.getAlert(s.sample_alert_id),
    onSuccess: (a) => setForm(formFromAlert(a)),
    onError: (e) => toast.error(e),
  })
  const shapes = q.data?.shapes ?? []
  if (shapes.length === 0) return null
  return (
    <>
      <details className="panel" style={{ marginBottom: 12 }} open={shapes[0].hits >= OPEN_FROM_HITS}>
        <summary className="panel-header" style={{ cursor: 'pointer' }}>
          <h2>Top repeating</h2>
          <span className="hint">
            The same rule, host and process, over and over in the last {q.data?.hours} hours. Often a scheduled job worth suppressing.
          </span>
        </summary>
        <div className="table-wrap">
          <table className="table compact">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Host</th>
                <th>Process</th>
                <th className="right">Hits</th>
                <th>Last seen</th>
                {canSuppress ? <th /> : null}
              </tr>
            </thead>
            <tbody>
              {shapes.map((s) => (
                <tr key={s.sample_alert_id}>
                  <td>
                    <span className="row" style={{ gap: 6 }}>
                      <SeverityBadge severity={s.severity} />
                      <Link to={`/alerts/${encodeURIComponent(s.sample_alert_id)}`}>{s.rule_title || s.rule_id}</Link>
                    </span>
                  </td>
                  <td>{s.hostname}</td>
                  <td className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>
                    {s.process || <span className="faint">none</span>}
                    {s.parent ? <span className="faint"> from {s.parent}</span> : null}
                  </td>
                  <td className="right" title={`${formatNumber(s.alerts)} open alerts`}>
                    {formatNumber(s.hits)}
                  </td>
                  <td>
                    <RelTime iso={s.last_seen} />
                  </td>
                  {canSuppress ? (
                    <td className="right">
                      <button type="button" className="btn sm" disabled={open.isPending} onClick={() => open.mutate(s)}>
                        {open.isPending && open.variables?.sample_alert_id === s.sample_alert_id ? <Spinner small /> : <Icon name="filter" size={12} />} Suppress
                      </button>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <SuppressDialog initial={form} onClose={() => setForm(null)} />
    </>
  )
}
