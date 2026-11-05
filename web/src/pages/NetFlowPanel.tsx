// Settings → Integrations: the NetFlow/IPFIX receiver's intake.

import type { NetFlowStats } from '../api'
import { RelTime } from '../components/Misc'
import { EmptyState } from '../components/States'
import { formatNumber } from '../lib/format'

const VERSION_LABEL: Record<number, string> = { 5: 'NetFlow v5', 9: 'NetFlow v9', 10: 'IPFIX' }

export function NetFlowPanel({ stats }: { stats?: NetFlowStats }) {
  if (!stats) return null
  const lost = stats.dropped + stats.discarded + stats.failed
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>NetFlow / IPFIX intake</h2>
        <span className="row small">
          <span className={`dot ${stats.listening ? 'online' : 'revoked'}`} aria-hidden="true" />
          {stats.listening ? `Listening on ${stats.addr} (UDP)` : stats.enabled ? 'Not listening: check the server log' : 'Off'}
        </span>
      </div>
      {!stats.enabled ? (
        <EmptyState title="The flow receiver is off" compact>
          Flows name the real device behind NAT, which traffic detections need. Set HOMEXDR_NETFLOW_ADDR=:2055 on the server, then follow docs/network-visibility.md.
        </EmptyState>
      ) : (
        <>
          <div className="stats" style={{ padding: 12 }}>
            <div className="stat">
              <span className="label">Packets</span>
              <span className="value">{formatNumber(stats.packets)}</span>
            </div>
            <div className="stat">
              <span className="label">Flows stored</span>
              <span className="value">{formatNumber(stats.records)}</span>
            </div>
            <div className="stat">
              <span className="label">Lost</span>
              <span className="value">{formatNumber(lost)}</span>
              <span className="sub" title="Queue full, no room for data waiting on a template, or the event store refused them">
                queue {formatNumber(stats.dropped)}, template {formatNumber(stats.discarded)}, store {formatNumber(stats.failed)}
              </span>
            </div>
            <div className="stat">
              <span className="label">Malformed</span>
              <span className="value">{formatNumber(stats.malformed)}</span>
            </div>
            <div className="stat">
              <span className="label">Not allowed</span>
              <span className="value">{formatNumber(stats.refused)}</span>
              <span className="sub">senders off HOMEXDR_NETFLOW_ALLOW</span>
            </div>
          </div>
          {stats.exporters.length === 0 ? (
            <EmptyState title="No exporters yet" compact>
              Nothing has sent flows here. See docs/network-visibility.md for the firewall steps.
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Exporter</th>
                    <th>Format</th>
                    <th className="right">Flows</th>
                    <th className="right">Templates</th>
                    <th>Last packet</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.exporters.map((e) => (
                    <tr key={e.ip}>
                      <td className="mono">{e.ip}</td>
                      <td>
                        <span className="tag">{VERSION_LABEL[e.version] ?? `Version ${e.version}`}</span>
                      </td>
                      <td className="right num">{formatNumber(e.records)}</td>
                      <td className="right num">{e.version === 5 ? '—' : formatNumber(e.templates)}</td>
                      <td>
                        <RelTime iso={e.last_seen} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}
