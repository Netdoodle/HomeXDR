import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { api, queryKeys, type Host } from '../api'
import { RelTime } from '../components/Misc'
import { EmptyState, QueryView } from '../components/States'
import { formatNumber, plural } from '../lib/format'

const LIMIT = 500

/** The software the agent last reported for a host, with a filter box. */
export function HostApplications({ host }: { host: Host }) {
  const q = useQuery({ queryKey: queryKeys.hostApplications(host.id), queryFn: () => api.hostApplications(host.id) })
  const [text, setText] = useState('')
  const [shown, setShown] = useState(LIMIT)
  const words = text.toLowerCase().split(/\s+/).filter(Boolean)
  const rows = useMemo(() => {
    const all = q.data?.applications ?? []
    if (!words.length) return all
    return all.filter((a) => {
      const hay = [a.name, a.version, a.type, a.architecture, a.vendor, a.source].filter(Boolean).join(' ').toLowerCase()
      return words.every((w) => hay.includes(w))
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data, text])

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Applications on {host.hostname}</h2>
        <div className="row">
          {q.data?.reported_at ? (
            <span className="hint">
              {plural(q.data.total, 'application')}, reported <RelTime iso={q.data.reported_at} />
            </span>
          ) : null}
          <input
            type="search"
            className="input"
            placeholder="Filter by name, version or type"
            aria-label="Filter applications"
            value={text}
            onChange={(e) => {
              setText(e.target.value)
              setShown(LIMIT)
            }}
          />
        </div>
      </div>
      <QueryView
        query={q}
        isEmpty={(d) => d.applications.length === 0}
        empty={
          <EmptyState title="No software list yet">
            The agent sends its software inventory every few hours (6 by default), and a list older than 14 days is not used. Check back after the next report.
          </EmptyState>
        }
      >
        {() =>
          rows.length === 0 ? (
            <EmptyState title="No applications match this filter" compact />
          ) : (
            <>
              <div className="table-wrap">
                <table className="table" style={{ minWidth: 640 }}>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Version</th>
                      <th>Type</th>
                      <th>Arch</th>
                      <th>Vendor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.slice(0, shown).map((a, i) => (
                      <tr key={`${a.name}|${a.version}|${a.type}|${a.architecture}|${i}`}>
                        <td className="truncate" title={a.install_path || a.source ? `${a.install_path ?? ''} ${a.source ? `(source package ${a.source})` : ''}`.trim() : undefined}>
                          {a.name}
                        </td>
                        <td className="mono small">{a.version || '—'}</td>
                        <td>{a.type || '—'}</td>
                        <td>{a.architecture || '—'}</td>
                        <td className="truncate">{a.vendor || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {rows.length > shown ? (
                <div className="pager">
                  <span>
                    Showing {formatNumber(shown)} of {formatNumber(rows.length)}
                  </span>
                  <button type="button" className="btn sm" onClick={() => setShown(shown + LIMIT)}>
                    Show more
                  </button>
                </div>
              ) : null}
            </>
          )
        }
      </QueryView>
    </section>
  )
}
