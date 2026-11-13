// Settings → Antivirus → Windows App Control: which files Windows refuses to start and
// where the policy is applied.

import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { appControlKeys, getAppControl, type AppControlHost } from '../api/antivirus'
import { RelTime } from '../components/Misc'
import { ErrorState, Loading } from '../components/States'

const MODE_LABEL: Record<string, string> = { off: 'Off', audit: 'Audit', enforce: 'Enforce' }

const STATUS: Record<string, { label: string; cls: string }> = {
  off: { label: 'Off', cls: 'muted' },
  applied: { label: 'Applied', cls: 'sev-text low' },
  pending: { label: 'Sending', cls: '' },
  offline: { label: 'Offline', cls: 'muted' },
  failed: { label: 'Failed', cls: 'sev-text high' },
  not_allowed: { label: 'Not allowed', cls: 'sev-text medium' },
}

export function AppControlPanel() {
  const q = useQuery({ queryKey: appControlKeys.status, queryFn: getAppControl, refetchInterval: 20_000 })
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Windows App Control</h2>
        <span className="hint">Block confirmed malware before it starts</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Files the antivirus confirmed as malware are added to a Windows App Control policy (<em>HomeXDR block list</em>) on Windows hosts, so Windows
          itself refuses to start them on every PC, not only where they were found. <strong>Audit</strong> only logs what would be blocked (Windows event
          3076); <strong>Enforce</strong> blocks (event 3077). Hacking tools and suspicious traits are never blocked, and allowlisted hashes are left out.
          Choose the mode above for every host, or per group under <Link to="/settings/groups">Settings → Groups</Link>. Needs Windows 11 22H2 or later.
        </p>
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Windows host</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th className="right">Blocked files</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.hosts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="muted small">
                        No Windows hosts.
                      </td>
                    </tr>
                  ) : (
                    q.data.hosts.map((h) => <HostRow key={h.host_id} h={h} />)
                  )}
                </tbody>
              </table>
            </div>
            <details>
              <summary className="small">
                {q.data.rules.length} file{q.data.rules.length === 1 ? '' : 's'} on the block list
              </summary>
              {q.data.rules.length === 0 ? (
                <p className="small muted">
                  None yet. A file joins once the antivirus confirms it as malware and its Authenticode hash is known: from the copy the server scanned, or
                  reported by the agent when it quarantines the file.
                </p>
              ) : (
                <div className="table-wrap" style={{ marginTop: 8 }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>File</th>
                        <th>Detection</th>
                        <th>SHA-256</th>
                        <th>Since</th>
                      </tr>
                    </thead>
                    <tbody>
                      {q.data.rules.map((r) => (
                        <tr key={r.sha256}>
                          <td className="truncate" title={r.path}>
                            {r.name}
                          </td>
                          <td className="small">{r.signature || r.source}</td>
                          <td className="mono xsmall truncate" title={r.sha256}>
                            {r.sha256}
                          </td>
                          <td>
                            <RelTime iso={r.checked_at} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </details>
          </>
        )}
      </div>
    </div>
  )
}

function HostRow({ h }: { h: AppControlHost }) {
  const s = STATUS[h.status] ?? { label: h.status, cls: '' }
  return (
    <tr>
      <td>
        <Link to={`/hosts/${encodeURIComponent(h.host_id)}`}>{h.hostname}</Link>
      </td>
      <td>
        {MODE_LABEL[h.mode] ?? h.mode} <span className="muted xsmall">from {h.mode_from || 'Global'}</span>
      </td>
      <td className={s.cls}>{s.label}</td>
      <td className="right num">{h.status === 'applied' ? h.rules : '—'}</td>
      <td className="small muted">
        {h.message}
        {h.updated_at ? (
          <>
            {' '}
            · <RelTime iso={h.updated_at} />
          </>
        ) : null}
      </td>
    </tr>
  )
}
