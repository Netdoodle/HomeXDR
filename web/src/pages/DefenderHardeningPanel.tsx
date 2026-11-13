// Settings → Antivirus → Microsoft Defender hardening: which Windows hosts have HomeXDR's
// ASR rules, Network Protection and Controlled Folder Access, and in which mode.

import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { getDefenderHardening, hardeningKeys, type HardeningHost } from '../api/hardening'
import { RelTime } from '../components/Misc'
import { ErrorState, Loading } from '../components/States'

const MODE_LABEL: Record<string, string> = { off: 'Off', audit: 'Audit', enforce: 'Enforce' }

const STATUS: Record<string, { label: string; cls: string }> = {
  off: { label: 'Off', cls: 'muted' },
  applied: { label: 'Applied', cls: 'sev-text low' },
  partial: { label: 'Partly applied', cls: 'sev-text medium' },
  pending: { label: 'Sending', cls: '' },
  offline: { label: 'Offline', cls: 'muted' },
  failed: { label: 'Failed', cls: 'sev-text high' },
  not_allowed: { label: 'Not allowed', cls: 'sev-text medium' },
}

export function DefenderHardeningPanel() {
  const q = useQuery({ queryKey: hardeningKeys.status, queryFn: getDefenderHardening, refetchInterval: 20_000 })
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Microsoft Defender hardening</h2>
        <span className="hint">Attack Surface Reduction, Network Protection, Controlled Folder Access</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Turns on 14 Attack Surface Reduction rules with few false positives (Office macros starting programs, credential theft from lsass.exe, scripts
          launching downloads, unsigned programs from USB, ...), Network Protection and Controlled Folder Access. <strong>Audit</strong> only logs (Defender
          events 1122, 1124, 1125); <strong>Enforce</strong> blocks (1121, 1126) and raises an alert. The PSExec/WMI rule and Controlled Folder Access stay in
          audit mode even when enforcing. <strong>Off</strong> puts back the settings HomeXDR found. Choose the mode above, or per group under{' '}
          <Link to="/settings/groups">Settings → Groups</Link>. Needs Defender as the active antivirus.
        </p>
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Windows host</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {q.data.hosts.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="muted small">
                      No Windows hosts.
                    </td>
                  </tr>
                ) : (
                  q.data.hosts.map((h) => <HostRow key={h.host_id} h={h} />)
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function HostRow({ h }: { h: HardeningHost }) {
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
      <td className="small muted">
        {h.message}
        {h.updated_at ? (
          <>
            {' '}
            · <RelTime iso={h.updated_at} />
          </>
        ) : null}
        {h.failures?.length ? (
          <ul className="sev-text medium xsmall" style={{ margin: '4px 0 0', paddingLeft: 16 }}>
            {h.failures.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        ) : null}
        {h.settings?.length ? (
          <details>
            <summary className="xsmall">{h.settings.length} settings</summary>
            <table className="table" style={{ marginTop: 4 }}>
              <tbody>
                {h.settings.map((x) => (
                  <tr key={x.name}>
                    <td className="xsmall">{x.name}</td>
                    <td className={`xsmall ${x.actual === x.wanted ? '' : 'sev-text medium'}`}>{x.actual}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        ) : null}
      </td>
    </tr>
  )
}
