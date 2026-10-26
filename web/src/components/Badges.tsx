import type { AlertStatus, CommandStatus, Host, HostStatus, HostUpdate, MitreMapping, Severity } from '../api/types'
import { UPDATE_STATE_LABEL } from '../lib/agents'
import {
  ALERT_STATUS_LABEL,
  COMMAND_STATUS_LABEL,
  HOST_STATUS_LABEL,
  SEVERITY_LABEL,
} from '../lib/severity'
import { OsGlyph } from './Icon'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev ${severity}`} title={`Severity: ${SEVERITY_LABEL[severity]}`}>
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  )
}

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status ${status}`}>{ALERT_STATUS_LABEL[status] ?? status}</span>
}

export function CommandStatusBadge({ status }: { status: CommandStatus }) {
  return <span className={`badge cmd-status ${status}`}>{COMMAND_STATUS_LABEL[status] ?? status}</span>
}

export function StatusDot({ status, label }: { status: HostStatus | string; label?: boolean }) {
  const text = HOST_STATUS_LABEL[status as HostStatus] ?? status
  return (
    <span className="row nowrap" style={{ gap: 7 }}>
      <span className={`dot ${status}`} aria-hidden="true" />
      {label ? <span>{text}</span> : <span className="sr-only">{text}</span>}
    </span>
  )
}

export function osLabel(os: Host['os']): string {
  if (os.platform === 'network') return [os.name, os.version].filter(Boolean).join(' ') || 'Network device'
  const name = os.name || { windows: 'Windows', linux: 'Linux', darwin: 'macOS' }[os.platform] || os.platform
  return [name, os.version].filter(Boolean).join(' ')
}

export function OsLabel({ os, short }: { os: Host['os']; short?: boolean }) {
  const label = osLabel(os)
  return (
    <span className="os" title={[label, os.kernel].filter(Boolean).join(' · ')}>
      <OsGlyph platform={os.platform} />
      <span className="truncate-inline">{short ? os.name || os.platform : label}</span>
    </span>
  )
}

export function MitreTag({ m }: { m: MitreMapping }) {
  const id = m.technique_id
  const title = [m.tactic, m.technique].filter(Boolean).join(' · ')
  const href = id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : undefined
  const content = (
    <>
      {id ?? m.tactic}
      {m.technique ? <span className="faint"> {m.technique}</span> : null}
    </>
  )
  return href ? (
    <a className="mitre" href={href} target="_blank" rel="noreferrer noopener" title={title}>
      {content}
    </a>
  ) : (
    <span className="mitre" title={title}>
      {content}
    </span>
  )
}

export function Tags({ tags, max }: { tags: string[]; max?: number }) {
  if (!tags?.length) return <span className="empty-cell">—</span>
  const shown = max ? tags.slice(0, max) : tags
  return (
    <span className="tags">
      {shown.map((t) => (
        <span key={t} className="tag">
          {t}
        </span>
      ))}
      {max && tags.length > max ? <span className="tag" title={tags.slice(max).join(', ')}>+{tags.length - max}</span> : null}
    </span>
  )
}

export function AlertCount({ n }: { n: number }) {
  if (!n) return <span className="empty-cell">0</span>
  return <span className="badge count alerts">{n}</span>
}

export function RiskScore({ score }: { score: number }) {
  const pct = Math.max(0, Math.min(100, score))
  return (
    <span className="risk" title={`Risk score ${score}/100`}>
      <span className="risk-bar" aria-hidden="true">
        <span style={{ width: `${pct}%` }} />
      </span>
      {score}
    </span>
  )
}

export function UpdateBadge({ update }: { update?: HostUpdate }) {
  if (!update) return null
  return (
    <span className={`badge upd ${update.state}`} title={update.reason ?? (update.target ? `Target ${update.target}` : undefined)}>
      {UPDATE_STATE_LABEL[update.state]}
    </span>
  )
}
