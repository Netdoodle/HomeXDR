import type { AlertStatus, CommandStatus, HostStatus, Severity } from '../api/types'

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
}

/** Risk score derived from severity, per docs/api.md. */
export const SEVERITY_RISK: Record<Severity, number> = {
  informational: 10,
  low: 21,
  medium: 47,
  high: 73,
  critical: 99,
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a]
}

export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New',
  in_progress: 'In progress',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export const OPEN_ALERT_STATUSES: AlertStatus[] = ['new', 'in_progress']

export const HOST_STATUS_LABEL: Record<HostStatus, string> = {
  online: 'Online',
  offline: 'Offline',
  isolated: 'Isolated',
  revoked: 'Revoked',
  decommissioned: 'Decommissioned',
}

export const COMMAND_STATUS_LABEL: Record<CommandStatus, string> = {
  queued: 'Queued',
  delivered: 'Delivered',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  rejected: 'Rejected',
  expired: 'Expired',
}
