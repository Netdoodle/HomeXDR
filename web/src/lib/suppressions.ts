// Turns an alert into a suggested suppression, and form state into an API spec.

import type { Suppression, SuppressionCondition, SuppressionOp, SuppressionSpec } from '../api/noise'
import type { Alert } from '../api/types'

export const SUPPRESSION_OPS: { value: SuppressionOp; label: string }[] = [
  { value: 'equals', label: 'is exactly' },
  { value: 'contains', label: 'contains' },
  { value: 'startswith', label: 'starts with' },
  { value: 'endswith', label: 'ends with' },
]

export const SUPPRESSION_FIELDS = [
  'process.executable',
  'process.name',
  'process.command_line',
  'process.parent.executable',
  'process.parent.name',
  'process.parent.command_line',
  'process.user.name',
  'file.path',
  'destination.ip',
  'destination.domain',
  'source.ip',
]

export interface SuppressForm {
  ruleId: string
  ruleTitle: string
  useRule: boolean
  hostId: string
  hostname: string
  useHost: boolean
  conditions: SuppressionCondition[]
}

export const EMPTY_SUPPRESS_FORM: SuppressForm = {
  ruleId: '',
  ruleTitle: '',
  useRule: true,
  hostId: '',
  hostname: '',
  useHost: false,
  conditions: [{ field: 'process.executable', op: 'equals', value: '' }],
}

/** The longest condition value the API accepts. */
const MAX_VALUE = 1024

/**
 * Suggests a suppression for this alert's rule, host, process and parent. File and network
 * events do not say what started the process, so the command line stands in for the parent:
 * the executable alone would also hide the same program run by anyone else. A process in a
 * container also gets its image, so the same command elsewhere still alerts.
 */
export function formFromAlert(a: Alert): SuppressForm {
  const ev = a.event ?? a.events?.[0]
  const p = ev?.process
  const conditions: SuppressionCondition[] = []
  // The image without its tag, so the suppression survives container updates.
  if (ev?.container?.image?.name) conditions.push({ field: 'container.image.name', op: 'equals', value: ev.container.image.name })
  if (p?.executable) conditions.push({ field: 'process.executable', op: 'equals', value: p.executable })
  else if (p?.name ?? a.process_name) conditions.push({ field: 'process.name', op: 'equals', value: (p?.name ?? a.process_name)! })
  const command = p?.command_line ?? a.command_line
  if (p?.parent?.executable) conditions.push({ field: 'process.parent.executable', op: 'equals', value: p.parent.executable })
  else if (p?.parent?.name) conditions.push({ field: 'process.parent.name', op: 'equals', value: p.parent.name })
  else if (command) {
    conditions.push(
      command.length > MAX_VALUE
        ? { field: 'process.command_line', op: 'startswith', value: command.slice(0, MAX_VALUE) }
        : { field: 'process.command_line', op: 'equals', value: command },
    )
  }
  return {
    ruleId: a.rule.id,
    ruleTitle: a.rule.title,
    useRule: true,
    hostId: a.host_id,
    hostname: a.hostname,
    useHost: true,
    conditions,
  }
}

/** Conditions with something in them; a half-filled row is left out, not sent. */
export function filledConditions(conditions: SuppressionCondition[]): SuppressionCondition[] {
  return conditions.filter((c) => c.field.trim() && c.value.trim()).map((c) => ({ ...c, field: c.field.trim() }))
}

/** What the form currently matches, in the shape the API takes. */
export function specFromForm(f: SuppressForm): SuppressionSpec {
  return {
    rule_id: f.useRule ? f.ruleId.trim() || undefined : undefined,
    host_id: f.useHost ? f.hostId || undefined : undefined,
    conditions: filledConditions(f.conditions),
  }
}

/** A suppression with neither a rule nor a condition matches everything: refused. */
export function hasScope(spec: SuppressionSpec): boolean {
  return !!spec.rule_id || (spec.conditions?.length ?? 0) > 0
}

/** A whole rule on every host. Allowed, but only when confirmed. */
export function isBroad(spec: SuppressionSpec): boolean {
  return !!spec.rule_id && !spec.host_id && (spec.conditions?.length ?? 0) === 0
}

export type ExpiryChoice = '30' | '90' | '365' | 'never'

export function expiryFields(choice: ExpiryChoice, now: number = Date.now()): Pick<SuppressionSpec, 'expires_at' | 'never_expires'> {
  if (choice === 'never') return { never_expires: true }
  return { expires_at: new Date(now + Number(choice) * 86_400_000).toISOString() }
}

export function isExpired(s: Pick<Suppression, 'expires_at'>, now: number = Date.now()): boolean {
  return !!s.expires_at && new Date(s.expires_at).getTime() <= now
}

export function describeOp(op: SuppressionOp): string {
  return SUPPRESSION_OPS.find((o) => o.value === op)?.label ?? op
}
