// Labels and notes for agent lifecycle: update policy and decommissioning.

import type { HostUpdate, UpdateMode, UpdateRule, UpdateState } from '../api/types'
import type { Choice } from './ai'

export const UPDATE_MODE_CHOICES: Choice<UpdateMode>[] = [
  { value: 'latest', label: 'Latest', note: 'Agents install each new signed release as soon as the server has it.' },
  {
    value: 'n-1',
    label: 'N-1 (one release behind)',
    note: 'Agents stay one release behind the newest, so each release has run on other hosts first. Needs two archived releases.',
  },
  { value: 'pinned', label: 'Pinned version', note: 'Agents update to one chosen release and stay on it.' },
  { value: 'off', label: 'Off', note: 'No automatic updates. “Update now” on a host still updates it to the latest release.' },
]

export const UPDATE_MODE_LABEL: Record<UpdateMode, string> = {
  latest: 'Latest',
  'n-1': 'N-1',
  pinned: 'Pinned',
  off: 'Off',
}

export const UPDATE_STATE_LABEL: Record<UpdateState, string> = {
  current: 'Up to date',
  pending: 'Waiting',
  updating: 'Updating',
  failed: 'Update failed',
  ahead: 'Newer than policy',
  off: 'Updates off',
  none: 'No release',
}

/** Decommission presets in days (0 = never). */
export const DECOMMISSION_CHOICES = [0, 7, 14, 30, 60, 90, 180]

export function decommissionLabel(days: number): string {
  return days === 0 ? 'Never' : `After ${days} days offline`
}

export function ruleLabel(rule: UpdateRule): string {
  return rule.mode === 'pinned' && rule.version ? `Pinned to ${shortVersion(rule.version)}` : UPDATE_MODE_LABEL[rule.mode]
}

/** "0.0.0-20261021163411.88faa4a" → "88faa4a (Oct 21 2026)"; other versions unchanged. */
export function shortVersion(v?: string): string {
  if (!v) return ''
  const m = /^\d+\.\d+\.\d+-(\d{4})(\d{2})(\d{2})\d{6}\.([0-9a-f]+)$/.exec(v)
  if (!m) return v
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])))
  return `${m[4]} (${d.toLocaleDateString('en', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })})`
}

/** Whether an "Update now" button makes sense. */
export function canUpdateNow(u?: HostUpdate): boolean {
  return !!u && u.state !== 'current' && u.state !== 'ahead' && u.state !== 'none'
}

/** Certificate state for display. */
export function certState(expires?: string, now = Date.now()): { text: string; level: 'ok' | 'warn' | 'danger' } | null {
  if (!expires) return null
  const ms = Date.parse(expires) - now
  const days = Math.round(ms / 86_400_000)
  if (ms <= 0) return { text: `Expired ${-days} days ago; the agent renews it when it reconnects`, level: 'danger' }
  if (days <= 30) return { text: `Expires in ${days} days; renewal is overdue`, level: 'warn' }
  return { text: `Valid for ${days} more days; renewed automatically`, level: 'ok' }
}

/** Time zones for the maintenance window, the browser's first. */
export function timeZones(): string[] {
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone
  let all: string[] = []
  try {
    all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? []
  } catch {
    all = []
  }
  return [...new Set([local, 'UTC', ...all])]
}
