// Data health: feed health, doctor and self-check. Types and calls in one place, so the
// shared api files stay as they are.

import { http } from './client'

export type FeedStatus = 'ok' | 'silent' | 'learning' | 'never_seen' | 'quiet' | 'muted' | 'host_offline'

export interface FeedView {
  host_id: string
  hostname: string
  /** Module and dataset are empty on the row about the host as a whole. */
  module: string
  dataset: string
  status: FeedStatus
  explanation?: string
  first_seen?: string
  last_seen?: string
  arrivals: number
  usual_gap_sec: number
  allowance_sec: number
  silent_sec: number
  muted: boolean
  expected: boolean
  can_alert: boolean
  /** the host label whose rule sets this host's offline allowance */
  label?: string
}

/** A fixed offline allowance for every host with this label. */
export interface OfflineLabelRule {
  label: string
  hours: number
}

/** A source HomeXDR reads from on a timer, such as a DNS resolver's query log. Not a host. */
export interface PulledSource {
  id: string
  name: string
  address: string
  dataset: string
  status: 'online' | 'offline' | 'waiting'
  explanation?: string
  last_poll?: string
  last_success?: string
  interval_sec: number
  settings_path: string
}

export interface FeedReport {
  sources: FeedView[]
  bootstrapped: boolean
  grace_until?: string
  note?: string
  offline_labels: OfflineLabelRule[]
  pulled?: PulledSource[]
}

export interface FeedPatch {
  host_id: string
  module: string
  dataset: string
  muted?: boolean
  expected?: boolean
}

/** Refused connections on the internet-facing agent listener. */
export interface RefusedReport {
  /** false when the internet listener is off */
  enabled: boolean
  /** since the start of the current clock hour */
  this_hour: number
  /** the last full hour */
  previous_hour: number
  last_24h: number
  top_sources: { ip: string; count: number }[]
}

export const healthKeys = {
  feeds: ['health', 'feeds'] as const,
  external: ['health', 'external'] as const,
}

export const getRefused = () => http.get<RefusedReport>('/api/health/external')

export const getFeeds = () => http.get<FeedReport>('/api/health/feeds')
export const patchFeed = (p: FeedPatch) => http.patch<FeedReport>('/api/health/feeds', p)
export const putOfflineLabels = (rules: OfflineLabelRule[]) => http.put<FeedReport>('/api/health/offline-labels', { rules })

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'skip'

export interface CheckResult {
  id: string
  name: string
  status: CheckStatus
  message: string
  fix?: string
}

export interface DoctorReport {
  at: string
  ok: number
  warn: number
  fail: number
  results: CheckResult[]
}

export interface SelfCheckFailure {
  rule_id: string
  title: string
  reason: string
}

export interface FieldCount {
  field: string
  rules: number
}

export interface CoverageGroup {
  logsource: string
  rules: number
  can_fire: number
  no_events: number
  missing_field: number
  missing?: FieldCount[]
}

export interface SelfCheckCoverage {
  days: number
  events: number
  sources: number
  rules: number
  can_fire: number
  cannot_fire: number
  groups: CoverageGroup[]
  missing: FieldCount[]
  note?: string
}

export interface SelfCheckResult {
  at: string
  took_ms: number
  rules: number
  fired: number
  rate: number
  failed: number
  failures: SelfCheckFailure[]
  pipeline: { passed: boolean; message: string }
  coverage?: SelfCheckCoverage
  previous?: { at: string; rules: number; fired: number; rate: number; cannot_fire: number; pipeline: boolean }
  regression: boolean
  reason?: string
}

export interface SelfCheckState {
  running: boolean
  last?: SelfCheckResult
}

export const doctorKey = ['health', 'doctor'] as const
export const selfCheckKey = ['health', 'selfcheck'] as const

export const getDoctor = (refresh = false) => http.get<DoctorReport>('/api/doctor', refresh ? { refresh: 1 } : undefined)
export const getSelfCheck = () => http.get<SelfCheckState>('/api/selfcheck')
export const startSelfCheck = () => http.post<SelfCheckState>('/api/selfcheck')
