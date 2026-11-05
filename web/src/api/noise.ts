// API helpers for suppressions and the "Top repeating" panel (docs/alerts.md).

import { http } from './client'
import type { Severity } from './types'

const enc = encodeURIComponent

export type SuppressionOp = 'equals' | 'contains' | 'startswith' | 'endswith'

export interface SuppressionCondition {
  field: string
  op: SuppressionOp
  value: string
}

export interface Suppression {
  id: string
  rule_id?: string
  rule_title?: string
  host_id?: string
  hostname?: string
  conditions: SuppressionCondition[]
  reason: string
  created_by: string
  created_at: string
  /** null means it never expires */
  expires_at: string | null
  enabled: boolean
  hit_count: number
  last_hit_at: string | null
  /** hits it matched but was not allowed to close (critical or must-alert) */
  override_count: number
  last_override_at: string | null
}

export interface SuppressionSpec {
  rule_id?: string
  host_id?: string
  conditions?: SuppressionCondition[]
  reason?: string
  expires_at?: string
  never_expires?: boolean
  enabled?: boolean
  confirm_broad?: boolean
  apply?: boolean
}

export interface SuppressionPatch {
  enabled?: boolean
  reason?: string
  expires_at?: string
  never_expires?: boolean
}

export interface SuppressionSample {
  id: string
  rule_title: string
  severity: Severity
  hostname: string
  process_name?: string
  command_line?: string
  count: number
  last_seen: string
}

export interface SuppressionPreview {
  matches: number
  hits: number
  kept: number
  sample: SuppressionSample[]
}

export interface SuppressionResult {
  suppression: Suppression
  closed: number
  kept: number
}

export interface RepeatingShape {
  rule_id: string
  rule_title: string
  severity: Severity
  host_id: string
  hostname: string
  process?: string
  parent?: string
  alerts: number
  hits: number
  last_seen: string
  sample_alert_id: string
}

export interface NoiseSettings {
  must_alert_rules: string[]
}

export const noiseKeys = {
  suppressions: ['suppressions'] as const,
  shapes: ['alerts', 'noise'] as const,
  preview: (spec: SuppressionSpec) => ['suppression-preview', spec] as const,
  settings: ['settings', 'noise'] as const,
}

export const listSuppressions = () => http.get<{ suppressions: Suppression[] }>('/api/suppressions')
export const createSuppression = (spec: SuppressionSpec) => http.post<SuppressionResult>('/api/suppressions', spec)
export const previewSuppression = (spec: SuppressionSpec) => http.post<SuppressionPreview>('/api/suppressions/preview', spec)
export const patchSuppression = (id: string, patch: SuppressionPatch) => http.patch<Suppression>(`/api/suppressions/${enc(id)}`, patch)
export const deleteSuppression = (id: string) => http.del(`/api/suppressions/${enc(id)}`)
export const topRepeating = () => http.get<{ shapes: RepeatingShape[]; hours: number }>('/api/alerts/noise')
export const getNoiseSettings = () => http.get<NoiseSettings>('/api/settings/noise')
export const putNoiseSettings = (s: NoiseSettings) => http.put<NoiseSettings>('/api/settings/noise', s)
