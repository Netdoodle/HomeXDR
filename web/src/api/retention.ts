// Event retention (Data retention page).

import { http } from './client'

export interface RetentionSettings {
  days: number
  max_bytes: number
}

export interface DayUsage {
  day: string
  bytes: number
  events: number
}

export interface RetentionStatus {
  settings: RetentionSettings
  source: 'environment' | 'console'
  event_store: string
  stored_bytes: number
  stored_events: number
  oldest?: string
  disk_total: number
  disk_free: number
  daily_avg_bytes: number
  coverage_days?: number
  time_falloff?: string
  size_falloff?: string
  next_falloff?: string
  next_reason?: 'time' | 'size'
  next_removes_day?: string
  next_removes_archived?: boolean
  days: DayUsage[]
}

export interface RetentionPreview {
  current: RetentionSettings
  proposed: RetentionSettings
  reduction: boolean
  removes_bytes: number
  removes_events: number
  removes_from?: string
  removes_until?: string
  keeps_from?: string
  next_falloff?: string
  next_reason?: 'time' | 'size'
  coverage_days?: number
  warnings: string[]
}

export const RETENTION_CONFIRM_PHRASE = 'DELETE EVENTS'

export const retentionKeys = { status: ['retention'] as const }

export const getRetention = () => http.get<RetentionStatus>('/api/retention')
export const previewRetention = (s: RetentionSettings) => http.post<RetentionPreview>('/api/retention/preview', s)
export const putRetention = (s: RetentionSettings & { acknowledge: boolean; confirm_phrase?: string }) =>
  http.put<RetentionStatus>('/api/settings/retention', s)
