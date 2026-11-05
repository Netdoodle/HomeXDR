// API helpers for notifications (docs/notifications.md). Secrets go in, and never come back:
// the API only says whether one is set.

import { http } from './client'
import type { Severity } from './types'

export type ChannelKind = 'ntfy' | 'discord' | 'email' | 'webhook'
export type NotifyRoute = 'now' | 'digest' | 'log'

export interface ChannelView {
  id: string
  kind: ChannelKind
  name: string
  enabled: boolean
  url_set: boolean
  url_host?: string
  token_set: boolean
  password_set: boolean
  smtp_host?: string
  smtp_port?: number
  smtp_user?: string
  from?: string
  to?: string
}

export interface ChannelUpdate {
  id?: string
  kind: ChannelKind
  name: string
  enabled: boolean
  /** blank keeps what is stored */
  url?: string
  token?: string
  password?: string
  clear_token?: boolean
  clear_password?: boolean
  smtp_host?: string
  smtp_port?: number
  smtp_user?: string
  from?: string
  to?: string
}

export interface RuleRoute {
  prefix: string
  route: NotifyRoute
}

interface NotifyCommon {
  severity_routes: Partial<Record<Severity, NotifyRoute>>
  rule_routes: RuleRoute[]
  rate_per_hour: number
  digest_enabled: boolean
  digest_time: string
  timezone: string
  heartbeat: boolean
  console_url: string
}

export interface NotifyFailure {
  id: string
  channel_id: string
  kind: string
  title?: string
  status: string
  attempts: number
  next_attempt_at: string
  last_error?: string
  created_at: string
}

export interface NotifyStatus {
  pending: number
  sent_24h: number
  failed_24h: number
  overflow_1h: number
  last_sent_at: string | null
  recent_failures: NotifyFailure[]
  last_digest_at: string | null
  next_digest_at: string | null
}

export interface NotifySettings extends NotifyCommon {
  channels: ChannelView[]
  status: NotifyStatus
}

export interface NotifySettingsUpdate extends NotifyCommon {
  channels: ChannelUpdate[]
}

export const notifyKeys = {
  settings: ['settings', 'notifications'] as const,
  status: ['settings', 'notifications', 'status'] as const,
}

export const getNotifySettings = () => http.get<NotifySettings>('/api/settings/notifications')
export const putNotifySettings = (u: NotifySettingsUpdate) => http.put<NotifySettings>('/api/settings/notifications', u)
export const testNotifyChannel = (id: string) =>
  http.post<{ ok: boolean; error?: string }>(`/api/settings/notifications/channels/${encodeURIComponent(id)}/test`, {})
