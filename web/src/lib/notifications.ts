// Form state for Settings > Notifications, and turning it into an API update.

import type { ChannelKind, ChannelUpdate, ChannelView, NotifyRoute, NotifySettings, NotifySettingsUpdate, RuleRoute } from '../api/notifications'
import type { Severity } from '../api/types'

export const CHANNEL_KINDS: { kind: ChannelKind; label: string; urlLabel: string; urlHelp: string }[] = [
  { kind: 'ntfy', label: 'ntfy', urlLabel: 'Topic URL', urlHelp: 'For example https://ntfy.sh/your-long-random-topic. Anyone with the URL can read the topic, so treat it like a password.' },
  { kind: 'discord', label: 'Discord', urlLabel: 'Webhook URL', urlHelp: 'In Discord: channel settings, Integrations, Webhooks, Copy Webhook URL.' },
  { kind: 'email', label: 'Email', urlLabel: '', urlHelp: '' },
  { kind: 'webhook', label: 'Webhook', urlLabel: 'URL', urlHelp: 'Gets a JSON POST for each message: title, body, severity, rule_id, alert_id and link.' },
]

export const ROUTE_LABELS: { value: NotifyRoute; label: string }[] = [
  { value: 'now', label: 'Alert now' },
  { value: 'digest', label: 'Daily digest' },
  { value: 'log', label: 'Log only' },
]

export const ROUTED_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export interface ChannelDraft {
  /** React key; stays the same across edits */
  key: string
  id?: string
  kind: ChannelKind
  name: string
  enabled: boolean
  url: string
  token: string
  password: string
  clearToken: boolean
  clearPassword: boolean
  smtpHost: string
  smtpPort: string
  smtpUser: string
  from: string
  to: string
  saved?: ChannelView
}

export interface NotifyDraft {
  channels: ChannelDraft[]
  severityRoutes: Partial<Record<Severity, NotifyRoute>>
  ruleRoutes: RuleRoute[]
  ratePerHour: string
  digestEnabled: boolean
  digestTime: string
  timezone: string
  heartbeat: boolean
  consoleUrl: string
}

let nextKey = 0

export function newChannelDraft(kind: ChannelKind): ChannelDraft {
  return {
    key: `new-${++nextKey}`,
    kind,
    name: CHANNEL_KINDS.find((k) => k.kind === kind)?.label ?? kind,
    enabled: true,
    url: '',
    token: '',
    password: '',
    clearToken: false,
    clearPassword: false,
    smtpHost: '',
    smtpPort: '587',
    smtpUser: '',
    from: '',
    to: '',
  }
}

export function draftFromSettings(s: NotifySettings): NotifyDraft {
  return {
    channels: s.channels.map((c) => ({
      ...newChannelDraft(c.kind),
      key: c.id,
      id: c.id,
      name: c.name,
      enabled: c.enabled,
      smtpHost: c.smtp_host ?? '',
      smtpPort: String(c.smtp_port ?? 587),
      smtpUser: c.smtp_user ?? '',
      from: c.from ?? '',
      to: c.to ?? '',
      saved: c,
    })),
    severityRoutes: { ...s.severity_routes },
    ruleRoutes: s.rule_routes.map((r) => ({ ...r })),
    ratePerHour: String(s.rate_per_hour),
    digestEnabled: s.digest_enabled,
    digestTime: s.digest_time,
    timezone: s.timezone ?? '',
    heartbeat: s.heartbeat,
    consoleUrl: s.console_url ?? '',
  }
}

function channelUpdate(d: ChannelDraft): ChannelUpdate {
  const base: ChannelUpdate = { id: d.id, kind: d.kind, name: d.name.trim(), enabled: d.enabled }
  if (d.kind === 'email') {
    return {
      ...base,
      smtp_host: d.smtpHost.trim(),
      smtp_port: Number(d.smtpPort) || 587,
      smtp_user: d.smtpUser.trim(),
      from: d.from.trim(),
      to: d.to.trim(),
      ...(d.password.trim() ? { password: d.password.trim() } : {}),
      ...(d.clearPassword ? { clear_password: true } : {}),
    }
  }
  return {
    ...base,
    ...(d.url.trim() ? { url: d.url.trim() } : {}),
    ...(d.token.trim() ? { token: d.token.trim() } : {}),
    ...(d.clearToken ? { clear_token: true } : {}),
  }
}

export function updateFromDraft(d: NotifyDraft): NotifySettingsUpdate {
  return {
    channels: d.channels.map(channelUpdate),
    severity_routes: d.severityRoutes,
    rule_routes: d.ruleRoutes.map((r) => ({ ...r, prefix: r.prefix.trim() })).filter((r) => r.prefix),
    rate_per_hour: Number(d.ratePerHour),
    digest_enabled: d.digestEnabled,
    digest_time: d.digestTime,
    timezone: d.timezone.trim(),
    heartbeat: d.heartbeat,
    console_url: d.consoleUrl.trim(),
  }
}

/** What the owner still has to fill in for a channel, or null when it can be saved. */
export function channelProblem(d: ChannelDraft): string | null {
  if (d.kind === 'email') {
    if (!d.smtpHost.trim()) return 'Needs a mail server.'
    if (!d.from.trim() || !d.to.trim()) return 'Needs From and To addresses.'
    return null
  }
  if (!d.url.trim() && !d.saved?.url_set) return 'Needs a URL.'
  return null
}
