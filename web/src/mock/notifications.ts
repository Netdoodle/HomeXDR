// Mock notification settings. Secrets go in and only come back as "set", like the real API.

import type { ChannelUpdate, ChannelView, NotifySettings, NotifySettingsUpdate } from '../api/notifications'
import type { MockDeps } from './noise'
import { makeId } from './rng'

const HOUR = 3_600_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

function nextDigest(time: string): string {
  const [h, m] = time.split(':').map(Number)
  const d = new Date()
  d.setHours(h, m, 0, 0)
  if (d.getTime() <= Date.now()) d.setDate(d.getDate() + 1)
  return d.toISOString()
}

const channels: ChannelView[] = [
  { id: 'chan-phone', kind: 'ntfy', name: 'Phone', enabled: true, url_set: true, url_host: 'ntfy.sh', token_set: false, password_set: false },
  { id: 'chan-discord', kind: 'discord', name: 'Home lab server', enabled: true, url_set: true, url_host: 'discord.com', token_set: false, password_set: false },
]

const settings: Omit<NotifySettings, 'channels' | 'status'> = {
  severity_routes: { critical: 'now', high: 'now', medium: 'digest', low: 'log', informational: 'log' },
  rule_routes: [
    { prefix: 'health:', route: 'now' },
    { prefix: 'net:new-device', route: 'digest' },
  ],
  rate_per_hour: 10,
  digest_enabled: true,
  digest_time: '07:00',
  timezone: 'Europe/Prague',
  heartbeat: false,
  console_url: 'https://xdr.example.test',
}

function view(): NotifySettings {
  return {
    ...settings,
    channels,
    status: {
      pending: 1,
      sent_24h: 14,
      failed_24h: 1,
      overflow_1h: 0,
      last_sent_at: iso(HOUR / 3),
      last_digest_at: iso(5 * HOUR),
      next_digest_at: settings.digest_enabled && channels.some((c) => c.enabled) ? nextDigest(settings.digest_time) : null,
      recent_failures: [
        {
          id: 'fail-1',
          channel_id: 'chan-discord',
          kind: 'alert',
          title: '[HIGH] Suspicious Network Connection on srv-docker01',
          status: 'pending',
          attempts: 2,
          next_attempt_at: iso(-60_000),
          last_error: 'the service answered HTTP 429',
          created_at: iso(120_000),
        },
        {
          id: 'fail-2',
          channel_id: 'chan-phone',
          kind: 'digest',
          title: 'HomeXDR daily digest: 12 alerts, 1548 suppressed',
          status: 'failed',
          attempts: 9,
          next_attempt_at: iso(2 * HOUR),
          last_error: 'dial tcp: connection refused',
          created_at: iso(7 * HOUR),
        },
      ],
    },
  }
}

function applyChannel(u: ChannelUpdate, old: ChannelView | undefined, fail: MockDeps['fail']): ChannelView {
  const urlSet = !!u.url || !!old?.url_set
  if (u.kind !== 'email' && !urlSet) fail(400, `channel "${u.name}" needs a URL`)
  if (u.kind === 'email' && !u.smtp_host) fail(400, `channel "${u.name}" needs an SMTP server name`)
  if (u.kind === 'email' && (!u.from || !u.to)) fail(400, `channel "${u.name}" needs valid From and To addresses`)
  let host = old?.url_host
  if (u.url) {
    try {
      host = new URL(u.url).host
    } catch {
      fail(400, `the URL of channel ${u.name} must be an http(s) URL`)
    }
  }
  return {
    id: u.id || makeId(Date.now()),
    kind: u.kind,
    name: u.name || u.kind,
    enabled: u.enabled,
    url_set: urlSet,
    url_host: host,
    token_set: !u.clear_token && (!!u.token || !!old?.token_set),
    password_set: !u.clear_password && (!!u.password || !!old?.password_set),
    smtp_host: u.smtp_host,
    smtp_port: u.smtp_port,
    smtp_user: u.smtp_user,
    from: u.from,
    to: u.to,
  }
}

export function registerNotificationMocks({ route, fail, obj, logAudit }: MockDeps) {
  route('GET', '/api/settings/notifications', () => view(), { role: 'admin' })
  route(
    'PUT',
    '/api/settings/notifications',
    ({ body, user }) => {
      const u = obj(body) as unknown as NotifySettingsUpdate
      if (!(u.rate_per_hour >= 1 && u.rate_per_hour <= 1000)) fail(400, 'the rate cap must be between 1 and 1000 alerts an hour')
      if (!/^\d{2}:\d{2}$/.test(u.digest_time)) fail(400, 'the digest time must look like 07:00')
      const next = u.channels.map((c) => applyChannel(c, channels.find((x) => x.id === c.id), fail))
      channels.splice(0, channels.length, ...next)
      const { channels: _channels, ...rest } = u
      Object.assign(settings, rest)
      logAudit(user, 'notify.settings', '', `channels: ${channels.map((c) => c.name).join(', ')}`)
      return view()
    },
    { role: 'admin' },
  )
  route(
    'POST',
    '/api/settings/notifications/channels/:id/test',
    ({ params, user }) => {
      const c = channels.find((x) => x.id === params.id) ?? fail(404, 'no such channel')
      logAudit(user, 'notify.test', c.id, 'sent')
      if (c.kind === 'email' && !c.smtp_host?.includes('.')) return { ok: false, error: 'the mail server does not offer STARTTLS, so nothing was sent' }
      return { ok: true }
    },
    { role: 'admin' },
  )
}
