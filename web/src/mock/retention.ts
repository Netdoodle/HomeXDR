// Mock data retention: 1 TB cap, no time limit, ~100 days of history.

import type { RetentionPreview, RetentionSettings, RetentionStatus } from '../api/retention'
import type { Role } from '../api/types'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const GiB = 1024 ** 3
const TiB = 1024 ** 4
const DAY = 86_400_000

let settings: RetentionSettings = { days: 0, max_bytes: TiB }
const today = Math.floor(Date.now() / DAY) * DAY
const days = Array.from({ length: 100 }, (_, i) => ({
  day: new Date(today - (99 - i) * DAY).toISOString(),
  bytes: Math.round((4.5 + ((i * 7) % 10) / 10) * GiB),
  events: 9_000_000 + ((i * 13) % 7) * 250_000,
}))

function status(s: RetentionSettings, ds = days): RetentionStatus {
  const stored = ds.reduce((n, d) => n + d.bytes, 0)
  const last7 = ds.slice(-8, -1)
  const avg = last7.length ? Math.round(last7.reduce((n, d) => n + d.bytes, 0) / last7.length) : 0
  const oldest = ds[0]?.day
  const timeF = s.days > 0 && oldest ? new Date(Date.parse(oldest) + (s.days + 1) * DAY).toISOString() : undefined
  const sizeF = s.max_bytes > 0 && avg ? new Date(Date.now() + Math.max(0, (s.max_bytes - stored) / avg) * DAY).toISOString() : undefined
  const next = timeF && (!sizeF || timeF <= sizeF) ? timeF : sizeF
  return {
    settings: s,
    source: 'console',
    event_store: 'clickhouse',
    stored_bytes: stored,
    stored_events: ds.reduce((n, d) => n + d.events, 0),
    oldest,
    disk_total: 16 * TiB,
    disk_free: 14.6 * TiB,
    daily_avg_bytes: avg,
    coverage_days: s.max_bytes && avg ? s.max_bytes / avg : undefined,
    time_falloff: timeF,
    size_falloff: sizeF,
    next_falloff: next,
    next_reason: next ? (next === timeF ? 'time' : 'size') : undefined,
    next_removes_day: next ? oldest : undefined,
    days: ds,
  }
}

function preview(p: RetentionSettings): RetentionPreview {
  let keep = 0
  let total = days.reduce((n, d) => n + d.bytes, 0)
  if (p.days > 0) {
    const cutoff = today - p.days * DAY
    while (keep < days.length && Date.parse(days[keep].day) < cutoff) total -= days[keep++].bytes
  }
  if (p.max_bytes > 0) while (keep < days.length - 1 && total > p.max_bytes) total -= days[keep++].bytes
  const removed = days.slice(0, keep)
  const shorter = (n: number, o: number) => n > 0 && (o === 0 || n < o)
  const st = status(p, days.slice(keep))
  const warnings: string[] = []
  if (removed.length)
    warnings.push(
      `${removed.reduce((n, d) => n + d.events, 0)} events will be permanently deleted within about 10 minutes of saving. There is no undo and HomeXDR keeps no backup.`,
      'Alerts from that period stay listed, but the events behind them are gone: search, hunts, process trees, the AI analyst and investigations can no longer see them.',
    )
  const reduction = shorter(p.days, settings.days) || shorter(p.max_bytes, settings.max_bytes)
  if (reduction) warnings.push('Less history means a shorter window to discover an intrusion after the fact: many compromises are found weeks or months later.')
  return {
    current: settings,
    proposed: p,
    reduction,
    removes_bytes: removed.reduce((n, d) => n + d.bytes, 0),
    removes_events: removed.reduce((n, d) => n + d.events, 0),
    removes_from: removed[0]?.day,
    removes_until: removed.length ? new Date(Date.parse(removed[removed.length - 1].day) + DAY).toISOString() : undefined,
    keeps_from: days[keep]?.day,
    next_falloff: st.next_falloff,
    next_reason: st.next_reason,
    coverage_days: st.coverage_days,
    warnings,
  }
}

/** Registers the data retention routes on the mock server. */
export function retentionRoutes(route: Route, fail: (status: number, message: string) => never) {
  route('GET', '/api/retention', () => status(settings))
  route('POST', '/api/retention/preview', ({ body }) => preview(body as RetentionSettings), { role: 'admin' })
  route(
    'PUT',
    '/api/settings/retention',
    ({ body }) => {
      const b = body as RetentionSettings & { acknowledge: boolean; confirm_phrase?: string }
      const pv = preview(b)
      if (!b.acknowledge) fail(400, 'confirm the change: acknowledge is required')
      if ((pv.reduction || pv.removes_events > 0) && b.confirm_phrase !== 'DELETE EVENTS') fail(400, 'reducing retention needs the confirmation phrase "DELETE EVENTS"')
      settings = { days: b.days, max_bytes: b.max_bytes }
      return status(settings)
    },
    { role: 'admin' },
  )
}

// Mock cloud backup.
let backup: import('../api/backup').BackupView = {
  enabled: true,
  provider: 'b2',
  endpoint: 'https://s3.us-west-004.backblazeb2.com',
  region: 'us-west-004',
  bucket: 'homexdr-archive',
  prefix: 'homelab',
  access_key_id: '004a1b2c3d4e5f0000000001',
  path_style: false,
  storage_class: '',
  skip_modules: ['netflow'],
  backfill: true,
  run_hour: 3,
  secret_set: true,
  last_run: new Date(Date.now() - 5 * 3600_000).toISOString(),
  last_success: new Date(Date.now() - 5 * 3600_000).toISOString(),
  archived_days: 99,
  archived_bytes: 99 * 3.1 * GiB,
  pending: [],
  recent: [],
}

/** Registers the backup routes on the mock server. */
export function backupRoutes(route: Route, fail: (status: number, message: string) => never) {
  route('GET', '/api/backup', () => backup, { role: 'admin' })
  route(
    'PUT',
    '/api/settings/backup',
    ({ body }) => {
      const b = body as import('../api/backup').BackupInput
      if (b.enabled && !/^https?:\/\//.test(b.endpoint)) fail(400, 'endpoint must start with https://')
      const { secret: _s, clear_secret: _c, ...rest } = b
      backup = { ...backup, ...rest, secret_set: b.clear_secret ? false : backup.secret_set || !!b.secret }
      return backup
    },
    { role: 'admin' },
  )
  route('POST', '/api/backup/test', () => ({ ok: true, message: 'Wrote, read back and deleted a test object: the bucket and keys work.' }), { role: 'admin' })
  route('POST', '/api/backup/run', () => null, { role: 'admin' })
  route(
    'GET',
    '/api/backup/archives',
    () =>
      Array.from({ length: 120 }, (_, i) => {
        const d = new Date(today - (i + 1) * DAY)
        return { day: d.toISOString().slice(0, 10), key: `homelab/events/${d.toISOString().slice(0, 10)}.ndjson.zst`, events: 8_000_000, bytes: Math.round(3.1 * GiB), in_store: i < 99 }
      }),
    { role: 'admin' },
  )
  route('POST', '/api/backup/import', () => null, { role: 'admin' })
}
