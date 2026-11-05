// Mock data health: the owner's real shape of problem (a Slackware host with no software
// list, a Suricata feed that went quiet) with made-up names and numbers.

import type { FeedPatch, FeedReport, FeedView } from '../api/health'
import type { User, Role } from '../api/types'

export interface MockCtx {
  params: Record<string, string>
  query: URLSearchParams
  body: unknown
  user: User | undefined
}

export type MockRoute = (method: string, path: string, handler: (c: MockCtx) => unknown, opts?: { auth?: boolean; role?: Role }) => void

const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString()
const HOUR = 3600
const DAY = 86400

const base = { arrivals: 500, muted: false, expected: false, can_alert: true, first_seen: ago(40 * 24 * 60) }

const feeds: FeedView[] = [
  { ...base, host_id: 'h-tower', hostname: 'tower', module: '', dataset: '', status: 'ok', last_seen: ago(0.5), usual_gap_sec: 0, allowance_sec: 900, silent_sec: 30 },
  { ...base, host_id: 'h-tower', hostname: 'tower', module: 'procfs', dataset: 'process.procconn', status: 'ok', last_seen: ago(0.2), usual_gap_sec: 90, allowance_sec: 900, silent_sec: 12 },
  { ...base, host_id: 'h-tower', hostname: 'tower', module: 'fanotify', dataset: 'file.fanotify', status: 'ok', last_seen: ago(4), usual_gap_sec: 40 * 60, allowance_sec: 2 * HOUR, silent_sec: 240 },
  { ...base, host_id: 'h-tower', hostname: 'tower', module: 'afpacket', dataset: 'network.dns', status: 'silent', explanation: 'This source has stopped sending data, for longer than its usual pattern allows.', last_seen: ago(95), usual_gap_sec: 20 * 60, allowance_sec: HOUR, silent_sec: 95 * 60 },
  { ...base, host_id: 'h-tower', hostname: 'tower', module: 'inventory', dataset: 'inventory.system.info', status: 'ok', last_seen: ago(200), usual_gap_sec: 6 * HOUR, allowance_sec: 18 * HOUR, silent_sec: 200 * 60 },
  { ...base, host_id: 'h-tower', hostname: 'tower', module: 'inventory', dataset: 'inventory.users.list', status: 'learning', explanation: 'Still learning its pattern. A source must be seen for a day and arrive at least 20 times before it can alert.', last_seen: ago(200), usual_gap_sec: 6 * HOUR, allowance_sec: 18 * HOUR, silent_sec: 200 * 60, arrivals: 4, can_alert: false },
  { host_id: 'h-tower', hostname: 'tower', module: 'inventory', dataset: 'inventory.software.list', status: 'never_seen', explanation: 'This host has never sent a list of installed software. The agent reads it every few hours. Agents older than this server cannot read Unraid or Slackware packages, so update the agent first. Known-exploited software matching needs this data.', arrivals: 0, usual_gap_sec: 0, allowance_sec: DAY, silent_sec: 0, muted: false, expected: false, can_alert: false },
  { host_id: 'h-tower', hostname: 'tower', module: 'inventory', dataset: 'inventory.services.list', status: 'never_seen', explanation: 'This host has never sent a list of services. The agent reads it every few hours. Agents older than this server cannot read Unraid or Slackware services, so update the agent first.', arrivals: 0, usual_gap_sec: 0, allowance_sec: DAY, silent_sec: 0, muted: false, expected: false, can_alert: false },
  { ...base, host_id: 'h-fw', hostname: 'opnsense', module: 'opnsense', dataset: 'opnsense.filterlog', status: 'ok', last_seen: ago(0.1), usual_gap_sec: 60, allowance_sec: 900, silent_sec: 6 },
  { ...base, host_id: 'h-fw', hostname: 'opnsense', module: 'suricata', dataset: 'suricata.alert', status: 'quiet', explanation: 'Alert-only feed: it only has rows when something matched, so a quiet IDS may just mean nothing matched. It does not raise a silence alert unless you mark it expected.', last_seen: ago(16 * 24 * 60), usual_gap_sec: 2 * DAY, allowance_sec: 7 * DAY, silent_sec: 16 * DAY, can_alert: false },
  { ...base, host_id: 'h-fw', hostname: 'opnsense', module: 'syslog', dataset: 'syslog.cron', status: 'muted', explanation: 'Muted: this source never raises an alert.', muted: true, can_alert: false, last_seen: ago(70), usual_gap_sec: HOUR, allowance_sec: 3 * HOUR, silent_sec: 70 * 60 },
]

function report(): FeedReport {
  return { sources: feeds, bootstrapped: true }
}

export function registerHealthMocks(route: MockRoute) {
  route('GET', '/api/health/feeds', () => report())
  route(
    'PATCH',
    '/api/health/feeds',
    ({ body }) => {
      const p = body as FeedPatch
      const f = feeds.find((x) => x.host_id === p.host_id && x.module === p.module && x.dataset === p.dataset)
      if (f) {
        if (p.muted !== undefined) {
          f.muted = p.muted
          f.status = p.muted ? 'muted' : f.last_seen ? 'ok' : 'never_seen'
        }
        if (p.expected !== undefined) f.expected = p.expected
        f.can_alert = !f.muted && (f.expected || (f.status === 'ok' && f.arrivals >= 20))
      }
      return report()
    },
    { role: 'admin' },
  )
}
