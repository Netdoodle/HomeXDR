// Mock suppressions, must-alert list and the "Top repeating" panel.

import type { RepeatingShape, Suppression, SuppressionCondition, SuppressionSpec } from '../api/noise'
import type { AITriage, Alert, Event, Role, User } from '../api/types'
import { alerts } from './fixtures'
import { LINUX_ID } from './hosts'
import { makeId } from './rng'

interface Ctx {
  params: Record<string, string>
  query: URLSearchParams
  body: unknown
  user: User | undefined
}

export interface MockDeps {
  route: (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { auth?: boolean; role?: Role }) => void
  fail: (status: number, message: string) => never
  obj: (b: unknown) => Record<string, unknown>
  logAudit: (user: User | undefined, action: string, target: string, details: unknown) => void
  noContent: unknown
}

const DAY = 86_400_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

// Scheduled-job noise: one open shape folded into many hits, and one hidden by a suppression.
const template = alerts[0]
function noisyAlert(over: Partial<Alert> & { parent: string; exe: string; cmd: string }): Alert {
  const { parent, exe, cmd, ...rest } = over
  const event = {
    ...(template.event ?? ({} as Event)),
    process: { name: exe.split('/').pop(), executable: exe, command_line: cmd, parent: { name: parent.split('/').pop(), executable: parent, command_line: `${parent} check user.scripts.plg` } },
  } as Event
  return {
    ...template,
    id: makeId(Date.now() + alerts.length),
    event,
    events: undefined,
    process_name: exe.split('/').pop(),
    command_line: cmd,
    notes: [],
    ai_triage: undefined,
    assignee: undefined,
    host_id: LINUX_ID,
    hostname: 'srv-docker01',
    rule: { ...template.rule, id: 'wget-tmp', title: 'Download File To Potentially Suspicious Directory Via Wget', level: 'medium' },
    severity: 'medium',
    risk_score: 47,
    ...rest,
  }
}

const suppressions: Suppression[] = [
  {
    id: 'sup-plugin-check',
    rule_id: 'wget-tmp',
    rule_title: 'Download File To Potentially Suspicious Directory Via Wget',
    host_id: LINUX_ID,
    hostname: 'srv-docker01',
    conditions: [{ field: 'process.parent.command_line', op: 'contains', value: 'check user.scripts.plg' }],
    reason: 'Unraid User Scripts plugin check, every few minutes',
    created_by: 'admin',
    created_at: iso(3 * DAY),
    expires_at: new Date(Date.now() + 87 * DAY).toISOString(),
    enabled: true,
    hit_count: 1548,
    last_hit_at: iso(180_000),
    override_count: 1,
    last_override_at: iso(DAY),
  },
  {
    id: 'sup-old-backup',
    conditions: [{ field: 'process.command_line', op: 'startswith', value: '/root/prerunget.sh' }],
    reason: 'Old backup script, retired',
    created_by: 'sam',
    created_at: iso(120 * DAY),
    expires_at: iso(30 * DAY),
    enabled: true,
    hit_count: 3,
    last_hit_at: iso(40 * DAY),
    override_count: 0,
    last_override_at: null,
  },
]

const mustAlert = { must_alert_rules: ['health:feed-silent'] }

function seed() {
  const now = new Date().toISOString()
  alerts.unshift(
    noisyAlert({ exe: '/usr/bin/php', parent: '/usr/local/sbin/startSchedule.php', cmd: 'php /usr/local/emhttp/plugins/user.scripts/startSchedule.php hourly', status: 'new', count: 219, first_seen: iso(DAY / 2), last_seen: now, rule: { ...template.rule, id: 'script-tmp', title: 'Execution Of Script Located In Potentially Suspicious Directory', level: 'medium' } }),
    noisyAlert({
      exe: '/usr/bin/wget',
      parent: '/usr/bin/php',
      cmd: 'wget -q -O /tmp/plugins/user.scripts.plg https://example.test/user.scripts.plg',
      status: 'suppressed',
      count: 1548,
      first_seen: iso(DAY / 2),
      last_seen: now,
      suppression: { id: 'sup-plugin-check', reason: suppressions[0].reason },
    }),
    noisyAlert({
      exe: '/usr/bin/wget',
      parent: '/usr/bin/php',
      cmd: 'wget -q -O /tmp/plugins/user.scripts.plg https://example.test/user.scripts.plg',
      status: 'new',
      severity: 'critical',
      risk_score: 99,
      count: 1,
      first_seen: iso(DAY),
      last_seen: iso(DAY),
      suppression: { id: 'sup-plugin-check', reason: suppressions[0].reason, overridden: true, why: 'critical alerts are never suppressed' },
    }),
  )
}

function fieldValues(ev: Event | undefined, field: string): string[] {
  let cur: unknown = ev
  for (const part of field.toLowerCase().split('.')) {
    if (!cur || typeof cur !== 'object') return []
    cur = (cur as Record<string, unknown>)[part]
  }
  if (cur === undefined || cur === null) return []
  return Array.isArray(cur) ? cur.map(String) : [String(cur)]
}

function condMatches(ev: Event | undefined, c: SuppressionCondition): boolean {
  return fieldValues(ev, c.field).some((v) => {
    if (c.op === 'equals') return v === c.value
    if (c.op === 'contains') return v.includes(c.value)
    if (c.op === 'startswith') return v.startsWith(c.value)
    return v.endsWith(c.value)
  })
}

const isOpen = (a: Alert) => a.status === 'new' || a.status === 'in_progress'

function matching(spec: SuppressionSpec) {
  const all = alerts.filter(
    (a) =>
      isOpen(a) &&
      (!spec.rule_id || a.rule.id === spec.rule_id) &&
      (!spec.host_id || a.host_id === spec.host_id) &&
      (spec.conditions ?? []).every((c) => condMatches(a.event, c)),
  )
  const kept = all.filter((a) => a.severity === 'critical' || mustAlert.must_alert_rules.includes(a.rule.id))
  return { matches: all.filter((a) => !kept.includes(a)), kept: kept.length }
}

function shapes(): RepeatingShape[] {
  const groups = new Map<string, RepeatingShape>()
  for (const a of alerts) {
    if (!isOpen(a)) continue
    const p = a.event?.process
    const exe = p?.executable ?? p?.name ?? a.process_name ?? ''
    const parent = p?.parent?.executable ?? p?.parent?.name ?? ''
    const key = [a.rule.id, a.host_id, exe, parent].join('|')
    const g = groups.get(key)
    if (g) {
      g.alerts++
      g.hits += a.count
      if (a.last_seen > g.last_seen) g.last_seen = a.last_seen
    } else {
      groups.set(key, { rule_id: a.rule.id, rule_title: a.rule.title, severity: a.severity, host_id: a.host_id, hostname: a.hostname, process: exe, parent, alerts: 1, hits: a.count, last_seen: a.last_seen, sample_alert_id: a.id })
    }
  }
  return [...groups.values()].filter((g) => g.hits > 1).sort((x, y) => y.hits - x.hits).slice(0, 8)
}

function validate(spec: SuppressionSpec, fail: MockDeps['fail'], forCreate: boolean) {
  const conds = spec.conditions ?? []
  if (!spec.rule_id && conds.length === 0) fail(400, 'a suppression needs a rule or at least one condition')
  if (!forCreate) return
  if (!spec.host_id && conds.length === 0 && !spec.confirm_broad) fail(400, 'this would suppress the whole rule on every host; set confirm_broad to do that')
  if (!spec.reason?.trim()) fail(400, 'a suppression needs a reason')
}

export function registerNoiseMocks({ route, fail, obj, logAudit, noContent }: MockDeps) {
  seed()

  route('GET', '/api/alerts/noise', () => ({ shapes: shapes(), hours: 24 }))
  route('GET', '/api/suppressions', () => ({ suppressions }))
  route(
    'POST',
    '/api/suppressions/preview',
    ({ body }) => {
      const spec = obj(body) as SuppressionSpec
      validate(spec, fail, false)
      const m = matching(spec)
      return {
        matches: m.matches.length,
        hits: m.matches.reduce((n, a) => n + a.count, 0),
        kept: m.kept,
        sample: m.matches.slice(0, 5).map((a) => ({ id: a.id, rule_title: a.rule.title, severity: a.severity, hostname: a.hostname, process_name: a.process_name, command_line: a.command_line, count: a.count, last_seen: a.last_seen })),
      }
    },
    { role: 'analyst' },
  )
  route(
    'POST',
    '/api/suppressions',
    ({ body, user }) => {
      const spec = obj(body) as SuppressionSpec
      validate(spec, fail, true)
      const rule = alerts.find((a) => a.rule.id === spec.rule_id)?.rule
      const host = alerts.find((a) => a.host_id === spec.host_id)
      const s: Suppression = {
        id: makeId(Date.now()),
        rule_id: spec.rule_id,
        rule_title: rule?.title,
        host_id: spec.host_id,
        hostname: host?.hostname,
        conditions: spec.conditions ?? [],
        reason: spec.reason!.trim(),
        created_by: user?.username ?? 'admin',
        created_at: new Date().toISOString(),
        expires_at: spec.never_expires ? null : spec.expires_at ?? new Date(Date.now() + 90 * DAY).toISOString(),
        enabled: spec.enabled ?? true,
        hit_count: 0,
        last_hit_at: null,
        override_count: 0,
        last_override_at: null,
      }
      suppressions.push(s)
      logAudit(user, 'suppression.create', s.id, s.reason)
      let closed = 0
      const m = matching(spec)
      if (spec.apply) {
        for (const a of m.matches) {
          a.status = 'suppressed'
          a.suppression = { id: s.id, reason: s.reason }
          a.notes = [...a.notes, { author: s.created_by, text: `Closed by a suppression: ${s.reason}`, at: s.created_at }]
          closed++
        }
      }
      return { suppression: s, closed, kept: m.kept }
    },
    { role: 'admin' },
  )
  route(
    'PATCH',
    '/api/suppressions/:id',
    ({ params, body, user }) => {
      const s = suppressions.find((x) => x.id === params.id) ?? fail(404, 'not found')
      const p = obj(body) as { enabled?: boolean; reason?: string; expires_at?: string; never_expires?: boolean }
      if (p.enabled !== undefined) s.enabled = p.enabled
      if (p.reason !== undefined) s.reason = p.reason
      if (p.expires_at) s.expires_at = p.expires_at
      if (p.never_expires) s.expires_at = null
      logAudit(user, 'suppression.update', s.id, p)
      return s
    },
    { role: 'admin' },
  )
  route(
    'DELETE',
    '/api/suppressions/:id',
    ({ params, user }) => {
      const i = suppressions.findIndex((x) => x.id === params.id)
      if (i < 0) fail(404, 'not found')
      suppressions.splice(i, 1)
      logAudit(user, 'suppression.delete', params.id, '')
      return noContent
    },
    { role: 'admin' },
  )
  route('GET', '/api/settings/noise', () => mustAlert)
  route(
    'PUT',
    '/api/settings/noise',
    ({ body, user }) => {
      const list = (obj(body) as { must_alert_rules?: string[] }).must_alert_rules ?? []
      mustAlert.must_alert_rules = [...new Set(list.map((s) => s.trim()).filter(Boolean))]
      logAudit(user, 'suppression.must_alert', '', mustAlert.must_alert_rules.join(', '))
      return mustAlert
    },
    { role: 'admin' },
  )
}

/** A report reused from an earlier benign investigation, so the panel has one to show. */
export function reusedTriage(a: Alert, src: Alert): AITriage {
  const at = iso(2 * DAY)
  a.ai_triage = { status: 'done', verdict: 'benign', confidence: 'high' }
  return {
    alert_id: a.id,
    status: 'done',
    trigger: 'reused',
    reused_from_alert: src.id,
    reused_from_at: at,
    engine: 'api',
    model: 'claude-opus-5-5',
    provider: 'anthropic',
    verdict: 'benign',
    confidence: 'high',
    tool_calls: 0,
    usage: { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0 },
    created_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    report: {
      verdict: 'benign',
      confidence: 'high',
      severity_assessment: 'low',
      summary: `Reused verdict: the AI did not look at this alert. It looked at alert ${src.id} on ${at.slice(0, 16).replace('T', ' ')} UTC, which has the same rule, host and process shape, and said: a scheduled plugin check.`,
      analysis: 'The parent process is the Unraid plugin manager, on its usual schedule.',
      evidence: [],
      mitre: [],
      recommended_actions: [],
      open_questions: [],
    },
  }
}
