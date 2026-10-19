// In-browser implementation of docs/api.md over the fixtures. Enforces the same
// conventions as the real server: session required, CSRF header on non-GET, roles,
// `{"error": ...}` bodies.

import type {
  AgentConfig,
  Alert,
  AlertPatch,
  CommandRequest,
  CommandType,
  Event,
  Host,
  HuntCreate,
  Overview,
  ProcessNode,
  Role,
  Rule,
  Severity,
  User,
} from '../api/types'
import { COMMAND_TYPES, SEVERITIES } from '../api/types'
import { compileQuery, QuerySyntaxError } from '../lib/query'
import { hasRole } from '../lib/roles'
import { OPEN_ALERT_STATUSES } from '../lib/severity'
import { events, eventById, processes, type MockProcess } from './events'
import {
  agentConfig,
  alerts,
  artifactRows,
  artifacts,
  audit,
  commands,
  hunts,
  integrations,
  recomputeOpenAlerts,
  serverSettings,
  tokens,
  users,
  type MockCommand,
  type MockHunt,
} from './fixtures'
import { HOUR, hostById, hosts } from './hosts'
import { makeId } from './rng'
import { detectionNeedles, parseRuleYaml, ruleById, rules } from './rules'

// --- session ----------------------------------------------------------------------------

const SS_SESSION = 'homexdr.mock.session'
const SS_ROLE = 'homexdr.mock.role'
const SS_SETUP = 'homexdr.mock.setup'

function ssGet(k: string): string | null {
  try {
    return sessionStorage.getItem(k)
  } catch {
    return null
  }
}
function ssSet(k: string, v: string | null) {
  try {
    if (v === null) sessionStorage.removeItem(k)
    else sessionStorage.setItem(k, v)
  } catch {
    // ignore
  }
}

const state = {
  loggedIn: ssGet(SS_SESSION) !== '0',
  needsSetup: ssGet(SS_SETUP) === '1',
  username: ssGet(SS_SESSION + '.user') ?? 'admin',
}

/** Applies ?mock_role=, ?mock_setup=1 and ?mock_logout=1 from the page URL. */
export function applyMockUrlFlags(search: string) {
  const sp = new URLSearchParams(search)
  const role = sp.get('mock_role')
  if (role === 'admin' || role === 'analyst' || role === 'viewer') ssSet(SS_ROLE, role)
  if (sp.get('mock_setup') === '1') {
    ssSet(SS_SETUP, '1')
    state.needsSetup = true
    state.loggedIn = false
    ssSet(SS_SESSION, '0')
  }
  if (sp.get('mock_logout') === '1') {
    state.loggedIn = false
    ssSet(SS_SESSION, '0')
  }
}

function currentUser(): User | undefined {
  const u = users.find((x) => x.username === state.username) ?? users[0]
  if (!u) return undefined
  const role = ssGet(SS_ROLE) as Role | null
  return role ? { ...u, role } : u
}

// --- plumbing ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
  }
}

const fail = (status: number, message: string): never => {
  throw new HttpError(status, message)
}

interface Ctx {
  params: Record<string, string>
  query: URLSearchParams
  body: unknown
  user: User | undefined
}

type Handler = (c: Ctx) => unknown

interface RouteDef {
  method: string
  re: RegExp
  keys: string[]
  handler: Handler
  auth: boolean
  role?: Role
}

const routes: RouteDef[] = []

function route(method: string, path: string, handler: Handler, opts: { auth?: boolean; role?: Role } = {}) {
  const keys: string[] = []
  const re = new RegExp(
    '^' +
      path.replace(/:[a-zA-Z]+/g, (m) => {
        keys.push(m.slice(1))
        return '([^/]+)'
      }) +
      '$',
  )
  routes.push({ method, re, keys, handler, auth: opts.auth ?? true, role: opts.role })
}

function json(status: number, body: unknown): Response {
  if (status === 204) return new Response(null, { status })
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

class NoContent {}
const NO_CONTENT = new NoContent()

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms))

export async function handleMockRequest(method: string, url: URL, headers: Headers, rawBody: string | null): Promise<Response> {
  await sleep(120 + Math.random() * 260)
  const path = url.pathname
  for (const r of routes) {
    if (r.method !== method) continue
    const m = r.re.exec(path)
    if (!m) continue
    const params: Record<string, string> = {}
    r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])))
    try {
      if (method !== 'GET' && headers.get('X-HomeXDR-CSRF') !== '1') fail(403, 'missing or invalid X-HomeXDR-CSRF header')
      const user = state.loggedIn ? currentUser() : undefined
      if (r.auth && !user) fail(401, 'not authenticated')
      if (r.role && !hasRole(user, r.role)) fail(403, `forbidden: requires ${r.role} role`)
      let body: unknown = undefined
      if (rawBody) {
        try {
          body = JSON.parse(rawBody)
        } catch {
          fail(400, 'invalid JSON body')
        }
      }
      const out = r.handler({ params, query: url.searchParams, body, user })
      if (out instanceof Response) return out
      if (out === NO_CONTENT) return json(204, null)
      return json(200, out)
    } catch (e) {
      if (e instanceof HttpError) return json(e.status, { error: e.message })
      console.error('[mock]', e)
      return json(500, { error: e instanceof Error ? e.message : String(e) })
    }
  }
  return json(404, { error: `no mock route for ${method} ${path}` })
}

function obj(b: unknown): Record<string, unknown> {
  if (!b || typeof b !== 'object' || Array.isArray(b)) fail(400, 'expected a JSON object')
  return b as Record<string, unknown>
}

function page<T>(xs: T[], q: URLSearchParams, def = 100): T[] {
  const limit = Math.min(1000, Math.max(1, Number(q.get('limit') ?? def) || def))
  const offset = Math.max(0, Number(q.get('offset') ?? 0) || 0)
  return xs.slice(offset, offset + limit)
}

function logAudit(user: User | undefined, action: string, target: string, details: unknown) {
  const at = new Date().toISOString()
  audit.unshift({ id: makeId(Date.now()), at, user: user?.username ?? 'system', action, target, details })
}

function list(q: URLSearchParams, k: string): string[] {
  return (q.get(k) ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

// --- setup and auth -----------------------------------------------------------------------

route('GET', '/api/setup/status', () => ({ needs_setup: state.needsSetup, version: serverSettings.version }), { auth: false })

route(
  'POST',
  '/api/setup',
  ({ body }) => {
    if (!state.needsSetup) fail(409, 'setup already completed')
    const b = obj(body)
    const username = String(b.username ?? '').trim()
    const password = String(b.password ?? '')
    if (!/^[a-zA-Z0-9._-]{2,32}$/.test(username)) fail(400, 'username must be 2-32 characters: letters, digits, . _ -')
    if (password.length < 10) fail(400, 'password must be at least 10 characters')
    users.splice(0, users.length, { id: makeId(Date.now()), username, role: 'admin', created_at: new Date().toISOString(), last_login: new Date().toISOString() })
    state.needsSetup = false
    state.loggedIn = true
    state.username = username
    ssSet(SS_SETUP, null)
    ssSet(SS_SESSION, '1')
    ssSet(SS_SESSION + '.user', username)
    ssSet(SS_ROLE, null)
    return { user: users[0] }
  },
  { auth: false },
)

route(
  'POST',
  '/api/auth/login',
  ({ body }) => {
    const b = obj(body)
    const u = users.find((x) => x.username === String(b.username ?? ''))
    if (!u || String(b.password ?? '').length < 10) fail(401, 'invalid username or password')
    state.loggedIn = true
    state.username = u!.username
    ssSet(SS_SESSION, '1')
    ssSet(SS_SESSION + '.user', u!.username)
    u!.last_login = new Date().toISOString()
    logAudit(u, 'auth.login', u!.username, { ip: '127.0.0.1' })
    return { user: currentUser() }
  },
  { auth: false },
)

route('POST', '/api/auth/logout', () => {
  state.loggedIn = false
  ssSet(SS_SESSION, '0')
  return NO_CONTENT
}, { auth: false })

route('GET', '/api/auth/me', ({ user }) => ({ user }))

route('GET', '/healthz', () => ({ status: 'ok', event_store: 'ok' }), { auth: false })

// --- overview -----------------------------------------------------------------------------

route('GET', '/api/stats/overview', ({ query }) => {
  const hours = Math.min(24 * 30, Math.max(1, Number(query.get('hours') ?? 24) || 24))
  const now = Date.now()
  const start = now - hours * HOUR
  const inWin = (iso: string) => Date.parse(iso) >= start
  const evs = events.filter((e) => inWin(e['@timestamp']))
  const bucket = (ms: number) => new Date(Math.floor(ms / HOUR) * HOUR).toISOString()
  const timeline = (stamps: number[]) => {
    const m = new Map<string, number>()
    for (const s of stamps) m.set(bucket(s), (m.get(bucket(s)) ?? 0) + 1)
    return [...m.entries()].sort().map(([t, count]) => ({ t, count }))
  }
  const open = alerts.filter((a) => OPEN_ALERT_STATUSES.includes(a.status))
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((a) => a.severity === s).length])) as Record<Severity, number>
  const winAlerts = alerts.filter((a) => inWin(a.last_seen))
  const ruleCounts = new Map<string, { rule_id: string; title: string; severity: Severity; count: number }>()
  for (const a of winAlerts) {
    const cur = ruleCounts.get(a.rule.id) ?? { rule_id: a.rule.id, title: a.rule.title, severity: a.severity, count: 0 }
    cur.count += a.count
    ruleCounts.set(a.rule.id, cur)
  }
  const hostCounts = new Map<string, { host_id: string; hostname: string; alerts: number }>()
  for (const a of winAlerts) {
    const cur = hostCounts.get(a.host_id) ?? { host_id: a.host_id, hostname: a.hostname, alerts: 0 }
    cur.alerts++
    hostCounts.set(a.host_id, cur)
  }
  const cats = new Map<string, number>()
  for (const e of evs) {
    const c = e.event.category?.[0] ?? 'other'
    cats.set(c, (cats.get(c) ?? 0) + 1)
  }
  const out: Overview = {
    hosts_total: hosts.filter((h) => h.status !== 'revoked').length,
    hosts_online: hosts.filter((h) => h.status === 'online' || h.status === 'isolated').length,
    hosts_isolated: hosts.filter((h) => h.isolated).length,
    alerts_open: open.length,
    alerts_by_severity: bySev,
    events_total: evs.length,
    events_timeline: timeline(evs.map((e) => Date.parse(e['@timestamp']))),
    alerts_timeline: timeline(
      alerts.flatMap((a) => a.event_ids.map((id) => eventById(id)).filter((e): e is Event => !!e && inWin(e['@timestamp'])).map((e) => Date.parse(e['@timestamp']))),
    ),
    top_rules: [...ruleCounts.values()].sort((a, b) => b.count - a.count).slice(0, 8),
    top_hosts: [...hostCounts.values()].sort((a, b) => b.alerts - a.alerts).slice(0, 8),
    events_by_category: [...cats.entries()].map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count),
  }
  return out
})

// --- hosts --------------------------------------------------------------------------------

function getHostOr404(id: string): Host {
  return hostById(id) ?? fail(404, 'host not found')
}

route('GET', '/api/hosts', ({ query }) => {
  const q = (query.get('q') ?? '').toLowerCase()
  const status = list(query, 'status')
  const label = query.get('label')
  const platform = query.get('platform')
  advanceCommands()
  recomputeOpenAlerts()
  const out = hosts.filter(
    (h) =>
      (!q || h.hostname.toLowerCase().includes(q) || h.ips.some((ip) => ip.includes(q))) &&
      (!status.length || status.includes(h.status)) &&
      (!label || h.labels.includes(label)) &&
      (!platform || h.os.platform === platform),
  )
  return { hosts: out, total: out.length }
})

route('GET', '/api/hosts/:id', ({ params }) => {
  advanceCommands()
  recomputeOpenAlerts()
  return getHostOr404(params.id)
})

route(
  'PATCH',
  '/api/hosts/:id',
  ({ params, body, user }) => {
    const h = getHostOr404(params.id)
    const b = obj(body)
    if (!Array.isArray(b.labels) || !b.labels.every((l) => typeof l === 'string')) fail(400, 'labels must be an array of strings')
    h.labels = [...new Set((b.labels as string[]).map((l) => l.trim().toLowerCase()).filter(Boolean))]
    logAudit(user, 'host.update', h.hostname, { labels: h.labels })
    return h
  },
  { role: 'analyst' },
)

route(
  'DELETE',
  '/api/hosts/:id',
  ({ params, user }) => {
    const h = getHostOr404(params.id)
    h.status = 'revoked'
    logAudit(user, 'host.revoke', h.hostname, null)
    return NO_CONTENT
  },
  { role: 'admin' },
)

function validateCommand(h: Host, req: CommandRequest) {
  const p = (req.params ?? {}) as Record<string, unknown>
  switch (req.type) {
    case 'process.kill':
      if (!Number.isInteger(p.pid) || (p.pid as number) <= 0) fail(400, 'params.pid must be a positive integer')
      break
    case 'file.quarantine':
    case 'file.get':
    case 'file.hash':
      if (typeof p.path !== 'string' || !p.path.trim()) fail(400, 'params.path is required')
      break
    case 'file.restore':
      if (typeof p.id !== 'string' || !p.id.trim()) fail(400, 'params.id is required')
      break
    case 'artifact.collect': {
      const a = artifacts.find((x) => x.name === p.name) ?? fail(400, `unknown artifact "${String(p.name)}"`)
      if (!a.platforms.includes(h.os.platform)) fail(400, `${a.name} is not available on ${h.os.platform}`)
      for (const arg of a.params ?? []) {
        const v = (p.params as Record<string, string> | undefined)?.[arg.name]
        if (arg.required && !v) fail(400, `parameter "${arg.name}" is required`)
      }
      break
    }
    case 'host.isolate':
      if (p.allow !== undefined && (!Array.isArray(p.allow) || !p.allow.every((x) => typeof x === 'string'))) fail(400, 'params.allow must be an array of strings')
      break
    case 'host.release':
      break
    default:
      fail(400, `unknown command type "${String((req as { type: unknown }).type)}"`)
  }
}

route(
  'POST',
  '/api/hosts/:id/actions',
  ({ params, body, user }) => {
    const h = getHostOr404(params.id)
    const req = obj(body) as unknown as CommandRequest
    if (!COMMAND_TYPES.includes(req.type as CommandType)) fail(400, `unknown command type "${String(req.type)}"`)
    if (h.kind === 'network') fail(409, 'network devices do not run commands')
    if (h.status === 'revoked') fail(409, 'host is revoked')
    if (h.allowed_actions && !h.allowed_actions.includes(req.type)) fail(409, `${req.type} is not allowed by the agent's local policy`)
    validateCommand(h, req)
    const now = Date.now()
    const c: MockCommand & { _issued: number } = {
      id: makeId(now),
      host_id: h.id,
      hostname: h.hostname,
      type: req.type,
      params: req.params ?? {},
      status: 'queued',
      issued_by: user!.username,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + HOUR).toISOString(),
      _issued: now,
      _outcome: 'completed',
    }
    commands.unshift(c)
    logAudit(user, 'command.create', h.hostname, { type: req.type, params: req.params })
    return c
  },
  { role: 'analyst' },
)

/** Moves live mock commands through queued → delivered → running → completed. */
function advanceCommands() {
  const now = Date.now()
  for (const c of commands as (MockCommand & { _issued?: number })[]) {
    if (c._issued === undefined) continue
    if (['completed', 'failed', 'rejected', 'expired'].includes(c.status)) continue
    const h = hostById(c.host_id)!
    const reachable = h.status === 'online' || h.status === 'isolated'
    const age = now - c._issued
    if (!reachable) {
      if (now > Date.parse(c.expires_at)) c.status = 'expired'
      continue
    }
    if (age > 1500 && c.status === 'queued') {
      c.status = 'delivered'
      c.delivered_at = new Date(c._issued + 1500).toISOString()
    }
    if (age > 2500 && c.status === 'delivered') c.status = 'running'
    if (age > 4500 && c.status === 'running') finishCommand(c, h)
  }
}

function finishCommand(c: MockCommand, h: Host) {
  c.status = 'completed'
  c.completed_at = new Date().toISOString()
  const p = c.params as Record<string, unknown>
  const sha = () => Array.from({ length: 64 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('')
  switch (c.type) {
    case 'process.kill': {
      const pid = Number(p.pid)
      const mp = processes.find((x) => x.host_id === h.id && x.pid === pid && !x.end)
      if (!mp) {
        c.status = 'failed'
        c.error = `no running process with PID ${pid}`
        break
      }
      if (typeof p.entity_id === 'string' && p.entity_id && p.entity_id !== mp.entity_id) {
        c.status = 'failed'
        c.error = 'PID was reused by a different process; nothing was killed'
        break
      }
      const killed = [pid]
      if (p.tree) {
        const walk = (e: string) => processes.filter((x) => x.parent === e && !x.end).forEach((x) => (killed.push(x.pid), walk(x.entity_id)))
        walk(mp.entity_id)
      }
      for (const k of killed) {
        const x = processes.find((y) => y.host_id === h.id && y.pid === k && !y.end)
        if (x) {
          x.end = Date.now()
          x.exit_code = 1
        }
      }
      c.output = { killed }
      break
    }
    case 'host.isolate':
      h.isolated = true
      h.status = 'isolated'
      c.output = {}
      break
    case 'host.release':
      h.isolated = false
      h.status = 'online'
      c.output = {}
      break
    case 'file.quarantine':
      c.output = { id: makeId(Date.now()), original_path: p.path, sha256: sha(), size: 4182 }
      break
    case 'file.restore':
      c.output = {}
      break
    case 'file.hash':
      c.output = { path: p.path, size: 4182, md5: sha().slice(0, 32), sha1: sha().slice(0, 40), sha256: sha() }
      break
    case 'file.get':
      c.output = { path: p.path, size: 120, md5: sha().slice(0, 32), sha1: sha().slice(0, 40), sha256: sha() }
      c._file = `HomeXDR mock mode: placeholder content for ${String(p.path)}\n`
      break
    case 'artifact.collect': {
      const rows = artifactRows(String(p.name), h.id, (p.params as Record<string, string>) ?? {})
      c._rows = rows
      c.row_count = rows.length
      c.output = { rows: rows.length }
      break
    }
  }
}

route('GET', '/api/hosts/:id/commands', ({ params }) => {
  getHostOr404(params.id)
  advanceCommands()
  return { commands: commands.filter((c) => c.host_id === params.id).map(publicCommand) }
})

function publicCommand(c: MockCommand): MockCommand {
  const { _outcome, _rows, _file, ...rest } = c as MockCommand & { _issued?: number }
  void _outcome
  void _rows
  void _file
  delete (rest as { _issued?: number })._issued
  return rest
}

function timeFilter(e: Event, from: string | null, to: string | null) {
  const t = e['@timestamp']
  return (!from || t >= new Date(from).toISOString()) && (!to || t <= new Date(to).toISOString())
}

route('GET', '/api/hosts/:id/timeline', ({ params, query }) => {
  getHostOr404(params.id)
  const cat = query.get('category')
  const limit = Math.min(1000, Number(query.get('limit') ?? 100) || 100)
  const out = events
    .filter((e) => e.host.id === params.id && timeFilter(e, query.get('from'), query.get('to')) && (!cat || e.event.category?.includes(cat)))
    .slice(0, limit)
  return { events: out }
})

// --- commands -------------------------------------------------------------------------------

function getCommandOr404(id: string): MockCommand {
  advanceCommands()
  return commands.find((c) => c.id === id) ?? fail(404, 'command not found')
}

route('GET', '/api/commands/:id', ({ params }) => publicCommand(getCommandOr404(params.id)))

route('GET', '/api/commands/:id/rows', ({ params, query }) => {
  const c = getCommandOr404(params.id)
  const rows = c._rows ?? []
  return { rows: page(rows, query), total: rows.length }
})

route('GET', '/api/commands/:id/download', ({ params }) => {
  const c = getCommandOr404(params.id)
  if (c.type !== 'file.get' || !c._file) fail(404, 'no uploaded file for this command')
  const path = String((c.params as { path?: string }).path ?? 'file')
  const name = path.split(/[\\/]/).pop() || 'file'
  return new Response(c._file!, {
    status: 200,
    headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${name}"` },
  })
})

// --- events ---------------------------------------------------------------------------------

route('POST', '/api/events/search', ({ body }) => {
  const b = obj(body)
  const started = performance.now()
  let match: (e: unknown) => boolean
  try {
    match = compileQuery(String(b.query ?? ''))
  } catch (e) {
    if (e instanceof QuerySyntaxError) fail(400, `query: ${e.message} at position ${e.pos + 1}`)
    throw e
  }
  const from = typeof b.from === 'string' ? b.from : null
  const to = typeof b.to === 'string' ? b.to : null
  const hostId = typeof b.host_id === 'string' ? b.host_id : null
  let out = events.filter((e) => (!hostId || e.host.id === hostId) && timeFilter(e, from, to) && match(e))
  if (b.order === 'asc') out = [...out].reverse()
  const limit = Math.min(1000, Math.max(1, Number(b.limit ?? 100) || 100))
  const offset = Math.max(0, Number(b.offset ?? 0) || 0)
  return { events: out.slice(offset, offset + limit), total: out.length, took_ms: Math.max(1, Math.round(performance.now() - started + 8)) }
})

route('GET', '/api/events/:id', ({ params }) => eventById(params.id) ?? fail(404, 'event not found'))

// --- process trees ----------------------------------------------------------------------------

function eventCounts(entityId: string): ProcessNode['event_counts'] {
  const c = { network: 0, file: 0, registry: 0, dns: 0, library: 0 }
  for (const e of events) {
    if (e.process?.entity_id !== entityId) continue
    const cat = e.event.category ?? []
    if (e.dns) c.dns++
    else if (cat.includes('network')) c.network++
    else if (cat.includes('file')) c.file++
    else if (cat.includes('registry')) c.registry++
    else if (cat.includes('library')) c.library++
  }
  return c
}

function toNode(p: MockProcess, children: ProcessNode[], target: string): ProcessNode {
  return {
    entity_id: p.entity_id,
    pid: p.pid,
    name: p.name,
    executable: p.executable,
    command_line: p.command_line,
    user: p.user,
    start: new Date(p.start).toISOString(),
    end: p.end ? new Date(p.end).toISOString() : undefined,
    exit_code: p.end ? p.exit_code : undefined,
    parent_entity_id: p.parent,
    hash_sha256: p.sha256,
    signed: p.signed,
    alert_count: alerts.filter((a) => a.process_entity_id === p.entity_id).length,
    event_counts: eventCounts(p.entity_id),
    children,
    is_target: p.entity_id === target || undefined,
  }
}

function descendants(p: MockProcess, depth: number, target: string): ProcessNode {
  const kids = depth > 0 ? processes.filter((x) => x.parent === p.entity_id).sort((a, b) => a.start - b.start) : []
  return toNode(
    p,
    kids.map((k) => descendants(k, depth - 1, target)),
    target,
  )
}

route('GET', '/api/process-tree', ({ query }) => {
  const hostId = query.get('host_id') ?? ''
  const entityId = query.get('entity_id') ?? ''
  const depth = Math.min(10, Math.max(0, Number(query.get('depth') ?? 3) || 3))
  const target = processes.find((p) => p.entity_id === entityId && p.host_id === hostId) ?? fail(404, 'process not found')
  let node = descendants(target, depth, target.entity_id)
  let cur = target
  while (cur.parent) {
    const parent = processes.find((p) => p.entity_id === cur.parent)
    if (!parent) break
    node = toNode(parent, [node], target.entity_id)
    cur = parent
  }
  return { root: node }
})

route('GET', '/api/process-events', ({ query }) => {
  const entityId = query.get('entity_id') ?? ''
  const cat = query.get('category')
  const limit = Math.min(1000, Number(query.get('limit') ?? 200) || 200)
  const out = events.filter((e) => {
    if (e.process?.entity_id !== entityId) return false
    const c = e.event.category ?? []
    if (c.includes('process') && !e.dns) return false
    if (!cat) return true
    if (cat === 'dns') return !!e.dns
    if (cat === 'network') return c.includes('network') && !e.dns
    return c.includes(cat)
  })
  return { events: out.slice(0, limit) }
})

// --- alerts ---------------------------------------------------------------------------------

function getAlertOr404(id: string): Alert {
  return alerts.find((a) => a.id === id) ?? fail(404, 'alert not found')
}

function alertMatches(a: Alert, q: string) {
  const hay = [a.rule.title, a.hostname, a.process_name, a.command_line, a.user, a.assignee, ...a.mitre.map((m) => `${m.technique_id} ${m.technique} ${m.tactic}`)]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
  return q
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => hay.includes(w))
}

route('GET', '/api/alerts', ({ query }) => {
  const status = list(query, 'status')
  const sev = list(query, 'severity')
  const hostId = query.get('host_id')
  const ruleId = query.get('rule_id')
  const q = query.get('q') ?? ''
  const out = alerts.filter(
    (a) =>
      (!status.length || status.includes(a.status)) &&
      (!sev.length || sev.includes(a.severity)) &&
      (!hostId || a.host_id === hostId) &&
      (!ruleId || a.rule.id === ruleId) &&
      (!q || alertMatches(a, q)),
  )
  return { alerts: page(out, query).map((a) => ({ ...a, events: undefined })), total: out.length }
})

route('GET', '/api/alerts/:id', ({ params }) => {
  const a = getAlertOr404(params.id)
  return { ...a, events: a.event_ids.map((id) => eventById(id)).filter(Boolean).slice(0, 20) }
})

function applyPatch(a: Alert, p: AlertPatch) {
  if (p.status !== undefined) {
    if (!['new', 'in_progress', 'resolved', 'false_positive'].includes(p.status)) fail(400, 'invalid status')
    a.status = p.status
  }
  if (p.assignee !== undefined) a.assignee = p.assignee || undefined
  a.updated_at = new Date().toISOString()
}

route(
  'PATCH',
  '/api/alerts/:id',
  ({ params, body, user }) => {
    const a = getAlertOr404(params.id)
    applyPatch(a, obj(body) as AlertPatch)
    recomputeOpenAlerts()
    logAudit(user, 'alert.update', a.rule.title, body)
    return a
  },
  { role: 'analyst' },
)

route(
  'POST',
  '/api/alerts/bulk',
  ({ body, user }) => {
    const b = obj(body) as { ids?: unknown } & AlertPatch
    if (!Array.isArray(b.ids)) fail(400, 'ids must be an array')
    let n = 0
    for (const id of b.ids as string[]) {
      const a = alerts.find((x) => x.id === id)
      if (!a) continue
      applyPatch(a, { status: b.status, assignee: b.assignee })
      n++
    }
    recomputeOpenAlerts()
    logAudit(user, 'alert.bulk_update', `${n} alerts`, { status: b.status, assignee: b.assignee })
    return { updated: n }
  },
  { role: 'analyst' },
)

route(
  'POST',
  '/api/alerts/:id/notes',
  ({ params, body, user }) => {
    const a = getAlertOr404(params.id)
    const text = String(obj(body).text ?? '').trim()
    if (!text) fail(400, 'text is required')
    a.notes = [...a.notes, { author: user!.username, text, at: new Date().toISOString() }]
    a.updated_at = new Date().toISOString()
    return a
  },
  { role: 'analyst' },
)

// --- rules ----------------------------------------------------------------------------------

function getRuleOr404(id: string): Rule {
  return ruleById(id) ?? fail(404, 'rule not found')
}

route('GET', '/api/rules', ({ query }) => {
  const q = (query.get('q') ?? '').toLowerCase()
  const enabled = query.get('enabled')
  const level = list(query, 'level')
  const source = query.get('source')
  const out = rules.filter(
    (r) =>
      (!q || [r.title, r.description, ...r.tags, ...r.mitre.map((m) => m.technique_id)].join(' ').toLowerCase().includes(q)) &&
      (!enabled || String(r.enabled) === enabled) &&
      (!level.length || level.includes(r.level)) &&
      (!source || r.source === source),
  )
  return { rules: out.map((r) => ({ ...r, yaml: undefined })), total: out.length }
})

route('GET', '/api/rules/:id', ({ params }) => getRuleOr404(params.id))

route(
  'POST',
  '/api/rules',
  ({ body, user }) => {
    const res = parseRuleYaml(String(obj(body).yaml ?? ''))
    if (!res.ok) fail(400, res.error)
    const rule = (res as { rule: Rule }).rule
    if (ruleById(rule.id)) fail(409, `a rule with id ${rule.id} already exists`)
    rule.author = rule.author ?? user!.username
    rules.unshift(rule)
    logAudit(user, 'rule.create', rule.title, null)
    return rule
  },
  { role: 'admin' },
)

route(
  'PUT',
  '/api/rules/:id',
  ({ params, body, user }) => {
    const r = getRuleOr404(params.id)
    if (r.source !== 'custom') fail(409, 'built-in rules cannot be edited; disable it and create a custom rule instead')
    const res = parseRuleYaml(String(obj(body).yaml ?? ''))
    if (!res.ok) fail(400, res.error)
    const next = (res as { rule: Rule }).rule
    Object.assign(r, { ...next, id: r.id, enabled: r.enabled, hits_24h: r.hits_24h, updated_at: new Date().toISOString() })
    logAudit(user, 'rule.update', r.title, null)
    return r
  },
  { role: 'admin' },
)

route(
  'PATCH',
  '/api/rules/:id',
  ({ params, body, user }) => {
    const r = getRuleOr404(params.id)
    const b = obj(body)
    if (typeof b.enabled !== 'boolean') fail(400, 'enabled must be a boolean')
    r.enabled = b.enabled as boolean
    r.updated_at = new Date().toISOString()
    logAudit(user, r.enabled ? 'rule.enable' : 'rule.disable', r.title, null)
    return r
  },
  { role: 'admin' },
)

route(
  'DELETE',
  '/api/rules/:id',
  ({ params, user }) => {
    const r = getRuleOr404(params.id)
    if (r.source !== 'custom') fail(409, 'built-in rules cannot be deleted')
    rules.splice(rules.indexOf(r), 1)
    logAudit(user, 'rule.delete', r.title, null)
    return NO_CONTENT
  },
  { role: 'admin' },
)

route(
  'POST',
  '/api/rules/reload',
  ({ user }) => {
    logAudit(user, 'rules.reload', `${rules.length} rules, 0 errors`, null)
    return { total: rules.length, enabled: rules.filter((r) => r.enabled).length, load_errors: [] }
  },
  { role: 'admin' },
)

route('POST', '/api/rules/validate', ({ body }) => {
  const res = parseRuleYaml(String(obj(body).yaml ?? ''))
  return res.ok ? { ok: true, rule: res.rule } : { ok: false, error: res.error }
})

route('POST', '/api/rules/test', ({ body }) => {
  const b = obj(body)
  const yaml = String(b.yaml ?? '')
  const res = parseRuleYaml(yaml)
  if (!res.ok) fail(400, res.error)
  const hours = Math.min(24 * 30, Math.max(1, Number(b.hours ?? 24) || 24))
  const since = new Date(Date.now() - hours * HOUR).toISOString()
  const scanned = events.filter((e) => e['@timestamp'] >= since)
  const needles = detectionNeedles(yaml)
  const need = Math.min(2, needles.length)
  const matches = needles.length
    ? scanned.filter((e) => {
        const hay = JSON.stringify(e).toLowerCase().replace(/\\\\/g, '\\')
        return needles.filter((n) => hay.includes(n)).length >= need
      })
    : []
  return { matches: matches.slice(0, 200), scanned: scanned.length }
})

// --- artifacts and hunts -----------------------------------------------------------------------

route('GET', '/api/artifacts', () => ({ artifacts }))

function huntHosts(t: HuntCreate['target'], artifact: string): Host[] {
  const a = artifacts.find((x) => x.name === artifact)!
  return hosts.filter(
    (h) =>
      h.kind === 'endpoint' &&
      h.status !== 'revoked' &&
      a.platforms.includes(h.os.platform) &&
      (t.all ||
        (t.labels?.length ? t.labels.some((l) => h.labels.includes(l)) : false) ||
        (t.host_ids?.length ? t.host_ids.includes(h.id) : false) ||
        (t.platform ? h.os.platform === t.platform : false)),
  )
}

type LiveHunt = MockHunt & { _created?: number; _hosts?: string[] }

function huntView(h: LiveHunt): MockHunt {
  if (h._created !== undefined && h._hosts) {
    const now = Date.now()
    const done: string[] = []
    h._hosts.forEach((id, i) => {
      const host = hostById(id)!
      const reachable = host.status === 'online' || host.status === 'isolated'
      if (h.status !== 'stopped' && reachable && now - h._created! > 2500 * (i + 1)) done.push(id)
    })
    h._rows = done.flatMap((id) => artifactRows(h.artifact, id, h.params).map((row) => ({ host_id: id, hostname: hostById(id)!.hostname, row })))
    h.stats = { scheduled: h._hosts.length, completed: done.length, failed: 0, rows: h._rows.length }
    if (h.status === 'running' && now > Date.parse(h.expires_at)) h.status = 'completed'
  }
  const { _rows, ...rest } = h
  void _rows
  delete (rest as Partial<LiveHunt>)._created
  delete (rest as Partial<LiveHunt>)._hosts
  return rest as MockHunt
}

function getHuntOr404(id: string): LiveHunt {
  return (hunts.find((h) => h.id === id) as LiveHunt) ?? fail(404, 'hunt not found')
}

route(
  'POST',
  '/api/hunts',
  ({ body, user }) => {
    const b = obj(body) as unknown as HuntCreate
    const a = artifacts.find((x) => x.name === b.artifact) ?? fail(400, `unknown artifact "${String(b.artifact)}"`)
    const t = b.target ?? {}
    if (!t.all && !t.labels?.length && !t.host_ids?.length && !t.platform) fail(400, 'target must select at least one host')
    for (const arg of a.params ?? []) if (arg.required && !b.params?.[arg.name]) fail(400, `parameter "${arg.name}" is required`)
    const now = Date.now()
    const matched = huntHosts(t, a.name)
    const h: LiveHunt = {
      id: makeId(now),
      artifact: a.name,
      params: b.params ?? {},
      description: b.description,
      target: t,
      status: 'running',
      created_by: user!.username,
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + (b.expires_hours ?? 24 * 7) * HOUR).toISOString(),
      stats: { scheduled: matched.length, completed: 0, failed: 0, rows: 0 },
      _rows: [],
      _created: now,
      _hosts: matched.map((x) => x.id),
    }
    hunts.unshift(h)
    logAudit(user, 'hunt.create', a.name, { target: t })
    return huntView(h)
  },
  { role: 'analyst' },
)

route('GET', '/api/hunts', () => ({ hunts: hunts.map((h) => huntView(h as LiveHunt)) }))
route('GET', '/api/hunts/:id', ({ params }) => huntView(getHuntOr404(params.id)))

route(
  'POST',
  '/api/hunts/:id/stop',
  ({ params, user }) => {
    const h = getHuntOr404(params.id)
    huntView(h)
    if (h.status === 'running') h.status = 'stopped'
    logAudit(user, 'hunt.stop', h.artifact, null)
    return huntView(h)
  },
  { role: 'analyst' },
)

route('GET', '/api/hunts/:id/results', ({ params, query }) => {
  const h = getHuntOr404(params.id)
  huntView(h)
  const hostId = query.get('host_id')
  const rows = h._rows.filter((r) => !hostId || r.host_id === hostId)
  return { rows: page(rows, query), total: rows.length }
})

// --- settings and admin ---------------------------------------------------------------------------

route('GET', '/api/settings/server', () => serverSettings)

route('GET', '/api/enrollment-tokens', () => ({ tokens: tokens.map((t) => ({ ...t, token: undefined })) }), { role: 'admin' })

route(
  'POST',
  '/api/enrollment-tokens',
  ({ body, user }) => {
    const b = obj(body)
    const name = String(b.name ?? '').trim()
    if (!name) fail(400, 'name is required')
    const now = Date.now()
    const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
    const secret = Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) => B32[x % 32]).join('')
    const t = {
      id: makeId(now),
      name,
      token: `hxe_${secret}`,
      created_at: new Date(now).toISOString(),
      created_by: user!.username,
      expires_at: typeof b.expires_hours === 'number' && b.expires_hours > 0 ? new Date(now + b.expires_hours * HOUR).toISOString() : undefined,
      max_uses: typeof b.max_uses === 'number' && b.max_uses > 0 ? b.max_uses : undefined,
      uses: 0,
      labels: Array.isArray(b.labels) ? (b.labels as string[]) : [],
    }
    tokens.unshift({ ...t, token: undefined })
    logAudit(user, 'token.create', name, { expires_hours: b.expires_hours, max_uses: b.max_uses })
    return t
  },
  { role: 'admin' },
)

route(
  'DELETE',
  '/api/enrollment-tokens/:id',
  ({ params, user }) => {
    const i = tokens.findIndex((t) => t.id === params.id)
    if (i < 0) fail(404, 'token not found')
    const [t] = tokens.splice(i, 1)
    logAudit(user, 'token.delete', t.name, null)
    return NO_CONTENT
  },
  { role: 'admin' },
)

route('GET', '/api/agent-config', () => agentConfig)

route(
  'PUT',
  '/api/agent-config',
  ({ body, user }) => {
    const b = obj(body) as unknown as AgentConfig
    if (typeof b.heartbeat_interval_sec !== 'number' || b.heartbeat_interval_sec < 5) fail(400, 'heartbeat_interval_sec must be a number >= 5')
    if (!b.sensors || !b.batch || !b.fim) fail(400, 'sensors, batch and fim are required')
    Object.assign(agentConfig, b, { version: agentConfig.version + 1 })
    logAudit(user, 'agent_config.update', 'default', { version: agentConfig.version })
    return agentConfig
  },
  { role: 'admin' },
)

route('GET', '/api/users', () => ({ users }), { role: 'admin' })

route(
  'POST',
  '/api/users',
  ({ body, user }) => {
    const b = obj(body)
    const username = String(b.username ?? '').trim()
    const password = String(b.password ?? '')
    const role = String(b.role ?? '') as Role
    if (!/^[a-zA-Z0-9._-]{2,32}$/.test(username)) fail(400, 'username must be 2-32 characters: letters, digits, . _ -')
    if (users.some((u) => u.username === username)) fail(409, 'username already exists')
    if (password.length < 10) fail(400, 'password must be at least 10 characters')
    if (!['admin', 'analyst', 'viewer'].includes(role)) fail(400, 'invalid role')
    const u: User = { id: makeId(Date.now()), username, role, created_at: new Date().toISOString() }
    users.push(u)
    logAudit(user, 'user.create', username, { role })
    return u
  },
  { role: 'admin' },
)

route('PATCH', '/api/users/:id', ({ params, body, user }) => {
  const u = users.find((x) => x.id === params.id) ?? fail(404, 'user not found')
  const b = obj(body)
  const self = u.id === user!.id
  if (!self && !hasRole(user, 'admin')) fail(403, 'forbidden: requires admin role')
  if (b.role !== undefined) {
    if (!hasRole(user, 'admin')) fail(403, 'only admins can change roles')
    if (self) fail(400, 'you cannot change your own role')
    if (!['admin', 'analyst', 'viewer'].includes(String(b.role))) fail(400, 'invalid role')
    u.role = b.role as Role
  }
  if (b.password !== undefined) {
    if (String(b.password).length < 10) fail(400, 'password must be at least 10 characters')
  }
  logAudit(user, 'user.update', u.username, { role: b.role, password_changed: b.password !== undefined })
  return u
})

route(
  'DELETE',
  '/api/users/:id',
  ({ params, user }) => {
    const i = users.findIndex((x) => x.id === params.id)
    if (i < 0) fail(404, 'user not found')
    if (users[i].id === user!.id) fail(400, 'you cannot delete yourself')
    const [u] = users.splice(i, 1)
    logAudit(user, 'user.delete', u.username, null)
    return NO_CONTENT
  },
  { role: 'admin' },
)

route('GET', '/api/audit', ({ query }) => ({ entries: page(audit, query), total: audit.length }), { role: 'admin' })

route('GET', '/api/integrations', () => integrations)
