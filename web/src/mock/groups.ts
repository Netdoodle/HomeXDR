// Mock host groups: Netdoodle › DTS Assets › Marketing Dept and
// Netdoodle › Infrastructure Assets › Linux Servers.

import type { Effective, GroupPolicy, GroupsView, HostGroup, SettingKey, SettingSource } from '../api/groups'
import type { Role } from '../api/types'
import { status as avStatus } from './antivirus'
import { firewallGlobal } from './firewall'
import { ago, DAY, hosts, LAPTOP_ID, LINUX_ID, PI_ID, WIN_ID } from './hosts'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

type G = { id: string; name: string; parent_id: string; policy: GroupPolicy; created_at: string }

let org = 'Netdoodle'
let seq = 0
const groups: G[] = [
  { id: 'g-dts', name: 'DTS Assets', parent_id: '', policy: { av: {} }, created_at: ago(9 * DAY) },
  { id: 'g-mkt', name: 'Marketing Dept', parent_id: 'g-dts', policy: { av: { yara: false } }, created_at: ago(9 * DAY) },
  { id: 'g-infra', name: 'Infrastructure Assets', parent_id: '', policy: { av: { clamav: true, action: 'alert' }, ai: { auto: false } }, created_at: ago(8 * DAY) },
  { id: 'g-linux', name: 'Linux Servers', parent_id: 'g-infra', policy: { av: {} }, created_at: ago(8 * DAY) },
]
const member: Record<string, string> = { [WIN_ID]: 'g-mkt', [LAPTOP_ID]: 'g-dts', [LINUX_ID]: 'g-linux', [PI_ID]: 'g-linux' }
for (const h of hosts) h.group_id = member[h.id] ?? ''

function chain(id: string): G[] {
  const out: G[] = []
  for (let g = groups.find((x) => x.id === id); g; g = groups.find((x) => x.id === g!.parent_id)) out.push(g)
  return out
}

function own(g: G, k: SettingKey): boolean | string | undefined {
  switch (k) {
    case 'clamav':
      return g.policy.av.clamav
    case 'yara':
      return g.policy.av.yara
    case 'action':
      return g.policy.av.action
    case 'app_control':
      return g.policy.av.app_control
    case 'ai_auto':
      return g.policy.ai?.auto
    case 'firewall':
      return g.policy.firewall?.enabled
  }
}

function globalOf(k: SettingKey): boolean | string {
  const s = avStatus.settings
  if (k === 'firewall') return firewallGlobal()
  return k === 'clamav' ? s.use_clamav : k === 'yara' ? s.use_yara : k === 'action' ? s.action : k === 'app_control' ? s.app_control : true
}

function effective(id: string): Effective {
  const one = (k: SettingKey): SettingSource<boolean | string> => {
    for (const g of chain(id)) {
      const v = own(g, k)
      if (v !== undefined) return { value: v, group_id: g.id, group_name: g.name }
    }
    return { value: globalOf(k) }
  }
  return { clamav: one('clamav'), yara: one('yara'), action: one('action'), app_control: one('app_control'), ai_auto: one('ai_auto'), firewall: one('firewall') } as Effective
}

/** For the firewall mock: a group and its ancestors, nearest first. */
export function groupChain(id: string): { id: string; name: string }[] {
  return chain(id)
}

/** For the firewall mock: whether host firewall control applies in a group. */
export function firewallEffective(id: string): SettingSource {
  return effective(id).firewall
}

function view(): GroupsView {
  const ordered: G[] = []
  const byName = (a: G, b: G) => a.name.localeCompare(b.name)
  for (const p of groups.filter((g) => !g.parent_id).sort(byName)) {
    ordered.push(p, ...groups.filter((g) => g.parent_id === p.id).sort(byName))
  }
  const out: HostGroup[] = ordered.map((g) => ({
    ...g,
    hosts: hosts.filter((h) => h.group_id === g.id).length,
    effective: effective(g.id),
  }))
  return {
    org: { name: org },
    global: { clamav: avStatus.settings.use_clamav, yara: avStatus.settings.use_yara, action: avStatus.settings.action, app_control: avStatus.settings.app_control, ai_auto: true, firewall: firewallGlobal() },
    groups: out,
    ungrouped: hosts.filter((h) => h.kind === 'endpoint' && !h.group_id).length,
  }
}

/** Registers the group routes on the mock server. */
export function groupRoutes(route: Route, fail: (status: number, message: string) => never) {
  const checkName = (name: string, parent: string, self = '') => {
    const n = name.trim()
    if (!n || n.length > 80) fail(400, 'a group name is 1 to 80 characters')
    if (groups.some((g) => g.parent_id === parent && g.id !== self && g.name.toLowerCase() === n.toLowerCase()))
      fail(400, `there already is a group named "${n}" here`)
    return n
  }
  route('GET', '/api/groups', () => view())
  route(
    'PUT',
    '/api/org',
    ({ body }) => {
      const n = String((body as { name: string }).name ?? '').trim()
      if (!n || n.length > 80) fail(400, 'the organisation name is 1 to 80 characters')
      org = n
      return view()
    },
    { role: 'admin' },
  )
  route(
    'POST',
    '/api/groups',
    ({ body }) => {
      const b = body as { name: string; parent_id: string }
      const parent = b.parent_id ?? ''
      if (parent) {
        const p = groups.find((g) => g.id === parent)
        if (!p) fail(400, 'the parent group does not exist')
        if (p!.parent_id) fail(400, 'groups go two levels deep: parent groups and their child groups')
      }
      groups.push({ id: `g-new-${++seq}`, name: checkName(b.name, parent), parent_id: parent, policy: { av: {} }, created_at: new Date().toISOString() })
      return view()
    },
    { role: 'admin' },
  )
  route(
    'PATCH',
    '/api/groups/:id',
    ({ params, body }) => {
      const g = groups.find((x) => x.id === params.id)
      if (!g) fail(404, 'no such group')
      const b = body as { name?: string; policy?: GroupPolicy }
      if (b.name !== undefined) g!.name = checkName(b.name, g!.parent_id, g!.id)
      if (b.policy) g!.policy = { av: { ...b.policy.av }, ai: { ...b.policy.ai }, firewall: { ...b.policy.firewall } }
      return view()
    },
    { role: 'admin' },
  )
  route(
    'DELETE',
    '/api/groups/:id',
    ({ params }) => {
      const g = groups.find((x) => x.id === params.id)
      if (!g) fail(404, 'no such group')
      if (groups.some((x) => x.parent_id === g!.id)) fail(400, 'delete or move its child groups first')
      for (const h of hosts) if (h.group_id === g!.id) h.group_id = g!.parent_id
      groups.splice(groups.indexOf(g!), 1)
      return view()
    },
    { role: 'admin' },
  )
  route(
    'PUT',
    '/api/hosts/group',
    ({ body }) => {
      const b = body as { host_ids: string[]; group_id: string }
      if (b.group_id && !groups.some((g) => g.id === b.group_id)) fail(400, 'the group does not exist')
      for (const h of hosts) if (b.host_ids.includes(h.id)) h.group_id = b.group_id
      return view()
    },
    { role: 'admin' },
  )
}

/** Whether a host in group hostGroup matches a ?group= filter (a group with its child
 * groups, or "none"). */
export function matchesGroupFilter(hostGroup: string | undefined, filter: string | null): boolean {
  if (!filter) return true
  if (filter === 'none') return !hostGroup
  return hostGroup === filter || groups.some((g) => g.id === hostGroup && g.parent_id === filter)
}
