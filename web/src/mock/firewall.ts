// Mock host firewall control: a few blocked addresses (documentation ranges only), one
// scoped to a group, and the hosts' states.

import type { FirewallBlock, FirewallBlockInput, FirewallHost, FirewallView } from '../api/firewall'
import { blockProblem } from '../lib/firewall'
import type { MockRoute } from './health'
import { firewallEffective, groupChain } from './groups'
import { ago, DAY, hosts, HOUR, LAPTOP_ID, LINUX_ID, PI_ID, WIN_ID } from './hosts'

const SERVER_ADDRS = ['192.168.1.10', '100.64.0.10']
let enabled = true
let seq = 0

const blocks: Omit<FirewallBlock, 'scope' | 'problem'>[] = [
  { id: 'fw-1', cidr: '203.0.113.45', direction: 'both', group_id: '', note: 'Alert: Beacon to known C2 server on DESKTOP-7QK2M4 (01HXAMPLE)', alert_id: 'a-1', created_by: 'admin', created_at: ago(2 * DAY) },
  { id: 'fw-2', cidr: '198.51.100.0/24', direction: 'both', group_id: '', note: 'Scanner network seen on the firewall', created_by: 'admin', created_at: ago(5 * DAY) },
  { id: 'fw-3', cidr: '2001:db8:bad::/48', direction: 'out', group_id: 'g-dts', note: 'Ad network the family PCs should not reach', created_by: 'admin', created_at: ago(1 * DAY) },
]

/** The global firewall.enabled value (Settings → Firewall), for the group mock. */
export function firewallGlobal(): boolean {
  return enabled
}

function scopeName(groupId: string): string {
  if (!groupId) return 'Netdoodle'
  const c = groupChain(groupId)
  return c.length ? c.reverse().map((g) => g.name).join(' > ') : 'a deleted group'
}

const STATE: Record<string, Partial<FirewallHost>> = {
  [WIN_ID]: { status: 'applied', backend: 'windows-firewall', message: '2 Windows Firewall rule(s) in group HomeXDR block 3 address(es) or network(s)', updated_at: ago(3 * HOUR) },
  [LINUX_ID]: { status: 'failed', backend: 'nftables', message: 'host firewall blocking needs nftables, and the nft command is not installed (iptables alone is not supported)', updated_at: ago(HOUR) },
  [LAPTOP_ID]: { status: 'offline', message: 'applies when the host is back online', updated_at: ago(6 * HOUR) },
  [PI_ID]: { status: 'applied', backend: 'nftables', message: 'table inet homexdr_block blocks 2 address(es) or network(s)', updated_at: ago(2 * HOUR) },
}

function view(): FirewallView {
  const out: FirewallHost[] = []
  for (const h of hosts) {
    if (h.kind !== 'endpoint' || !['windows', 'linux', 'darwin'].includes(h.os.platform)) continue
    const eff = firewallEffective(h.group_id ?? '')
    const scopes = new Set(['', ...groupChain(h.group_id ?? '').map((g) => g.id)])
    const rules = eff.value ? blocks.filter((b) => scopes.has(b.group_id)).length : 0
    const st = STATE[h.id] ?? {}
    out.push({
      host_id: h.id,
      hostname: h.hostname,
      platform: h.os.platform,
      enabled: eff.value,
      enabled_from: eff.group_name,
      status: !eff.value && !st.status ? 'off' : (st.status ?? (rules ? 'pending' : 'empty')),
      rules,
      applied_rules: st.status === 'applied' ? rules : 0,
      backend: st.backend,
      message: st.message,
      updated_at: st.updated_at,
    })
  }
  return {
    settings: { enabled },
    blocks: blocks.map((b) => ({ ...b, scope: scopeName(b.group_id), problem: b.group_id && !groupChain(b.group_id).length ? 'its group was deleted, so it applies to no host' : undefined })),
    hosts: out,
    server_addrs: SERVER_ADDRS,
    limits: { max_blocks: 1000, min_prefix_v4: 8, min_prefix_v6: 32 },
  }
}

export function registerFirewallMocks(route: MockRoute, fail: (status: number, message: string) => never) {
  route('GET', '/api/firewall', () => view())
  route(
    'POST',
    '/api/firewall/blocks',
    ({ body, user }) => {
      const b = body as FirewallBlockInput
      const problem = blockProblem(b.cidr ?? '')
      if (problem) fail(400, problem)
      const cidr = b.cidr.trim().replace(/\/32$|\/128$/, '')
      if (SERVER_ADDRS.includes(cidr)) fail(400, `${cidr} covers ${cidr}, an address of the HomeXDR server: blocking it would cut hosts off from HomeXDR`)
      if (blocks.some((x) => x.cidr === cidr && x.group_id === (b.group_id ?? ''))) fail(400, `${cidr} is already blocked for ${scopeName(b.group_id ?? '')}`)
      blocks.unshift({
        id: `fw-new-${++seq}`,
        cidr,
        direction: b.direction ?? 'both',
        group_id: b.group_id ?? '',
        note: (b.note ?? '').trim(),
        alert_id: b.alert_id,
        created_by: user?.username ?? 'admin',
        created_at: new Date().toISOString(),
      })
      return view()
    },
    { role: 'admin' },
  )
  route(
    'DELETE',
    '/api/firewall/blocks/:id',
    ({ params }) => {
      const i = blocks.findIndex((b) => b.id === params.id)
      if (i < 0) fail(404, 'not found')
      blocks.splice(i, 1)
      return view()
    },
    { role: 'admin' },
  )
  route(
    'PUT',
    '/api/settings/firewall',
    ({ body }) => {
      enabled = !!(body as { enabled: boolean }).enabled
      return view()
    },
    { role: 'admin' },
  )
}
