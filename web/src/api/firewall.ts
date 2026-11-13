// Host firewall control (Settings → Firewall): addresses blocked in every host's own
// firewall, everywhere or for one group and its child groups. See docs/firewall.md.

import { http } from './client'

export type FirewallDirection = 'both' | 'in' | 'out'

export interface FirewallBlock {
  id: string
  cidr: string
  direction: FirewallDirection
  /** "" for every host */
  group_id: string
  note: string
  alert_id?: string
  created_by: string
  created_at: string
  /** the organisation, or the group's path */
  scope: string
  /** why the block reaches no host, if it does not */
  problem?: string
}

export type FirewallHostStatus = 'off' | 'empty' | 'applied' | 'pending' | 'failed' | 'not_allowed' | 'offline'

export interface FirewallHost {
  host_id: string
  hostname: string
  platform: string
  enabled: boolean
  enabled_from?: string
  status: FirewallHostStatus
  desired?: string
  rules: number
  applied?: string
  applied_rules: number
  backend?: string
  message?: string
  updated_at?: string
}

export interface FirewallView {
  settings: { enabled: boolean }
  blocks: FirewallBlock[]
  hosts: FirewallHost[]
  server_addrs: string[]
  limits: { max_blocks: number; min_prefix_v4: number; min_prefix_v6: number }
}

export interface FirewallBlockInput {
  cidr: string
  direction?: FirewallDirection
  group_id?: string
  note?: string
  alert_id?: string
}

export const firewallKeys = { status: ['firewall'] as const }

export const getFirewall = () => http.get<FirewallView>('/api/firewall')
export const addFirewallBlock = (b: FirewallBlockInput) => http.post<FirewallView>('/api/firewall/blocks', b)
export const removeFirewallBlock = (id: string) => http.del<FirewallView>(`/api/firewall/blocks/${encodeURIComponent(id)}`)
export const putFirewallSettings = (s: { enabled: boolean }) => http.put<FirewallView>('/api/settings/firewall', s)
