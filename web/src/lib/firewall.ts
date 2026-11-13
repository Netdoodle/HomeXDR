// Host firewall control helpers. The server checks every address (shared/hostfw) and is
// the authority; this catches the obvious mistakes while typing.

import type { FirewallDirection, FirewallHostStatus } from '../api/firewall'

export const DIRECTION_LABEL: Record<FirewallDirection, string> = {
  both: 'Both ways',
  in: 'Inbound only',
  out: 'Outbound only',
}

export const FIREWALL_STATUS: Record<FirewallHostStatus, { label: string; cls: string }> = {
  off: { label: 'Off', cls: 'muted' },
  empty: { label: 'Nothing to block', cls: 'muted' },
  applied: { label: 'Applied', cls: 'sev-text low' },
  pending: { label: 'Sending', cls: '' },
  offline: { label: 'Offline', cls: 'muted' },
  failed: { label: 'Failed', cls: 'sev-text high' },
  not_allowed: { label: 'Not allowed', cls: 'sev-text medium' },
}

export const PLATFORM_FIREWALL: Record<string, string> = {
  windows: 'Windows Firewall',
  linux: 'nftables',
  darwin: 'pf',
}

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function v4Octets(s: string): number[] | null {
  const m = V4.exec(s)
  if (!m) return null
  const o = m.slice(1).map(Number)
  return o.every((x) => x <= 255) ? o : null
}

/**
 * Why an address or CIDR cannot be blocked, or null when it looks fine. Mirrors the
 * server's rules: IPv4 /8 or narrower, IPv6 /32 or narrower, and never loopback,
 * link-local, multicast, broadcast or unspecified addresses.
 */
export function blockProblem(input: string, minV4 = 8, minV6 = 32): string | null {
  const s = input.trim()
  if (!s) return 'Enter an IP address or CIDR'
  const [addr, bitsText, extra] = s.split('/')
  if (extra !== undefined || (bitsText !== undefined && !/^\d{1,3}$/.test(bitsText))) return 'Not an IP address or CIDR'
  const o = v4Octets(addr)
  if (o) {
    const bits = bitsText === undefined ? 32 : Number(bitsText)
    if (bits > 32) return 'Not an IP address or CIDR'
    if (bits < minV4) return `Too broad: IPv4 blocks are /${minV4} or narrower`
    if (o[0] === 127) return 'Loopback addresses are never blocked'
    if (o[0] === 0) return 'The unspecified network 0.0.0.0/8 is never blocked'
    if (o[0] === 169 && o[1] === 254) return 'Link-local addresses are never blocked'
    if (o[0] >= 224 && o[0] <= 239) return 'Multicast addresses are never blocked'
    if (o.every((x) => x === 255)) return 'The broadcast address is never blocked'
    return null
  }
  if (!/^[0-9a-f:.]+$/i.test(addr) || !addr.includes(':') || (addr.match(/::/g) ?? []).length > 1) return 'Not an IP address or CIDR'
  const bits = bitsText === undefined ? 128 : Number(bitsText)
  if (bits > 128) return 'Not an IP address or CIDR'
  if (bits < minV6) return `Too broad: IPv6 blocks are /${minV6} or narrower`
  const lower = addr.toLowerCase()
  if (lower === '::1') return 'Loopback addresses are never blocked'
  if (lower === '::') return 'The unspecified address is never blocked'
  if (/^fe[89ab][0-9a-f]?:/.test(lower)) return 'Link-local addresses are never blocked'
  if (/^ff[0-9a-f]{0,2}:/.test(lower)) return 'Multicast addresses are never blocked'
  return null
}

/** The note for a block made from an alert. */
export function alertBlockNote(a: { id: string; rule: { title: string }; hostname?: string }): string {
  const note = `Alert: ${a.rule.title}${a.hostname ? ` on ${a.hostname}` : ''} (${a.id})`
  return note.length > 300 ? note.slice(0, 297) + '...' : note
}
