// Offline lists: turning facts into short phrases.

import type { OfflineFacts } from '../api/lists'

/** Short phrases for what the lists know. Empty when they know nothing worth saying. */
export function factPhrases(f?: OfflineFacts | null): string[] {
  const out: string[] = []
  if (!f) return out
  if (f.domain) {
    const d = f.domain
    if (d.rank) out.push(`Popular site, rank ${d.rank.toLocaleString('en-US')}`)
    if (d.category) out.push(`Category: ${d.category}`)
    if (d.newly_registered) out.push('Newly registered')
    if (d.registered) out.push(`Registered domain ${d.registered}`)
  }
  if (f.ip) {
    const i = f.ip
    if (i.asn) out.push(`AS${i.asn}${i.as_name ? ` ${i.as_name}` : ''}`)
    if (i.country) out.push(i.country)
  }
  if (f.mac) {
    if (f.mac.randomized) out.push('Randomized MAC address, as phones use for privacy')
    if (f.mac.vendor) out.push(`Made by ${f.mac.vendor}`)
  }
  return out
}
