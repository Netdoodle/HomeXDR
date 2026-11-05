// Mock offline lists, with one showing what a blocked download looks like.

import type { OfflineFacts, OfflineList } from '../api/lists'
import type { MockRoute } from './health'

const ago = (days: number) => new Date(Date.now() - days * 86400_000).toISOString()

const lists: OfflineList[] = [
  { id: 'tranco', name: 'Tranco popular sites', about: 'Ranks the top million sites, so an alert can say whether a domain is well known.', site_url: 'https://tranco-list.eu/', license: 'No licence of its own. Free to use, with credit to the Tranco project. It is built from five lists, some of them for non-commercial use only (CC BY-NC 4.0).', license_url: 'https://tranco-list.eu/', enabled: true, default_on: true, every_hours: 168, last_check: ago(1), last_update: ago(1), entries: 1000000, updating: false },
  { id: 'oui', name: 'MAC address vendors', about: 'Names the maker of a network card from the first half of its MAC address.', site_url: 'https://standards-oui.ieee.org/', license: 'IEEE’s public registry listing, free to download. If IEEE refuses the download, Wireshark’s copy of the same data is used instead.', license_url: 'https://standards.ieee.org/products-programs/regauth/', enabled: true, default_on: true, every_hours: 720, last_check: ago(9), last_update: ago(9), entries: 38221, updating: false },
  { id: 'iptoasn', name: 'IP networks', about: 'Names the network and country behind an IP address.', site_url: 'https://iptoasn.com/', license: 'Public domain (PDDL v1.0).', license_url: 'https://opendatacommons.org/licenses/pddl/1.0/', enabled: true, default_on: true, every_hours: 168, last_check: ago(3), last_update: ago(10), entries: 579453, error: 'Could not look up iptoasn.com. If your firewall or DNS blocklist blocks it, allow this host or turn this list off.', updating: false },
  { id: 'ut1', name: 'Website categories (UT1)', about: 'Sorts domains into categories such as advertising, VPN or file hosting.', site_url: 'https://dsi.ut-capitole.fr/blacklists/', warning: 'Its licence could not be read when this list was added, because the page was down. Check it yourself before turning this on.', license: 'From Université Toulouse Capitole. Terms not confirmed: see their page.', license_url: 'https://dsi.ut-capitole.fr/blacklists/', enabled: false, default_on: false, every_hours: 168, entries: 0, updating: false },
  { id: 'nrd', name: 'Newly registered domains', about: 'Flags domains registered in the last month. It is a sample of 10,000 a day, so a domain not on it may still be new.', site_url: 'https://github.com/WhoisFreaks/daily-newly-registered-domains', warning: 'The repository states no licence, so check that its terms suit you before turning this on.', license: 'WhoisFreaks’ free daily list. No licence stated.', license_url: 'https://github.com/WhoisFreaks/daily-newly-registered-domains', enabled: false, default_on: false, every_hours: 24, entries: 0, updating: false },
  { id: 'kev', name: 'Known exploited vulnerabilities (CISA)', about: 'The vulnerabilities CISA knows are being exploited, compared with the software your agents report.', site_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', license: 'U.S. government data from CISA, free to use.', license_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', enabled: true, default_on: true, every_hours: 24, last_check: ago(0.2), last_update: ago(0.2), entries: 1768, updating: false },
]

/** What the lists might know, for mock Investigate pages and alerts. */
export function offlineFacts(value: string): OfflineFacts | undefined {
  const v = value.trim().toLowerCase()
  if (/^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/.test(v)) {
    const first = parseInt(v.slice(0, 2), 16)
    return first & 2 ? { mac: { randomized: true } } : { mac: { vendor: 'Cisco Systems, Inc' } }
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v) || v.includes(':')) {
    if (/^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v)) return undefined
    return { ip: { asn: 64496, as_name: 'EXAMPLE-AS Example Networks', country: 'US' } }
  }
  if (/^https?:\/\//.test(v) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v)) {
    const host = v.replace(/^https?:\/\//, '').split('/')[0]
    const parts = host.split('.')
    const registered = parts.slice(-2).join('.')
    return { domain: { registered, ...(registered === 'example.com' ? { rank: 214 } : {}) } }
  }
  return undefined
}

export function registerListMocks(route: MockRoute) {
  route('GET', '/api/settings/lists', () => ({ lists }), { role: 'admin' })
  route(
    'PUT',
    '/api/settings/lists/:id',
    ({ params, body }) => {
      const l = lists.find((x) => x.id === params.id)
      if (l) l.enabled = (body as { enabled: boolean }).enabled
      return { lists }
    },
    { role: 'admin' },
  )
  route(
    'POST',
    '/api/settings/lists/:id/refresh',
    ({ params }) => {
      const l = lists.find((x) => x.id === params.id)
      if (l) {
        l.last_check = new Date().toISOString()
        l.last_update = l.last_check
        l.error = undefined
      }
      return { lists }
    },
    { role: 'admin' },
  )
  route('POST', '/api/lists/lookup', ({ body }) => {
    const results: Record<string, OfflineFacts> = {}
    for (const q of (body as { indicators: string[] }).indicators ?? []) {
      const f = offlineFacts(q)
      if (f) results[q] = f
    }
    return { results }
  })
}
