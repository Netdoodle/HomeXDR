// Mock threat intelligence: canned answers that arrive one by one, like the real services.

import type { Alert, Event, IndicatorKind, IntelLookupSummary, IntelProvider, IntelResult, IntelSettings, IntelSettingsUpdate, IntelSightings, IntelVerdict, IntelView } from '../api/types'

const PROVIDERS: IntelProvider[] = [
  { id: 'virustotal', name: 'VirusTotal', about: 'Verdicts from about 90 antivirus engines and URL scanners.', key_mode: 'required', key_url: 'https://www.virustotal.com/gui/my-apikey', free: '4 lookups a minute, 500 a day', kinds: ['ip', 'domain', 'url', 'hash'], enabled: true, key_set: false },
  { id: 'abuseipdb', name: 'AbuseIPDB', about: 'Community reports of abusive IP addresses.', key_mode: 'required', key_url: 'https://www.abuseipdb.com/account/api', free: '1,000 lookups a day', kinds: ['ip'], enabled: true, key_set: true, key_hint: '...a1b2' },
  { id: 'abusech', name: 'abuse.ch', about: 'URLhaus (malware URLs), MalwareBazaar (malware samples) and ThreatFox (IOCs), with one key.', key_mode: 'required', key_url: 'https://auth.abuse.ch/', free: 'Free key, fair use', kinds: ['ip', 'domain', 'url', 'hash'], enabled: true, key_set: false },
  { id: 'otx', name: 'AlienVault OTX', about: 'Community threat reports (pulses).', key_mode: 'optional', key_url: 'https://otx.alienvault.com/api', kinds: ['ip', 'domain', 'url', 'hash'], enabled: true, key_set: false },
  { id: 'greynoise', name: 'GreyNoise', about: 'Whether an IP scans the internet, and whether that looks malicious.', key_mode: 'optional', key_url: 'https://viz.greynoise.io/account/api-key', free: 'Limited lookups a day without a key', kinds: ['ip'], enabled: true, key_set: false },
  { id: 'internetdb', name: 'Shodan InternetDB', about: 'Open ports, hostnames and known CVEs.', key_mode: 'none', kinds: ['ip'], enabled: true, key_set: false },
  { id: 'ipwho', name: 'ipwho.is', about: 'Location and network of an IP.', key_mode: 'none', kinds: ['ip'], enabled: true, key_set: false },
  { id: 'rdap', name: 'WHOIS (RDAP)', about: 'Registration data for IP networks and domains.', key_mode: 'none', kinds: ['ip', 'domain'], enabled: true, key_set: false },
]

const settings: IntelSettings = { providers: PROVIDERS, cache_hours: 24, ai_access: true, internal_domains: [] }

export function getIntelSettings(): IntelSettings {
  return settings
}

export function putIntelSettings(u: IntelSettingsUpdate): IntelSettings {
  for (const p of settings.providers) {
    const c = u.providers?.[p.id]
    if (!c) continue
    if (c.enabled !== undefined) p.enabled = c.enabled
    if (c.key) {
      p.key_set = true
      p.key_hint = '...' + c.key.slice(-4)
    }
    if (c.clear_key) {
      p.key_set = false
      p.key_hint = undefined
    }
  }
  if (u.cache_hours) settings.cache_hours = u.cache_hours
  if (u.ai_access !== undefined) settings.ai_access = u.ai_access
  if (u.internal_domains) settings.internal_domains = u.internal_domains
  return settings
}

function parse(raw: string): IntelView['indicator'] | null {
  const v = raw.trim().replace(/\[\.\]/g, '.').replace(/^hxxp/i, 'http')
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]*:[0-9a-f:]*$/i.test(v)) return { value: v, kind: 'ip', private: /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fd)/i.test(v) }
  if (/^[0-9a-f]{32}$/i.test(v)) return { value: v.toLowerCase(), kind: 'hash', hash_type: 'md5', private: false }
  if (/^[0-9a-f]{40}$/i.test(v)) return { value: v.toLowerCase(), kind: 'hash', hash_type: 'sha1', private: false }
  if (/^[0-9a-f]{64}$/i.test(v)) return { value: v.toLowerCase(), kind: 'hash', hash_type: 'sha256', private: false }
  if (/^https?:\/\//i.test(v)) return { value: v, kind: 'url', private: /\.(local|lan)\b/.test(v) }
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return { value: v.toLowerCase(), kind: 'domain', private: /\.(local|lan|internal|home)$/i.test(v) }
  return null
}

interface Lookup {
  indicator: IntelView['indicator']
  results: IntelResult[]
  updated_at: string
  updated_by: string
  first_at: string
  lookups: number
}

const lookups = new Map<string, Lookup>()

const now = () => new Date().toISOString()

function answers(ind: IntelView['indicator'], hostile: boolean): IntelResult[] {
  const base = (source: string, name: string, extra: Partial<IntelResult>): IntelResult => ({ source, name, state: 'ok', checked_at: now(), ...extra })
  const kind = ind.kind
  const out: IntelResult[] = []
  const keyOf = (id: string) => PROVIDERS.find((p) => p.id === id)!
  const add = (id: string, r: IntelResult) => {
    const p = keyOf(id)
    if (!p.enabled) return
    if (p.key_mode === 'required' && !p.key_set) out.push({ source: r.source, name: r.name, state: 'needs_key', message: 'Add a free API key in Settings > Threat intel.', checked_at: '' })
    else out.push(r)
  }
  add('virustotal', base('virustotal', 'VirusTotal', {
    risk: hostile ? 75 : 10,
    headline: hostile ? '7 of 92 engines flag it' : '1 of 92 engines flag it',
    link: 'https://www.virustotal.com/gui/search/' + encodeURIComponent(ind.value),
    fields: [{ label: 'Malicious', value: hostile ? '4' : '1' }, { label: 'Suspicious', value: hostile ? '3' : '0' }, { label: 'Harmless', value: '53' }, { label: 'Undetected', value: hostile ? '32' : '38' }, { label: 'Last analysis', value: '2026-11-02' }],
  }))
  if (kind === 'ip') {
    add('abuseipdb', base('abuseipdb', 'AbuseIPDB', {
      risk: hostile ? 100 : 0,
      headline: hostile ? 'Abuse confidence 100%, 728 reports in 90 days' : 'Abuse confidence 0%, 437 reports in 90 days',
      link: 'https://www.abuseipdb.com/check/' + ind.value,
      fields: [{ label: 'Abuse confidence', value: hostile ? '100' : '0' }, { label: 'Reports', value: hostile ? '728' : '437' }, { label: 'Usage', value: hostile ? 'Data Center/Web Hosting' : 'Content Delivery Network' }, { label: 'Last reported', value: '2026-11-02' }],
      tags: hostile ? ['tor'] : [],
    }))
    add('greynoise', hostile ? base('greynoise', 'GreyNoise', { risk: 85, headline: 'Classified as malicious', fields: [{ label: 'Classification', value: 'malicious' }, { label: 'Last seen', value: '2026-11-03' }], tags: ['internet scanner'], link: 'https://viz.greynoise.io/ip/' + ind.value }) : { source: 'greynoise', name: 'GreyNoise', state: 'no_data', message: 'not observed scanning the internet', checked_at: now() })
    add('internetdb', base('internetdb', 'Shodan InternetDB', {
      headline: hostile ? '4 open ports, 2 known CVEs' : '2 open ports, 0 known CVEs',
      link: 'https://www.shodan.io/host/' + ind.value,
      fields: [{ label: 'Open ports', value: hostile ? '22, 80, 443, 9001' : '53, 443' }, { label: 'Hostnames', value: hostile ? 'tor-exit.example.net' : 'dns.google' }, ...(hostile ? [{ label: 'CVEs', value: 'CVE-2023-38408, CVE-2024-6387' }] : [])],
      tags: hostile ? ['tor', 'self-signed'] : ['pqc'],
    }))
    add('ipwho', base('ipwho', 'ipwho.is', { headline: hostile ? 'Berlin, Germany' : 'San Jose, United States', fields: [{ label: 'ASN', value: hostile ? 'AS60729' : 'AS15169' }, { label: 'Org', value: hostile ? 'Example Hosting' : 'Google LLC' }] }))
  }
  add('otx', hostile ? base('otx', 'AlienVault OTX', { risk: 60, headline: 'In 50 threat reports', fields: [{ label: 'Pulses', value: '50' }, { label: 'Last report', value: '2026-11-03' }, { label: 'Reports', value: 'Webscanners, Honeypot Data' }], tags: ['scanner', 'tor'], link: 'https://otx.alienvault.com/' }) : { source: 'otx', name: 'AlienVault OTX', state: 'no_data', message: 'no threat reports', checked_at: now() })
  if (kind === 'ip' || kind === 'domain') {
    add('rdap', base('rdap', 'WHOIS (RDAP)', { headline: hostile ? 'Example Hosting e.V.' : 'Google LLC GOGL', fields: [{ label: 'Created', value: '2021-08-19' }] }))
  }
  return out
}

export function startLookup(raw: string, refresh: boolean, user: string): IntelView | { error: string } {
  const ind = parse(raw)
  if (!ind) return { error: 'enter an IP address, domain, URL or file hash (MD5, SHA-1 or SHA-256)' }
  const cur = lookups.get(ind.value)
  if (cur && !refresh) return viewOf(cur)
  const hostile = /^185\.|evil|malware|^[0-9a-f]{32,64}$/i.test(ind.value)
  const final = ind.private ? [] : answers(ind, hostile)
  const l: Lookup = {
    indicator: ind,
    results: final.map((r) => (r.state === 'needs_key' ? r : { source: r.source, name: r.name, state: 'pending', checked_at: '' })),
    updated_at: now(),
    updated_by: user,
    first_at: cur?.first_at ?? now(),
    lookups: (cur?.lookups ?? 0) + 1,
  }
  lookups.set(ind.value, l)
  final.forEach((r, i) => {
    if (r.state === 'needs_key') return
    setTimeout(() => {
      l.results = l.results.map((x) => (x.source === r.source ? r : x))
      l.updated_at = now()
    }, 350 + i * 320)
  })
  return viewOf(l)
}

export function getLookup(raw: string): IntelView | null {
  const ind = parse(raw)
  const l = ind && lookups.get(ind.value)
  return l ? viewOf(l) : null
}

function viewOf(l: Lookup): IntelView {
  const rs = l.results
  const answered = rs.filter((r) => r.state === 'ok' && r.risk !== undefined)
  let score: number | undefined
  let verdict: IntelVerdict = 'unknown'
  let basis = 'No reputation source had data on it.'
  if (l.indicator.private) {
    verdict = 'internal'
    basis = 'Not sent to any external service.'
  } else if (answered.length) {
    const top = Math.max(...answered.map((r) => r.risk!))
    const avg = answered.reduce((a, r) => a + r.risk!, 0) / answered.length
    score = Math.round(0.6 * top + 0.4 * avg)
    verdict = score >= 75 ? 'malicious' : score >= 45 ? 'suspicious' : score >= 20 ? 'low' : 'clean'
    basis = `From ${answered.map((r) => r.name).join(', ')}.`
  }
  const v = l.indicator.value
  const brief = l.indicator.private
    ? [`${v} is a private address or internal name, so it was not sent to any external service. Only your own data is searched.`]
    : verdict === 'malicious'
      ? [`${v} looks malicious: ${answered.filter((r) => r.risk! >= 60).map((r) => r.name).join(', ')} report it.`, ...answered.filter((r) => r.risk! >= 40).map((r) => `${r.name}: ${r.headline}.`), 'Anonymizing service: TOR.']
      : verdict === 'unknown'
        ? [`No reputation source has data on ${v}. That does not make it safe: new or targeted infrastructure often has no history.`]
        : [`${v} shows no sign of malicious activity in ${answered.map((r) => r.name).join(', ')}.`]
  if (rs.some((r) => r.state === 'needs_key')) brief.push('For a firmer answer: VirusTotal and abuse.ch need a free API key (Settings > Threat intel).')
  const hostile = verdict === 'malicious' || verdict === 'suspicious'
  const geoReady = rs.some((r) => r.source === 'ipwho' && r.state === 'ok')
  const whoisReady = rs.some((r) => r.source === 'rdap' && r.state === 'ok')
  return {
    indicator: l.indicator,
    running: rs.some((r) => r.state === 'pending'),
    results: rs,
    updated_at: l.updated_at,
    updated_by: l.updated_by,
    lookups: l.lookups,
    summary: {
      score,
      verdict,
      basis,
      brief,
      geo: geoReady
        ? hostile
          ? { lat: 52.52, lon: 13.4, city: 'Berlin', region: 'Berlin', country: 'Germany', country_code: 'DE', asn: 'AS60729', org: 'Example Hosting', isp: 'Example ISP', timezone: 'Europe/Berlin' }
          : { lat: 37.34, lon: -121.89, city: 'San Jose', region: 'California', country: 'United States', country_code: 'US', asn: 'AS15169', org: 'Google LLC', isp: 'Google LLC', timezone: 'America/Los_Angeles' }
        : undefined,
      whois: whoisReady ? { registrant: hostile ? 'Example Hosting e.V.' : 'Google LLC', net_name: hostile ? 'EXAMPLE-NET' : 'GOGL', range: hostile ? '185.220.101.0 – 185.220.101.31' : '8.8.8.0 – 8.8.8.255', created: '2021-08-19', updated: '2025-06-18', abuse: 'abuse@example.net' } : undefined,
      coverage: {
        checked: rs.filter((r) => !['needs_key', 'pending'].includes(r.state)).length,
        with_data: rs.filter((r) => r.state === 'ok').length,
        no_data: rs.filter((r) => r.state === 'no_data').length,
        needs_key: rs.filter((r) => r.state === 'needs_key').length,
        failed: rs.filter((r) => r.state === 'error' || r.state === 'quota').length,
        pending: rs.filter((r) => r.state === 'pending').length,
      },
    },
  }
}

export function lookupHistory(): IntelLookupSummary[] {
  return [...lookups.values()]
    .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
    .map((l) => {
      const v = viewOf(l)
      return { indicator: l.indicator.value, kind: l.indicator.kind as IndicatorKind, score: v.summary.score, verdict: v.summary.verdict, first_at: l.first_at, updated_at: l.updated_at, updated_by: l.updated_by, lookups: l.lookups }
    })
}

/** Searches the mock events for the indicator as text. */
export function sightings(raw: string, days: number, events: Event[], alerts: Alert[]): IntelSightings | null {
  const ind = parse(raw)
  if (!ind) return null
  const needle = ind.value.toLowerCase()
  const since = Date.now() - days * 86400000
  const hits = events.filter((e) => Date.parse(e['@timestamp']) >= since && JSON.stringify(e).toLowerCase().includes(needle))
  const hosts = new Map<string, { id?: string; name: string; count: number; last?: string }>()
  const procs = new Map<string, number>()
  for (const e of hits) {
    const id = e.host.id ?? e.host.name ?? ''
    const h = hosts.get(id) ?? { id: e.host.id, name: e.host.name ?? id, count: 0 }
    h.count++
    hosts.set(id, h)
    if (e.process?.name) procs.set(e.process.name, (procs.get(e.process.name) ?? 0) + 1)
  }
  const times = hits.map((e) => e['@timestamp']).sort()
  const ids = new Set(hits.map((e) => e.id))
  return {
    query: `source.ip:"${ind.value}" OR destination.ip:"${ind.value}"`,
    days,
    events: hits.length,
    first: times[0],
    last: times[times.length - 1],
    hosts: [...hosts.values()].sort((a, b) => b.count - a.count).slice(0, 10),
    processes: [...procs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count })),
    recent: hits.slice(0, 5),
    alerts: alerts.filter((a) => a.event_ids?.some((id) => ids.has(id))).slice(0, 10),
    own_hosts: [],
  }
}
