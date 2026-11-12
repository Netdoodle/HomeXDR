// Mock threat map data.

import type { InboundView } from '../api/inbound'
import type { Role } from '../api/types'

type Ctx = { params: Record<string, string>; body: unknown; query?: URLSearchParams }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const COUNTRIES: [string, number, number, number][] = [
  ['US', 18200, 1210, 3], ['CN', 9400, 640, 0], ['NL', 7100, 220, 0], ['RU', 5200, 380, 0], ['DE', 3900, 190, 0],
  ['BR', 2600, 410, 0], ['IN', 2200, 300, 0], ['GB', 1900, 120, 0], ['SG', 1500, 60, 0], ['KR', 1300, 150, 0],
  ['VN', 1100, 170, 0], ['FR', 900, 80, 0], ['BG', 800, 20, 0], ['HK', 700, 45, 0], ['JP', 520, 40, 0],
  ['ZA', 300, 30, 0], ['AU', 260, 22, 0], ['IR', 240, 35, 0], ['TR', 200, 28, 0], ['AR', 120, 18, 0],
]

function view(hours: number): InboundView {
  const f = Math.max(hours / 24, 0.05)
  const countries = COUNTRIES.map(([code, a, s, allowed], i) => ({ code, attempts: Math.round(a * f), sources: Math.max(1, Math.round(s * Math.min(f, 3))), allowed, last: new Date(Date.now() - i * 45_000).toISOString() }))
  const attempts = countries.reduce((n, c) => n + c.attempts, 0)
  const now = Date.now()
  const span = hours <= 1 ? 300 : hours <= 48 ? 3600 : hours <= 168 ? 21600 : 86400
  const buckets = Math.min(60, Math.ceil((hours * 3600) / span))
  return {
    hours, span_sec: span, attempts, allowed: 3, blocked: attempts - 3, sources: countries.reduce((n, c) => n + c.sources, 0), countries,
    top_sources: [
      { ip: '45.141.233.145', country: 'NL', asn: 51396, as_name: 'PFCLOUD', attempts: Math.round(4200 * f), allowed: 0, ports: 1840, first: new Date(now - hours * 3600e3).toISOString(), last: new Date(now - 60e3).toISOString() },
      { ip: '167.94.138.44', country: 'US', asn: 398705, as_name: 'CENSYS-ARIN-01', attempts: Math.round(2100 * f), allowed: 0, ports: 960, first: new Date(now - hours * 3600e3).toISOString(), last: new Date(now - 300e3).toISOString() },
      { ip: '218.92.0.112', country: 'CN', asn: 4134, as_name: 'CHINANET-BACKBONE', attempts: Math.round(1500 * f), allowed: 0, ports: 3, first: new Date(now - hours * 3600e3).toISOString(), last: new Date(now - 900e3).toISOString() },
      { ip: '80.82.77.139', country: 'NL', asn: 202425, as_name: 'INT-NETWORK', attempts: Math.round(900 * f), allowed: 0, ports: 410, first: new Date(now - hours * 3600e3).toISOString(), last: new Date(now - 1200e3).toISOString() },
    ],
    allowed_sources: [
      { ip: '104.28.212.9', country: 'US', asn: 13335, as_name: 'CLOUDFLARENET', attempts: 3, allowed: 3, ports: 1, first: new Date(now - 7200e3).toISOString(), last: new Date(now - 600e3).toISOString() },
    ],
    networks: [
      { asn: 51396, name: 'PFCLOUD', country: 'NL', attempts: Math.round(5200 * f), sources: 40 },
      { asn: 4134, name: 'CHINANET-BACKBONE', country: 'CN', attempts: Math.round(4300 * f), sources: 220 },
      { asn: 398705, name: 'CENSYS-ARIN-01', country: 'US', attempts: Math.round(3100 * f), sources: 70 },
      { asn: 14061, name: 'DIGITALOCEAN-ASN', country: 'US', attempts: Math.round(2500 * f), sources: 180 },
    ],
    ports: [
      { port: 22, transport: 'tcp', attempts: Math.round(9800 * f), sources: 900 },
      { port: 23, transport: 'tcp', attempts: Math.round(6200 * f), sources: 700 },
      { port: 445, transport: 'tcp', attempts: Math.round(4100 * f), sources: 300 },
      { port: 3389, transport: 'tcp', attempts: Math.round(3500 * f), sources: 260 },
      { port: 80, transport: 'tcp', attempts: Math.round(2900 * f), sources: 410 },
      { port: 8080, transport: 'tcp', attempts: Math.round(1800 * f), sources: 220 },
    ],
    timeline: Array.from({ length: buckets }, (_, i) => ({
      t: new Date(now - (buckets - i) * span * 1000).toISOString(),
      blocked: Math.round((attempts / buckets) * (0.7 + 0.6 * Math.abs(Math.sin(i / 3)))),
      allowed: 0,
      sources: Math.round(60 + 40 * Math.abs(Math.cos(i / 4))),
    })),
    home_country: 'US',
    prev_attempts: Math.round(attempts * 1.16),
    prev_blocked: Math.round((attempts - 3) * 1.16),
    prev_sources: Math.round(countries.reduce((n, c) => n + c.sources, 0) * 0.93),
  }
}

export function inboundRoutes(route: Route) {
  route('GET', '/api/stats/inbound/ids', ({ query }) => {
    const hours = Number(query?.get('hours') ?? 24) || 24
    const buckets = 24
    const now = Date.now()
    const spark = (seed: number) => Array.from({ length: buckets }, (_, i) => Math.max(0, Math.round(seed * (0.4 + Math.abs(Math.sin(i / 2 + seed))))))
    const cats = ['Misc Attack', 'Attempted Information Leak', 'Potentially Bad Traffic', 'Attempted Administrator Privilege Gain', 'Web Application Attack']
    return {
      hours,
      span_sec: 3600,
      buckets: Array.from({ length: buckets }, (_, i) => new Date(now - (buckets - i) * 3600e3).toISOString()),
      total: 1420,
      categories: cats,
      threats: [
        { name: 'ET CINS Active Threat Intelligence Poor Reputation IP', category: 'Misc Attack', severity: 'medium', count: 812, sources: 640, countries: 41, top_country: 'US', spark: spark(30) },
        { name: 'ET SCAN Suspicious inbound to MSSQL port 1433', category: 'Potentially Bad Traffic', severity: 'medium', count: 231, sources: 88, countries: 19, top_country: 'CN', spark: spark(9) },
        { name: 'ET SCAN NMAP -sS window 1024', category: 'Attempted Information Leak', severity: 'medium', count: 184, sources: 52, countries: 14, top_country: 'NL', spark: spark(7) },
        { name: 'ET EXPLOIT Possible Hikvision Command Injection', category: 'Attempted Administrator Privilege Gain', severity: 'high', count: 116, sources: 12, countries: 5, top_country: 'RU', spark: spark(4) },
        { name: 'ET WEB_SERVER WebShell Generic - wget http - POST', category: 'Web Application Attack', severity: 'high', count: 77, sources: 9, countries: 4, top_country: 'BG', spark: spark(3) },
      ],
      countries: [
        { code: 'US', total: 420, sources: 260, max_severity: 'medium', by_category: { 'Misc Attack': 310, 'Attempted Information Leak': 60, 'Potentially Bad Traffic': 50 } },
        { code: 'CN', total: 300, sources: 150, max_severity: 'high', by_category: { 'Potentially Bad Traffic': 120, 'Misc Attack': 140, 'Attempted Administrator Privilege Gain': 40 } },
        { code: 'NL', total: 210, sources: 70, max_severity: 'medium', by_category: { 'Attempted Information Leak': 90, 'Misc Attack': 100, 'Web Application Attack': 20 } },
        { code: 'RU', total: 150, sources: 40, max_severity: 'high', by_category: { 'Attempted Administrator Privilege Gain': 60, 'Misc Attack': 90 } },
        { code: 'BR', total: 90, sources: 35, max_severity: 'low', by_category: { 'Misc Attack': 90 } },
        { code: 'BG', total: 60, sources: 9, max_severity: 'high', by_category: { 'Web Application Attack': 50, 'Misc Attack': 10 } },
      ],
    }
  })
  route('GET', '/api/stats/inbound', ({ query }) => view(Number(query?.get('hours') ?? 24) || 24))
  route('GET', '/api/stats/inbound/events', ({ query }) => {
    const kind = query?.get('kind') ?? 'all'
    const country = query?.get('country') ?? ''
    const ips = country === 'US' ? ['104.28.212.9', '167.94.138.44'] : ['45.141.233.145', '80.82.77.139']
    const n = kind === 'allowed' ? (country === 'US' ? 3 : 0) : 12
    const events = Array.from({ length: n }, (_, i) => ({
      id: `mock-fw-${country}-${kind}-${i}`,
      '@timestamp': new Date(Date.now() - i * 97_000).toISOString(),
      event: { module: 'opnsense', dataset: 'opnsense.filterlog', action: kind === 'allowed' ? 'rdr' : 'block', category: ['network'] },
      host: { id: 'fw', name: 'OPNsense.home.example' },
      source: { ip: ips[i % 2], port: 40000 + i },
      destination: { ip: '203.0.113.86', port: kind === 'allowed' ? 443 : [22, 23, 3389][i % 3] },
      network: { direction: 'inbound', transport: 'tcp' },
      message: `${kind === 'allowed' ? 'rdr' : 'block'} tcp ${ips[i % 2]} -> 203.0.113.86`,
    }))
    return {
      events,
      total: n,
      sources: n ? 2 : 0,
      query: n ? `event.dataset:opnsense.filterlog network.direction:inbound (source.ip:${ips[0]} OR source.ip:${ips[1]})` : undefined,
    }
  })
}
