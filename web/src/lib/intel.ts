// Investigate: recognizing indicators in events, and labels for lookups.

import type { Event, IntelResult, IntelState, IntelVerdict, IndicatorKind } from '../api/types'
import { WORLD_LAT_BOTTOM, WORLD_LAT_TOP, WORLD_ROWS } from './worldMask'

export const VERDICT_LABEL: Record<IntelVerdict, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  low: 'Low risk',
  clean: 'Clean',
  no_signal: 'No known signal',
  unknown: 'Unknown',
  internal: 'Internal',
}

export const KIND_LABEL: Record<IndicatorKind, string> = { ip: 'IP address', domain: 'Domain', url: 'URL', hash: 'File hash' }

export const STATE_LABEL: Record<IntelState, string> = {
  ok: 'Has data',
  no_data: 'No data',
  needs_key: 'Needs an API key',
  quota: 'Over quota',
  error: 'Failed',
  pending: 'Checking…',
}

export const CACHE_CHOICES: { hours: number; label: string }[] = [
  { hours: 1, label: '1 hour' },
  { hours: 6, label: '6 hours' },
  { hours: 24, label: '1 day' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '1 week' },
]

export const SIGHTING_WINDOWS = [7, 30, 90, 365]

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const IPV6 = /^[0-9a-f:]*:[0-9a-f:.]*$/i
const DOMAIN = /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$/i
const HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i
const URL_RE = /^https?:\/\//i

/** Which fields of an event hold what, so a file name is not offered as a domain. */
const DOMAIN_FIELD = /(^|\.)(domain|host|hostname|server_name|question\.name|registered_domain|name)$/
const IP_FIELD = /(^|[._])(ip|ips|resolved_ip|address|ipaddress)$/i
const HASH_FIELD = /(^|\.)(hash\.)?(md5|sha1|sha256)$/
const SKIP_FIELD = /^(id|host\.|event\.|observer\.|process\.(name|executable|command_line)|user\.|file\.(name|path)|agent\.|rule\.)/

/** The indicator in an event field's value, if it holds one worth investigating. */
export function indicatorInField(path: string, value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null
  const v = value.trim()
  if (!v) return null
  if (HASH_FIELD.test(path)) return HASH.test(v) ? v : null
  if (SKIP_FIELD.test(path)) return null
  if (IPV4.test(v) || (IP_FIELD.test(path) && IPV6.test(v))) return v
  if (URL_RE.test(v)) return v
  if (DOMAIN_FIELD.test(path) && DOMAIN.test(v)) return v
  return null
}

export function investigateHref(indicator: string): string {
  return `/investigate?q=${encodeURIComponent(indicator)}`
}

/** Sources with data, the most concerning first; those without a risk (context) last. */
export function sortedResults(results: IntelResult[]): IntelResult[] {
  const rank = (r: IntelResult) => (r.risk === undefined ? -1 : r.risk)
  return results.filter((r) => r.state === 'ok').sort((a, b) => rank(b) - rank(a))
}

/** "Checked 12 sources: 7 with data, 3 with nothing, 1 failed. 3 need a key." */
export function coverageLine(c: { checked: number; with_data: number; no_data: number; failed: number; needs_key: number; pending: number }): string {
  const parts = [`${c.with_data} with data`, `${c.no_data} with nothing`]
  if (c.failed) parts.push(`${c.failed} failed`)
  let s = `Checked ${c.checked} ${c.checked === 1 ? 'source' : 'sources'}: ${parts.join(', ')}.`
  if (c.pending) s = `Checking ${c.pending} more… ` + s
  if (c.needs_key) s += ` ${c.needs_key} more ${c.needs_key === 1 ? 'needs' : 'need'} an API key.`
  return s
}

/** The land dots as one SVG path (a zero-length line per dot, drawn with round caps). */
export function worldDotsPath(): { path: string; width: number; height: number } {
  const height = WORLD_ROWS.length
  const width = WORLD_ROWS[0].length
  let path = ''
  WORLD_ROWS.forEach((row, y) => {
    for (let x = 0; x < width; x++) if (row[x] === '#') path += `M${x + 0.5} ${y + 0.5}h0`
  })
  return { path, width, height }
}

/** Where a coordinate falls on the map, in the same units as worldDotsPath. */
export function worldPoint(lat: number, lon: number): { x: number; y: number } {
  const height = WORLD_ROWS.length
  const width = WORLD_ROWS[0].length
  const clamped = Math.min(WORLD_LAT_TOP, Math.max(WORLD_LAT_BOTTOM, lat))
  return { x: ((lon + 180) / 360) * width, y: ((WORLD_LAT_TOP - clamped) / (WORLD_LAT_TOP - WORLD_LAT_BOTTOM)) * height }
}

export function flagEmoji(code?: string): string {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return ''
  const base = 0x1f1e6 - 65
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => c.charCodeAt(0) + base))
}

const PRIVATE_IP = /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.|::1$|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i

/** The indicators worth investigating in an event: public addresses, domains and hashes. */
/** Something in an event that the Investigate page can look up. */
export interface InvestigateTarget {
  label: string
  value: string
  /** A private address: only your own data is searched, nothing is sent out. */
  local?: boolean
  /** An IP address (it can be blocked in the hosts' firewalls). */
  ip?: boolean
}

const HASH_VALUE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i

/**
 * Everything in an event worth investigating: its addresses (private ones too, which are
 * searched in your own data only), domains, URL, file hashes and the host's own address.
 */
export function investigateTargets(e?: Event): InvestigateTarget[] {
  if (!e) return []
  const out: InvestigateTarget[] = []
  const add = (label: string, value?: string | null, local?: boolean, isIP?: boolean) => {
    const v = value?.trim()
    if (v && !out.some((x) => x.value === v)) out.push(isIP ? { label, value: v, local, ip: true } : { label, value: v, local })
  }
  const ip = (label: string, value?: string) => {
    if (value && (IPV4.test(value) || IPV6.test(value))) add(label, value, PRIVATE_IP.test(value), true)
  }
  const hashes = (what: string, h?: { md5?: string; sha1?: string; sha256?: string }) => {
    if (!h) return
    for (const k of ['sha256', 'sha1', 'md5'] as const) {
      if (h[k] && HASH_VALUE.test(h[k]!)) add(`${what} ${k.toUpperCase().replace('SHA', 'SHA-')}`, h[k])
    }
  }
  ip('Source', e.source?.ip)
  ip('Destination', e.destination?.ip)
  add('Domain', e.destination?.domain)
  add('DNS query', e.dns?.question?.name)
  if (e.http?.url && /^https?:\/\//i.test(e.http.url)) add('URL', e.http.url)
  hashes('Process', e.process?.hash)
  hashes('Parent process', e.process?.parent?.hash)
  hashes('File', e.file?.hash)
  const hostIP = (e.host?.ip ?? []).find((a) => IPV4.test(a) && !a.startsWith('127.') && !a.startsWith('172.17.'))
  if (hostIP) add(`Host ${e.host?.name ?? ''}`.trim(), hostIP, PRIVATE_IP.test(hostIP))
  return out
}

export function eventIndicators(e?: Event): { label: string; value: string }[] {
  if (!e) return []
  const out: { label: string; value: string }[] = []
  const add = (label: string, value?: string) => {
    if (value && !out.some((x) => x.value === value)) out.push({ label, value })
  }
  const ip = (label: string, value?: string) => {
    if (value && !PRIVATE_IP.test(value)) add(label, value)
  }
  ip('Source IP', e.source?.ip)
  ip('Destination IP', e.destination?.ip)
  add('Domain', e.destination?.domain)
  add('DNS query', e.dns?.question?.name)
  add('Process SHA-256', e.process?.hash?.sha256)
  add('File SHA-256', e.file?.hash?.sha256)
  return out
}
