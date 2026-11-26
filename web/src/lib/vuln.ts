// Vulnerability management: pure helpers for the page.

import type { VulnBand, VulnFinding, VulnHistoryPoint, VulnHost, VulnSource, VulnStatus, Exposure } from '../api/vuln'

export const BANDS: VulnBand[] = ['critical', 'high', 'medium', 'low']
export const BAND_LABEL: Record<VulnBand, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

/** Band for a 0..10 risk score. */
export function bandFor(risk: number): VulnBand {
  return risk >= 8 ? 'critical' : risk >= 6 ? 'high' : risk >= 3 ? 'medium' : 'low'
}

/** A Docker image is labelled as one, so it is not mistaken for a package. */
export function packageLabel(m: Pick<VulnFinding, 'package' | 'package_type'>): string {
  if (m.package_type === 'docker') return `${m.package} (Docker image)`
  if (m.package_type === 'os') return `${m.package} (operating system)`
  return m.package
}

/** "CVSS 9.8 × likelihood 3.0 ÷ 10 = risk 2.9" */
export function scoreText(f: Pick<VulnFinding, 'cvss' | 'likelihood' | 'risk'>): string {
  const cvss = f.cvss === null ? 'unknown' : f.cvss.toFixed(1)
  if (f.cvss === null) return `CVSS unknown (estimated) × likelihood ${f.likelihood.toFixed(1)} ÷ 10 = risk ${f.risk.toFixed(1)}`
  return `CVSS ${cvss} × likelihood ${f.likelihood.toFixed(1)} ÷ 10 = risk ${f.risk.toFixed(1)}`
}

export function epssText(epss: number | null): string {
  if (epss === null) return '—'
  const p = epss * 100
  return p > 0 && p < 0.1 ? '<0.1%' : `${p < 10 ? p.toFixed(1) : Math.round(p)}%`
}

export type SortKey = 'risk' | 'cvss' | 'likelihood' | 'epss' | 'first_seen' | 'host'
export type SortDir = 'asc' | 'desc'

const sortValue = (f: VulnFinding, k: SortKey): number | string => {
  switch (k) {
    case 'risk': return f.risk
    case 'cvss': return f.cvss ?? -1
    case 'likelihood': return f.likelihood
    case 'epss': return f.epss ?? -1
    case 'first_seen': return Date.parse(f.first_seen) || 0
    case 'host': return f.hostname.toLowerCase()
  }
}

/** Sorted copy. Ties fall back to risk (high first), then CVE, so the order is stable. */
export function sortFindings(list: VulnFinding[], key: SortKey, dir: SortDir): VulnFinding[] {
  const m = dir === 'asc' ? 1 : -1
  return [...list].sort((a, b) => {
    const x = sortValue(a, key)
    const y = sortValue(b, key)
    if (x < y) return -m
    if (x > y) return m
    return b.risk - a.risk || a.cve.localeCompare(b.cve) || a.id.localeCompare(b.id)
  })
}

export interface VulnFilters {
  status: VulnStatus | 'all'
  band: VulnBand | ''
  host: string // host_id or ''
  exposure: Exposure | ''
  kevOnly: boolean
  hasFix: boolean
  /** only findings with no patched version released */
  noFix: boolean
  /** first seen (new7d) or fixed (fixed7d) in the last 7 days */
  since: '' | 'new7d' | 'fixed7d'
  /** the search box: words, "phrases", field:value and numeric comparisons (see parseVulnQuery) */
  text: string
}

export const defaultFilters: VulnFilters = { status: 'open', band: '', host: '', exposure: '', kevOnly: false, hasFix: false, noFix: false, since: '', text: '' }

/** The summary tiles, each a shortcut to the filters that list exactly what it counts. */
export type TileKey = 'open' | 'critical' | 'high' | 'internet' | 'kev' | 'nofix' | 'new7d' | 'fixed7d'

export function tileFilters(k: TileKey): VulnFilters {
  const open = { ...defaultFilters, status: 'open' as const }
  switch (k) {
    case 'open': return open
    case 'critical': return { ...open, band: 'critical' }
    case 'high': return { ...open, band: 'high' }
    case 'internet': return { ...open, exposure: 'internet' }
    case 'kev': return { ...open, kevOnly: true }
    case 'nofix': return { ...open, noFix: true }
    case 'new7d': return { ...defaultFilters, status: 'all', since: 'new7d' }
    case 'fixed7d': return { ...defaultFilters, status: 'all', since: 'fixed7d' }
  }
}

/** Which tile the filters stand for, if any (the search text is ignored). */
export function activeTile(f: VulnFilters): TileKey | null {
  const keys: TileKey[] = ['critical', 'high', 'internet', 'kev', 'nofix', 'new7d', 'fixed7d', 'open']
  return keys.find((k) => {
    const t = tileFilters(k)
    return (Object.keys(t) as (keyof VulnFilters)[]).every((x) => x === 'text' || t[x] === f[x])
  }) ?? null
}

type NumField = 'cvss' | 'risk' | 'epss' | 'likelihood'
type TextField = 'cve' | 'host' | 'app' | 'os' | 'title' | 'type'
type Op = '>' | '>=' | '<' | '<=' | '='

export interface VulnQuery {
  /** plain words and phrases, matched anywhere (all must match) */
  terms: string[]
  /** words and phrases that must not match */
  not: string[]
  fields: { field: TextField; value: string }[]
  nums: { field: NumField; op: Op; value: number; /** "cvss:9" matches 9.0 to 9.9 */ whole: boolean }[]
}

const NUM_FIELDS: Record<string, NumField> = { cvss: 'cvss', score: 'cvss', risk: 'risk', epss: 'epss', likelihood: 'likelihood' }
const TEXT_FIELDS: Record<string, TextField> = {
  cve: 'cve', host: 'host', hostname: 'host', app: 'app', pkg: 'app', package: 'app', software: 'app', os: 'os', title: 'title', type: 'type',
}

/**
 * Parses the findings search: plain words and "quoted phrases" match the CVE, software, version,
 * host, OS, title and summary; -word excludes; field:value narrows to one field (cve, host, app
 * or pkg, os, title, type); cvss, risk, epss and likelihood take >, >=, <, <=, = or : with a
 * number (epss as 0.5 or 50%).
 */
export function parseVulnQuery(text: string): VulnQuery {
  const q: VulnQuery = { terms: [], not: [], fields: [], nums: [] }
  const unquote = (v: string) => v.replace(/^"(.*)"?$/, '$1').replace(/"$/, '').toLowerCase()
  for (const m of text.matchAll(/(-?)([a-z]+)(>=|<=|>|<|=|:)("[^"]*"?|\S+)|(-?)("[^"]*"?|\S+)/gi)) {
    if (m[2] !== undefined) {
      const name = m[2].toLowerCase()
      const raw = unquote(m[4])
      const num = NUM_FIELDS[name]
      if (num && !m[1]) {
        const pct = raw.endsWith('%')
        let n = Number(pct ? raw.slice(0, -1) : raw)
        if (Number.isFinite(n) && raw !== '') {
          if (num === 'epss' && (pct || n > 1)) n /= 100
          const op = (m[3] === ':' ? '=' : m[3]) as Op
          q.nums.push({ field: num, op, value: n, whole: op === '=' && !raw.includes('.') && num !== 'epss' })
          continue
        }
      }
      const tf = TEXT_FIELDS[name]
      if (tf && (m[3] === ':' || m[3] === '=') && raw) {
        if (m[1]) q.not.push(raw)
        else q.fields.push({ field: tf, value: raw })
        continue
      }
      // Not a known field: search for the text as typed.
      const whole = (m[2] + m[3] + raw).toLowerCase()
      ;(m[1] ? q.not : q.terms).push(whole)
      continue
    }
    const v = unquote(m[6])
    if (!v) continue
    if (m[5] && v) q.not.push(v)
    else q.terms.push(v)
  }
  return q
}

function numValue(x: VulnFinding, f: NumField): number | null {
  return f === 'cvss' ? x.cvss : f === 'epss' ? x.epss : f === 'risk' ? x.risk : x.likelihood
}

function fieldText(x: VulnFinding, f: TextField, os: string): string {
  switch (f) {
    case 'cve': return x.cve
    case 'host': return x.hostname
    case 'app': return `${x.package} ${x.source_package}`
    case 'os': return os
    case 'title': return `${x.title} ${x.summary}`
    case 'type': return `${x.package_type} ${x.package_type === 'os' ? 'operating system' : ''}`
  }
}

/** Whether a finding matches a parsed search. hostOS is the host's OS ("Debian 12"). */
export function matchesQuery(x: VulnFinding, q: VulnQuery, hostOS = ''): boolean {
  for (const n of q.nums) {
    const v = numValue(x, n.field)
    if (v === null) return false
    const r = Math.round(v * 1000) / 1000
    const ok = n.op === '>' ? r > n.value : n.op === '>=' ? r >= n.value : n.op === '<' ? r < n.value : n.op === '<=' ? r <= n.value
      : n.whole ? r >= n.value && r < n.value + 1 : Math.abs(r - n.value) < 0.05
    if (!ok) return false
  }
  for (const f of q.fields) {
    if (!fieldText(x, f.field, hostOS).toLowerCase().includes(f.value)) return false
  }
  if (q.terms.length || q.not.length) {
    const hay = [x.cve, x.package, x.source_package, x.version, x.fixed_version, x.package_type, x.hostname, hostOS, x.title, x.summary].join(' ').toLowerCase()
    if (!q.terms.every((t) => hay.includes(t))) return false
    if (q.not.some((t) => hay.includes(t))) return false
  }
  return true
}

export function filterFindings(list: VulnFinding[], f: VulnFilters, opts: { now?: number; hostOS?: Record<string, string> } = {}): VulnFinding[] {
  const q = parseVulnQuery(f.text)
  const week = (opts.now ?? Date.now()) - 7 * 86400_000
  return list.filter((x) => {
    if (f.status !== 'all' && x.status !== f.status) return false
    if (f.band && x.band !== f.band) return false
    if (f.host && x.host_id !== f.host) return false
    if (f.exposure && x.exposure !== f.exposure) return false
    if (f.kevOnly && !x.kev) return false
    if (f.hasFix && !x.fixed_version) return false
    if (f.noFix && x.fixed_version) return false
    if (f.since === 'new7d' && !(Date.parse(x.first_seen) > week)) return false
    if (f.since === 'fixed7d' && !(x.fixed_at && Date.parse(x.fixed_at) > week)) return false
    return matchesQuery(x, q, opts.hostOS?.[x.host_id] ?? '')
  })
}

/** Open critical/high findings first seen within `days`, newest first. */
export function newFindings(list: VulnFinding[], now: number = Date.now(), days = 7): VulnFinding[] {
  const cutoff = now - days * 86400_000
  return list
    .filter((f) => f.status === 'open' && (f.band === 'critical' || f.band === 'high') && Date.parse(f.first_seen) >= cutoff)
    .sort((a, b) => Date.parse(b.first_seen) - Date.parse(a.first_seen) || b.risk - a.risk)
}

export interface WeekPoint { week: string; new: number; fixed: number }

/** Daily history summed into calendar weeks starting Monday (UTC). `week` is the Monday's date. */
export function weeklyHistory(h: VulnHistoryPoint[]): WeekPoint[] {
  const weeks = new Map<string, WeekPoint>()
  for (const p of h) {
    const d = new Date(`${p.date}T00:00:00Z`)
    if (Number.isNaN(d.getTime())) continue
    const back = (d.getUTCDay() + 6) % 7
    const key = new Date(d.getTime() - back * 86400_000).toISOString().slice(0, 10)
    const w = weeks.get(key) ?? { week: key, new: 0, fixed: 0 }
    w.new += p.new
    w.fixed += p.fixed
    weeks.set(key, w)
  }
  return [...weeks.values()].sort((a, b) => a.week.localeCompare(b.week))
}

/** Hosts with open findings, worst first (max risk, then open count). */
export function hostsByRisk(hosts: VulnHost[]): VulnHost[] {
  return hosts.filter((h) => h.open > 0).sort((a, b) => b.max_risk - a.max_risk || b.open - a.open || a.hostname.localeCompare(b.hostname))
}

export function exposureCounts(list: VulnFinding[]): { internet: number; lan: number } {
  let internet = 0
  let lan = 0
  for (const f of list) {
    if (f.status !== 'open') continue
    if (f.exposure === 'internet') internet++
    else lan++
  }
  return { internet, lan }
}

export function coverageText(c: VulnHost['coverage']): string {
  if (c === 'full') return 'Full: distro advisories cover this host’s packages.'
  if (c === 'kev_only') return 'Only CISA’s known-exploited list applies; no distro advisories exist for this package type.'
  return 'None: no software list yet, so nothing can be checked.'
}

/** Plain sentences about sources that are off, empty or failing. Empty when all is well. */
export function sourceProblems(sources: VulnSource[], hosts: VulnHost[]): string[] {
  const out: string[] = []
  for (const s of sources) {
    if (!s.enabled) out.push(`${s.name} is turned off. Turn it on under Settings → Offline lists.`)
    else if (s.error) out.push(`${s.name} could not be updated: ${s.error}`)
    else if (!s.entries) out.push(`${s.name} has not been downloaded yet. It downloads by itself within a few minutes of the server starting.`)
  }
  if (hosts.length === 0) out.push('No agents are enrolled. Software lists come from endpoint agents.')
  for (const h of hosts) {
    if (h.packages > 0) continue
    out.push(
      h.note
        ? `${h.hostname} has sent no software list. The agent says: ${h.note}`
        : `${h.hostname} has sent no software list. The agent sends one every few hours; if it never does, update the agent.`,
    )
  }
  return out
}
