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
  text: string
}

export const defaultFilters: VulnFilters = { status: 'open', band: '', host: '', exposure: '', kevOnly: false, hasFix: false, text: '' }

export function filterFindings(list: VulnFinding[], f: VulnFilters): VulnFinding[] {
  const terms = f.text.toLowerCase().split(/\s+/).filter(Boolean)
  return list.filter((x) => {
    if (f.status !== 'all' && x.status !== f.status) return false
    if (f.band && x.band !== f.band) return false
    if (f.host && x.host_id !== f.host) return false
    if (f.exposure && x.exposure !== f.exposure) return false
    if (f.kevOnly && !x.kev) return false
    if (f.hasFix && !x.fixed_version) return false
    if (terms.length) {
      const hay = `${x.cve} ${x.package} ${x.hostname} ${x.title}`.toLowerCase()
      if (!terms.every((t) => hay.includes(t))) return false
    }
    return true
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
