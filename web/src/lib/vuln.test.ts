import { describe, expect, it } from 'vitest'
import type { VulnFinding, VulnHost } from '../api/vuln'
import {
  bandFor, defaultFilters, epssText, exposureCounts, filterFindings, hostsByRisk, newFindings, packageLabel, scoreText, sortFindings, sourceProblems, weeklyHistory,
} from './vuln'

const NOW = Date.parse('2026-11-25T12:00:00Z')
const day = (n: number) => new Date(NOW - n * 86400_000).toISOString()
const f = (o: Partial<VulnFinding>): VulnFinding => ({
  id: 'h|p|CVE-1', host_id: 'h', hostname: 'tower', package: 'p', source_package: 'p', version: '1', package_type: 'deb', cve: 'CVE-1', title: 't', summary: '', fixed_version: '1.1',
  cvss: 7, cvss_vector: '', severity_source: 'nvd', epss: 0.1, epss_percentile: 0.5, kev: false, kev_due_date: '', ransomware: false, exposure: 'lan', exposed_ports: [], attack_vector: 'network',
  likelihood: 5, risk: 3.5, band: 'medium', likelihood_reasons: [], confidence: 'confirmed', status: 'open', accepted_note: '', first_seen: day(10), last_seen: day(0), ...o,
})

describe('scoring text', () => {
  it('bands', () => {
    expect([9, 8, 7.9, 6, 5.9, 3, 2.9].map(bandFor)).toEqual(['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low'])
  })
  it('explains the score', () => {
    expect(scoreText({ cvss: 9.8, likelihood: 3, risk: 2.94 })).toBe('CVSS 9.8 × likelihood 3.0 ÷ 10 = risk 2.9')
    expect(scoreText({ cvss: null, likelihood: 3, risk: 1 })).toContain('unknown')
  })
  it('formats EPSS', () => {
    expect(epssText(null)).toBe('—')
    expect(epssText(0.0004)).toBe('<0.1%')
    expect(epssText(0.123)).toBe('12%')
    expect(epssText(0.034)).toBe('3.4%')
  })
  it('labels images and the operating system', () => {
    expect(packageLabel({ package: 'openssl', package_type: 'deb' })).toBe('openssl')
    expect(packageLabel({ package: 'plex', package_type: 'docker' })).toBe('plex (Docker image)')
    expect(packageLabel({ package: 'Unraid OS', package_type: 'os' })).toBe('Unraid OS (operating system)')
  })
})

describe('sortFindings', () => {
  const a = f({ id: 'a', cve: 'CVE-A', risk: 2, cvss: 9, epss: null, hostname: 'zed', first_seen: day(1), likelihood: 1 })
  const b = f({ id: 'b', cve: 'CVE-B', risk: 9, cvss: 5, epss: 0.5, hostname: 'alpha', first_seen: day(5), likelihood: 9 })
  const c = f({ id: 'c', cve: 'CVE-C', risk: 5, cvss: null, epss: 0.1, hostname: 'mid', first_seen: day(3), likelihood: 5 })
  const ids = (l: VulnFinding[]) => l.map((x) => x.id).join('')
  it('sorts by each key', () => {
    expect(ids(sortFindings([a, b, c], 'risk', 'desc'))).toBe('bca')
    expect(ids(sortFindings([a, b, c], 'cvss', 'desc'))).toBe('abc')
    expect(ids(sortFindings([a, b, c], 'epss', 'desc'))).toBe('bca')
    expect(ids(sortFindings([a, b, c], 'first_seen', 'desc'))).toBe('acb')
    expect(ids(sortFindings([a, b, c], 'host', 'asc'))).toBe('bca')
    expect(ids(sortFindings([a, b, c], 'likelihood', 'asc'))).toBe('acb')
  })
  it('does not mutate and breaks ties by risk', () => {
    const list = [a, b]
    sortFindings(list, 'host', 'asc')
    expect(list[0]).toBe(a)
    const x = f({ id: 'x', risk: 1, hostname: 'same' })
    const y = f({ id: 'y', risk: 4, hostname: 'same' })
    expect(ids(sortFindings([x, y], 'host', 'asc'))).toBe('yx')
  })
})

describe('filterFindings', () => {
  const list = [
    f({ id: '1', cve: 'CVE-2024-1', status: 'open', band: 'critical', kev: true, exposure: 'internet', fixed_version: '' }),
    f({ id: '2', cve: 'CVE-2024-2', status: 'accepted', hostname: 'nas', host_id: 'n', package: 'openssl' }),
    f({ id: '3', cve: 'CVE-2024-3', status: 'fixed', title: 'Kernel flaw' }),
  ]
  const ids = (o: Partial<typeof defaultFilters>) => filterFindings(list, { ...defaultFilters, ...o }).map((x) => x.id).join('')
  it('defaults to open', () => expect(ids({})).toBe('1'))
  it('filters', () => {
    expect(ids({ status: 'all' })).toBe('123')
    expect(ids({ status: 'accepted' })).toBe('2')
    expect(ids({ status: 'all', band: 'critical' })).toBe('1')
    expect(ids({ status: 'all', host: 'n' })).toBe('2')
    expect(ids({ status: 'all', exposure: 'internet' })).toBe('1')
    expect(ids({ status: 'all', kevOnly: true })).toBe('1')
    expect(ids({ status: 'all', hasFix: true })).toBe('23')
    expect(ids({ status: 'all', text: 'openssl nas' })).toBe('2')
    expect(ids({ status: 'all', text: 'KERNEL' })).toBe('3')
  })
})

describe('newFindings', () => {
  it('keeps recent open critical/high, newest first', () => {
    const list = [
      f({ id: 'old', band: 'critical', first_seen: day(9) }),
      f({ id: 'med', band: 'medium', first_seen: day(1) }),
      f({ id: 'a', band: 'high', first_seen: day(3) }),
      f({ id: 'b', band: 'critical', first_seen: day(1) }),
      f({ id: 'acc', band: 'critical', first_seen: day(1), status: 'accepted' }),
    ]
    expect(newFindings(list, NOW).map((x) => x.id)).toEqual(['b', 'a'])
  })
})

describe('weeklyHistory', () => {
  const p = (date: string, n: number, x: number) => ({ date, critical: 0, high: 0, medium: 0, low: 0, new: n, fixed: x })
  it('groups by Monday', () => {
    // 2026-11-23 is a Monday
    const w = weeklyHistory([p('2026-11-22', 1, 0), p('2026-11-23', 2, 1), p('2026-11-29', 3, 1), p('2026-11-30', 4, 0)])
    expect(w).toEqual([
      { week: '2026-11-16', new: 1, fixed: 0 },
      { week: '2026-11-23', new: 5, fixed: 2 },
      { week: '2026-11-30', new: 4, fixed: 0 },
    ])
  })
  it('handles empty', () => expect(weeklyHistory([])).toEqual([]))
})

describe('hosts and exposure', () => {
  const h = (o: Partial<VulnHost>): VulnHost => ({ host_id: 'x', hostname: 'x', os: '', packages: 5, coverage: 'full', exposure: 'lan', exposed_ports: [], open: 1, max_risk: 1, ...o })
  it('ranks hosts and drops clean ones', () => {
    expect(hostsByRisk([h({ hostname: 'a', max_risk: 3 }), h({ hostname: 'b', max_risk: 9 }), h({ hostname: 'c', open: 0 })]).map((x) => x.hostname)).toEqual(['b', 'a'])
  })
  it('counts open findings by exposure', () => {
    expect(exposureCounts([f({ exposure: 'internet' }), f({}), f({ status: 'fixed', exposure: 'internet' })])).toEqual({ internet: 1, lan: 1 })
  })
})

describe('sourceProblems', () => {
  const host = h0()
  function h0(): VulnHost { return { host_id: 'h', hostname: 'tower', os: '', packages: 380, coverage: 'full', exposure: 'lan', exposed_ports: [], open: 0, max_risk: 0 } }
  const ok = { id: 'kev', name: 'CISA KEV', enabled: true, entries: 1768 }
  it('is empty when all is well', () => expect(sourceProblems([ok], [host])).toEqual([]))
  it('names problems', () => {
    expect(sourceProblems([{ ...ok, enabled: false }], [host])[0]).toContain('turned off')
    expect(sourceProblems([{ ...ok, entries: 0 }], [host])[0]).toContain('not been downloaded')
    expect(sourceProblems([{ ...ok, error: 'Could not look up www.cisa.gov.' }], [host])[0]).toContain('www.cisa.gov')
    expect(sourceProblems([ok], [])[0]).toContain('No agents')
    expect(sourceProblems([ok], [{ ...host, packages: 0, note: 'no package database' }])[0]).toContain('no package database')
  })
})
