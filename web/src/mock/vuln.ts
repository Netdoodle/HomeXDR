// Mock known-exploited software results.

import type { VulnMatch, VulnReport } from '../api/vuln'
import type { MockRoute } from './health'

const ago = (days: number) => new Date(Date.now() - days * 86400_000).toISOString()
const seen = { first_seen: ago(4), last_seen: ago(0.1) }

const matches: VulnMatch[] = [
  { ...seen, host_id: 'h-tower', hostname: 'tower', package: 'exim', version: '4.69', package_type: 'slackware', cve: 'CVE-2010-4344', title: 'Exim Heap-Based Buffer Overflow Vulnerability', kev_date: '2022-03-25', due_date: '2022-04-15', ransomware: true, confidence: 'confirmed', reason: 'Version 4.69 is affected: CISA’s description says versions before 4.70 are.' },
  { ...seen, host_id: 'h-tower', hostname: 'tower', package: 'samba', version: '4.22.10', package_type: 'slackware', cve: 'CVE-2017-7494', title: 'Samba Remote Code Execution Vulnerability', kev_date: '2022-03-25', due_date: '2022-04-15', ransomware: true, confidence: 'possible', reason: 'The name matches. CISA’s catalog has no version ranges, so this does not say your version is affected.' },
  { ...seen, host_id: 'h-tower', hostname: 'tower', package: 'sudo', version: '1.9.17p2', package_type: 'slackware', cve: 'CVE-2021-3156', title: 'Sudo Heap-Based Buffer Overflow Vulnerability', kev_date: '2022-04-06', due_date: '2022-04-27', ransomware: false, confidence: 'possible', reason: 'The name matches. CISA’s catalog has no version ranges, so this does not say your version is affected.' },
  { ...seen, host_id: 'h-tower', hostname: 'tower', package: 'lscr.io/linuxserver/plex', version: 'latest', package_type: 'docker', cve: 'CVE-2020-5741', title: 'Plex Media Server Remote Code Execution Vulnerability', kev_date: '2023-03-10', due_date: '2023-03-31', ransomware: false, confidence: 'possible', reason: 'The name matches. CISA’s catalog has no version ranges, so this does not say your version is affected.' },
]

const report: VulnReport = {
  matches,
  confirmed: 1,
  possible: 3,
  hosts: [
    { host_id: 'h-tower', hostname: 'tower', packages: 380, snapshot_at: ago(0.2) },
    { host_id: 'h-laptop', hostname: 'laptop', packages: 0, note: 'software.list: no supported package database found (looked for dpkg, rpm, apk, pacman and Slackware packages)' },
  ],
  kev: { enabled: true, entries: 1768, version: '2026.11.04', last_update: ago(0.5) },
  osv: { enabled: false },
  last_run: ago(0.02),
  running: false,
}

export function registerVulnMocks(route: MockRoute) {
  route('GET', '/api/vulnerabilities', () => report)
  route('POST', '/api/vulnerabilities/refresh', () => report, { role: 'admin' })
  route(
    'PUT',
    '/api/settings/vuln',
    ({ body }) => {
      report.osv.enabled = (body as { osv: boolean }).osv
      return report
    },
    { role: 'admin' },
  )
}
