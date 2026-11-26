// Mock vulnerability management data: hosts of every coverage kind, internet and LAN
// exposure, open/accepted/fixed findings and 90 days of history.

import type { Exposure, VulnFinding, VulnHistoryPoint, VulnHost, VulnReport, VulnStatus } from '../api/vuln'
import { bandFor } from '../lib/vuln'
import type { MockRoute } from './health'
import { mulberry32 } from './rng'

const DAY = 86400_000
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString()
const r = mulberry32(0x7075)
const round1 = (n: number) => Math.round(n * 10) / 10

interface HostDef {
  host_id: string
  hostname: string
  os: string
  packages: number
  coverage: VulnHost['coverage']
  exposure: Exposure
  exposed_ports: number[]
  type: string
  note?: string
  snapshot?: number
}
const hostDefs: HostDef[] = [
  { host_id: 'h-web', hostname: 'web01', os: 'Debian 12', packages: 612, coverage: 'full', exposure: 'internet', exposed_ports: [80, 443], type: 'deb', snapshot: 0.1 },
  { host_id: 'h-pihole', hostname: 'pihole', os: 'Raspberry Pi OS 12', packages: 498, coverage: 'full', exposure: 'lan', exposed_ports: [53, 80], type: 'deb', snapshot: 0.3 },
  { host_id: 'h-laptop', hostname: 'laptop', os: 'Ubuntu 24.04', packages: 1904, coverage: 'full', exposure: 'lan', exposed_ports: [], type: 'deb', snapshot: 1.2 },
  { host_id: 'h-alpine', hostname: 'edge-proxy', os: 'Alpine 3.20', packages: 143, coverage: 'full', exposure: 'internet', exposed_ports: [443, 8443], type: 'apk', snapshot: 0.2 },
  { host_id: 'h-tower', hostname: 'tower', os: 'Unraid 7.1', packages: 380, coverage: 'kev_only', exposure: 'lan', exposed_ports: [445, 32400], type: 'slackware', snapshot: 0.2 },
  { host_id: 'h-arch', hostname: 'devbox', os: 'Arch Linux', packages: 811, coverage: 'kev_only', exposure: 'lan', exposed_ports: [22], type: 'pacman', snapshot: 5.5 },
  { host_id: 'h-old', hostname: 'old-vm', os: 'Unknown', packages: 0, coverage: 'none', exposure: 'lan', exposed_ports: [], type: 'deb', note: 'software.list: no supported package database found (looked for dpkg, rpm, apk, pacman and Slackware packages)' },
]
const hid = (h: string) => hostDefs.find((d) => d.hostname === h)!

// [host, package, version, fixed, cve, title, cvss, epss, kev, ransomware, vector, source, status, age(days)]
type Row = [string, string, string, string, string, string, number | null, number | null, boolean, boolean, 'network' | 'adjacent' | 'local' | 'physical', 'nvd' | 'osv' | 'distro' | 'estimated', VulnStatus, number]
const rows: Row[] = [
  ['web01', 'openssh-server', '1:9.2p1-2+deb12u2', '1:9.2p1-2+deb12u3', 'CVE-2024-6387', 'OpenSSH regreSSHion race condition', 8.1, 0.62, false, false, 'network', 'nvd', 'open', 2],
  ['web01', 'nginx', '1.22.1-9', '1.22.1-9+deb12u1', 'CVE-2024-7347', 'nginx mp4 module buffer over-read', 4.7, 0.01, false, false, 'network', 'nvd', 'open', 12],
  ['web01', 'libssl3', '3.0.11-1~deb12u2', '3.0.14-1~deb12u1', 'CVE-2024-5535', 'OpenSSL SSL_select_next_proto buffer overread', 9.1, 0.04, false, false, 'network', 'nvd', 'open', 3],
  ['web01', 'php8.2-fpm', '8.2.7-1', '8.2.20-1', 'CVE-2024-4577', 'PHP-CGI argument injection', 9.8, 0.97, true, true, 'network', 'nvd', 'open', 1],
  ['web01', 'curl', '7.88.1-10+deb12u5', '7.88.1-10+deb12u6', 'CVE-2024-6197', 'curl freeing stack buffer in utf8asn1str', 7.5, 0.003, false, false, 'network', 'distro', 'open', 20],
  ['web01', 'libxml2', '2.9.14+dfsg-1.3', '2.9.14+dfsg-1.3~deb12u1', 'CVE-2024-34459', 'libxml2 xmllint buffer over-read', 6.5, 0.002, false, false, 'local', 'nvd', 'open', 30],
  ['web01', 'glibc', '2.36-9+deb12u3', '2.36-9+deb12u4', 'CVE-2023-4911', 'Looney Tunables privilege escalation', 7.8, 0.9, true, false, 'local', 'nvd', 'fixed', 40],
  ['web01', 'sudo', '1.9.13p3-1', '', 'CVE-2025-32463', 'Sudo chroot option local privilege escalation', 9.3, 0.5, true, false, 'local', 'nvd', 'open', 5],
  ['web01', 'zlib1g', '1:1.2.13.dfsg-1', '1:1.2.13.dfsg-1+deb12u1', 'CVE-2022-37434', 'zlib heap buffer over-read in inflate', 9.8, 0.01, false, false, 'network', 'nvd', 'fixed', 15],
  ['pihole', 'dnsmasq', '2.89-1', '2.90-1', 'CVE-2023-28450', 'dnsmasq default EDNS0 size too large', 7.5, 0.02, false, false, 'network', 'nvd', 'open', 25],
  ['pihole', 'lighttpd', '1.4.69-1', '1.4.69-1+deb12u1', 'CVE-2022-41556', 'lighttpd mod_auth memory leak', 5.3, 0.001, false, false, 'network', 'distro', 'open', 50],
  ['pihole', 'openssh-server', '1:9.2p1-2+deb12u2', '1:9.2p1-2+deb12u3', 'CVE-2024-6387', 'OpenSSH regreSSHion race condition', 8.1, 0.62, false, false, 'network', 'nvd', 'open', 2],
  ['pihole', 'php8.2-cgi', '8.2.7-1', '8.2.20-1', 'CVE-2024-4577', 'PHP-CGI argument injection', 9.8, 0.97, true, true, 'network', 'nvd', 'accepted', 20],
  ['pihole', 'libc-bin', '2.36-9+deb12u3', '2.36-9+deb12u4', 'CVE-2024-2961', 'iconv ISO-2022-CN-EXT out-of-bounds write', 7.3, 0.1, false, false, 'local', 'nvd', 'open', 35],
  ['pihole', 'tar', '1.34+dfsg-1.2', '', 'CVE-2005-2541', 'tar setuid and setgid preservation', null, null, false, false, 'local', 'estimated', 'open', 14],
  ['laptop', 'linux-image-6.8.0-45', '6.8.0-45.45', '6.8.0-48.48', 'CVE-2024-46800', 'Linux kernel sch_netem use-after-free', 7.8, 0.004, false, false, 'local', 'distro', 'open', 6],
  ['laptop', 'firefox', '130.0', '131.0', 'CVE-2024-9680', 'Firefox animation timeline use-after-free', 9.8, 0.55, true, false, 'network', 'nvd', 'open', 2],
  ['laptop', 'cups-browsed', '2.0.0-0ubuntu10', '2.0.0-0ubuntu10.1', 'CVE-2024-47176', 'cups-browsed binds on UDP INADDR_ANY:631', 8.4, 0.88, false, false, 'network', 'nvd', 'open', 4],
  ['laptop', 'libreoffice-core', '24.2.5-0ubuntu0.24.04.1', '24.2.6-0ubuntu0.24.04.1', 'CVE-2024-7788', 'LibreOffice improper digital signature validation', 7.5, 0.003, false, false, 'local', 'nvd', 'open', 18],
  ['laptop', 'python3.12', '3.12.3-1ubuntu0.1', '3.12.3-1ubuntu0.2', 'CVE-2024-6232', 'Python tarfile regex backtracking', 7.5, 0.002, false, false, 'local', 'distro', 'open', 22],
  ['laptop', 'bash', '5.2.21-2ubuntu4', '', 'CVE-2022-3715', 'Bash valid_parameter_name heap overflow', 7.8, 0.001, false, false, 'local', 'nvd', 'accepted', 60],
  ['laptop', 'git', '1:2.43.0-1ubuntu7', '1:2.43.0-1ubuntu7.1', 'CVE-2024-32002', 'Git recursive clone remote code execution', 9.0, 0.08, false, false, 'network', 'nvd', 'fixed', 11],
  ['laptop', 'openssl', '3.0.13-0ubuntu3', '3.0.13-0ubuntu3.4', 'CVE-2024-9143', 'OpenSSL out-of-bounds in GF(2^m) curves', 4.3, 0.001, false, false, 'network', 'nvd', 'open', 3],
  ['edge-proxy', 'busybox', '1.36.1-r29', '1.36.1-r31', 'CVE-2023-42366', 'BusyBox awk heap-buffer-overflow', 5.5, 0.003, false, false, 'local', 'nvd', 'open', 28],
  ['edge-proxy', 'openssl', '3.3.1-r3', '3.3.2-r0', 'CVE-2024-9143', 'OpenSSL out-of-bounds in GF(2^m) curves', 4.3, 0.001, false, false, 'network', 'nvd', 'open', 3],
  ['edge-proxy', 'nginx', '1.26.1-r0', '1.26.2-r0', 'CVE-2024-7347', 'nginx mp4 module buffer over-read', 4.7, 0.01, false, false, 'network', 'nvd', 'open', 9],
  ['edge-proxy', 'curl', '8.8.0-r0', '8.9.0-r0', 'CVE-2024-6874', 'curl macidn punycode buffer overread', 5.3, 0.002, false, false, 'network', 'osv', 'open', 16],
  ['edge-proxy', 'libexpat', '2.6.2-r0', '2.6.3-r0', 'CVE-2024-45490', 'Expat negative length integer overflow', 9.8, 0.03, false, false, 'network', 'nvd', 'open', 6],
  ['edge-proxy', 'musl', '1.2.5-r0', '1.2.5-r1', 'CVE-2025-26519', 'musl iconv EUC-KR out-of-bounds write', 8.1, 0.002, false, false, 'local', 'nvd', 'fixed', 21],
  ['edge-proxy', 'zlib', '1.3.1-r1', '1.3.1-r2', 'CVE-2024-99999', 'zlib hypothetical overflow', 5.9, null, false, false, 'network', 'estimated', 'fixed', 8],
  ['tower', 'exim', '4.69', '', 'CVE-2010-4344', 'Exim heap-based buffer overflow', 9.8, 0.94, true, true, 'network', 'nvd', 'open', 30],
  ['tower', 'samba', '4.22.10', '', 'CVE-2017-7494', 'Samba remote code execution (SambaCry)', 9.8, 0.97, true, true, 'network', 'nvd', 'open', 30],
  ['tower', 'sudo', '1.9.17p2', '', 'CVE-2021-3156', 'Sudo heap-based buffer overflow (Baron Samedit)', 7.8, 0.95, true, false, 'local', 'nvd', 'open', 30],
  ['tower', 'lscr.io/linuxserver/plex', 'latest', '', 'CVE-2020-5741', 'Plex Media Server remote code execution', 7.2, 0.35, true, false, 'network', 'nvd', 'open', 6],
  ['tower', 'Unraid OS', '7.1.2', '', 'CVE-2025-6018', 'Unraid web UI authentication bypass', 8.8, 0.04, false, false, 'network', 'estimated', 'open', 3],
  ['tower', 'openssl', '3.2.3', '', 'CVE-2022-0778', 'OpenSSL BN_mod_sqrt infinite loop', 7.5, 0.7, true, false, 'network', 'nvd', 'accepted', 40],
  ['tower', 'bash', '5.2.032', '', 'CVE-2014-6271', 'GNU Bash Shellshock', 9.8, 0.97, true, false, 'network', 'nvd', 'fixed', 14],
  ['devbox', 'openssh', '9.8p1', '', 'CVE-2024-6387', 'OpenSSH regreSSHion race condition', 8.1, 0.62, true, false, 'network', 'nvd', 'open', 2],
  ['devbox', 'glibc', '2.39', '', 'CVE-2023-4911', 'Looney Tunables privilege escalation', 7.8, 0.9, true, false, 'local', 'nvd', 'open', 45],
  ['devbox', 'git', '2.45.2', '', 'CVE-2024-32002', 'Git recursive clone remote code execution', 9.0, 0.08, true, false, 'network', 'nvd', 'accepted', 47],
]

// A second pass of lower-risk filler so the table has real volume to sort and page.
const filler: [string, string, string, string, string, number][] = [
  ['laptop', 'libpng16-16', '1.6.43', '1.6.44', 'CVE-2024-99101', 5.5],
  ['laptop', 'libtiff6', '4.5.1', '4.5.1+git1', 'CVE-2024-99102', 6.1],
  ['laptop', 'gstreamer1.0-plugins-bad', '1.24.2', '1.24.3', 'CVE-2024-99103', 7.8],
  ['laptop', 'libgdk-pixbuf-2.0-0', '2.42.10', '2.42.12', 'CVE-2024-99104', 5.5],
  ['laptop', 'evolution-data-server', '3.52.3', '3.52.4', 'CVE-2024-99105', 4.3],
  ['laptop', 'vim', '2:9.1.0016', '2:9.1.0100', 'CVE-2024-99106', 5.9],
  ['laptop', 'ghostscript', '10.02.1', '10.03.1', 'CVE-2024-99107', 7.8],
  ['laptop', 'imagemagick', '8:6.9.12', '8:6.9.13', 'CVE-2024-99108', 6.5],
  ['web01', 'libgnutls30', '3.7.9', '3.7.9-2+deb12u3', 'CVE-2024-99109', 7.5],
  ['web01', 'libcurl4', '7.88.1', '7.88.1-10+deb12u6', 'CVE-2024-99110', 6.3],
  ['web01', 'postgresql-15', '15.5', '15.8', 'CVE-2024-99111', 8.8],
  ['web01', 'libpq5', '15.5', '15.8', 'CVE-2024-99112', 7.5],
  ['web01', 'python3.11', '3.11.2', '3.11.2-6+deb12u3', 'CVE-2024-99113', 6.2],
  ['pihole', 'libsqlite3-0', '3.40.1', '3.40.1-2+deb12u1', 'CVE-2024-99114', 5.1],
  ['pihole', 'systemd', '252.22', '252.26', 'CVE-2024-99115', 5.5],
  ['pihole', 'wget', '1.21.3', '1.21.3-1+deb12u1', 'CVE-2024-99116', 6.5],
  ['pihole', 'libexpat1', '2.5.0', '2.5.0-1+deb12u1', 'CVE-2024-99117', 7.5],
  ['edge-proxy', 'libcrypto3', '3.3.1-r3', '3.3.2-r0', 'CVE-2024-99118', 6.5],
  ['edge-proxy', 'pcre2', '10.43', '10.44', 'CVE-2024-99119', 5.3],
  ['edge-proxy', 'sqlite-libs', '3.45.3', '3.45.4', 'CVE-2024-99120', 6.1],
]

function build(row: Row): VulnFinding {
  const [host, pkg, version, fixed, cve, title, cvss, epss, kev, ransomware, av, source, status, age] = row
  const h = hid(host)
  const ports = h.exposed_ports
  const reasons: string[] = []
  let lik = av === 'network' ? 4 : av === 'adjacent' ? 3 : 2
  reasons.push(
    av === 'network'
      ? 'The flaw can be reached over the network.'
      : av === 'local'
        ? 'The flaw needs an attacker who already has an account on the host.'
        : 'The flaw needs the attacker on the same network segment.',
  )
  if (h.exposure === 'internet' && av === 'network') {
    lik += 3
    reasons.push(`${h.hostname} is reachable from the internet on port ${ports.join(', ')}.`)
  } else if (av === 'network') {
    lik += 1
    reasons.push(`${h.hostname} is only reachable from your LAN.`)
  }
  if (kev) {
    lik += 2
    reasons.push('CISA lists it as exploited in the wild.')
  }
  if (ransomware) reasons.push('Ransomware groups are known to use it.')
  if (epss !== null && epss >= 0.5) {
    lik += 1
    reasons.push(`EPSS puts the chance of exploitation in the next 30 days at ${Math.round(epss * 100)}%.`)
  }
  if (fixed === '') reasons.push('No fixed version has been released, so patching is not possible yet.')
  const likelihood = Math.min(10, Math.max(0.5, lik))
  const score = cvss ?? 5
  const risk = round1((score * likelihood) / 10)
  return {
    id: `${h.host_id}|${pkg}|${cve}`,
    host_id: h.host_id,
    hostname: h.hostname,
    package: pkg,
    source_package: pkg.replace(/-\d.*$/, ''),
    version,
    package_type: pkg.includes('/') ? 'docker' : pkg === 'Unraid OS' ? 'os' : h.type,
    cve,
    title,
    summary: `${title}. Affects ${pkg} before ${fixed || 'a release that does not exist yet'}. An attacker could abuse it to run code, read data or crash the service, depending on how ${pkg} is used.`,
    fixed_version: fixed,
    cvss,
    cvss_vector: cvss === null ? '' : `CVSS:3.1/AV:${av[0].toUpperCase()}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
    severity_source: source,
    epss,
    epss_percentile: epss === null ? null : Math.min(0.999, 0.4 + epss * 0.6),
    kev,
    kev_due_date: kev ? new Date(Date.now() + (ransomware ? -200 : 14) * DAY).toISOString().slice(0, 10) : '',
    ransomware,
    exposure: h.exposure,
    exposed_ports: ports,
    attack_vector: av,
    likelihood,
    risk,
    band: bandFor(risk),
    likelihood_reasons: reasons,
    confidence: h.coverage === 'kev_only' && pkg !== 'Unraid OS' && !fixed && cve !== 'CVE-2010-4344' ? 'possible' : 'confirmed',
    status,
    accepted_note: status === 'accepted' ? 'Not reachable in my setup; revisit after the next upgrade.' : '',
    first_seen: ago(age),
    last_seen: status === 'fixed' ? ago(Math.max(1, age - 5)) : ago(0.1),
    fixed_at: status === 'fixed' ? ago(Math.max(1, Math.min(age - 1, 6 + Math.floor(r() * 15)))) : undefined,
  }
}

const findings: VulnFinding[] = [
  ...rows.map(build),
  ...filler.map(([host, pkg, version, fixed, cve, cvss], i) =>
    build([host, pkg, version, fixed, cve, `${pkg} security flaw`, cvss, r() < 0.5 ? null : Math.round(r() * 300) / 1000, false, false, i % 3 ? 'local' : 'network', i % 4 ? 'distro' : 'osv', i % 9 === 8 ? 'fixed' : 'open', 3 + Math.floor(r() * 80)]),
  ),
]

function history(): VulnHistoryPoint[] {
  const out: VulnHistoryPoint[] = []
  const days = 90
  const cur = { critical: 4, high: 9, medium: 18, low: 10 }
  // build forward from a smaller starting backlog with noise
  const s = { critical: 2, high: 6, medium: 12, low: 7 }
  for (let i = days; i >= 0; i--) {
    const d = new Date(Date.now() - i * DAY).toISOString().slice(0, 10)
    const t = (days - i) / days
    const nw = Math.floor(r() * 4) + (r() < 0.08 ? 4 : 0)
    const fx = Math.floor(r() * 3)
    const p = { critical: 0, high: 0, medium: 0, low: 0, new: nw, fixed: fx, date: d }
    for (const k of ['critical', 'high', 'medium', 'low'] as const) {
      p[k] = Math.max(0, Math.round(s[k] + (cur[k] - s[k]) * t + (r() - 0.5) * (k === 'critical' ? 1.5 : 3)))
    }
    out.push(p)
  }
  return out
}

const hist = history()

let report: VulnReport = build_report()

function build_report(): VulnReport {
  const open = findings.filter((f) => f.status === 'open')
  const hosts: VulnHost[] = hostDefs.map((h) => {
    const mine = open.filter((f) => f.host_id === h.host_id)
    return {
      host_id: h.host_id,
      hostname: h.hostname,
      os: h.os,
      packages: h.packages,
      snapshot_at: h.snapshot === undefined ? undefined : ago(h.snapshot),
      note: h.note,
      coverage: h.coverage,
      exposure: h.exposure,
      exposed_ports: h.exposed_ports,
      open: mine.length,
      max_risk: Math.max(0, ...mine.map((f) => f.risk)),
    }
  })
  const count = (b: string) => open.filter((f) => f.band === b).length
  return {
    findings: [...findings],
    summary: {
      open: open.length,
      critical: count('critical'),
      high: count('high'),
      medium: count('medium'),
      low: count('low'),
      internet_exposed: open.filter((f) => f.exposure === 'internet').length,
      kev: open.filter((f) => f.kev).length,
      new_7d: findings.filter((f) => Date.parse(f.first_seen) > Date.now() - 7 * DAY).length,
      fixed_7d: findings.filter((f) => f.fixed_at && Date.parse(f.fixed_at) > Date.now() - 7 * DAY).length,
      no_fix: open.filter((f) => !f.fixed_version).length,
    },
    history: hist,
    hosts,
    sources: [
      { id: 'debian', name: 'Debian security tracker', enabled: true, entries: 38120, last_update: ago(0.4) },
      { id: 'ubuntu', name: 'Ubuntu security notices', enabled: true, entries: 21404, last_update: ago(0.4) },
      { id: 'alpine', name: 'Alpine secdb', enabled: true, entries: 5230, last_update: ago(0.4) },
      { id: 'nvd', name: 'NVD CVSS scores', enabled: true, entries: 231884, last_update: ago(0.6) },
      { id: 'epss', name: 'FIRST EPSS', enabled: true, entries: 247113, last_update: ago(0.5), error: undefined },
      { id: 'kev', name: 'CISA known exploited', enabled: true, entries: 1768, last_update: ago(0.5) },
    ],
    osv_api: { enabled: false },
    last_run: ago(0.02),
    running: false,
  }
}

export function registerVulnMocks(route: MockRoute) {
  route('GET', '/api/vulnerabilities', () => report)
  route('POST', '/api/vulnerabilities/refresh', () => report, { role: 'admin' })
  route(
    'PUT',
    '/api/settings/vuln',
    ({ body }) => {
      report = { ...report, osv_api: { enabled: (body as { osv: boolean }).osv } }
      return report
    },
    { role: 'admin' },
  )
  route(
    'PUT',
    '/api/vulnerabilities/accept',
    ({ body }) => {
      const b = body as { host_id: string; package: string; cve: string; accepted: boolean; note: string }
      const f = findings.find((x) => x.host_id === b.host_id && x.package === b.package && x.cve === b.cve)
      if (f && f.status !== 'fixed') {
        f.status = b.accepted ? 'accepted' : 'open'
        f.accepted_note = b.accepted ? b.note : ''
      }
      report = build_report()
      return report
    },
    { role: 'admin' },
  )
}
