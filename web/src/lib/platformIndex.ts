// The places in the console the top search bar can jump to: pages, settings tabs and the
// sections inside them. A section is found on its page by its heading (lib/anchor.ts), so
// `section` must match the heading text.

export interface PlatformPlace {
  /** Where it is, outermost first: ["Settings", "Agent updates", "Inactive agents"]. */
  crumbs: string[]
  path: string
  /** Heading of a section on the page, scrolled to after navigating. */
  section?: string
  /** Other words people may type for it. */
  keywords?: string[]
  admin?: boolean
}

const S = 'Settings'

export const PLATFORM_PLACES: PlatformPlace[] = [
  // Pages
  { crumbs: ['Dashboard'], path: '/', keywords: ['home', 'overview'] },
  { crumbs: ['Dashboard', 'Top rules'], path: '/', section: 'Top rules' },
  { crumbs: ['Dashboard', 'Top hosts by alerts'], path: '/', section: 'Top hosts by alerts' },
  { crumbs: ['Dashboard', 'Latest open alerts'], path: '/', section: 'Latest open alerts' },
  { crumbs: ['Alerts'], path: '/alerts', keywords: ['detections', 'triage', 'incidents'] },
  { crumbs: ['Alerts', 'Top repeating'], path: '/alerts', section: 'Top repeating', keywords: ['noise', 'suppress', 'suppressions', 'noisy alerts'] },
  { crumbs: ['Alerts', 'Alert detail', 'Suppress'], path: '/alerts', keywords: ['suppressions', 'suppress this alert', 'false positive'] },
  { crumbs: ['Hosts'], path: '/hosts', keywords: ['agents', 'endpoints', 'computers', 'machines'] },
  { crumbs: ['Hosts', 'Host detail', 'Labels'], path: '/hosts', keywords: ['tags', 'host labels'] },
  { crumbs: ['Hosts', 'Host detail', 'Response actions'], path: '/hosts', keywords: ['isolate', 'kill process', 'quarantine', 'defender', 'scan'] },
  { crumbs: ['Devices'], path: '/devices', keywords: ['network devices', 'inventory', 'dhcp', 'mac'] },
  { crumbs: ['Search'], path: '/search', keywords: ['events', 'query', 'logs', 'hunt events'] },
  { crumbs: ['Investigate'], path: '/investigate', keywords: ['ioc', 'indicator', 'lookup', 'ip', 'domain', 'hash', 'whois', 'osint'] },
  { crumbs: ['Threat map'], path: '/threat-map', keywords: ['attack map', 'countries', 'scanning', 'scanners', 'inbound', 'firewall', 'geo', 'world map', 'blocked connections'] },
  { crumbs: ['Threat map', 'Targeted ports'], path: '/threat-map', section: 'Targeted ports', keywords: ['ports', 'scans'] },
  { crumbs: ['Threat map', 'Let in from the internet'], path: '/threat-map', section: 'Let in from the internet', keywords: ['exposed', 'port forward', 'open ports'] },
  { crumbs: ['Rules'], path: '/rules', keywords: ['sigma', 'detection rules'] },
  { crumbs: ['Rules', 'New rule'], path: '/rules/new', keywords: ['create rule', 'write rule'] },
  { crumbs: ['Rules', 'Rule repositories'], path: '/rules/repositories', keywords: ['sigmahq', 'git', 'rule sources'] },
  { crumbs: ['Hunts'], path: '/hunts', keywords: ['artifacts', 'collect'] },
  { crumbs: ['Hunts', 'New hunt'], path: '/hunts/new' },
  { crumbs: ['Data health'], path: '/health', keywords: ['health', 'feeds', 'status'] },
  { crumbs: ['Data health', 'Data sources'], path: '/health/sources', keywords: ['feeds', 'syslog', 'missing data'] },
  { crumbs: ['Data health', 'Doctor'], path: '/health/doctor', admin: true, keywords: ['diagnostics', 'checks'] },
  { crumbs: ['Data health', 'Self-check'], path: '/health/selfcheck', admin: true, keywords: ['rule logic', 'can rules fire'] },
  { crumbs: ['Data retention'], path: '/retention', keywords: ['disk', 'storage', 'ttl', 'falloff'] },
  { crumbs: ['Data retention', 'Next falloff'], path: '/retention', section: 'Next falloff', keywords: ['expiry', 'expire'] },
  { crumbs: ['Data retention', 'Storage'], path: '/retention', section: 'Storage', keywords: ['disk usage', 'size'] },
  { crumbs: ['Data retention', 'Retention settings'], path: '/retention', section: 'Retention settings', keywords: ['retention days', 'max size'] },
  { crumbs: ['Data retention', 'Cloud backup'], path: '/retention', section: 'Cloud backup (cold storage)', keywords: ['s3', 'bucket', 'archive', 'cold storage', 'backup'] },
  { crumbs: ['Data retention', 'Archived days'], path: '/retention', section: 'Archived days', keywords: ['import', 'restore'] },
  { crumbs: ['Vulnerabilities'], path: '/vulnerabilities', keywords: ['cve', 'osv', 'scanner'] },

  // Settings tabs and their sections
  { crumbs: [S, 'Enrollment'], path: '/settings/tokens', admin: true, keywords: ['enrollment tokens', 'install agent', 'add host'] },
  { crumbs: [S, 'Users'], path: '/settings/users', admin: true, keywords: ['accounts', 'roles', 'add user'] },
  { crumbs: [S, 'Agent config'], path: '/settings/agent-config', keywords: ['sensors', 'event log channels', 'fim', 'agent settings'] },
  { crumbs: [S, 'Agent updates'], path: '/settings/agents', section: 'Agent updates', admin: true, keywords: ['upgrade', 'versions', 'rollout'] },
  { crumbs: [S, 'Agent updates', 'Inactive agents'], path: '/settings/agents', section: 'Inactive agents', admin: true, keywords: ['offline agents', 'stale', 'dead agents'] },
  { crumbs: [S, 'Agent updates', 'Release archive'], path: '/settings/agents', section: 'Release archive', admin: true },
  { crumbs: [S, 'Integrations'], path: '/settings/integrations', keywords: ['syslog intake', 'netflow', 'opnsense'] },
  { crumbs: [S, 'Integrations', 'Syslog intake'], path: '/settings/integrations', section: 'Syslog intake', keywords: ['firewall logs'] },
  { crumbs: [S, 'Suppressions'], path: '/settings/suppressions', section: 'Suppressions', keywords: ['tuning', 'exceptions', 'false positives', 'allowlist'] },
  { crumbs: [S, 'Suppressions', 'Must alert'], path: '/settings/suppressions', section: 'Must alert', keywords: ['suppressions', 'never suppress'] },
  { crumbs: [S, 'Suppressions', 'Top repeating'], path: '/settings/suppressions', section: 'Top repeating', keywords: ['suppressions', 'noise'] },
  { crumbs: [S, 'Maintenance'], path: '/settings/maintenance', keywords: ['ssh keys', 'maintenance window', 'suppressions', 'docker updates', 'tuning'] },
  { crumbs: [S, 'Maintenance', 'SSH keys'], path: '/settings/maintenance', section: 'SSH keys', keywords: ['key fingerprint', 'ssh'] },
  { crumbs: [S, 'Maintenance', 'Container updates'], path: '/settings/maintenance', section: 'Container updates', keywords: ['docker', 'unraid', 'appdata backup', 'suppressions'] },
  { crumbs: [S, 'Notifications'], path: '/settings/notifications', admin: true, keywords: ['email', 'ntfy', 'webhook', 'discord', 'alerts'] },
  { crumbs: [S, 'Notifications', 'Daily digest'], path: '/settings/notifications', section: 'Daily digest', admin: true },
  { crumbs: [S, 'Network'], path: '/settings/network', admin: true, keywords: ['home network', 'subnets', 'firewall addresses'] },
  { crumbs: [S, 'Network', 'Behaviour detectors'], path: '/settings/network', section: 'Behaviour detectors', admin: true, keywords: ['beaconing', 'dns bypass', 'scan'] },
  { crumbs: [S, 'Network', 'DNS resolver query log'], path: '/settings/network', section: 'DNS resolver query log', admin: true, keywords: ['adguard', 'pi-hole', 'pihole', 'technitium', 'dns'] },
  { crumbs: [S, 'Network', 'NetFlow / IPFIX intake'], path: '/settings/network', section: 'NetFlow / IPFIX intake', admin: true, keywords: ['netflow', 'ipfix', 'flows'] },
  { crumbs: [S, 'AI analyst'], path: '/settings/ai', admin: true, keywords: ['claude', 'triage', 'mcp', 'llm'] },
  { crumbs: [S, 'AI analyst', 'MCP access'], path: '/settings/ai', section: 'MCP access', admin: true },
  { crumbs: [S, 'Groups'], path: '/settings/groups', section: 'Host groups', keywords: ['group', 'parent', 'child', 'organisation', 'organization', 'inherit', 'override'] },
  { crumbs: [S, 'Antivirus'], path: '/settings/antivirus', section: 'Antivirus', keywords: ['clamav', 'yara', 'malware', 'quarantine', 'blocklist'] },
  { crumbs: [S, 'Antivirus', 'Recent detections'], path: '/settings/antivirus', section: 'Recent detections' },
  { crumbs: [S, 'Threat intel'], path: '/settings/intel', admin: true, keywords: ['virustotal', 'abuseipdb', 'api keys', 'feeds'] },
  { crumbs: [S, 'Offline lists'], path: '/settings/lists', admin: true, keywords: ['blocklists', 'feeds', 'ioc lists'] },
  { crumbs: [S, 'Audit log'], path: '/settings/audit', admin: true, keywords: ['history', 'who changed'] },
  { crumbs: [S, 'My account'], path: '/settings/account', keywords: ['password', 'change password', 'profile'] },
]

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()

/** Places matching a query, best first. Every word must appear in the place's names or keywords. */
export function searchPlaces(query: string, isAdmin: boolean, limit = 8): PlatformPlace[] {
  const q = norm(query)
  if (q.length < 2) return []
  const words = q.split(' ')
  const scored: { p: PlatformPlace; score: number }[] = []
  for (const p of PLATFORM_PLACES) {
    if (p.admin && !isAdmin) continue
    const last = norm(p.crumbs[p.crumbs.length - 1])
    const names = norm(p.crumbs.join(' '))
    const keys = (p.keywords ?? []).map(norm)
    const hay = names + ' ' + keys.join(' ')
    if (!words.every((w) => hay.includes(w))) continue
    let score = 0
    if (last === q) score += 100
    else if (last.startsWith(q)) score += 60
    else if (last.includes(q)) score += 40
    if (names.includes(q)) score += 20
    if (keys.some((k) => k === q)) score += 30
    else if (keys.some((k) => k.includes(q))) score += 10
    score -= p.crumbs.length // shallower first on ties
    scored.push({ p, score })
  }
  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, limit).map((s) => s.p)
}

/** The URL of a place, with its section as a hash. */
export function placeHref(p: PlatformPlace): string {
  return p.section ? `${p.path}#${slug(p.section)}` : p.path
}

export const slug = (s: string) => norm(s).replace(/ /g, '-')
