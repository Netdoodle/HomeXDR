import { uuid } from '../lib/uuid'
// Mock Sigma rules (detection logic only; these describe what to look for).

import type { MitreMapping, Rule, Severity } from '../api/types'
import { DAY, HOUR, ago } from './hosts'

interface RuleSeed {
  id: string
  title: string
  description: string
  level: Severity
  source: 'builtin' | 'custom'
  enabled?: boolean
  logsource: Rule['logsource']
  mitre: MitreMapping[]
  tags: string[]
  detection: string
  falsepositives?: string[]
  references?: string[]
  hits: number
  author?: string
}

function toYaml(s: RuleSeed): string {
  const lines = [
    `title: ${s.title}`,
    `id: ${s.id}`,
    `status: ${s.source === 'custom' ? 'experimental' : 'stable'}`,
    `description: ${s.description}`,
  ]
  if (s.references?.length) {
    lines.push('references:')
    for (const r of s.references) lines.push(`  - ${r}`)
  }
  lines.push(`author: ${s.author ?? 'HomeXDR'}`)
  lines.push('tags:')
  for (const t of s.tags) lines.push(`  - ${t}`)
  lines.push('logsource:')
  for (const [k, v] of Object.entries(s.logsource)) if (v) lines.push(`  ${k}: ${v}`)
  lines.push('detection:')
  lines.push(...s.detection.trim().split('\n').map((l) => '  ' + l))
  if (s.falsepositives?.length) {
    lines.push('falsepositives:')
    for (const f of s.falsepositives) lines.push(`  - ${f}`)
  }
  lines.push(`level: ${s.level}`)
  return lines.join('\n') + '\n'
}

const seeds: RuleSeed[] = [
  {
    id: 'b7e3a1c2-5f04-4c1e-9d0b-1a2f3e4d5c60',
    title: 'PowerShell Script Run From Downloads With ExecutionPolicy Bypass',
    description: 'A PowerShell script located in a user Downloads folder was started with the execution policy bypassed.',
    level: 'high',
    source: 'builtin',
    logsource: { product: 'windows', category: 'process_creation' },
    mitre: [{ tactic: 'Execution', technique_id: 'T1059.001', technique: 'PowerShell' }],
    tags: ['attack.execution', 'attack.t1059.001'],
    detection: `selection_img:
  Image|endswith:
    - '\\powershell.exe'
    - '\\pwsh.exe'
selection_cli:
  CommandLine|contains|all:
    - '-ExecutionPolicy Bypass'
    - '\\Downloads\\'
condition: all of selection_*`,
    falsepositives: ['Installers that ship PowerShell helpers and are run from Downloads'],
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    hits: 1,
  },
  {
    id: 'c1d2e3f4-a5b6-47c8-9d0e-1f2a3b4c5d6e',
    title: 'Registry Run Key Set by Script Interpreter',
    description: 'A Run/RunOnce key value that launches a script interpreter was written, a common persistence location.',
    level: 'critical',
    source: 'builtin',
    logsource: { product: 'windows', category: 'registry_set' },
    mitre: [{ tactic: 'Persistence', technique_id: 'T1547.001', technique: 'Registry Run Keys / Startup Folder' }],
    tags: ['attack.persistence', 'attack.t1547.001'],
    detection: `selection_key:
  TargetObject|contains:
    - '\\CurrentVersion\\Run\\'
    - '\\CurrentVersion\\RunOnce\\'
selection_data:
  Details|contains:
    - 'powershell'
    - 'wscript'
    - 'mshta'
condition: all of selection_*`,
    falsepositives: ['Software that registers a PowerShell-based updater'],
    hits: 1,
  },
  {
    id: 'd4c3b2a1-0f9e-4d8c-b7a6-958473625140',
    title: 'Local Account and Group Discovery via net.exe',
    description: 'net.exe or net1.exe was used to list local users or the local administrators group.',
    level: 'medium',
    source: 'builtin',
    logsource: { product: 'windows', category: 'process_creation' },
    mitre: [{ tactic: 'Discovery', technique_id: 'T1087.001', technique: 'Local Account' }],
    tags: ['attack.discovery', 'attack.t1087.001'],
    detection: `selection_img:
  Image|endswith:
    - '\\net.exe'
    - '\\net1.exe'
selection_cli:
  CommandLine|contains:
    - ' user'
    - ' localgroup'
condition: all of selection_*`,
    falsepositives: ['Administrators and inventory scripts'],
    hits: 3,
  },
  {
    id: 'e5f6a7b8-c9d0-41e2-a3b4-c5d6e7f8a9b0',
    title: 'Whoami Execution',
    description: 'whoami.exe was executed. Often part of discovery right after initial access, but also common in admin scripts.',
    level: 'low',
    source: 'builtin',
    logsource: { product: 'windows', category: 'process_creation' },
    mitre: [{ tactic: 'Discovery', technique_id: 'T1033', technique: 'System Owner/User Discovery' }],
    tags: ['attack.discovery', 'attack.t1033'],
    detection: `selection:
  Image|endswith: '\\whoami.exe'
condition: selection`,
    falsepositives: ['Admin and support scripts'],
    hits: 1,
  },
  {
    id: 'f0e1d2c3-b4a5-4697-8879-6a5b4c3d2e1f',
    title: 'Outbound Connection From PowerShell to Public Address',
    description: 'powershell.exe opened an outbound connection to a non-private address.',
    level: 'medium',
    source: 'builtin',
    logsource: { product: 'windows', category: 'network_connection' },
    mitre: [{ tactic: 'Command and Control', technique_id: 'T1071.001', technique: 'Web Protocols' }],
    tags: ['attack.command_and_control', 'attack.t1071.001'],
    detection: `selection:
  Image|endswith: '\\powershell.exe'
  Initiated: 'true'
filter_private:
  DestinationIp|cidr:
    - '10.0.0.0/8'
    - '172.16.0.0/12'
    - '192.168.0.0/16'
condition: selection and not filter_private`,
    falsepositives: ['Module installs from the PowerShell Gallery', 'Windows Update scripts'],
    hits: 2,
  },
  {
    id: '0a1b2c3d-4e5f-4061-8273-94a5b6c7d8e9',
    title: 'Repeated SSH Authentication Failures',
    description: 'Many failed SSH logons from a single source address within a short window.',
    level: 'medium',
    source: 'builtin',
    logsource: { product: 'linux', service: 'auth' },
    mitre: [{ tactic: 'Credential Access', technique_id: 'T1110.001', technique: 'Password Guessing' }],
    tags: ['attack.credential_access', 'attack.t1110.001'],
    detection: `selection:
  event.action: 'ssh-login'
  event.outcome: 'failure'
condition: selection | count() by source.ip > 10
timeframe: 10m`,
    falsepositives: ['Misconfigured automation with a stale key or password'],
    hits: 57,
  },
  {
    id: '1b2c3d4e-5f60-4172-8394-a5b6c7d8e9f0',
    title: 'Suricata Alert: Network Scan',
    description: 'Suricata reported a scanning signature (ET SCAN) at the network edge.',
    level: 'low',
    source: 'builtin',
    logsource: { product: 'suricata' },
    mitre: [{ tactic: 'Discovery', technique_id: 'T1046', technique: 'Network Service Discovery' }],
    tags: ['attack.discovery', 'attack.t1046'],
    detection: `selection:
  event.kind: 'alert'
  rule.name|startswith: 'ET SCAN'
condition: selection`,
    hits: 24,
  },
  {
    id: '2c3d4e5f-6071-4283-94a5-b6c7d8e9f0a1',
    title: 'New Systemd Service Installed',
    description: 'A systemd unit was enabled. Expected during software installs; review unexpected ones.',
    level: 'informational',
    source: 'builtin',
    logsource: { product: 'linux', category: 'file_event' },
    mitre: [{ tactic: 'Persistence', technique_id: 'T1543.002', technique: 'Systemd Service' }],
    tags: ['attack.persistence', 'attack.t1543.002'],
    detection: `selection:
  TargetFilename|startswith: '/etc/systemd/system/'
  TargetFilename|endswith: '.service'
condition: selection`,
    falsepositives: ['Package installs'],
    hits: 1,
  },
  {
    id: '3d4e5f60-7182-4394-a5b6-c7d8e9f0a1b2',
    title: 'Microsoft Defender Real-Time Protection Disabled',
    description: 'Defender reported that real-time protection was turned off (Event ID 5001).',
    level: 'high',
    source: 'builtin',
    logsource: { product: 'windows', service: 'windefend' },
    mitre: [{ tactic: 'Defense Evasion', technique_id: 'T1562.001', technique: 'Disable or Modify Tools' }],
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    detection: `selection:
  EventID: 5001
condition: selection`,
    falsepositives: ['A user turning it off temporarily', 'Third-party antivirus taking over'],
    hits: 0,
  },
  {
    id: '4e5f6071-8293-44a5-b6c7-d8e9f0a1b2c3',
    title: 'Scheduled Task Created From User Temp Directory',
    description: 'schtasks.exe created a task whose action points into a user temp directory.',
    level: 'high',
    source: 'builtin',
    enabled: false,
    logsource: { product: 'windows', category: 'process_creation' },
    mitre: [{ tactic: 'Persistence', technique_id: 'T1053.005', technique: 'Scheduled Task' }],
    tags: ['attack.persistence', 'attack.t1053.005'],
    detection: `selection:
  Image|endswith: '\\schtasks.exe'
  CommandLine|contains|all:
    - '/create'
    - '\\AppData\\Local\\Temp\\'
condition: selection`,
    hits: 0,
  },
  {
    id: '5f607182-93a4-45b6-c7d8-e9f0a1b2c3d4',
    title: 'Custom: Docker Socket Mounted Into Container',
    description: 'A container was started with /var/run/docker.sock mounted, which gives it control of the host.',
    level: 'medium',
    source: 'custom',
    author: 'admin',
    logsource: { product: 'linux', category: 'process_creation' },
    mitre: [{ tactic: 'Privilege Escalation', technique_id: 'T1611', technique: 'Escape to Host' }],
    tags: ['attack.privilege_escalation', 'attack.t1611', 'homelab'],
    detection: `selection:
  Image|endswith: '/docker'
  CommandLine|contains|all:
    - ' run '
    - '/var/run/docker.sock'
condition: selection`,
    falsepositives: ['Portainer, Watchtower and similar management containers'],
    hits: 0,
  },
]

export const rules: Rule[] = seeds.map((s, i) => ({
  id: s.id,
  title: s.title,
  description: s.description,
  status: s.source === 'custom' ? 'experimental' : 'stable',
  level: s.level,
  enabled: s.enabled ?? true,
  source: s.source,
  tags: s.tags,
  author: s.author ?? 'HomeXDR',
  references: s.references,
  logsource: s.logsource,
  mitre: s.mitre,
  hits_24h: s.hits,
  updated_at: ago(s.source === 'custom' ? 3 * DAY : 20 * DAY + i * HOUR),
  yaml: toYaml(s),
}))

export const ruleById = (id: string) => rules.find((r) => r.id === id)
export const RULE = {
  psBypass: seeds[0].id,
  runKey: seeds[1].id,
  netDiscovery: seeds[2].id,
  whoami: seeds[3].id,
  psOutbound: seeds[4].id,
  sshBrute: seeds[5].id,
  suricataScan: seeds[6].id,
  systemd: seeds[7].id,
  defender: seeds[8].id,
}

/** Minimal YAML checks for the mock validator. */
export function parseRuleYaml(yaml: string): { ok: true; rule: Rule } | { ok: false; error: string } {
  const get = (key: string) => {
    const m = new RegExp(`^${key}:[ \\t]*(.*)$`, 'm').exec(yaml)
    return m ? m[1].trim() : undefined
  }
  if (/^\t/m.test(yaml)) return { ok: false, error: 'yaml: tabs are not allowed for indentation' }
  const title = get('title')
  if (!title) return { ok: false, error: 'rule: missing required field "title"' }
  if (get('logsource') === undefined) return { ok: false, error: 'rule: missing required field "logsource"' }
  if (get('detection') === undefined) return { ok: false, error: 'rule: missing required field "detection"' }
  if (!/^\s+condition:/m.test(yaml)) return { ok: false, error: 'detection: missing "condition"' }
  const level = (get('level') ?? 'medium') as Severity
  if (!['critical', 'high', 'medium', 'low', 'informational'].includes(level)) {
    return { ok: false, error: `rule: invalid level "${level}"` }
  }
  const block = (name: string) => {
    const m = new RegExp(`^${name}:\\s*\\n((?:[ \\t]+.*\\n?)*)`, 'm').exec(yaml)
    return m ? m[1] : ''
  }
  const logsource: Rule['logsource'] = {}
  for (const line of block('logsource').split('\n')) {
    const m = /^\s+(product|category|service):\s*(.+)$/.exec(line)
    if (m) logsource[m[1] as 'product'] = m[2].trim()
  }
  const tags = block('tags')
    .split('\n')
    .map((l) => l.replace(/^\s*-\s*/, '').trim())
    .filter(Boolean)
  const mitre: MitreMapping[] = tags
    .filter((t) => /^attack\.t\d{4}/i.test(t))
    .map((t) => ({ technique_id: t.slice(7).toUpperCase() }))
  const id = get('id') ?? uuid()
  return {
    ok: true,
    rule: {
      id,
      title,
      description: get('description'),
      status: get('status') ?? 'experimental',
      level,
      enabled: true,
      source: 'custom',
      tags,
      author: get('author'),
      logsource,
      mitre,
      hits_24h: 0,
      updated_at: new Date().toISOString(),
      yaml,
    },
  }
}

/** Literal strings from a rule's detection block, used by the mock "test" endpoint. */
export function detectionNeedles(yaml: string): string[] {
  const m = /^detection:\s*\n((?:[ \t]+.*\n?)*)/m.exec(yaml)
  if (!m) return []
  const out: string[] = []
  for (const line of m[1].split('\n')) {
    if (/^\s*(condition|timeframe):/.test(line)) continue
    const v = /(?:-\s*|:\s+)'([^']+)'|(?:-\s*|:\s+)"([^"]+)"/.exec(line)
    const val = v ? (v[1] ?? v[2]) : undefined
    if (val && val.length >= 3) out.push(val.replace(/\\\\/g, '\\').replace(/\*/g, '').toLowerCase())
  }
  return out
}
