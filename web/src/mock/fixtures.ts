// Alerts, commands, hunts, artifacts and admin fixtures for mock mode.

import type {
  AgentConfig,
  Alert,
  ArtifactDef,
  AuditEntry,
  CommandRecord,
  EnrollmentToken,
  Event,
  Hunt,
  HuntResultRow,
  Integrations,
  Row,
  ServerSettings,
  Severity,
  User,
} from '../api/types'
import { SEVERITY_RISK } from '../lib/severity'
import {
  defenderEvent,
  events,
  scenarioConnect,
  scenarioRegistry,
  sshFailures,
  suricataAlerts,
  wNetGroup,
  wNetUser,
  wPowershell,
  wReg,
  wWhoami,
  lSshd,
} from './events'
import { DAY, FW_ID, HOUR, LAPTOP_ID, LINUX_ID, MIN, NOW, PI_ID, SEC, WIN_ID, ago, hostById, hosts } from './hosts'
import { hex, makeId, mulberry32 } from './rng'
import { RULE, ruleById } from './rules'

const r = mulberry32(0xa1e27)

// --- users ------------------------------------------------------------------------------

export const users: User[] = [
  { id: makeId(NOW - 40 * DAY, r), username: 'admin', role: 'admin', created_at: ago(40 * DAY), last_login: ago(2 * HOUR) },
  { id: makeId(NOW - 35 * DAY, r), username: 'sam', role: 'analyst', created_at: ago(35 * DAY), last_login: ago(3 * DAY) },
  { id: makeId(NOW - 10 * DAY, r), username: 'guest', role: 'viewer', created_at: ago(10 * DAY) },
]

// --- alerts -----------------------------------------------------------------------------

function findStartEvent(entityId: string): Event | undefined {
  return events.find((e) => e.process?.entity_id === entityId && e.event.type?.includes('start') && e.event.category?.includes('process'))
}

function alert(opts: {
  rule: string
  hostId: string
  events: Event[]
  status?: Alert['status']
  assignee?: string
  count?: number
  notes?: Alert['notes']
  severity?: Severity
}): Alert {
  const rule = ruleById(opts.rule)!
  const first = opts.events[opts.events.length - 1] ?? opts.events[0]
  const last = opts.events[0]
  const ev = opts.events[0]
  const host = hostById(opts.hostId)!
  const severity = opts.severity ?? rule.level
  return {
    id: makeId(Date.parse(first['@timestamp']) + 2000, r),
    created_at: first['@timestamp'],
    updated_at: opts.notes?.length ? opts.notes[opts.notes.length - 1].at : last['@timestamp'],
    first_seen: first['@timestamp'],
    last_seen: last['@timestamp'],
    count: opts.count ?? opts.events.length,
    status: opts.status ?? 'new',
    severity,
    risk_score: SEVERITY_RISK[severity],
    assignee: opts.assignee,
    rule: {
      id: rule.id,
      title: rule.title,
      description: rule.description,
      level: rule.level,
      tags: rule.tags,
      references: rule.references,
      false_positives: rule.yaml?.includes('falsepositives') ? rule.yaml.split('falsepositives:\n')[1]?.split('\nlevel')[0].split('\n').map((l) => l.replace(/^\s*-\s*/, '')).filter(Boolean) : undefined,
    },
    mitre: rule.mitre,
    host_id: host.id,
    hostname: host.hostname,
    process_entity_id: ev.process?.entity_id,
    process_name: ev.process?.name,
    command_line: ev.process?.command_line,
    user: ev.user?.name ?? ev.process?.user?.name,
    event_ids: opts.events.map((e) => e.id),
    event: ev,
    notes: opts.notes ?? [],
  }
}

const psStart = findStartEvent(wPowershell.entity_id)!
const regStart = findStartEvent(wReg.entity_id)!

export const alerts: Alert[] = [
  alert({ rule: RULE.runKey, hostId: WIN_ID, events: [scenarioRegistry] }),
  alert({ rule: RULE.psBypass, hostId: WIN_ID, events: [psStart] }),
  alert({
    rule: RULE.netDiscovery,
    hostId: WIN_ID,
    events: [findStartEvent(wNetGroup.entity_id)!, findStartEvent(wNetUser.entity_id)!],
  }),
  alert({
    rule: RULE.whoami,
    hostId: WIN_ID,
    events: [findStartEvent(wWhoami.entity_id)!],
    status: 'in_progress',
    assignee: 'admin',
    notes: [{ author: 'admin', text: 'Part of the printer-setup script chain. Checking where the script came from.', at: ago(70 * MIN) }],
  }),
  alert({ rule: RULE.psOutbound, hostId: WIN_ID, events: [scenarioConnect], count: 2 }),
  alert({ rule: RULE.sshBrute, hostId: LINUX_ID, events: [...sshFailures].reverse(), count: sshFailures.length }),
  alert({
    rule: RULE.suricataScan,
    hostId: FW_ID,
    events: suricataAlerts.slice(0, 20),
    count: suricataAlerts.length,
    status: 'resolved',
    assignee: 'sam',
    notes: [{ author: 'sam', text: 'Internet background scanning, blocked at the edge. Nothing exposed on 22.', at: ago(5 * HOUR) }],
  }),
  alert({
    rule: RULE.systemd,
    hostId: LINUX_ID,
    events: [events.find((e) => e.service?.name === 'prometheus-node-exporter.service')!],
    status: 'false_positive',
    assignee: 'admin',
    notes: [{ author: 'admin', text: 'Expected: I installed node-exporter for Grafana.', at: ago(2 * HOUR + 50 * MIN) }],
  }),
  alert({ rule: RULE.defender, hostId: LAPTOP_ID, events: [defenderEvent], status: 'in_progress', assignee: 'sam' }),
]
// Keep the reg.exe start event referenced so its alert-count shows in the tree too.
alerts[0].process_entity_id = wReg.entity_id
alerts[0].process_name = wReg.name
alerts[0].command_line = wReg.command_line
alerts[0].event_ids = [scenarioRegistry.id, regStart.id]

alerts.sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1))

export function recomputeOpenAlerts() {
  for (const h of hosts) {
    h.open_alerts = alerts.filter((a) => a.host_id === h.id && (a.status === 'new' || a.status === 'in_progress')).length
  }
}
recomputeOpenAlerts()

// --- artifacts (mirrors shared/api/artifacts.go) -----------------------------------------

const allPlatforms = ['windows', 'linux', 'darwin']
export const artifacts: ArtifactDef[] = [
  { name: 'system.info', description: 'Host details: OS, kernel, uptime, CPU, memory, domain membership.', platforms: allPlatforms, columns: ['hostname', 'os_name', 'os_version', 'kernel', 'arch', 'boot_time', 'cpus', 'memory_bytes', 'domain'] },
  {
    name: 'process.list',
    description: 'Running processes with parent, user, command line and executable hash.',
    platforms: allPlatforms,
    params: [{ name: 'hash', type: 'bool', default: 'true', description: 'Compute SHA-256 of each executable.' }],
    columns: ['pid', 'ppid', 'entity_id', 'name', 'executable', 'command_line', 'user', 'start', 'sha256'],
  },
  { name: 'network.connections', description: 'Open sockets (listening and established) with owning process.', platforms: allPlatforms, columns: ['transport', 'state', 'local_ip', 'local_port', 'remote_ip', 'remote_port', 'pid', 'process_name', 'community_id'] },
  { name: 'users.list', description: 'Local user accounts and their group memberships.', platforms: allPlatforms, columns: ['name', 'id', 'groups', 'shell', 'home', 'disabled', 'admin', 'last_logon'] },
  { name: 'users.sessions', description: 'Currently logged-on users and sessions.', platforms: allPlatforms, columns: ['user', 'session', 'type', 'source_ip', 'started'] },
  {
    name: 'persistence.autoruns',
    description:
      'Autostart locations: Run/RunOnce keys, services, scheduled tasks and startup folders on Windows; cron, systemd units, rc.local, shell profiles, ld.so.preload and authorized_keys on Linux; LaunchAgents/LaunchDaemons on macOS.',
    platforms: allPlatforms,
    columns: ['type', 'location', 'name', 'command', 'user', 'enabled', 'sha256', 'signed'],
  },
  { name: 'services.list', description: 'Installed services with start type, state and binary path.', platforms: allPlatforms, columns: ['name', 'display_name', 'state', 'start_type', 'path', 'account'] },
  { name: 'software.list', description: 'Installed software packages.', platforms: allPlatforms, columns: ['name', 'version', 'vendor', 'type', 'install_date'] },
  {
    name: 'file.find',
    description: 'Find files under a directory by glob, optionally hashing them.',
    platforms: allPlatforms,
    params: [
      { name: 'root', type: 'string', required: true, description: 'Directory to search.' },
      { name: 'glob', type: 'string', default: '*', description: 'File name pattern, e.g. *.exe' },
      { name: 'max_depth', type: 'int', default: '5', description: 'Maximum directory depth.' },
      { name: 'hash', type: 'bool', default: 'false', description: 'Compute SHA-256.' },
      { name: 'max_results', type: 'int', default: '1000', description: 'Stop after this many matches.' },
    ],
    columns: ['path', 'size', 'mtime', 'mode', 'owner', 'sha256'],
  },
  { name: 'kernel.modules', description: 'Loaded kernel modules (Linux) or drivers (Windows).', platforms: ['windows', 'linux'], columns: ['name', 'path', 'size', 'signed', 'state'] },
]

/** Plausible artifact rows for a host. */
export function artifactRows(name: string, hostId: string, params: Record<string, string> = {}): Row[] {
  const h = hostById(hostId)!
  const win = h.os.platform === 'windows'
  switch (name) {
    case 'system.info':
      return [{ hostname: h.hostname, os_name: h.os.name, os_version: h.os.version, kernel: h.os.kernel ?? '', arch: h.arch, boot_time: h.boot_time, cpus: h.cpus, memory_bytes: h.memory_bytes, domain: win ? 'WORKGROUP' : '' }]
    case 'process.list':
      return events
        .filter((e) => e.host.id === hostId && e.event.type?.includes('start') && e.process)
        .slice(0, 14)
        .map((e) => ({
          pid: e.process!.pid,
          ppid: e.process!.parent?.pid ?? 0,
          entity_id: e.process!.entity_id,
          name: e.process!.name,
          executable: e.process!.executable,
          command_line: e.process!.command_line,
          user: e.process!.user?.name,
          start: e.process!.start,
          sha256: params.hash === 'false' ? '' : e.process!.hash?.sha256,
        }))
    case 'network.connections':
      return [
        { transport: 'tcp', state: 'LISTEN', local_ip: '0.0.0.0', local_port: win ? 135 : 22, remote_ip: '', remote_port: 0, pid: win ? 1104 : lSshd.pid, process_name: win ? 'svchost.exe' : 'sshd', community_id: '' },
        { transport: 'tcp', state: 'ESTABLISHED', local_ip: h.ips[0], local_port: 52114, remote_ip: '203.0.113.10', remote_port: 443, pid: 4410, process_name: win ? 'chrome.exe' : 'dockerd', community_id: '1:LQU9qZlK+B5F3KDmev6m5PMibrg=' },
        { transport: 'udp', state: '', local_ip: '0.0.0.0', local_port: 5353, remote_ip: '', remote_port: 0, pid: 2080, process_name: win ? 'svchost.exe' : 'avahi-daemon', community_id: '' },
      ]
    case 'users.list':
      return win
        ? [
            { name: 'alex', id: 'S-1-5-21-3623811015-3361044348-30300820-1001', groups: 'Administrators, Users', shell: '', home: 'C:\\Users\\alex', disabled: false, admin: true, last_logon: ago(2 * DAY) },
            { name: 'Guest', id: 'S-1-5-21-3623811015-3361044348-30300820-501', groups: 'Guests', shell: '', home: '', disabled: true, admin: false, last_logon: '' },
          ]
        : [
            { name: 'root', id: '0', groups: 'root', shell: '/bin/bash', home: '/root', disabled: false, admin: true, last_logon: '' },
            { name: 'admin', id: '1000', groups: 'admin, sudo, docker', shell: '/bin/bash', home: '/home/admin', disabled: false, admin: true, last_logon: ago(3 * HOUR) },
          ]
    case 'users.sessions':
      return win
        ? [{ user: 'alex', session: '1', type: 'console', source_ip: '', started: ago(2 * DAY) }]
        : [{ user: 'admin', session: 'pts/0', type: 'ssh', source_ip: '192.168.1.42', started: ago(3 * HOUR) }]
    case 'persistence.autoruns':
      return win
        ? [
            { type: 'registry', location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'OneDrive', command: '"C:\\Users\\alex\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', user: 'alex', enabled: true, sha256: hex(64, r), signed: true },
            { type: 'registry', location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'PrinterHelper', command: 'powershell.exe -WindowStyle Hidden -File C:\\Users\\alex\\AppData\\Roaming\\PrinterHelper\\helper.ps1', user: 'alex', enabled: true, sha256: hex(64, r), signed: false },
            { type: 'service', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Services', name: 'HomeXDR Agent', command: '"C:\\Program Files\\HomeXDR\\homexdr-agent.exe" run', user: 'LocalSystem', enabled: true, sha256: hex(64, r), signed: true },
            { type: 'scheduled_task', location: '\\Microsoft\\Windows\\Defrag', name: 'ScheduledDefrag', command: '%windir%\\system32\\defrag.exe -c -h -o -$', user: 'SYSTEM', enabled: true, sha256: hex(64, r), signed: true },
          ]
        : [
            { type: 'systemd', location: '/etc/systemd/system/multi-user.target.wants', name: 'prometheus-node-exporter.service', command: '/usr/bin/prometheus-node-exporter', user: 'prometheus', enabled: true, sha256: hex(64, r), signed: '' },
            { type: 'systemd', location: '/etc/systemd/system/multi-user.target.wants', name: 'homexdr-agent.service', command: '/usr/bin/homexdr-agent run', user: 'root', enabled: true, sha256: hex(64, r), signed: '' },
            { type: 'cron', location: '/etc/cron.d/restic', name: 'restic', command: '0 3 * * * root restic backup /srv/data --tag nightly', user: 'root', enabled: true, sha256: '', signed: '' },
            { type: 'authorized_keys', location: '/home/admin/.ssh/authorized_keys', name: 'alex@DESKTOP-7QK2M4', command: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL4x…', user: 'admin', enabled: true, sha256: '', signed: '' },
          ]
    case 'services.list':
      return win
        ? [
            { name: 'WinDefend', display_name: 'Microsoft Defender Antivirus Service', state: 'running', start_type: 'auto', path: '"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.25080.5-0\\MsMpEng.exe"', account: 'LocalSystem' },
            { name: 'HomeXDRAgent', display_name: 'HomeXDR Agent', state: 'running', start_type: 'auto', path: '"C:\\Program Files\\HomeXDR\\homexdr-agent.exe" run', account: 'LocalSystem' },
            { name: 'Spooler', display_name: 'Print Spooler', state: 'running', start_type: 'auto', path: 'C:\\Windows\\System32\\spoolsv.exe', account: 'LocalSystem' },
          ]
        : [
            { name: 'docker.service', display_name: 'Docker Application Container Engine', state: 'running', start_type: 'enabled', path: '/usr/bin/dockerd', account: 'root' },
            { name: 'ssh.service', display_name: 'OpenBSD Secure Shell server', state: 'running', start_type: 'enabled', path: '/usr/sbin/sshd', account: 'root' },
            { name: 'homexdr-agent.service', display_name: 'HomeXDR Agent', state: 'running', start_type: 'enabled', path: '/usr/bin/homexdr-agent', account: 'root' },
          ]
    case 'software.list':
      return win
        ? [
            { name: 'Google Chrome', version: '141.0.7390.66', vendor: 'Google LLC', type: 'msi', install_date: '2025-02-11' },
            { name: 'Microsoft Visual Studio Code', version: '1.105.1', vendor: 'Microsoft Corporation', type: 'winget', install_date: '2025-03-02' },
            { name: 'Git', version: '2.51.0', vendor: 'The Git Development Community', type: 'winget', install_date: '2025-03-02' },
            { name: 'Steam', version: '2.10.91.91', vendor: 'Valve Corporation', type: 'exe', install_date: '2025-01-19' },
          ]
        : [
            { name: 'docker-ce', version: '5:28.5.1-1~ubuntu.24.04~noble', vendor: 'Docker Inc.', type: 'deb', install_date: '2025-09-01' },
            { name: 'openssh-server', version: '1:9.6p1-3ubuntu13.5', vendor: 'Ubuntu', type: 'deb', install_date: '2025-06-12' },
            { name: 'prometheus-node-exporter', version: '1.7.0-1ubuntu0.3', vendor: 'Ubuntu', type: 'deb', install_date: new Date(NOW - 3 * HOUR).toISOString().slice(0, 10) },
          ]
    case 'file.find': {
      const root = params.root || (win ? 'C:\\Users' : '/home')
      const sep = win ? '\\' : '/'
      const names = win ? ['printer-setup-v2.4.1-x64-unattended-installer-helper.ps1', 'report.docx', 'photo.jpg', 'tool.zip'] : ['backup.tar.gz', 'compose.yaml', 'notes.md']
      return names.map((n, i) => ({ path: `${root}${root.endsWith(sep) ? '' : sep}${n}`, size: 1024 * (i + 3) * 17, mtime: ago((i + 1) * 9 * HOUR), mode: win ? '' : '0644', owner: win ? 'alex' : 'admin', sha256: params.hash === 'true' ? hex(64, r) : '' }))
    }
    case 'kernel.modules':
      return win
        ? [
            { name: 'WdFilter', path: 'C:\\Windows\\system32\\drivers\\wd\\WdFilter.sys', size: 512000, signed: true, state: 'running' },
            { name: 'tcpip', path: 'C:\\Windows\\System32\\drivers\\tcpip.sys', size: 3200000, signed: true, state: 'running' },
          ]
        : [
            { name: 'overlay', path: '/lib/modules/6.8.0-45-generic/kernel/fs/overlayfs/overlay.ko.zst', size: 151552, signed: true, state: 'live' },
            { name: 'br_netfilter', path: '/lib/modules/6.8.0-45-generic/kernel/net/bridge/br_netfilter.ko.zst', size: 32768, signed: true, state: 'live' },
          ]
    default:
      return []
  }
}

// --- commands ---------------------------------------------------------------------------

export interface MockCommand extends CommandRecord {
  /** Mock-only: how the lifecycle should end. */
  _outcome?: 'completed' | 'failed' | 'rejected'
  _rows?: Row[]
  _file?: string
}

function cmd(c: Partial<MockCommand> & Pick<MockCommand, 'host_id' | 'type' | 'params' | 'status' | 'issued_at'>): MockCommand {
  const h = hostById(c.host_id)!
  const issued = Date.parse(c.issued_at)
  return {
    id: makeId(issued, r),
    hostname: h.hostname,
    issued_by: 'admin',
    expires_at: new Date(issued + HOUR).toISOString(),
    delivered_at: c.status === 'queued' ? undefined : new Date(issued + 800).toISOString(),
    completed_at: ['completed', 'failed', 'rejected'].includes(c.status) ? new Date(issued + 4 * SEC).toISOString() : undefined,
    ...c,
  }
}

export const commands: MockCommand[] = []
{
  const rows = artifactRows('process.list', WIN_ID, { hash: 'true' })
  commands.push(
    cmd({ host_id: WIN_ID, type: 'artifact.collect', params: { name: 'process.list', params: { hash: 'true' } }, status: 'completed', issued_at: ago(80 * MIN), row_count: rows.length, _rows: rows, output: { rows: rows.length } }),
    cmd({
      host_id: WIN_ID,
      type: 'file.hash',
      params: { path: 'C:\\Users\\alex\\AppData\\Roaming\\PrinterHelper\\helper.ps1' },
      status: 'completed',
      issued_at: ago(78 * MIN),
      output: { path: 'C:\\Users\\alex\\AppData\\Roaming\\PrinterHelper\\helper.ps1', size: 4182, md5: hex(32, r), sha1: hex(40, r), sha256: hex(64, r) },
    }),
    cmd({
      host_id: WIN_ID,
      type: 'file.get',
      params: { path: 'C:\\Users\\alex\\AppData\\Roaming\\PrinterHelper\\helper.ps1' },
      status: 'completed',
      issued_at: ago(76 * MIN),
      output: { path: 'C:\\Users\\alex\\AppData\\Roaming\\PrinterHelper\\helper.ps1', size: 4182, md5: hex(32, r), sha1: hex(40, r), sha256: hex(64, r) },
      _file: '# Mock file content for helper.ps1 (HomeXDR mock mode)\r\nWrite-Output "printer helper"\r\n',
    }),
    cmd({ host_id: LINUX_ID, type: 'file.get', params: { path: '/var/log/auth.log' }, status: 'rejected', issued_at: ago(40 * MIN), error: 'rejected by local policy: file.get is not in allowed_actions', issued_by: 'sam' }),
    cmd({ host_id: LINUX_ID, type: 'artifact.collect', params: { name: 'users.sessions' }, status: 'completed', issued_at: ago(30 * MIN), row_count: 1, _rows: artifactRows('users.sessions', LINUX_ID), hunt_id: undefined }),
    cmd({ host_id: PI_ID, type: 'host.isolate', params: { allow: ['192.168.1.10'] }, status: 'completed', issued_at: ago(5 * HOUR), output: {} }),
    cmd({ host_id: LAPTOP_ID, type: 'artifact.collect', params: { name: 'system.info' }, status: 'expired', issued_at: ago(DAY + 2 * HOUR), issued_by: 'sam' }),
    cmd({ host_id: LAPTOP_ID, type: 'process.kill', params: { pid: 7712, tree: false }, status: 'queued', issued_at: ago(20 * MIN), issued_by: 'sam' }),
  )
  commands.sort((a, b) => (a.issued_at < b.issued_at ? 1 : -1))
}

// --- hunts ------------------------------------------------------------------------------

export interface MockHunt extends Hunt {
  _rows: HuntResultRow[]
}

function huntRows(name: string, hostIds: string[], params?: Record<string, string>): HuntResultRow[] {
  return hostIds.flatMap((id) => artifactRows(name, id, params).map((row) => ({ host_id: id, hostname: hostById(id)!.hostname, row })))
}

export const hunts: MockHunt[] = [
  (() => {
    const rows = huntRows('persistence.autoruns', [WIN_ID, LINUX_ID, PI_ID])
    return {
      id: makeId(NOW - 70 * MIN, r),
      artifact: 'persistence.autoruns',
      params: {},
      description: 'Autoruns sweep after the PrinterHelper alert',
      target: { all: true },
      status: 'running',
      created_by: 'admin',
      created_at: ago(70 * MIN),
      expires_at: new Date(NOW + 7 * DAY - 70 * MIN).toISOString(),
      stats: { scheduled: 4, completed: 3, failed: 0, rows: rows.length },
      _rows: rows,
    }
  })(),
  (() => {
    const rows = huntRows('users.list', [LINUX_ID, PI_ID])
    return {
      id: makeId(NOW - 2 * DAY, r),
      artifact: 'users.list',
      params: {},
      description: 'Local accounts on servers',
      target: { labels: ['server', 'iot'] },
      status: 'completed',
      created_by: 'sam',
      created_at: ago(2 * DAY),
      expires_at: ago(DAY),
      stats: { scheduled: 2, completed: 2, failed: 0, rows: rows.length },
      _rows: rows,
    }
  })(),
  (() => {
    const rows = huntRows('software.list', [WIN_ID])
    return {
      id: makeId(NOW - 5 * DAY, r),
      artifact: 'software.list',
      params: {},
      target: { platform: 'windows' },
      status: 'stopped',
      created_by: 'admin',
      created_at: ago(5 * DAY),
      expires_at: ago(4 * DAY),
      stats: { scheduled: 2, completed: 1, failed: 1, rows: rows.length },
      _rows: rows,
    }
  })(),
]

// --- settings ---------------------------------------------------------------------------

export const serverSettings: ServerSettings = {
  version: '0.1.0-dev',
  agent_url: 'https://homexdr.lan:8443',
  ca_pin: 'sha256:' + hex(64, mulberry32(42)),
  server_names: ['homexdr.lan', '192.168.1.10'],
  event_store: 'clickhouse',
  retention_days: 0,
  retention_max_bytes: 1e12,
  event_store_bytes: 48_300_000_000,
  syslog_addr: ':5514',
  update_key: 'ed25519:' + btoa(hex(32, mulberry32(7))).slice(0, 43) + '=',
  agent_release: { version: '0.1.0-dev', signed: true },
}

export const tokens: EnrollmentToken[] = [
  { id: makeId(NOW - 40 * DAY, r), name: 'homelab-servers', created_at: ago(40 * DAY), created_by: 'admin', max_uses: 5, uses: 2, labels: ['server'] },
  { id: makeId(NOW - 14 * DAY, r), name: 'family-laptops', created_at: ago(14 * DAY), created_by: 'admin', expires_at: new Date(NOW + 3 * DAY).toISOString(), uses: 2, labels: ['family'] },
  { id: makeId(NOW - 60 * DAY, r), name: 'initial-test', created_at: ago(60 * DAY), created_by: 'admin', expires_at: ago(59 * DAY), max_uses: 1, uses: 1, labels: [] },
]

export const agentConfig: AgentConfig = {
  version: 3,
  heartbeat_interval_sec: 30,
  inventory_interval_sec: 6 * 3600,
  batch: { max_events: 500, flush_interval_ms: 2000 },
  sensors: {
    process: { enabled: true, hash_executables: true },
    network: { enabled: true },
    file: { enabled: true, exclude: ['**/node_modules/**', '/var/lib/docker/overlay2/**'] },
    registry: { enabled: true },
    dns: { enabled: true },
    library: { enabled: false },
    auth: { enabled: true },
    eventlog: {
      enabled: true,
      channels: [
        'Security',
        'System',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
      ],
    },
  },
  fim: { enabled: true, paths: ['/etc', '/usr/local/bin', 'C:\\Windows\\System32\\drivers\\etc'], interval_sec: 3600, max_file_size: 64 << 20 },
  logs: [{ path: '/var/log/nginx/access.log', format: 'raw', dataset: 'nginx.access' }],
  filters: [{ category: 'network', field: 'process.executable', op: 'suffix', value: '\\steam.exe' }],
  spool_max_bytes: 512 << 20,
}

export const audit: AuditEntry[] = [
  { id: makeId(NOW - 20 * MIN, r), at: ago(20 * MIN), user: 'sam', action: 'command.create', target: 'laptop-sam', details: { type: 'process.kill', pid: 7712 } },
  { id: makeId(NOW - 40 * MIN, r), at: ago(40 * MIN), user: 'sam', action: 'command.create', target: 'srv-docker01', details: { type: 'file.get', path: '/var/log/auth.log' } },
  { id: makeId(NOW - 70 * MIN, r), at: ago(70 * MIN), user: 'admin', action: 'hunt.create', target: 'persistence.autoruns', details: { target: { all: true } } },
  { id: makeId(NOW - 76 * MIN, r), at: ago(76 * MIN), user: 'admin', action: 'command.create', target: 'DESKTOP-7QK2M4', details: { type: 'file.get' } },
  { id: makeId(NOW - 2 * HOUR, r), at: ago(2 * HOUR), user: 'admin', action: 'auth.login', target: 'admin', details: { ip: '192.168.1.42' } },
  { id: makeId(NOW - 3 * DAY, r), at: ago(3 * DAY), user: 'admin', action: 'rule.create', target: 'Custom: Docker Socket Mounted Into Container', details: null },
  { id: makeId(NOW - 5 * HOUR, r), at: ago(5 * HOUR), user: 'admin', action: 'command.create', target: 'pi-media', details: { type: 'host.isolate', allow: ['192.168.1.10'] } },
  { id: makeId(NOW - 14 * DAY, r), at: ago(14 * DAY), user: 'admin', action: 'token.create', target: 'family-laptops', details: { expires_hours: 408 } },
  { id: makeId(NOW - 20 * DAY, r), at: ago(20 * DAY), user: 'admin', action: 'agent_config.update', target: 'default', details: { version: 3 } },
].sort((a, b) => (a.at < b.at ? 1 : -1))

export const integrations: Integrations = {
  syslog: {
    listening: true,
    addr: ':5514',
    received: 184233,
    parsed: 183901,
    failed: 332,
    sources: [
      { ip: '192.168.1.1', name: 'fw-opnsense', kind: 'opnsense', last_seen: ago(3 * SEC), count: 171022 },
      { ip: '192.168.1.1', name: 'suricata', kind: 'suricata', last_seen: ago(4 * MIN), count: 12877 },
      { ip: '192.168.1.5', name: 'switch-core', kind: 'syslog', last_seen: ago(DAY + 2 * HOUR), count: 334 },
    ],
  },
}
