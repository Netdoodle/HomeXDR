// Mock hosts. Addresses use private and documentation ranges only.

import type { Host } from '../api/types'
import { COMMAND_TYPES } from '../api/types'
import { makeId, NOW } from './rng'

export { NOW }
export const SEC = 1000
export const MIN = 60 * SEC
export const HOUR = 60 * MIN
export const DAY = 24 * HOUR
export const ago = (ms: number) => new Date(NOW - ms).toISOString()

export const WIN_ID = makeId(NOW - 21 * DAY)
export const LINUX_ID = makeId(NOW - 40 * DAY)
export const FW_ID = makeId(NOW - 40 * DAY + 5 * MIN)
export const LAPTOP_ID = makeId(NOW - 14 * DAY)
export const PI_ID = makeId(NOW - 30 * DAY)

export const hosts: Host[] = [
  {
    id: WIN_ID,
    hostname: 'DESKTOP-7QK2M4',
    kind: 'endpoint',
    os: { platform: 'windows', family: 'windows', name: 'Windows 11 Pro', version: '10.0.26200', kernel: '10.0.26200.6584' },
    arch: 'amd64',
    ips: ['192.168.1.42', 'fe80::1c2b:3aff:fe11:9c2d'],
    macs: ['3c:7c:3f:1a:22:9e'],
    agent_version: '0.1.0',
    status: 'online',
    isolated: false,
    last_seen: ago(12 * SEC),
    enrolled_at: ago(21 * DAY),
    labels: ['workstation', 'family'],
    sensors: [
      { name: 'process', impl: 'etw', state: 'running', events: 48211 },
      { name: 'network', impl: 'etw', state: 'running', events: 210554 },
      { name: 'file', impl: 'etw', state: 'running', events: 98113 },
      { name: 'registry', impl: 'etw', state: 'running', events: 30122 },
      { name: 'dns', impl: 'etw', state: 'running', events: 61907 },
      { name: 'library', impl: 'etw', state: 'disabled', events: 0 },
      { name: 'auth', impl: 'eventlog', state: 'running', events: 1840 },
      { name: 'eventlog', impl: 'eventlog', state: 'running', events: 22561 },
    ],
    queue_events: 0,
    allowed_actions: [...COMMAND_TYPES],
    open_alerts: 0,
    boot_time: ago(2 * DAY + 3 * HOUR),
    cpus: 16,
    memory_bytes: 32 * 1024 ** 3,
  },
  {
    id: LINUX_ID,
    hostname: 'srv-docker01',
    kind: 'endpoint',
    os: { platform: 'linux', family: 'debian', name: 'Ubuntu', version: '24.04.1 LTS', kernel: '6.8.0-45-generic' },
    arch: 'amd64',
    ips: ['192.168.1.20', '172.17.0.1'],
    macs: ['52:54:00:8b:11:02'],
    agent_version: '0.1.0',
    status: 'online',
    isolated: false,
    last_seen: ago(8 * SEC),
    enrolled_at: ago(40 * DAY),
    labels: ['server', 'docker'],
    sensors: [
      { name: 'process', impl: 'ebpf', state: 'running', events: 402118 },
      { name: 'network', impl: 'ebpf', state: 'running', events: 1203311 },
      {
        name: 'file',
        impl: 'fanotify',
        state: 'degraded',
        error: 'fanotify: FAN_REPORT_FID not supported on overlayfs; container paths are not watched',
        events: 55120,
      },
      { name: 'dns', impl: 'ebpf', state: 'running', events: 88410 },
      { name: 'auth', impl: 'authlog', state: 'running', events: 9133 },
    ],
    queue_events: 0,
    // Local policy on this server does not allow file uploads.
    allowed_actions: COMMAND_TYPES.filter((t) => t !== 'file.get'),
    open_alerts: 0,
    boot_time: ago(17 * DAY),
    cpus: 8,
    memory_bytes: 64 * 1024 ** 3,
  },
  {
    id: FW_ID,
    hostname: 'fw-opnsense',
    kind: 'network',
    os: { platform: 'network', family: 'freebsd', name: 'OPNsense', version: '24.7.6' },
    ips: ['192.168.1.1'],
    status: 'online',
    isolated: false,
    last_seen: ago(3 * SEC),
    enrolled_at: ago(40 * DAY),
    labels: ['network', 'edge'],
    allowed_actions: [],
    open_alerts: 0,
  },
  {
    id: LAPTOP_ID,
    hostname: 'laptop-sam',
    kind: 'endpoint',
    os: { platform: 'windows', family: 'windows', name: 'Windows 10 Home', version: '10.0.19045' },
    arch: 'amd64',
    ips: ['192.168.1.57'],
    agent_version: '0.1.0',
    status: 'offline',
    isolated: false,
    last_seen: ago(2 * DAY + 4 * HOUR),
    enrolled_at: ago(14 * DAY),
    labels: ['laptop', 'family'],
    sensors: [
      { name: 'process', impl: 'etw', state: 'running', events: 9120 },
      { name: 'network', impl: 'etw', state: 'running', events: 30551 },
      { name: 'file', impl: 'etw', state: 'running', events: 12011 },
      { name: 'eventlog', impl: 'eventlog', state: 'running', events: 4410 },
    ],
    queue_events: 1834,
    allowed_actions: [...COMMAND_TYPES],
    open_alerts: 0,
    cpus: 4,
    memory_bytes: 8 * 1024 ** 3,
  },
  {
    id: PI_ID,
    hostname: 'pi-media',
    kind: 'endpoint',
    os: { platform: 'linux', family: 'debian', name: 'Debian GNU/Linux', version: '12', kernel: '6.6.51+rpt-rpi-v8' },
    arch: 'arm64',
    ips: ['192.168.1.33'],
    agent_version: '0.1.0',
    status: 'isolated',
    isolated: true,
    last_seen: ago(20 * SEC),
    enrolled_at: ago(30 * DAY),
    labels: ['iot', 'media'],
    sensors: [
      { name: 'process', impl: 'procconn', state: 'degraded', error: 'eBPF unavailable (kernel lockdown); using netlink proc connector', events: 22015 },
      { name: 'network', impl: 'procfs', state: 'degraded', error: 'polling /proc/net every 5s', events: 8120 },
      { name: 'file', impl: 'fanotify', state: 'running', events: 4011 },
      { name: 'auth', impl: 'authlog', state: 'running', events: 310 },
    ],
    queue_events: 0,
    allowed_actions: [...COMMAND_TYPES],
    open_alerts: 0,
    boot_time: ago(6 * DAY),
    cpus: 4,
    memory_bytes: 4 * 1024 ** 3,
  },
]

export const hostById = (id: string) => hosts.find((h) => h.id === id)
