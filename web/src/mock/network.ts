// Mock network visibility: NetFlow intake, device inventory and behaviour detection.

import type { BehaviorSettingsUpdate, DetectorSettings, DetectorStatus, Device, DevicePatch, DeviceList, NetworkSettings } from '../api/network'
import type { NetFlowStats, Role } from '../api/types'
import { adguardRoutes } from './adguard'
import { antivirusRoutes } from './antivirus'

const NOW = Date.now()
const SEC = 1000
const MIN = 60 * SEC
const HOUR = 60 * MIN
const DAY = 24 * HOUR
const ago = (ms: number) => new Date(NOW - ms).toISOString()

export const netflowStats: NetFlowStats = {
  enabled: true,
  listening: true,
  addr: ':2055',
  packets: 48213,
  records: 391877,
  dropped: 0,
  refused: 12,
  malformed: 0,
  waiting: 3,
  discarded: 0,
  failed: 0,
  exporters: [{ ip: '192.168.1.1', version: 9, packets: 48213, records: 391877, templates: 2, last_seen: ago(4 * SEC) }],
}

const ip = (addr: string, firstAgo: number, lastAgo: number) => ({ ip: addr, first_seen: ago(firstAgo), last_seen: ago(lastAgo) })

const devices: Device[] = [
  {
    id: 'b8:27:eb:12:34:56', mac: 'b8:27:eb:12:34:56', macs: ['b8:27:eb:12:34:56'], ip: '192.168.1.20', ips: [ip('192.168.1.20', 30 * DAY, 20 * SEC)],
    hostname: 'tower', hostnames: ['tower'], vendor: 'Raspberry Pi Foundation', subnet: '192.168.1.0/24', interface: 'igb1',
    sources: ['dhcp', 'firewall', 'netflow', 'agent'], host_id: 'host-linux', host_name: 'tower', name: 'Home server', known: true, new: false,
    first_seen: ago(30 * DAY), last_seen: ago(20 * SEC),
  },
  {
    id: '3a:91:0c:55:21:7e', mac: '3a:91:0c:55:21:7e', macs: ['3a:91:0c:55:21:7e', '5e:12:88:aa:0b:44'], randomized_mac: true, ip: '192.168.1.57',
    ips: [ip('192.168.1.42', 20 * DAY, 9 * DAY), ip('192.168.1.57', 9 * DAY, 2 * MIN)], hostname: 'pixel-of-sam', hostnames: ['pixel-of-sam'], subnet: '192.168.1.0/24',
    sources: ['dhcp', 'dns', 'netflow'], name: "Sam's phone", note: 'Rotates its MAC address every few weeks.', known: true, new: false, first_seen: ago(20 * DAY), last_seen: ago(2 * MIN),
  },
  {
    id: 'ec:71:db:0a:bc:de', mac: 'ec:71:db:0a:bc:de', macs: ['ec:71:db:0a:bc:de'], ip: '192.168.40.11', ips: [ip('192.168.40.11', 18 * DAY, 8 * SEC)],
    hostname: 'reolink-front', hostnames: ['reolink-front'], vendor: 'Reolink Innovation', subnet: '192.168.40.0/24', sources: ['dhcp', 'firewall', 'netflow'],
    known: false, new: false, first_seen: ago(18 * DAY), last_seen: ago(8 * SEC),
  },
  {
    id: '00:1a:2b:3c:4d:5e', mac: '00:1a:2b:3c:4d:5e', macs: ['00:1a:2b:3c:4d:5e'], ip: '192.168.30.77', ips: [ip('192.168.30.77', 5 * HOUR, 40 * SEC)],
    hostname: 'ESP_3C4D5E', hostnames: ['ESP_3C4D5E'], vendor: 'Espressif', subnet: '192.168.30.0/24', sources: ['dhcp', 'dns'],
    known: false, new: true, first_seen: ago(5 * HOUR), last_seen: ago(40 * SEC), alerted_at: ago(5 * HOUR),
  },
  {
    id: 'ip:192.168.1.88', ip: '192.168.1.88', ips: [ip('192.168.1.88', 2 * HOUR, 12 * MIN)], subnet: '192.168.1.0/24', sources: ['firewall'],
    known: false, new: true, first_seen: ago(2 * HOUR), last_seen: ago(12 * MIN), alerted_at: ago(2 * HOUR),
  },
  {
    id: 'ip:192.168.10.40', ip: '192.168.10.40', ips: [ip('192.168.10.40', DAY, DAY)], subnet: '192.168.10.0/24', sources: ['firewall'], dest_only: true,
    known: false, new: false, first_seen: ago(DAY), last_seen: ago(DAY),
  },
  {
    id: 'ip:192.168.1.30', ip: '192.168.1.30', ips: [ip('192.168.1.30', 25 * DAY, 3 * HOUR)], subnet: '192.168.1.0/24', sources: ['firewall', 'netflow'],
    known: false, new: false, first_seen: ago(25 * DAY), last_seen: ago(3 * HOUR),
  },
]

const netSettings: NetworkSettings = { subnets: [], exclude: [], firewall_ips: [], new_device_alerts: true, learning_days: 3 }

function subnetCounts() {
  const counts = new Map<string, number>()
  for (const d of devices) if (d.subnet) counts.set(d.subnet, (counts.get(d.subnet) ?? 0) + 1)
  return [...counts].sort().map(([subnet, n]) => ({ subnet, devices: n }))
}

const learningUntil = ago(27 * DAY)

function deviceList(): DeviceList {
  return { devices: [...devices].sort((a, b) => b.last_seen.localeCompare(a.last_seen)), total: devices.length, learning: false, learning_until: learningUntil, subnets: subnetCounts() }
}

function netView(): NetworkSettings {
  return { ...netSettings, firewall_learned: ['192.168.1.1', '203.0.113.9'], subnets_seen: subnetCounts(), learning_until: learningUntil }
}

const t = (key: string, label: string, help: string, def: number, min: number, max: number) => ({ key, label, help, default: def, min, max })
const reported = (def: number) => t('reported_days', 'Days before reporting again', 'The same thing is reported once in this many days.', def, 1, 365)
const learning = (def: number) =>
  t('learning_days', 'Learning days', 'For this long what is seen becomes normal and nothing is reported. It starts when the input first arrives, and again when NetFlow first arrives.', def, 1, 90)

const detectors: DetectorSettings[] = [
  {
    id: 'beaconing',
    title: 'Beaconing',
    about: 'A device contacting one internet address at very even intervals, the way malware checks in with its controller. Push services, time sync and similar are left out.',
    enabled: true,
    values: {},
    lists: {},
    thresholds: [
      t('min_count', 'Minimum check-ins', 'Fewer connections than this are not looked at.', 10, 3, 200),
      t('min_span_sec', 'Minimum span in seconds', 'The check-ins must cover at least this long.', 600, 60, 86400),
      t('max_cv', 'Maximum variation', 'How even the gaps must be: their spread divided by their average. Lower is stricter.', 0.15, 0.01, 1),
      t('min_interval_sec', 'Shortest gap in seconds', 'Gaps shorter than this on average are a busy connection, not a check-in.', 5, 1, 3600),
      reported(7),
    ],
    list_defs: [
      { key: 'benign_domains', label: 'Domains to leave out', help: 'One per line. A domain covers its subdomains.', kind: 'domain' },
      { key: 'ignore_ports', label: 'Ports to leave out', help: 'One per line, such as tcp/8883 or 8883.', kind: 'port' },
    ],
  },
  {
    id: 'dns_tunnel',
    title: 'DNS tunnelling',
    about: 'A device looking up many long or random-looking names under one domain, which is how data is smuggled out through DNS. Popular domains and local names are left out.',
    enabled: true,
    values: {},
    lists: {},
    thresholds: [t('label_len', 'Long label length', 'A label at least this long counts as long.', 30, 10, 63), t('min_long_names', 'Long names to report', 'This many different names with a long label under one domain is reported.', 20, 2, 100000), reported(7)],
    list_defs: [{ key: 'ignore_domains', label: 'Domains to leave out', help: 'One per line. A domain covers its subdomains.', kind: 'domain' }],
  },
  {
    id: 'dns_bypass',
    title: 'DNS bypass',
    about: 'A device sending DNS (port 53) or DNS over TLS (port 853) to something other than your resolver, so its lookups dodge your filtering and logs. Pairs seen while learning count as normal.',
    enabled: true,
    values: {},
    lists: { approved_resolvers: ['192.168.1.53'] },
    thresholds: [learning(3), reported(7)],
    list_defs: [{ key: 'approved_resolvers', label: 'Approved resolvers', help: 'One address per line. The firewall is always approved.', kind: 'ip' }],
  },
  {
    id: 'upload_spike',
    title: 'Upload spike',
    about: "A device sending far more to the internet in an hour than it normally does at that hour. Each device has its own normal, so a camera that uploads all day is fine.",
    enabled: true,
    values: {},
    lists: {},
    thresholds: [t('factor', 'Times its normal', "An hour must be at least this many times the device's normal for that hour.", 10, 2, 1000), t('min_mb', 'Minimum megabytes', 'An hour below this is never reported.', 500, 1, 1000000), learning(7), reported(1)],
    list_defs: [],
  },
  {
    id: 'unusual_port',
    title: 'Unusual port',
    about: 'A device connecting to the internet on a port no device here has used, as reverse shells and tunnels often do. High UDP ports are left out, since games and calls use them all the time.',
    enabled: true,
    values: {},
    lists: {},
    thresholds: [learning(7), reported(7)],
    list_defs: [{ key: 'allowed_ports', label: 'Ports to leave out', help: 'One per line, such as tcp/8443 or 8443.', kind: 'port' }],
  },
  {
    id: 'internal_scan',
    title: 'Internal scan',
    about: 'A device reaching many other devices or many ports on one device, as scanners and spreading malware do. Only traffic that crosses the firewall is seen. Discovery protocols are left out.',
    enabled: true,
    values: {},
    lists: {},
    thresholds: [t('min_hosts', 'Hosts reached', 'Reaching this many other addresses is reported.', 30, 5, 65536), t('min_ports', 'Ports on one host', 'Reaching this many ports on one address is reported.', 30, 5, 65536), reported(1)],
    list_defs: [{ key: 'allowed_scanners', label: 'Devices to leave out', help: 'One address per line, for a monitoring box or a network scanner you run.', kind: 'ip' }],
  },
  {
    id: 'rogue_dhcp',
    title: 'Rogue DHCP server',
    about: 'A device answering DHCP that is not the firewall, which could hand out a hostile gateway or DNS server. Servers seen while learning count as normal.',
    enabled: true,
    values: {},
    lists: {},
    thresholds: [learning(3), reported(7)],
    list_defs: [{ key: 'approved_servers', label: 'Approved DHCP servers', help: 'One address per line. The firewall is always approved.', kind: 'ip' }],
  },
  {
    id: 'exposure',
    title: 'Exposed service',
    about: 'Traffic from the internet allowed in to an internal device and port: a port forward or a UPnP mapping. Ones seen while learning count as normal.',
    enabled: true,
    values: {},
    lists: { expected: ['192.168.1.20:443'] },
    thresholds: [learning(3), reported(30)],
    list_defs: [{ key: 'expected', label: 'Expected services', help: 'One per line, such as 192.168.20.20:443, tcp/443 or 443.', kind: 'endpoint' }],
  },
]

function detectorViews(): DetectorSettings[] {
  return detectors.map((d) => ({ ...d, values: { ...Object.fromEntries(d.thresholds.map((x) => [x.key, x.default])), ...d.values } }))
}

const STATUS: Record<string, Partial<DetectorStatus>> = {
  beaconing: { status: 'ok', last_run: ago(20 * MIN), last_duration_ms: 412, last_finding_count: 0, total_finding_count: 2 },
  dns_tunnel: { status: 'ok', last_run: ago(9 * MIN), last_duration_ms: 86, last_finding_count: 0, total_finding_count: 0 },
  dns_bypass: { status: 'ok', last_run: ago(8 * MIN), last_duration_ms: 31, last_finding_count: 1, total_finding_count: 3 },
  upload_spike: { status: 'learning', last_run: ago(7 * MIN), last_duration_ms: 44, last_finding_count: 0, total_finding_count: 0, learning_until: new Date(NOW + 4 * DAY).toISOString() },
  unusual_port: { status: 'limited', last_run: ago(6 * MIN), last_duration_ms: 52, last_finding_count: 0, total_finding_count: 1, data_needed: 'Running on firewall rows only, which rarely name the device behind NAT. NetFlow gives it the full picture. See docs/network-visibility.md.' },
  internal_scan: { status: 'ok', last_run: ago(5 * MIN), last_duration_ms: 37, last_finding_count: 0, total_finding_count: 0 },
  rogue_dhcp: { status: 'needs_data', last_run: ago(4 * MIN), last_finding_count: 0, total_finding_count: 0, data_needed: 'Firewall logs or NetFlow. See docs/network-visibility.md.' },
  exposure: { status: 'error', last_run: ago(3 * MIN), last_finding_count: 0, total_finding_count: 0, error: 'the event store took too long to answer' },
}

function statuses(): DetectorStatus[] {
  return detectors.map((d) => ({
    id: d.id,
    title: d.title,
    about: d.about,
    enabled: d.enabled,
    status: 'pending',
    last_finding_count: 0,
    total_finding_count: 0,
    ...STATUS[d.id],
    ...(d.enabled ? {} : { status: 'disabled' as const }),
  }))
}

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

/** Registers this feature's routes on the mock server. */
export function networkRoutes(route: Route, fail: (status: number, message: string) => never) {
  adguardRoutes(route, fail)
  antivirusRoutes(route, fail)
  route('GET', '/api/devices', () => deviceList())
  route(
    'PATCH',
    '/api/devices/:id',
    ({ params, body }) => {
      const d = devices.find((x) => x.id === decodeURIComponent(params.id)) ?? fail(404, 'not found')
      const p = (body ?? {}) as DevicePatch
      if (p.name === undefined && p.note === undefined && p.known === undefined) fail(400, 'nothing to update')
      if (p.name !== undefined) d.name = p.name.trim()
      if (p.note !== undefined) d.note = p.note.trim()
      if (p.known !== undefined) {
        d.known = p.known
        d.new = d.new && !p.known
      }
      return d
    },
    { role: 'analyst' },
  )
  route('GET', '/api/settings/network', () => netView(), { role: 'admin' })
  route(
    'PUT',
    '/api/settings/network',
    ({ body }) => {
      const s = body as NetworkSettings
      for (const x of [...s.subnets, ...s.exclude]) if (!/^[0-9a-f:.]+(\/\d+)?$/i.test(x)) fail(400, `"${x}" is not a subnet such as 192.168.20.0/24`)
      if (s.learning_days < 1 || s.learning_days > 90) fail(400, 'the learning period must be 1 to 90 days')
      Object.assign(netSettings, s)
      return netView()
    },
    { role: 'admin' },
  )
  route('GET', '/api/behavior/status', () => ({ detectors: statuses() }))
  route('GET', '/api/settings/behavior', () => ({ detectors: detectorViews() }), { role: 'admin' })
  route(
    'PUT',
    '/api/settings/behavior',
    ({ body }) => {
      const u = body as BehaviorSettingsUpdate
      for (const d of detectors) {
        const c = u.detectors?.[d.id] ?? {}
        d.enabled = c.enabled ?? true
        d.values = c.values ?? {}
        d.lists = c.lists ?? {}
      }
      return { detectors: detectorViews() }
    },
    { role: 'admin' },
  )
}
