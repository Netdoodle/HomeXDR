// Device list filtering and sorting, and settings form helpers.

import type { BehaviorSettingsUpdate, DetectorSettings, DetectorState, Device } from '../api/network'

export type DeviceFilter = '' | 'new' | 'known' | 'unknown'
export type DeviceSort = 'last_seen' | 'first_seen' | 'name' | 'ip'

/** What to call a device: the owner's name, then its own, then an agent's, then its address. */
export function deviceName(d: Device): string {
  return d.name || d.hostname || d.host_name || d.ip || d.mac || d.id
}

function searchable(d: Device): string {
  return [d.name, d.hostname, d.host_name, d.vendor, d.note, d.subnet, d.mac, ...(d.macs ?? []), ...(d.hostnames ?? []), ...d.ips.map((i) => i.ip)]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

export function filterDevices(devices: Device[], text: string, filter: DeviceFilter): Device[] {
  const words = text.trim().toLowerCase().split(/\s+/).filter(Boolean)
  return devices.filter((d) => {
    if (filter === 'new' && !d.new) return false
    if (filter === 'known' && !d.known) return false
    if (filter === 'unknown' && d.known) return false
    if (words.length === 0) return true
    const hay = searchable(d)
    return words.every((w) => hay.includes(w))
  })
}

/** Sorts addresses by number, so .9 comes before .10. */
export function ipSortKey(ip: string | undefined): string {
  if (!ip) return '~'
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split('.').map((p) => p.padStart(3, '0')).join('.')
  return `z${ip}`
}

export function sortDevices(devices: Device[], sort: DeviceSort): Device[] {
  const out = [...devices]
  const cmp: Record<DeviceSort, (a: Device, b: Device) => number> = {
    last_seen: (a, b) => b.last_seen.localeCompare(a.last_seen),
    first_seen: (a, b) => b.first_seen.localeCompare(a.first_seen),
    name: (a, b) => deviceName(a).localeCompare(deviceName(b), undefined, { sensitivity: 'base' }),
    ip: (a, b) => ipSortKey(a.ip).localeCompare(ipSortKey(b.ip)),
  }
  return out.sort(cmp[sort])
}

/** A search for everything an address did. */
export function addressSearchHref(ip: string): string {
  return `/search?q=${encodeURIComponent(`source.ip:"${ip}" OR destination.ip:"${ip}"`)}`
}

export const SOURCE_LABEL: Record<string, string> = {
  dhcp: 'DHCP',
  firewall: 'Firewall',
  netflow: 'NetFlow',
  dns: 'DNS',
  suricata: 'Suricata',
  agent: 'Agent',
}

export const STATE_LABEL: Record<DetectorState, string> = {
  pending: 'Not run yet',
  ok: 'Running',
  limited: 'Running, partial data',
  learning: 'Learning',
  needs_data: 'Needs data',
  disabled: 'Off',
  error: 'Error',
}

/** The status dot class for a detector state. */
export function stateDot(s: DetectorState): string {
  switch (s) {
    case 'ok':
      return 'online'
    case 'limited':
    case 'learning':
      return 'degraded'
    case 'error':
      return 'revoked'
    default:
      return 'offline'
  }
}

/** Splits a settings text box into its entries: one per line, commas also work. */
export function parseLines(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

/**
 * Builds the settings update, holding only what differs from the defaults, so later changes
 * to a default reach a detector the owner did not customise.
 */
export function behaviorUpdate(detectors: DetectorSettings[]): BehaviorSettingsUpdate {
  const out: BehaviorSettingsUpdate = { detectors: {} }
  for (const d of detectors) {
    const values: Record<string, number> = {}
    for (const t of d.thresholds) {
      const v = d.values[t.key]
      if (v !== undefined && v !== t.default) values[t.key] = v
    }
    const lists: Record<string, string[]> = {}
    for (const l of d.list_defs) {
      const v = d.lists[l.key] ?? []
      if (v.join('\n') !== (l.default ?? []).join('\n')) lists[l.key] = v
    }
    out.detectors[d.id] = {
      ...(d.enabled ? {} : { enabled: false }),
      ...(Object.keys(values).length ? { values } : {}),
      ...(Object.keys(lists).length ? { lists } : {}),
    }
  }
  return out
}
