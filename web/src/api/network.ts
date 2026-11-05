// Device inventory and behaviour detection: types and endpoints (docs/api.md).

import { http } from './client'

export interface DeviceIP {
  ip: string
  first_seen: string
  last_seen: string
}

export interface Device {
  /** The device's first MAC, or "ip:<address>" until DHCP reveals one. */
  id: string
  mac?: string
  macs?: string[]
  randomized_mac?: boolean
  ip?: string
  ips: DeviceIP[]
  hostname?: string
  hostnames?: string[]
  vendor?: string
  subnet?: string
  interface?: string
  sources: string[]
  host_id?: string
  host_name?: string
  name?: string
  note?: string
  known: boolean
  dest_only?: boolean
  first_seen: string
  last_seen: string
  alerted_at?: string
  /** First seen after learning, and nobody has marked it as known. */
  new: boolean
}

export interface SubnetCount {
  subnet: string
  devices: number
}

export interface DeviceList {
  devices: Device[]
  total: number
  learning: boolean
  learning_until: string
  subnets: SubnetCount[]
  overflow?: number
}

export interface DevicePatch {
  name?: string
  note?: string
  known?: boolean
}

export interface NetworkSettings {
  subnets: string[]
  exclude: string[]
  firewall_ips: string[]
  new_device_alerts: boolean
  learning_days: number
  firewall_learned?: string[]
  subnets_seen?: SubnetCount[]
  learning_until?: string
}

export type DetectorState = 'pending' | 'ok' | 'limited' | 'learning' | 'needs_data' | 'disabled' | 'error'

export interface DetectorStatus {
  id: string
  title: string
  about: string
  enabled: boolean
  status: DetectorState
  data_needed?: string
  last_run?: string
  last_duration_ms?: number
  last_finding_count: number
  total_finding_count: number
  learning_until?: string
  error?: string
}

export interface ThresholdDef {
  key: string
  label: string
  help: string
  default: number
  min: number
  max: number
}

export interface ListDef {
  key: string
  label: string
  help: string
  kind: string
  default?: string[]
}

export interface DetectorSettings {
  id: string
  title: string
  about: string
  enabled: boolean
  values: Record<string, number>
  lists: Record<string, string[]>
  thresholds: ThresholdDef[]
  list_defs: ListDef[]
}

export interface DetectorUpdate {
  enabled?: boolean
  values?: Record<string, number>
  lists?: Record<string, string[]>
}

export interface BehaviorSettingsUpdate {
  detectors: Record<string, DetectorUpdate>
}

export const networkKeys = {
  devices: ['devices'] as const,
  settings: ['settings', 'network'] as const,
  behaviorStatus: ['behavior', 'status'] as const,
  behaviorSettings: ['settings', 'behavior'] as const,
}

export const listDevices = () => http.get<DeviceList>('/api/devices')
export const patchDevice = (id: string, p: DevicePatch) => http.patch<Device>(`/api/devices/${encodeURIComponent(id)}`, p)
export const getNetworkSettings = () => http.get<NetworkSettings>('/api/settings/network')
export const putNetworkSettings = (s: NetworkSettings) => http.put<NetworkSettings>('/api/settings/network', s)
export const behaviorStatus = () => http.get<{ detectors: DetectorStatus[] }>('/api/behavior/status')
export const getBehaviorSettings = () => http.get<{ detectors: DetectorSettings[] }>('/api/settings/behavior')
export const putBehaviorSettings = (u: BehaviorSettingsUpdate) => http.put<{ detectors: DetectorSettings[] }>('/api/settings/behavior', u)
