// Known-exploited software.

import { http } from './client'

export type VulnConfidence = 'confirmed' | 'possible'

export interface VulnMatch {
  host_id: string
  hostname: string
  package: string
  version: string
  package_type: string
  cve: string
  title: string
  kev_date: string
  due_date: string
  ransomware: boolean
  confidence: VulnConfidence
  reason: string
  first_seen: string
  last_seen: string
}

export interface HostInventory {
  host_id: string
  hostname: string
  packages: number
  snapshot_at?: string
  note?: string
}

export interface VulnReport {
  matches: VulnMatch[]
  confirmed: number
  possible: number
  hosts: HostInventory[]
  kev: { enabled: boolean; entries: number; version?: string; last_update?: string; error?: string }
  osv: { enabled: boolean; error?: string }
  last_run?: string
  running: boolean
}

export const vulnKey = ['vulnerabilities'] as const

export const getVulns = () => http.get<VulnReport>('/api/vulnerabilities')
export const refreshVulns = () => http.post<VulnReport>('/api/vulnerabilities/refresh')
export const setOSV = (osv: boolean) => http.put<VulnReport>('/api/settings/vuln', { osv })
