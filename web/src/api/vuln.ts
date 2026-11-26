// Vulnerability management.

import { http } from './client'

export type VulnBand = 'critical' | 'high' | 'medium' | 'low'
export type VulnStatus = 'open' | 'fixed' | 'accepted'
export type Exposure = 'internet' | 'lan'

export interface VulnFinding {
  id: string // stable: host_id|package|cve
  host_id: string
  hostname: string
  package: string
  source_package: string
  version: string
  package_type: string // deb, rpm, apk, slackware, docker, os, pacman
  cve: string
  title: string
  summary: string
  fixed_version: string // '' means no fix released yet
  cvss: number | null
  cvss_vector: string
  severity_source: 'nvd' | 'osv' | 'distro' | 'estimated'
  epss: number | null // 0..1 probability of exploitation in 30 days
  epss_percentile: number | null
  kev: boolean
  kev_due_date: string
  ransomware: boolean
  exposure: Exposure
  exposed_ports: number[]
  attack_vector: 'network' | 'adjacent' | 'local' | 'physical' | ''
  likelihood: number // 0..10
  risk: number // 0..10 = cvss * likelihood / 10
  band: VulnBand // risk >= 8 critical, >= 6 high, >= 3 medium, else low
  likelihood_reasons: string[]
  confidence: 'confirmed' | 'possible'
  status: VulnStatus
  accepted_note: string
  first_seen: string
  last_seen: string
  fixed_at?: string // RFC3339
}

export interface VulnHost {
  host_id: string
  hostname: string
  os: string
  packages: number
  snapshot_at?: string
  note?: string
  coverage: 'full' | 'kev_only' | 'none'
  exposure: Exposure
  exposed_ports: number[]
  open: number
  max_risk: number
}

export interface VulnHistoryPoint {
  date: string // YYYY-MM-DD
  critical: number
  high: number
  medium: number
  low: number
  new: number
  fixed: number
}

export interface VulnSource {
  id: string
  name: string
  enabled: boolean
  entries: number
  last_update?: string
  error?: string
}

export interface VulnSummary {
  open: number
  critical: number
  high: number
  medium: number
  low: number
  internet_exposed: number
  kev: number
  new_7d: number
  fixed_7d: number
  no_fix: number
}

export interface VulnReport {
  findings: VulnFinding[] // open + accepted, plus ones fixed in the last 30 days
  summary: VulnSummary
  history: VulnHistoryPoint[] // daily, oldest first, up to 180 days
  hosts: VulnHost[]
  sources: VulnSource[]
  osv_api: { enabled: boolean; error?: string }
  last_run?: string
  running: boolean
}

export const vulnKey = ['vulnerabilities'] as const

export const getVulns = () => http.get<VulnReport>('/api/vulnerabilities')
export const refreshVulns = () => http.post<VulnReport>('/api/vulnerabilities/refresh')
export const setOSV = (osv: boolean) => http.put<VulnReport>('/api/settings/vuln', { osv })
export const acceptVuln = (b: { host_id: string; package: string; cve: string; accepted: boolean; note: string }) =>
  http.put<VulnReport>('/api/vulnerabilities/accept', b)
