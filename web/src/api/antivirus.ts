// Antivirus (Settings → Antivirus).

import { http } from './client'

export type AVAction = 'alert' | 'quarantine'

export interface AVSettings {
  enabled: boolean
  action: AVAction
  scan_unknown: boolean
  use_intel: boolean
  max_file_mb: number
  blocked_hashes: string[] | null
  allowed_hashes: string[] | null
}

export interface AVVerdict {
  sha256: string
  verdict: 'malicious' | 'clean' | 'known' | 'skipped'
  source: string
  signature?: string
  path?: string
  host_id?: string
  checked_at: string
}

export interface AVStatus {
  settings: AVSettings
  clamd: { configured: boolean; ok: boolean; version?: string; error?: string }
  verdicts: Record<string, number> | null
  scanned: number
  detected: number
  queue: number
  last_error?: string
  detections: AVVerdict[]
}

export const avKeys = { status: ['antivirus'] as const }

export const getAV = () => http.get<AVStatus>('/api/antivirus')
export const putAV = (s: AVSettings) => http.put<AVStatus>('/api/settings/antivirus', s)
export const forgetAVVerdict = (sha256: string) => http.del(`/api/antivirus/verdicts/${sha256}`)
