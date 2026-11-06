// AdGuard Home query log integration (Settings → Network).

import { http } from './client'

export interface AdGuardStatus {
  state: 'off' | 'waiting' | 'ok' | 'error'
  last_poll?: string
  last_success?: string
  last_error?: string
  version?: string
  imported: number
  last_batch: number
  fell_behind: number
  since?: string
}

export interface AdGuardSettings {
  enabled: boolean
  url: string
  username: string
  password_set: boolean
  server_name?: string
  pin_sha256?: string
  interval_sec: number
  status: AdGuardStatus
}

/** What the console sends. An empty password keeps the saved one unless clear_password is set. */
export interface AdGuardInput {
  enabled: boolean
  url: string
  username: string
  password?: string
  clear_password?: boolean
  server_name?: string
  pin_sha256?: string
  interval_sec: number
}

export interface AdGuardCert {
  subject: string
  names?: string[]
  issuer: string
  not_after: string
  expired: boolean
  fingerprint: string
}

export interface AdGuardTestResult {
  ok: boolean
  message: string
  version?: string
  certificate?: AdGuardCert
}

export const adguardKeys = { settings: ['settings', 'adguard'] as const }

export const getAdGuardSettings = () => http.get<AdGuardSettings>('/api/settings/adguard')
export const putAdGuardSettings = (s: AdGuardInput) => http.put<AdGuardSettings>('/api/settings/adguard', s)
export const testAdGuardSettings = (s: AdGuardInput) => http.post<AdGuardTestResult>('/api/settings/adguard/test', s)
