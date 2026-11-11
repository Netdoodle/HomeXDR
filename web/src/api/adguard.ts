// DNS resolver query log integration (Settings → Network): AdGuard Home, Pi-hole or
// Technitium DNS Server. The API keeps its first resolver's name in its paths.

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

export type ResolverKind = 'adguard' | 'pihole' | 'technitium'

/** What the console needs to know about each resolver it can read. */
export const RESOLVERS: Record<ResolverKind, { name: string; dataset: string; address: string; username: boolean; secret: string; secretHelp: string }> = {
  adguard: {
    name: 'AdGuard Home',
    dataset: 'dns.adguard',
    address: 'https://192.168.20.1:3001',
    username: true,
    secret: 'Password',
    secretHelp: 'AdGuard Home has no read-only accounts, so this login can change its settings. HomeXDR only reads the status and the query log.',
  },
  pihole: {
    name: 'Pi-hole',
    dataset: 'dns.pihole',
    address: 'https://192.168.20.2',
    username: false,
    secret: 'Password or app password',
    secretHelp:
      'Pi-hole v6 or later. Prefer an app password (Settings → Web interface / API → Configure app password): it skips two-factor and can be replaced without changing your own. HomeXDR keeps one login session and only reads the version and the query log.',
  },
  technitium: {
    name: 'Technitium DNS Server',
    dataset: 'dns.technitium',
    address: 'http://192.168.20.2:5380',
    username: false,
    secret: 'API token',
    secretHelp:
      'Create one under Administration → Sessions → Create Token, for a user allowed to view logs and apps. The query log comes from a query log app such as "Query Logs (Sqlite)" from the App Store.',
  },
}

export const resolverOf = (kind?: string): ResolverKind => (kind === 'pihole' || kind === 'technitium' ? kind : 'adguard')

export interface AdGuardSettings {
  kind?: ResolverKind
  enabled: boolean
  url: string
  username: string
  password_set: boolean
  server_name?: string
  pin_sha256?: string
  interval_sec: number
  status: AdGuardStatus
  /** One-time import of the history from before live importing began. */
  backfill?: { state: '' | 'running' | 'done' | 'error'; imported: number; oldest?: string; error?: string }
}

/** What the console sends. An empty password keeps the saved one unless clear_password is set. */
export interface AdGuardInput {
  kind: ResolverKind
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
export const backfillAdGuard = () => http.post<void>('/api/settings/adguard/backfill')
export const testAdGuardSettings = (s: AdGuardInput) => http.post<AdGuardTestResult>('/api/settings/adguard/test', s)
