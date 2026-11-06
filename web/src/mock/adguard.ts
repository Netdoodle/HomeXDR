// Mock AdGuard Home integration.

import type { AdGuardInput, AdGuardSettings, AdGuardTestResult } from '../api/adguard'
import type { Role } from '../api/types'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const NOW = Date.now()
const ago = (ms: number) => new Date(NOW - ms).toISOString()
const FINGERPRINT = 'B2:B6:FA:DD:7C:C4:6B:66:51:17:97:DC:A5:AF:09:84:0A:B9:84:74:F5:77:4B:77:68:83:CF:88:B0:4F:D2:24'

let password = 'mock-password'
const settings: AdGuardSettings = {
  enabled: true,
  url: 'https://192.168.20.1:3001',
  username: 'admin',
  password_set: true,
  server_name: 'ads.example.com',
  pin_sha256: FINGERPRINT,
  interval_sec: 30,
  status: {
    state: 'ok',
    last_poll: ago(12_000),
    last_success: ago(12_000),
    version: 'v0.107.79',
    imported: 18_432,
    last_batch: 87,
    fell_behind: 0,
    since: ago(6 * 3600_000),
  },
}

/** Registers the AdGuard Home routes on the mock server. */
export function adguardRoutes(route: Route, fail: (status: number, message: string) => never) {
  route('GET', '/api/settings/adguard', () => settings, { role: 'admin' })
  route(
    'PUT',
    '/api/settings/adguard',
    ({ body }) => {
      const s = body as AdGuardInput
      if (s.enabled && !/^https?:\/\/[^/@]+\/?$/.test(s.url)) fail(400, "enter AdGuard Home's address, such as https://192.168.20.1:3001")
      if (s.clear_password) password = ''
      else if (s.password) password = s.password
      if (s.enabled && (!s.username || !password)) fail(400, "enter AdGuard Home's username and password")
      Object.assign(settings, {
        enabled: s.enabled,
        url: s.url.replace(/\/$/, ''),
        username: s.username,
        password_set: password !== '',
        server_name: s.server_name ?? '',
        pin_sha256: s.pin_sha256 ?? '',
        interval_sec: s.interval_sec || 30,
      })
      settings.status = { ...settings.status, state: s.enabled ? 'waiting' : 'off', last_error: undefined }
      return settings
    },
    { role: 'admin' },
  )
  route(
    'POST',
    '/api/settings/adguard/test',
    ({ body }): AdGuardTestResult => {
      const s = body as AdGuardInput
      if (s.url.startsWith('https://') && !s.pin_sha256) {
        return {
          ok: false,
          message: "AdGuard Home's certificate has expired",
          certificate: { subject: 'ads.example.com', names: ['ads.example.com'], issuer: 'E6', not_after: '2026-08-06T05:01:40Z', expired: true, fingerprint: FINGERPRINT },
        }
      }
      return { ok: true, message: 'Connected to AdGuard Home v0.107.79. The query log is readable.', version: 'v0.107.79' }
    },
    { role: 'admin' },
  )
}
