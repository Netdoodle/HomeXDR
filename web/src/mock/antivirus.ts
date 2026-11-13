// Mock antivirus.

import type { AVSettings, AVStatus } from '../api/antivirus'
import type { Role } from '../api/types'
import { hardeningRoutes } from './hardening'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const NOW = Date.now()
const ago = (ms: number) => new Date(NOW - ms).toISOString()

export const status: AVStatus = {
  settings: { enabled: true, action: 'quarantine', scan_unknown: true, use_clamav: true, use_yara: true, app_control: 'off', defender_hardening: 'off', use_intel: true, max_file_mb: 64, blocked_hashes: [], allowed_hashes: [] },
  clamd: { configured: true, ok: true, version: 'ClamAV 1.4.6/27450/Fri Nov  6 08:21:00 2026' },
  yara: { configured: true, ok: true, yara_version: '4.5.4', rules: 5128, package: 'YARA Forge core 2026-11-08', custom_files: 1, compiled: ago(3 * 3600_000) },
  verdicts: { clean: 214, known: 1310, malicious: 2, skipped: 3 },
  scanned: 37,
  detected: 2,
  queue: 0,
  detections: [
    {
      sha256: '9f3c1a7e5b2d4c6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f',
      verdict: 'malicious',
      source: 'clamav',
      signature: 'Win.Trojan.AgentTesla-9876543-0',
      path: 'C:\\Users\\alice\\Downloads\\invoice_2026.exe',
      host_id: 'h-desk',
      checked_at: ago(42 * 60_000),
    },
    {
      sha256: '1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c',
      verdict: 'malicious',
      source: 'intel:malwarebazaar',
      signature: 'RedLineStealer',
      path: 'C:\\Users\\bob\\AppData\\Local\\Temp\\setup_x64.exe',
      host_id: 'h-laptop',
      checked_at: ago(26 * 3600_000),
    },
    {
      sha256: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
      verdict: 'malicious',
      source: 'yara:tool',
      signature: 'SIGNATURE_BASE_HKTL_Mimikatz_Strings (+2 more)',
      path: 'C:\\Users\\alice\\Desktop\\tools\\mk.exe',
      host_id: 'h-desk',
      checked_at: ago(3 * 24 * 3600_000),
    },
  ],
}

/** Registers the antivirus routes on the mock server. */
export function antivirusRoutes(route: Route, fail: (status: number, message: string) => never) {
  route('GET', '/api/antivirus', () => status)
  route('GET', '/api/appcontrol', () => ({
    mode: status.settings.app_control,
    rules: [
      {
        sha256: '9f3c1a7e5b2d4c6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f',
        auth_sha256: '1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f9f3c1a7e5b2d4c6f8a0b',
        name: 'invoice_2026.exe',
        signature: 'Win.Trojan.AgentTesla-9876543-0',
        source: 'clamav',
        path: 'C:\\Users\\alice\\Downloads\\invoice_2026.exe',
        checked_at: ago(42 * 60_000),
      },
    ],
    hosts: [
      { host_id: 'h-desk', hostname: 'DESKTOP-7QK2M4', mode: 'audit', mode_from: 'DTS Assets', status: 'applied', rules: 1, message: 'audit mode: Windows logs (CodeIntegrity event 3076) but still runs 1 blocked file(s)', updated_at: ago(5 * 60_000) },
      { host_id: 'h-laptop', hostname: 'LAPTOP-ALICE', mode: 'off', status: 'off', rules: 0 },
    ],
  }))
  hardeningRoutes(route, () => status.settings.defender_hardening)
  route(
    'PUT',
    '/api/settings/antivirus',
    ({ body }) => {
      const s = body as AVSettings
      for (const h of [...(s.blocked_hashes ?? []), ...(s.allowed_hashes ?? [])]) {
        if (!/^[0-9a-fA-F]{64}$/.test(h)) fail(400, `blocked hashes: "${h}" is not a SHA-256 hash (64 hex characters)`)
      }
      status.settings = { ...s, blocked_hashes: (s.blocked_hashes ?? []).map((h) => h.toLowerCase()), allowed_hashes: (s.allowed_hashes ?? []).map((h) => h.toLowerCase()) }
      return status
    },
    { role: 'admin' },
  )
  route(
    'DELETE',
    '/api/antivirus/verdicts/:sha256',
    ({ params }) => {
      status.detections = status.detections.filter((d) => d.sha256 !== params.sha256)
      return null
    },
    { role: 'analyst' },
  )
}
