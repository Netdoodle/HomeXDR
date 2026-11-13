// Mock Defender hardening: the desktop applied in audit mode (from DTS Assets), the
// laptop offline.

import type { HardeningSetting, HardeningView } from '../api/hardening'
import type { Role } from '../api/types'
import { ago, LAPTOP_ID, WIN_ID } from './hosts'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const RULES = [
  'Block abuse of exploited vulnerable signed drivers',
  'Block credential stealing from the Windows local security authority subsystem (lsass.exe)',
  'Block persistence through WMI event subscription',
  'Block executable content from email client and webmail',
  'Block all Office applications from creating child processes',
  'Block Office applications from creating executable content',
  'Block Office applications from injecting code into other processes',
  'Block Office communication application from creating child processes',
  'Block Win32 API calls from Office macros',
  'Block Adobe Reader from creating child processes',
  'Block JavaScript or VBScript from launching downloaded executable content',
  'Block execution of potentially obfuscated scripts',
  'Block untrusted and unsigned processes that run from USB',
  'Block process creations originating from PSExec and WMI commands',
]

const settings: HardeningSetting[] = [
  ...RULES.map((name) => ({ name, wanted: 'Audit', actual: 'Audit' })),
  { name: 'Network Protection', wanted: 'Audit', actual: 'Audit' },
  { name: 'Controlled Folder Access', wanted: 'Audit', actual: 'Audit' },
]

/** Registers the Defender hardening route on the mock server. */
export function hardeningRoutes(route: Route, globalMode: () => string) {
  route(
    'GET',
    '/api/defender/hardening',
    (): HardeningView => ({
      mode: globalMode(),
      profile: '1',
      hosts: [
        {
          host_id: WIN_ID,
          hostname: 'DESKTOP-7QK2M4',
          mode: 'audit',
          mode_from: 'DTS Assets',
          status: 'applied',
          desired: 'audit-p1',
          applied: 'audit-p1',
          applied_mode: 'audit',
          message: 'audit: 16 of 16 settings in effect; ASR rules: 0 blocking, 14 audit; Network Protection Audit; Controlled Folder Access Audit; Tamper Protection is on',
          settings,
          updated_at: ago(12 * 60_000),
        },
        { host_id: LAPTOP_ID, hostname: 'laptop-sam', mode: 'audit', mode_from: 'DTS Assets', status: 'offline', message: 'applies when the host is back online', updated_at: ago(3 * 60_000) },
      ],
    }),
  )
}
