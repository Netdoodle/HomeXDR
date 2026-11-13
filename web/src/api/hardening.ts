// Microsoft Defender hardening (Settings → Antivirus): ASR rules, Network Protection and
// Controlled Folder Access on Windows hosts, per group.

import { http } from './client'

export interface HardeningSetting {
  name: string
  wanted: string
  actual: string
}

export interface HardeningHost {
  host_id: string
  hostname: string
  mode: string
  mode_from?: string
  status: 'off' | 'applied' | 'partial' | 'pending' | 'offline' | 'failed' | 'not_allowed' | string
  desired?: string
  applied?: string
  applied_mode?: string
  message?: string
  failures?: string[]
  settings?: HardeningSetting[]
  updated_at?: string
}

export interface HardeningView {
  mode: string
  profile: string
  hosts: HardeningHost[]
}

export const hardeningKeys = { status: ['defender-hardening'] as const }
export const getDefenderHardening = () => http.get<HardeningView>('/api/defender/hardening')
