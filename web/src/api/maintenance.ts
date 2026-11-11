// Settings → Maintenance: SSH key names and maintenance suppressions.

import { http } from './client'

export interface SSHKeyTag {
  fingerprint: string
  name: string
  maintenance: boolean
  expires_at?: string
  suppression_id?: string
}

export interface SSHKeySeen extends SSHKeyTag {
  logins: number
  last_login?: string
  users?: string[]
  hosts?: string[]
  sources?: string[]
  suppressed: number
}

export interface MaintenanceSource {
  id: 'docker-update' | 'appdata-backup' | 'container-start'
  maintenance: boolean
  expires_at?: string
  suppression_id?: string
  title: string
  help: string
  suppressed: number
}

export interface MaintenanceView {
  ssh_keys: SSHKeySeen[]
  sources: MaintenanceSource[]
  container_start_minutes: number
  days: number
}

export interface MaintenanceInput {
  ssh_keys: Pick<SSHKeyTag, 'fingerprint' | 'name' | 'maintenance' | 'expires_at'>[]
  sources: Pick<MaintenanceSource, 'id' | 'maintenance' | 'expires_at'>[]
  container_start_minutes: number
}

export const maintenanceKeys = { view: ['settings', 'maintenance'] as const }

export const getMaintenance = () => http.get<MaintenanceView>('/api/settings/maintenance')
export const putMaintenance = (m: MaintenanceInput) => http.put<MaintenanceView>('/api/settings/maintenance', m)
