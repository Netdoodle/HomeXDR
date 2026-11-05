// Offline lists: settings, and what they say about an indicator.

import { http } from './client'

export interface OfflineList {
  id: string
  name: string
  about: string
  site_url: string
  warning?: string
  license: string
  license_url?: string
  enabled: boolean
  default_on: boolean
  every_hours: number
  last_check?: string
  last_update?: string
  entries: number
  error?: string
  updating: boolean
}

export interface DomainFacts {
  registered?: string
  rank?: number
  category?: string
  newly_registered?: boolean
}

export interface IPFacts {
  asn?: number
  as_name?: string
  country?: string
}

export interface MACFacts {
  vendor?: string
  randomized?: boolean
}

export interface OfflineFacts {
  domain?: DomainFacts
  ip?: IPFacts
  mac?: MACFacts
}

export const listsKey = ['settings', 'lists'] as const

export const getLists = () => http.get<{ lists: OfflineList[] }>('/api/settings/lists')
export const setListEnabled = (id: string, enabled: boolean) => http.put<{ lists: OfflineList[] }>(`/api/settings/lists/${encodeURIComponent(id)}`, { enabled })
export const refreshList = (id: string) => http.post<{ lists: OfflineList[] }>(`/api/settings/lists/${encodeURIComponent(id)}/refresh`)
export const lookupOffline = (q: string[]) =>
  http.post<{ results: Record<string, OfflineFacts> }>('/api/lists/lookup', { indicators: q })
