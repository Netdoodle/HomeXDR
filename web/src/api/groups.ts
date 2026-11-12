// Host groups (Settings → Groups): the organisation at the top ("Global"), parent groups
// and child groups. Groups override settings for their hosts; unset settings are
// inherited from the parent group, then from Global.

import { http } from './client'

/** A group's overrides; a missing value inherits. */
export interface GroupPolicy {
  av: { clamav?: boolean; yara?: boolean }
}

/** An effective setting and where it comes from (no group: Global). */
export interface SettingSource {
  value: boolean
  group_id?: string
  group_name?: string
}

export interface HostGroup {
  id: string
  name: string
  parent_id: string
  policy: GroupPolicy
  created_at: string
  hosts: number
  effective: { clamav: SettingSource; yara: SettingSource }
}

export interface GroupsView {
  org: { name: string }
  global: { clamav: boolean; yara: boolean }
  groups: HostGroup[]
  ungrouped: number
}

export type Scanner = 'clamav' | 'yara'
export const SCANNER_LABEL: Record<Scanner, string> = { clamav: 'ClamAV', yara: 'YARA' }

export const groupKeys = { all: ['groups'] as const }

export const getGroups = () => http.get<GroupsView>('/api/groups')
export const putOrg = (name: string) => http.put<GroupsView>('/api/org', { name })
export const createGroup = (name: string, parent_id: string) => http.post<GroupsView>('/api/groups', { name, parent_id })
export const updateGroup = (id: string, u: { name?: string; parent_id?: string; policy?: GroupPolicy }) =>
  http.patch<GroupsView>(`/api/groups/${id}`, u)
export const deleteGroup = (id: string) => http.del<GroupsView>(`/api/groups/${id}`)
export const setHostsGroup = (host_ids: string[], group_id: string) => http.put<GroupsView>('/api/hosts/group', { host_ids, group_id })

/** "DTS Assets › Marketing Dept" */
export function groupPath(v: GroupsView, id: string): string {
  const g = v.groups.find((x) => x.id === id)
  if (!g) return v.org.name
  const p = v.groups.find((x) => x.id === g.parent_id)
  return p ? `${p.name} › ${g.name}` : g.name
}

/** What a group would get for a scanner if it set nothing itself: its parent's value. */
export function inheritedValue(v: GroupsView, g: HostGroup, s: Scanner): { value: boolean; from: string } {
  const p = v.groups.find((x) => x.id === g.parent_id)
  if (p) return { value: p.effective[s].value, from: p.effective[s].group_name ?? v.org.name }
  return { value: v.global[s], from: v.org.name }
}
