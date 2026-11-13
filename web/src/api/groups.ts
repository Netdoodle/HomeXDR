// Host groups (Settings → Groups): the organisation at the top ("Global"), parent groups
// and child groups. Groups override settings for their hosts; unset settings are
// inherited from the parent group, then from Global.

import { http } from './client'

/** A group's overrides; a missing value inherits. */
export interface GroupPolicy {
  av: {
    clamav?: boolean
    yara?: boolean
    action?: 'quarantine' | 'alert'
    app_control?: 'off' | 'audit' | 'enforce'
    defender_hardening?: 'off' | 'audit' | 'enforce'
  }
  ai?: { auto?: boolean }
}

/** An effective setting and where it comes from (no group: Global). */
export interface SettingSource<T = boolean> {
  value: T
  group_id?: string
  group_name?: string
}

export interface Effective {
  clamav: SettingSource
  yara: SettingSource
  action: SettingSource<string>
  app_control: SettingSource<string>
  ai_auto: SettingSource
  defender_hardening: SettingSource<string>
}

export interface HostGroup {
  id: string
  name: string
  parent_id: string
  policy: GroupPolicy
  created_at: string
  hosts: number
  effective: Effective
}

export interface GroupsView {
  org: { name: string }
  global: { clamav: boolean; yara: boolean; action: string; app_control: string; ai_auto: boolean; defender_hardening: string }
  groups: HostGroup[]
  ungrouped: number
}

export type SettingKey = 'clamav' | 'yara' | 'action' | 'app_control' | 'ai_auto' | 'defender_hardening'

/** One overridable setting: its choices, from strongest protection to weakest. */
export interface SettingDef {
  key: SettingKey
  label: string
  /** values in order of protection, strongest first, with their labels */
  choices: { value: string; label: string }[]
  /** the group's own value, as a choice value; undefined inherits */
  get: (p: GroupPolicy) => string | undefined
  set: (p: GroupPolicy, v: string | undefined) => GroupPolicy
  /** what turning it down means, for the confirmation */
  weaker: (name: string) => string
}

const bool = (v: string | undefined) => (v === undefined ? undefined : v === 'on')
const onOff = (b: boolean | undefined) => (b === undefined ? undefined : b ? 'on' : 'off')

export const SETTINGS: SettingDef[] = [
  {
    key: 'clamav',
    label: 'ClamAV',
    choices: [
      { value: 'on', label: 'On' },
      { value: 'off', label: 'Off' },
    ],
    get: (p) => onOff(p.av.clamav),
    set: (p, v) => ({ ...p, av: { ...p.av, clamav: bool(v) } }),
    weaker: () => 'will no longer have programs scanned with ClamAV, and ClamAV detections will not raise alerts for them',
  },
  {
    key: 'yara',
    label: 'YARA',
    choices: [
      { value: 'on', label: 'On' },
      { value: 'off', label: 'Off' },
    ],
    get: (p) => onOff(p.av.yara),
    set: (p, v) => ({ ...p, av: { ...p.av, yara: bool(v) } }),
    weaker: () => 'will no longer have programs scanned with YARA, and YARA detections will not raise alerts for them',
  },
  {
    key: 'action',
    label: 'Malware response',
    choices: [
      { value: 'quarantine', label: 'Stop and quarantine' },
      { value: 'alert', label: 'Alert only' },
    ],
    get: (p) => p.av.action,
    set: (p, v) => ({ ...p, av: { ...p.av, action: v as 'quarantine' | 'alert' | undefined } }),
    weaker: () => 'will only get an alert when malware runs: the process is not stopped and the file is not quarantined',
  },
  {
    key: 'app_control',
    label: 'App Control (Windows)',
    choices: [
      { value: 'enforce', label: 'Enforce' },
      { value: 'audit', label: 'Audit' },
      { value: 'off', label: 'Off' },
    ],
    get: (p) => p.av.app_control,
    set: (p, v) => ({ ...p, av: { ...p.av, app_control: v as 'off' | 'audit' | 'enforce' | undefined } }),
    weaker: () => 'will start confirmed malware again if it reappears, instead of Windows refusing to run it',
  },
  {
    key: 'defender_hardening',
    label: 'Defender hardening (Windows)',
    choices: [
      { value: 'enforce', label: 'Enforce' },
      { value: 'audit', label: 'Audit' },
      { value: 'off', label: 'Off' },
    ],
    get: (p) => p.av.defender_hardening,
    set: (p, v) => ({ ...p, av: { ...p.av, defender_hardening: v as 'off' | 'audit' | 'enforce' | undefined } }),
    weaker: () =>
      "will have fewer Microsoft Defender protections: Attack Surface Reduction rules and Network Protection only log (Audit), or Defender's settings from before HomeXDR are put back (Off)",
  },
  {
    key: 'ai_auto',
    label: 'AI analyst',
    choices: [
      { value: 'on', label: 'Investigate' },
      { value: 'off', label: 'Off' },
    ],
    get: (p) => onOff(p.ai?.auto),
    set: (p, v) => ({ ...p, ai: { ...p.ai, auto: bool(v) } }),
    weaker: () => 'will no longer have their alerts investigated automatically by the AI analyst',
  },
]

/** A setting's effective value as a choice value. */
export function effectiveValue(e: Effective, key: SettingKey): string {
  const s = e[key]
  return typeof s.value === 'boolean' ? (s.value ? 'on' : 'off') : s.value
}

export function globalValue(v: GroupsView, key: SettingKey): string {
  const g = v.global[key]
  return typeof g === 'boolean' ? (g ? 'on' : 'off') : g
}

export function choiceLabel(def: SettingDef, value: string): string {
  return def.choices.find((c) => c.value === value)?.label ?? value
}

/** Whether a is weaker protection than b. */
export function isWeaker(def: SettingDef, a: string, b: string): boolean {
  const i = def.choices.findIndex((c) => c.value === a)
  const j = def.choices.findIndex((c) => c.value === b)
  return i > j
}

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

/** What a group would get for a setting if it set nothing itself: its parent's value. */
export function inheritedValue(v: GroupsView, g: HostGroup, key: SettingKey): { value: string; from: string } {
  const p = v.groups.find((x) => x.id === g.parent_id)
  if (p) return { value: effectiveValue(p.effective, key), from: p.effective[key].group_name ?? v.org.name }
  return { value: globalValue(v, key), from: v.org.name }
}
