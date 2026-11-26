// The per-host Actions menu: what is in it, who may use each item on which host, how the
// search box matches, and the recently used and favourite lists kept in localStorage.
// Pure functions, so the rules are testable without rendering.

import type { CommandType, Host, Role } from '../api/types'
import { canUpdateNow } from './agents'

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }
const can = (role: Role | undefined, min: Role) => role !== undefined && RANK[role] >= RANK[min]

export type MenuSection = 'response' | 'endpoint' | 'agent' | 'danger'

export const SECTION_LABEL: Record<MenuSection, string> = {
  response: 'Response',
  endpoint: 'Endpoint',
  agent: 'Agent',
  danger: 'Danger',
}
export const SECTION_ORDER: MenuSection[] = ['response', 'endpoint', 'agent', 'danger']

/** What choosing an item does. 'form' items need input: they open the form on the Actions tab. */
export type MenuAction =
  | { kind: 'command'; type: CommandType } // one confirm dialog, no input
  | { kind: 'power'; type: 'host.reboot' | 'host.shutdown' } // confirm dialog with a delay
  | { kind: 'form'; anchor: string } // /hosts/{id}?tab=actions&focus=anchor
  | { kind: 'search' }
  | { kind: 'applications' }
  | { kind: 'group' }
  | { kind: 'rescan' }
  | { kind: 'update-now' }
  | { kind: 'decommission' }
  | { kind: 'recommission' }
  | { kind: 'revoke' }
  | { kind: 'remove' }

export interface MenuItem {
  id: string
  section: MenuSection
  /** shown in the menu; may depend on the host (Isolate / Release) */
  label: (h: Host) => string
  /** extra words the search box matches */
  keywords: string
  /** lowest role the server lets do this */
  role: Role
  action: (h: Host) => MenuAction
  /** command types the agent's local policy (allowed_actions) must include */
  needs?: (h: Host) => CommandType[]
}

export const MENU_ITEMS: MenuItem[] = [
  {
    id: 'isolate',
    section: 'response',
    label: (h) => (h.isolated ? 'Release from isolation' : 'Isolate host'),
    keywords: 'network quarantine contain cut off release',
    role: 'analyst',
    action: (h) => ({ kind: 'command', type: h.isolated ? 'host.release' : 'host.isolate' }),
    needs: (h) => [h.isolated ? 'host.release' : 'host.isolate'],
  },
  {
    id: 'kill',
    section: 'response',
    label: () => 'Kill process…',
    keywords: 'terminate pid process',
    role: 'analyst',
    action: () => ({ kind: 'form', anchor: 'kill' }),
    needs: () => ['process.kill'],
  },
  {
    id: 'quarantine',
    section: 'response',
    label: () => 'Quarantine / restore file…',
    keywords: 'file malware move restore',
    role: 'analyst',
    action: () => ({ kind: 'form', anchor: 'quarantine' }),
    needs: () => ['file.quarantine', 'file.restore'],
  },
  {
    id: 'get-file',
    section: 'response',
    label: () => 'Get file…',
    keywords: 'download collect upload fetch',
    role: 'admin',
    action: () => ({ kind: 'form', anchor: 'get-file' }),
    needs: () => ['file.get'],
  },
  {
    id: 'hash',
    section: 'response',
    label: () => 'Hash file…',
    keywords: 'sha256 md5 sha1 checksum',
    role: 'analyst',
    action: () => ({ kind: 'form', anchor: 'hash' }),
    needs: () => ['file.hash'],
  },
  {
    id: 'artifact',
    section: 'response',
    label: () => 'Run artifact…',
    keywords: 'collect forensic collector triage',
    role: 'analyst',
    action: () => ({ kind: 'form', anchor: 'artifact' }),
    needs: () => ['artifact.collect'],
  },
  {
    id: 'defender',
    section: 'response',
    label: () => 'Microsoft Defender…',
    keywords: 'antivirus scan signatures threat windows',
    role: 'analyst',
    action: () => ({ kind: 'form', anchor: 'defender' }),
    needs: () => ['defender.action'],
  },

  {
    id: 'reboot',
    section: 'endpoint',
    label: () => 'Reboot…',
    keywords: 'restart power',
    role: 'admin',
    action: () => ({ kind: 'power', type: 'host.reboot' }),
    needs: () => ['host.reboot'],
  },
  {
    id: 'shutdown',
    section: 'endpoint',
    label: () => 'Shut down…',
    keywords: 'power off halt',
    role: 'admin',
    action: () => ({ kind: 'power', type: 'host.shutdown' }),
    needs: () => ['host.shutdown'],
  },
  {
    id: 'move-group',
    section: 'endpoint',
    label: () => 'Move to group…',
    keywords: 'group policy organisation',
    role: 'admin',
    action: () => ({ kind: 'group' }),
  },
  {
    id: 'search',
    section: 'endpoint',
    label: () => 'Search events on this host',
    keywords: 'events logs query timeline',
    role: 'viewer',
    action: () => ({ kind: 'search' }),
  },
  {
    id: 'applications',
    section: 'endpoint',
    label: () => 'Applications',
    keywords: 'software inventory packages installed programs',
    role: 'viewer',
    action: () => ({ kind: 'applications' }),
  },
  {
    id: 'rescan',
    section: 'endpoint',
    label: () => 'Rescan vulnerabilities',
    keywords: 'cve vulnerability scan software',
    role: 'analyst',
    action: () => ({ kind: 'rescan' }),
  },

  {
    id: 'restart-agent',
    section: 'agent',
    label: () => 'Restart agent',
    keywords: 'service reload',
    role: 'admin',
    action: () => ({ kind: 'command', type: 'agent.restart' }),
    needs: () => ['agent.restart'],
  },
  {
    id: 'agent-logs',
    section: 'agent',
    label: () => 'Fetch agent logs',
    keywords: 'diagnostics troubleshoot download',
    role: 'admin',
    action: () => ({ kind: 'command', type: 'agent.logs' }),
    needs: () => ['agent.logs'],
  },
  {
    id: 'flush-queue',
    section: 'agent',
    label: () => 'Flush event queue',
    keywords: 'spool backlog drop discard clear events',
    role: 'admin',
    action: () => ({ kind: 'command', type: 'agent.flush_queue' }),
    needs: () => ['agent.flush_queue'],
  },
  {
    id: 'update-now',
    section: 'agent',
    label: () => 'Update now',
    keywords: 'upgrade version agent release',
    role: 'admin',
    action: () => ({ kind: 'update-now' }),
  },
  {
    id: 'decommission',
    section: 'agent',
    label: (h) => (h.status === 'decommissioned' ? 'Restore (recommission)' : 'Decommission'),
    keywords: 'hide retire restore recommission',
    role: 'admin',
    action: (h) => ({ kind: h.status === 'decommissioned' ? 'recommission' : 'decommission' }),
  },
  {
    id: 'revoke',
    section: 'agent',
    label: () => 'Revoke agent…',
    keywords: 'certificate block distrust',
    role: 'admin',
    action: () => ({ kind: 'revoke' }),
  },

  {
    id: 'remove',
    section: 'danger',
    label: () => 'Remove host…',
    keywords: 'delete permanently erase',
    role: 'admin',
    action: () => ({ kind: 'remove' }),
  },
]

/** Items a network device (syslog source) can have: it runs no agent and has no software list. */
const NETWORK_ITEMS = new Set(['search', 'remove'])
const WINDOWS_ONLY = new Set(['defender'])

export type Availability = { state: 'enabled' } | { state: 'disabled'; reason: string } | { state: 'hidden' }

const isCommandItem = (it: MenuItem) => it.needs !== undefined

/** Whether `it` shows for `host` and `role`, and why not when it is disabled. */
export function availability(it: MenuItem, host: Host, role: Role | undefined): Availability {
  if (host.kind === 'network' && !NETWORK_ITEMS.has(it.id)) return { state: 'hidden' }
  if (WINDOWS_ONLY.has(it.id) && host.os.platform !== 'windows') return { state: 'hidden' }
  if (it.section === 'danger' && !can(role, 'admin')) return { state: 'hidden' }

  if (!can(role, it.role)) {
    return { state: 'disabled', reason: `Needs the ${it.role} role` }
  }
  const revoked = host.status === 'revoked'
  const decommissioned = host.status === 'decommissioned'
  if (isCommandItem(it) || it.id === 'update-now') {
    if (revoked) return { state: 'disabled', reason: 'This agent is revoked and no longer receives commands' }
    if (decommissioned) return { state: 'disabled', reason: 'This agent is decommissioned: restore it first' }
  }
  if (it.id === 'decommission' || it.id === 'revoke') {
    if (revoked) return { state: 'disabled', reason: 'This agent is already revoked' }
  }
  if (it.id === 'move-group' && revoked) return { state: 'disabled', reason: 'This agent is revoked' }
  if (it.needs && host.allowed_actions) {
    const missing = it.needs(host).filter((t) => !host.allowed_actions!.includes(t))
    // Quarantine / restore is one item for two commands: it works if either does.
    if (missing.length === it.needs(host).length) {
      return { state: 'disabled', reason: "Not allowed by this agent's local policy (allowed_actions in its config file)" }
    }
  }
  if (it.id === 'update-now') {
    if (host.update_now_at) return { state: 'disabled', reason: 'An update was already requested' }
    if (!canUpdateNow(host.update)) return { state: 'disabled', reason: 'No update is pending for this agent' }
  }
  return { state: 'enabled' }
}

export interface MenuEntry {
  item: MenuItem
  label: string
  availability: Availability
}

/** Every item that is not hidden for this host and role, in menu order. */
export function menuEntries(host: Host, role: Role | undefined): MenuEntry[] {
  const out: MenuEntry[] = []
  for (const item of MENU_ITEMS) {
    const a = availability(item, host, role)
    if (a.state !== 'hidden') out.push({ item, label: item.label(host), availability: a })
  }
  return out
}

/** Entries matching every word of `query` in their label, section or keywords. */
export function filterEntries(entries: MenuEntry[], query: string): MenuEntry[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return entries
  return entries.filter((e) => {
    const hay = `${e.label} ${SECTION_LABEL[e.item.section]} ${e.item.keywords}`.toLowerCase()
    return words.every((w) => hay.includes(w))
  })
}

export function isUnraid(host: Pick<Host, 'os'>): boolean {
  return /unraid/i.test([host.os.name, host.os.family, host.os.version].filter(Boolean).join(' '))
}

// ---- recently used and favourites ------------------------------------------------------

export const RECENT_KEY = 'homexdr.hostActions.recent'
export const FAVOURITES_KEY = 'homexdr.hostActions.favourites'
export const RECENT_MAX = 5

export function readList(key: string): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? '[]')
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
  } catch {
    return []
  }
}

export function writeList(key: string, list: string[]): void {
  try {
    localStorage.setItem(key, JSON.stringify(list))
  } catch {
    // storage blocked or full: the menu still works, it just forgets
  }
}

/** `id` moved to the front of the recent list, which keeps the last RECENT_MAX. */
export function pushRecent(list: string[], id: string): string[] {
  return [id, ...list.filter((x) => x !== id)].slice(0, RECENT_MAX)
}

export function toggleFavourite(list: string[], id: string): string[] {
  return list.includes(id) ? list.filter((x) => x !== id) : [...list, id]
}
