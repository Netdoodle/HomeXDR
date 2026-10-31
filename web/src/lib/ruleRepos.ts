// Rule repositories: presets for the import dialog and display helpers.

import type { RuleRepo, RuleRepoFile, RuleRepoSettings, SigmaStatus } from '../api/types'
import type { Choice } from './ai'

export interface RepoPreset {
  id: string
  label: string
  note: string
  settings: Partial<RuleRepoSettings>
}

/** SigmaHQ's rules are DRL 1.1 licensed (attribution required), so they are not bundled. */
export const REPO_PRESETS: RepoPreset[] = [
  {
    id: 'sigmahq',
    label: 'SigmaHQ: Windows and Linux',
    note: 'The SigmaHQ repository’s default branch, rules/windows and rules/linux, medium level and above (about 2,400 rules). New rules land here first.',
    settings: { name: 'SigmaHQ', url: 'https://github.com/SigmaHQ/sigma', ref: '', paths: ['rules/windows', 'rules/linux'], min_level: 'medium' },
  },
  {
    id: 'sigmahq-core',
    label: 'SigmaHQ Core release',
    note: 'SigmaHQ’s curated release package: stable and test rules of high and critical level (about 1,200 for Windows and Linux). Changes when SigmaHQ publishes a release.',
    settings: {
      name: 'SigmaHQ Core',
      url: 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip',
      ref: '',
      paths: ['rules/windows', 'rules/linux'],
      min_level: '',
    },
  },
  {
    id: 'custom',
    label: 'Another repository or archive',
    note: 'Any public git repository on GitHub, GitLab, Gitea/Forgejo or Bitbucket, or a link to a .zip or .tar.gz of Sigma rules.',
    settings: { name: '', url: '', ref: '', paths: [], min_level: '' },
  },
]

export const DEFAULT_REPO_SETTINGS: RuleRepoSettings = {
  name: '',
  url: '',
  ref: '',
  paths: [],
  min_level: '',
  statuses: ['stable', 'test', 'experimental'],
  enable_rules: true,
  auto_update: true,
  interval_hours: 24,
  enabled: true,
}

export const SIGMA_STATUSES: { value: SigmaStatus; note: string }[] = [
  { value: 'stable', note: 'tested for a long time' },
  { value: 'test', note: 'most SigmaHQ rules' },
  { value: 'experimental', note: 'new, may be noisy' },
  { value: 'deprecated', note: 'replaced by other rules' },
  { value: 'unsupported', note: 'needs features Sigma engines lack' },
]

export const UPDATE_CHOICES: Choice<'auto' | 'manual'>[] = [
  {
    value: 'auto',
    label: 'Automatic',
    note: 'Install new versions as soon as a check finds them. New rules start enabled or disabled as chosen above; rules you switched on or off keep your choice.',
  },
  {
    value: 'manual',
    label: 'Manual',
    note: 'Checks only report that an update is available. Nothing changes until you click Update.',
  },
]

export const INTERVAL_CHOICES: { hours: number; label: string }[] = [
  { hours: 1, label: 'Every hour' },
  { hours: 6, label: 'Every 6 hours' },
  { hours: 12, label: 'Every 12 hours' },
  { hours: 24, label: 'Daily' },
  { hours: 168, label: 'Weekly' },
]

export function intervalLabel(hours: number): string {
  return INTERVAL_CHOICES.find((c) => c.hours === hours)?.label ?? `Every ${hours} hours`
}

/** A commit or archive hash, shortened for display. */
export function shortRepoVersion(v?: string): string {
  if (!v) return ''
  return v.replace(/^sha256:/, '').slice(0, 7)
}

/** Whether a URL points at an archive rather than a git repository (mirrors the server). */
export function isArchiveUrl(url: string): boolean {
  const path = url.trim().split(/[?#]/)[0].toLowerCase()
  return path.endsWith('.zip') || path.endsWith('.tar.gz') || path.endsWith('.tgz')
}

/** Folders typed one per line, cleaned of blanks, slashes and duplicates. */
export function parseFolders(text: string): string[] {
  const out: string[] = []
  for (const line of text.split('\n')) {
    const f = line.trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '')
    if (f && !out.includes(f)) out.push(f)
  }
  return out
}

export type RepoState = 'syncing' | 'error' | 'never' | 'update' | 'current' | 'disabled'

export function repoState(r: RuleRepo): RepoState {
  if (r.syncing) return 'syncing'
  if (!r.enabled) return 'disabled'
  if (r.error) return 'error'
  if (!r.version) return 'never'
  if (r.update_available) return 'update'
  return 'current'
}

/** One line on what a repository contributes: "1,954 rules, 1,950 enabled · 12 below the level filter". */
export function repoRulesSummary(r: RuleRepo, fmt: (n: number) => string = String): string[] {
  const parts = [`${fmt(r.rules)} ${r.rules === 1 ? 'rule' : 'rules'} loaded, ${fmt(r.rules_enabled)} enabled`]
  if (r.filtered) parts.push(`${fmt(r.filtered)} skipped by the level or status filter`)
  if (r.duplicates) parts.push(`${fmt(r.duplicates)} already provided by another source`)
  if (r.load_errors) parts.push(`${fmt(r.load_errors)} failed to load`)
  return parts
}

// --- Choosing folders from a tree of the download (mirrors the server's filters) -------------

const LEVEL_RANK: Record<string, number> = { informational: 1, low: 2, medium: 3, high: 4, critical: 5 }

/** The server's level filter: no minimum loads every level. */
export function levelAtLeast(level: string, min: string): boolean {
  return !min || (LEVEL_RANK[level] ?? 0) >= (LEVEL_RANK[min] ?? 0)
}

/** The server's status filter: none ticked loads all but deprecated and unsupported; rules without a status always load. */
export function statusAllowed(status: string | undefined, allowed: string[]): boolean {
  if (!status) return true
  if (allowed.length === 0) return status !== 'deprecated' && status !== 'unsupported'
  return allowed.includes(status)
}

type Filters = Pick<RuleRepoSettings, 'statuses' | 'min_level'>

export function passesFilters(s: Filters, f: Pick<RuleRepoFile, 'status' | 'level'>): boolean {
  return statusAllowed(f.status, s.statuses) && levelAtLeast(f.level, s.min_level)
}

/**
 * The tree works on a selection where "" is the whole repository and [] is nothing; the
 * server's paths use [] for the whole repository.
 */
export function selectionFromPaths(paths: string[]): string[] {
  return paths.length ? paths : ['']
}

/** Paths to save for a selection, or null when nothing is selected. */
export function pathsFromSelection(sel: string[]): string[] | null {
  if (sel.includes('')) return []
  return sel.length ? sel : null
}

export function pathSelected(sel: string[], path: string): boolean {
  return sel.some((p) => p === '' || path === p || path.startsWith(p + '/'))
}

export interface FolderNode {
  path: string // "" for the repository root
  name: string
  children: FolderNode[]
  /** Rule files directly in this folder. */
  files: RuleRepoFile[]
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/')
  return i < 0 ? '' : path.slice(0, i)
}

/** The folder tree of a download's rule files (folders sorted by name). */
export function buildTree(files: RuleRepoFile[]): { root: FolderNode; byPath: Map<string, FolderNode> } {
  const root: FolderNode = { path: '', name: '', children: [], files: [] }
  const byPath = new Map<string, FolderNode>([['', root]])
  const nodeFor = (path: string): FolderNode => {
    const have = byPath.get(path)
    if (have) return have
    const parent = nodeFor(dirOf(path))
    const n: FolderNode = { path, name: path.slice(path.lastIndexOf('/') + 1), children: [], files: [] }
    parent.children.push(n)
    byPath.set(path, n)
    return n
  }
  for (const f of files) {
    const n = nodeFor(dirOf(f.path))
    if (!n.files.some((x) => x.path === f.path)) n.files.push(f) // a file can hold several rules
  }
  for (const n of byPath.values()) n.children.sort((a, b) => a.name.localeCompare(b.name))
  return { root, byPath }
}

export interface FolderCounts {
  /** Rules in the folder (recursively). */
  total: number
  /** Passing the level and status filters. */
  matching: number
  /** Passing the filters but unable to run. */
  unsupported: number
}

/** Counts every folder's rules under the current filters. */
export function folderCounts(files: RuleRepoFile[], s: Filters): Map<string, FolderCounts> {
  const out = new Map<string, FolderCounts>()
  for (const f of files) {
    const match = passesFilters(s, f)
    let dir = dirOf(f.path)
    for (;;) {
      const c = out.get(dir) ?? { total: 0, matching: 0, unsupported: 0 }
      c.total++
      if (match) {
        c.matching++
        if (f.error) c.unsupported++
      }
      out.set(dir, c)
      if (dir === '') break
      dir = dirOf(dir)
    }
  }
  return out
}

export type CheckState = 'on' | 'partial' | 'off'

export function folderState(sel: string[], folder: string): CheckState {
  if (pathSelected(sel, folder)) return 'on'
  return sel.some((p) => folder === '' || p.startsWith(folder + '/')) ? 'partial' : 'off'
}

/**
 * Selects or clears a folder. Clearing a folder inside a selected one replaces that
 * selection with everything else it held (sibling folders and files on the way down).
 */
export function toggleFolder(sel: string[], folder: string, byPath: Map<string, FolderNode>): string[] {
  if (!pathSelected(sel, folder)) {
    const next = sel.filter((p) => !(folder === '' || p.startsWith(folder + '/')))
    next.push(folder)
    return next.sort()
  }
  const cover = sel.find((p) => p === '' || folder === p || folder.startsWith(p + '/'))!
  const next = sel.filter((p) => p !== cover)
  let node = byPath.get(cover)
  while (node && node.path !== folder) {
    const onPath = node.children.find((c) => folder === c.path || folder.startsWith(c.path + '/'))
    for (const c of node.children) if (c !== onPath) next.push(c.path)
    for (const f of node.files) next.push(f.path)
    node = onPath
  }
  return next.sort()
}

/** What a selection loads: rule counts and the most common products. */
export function selectionSummary(files: RuleRepoFile[], sel: string[], s: Filters) {
  let selected = 0
  let runnable = 0
  const products = new Map<string, number>()
  for (const f of files) {
    if (!pathSelected(sel, f.path) || !passesFilters(s, f)) continue
    selected++
    if (!f.error) runnable++
    const p = f.product || 'other'
    products.set(p, (products.get(p) ?? 0) + 1)
  }
  return { selected, runnable, unsupported: selected - runnable, products: [...products.entries()].sort((a, b) => b[1] - a[1]) }
}
