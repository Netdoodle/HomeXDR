// Rule repositories: presets for the import dialog and display helpers.

import type { RuleRepo, RuleRepoSettings, SigmaStatus } from '../api/types'
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
