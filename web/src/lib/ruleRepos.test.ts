import { describe, expect, it } from 'vitest'
import type { RuleRepo, RuleRepoFile } from '../api/types'
import { normalizeRuleRepo } from '../api/normalize'
import {
  buildTree,
  DEFAULT_REPO_SETTINGS,
  folderCounts,
  folderState,
  isArchiveUrl,
  levelAtLeast,
  parseFolders,
  pathsFromSelection,
  REPO_PRESETS,
  repoRulesSummary,
  repoState,
  selectionFromPaths,
  selectionSummary,
  shortRepoVersion,
  statusAllowed,
  toggleFolder,
} from './ruleRepos'

const repo = (over: Partial<RuleRepo> = {}): RuleRepo => ({
  ...DEFAULT_REPO_SETTINGS,
  id: 'r1',
  kind: 'git',
  update_available: false,
  syncing: false,
  files: 0,
  folders: [],
  added: 0,
  removed: 0,
  rules: 0,
  rules_enabled: 0,
  filtered: 0,
  duplicates: 0,
  load_errors: 0,
  created_at: '2026-10-30T00:00:00Z',
  created_by: 'admin',
  ...over,
})

describe('rule repositories', () => {
  it('offers SigmaHQ presets with folders and a custom choice', () => {
    expect(REPO_PRESETS.map((p) => p.id)).toEqual(['sigmahq', 'sigmahq-core', 'custom'])
    expect(REPO_PRESETS[0].settings.paths).toEqual(['rules/windows', 'rules/linux'])
    expect(isArchiveUrl(REPO_PRESETS[1].settings.url!)).toBe(true)
    expect(isArchiveUrl(REPO_PRESETS[0].settings.url!)).toBe(false)
  })

  it('recognizes archive URLs like the server', () => {
    expect(isArchiveUrl('https://x/y/rules.tar.gz?token=1')).toBe(true)
    expect(isArchiveUrl('https://x/y/RULES.TGZ')).toBe(true)
    expect(isArchiveUrl('https://github.com/SigmaHQ/sigma/tree/master/rules')).toBe(false)
  })

  it('cleans folders typed one per line', () => {
    expect(parseFolders(' /rules/windows/ \n\nrules\\linux\nrules/windows\n')).toEqual(['rules/windows', 'rules/linux'])
  })

  it('shortens commits and archive hashes', () => {
    expect(shortRepoVersion('05d1031f537e830b76da53bae2400c5814c89165')).toBe('05d1031')
    expect(shortRepoVersion('sha256:45ccbd62cbf0aa')).toBe('45ccbd6')
    expect(shortRepoVersion(undefined)).toBe('')
  })

  it('derives one state for the status line', () => {
    expect(repoState(repo({ syncing: true, error: 'x' }))).toBe('syncing')
    expect(repoState(repo({ enabled: false, error: 'x' }))).toBe('disabled')
    expect(repoState(repo({ error: 'HTTP 404' }))).toBe('error')
    expect(repoState(repo())).toBe('never')
    expect(repoState(repo({ version: 'a', latest_version: 'b', update_available: true }))).toBe('update')
    expect(repoState(repo({ version: 'a', latest_version: 'a' }))).toBe('current')
  })

  it('summarizes what a repository contributes', () => {
    expect(repoRulesSummary(repo({ rules: 1954, rules_enabled: 1950, duplicates: 1202, load_errors: 5 }))).toEqual([
      '1954 rules loaded, 1950 enabled',
      '1202 already provided by another source',
      '5 failed to load',
    ])
  })

  it('fills lists Go sent as null', () => {
    const r = normalizeRuleRepo({ ...repo(), paths: null, statuses: null, folders: null } as unknown as RuleRepo)
    expect([r.paths, r.statuses, r.folders]).toEqual([[], [], []])
  })
})

describe('choosing folders from a tree', () => {
  const files: RuleRepoFile[] = [
    { path: 'rules/linux/a.yml', status: 'stable', level: 'high', product: 'linux' },
    { path: 'rules/linux/b.yml', status: 'experimental', level: 'medium', product: 'linux' },
    { path: 'rules/linux/auditd/c.yml', status: 'test', level: 'low', product: 'linux' },
    { path: 'rules/windows/w.yml', status: 'stable', level: 'critical', product: 'windows', error: 'unsupported' },
    { path: 'rules/top.yml', level: 'informational' },
    { path: 'deprecated/old.yml', status: 'deprecated', level: 'high' },
  ]

  it('applies the server filters', () => {
    expect(statusAllowed('deprecated', [])).toBe(false)
    expect(statusAllowed('experimental', [])).toBe(true)
    expect(statusAllowed(undefined, ['stable'])).toBe(true)
    expect(statusAllowed('test', ['stable'])).toBe(false)
    expect(levelAtLeast('low', '')).toBe(true)
    expect(levelAtLeast('low', 'medium')).toBe(false)
  })

  it('maps paths to a selection and back', () => {
    expect(selectionFromPaths([])).toEqual([''])
    expect(pathsFromSelection([''])).toEqual([])
    expect(pathsFromSelection(['rules/linux'])).toEqual(['rules/linux'])
    expect(pathsFromSelection([])).toBeNull()
  })

  it('counts folders under the filters', () => {
    const counts = folderCounts(files, { statuses: ['stable', 'test'], min_level: 'low' })
    expect(counts.get('rules')).toEqual({ total: 5, matching: 3, unsupported: 1 })
    expect(counts.get('')!.total).toBe(6)
    const { root, byPath } = buildTree(files)
    expect(root.children.map((c) => c.name)).toEqual(['deprecated', 'rules'])
    expect(byPath.get('rules')!.files.map((f) => f.path)).toEqual(['rules/top.yml'])
  })

  it('splits a selection when a subfolder is cleared', () => {
    const { byPath } = buildTree(files)
    let sel = toggleFolder([''], 'deprecated', byPath)
    expect(sel).toEqual(['rules'])
    sel = toggleFolder(sel, 'rules/linux/auditd', byPath)
    expect(sel).toEqual(['rules/linux/a.yml', 'rules/linux/b.yml', 'rules/top.yml', 'rules/windows'])
    expect(folderState(sel, 'rules')).toBe('partial')
    expect(folderState(sel, '')).toBe('partial')
    sel = toggleFolder(sel, 'rules', byPath)
    expect(sel).toEqual(['rules'])
    expect(toggleFolder(sel, '', byPath)).toEqual([''])
  })

  it('summarizes what loads', () => {
    expect(selectionSummary(files, ['rules'], { statuses: [], min_level: '' })).toEqual({
      selected: 5,
      runnable: 4,
      unsupported: 1,
      products: [
        ['linux', 3],
        ['windows', 1],
        ['other', 1],
      ],
    })
  })
})
