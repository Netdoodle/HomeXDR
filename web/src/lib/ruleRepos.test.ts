import { describe, expect, it } from 'vitest'
import type { RuleRepo } from '../api/types'
import { normalizeRuleRepo } from '../api/normalize'
import { DEFAULT_REPO_SETTINGS, isArchiveUrl, parseFolders, REPO_PRESETS, repoRulesSummary, repoState, shortRepoVersion } from './ruleRepos'

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
