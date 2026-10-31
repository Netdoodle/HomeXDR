// Mock rule repository downloads: a SigmaHQ-shaped folder layout (paths and metadata
// only) for the folder tree.

import type { RuleRepoFile, RuleRepoSkip, RuleRepoSettings } from '../api/types'
import { passesFilters, pathSelected, selectionFromPaths } from '../lib/ruleRepos'

const LAYOUT: [string, string, number][] = [
  ['rules/linux/process_creation', 'linux', 120],
  ['rules/linux/network_connection', 'linux', 8],
  ['rules/linux/file_event', 'linux', 21],
  ['rules/linux/auditd', 'linux', 43],
  ['rules/windows/process_creation', 'windows', 1205],
  ['rules/windows/registry', 'windows', 196],
  ['rules/windows/powershell', 'windows', 161],
  ['rules/windows/image_load', 'windows', 152],
  ['rules/network/firewall', '', 5],
  ['rules/network/dns', '', 8],
  ['rules/cloud/aws', 'aws', 63],
  ['rules/cloud/azure', 'azure', 71],
  ['rules/web/webserver', '', 30],
  ['rules-emerging-threats/2024', 'windows', 39],
  ['rules-emerging-threats/2025', 'windows', 47],
  ['rules-threat-hunting/windows', 'windows', 81],
  ['deprecated/windows', 'windows', 153],
  ['unsupported/windows', 'windows', 60],
]
const LEVELS = ['medium', 'high', 'low', 'high', 'medium', 'critical', 'informational', 'medium']

let cache: RuleRepoFile[] | null = null

/** Every rule in a mock download. */
export function repoFiles(): RuleRepoFile[] {
  if (cache) return cache
  const out: RuleRepoFile[] = []
  for (const [dir, product, n] of LAYOUT) {
    for (let i = 0; i < n; i++) {
      const status = dir.startsWith('deprecated') ? 'deprecated' : dir.startsWith('unsupported') ? 'unsupported' : ['stable', 'test', 'test', 'experimental'][i % 4]
      const unsupported = dir.startsWith('unsupported') ? i % 5 !== 0 : i % 211 === 17
      out.push({
        path: `${dir}/rule_${String(i + 1).padStart(4, '0')}.yml`,
        status,
        level: LEVELS[i % LEVELS.length],
        product: product || undefined,
        error: unsupported ? (i % 2 ? 'aggregation conditions are not supported' : 'correlation rules are not supported') : undefined,
      })
    }
  }
  cache = out.sort((a, b) => a.path.localeCompare(b.path))
  return cache
}

/** Rules in the chosen folders that do not load. */
export function repoSkipped(s: Pick<RuleRepoSettings, 'paths' | 'statuses' | 'min_level'>): RuleRepoSkip[] {
  const sel = selectionFromPaths(s.paths)
  return repoFiles()
    .filter((f) => f.error && pathSelected(sel, f.path) && passesFilters(s, f))
    .map((f) => ({ path: f.path, error: f.error! }))
}
