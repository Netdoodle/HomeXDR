// Defensive normalization of server responses where the wire format has been seen to
// drift from docs/api.md. Keep these small and covered by tests.

import type { Rule, RuleRepo, RuleValidateResponse } from './types'

/**
 * Rule.logsource keys are documented as lowercase (product/category/service). Accept any
 * casing (e.g. Go's default `Product`) and drop empty values so the UI treats them as unset.
 */
export function normalizeLogsource(ls: unknown): Rule['logsource'] {
  const out: Rule['logsource'] = {}
  if (!ls || typeof ls !== 'object') return out
  for (const [k, v] of Object.entries(ls as Record<string, unknown>)) {
    const key = k.toLowerCase()
    if ((key === 'product' || key === 'category' || key === 'service') && typeof v === 'string' && v !== '') out[key] = v
  }
  return out
}

export function normalizeRule<T extends Rule | undefined>(r: T): T {
  if (!r) return r
  return {
    ...r,
    tags: r.tags ?? [],
    mitre: r.mitre ?? [],
    logsource: normalizeLogsource(r.logsource),
  }
}

export function normalizeValidate(v: RuleValidateResponse): RuleValidateResponse {
  return v.rule ? { ...v, rule: normalizeRule(v.rule) } : v
}

/** Go encodes empty lists as null; the UI expects arrays. */
export function normalizeRuleRepo(r: RuleRepo): RuleRepo {
  return { ...r, paths: r.paths ?? [], statuses: r.statuses ?? [], folders: r.folders ?? [] }
}
