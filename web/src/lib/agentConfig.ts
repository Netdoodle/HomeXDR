import type { AgentConfig } from '../api/types'

const isNum = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n)

/** Defaults for the decoy section, used when a config predates it. */
export const DECOY_DEFAULTS = { enabled: true, check_interval_sec: 60 }
export const DECOY_MIN_INTERVAL = 15
export const DECOY_MAX_EXTRA = 32

/** An absolute Unix or Windows file path without wildcards (the server checks the same). */
export function isAbsDecoyPath(p: string): boolean {
  if (p.length > 1024 || /[*?\u0000]/.test(p) || p.endsWith('/') || p.endsWith('\\')) return false
  return (p.startsWith('/') && p.length > 1) || /^[A-Za-z]:\\./.test(p)
}

/** Client-side sanity checks before PUT /api/agent-config; the server validates again. */
export function validateAgentConfig(c: AgentConfig): string[] {
  const out: string[] = []
  if (!isNum(c.heartbeat_interval_sec) || c.heartbeat_interval_sec < 5) out.push('Heartbeat interval must be at least 5 seconds.')
  if (!isNum(c.inventory_interval_sec) || c.inventory_interval_sec < 0) out.push('Inventory interval must be a positive number.')
  if (!c.batch || !isNum(c.batch.max_events) || c.batch.max_events < 1) out.push('Batch max events must be at least 1.')
  if (!c.batch || !isNum(c.batch.flush_interval_ms) || c.batch.flush_interval_ms < 100) out.push('Batch flush interval must be at least 100 ms.')
  if (!isNum(c.spool_max_bytes) || c.spool_max_bytes < 16 * 1024 * 1024) out.push('Spool limit must be at least 16 MiB.')
  if (!c.fim || !isNum(c.fim.interval_sec) || c.fim.interval_sec < 60) out.push('FIM interval must be at least 60 seconds.')
  if (c.decoys) {
    if (!isNum(c.decoys.check_interval_sec) || c.decoys.check_interval_sec < DECOY_MIN_INTERVAL) out.push(`Decoy check interval must be at least ${DECOY_MIN_INTERVAL} seconds.`)
    const extra = c.decoys.extra ?? []
    if (extra.length > DECOY_MAX_EXTRA) out.push(`At most ${DECOY_MAX_EXTRA} extra decoy paths.`)
    for (const p of extra) if (!isAbsDecoyPath(p)) out.push(`Extra decoy path "${p}" must be an absolute file path.`)
  }
  if (!c.sensors) out.push('Sensors section is missing.')
  for (const [i, l] of (c.logs ?? []).entries()) if (!l.path?.trim()) out.push(`Log file ${i + 1} needs a path.`)
  for (const [i, f] of (c.filters ?? []).entries()) {
    if (!f.field?.trim()) out.push(`Filter ${i + 1} needs a field.`)
    if (!['equals', 'prefix', 'suffix', 'contains'].includes(f.op)) out.push(`Filter ${i + 1} has an unknown operator.`)
    if (!f.value?.trim()) out.push(`Filter ${i + 1} needs a value.`)
  }
  return out
}
