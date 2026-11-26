// Helpers for the running-process list on the Kill process card. The list comes from the
// agent's process.list artifact, so rows are loosely typed.

import type { Row } from '../api/types'

export interface ProcRow {
  pid: number
  ppid: number
  entity_id: string
  name: string
  executable: string
  command_line: string
  user: string
  start: string
  /** number of listed processes whose parent is this one */
  children: number
}

export type ProcSort = 'name' | 'pid' | 'user' | 'start'

const str = (v: unknown) => (v === undefined || v === null ? '' : String(v))

/** Turns artifact rows into process rows, dropping rows without a usable PID. */
export function toProcRows(rows: Row[]): ProcRow[] {
  const out: ProcRow[] = []
  for (const r of rows) {
    const pid = Number(r.pid)
    if (!Number.isInteger(pid) || pid <= 0) continue
    out.push({
      pid,
      ppid: Number(r.ppid) || 0,
      entity_id: str(r.entity_id),
      name: str(r.name) || str(r.executable).split(/[\\/]/).pop() || `PID ${pid}`,
      executable: str(r.executable),
      command_line: str(r.command_line),
      user: str(r.user),
      start: str(r.start),
      children: 0,
    })
  }
  const kids = new Map<number, number>()
  for (const p of out) if (p.ppid) kids.set(p.ppid, (kids.get(p.ppid) ?? 0) + 1)
  for (const p of out) p.children = kids.get(p.pid) ?? 0
  return out
}

/** Every word must appear in the name, PID, user, executable or command line. */
export function filterProcs(rows: ProcRow[], text: string): ProcRow[] {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return rows
  return rows.filter((p) => {
    const hay = `${p.name} ${p.pid} ${p.user} ${p.executable} ${p.command_line}`.toLowerCase()
    return words.every((w) => hay.includes(w))
  })
}

export function sortProcs(rows: ProcRow[], by: ProcSort, desc = false): ProcRow[] {
  const cmp = (a: ProcRow, b: ProcRow): number => {
    switch (by) {
      case 'pid':
        return a.pid - b.pid
      case 'user':
        return a.user.localeCompare(b.user) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) || a.pid - b.pid
      case 'start': {
        const ta = Date.parse(a.start) || 0
        const tb = Date.parse(b.start) || 0
        return ta - tb || a.pid - b.pid
      }
      default:
        return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) || a.pid - b.pid
    }
  }
  const out = [...rows].sort(cmp)
  return desc ? out.reverse() : out
}
