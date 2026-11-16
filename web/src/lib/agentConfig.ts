import type { AgentConfig, DecoyFile, DecoyOS } from '../api/types'

const isNum = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n)

export const DECOY_MIN_INTERVAL = 15
export const DECOY_MAX_FILES = 64
export const DECOY_MAX_PATH = 260
export const DECOY_HOME = '{home}'

/** The decoy locations agents use unless an admin changes them (shared/api/decoy.go). */
export function decoyDefaultFiles(): DecoyFile[] {
  return [
    { os: 'windows', path: '{home}\\Documents\\Passwords.xlsx', hidden: false },
    { os: 'windows', path: 'C:\\ProgramData\\Backup\\credentials.csv', hidden: false },
    { os: 'linux', path: '{home}/Documents/passwords.txt', hidden: false },
    { os: 'linux', path: '{home}/.aws/credentials.bak', hidden: false },
    { os: 'linux', path: '/var/backups/db-credentials.sql', hidden: false },
    { os: 'darwin', path: '{home}/Documents/Passwords.txt', hidden: false },
  ]
}

/** Defaults for the decoy section, used when a config predates it. */
export const DECOY_DEFAULTS = { enabled: true, check_interval_sec: 60, files: decoyDefaultFiles() }

/** The platforms of the decoy list, in the order shown. */
export const DECOY_PLATFORMS: { os: DecoyOS; label: string; placeholder: string }[] = [
  { os: 'windows', label: 'Windows', placeholder: '{home}\\Documents\\Logins.xlsx or C:\\Shares\\Finance\\logins.csv' },
  { os: 'linux', label: 'Linux', placeholder: '{home}/.config/backup.txt or /srv/share/passwords.txt' },
  { os: 'darwin', label: 'macOS', placeholder: '{home}/Documents/Logins.txt or /Users/Shared/passwords.txt' },
]

export const decoyOSLabel = (os: string) => DECOY_PLATFORMS.find((p) => p.os === os)?.label ?? os

/** Linux has no hidden attribute. */
export const decoyHiddenSupported = (os: DecoyOS) => os !== 'linux'
export const LINUX_HIDDEN_NOTE = 'Linux has no hidden attribute; start the file name with a dot instead.'

const isDrive = (c: string) => /^[A-Za-z]$/.test(c)

/**
 * What is wrong with a decoy path for a platform, or '' when it is usable. The same rules
 * as the server (DecoyPathProblem in shared/api/decoy.go).
 */
export function decoyPathProblem(os: string, p: string): string {
  if (os !== 'windows' && os !== 'linux' && os !== 'darwin') return `unknown platform "${os}"`
  if (p === '') return 'enter a path'
  if ([...p].length > DECOY_MAX_PATH) return `is longer than ${DECOY_MAX_PATH} characters`
  if (/[*?]/.test(p)) return 'must not contain wildcards (* or ?)'
  for (const ch of p) {
    const c = ch.codePointAt(0)!
    if (c < 0x20 || c === 0x7f) return 'must not contain control characters'
  }
  const sep = os === 'windows' ? '\\' : '/'
  let rest: string
  if (os === 'windows') {
    if (p.includes('/')) return 'use \\ as the separator on Windows'
    if (/[<>"|]/.test(p)) return 'must not contain < > " or |'
    if (p.startsWith(DECOY_HOME + sep)) rest = p.slice(DECOY_HOME.length + 1)
    else if (p.length >= 3 && isDrive(p[0]) && p[1] === ':' && p[2] === '\\') rest = p.slice(3)
    else return 'must start with {home}\\ or a drive such as C:\\'
    if (rest.includes(':')) return 'must not contain a colon after the drive letter'
  } else {
    if (p.includes('\\')) return 'use / as the separator on Linux and macOS'
    if (p.startsWith(DECOY_HOME + sep)) rest = p.slice(DECOY_HOME.length + 1)
    else if (p.startsWith('/')) rest = p.slice(1)
    else return 'must start with {home}/ or /'
  }
  if (rest.includes(DECOY_HOME)) return '{home} can only be at the start'
  const segs = rest.split(sep)
  if (segs[segs.length - 1] === '') return 'must end with a file name'
  for (const s of segs) {
    if (s === '') return 'must not contain two separators in a row'
    if (s === '.' || s === '..') return 'must not contain "." or ".." folders'
  }
  return ''
}

/** The problem of each row of the decoy list ('' when fine), including duplicates. */
export function decoyRowProblems(files: DecoyFile[]): string[] {
  const seen = new Set<string>()
  return files.map((f) => {
    const p = f.path.trim()
    const msg = decoyPathProblem(f.os, p)
    if (msg) return msg
    const key = `${f.os}\u0000${p}`
    if (seen.has(key)) return 'is listed twice'
    seen.add(key)
    return ''
  })
}

/** Adds an empty row for a platform. */
export const addDecoyFile = (files: DecoyFile[], os: DecoyOS): DecoyFile[] => [...files, { os, path: '', hidden: false }]

export const removeDecoyFile = (files: DecoyFile[], i: number): DecoyFile[] => files.filter((_, j) => j !== i)

export const updateDecoyFile = (files: DecoyFile[], i: number, patch: Partial<Omit<DecoyFile, 'os'>>): DecoyFile[] =>
  files.map((f, j) => (j === i ? { ...f, ...patch } : f))

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
    const files = c.decoys.files ?? []
    if (files.length > DECOY_MAX_FILES) out.push(`At most ${DECOY_MAX_FILES} decoy files.`)
    decoyRowProblems(files).forEach((msg, i) => {
      if (msg) out.push(`Decoy file "${files[i].path.trim()}" (${decoyOSLabel(files[i].os)}): ${msg}.`)
    })
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
