// Number, byte and text formatting.

export function formatBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = n
  let i = 0
  while (Math.abs(v) >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

/** Formats a configured size the way it was likely written: 1e12 as "1 TB", 2^40 as "1 TiB". */
export function formatSizeSetting(n: number): string {
  const bin = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const dec = ['B', 'kB', 'MB', 'GB', 'TB', 'PB']
  for (let i = 5; i > 0; i--) {
    if (n >= 1024 ** i && n % 1024 ** i === 0) return `${n / 1024 ** i} ${bin[i]}`
    if (n >= 1000 ** i && n % 1000 ** i === 0) return `${n / 1000 ** i} ${dec[i]}`
  }
  return formatBytes(n)
}

const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })
const plain = new Intl.NumberFormat('en')

/** 1,284 below ten thousand; 12.9K, 4.2M above. */
export function formatCount(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—'
  return Math.abs(n) < 10_000 ? plain.format(n) : compact.format(n)
}

export function formatNumber(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—'
  return plain.format(n)
}

export function plural(n: number, one: string, many = one + 's'): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`
}

export function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

/** Splits "a, b,  c" / newline lists into trimmed, non-empty, unique items. */
export function splitList(s: string): string[] {
  const out: string[] = []
  for (const part of s.split(/[\n,]/)) {
    const t = part.trim()
    if (t && !out.includes(t)) out.push(t)
  }
  return out
}

export function titleCase(s: string): string {
  return s.replace(/[_.-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function prettyJSON(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2)
  } catch {
    return String(v)
  }
}
