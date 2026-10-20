// A small client-side model of the server's search pipeline (server/internal/events/
// pipeline.go), used by the mock backend. It covers the common commands; where, eval and
// rex need the real server.

import type { ResultColumn, SearchResponse } from '../api/types'
import { commandName, compileQuery, fieldValues, splitPipeline } from './query'

type Row = Record<string, unknown>

const SPANS_SEC = [1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 10800, 21600, 43200, 86400, 604800, 2592000]

/** Smallest bucket size (seconds) giving at most 100 buckets, as on the server. */
export function pickSpan(rangeMs: number): number {
  for (const s of SPANS_SEC) if (rangeMs / (s * 1000) <= 100) return s
  return SPANS_SEC[SPANS_SEC.length - 1]
}

/** Bucket starts (ms) covering [from, to). */
export function buckets(from: number, to: number, spanSec: number): number[] {
  const ms = spanSec * 1000
  const out: number[] = []
  for (let t = Math.floor(from / ms) * ms; t < to; t += ms) out.push(t)
  return out
}

function parseSpan(s: string): number {
  const m = /^(\d+)(s|m|h|d|w)$/.exec(s)
  if (!m) throw new Error(`span ${s}: use a number and a unit, e.g. 5m`)
  return Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[m[2] as 's']
}

/** Tokens of a command: quoted strings, name(field) calls, words; commas dropped. */
function tokens(s: string): string[] {
  return (s.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_@][\w@.]*\([^)]*\)|[^\s,]+/g) ?? []).map((t) =>
    /^['"]/.test(t) ? t.slice(1, -1) : t,
  )
}

interface Agg {
  fn: string
  field?: string
  as: string
}

const AGG_FNS: Record<string, string> = { count: 'count', dc: 'dc', distinct_count: 'dc', sum: 'sum', avg: 'avg', mean: 'avg', min: 'min', max: 'max', values: 'values' }

function parseAggs(toks: string[]): { aggs: Agg[]; by: string[] } {
  const aggs: Agg[] = []
  let i = 0
  while (i < toks.length && toks[i].toLowerCase() !== 'by') {
    const m = /^(\w+)(?:\(([^)]*)\))?$/.exec(toks[i])
    const fn = m ? AGG_FNS[m[1].toLowerCase()] : undefined
    if (!m || !fn) throw new Error(`unknown aggregation ${toks[i]}`)
    const agg: Agg = { fn, field: m[2] || undefined, as: toks[i].toLowerCase() === 'c' ? 'count' : toks[i] }
    i++
    if (toks[i]?.toLowerCase() === 'as' && toks[i + 1]) {
      agg.as = toks[i + 1]
      i += 2
    }
    aggs.push(agg)
  }
  if (aggs.length === 0) throw new Error('name at least one aggregation, e.g. stats count by host')
  return { aggs, by: toks.slice(i + 1) }
}

interface State {
  events: boolean
  rows: unknown[]
  columns: string[]
}

function get(state: State, row: unknown, field: string): unknown {
  if (!state.events) return (row as Row)[field]
  const vals = field === '_time' ? fieldValues(row, '@timestamp') : fieldValues(row, field)
  if (vals.length === 0) return undefined
  return vals.length === 1 ? vals[0] : vals
}

const present = (v: unknown) => v !== undefined && v !== null && v !== ''

function aggregate(state: State, rows: unknown[], a: Agg): unknown {
  if (a.fn === 'count' && !a.field) return rows.length
  const vals = rows.map((r) => get(state, r, a.field!)).filter(present)
  const nums = vals.map(Number).filter((n) => Number.isFinite(n))
  switch (a.fn) {
    case 'count':
      return vals.length
    case 'dc':
      return new Set(vals.map(String)).size
    case 'sum':
      return nums.reduce((x, y) => x + y, 0)
    case 'avg':
      return nums.length ? nums.reduce((x, y) => x + y, 0) / nums.length : null
    case 'min':
      return nums.length ? Math.min(...nums) : null
    case 'max':
      return nums.length ? Math.max(...nums) : null
    case 'values':
      return [...new Set(vals.flat().map(String))].sort().slice(0, 100)
  }
  return null
}

/** Groups rows by the by-fields; array values (event.category) split into one group each. */
function group(state: State, rows: unknown[], by: string[]): Map<string, { key: unknown[]; rows: unknown[] }> {
  const groups = new Map<string, { key: unknown[]; rows: unknown[] }>()
  for (const r of rows) {
    let keys: unknown[][] = [[]]
    for (const f of by) {
      const v = get(state, r, f)
      const list = (Array.isArray(v) ? v : [v]).filter(present)
      keys = keys.flatMap((k) => list.map((x) => [...k, x]))
    }
    for (const k of keys) {
      const id = JSON.stringify(k)
      const g = groups.get(id) ?? { key: k, rows: [] }
      g.rows.push(r)
      groups.set(id, g)
    }
  }
  return groups
}

function compareValues(a: unknown, b: unknown): number {
  if (!present(a)) return present(b) ? 1 : 0
  if (!present(b)) return -1
  const x = Number(a)
  const y = Number(b)
  if (Number.isFinite(x) && Number.isFinite(y)) return x - y
  return String(a).localeCompare(String(b))
}

function table(columns: string[], groups: Iterable<{ key: unknown[]; rows: unknown[] }>, extra: (g: { rows: unknown[] }) => unknown[], names: string[]): State {
  const rows: Row[] = []
  for (const g of groups) {
    const row: Row = {}
    columns.forEach((c, i) => (row[c] = g.key[i]))
    extra(g).forEach((v, i) => (row[names[i]] = v))
    rows.push(row)
  }
  return { events: false, rows, columns: [...columns, ...names] }
}

/** Runs a pipeline over already-filtered events (newest first). */
export function runPipeline(events: unknown[], query: string, range: { from: number; to: number }): SearchResponse {
  const { commands } = splitPipeline(query)
  let state: State = { events: true, rows: events, columns: [] }
  let chart: string | undefined
  let span: number | undefined
  for (const c of commands) {
    const name = commandName(c.text)
    const toks = tokens(c.text.slice(name.length))
    const opt = (key: string) => {
      const t = toks.find((x) => x.toLowerCase().startsWith(key + '='))
      if (t) toks.splice(toks.indexOf(t), 1)
      return t?.slice(key.length + 1)
    }
    switch (name) {
      case 'search': {
        if (!state.events) throw new Error('search: use where after stats, top or table')
        const match = compileQuery(c.text.slice(name.length))
        state = { ...state, rows: state.rows.filter(match) }
        break
      }
      case 'head':
      case 'limit':
        state = { ...state, rows: state.rows.slice(0, Number(toks[0] ?? 10)) }
        break
      case 'sort': {
        let limit = 0
        if (/^\d+$/.test(toks[0] ?? '')) limit = Number(toks.shift())
        const keys = toks.map((t) => ({ f: t.replace(/^[-+]/, ''), desc: t.startsWith('-') }))
        const rows = [...state.rows].sort((a, b) => {
          for (const k of keys) {
            const d = compareValues(get(state, a, k.f), get(state, b, k.f))
            if (d) return k.desc ? -d : d
          }
          return 0
        })
        state = { ...state, rows: limit ? rows.slice(0, limit) : rows }
        break
      }
      case 'dedup': {
        let n = 1
        if (/^\d+$/.test(toks[0] ?? '')) n = Number(toks.shift())
        const seen = new Map<string, number>()
        state = {
          ...state,
          rows: state.rows.filter((r) => {
            const vals = toks.map((f) => get(state, r, f))
            if (!vals.every(present)) return false
            const k = JSON.stringify(vals)
            seen.set(k, (seen.get(k) ?? 0) + 1)
            return seen.get(k)! <= n
          }),
        }
        break
      }
      case 'table':
      case 'fields':
        state = { events: false, columns: toks, rows: state.rows.map((r) => Object.fromEntries(toks.map((f) => [f, get(state, r, f)]))) }
        break
      case 'rename': {
        if (state.events) break
        for (let i = 0; i + 2 < toks.length; i += 3) {
          const [from, , to] = toks.slice(i, i + 3)
          state = {
            ...state,
            columns: state.columns.map((col) => (col === from ? to : col)),
            rows: (state.rows as Row[]).map((r) => {
              const { [from]: v, ...rest } = r
              return { ...rest, [to]: v }
            }),
          }
        }
        break
      }
      case 'stats': {
        const { aggs, by } = parseAggs(toks)
        const groups = by.length ? group(state, state.rows, by) : new Map([['', { key: [], rows: state.rows }]])
        const next = table(by, groups.values(), (g) => aggs.map((a) => aggregate(state, g.rows, a)), aggs.map((a) => a.as))
        next.rows.sort((a, b) => by.reduce((d, f) => d || compareValues((a as Row)[f], (b as Row)[f]), 0))
        state = next
        break
      }
      case 'top':
      case 'rare': {
        const limit = Number(opt('limit') ?? 10)
        const groups = [...group(state, state.rows, toks).values()]
        const total = groups.reduce((n, g) => n + g.rows.length, 0) || 1
        const next = table(toks, groups, (g) => [g.rows.length, (g.rows.length * 100) / total], ['count', 'percent'])
        next.rows.sort((a, b) => ((a as Row).count as number) - ((b as Row).count as number) || compareValues((a as Row)[toks[0]], (b as Row)[toks[0]]))
        if (name === 'top') next.rows.sort((a, b) => ((b as Row).count as number) - ((a as Row).count as number))
        state = { ...next, rows: next.rows.slice(0, limit) }
        break
      }
      case 'timechart': {
        if (!state.events) throw new Error('timechart needs event times (_time): put it before stats, top or table')
        const spanOpt = opt('span')
        span = spanOpt ? parseSpan(spanOpt) : pickSpan(range.to - range.from)
        const limit = Number(opt('limit') ?? 8)
        const byAt = toks.findIndex((t) => t.toLowerCase() === 'by')
        const { aggs } = parseAggs(byAt >= 0 ? toks.slice(0, byAt) : toks)
        const agg = aggs[0]
        const by = byAt >= 0 ? toks[byAt + 1] : undefined
        const starts = buckets(range.from, range.to, span)
        const cells = new Map<string, Map<number, unknown[]>>()
        const ms = span * 1000
        for (const r of state.rows) {
          const t = Math.floor(Date.parse(String(get(state, r, '_time'))) / ms) * ms
          const keys = by ? [get(state, r, by)].flat().filter(present).map(String) : [agg.as]
          for (const k of keys) {
            const m = cells.get(k) ?? new Map<number, unknown[]>()
            m.set(t, [...(m.get(t) ?? []), r])
            cells.set(k, m)
          }
        }
        if (!by) cells.set(agg.as, cells.get(agg.as) ?? new Map())
        const value = (rows: unknown[] | undefined) => aggregate(state, rows ?? [], agg)
        const totals = new Map([...cells].map(([k, m]) => [k, [...m.values()].reduce((n, rows) => n + (Number(value(rows)) || 0), 0)]))
        const series = [...cells.keys()].sort((a, b) => totals.get(b)! - totals.get(a)! || a.localeCompare(b))
        const kept = series.slice(0, limit)
        const rest = series.slice(limit)
        const additive = agg.fn === 'count' || agg.fn === 'sum'
        const zero = additive || agg.fn === 'dc' ? 0 : null
        const cols = ['_time', ...kept, ...(additive && rest.length ? ['OTHER'] : [])]
        const rows = starts.map((t) => {
          const row: Row = { _time: new Date(t).toISOString() }
          for (const s of kept) row[s] = cells.get(s)?.get(t) ? value(cells.get(s)!.get(t)) : zero
          if (cols.includes('OTHER')) row.OTHER = rest.reduce((n, s) => n + (Number(value(cells.get(s)?.get(t))) || 0), 0)
          return row
        })
        state = { events: false, columns: cols, rows }
        chart = 'timechart'
        break
      }
      default:
        throw new Error(`${name} is not available in demo mode`)
    }
  }
  if (state.events) {
    return { mode: 'events', events: state.rows as SearchResponse['events'], total: state.rows.length, took_ms: 1 }
  }
  const rows = state.rows as Row[]
  const columns: ResultColumn[] = state.columns.map((name) => {
    const sample = rows.map((r) => r[name]).find(present)
    const type = name === '_time' ? 'time' : Array.isArray(sample) ? 'array' : typeof sample === 'number' ? 'number' : 'string'
    return { name, type }
  })
  return {
    mode: 'table',
    events: [],
    columns,
    rows: rows.slice(0, 10_000).map((r) => state.columns.map((c) => (r[c] === undefined ? null : r[c]))),
    truncated: rows.length > 10_000,
    total: Math.min(rows.length, 10_000),
    chart,
    timeline_span: span,
    took_ms: 1,
  }
}
