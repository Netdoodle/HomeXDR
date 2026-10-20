// Result views for the search page: the statistics table, the visualization panel and the
// fields sidebar with top values.

import { useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { api, type Event, type ResultColumn, type SearchResponse } from '../api'
import { formatNumber } from '../lib/format'
import { useLocalStorage } from '../lib/hooks'
import { fieldRef } from '../lib/query'
import { formatTimestamp, resolveRange, type TimeRange } from '../lib/time'
import { leafPaths } from '../lib/fields'
import { BarList } from './Charts'
import { Icon } from './Icon'
import { Pager } from './Misc'
import { colorSeries, Legend, TimeSeriesChart } from './SearchCharts'
import { EmptyState, ErrorState, Spinner } from './States'

export function formatCell(v: unknown, type: ResultColumn['type']): string {
  if (v === null || v === undefined) return ''
  if (type === 'time') return formatTimestamp(String(v))
  if (typeof v === 'number') return formatNumber(Number.isInteger(v) ? v : Math.round(v * 100) / 100)
  if (Array.isArray(v)) return v.join(', ')
  return String(v)
}

function compareCells(a: unknown, b: unknown): number {
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1
  if (b === null || b === undefined) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), undefined, { numeric: true })
}

/** CSV with formula-looking text cells defused: log data is attacker-controlled. */
export function toCSV(columns: ResultColumn[], rows: unknown[][]): string {
  const cell = (v: unknown, type: ResultColumn['type']) => {
    if (v === null || v === undefined) return ''
    let s = Array.isArray(v) ? v.join('; ') : String(v)
    if (type !== 'number' && /^[=+\-@\t\r]/.test(s)) s = "'" + s
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const lines = [columns.map((c) => cell(c.name, 'string')).join(',')]
  for (const r of rows) lines.push(columns.map((c, i) => cell(r[i], c.type)).join(','))
  return lines.join('\r\n') + '\r\n'
}

function downloadCSV(columns: ResultColumn[], rows: unknown[][]) {
  const url = URL.createObjectURL(new Blob([toCSV(columns, rows)], { type: 'text/csv' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `homexdr-search-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const PAGE = 100

export function StatsTable({ columns, rows, truncated }: { columns: ResultColumn[]; rows: unknown[][]; truncated?: boolean }) {
  const [sort, setSort] = useState<{ col: number; desc: boolean } | null>(null)
  const [offset, setOffset] = useState(0)
  useEffect(() => {
    setSort(null)
    setOffset(0)
  }, [rows])
  const sorted = useMemo(() => {
    if (!sort) return rows
    const out = [...rows].sort((a, b) => compareCells(a[sort.col], b[sort.col]))
    return sort.desc ? out.reverse() : out
  }, [rows, sort])
  const page = sorted.slice(offset, offset + PAGE)
  return (
    <>
      <div className="row small" style={{ justifyContent: 'space-between', padding: '8px 12px' }}>
        <span className="muted">
          {formatNumber(rows.length)} {rows.length === 1 ? 'row' : 'rows'}
          {truncated ? ' (the first 10,000; narrow the search or add | head for the rest)' : ''}
        </span>
        <button type="button" className="btn sm" onClick={() => downloadCSV(columns, sorted)} disabled={rows.length === 0}>
          <Icon name="download" size={12} /> Export CSV
        </button>
      </div>
      <div className="table-wrap">
        <table className="table compact stats-table">
          <thead>
            <tr>
              {columns.map((c, i) => {
                const active = sort?.col === i
                return (
                  <th key={i} className={c.type === 'number' ? 'num' : undefined} aria-sort={active ? (sort!.desc ? 'descending' : 'ascending') : undefined}>
                    <button
                      type="button"
                      className="th-sort"
                      onClick={() => setSort(active ? { col: i, desc: !sort!.desc } : { col: i, desc: c.type === 'number' })}
                      title={`Sort by ${c.name}`}
                    >
                      <span className="truncate-inline">{c.name}</span>
                      {active ? <Icon name={sort!.desc ? 'chevronDown' : 'chevronRight'} size={10} /> : null}
                    </button>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {page.map((r, ri) => (
              <tr key={offset + ri}>
                {columns.map((c, i) => {
                  const text = formatCell(r[i], c.type)
                  return (
                    <td key={i} className={c.type === 'number' ? 'num' : c.type === 'time' ? 'cmd' : undefined} title={text}>
                      {text === '' ? <span className="empty-cell">—</span> : text}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > PAGE ? <Pager offset={offset} limit={PAGE} total={rows.length} shown={page.length} onChange={setOffset} /> : null}
    </>
  )
}

const MAX_BARS = 50

/** Charts a table result: a time chart for timechart, bars for category/number tables,
 * and a plain figure for a single row of numbers. */
export function VizPanel({ res, onRun, filter }: { res: SearchResponse; onRun: (q: string) => void; filter: string }) {
  const columns = res.columns ?? []
  const rows = res.rows ?? []
  const [kind, setKind] = useLocalStorage<'column' | 'line'>('homexdr.search.chartKind', 'column')
  const numIdx = columns.flatMap((c, i) => (c.type === 'number' ? [i] : []))
  const labelIdx = columns.flatMap((c, i) => (c.type !== 'number' ? [i] : []))
  const [measure, setMeasure] = useState<number | undefined>(undefined)
  const m = measure !== undefined && numIdx.includes(measure) ? measure : numIdx[0]

  if (res.chart === 'timechart') {
    const names = columns.slice(1).map((c) => c.name)
    const values = names.map((_, j) => rows.map((r) => (typeof r[j + 1] === 'number' ? (r[j + 1] as number) : null)))
    const { series, hidden } = colorSeries(names, values)
    return (
      <div className="viz">
        <div className="row viz-toolbar">
          <div className="segmented" role="group" aria-label="Chart type">
            {(['column', 'line'] as const).map((k) => (
              <button key={k} type="button" className={kind === k ? 'active' : undefined} aria-pressed={kind === k} onClick={() => setKind(k)}>
                {k === 'column' ? 'Columns' : 'Lines'}
              </button>
            ))}
          </div>
          {series.length > 1 ? <Legend series={series} kind={kind} /> : <span className="small muted">{series[0]?.name}</span>}
        </div>
        <TimeSeriesChart times={rows.map((r) => String(r[0]))} series={series} spanSec={res.timeline_span ?? 3600} kind={kind} />
        {hidden > 0 ? (
          <p className="small muted" style={{ margin: '6px 0 0' }}>
            {hidden} more {hidden === 1 ? 'series is' : 'series are'} in the Statistics tab. Charts show 8; add <code>limit=8</code> to group the rest as OTHER.
          </p>
        ) : null}
      </div>
    )
  }
  if (rows.length === 0) return <EmptyState title="No results to chart" />
  if (labelIdx.length === 0 && numIdx.length > 0) {
    // One row of numbers (| stats count): the number is the chart.
    return (
      <div className="viz figures">
        {numIdx.map((i) => (
          <div key={i} className="figure">
            <div className="figure-label">{columns[i].name}</div>
            <div className="figure-value">{formatCell(rows[0][i], 'number') || '—'}</div>
          </div>
        ))}
      </div>
    )
  }
  if (numIdx.length === 0) {
    return (
      <EmptyState title="Nothing to chart">
        A chart needs a number column, for example{' '}
        <button type="button" className="linklike mono" onClick={() => onRun(`${filter.trim()} | stats count by ${columns[0]?.name ? fieldRef(columns[0].name) : 'host.name'}`.trim())}>
          | stats count by {columns[0]?.name ?? 'host.name'}
        </button>
      </EmptyState>
    )
  }
  const items = rows.slice(0, MAX_BARS).map((r, k) => {
    const label = labelIdx.map((i) => formatCell(r[i], columns[i].type) || '—').join(' · ')
    return { key: String(k), label, title: label, value: typeof r[m] === 'number' ? (r[m] as number) : 0 }
  })
  return (
    <div className="viz">
      <div className="row viz-toolbar">
        {numIdx.length > 1 ? (
          <label className="row small">
            <span className="muted">Measure</span>
            <select className="input sm" value={m} onChange={(e) => setMeasure(Number(e.target.value))}>
              {numIdx.map((i) => (
                <option key={i} value={i}>
                  {columns[i].name}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <span className="small muted">
            {columns[m].name} by {labelIdx.map((i) => columns[i].name).join(', ')}
          </span>
        )}
      </div>
      <BarList items={items} max={Math.max(1, ...items.map((i) => i.value))} />
      {rows.length > MAX_BARS ? (
        <p className="small muted" style={{ margin: '6px 0 0' }}>
          Showing the first {MAX_BARS} of {formatNumber(rows.length)} rows; all are in the Statistics tab.
        </p>
      ) : null}
    </div>
  )
}

/** Field list for events results, with top values per field over the whole search. */
export function FieldsSidebar({
  events,
  filter,
  range,
  selected,
  onToggleColumn,
  onAddFilter,
  onRun,
}: {
  events: Event[]
  filter: string
  range: TimeRange
  selected: string[]
  onToggleColumn: (field: string) => void
  onAddFilter: (field: string, value: string, negate: boolean) => void
  onRun: (query: string) => void
}) {
  const [find, setFind] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const counts = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of events.slice(0, 200)) for (const p of leafPaths(e)) m.set(p, (m.get(p) ?? 0) + 1)
    return m
  }, [events])
  const sample = Math.min(events.length, 200)
  const names = [...counts.keys()].filter((f) => f.toLowerCase().includes(find.toLowerCase()))
  const chosen = names.filter((f) => selected.includes(f))
  const others = names.filter((f) => !selected.includes(f)).sort((a, b) => counts.get(b)! - counts.get(a)! || a.localeCompare(b))
  const row = (f: string) => (
    <li key={f}>
      <button type="button" className={open === f ? 'field-name open' : 'field-name'} aria-expanded={open === f} onClick={() => setOpen(open === f ? null : f)}>
        <span className="mono truncate-inline">{f}</span>
        <span className="faint num">{Math.round(((counts.get(f) ?? 0) * 100) / Math.max(1, sample))}%</span>
      </button>
      {open === f ? (
        <FieldValues
          field={f}
          filter={filter}
          range={range}
          selected={selected.includes(f)}
          onToggleColumn={() => onToggleColumn(f)}
          onAddFilter={onAddFilter}
          onRun={onRun}
        />
      ) : null}
    </li>
  )
  return (
    <aside className="fields-sidebar" aria-label="Fields">
      <input className="input sm" placeholder="Find field" value={find} onChange={(e) => setFind(e.target.value)} aria-label="Find field" />
      {chosen.length ? (
        <>
          <div className="fields-head">Selected fields</div>
          <ul>{chosen.map(row)}</ul>
        </>
      ) : null}
      <div className="fields-head">
        Fields <span className="faint">· % of {formatNumber(sample)} events shown</span>
      </div>
      <ul>{others.map(row)}</ul>
      {names.length === 0 ? <div className="small faint">No fields</div> : null}
    </aside>
  )
}

function FieldValues({
  field,
  filter,
  range,
  selected,
  onToggleColumn,
  onAddFilter,
  onRun,
}: {
  field: string
  filter: string
  range: TimeRange
  selected: boolean
  onToggleColumn: () => void
  onAddFilter: (field: string, value: string, negate: boolean) => void
  onRun: (query: string) => void
}) {
  const base = filter.trim()
  const ref = fieldRef(field)
  const top = useQuery({
    queryKey: ['field-top', base, field, JSON.stringify(range)],
    queryFn: () => {
      const { from, to } = resolveRange(range)
      return api.searchEvents({ query: `${base} | top limit=10 ${ref}`, from, to })
    },
    staleTime: 30_000,
  })
  const rows = top.data?.rows ?? []
  return (
    <div className="field-values">
      <div className="row xsmall" style={{ gap: 10, flexWrap: 'wrap' }}>
        <button type="button" className="linklike" onClick={() => onRun(`${base} | top limit=20 ${ref}`.trim())}>
          Top values
        </button>
        <button type="button" className="linklike" onClick={() => onRun(`${base} | timechart count by ${ref}`.trim())}>
          Over time
        </button>
        <button type="button" className="linklike" onClick={() => onRun(`${base} | rare limit=20 ${ref}`.trim())}>
          Rare values
        </button>
        <button type="button" className="linklike" onClick={onToggleColumn}>
          {selected ? 'Remove column' : 'Add column'}
        </button>
      </div>
      {top.isPending ? (
        <div className="row small muted" style={{ padding: 6 }}>
          <Spinner small /> Counting…
        </div>
      ) : top.isError ? (
        <ErrorState error={top.error} title="Could not count values" />
      ) : rows.length === 0 ? (
        <div className="small faint" style={{ padding: 6 }}>
          No values
        </div>
      ) : (
        <ul className="value-list">
          {rows.map((r, i) => {
            const value = String(r[0] ?? '')
            const pct = Number(r[2] ?? 0)
            return (
              <li key={i}>
                <span className="v-text mono truncate-inline" title={value}>
                  {value}
                </span>
                <span className="faint num">{pct >= 10 ? Math.round(pct) : pct.toFixed(1)}%</span>
                <button type="button" className="btn ghost icon sm" title={`Add ${field}=${value} to the search`} aria-label={`Filter on ${value}`} onClick={() => onAddFilter(field, value, false)}>
                  <Icon name="plus" size={11} />
                </button>
                <button type="button" className="btn ghost icon sm" title={`Exclude ${field}=${value}`} aria-label={`Exclude ${value}`} onClick={() => onAddFilter(field, value, true)}>
                  <span aria-hidden="true">−</span>
                </button>
                <span className="v-track" aria-hidden="true">
                  <span style={{ width: `${Math.min(100, pct)}%` }} />
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
