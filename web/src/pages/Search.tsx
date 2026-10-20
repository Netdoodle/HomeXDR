import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Fragment, useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link } from 'react-router'
import { api, type Event, type SearchResponse } from '../api'
import { FieldTree } from '../components/FieldTree'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { ButtonTabs, Pager } from '../components/Misc'
import { Histogram } from '../components/SearchCharts'
import { FieldsSidebar, StatsTable, VizPanel } from '../components/SearchViews'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { TimeRangePicker } from '../components/TimeRangePicker'
import { COLUMN_LABELS, COMMON_FIELDS, DEFAULT_SEARCH_COLUMNS, eventSummary, fieldString, leafPaths } from '../lib/fields'
import { formatNumber, plural } from '../lib/format'
import { useDocumentTitle, useLocalStorage, useUrlState } from '../lib/hooks'
import { addTerm, splitPipeline, validateQuery } from '../lib/query'
import { describeRange, formatTimestamp, rangeFromParams, rangeToParams, resolveRange, type TimeRange } from '../lib/time'

const LIMIT = 100

const EXAMPLES: { q: string; note: string }[] = [
  { q: 'index=opnsense action=block | stats count by src | sort -count | head 10', note: 'Top blocked sources' },
  { q: 'index=opnsense | timechart count by action', note: 'Firewall actions over time' },
  { q: 'index=suricata | stats count, dc(src) as sources by rule.name | sort -count', note: 'Suricata alerts by signature' },
  { q: 'event.category=authentication event.outcome=failure | stats count by user.name, source.ip', note: 'Failed logins' },
  { q: 'event.category=process | top limit=15 process.name', note: 'Most common processes' },
  { q: 'dns.question.name=*.example | dedup dns.question.name | table _time, host.name, dns.question.name', note: 'Distinct DNS names' },
  { q: 'event.category:process AND process.name:powershell.exe AND NOT user.name:SYSTEM', note: 'A filter on its own lists events' },
]

const COMMAND_HELP: [string, string][] = [
  ['stats count, avg(f) [as name] … [by f, …]', 'Aggregate: count, dc, sum, avg, min, max, values'],
  ['timechart [span=5m] [limit=8] count [by f]', 'Values over time (the last command)'],
  ['top [limit=10] f  ·  rare f', 'Most and least common values, with percent'],
  ['table f, …  ·  fields f, …', 'A table of those fields'],
  ['sort [-]f, …  ·  head N  ·  dedup f', 'Order, keep the first N, drop repeats'],
  ['where expr  ·  eval name = expr', 'Filter or compute: + - * / . = != < > AND OR NOT, if, case, coalesce, like, match, round, len, lower …'],
  ['rename f as name  ·  rex field=f "(?<name>…)"', 'Rename a column, extract fields with a regex'],
  ['search filter', 'More filtering, before stats'],
]

/** Fixed width for a column, or undefined for flexible text columns (summary, command lines). */
function colWidth(c: string): number | undefined {
  if (c === '@timestamp') return 178
  if (c === 'summary' || c === 'message' || c.endsWith('command_line')) return undefined
  if (c.endsWith('.path') || c.endsWith('executable') || c.endsWith('sha256')) return 260
  return 140
}

function cellValue(e: Event, col: string): string {
  if (col === 'summary') return eventSummary(e)
  if (col === '@timestamp') return formatTimestamp(e['@timestamp'])
  return fieldString(e, col)
}

type Tab = 'events' | 'stats' | 'viz'

export function SearchPage() {
  useDocumentTitle('Search')
  const [sp, patch] = useUrlState()
  const q = sp.get('q') ?? ''
  const range = rangeFromParams(sp, '24h')
  const offset = Number(sp.get('offset') ?? 0) || 0
  const tabParam = sp.get('tab')
  const [draft, setDraft] = useState(q)
  const [runId, setRunId] = useState(0)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Keep the box in sync when the URL changes (back/forward, links from other pages).
  useEffect(() => setDraft(q), [q])

  const draftError = validateQuery(draft)
  const queryInvalid = validateQuery(q)
  const rangeKey = JSON.stringify(range)
  const parts = useMemo(() => splitPipeline(q), [q])
  const filter = parts.filter.trim()

  const search = useQuery({
    queryKey: ['search', q, rangeKey, offset, runId],
    queryFn: () => {
      const { from, to } = resolveRange(JSON.parse(rangeKey) as TimeRange)
      return api.searchEvents({ query: q, from, to, limit: LIMIT, offset, order: 'desc', timeline: true })
    },
    placeholderData: keepPreviousData,
    enabled: queryInvalid === null,
    staleTime: 30_000,
  })
  const res = search.data
  const isTable = res?.mode === 'table'
  const tab: Tab =
    tabParam === 'events' || tabParam === 'stats' || tabParam === 'viz' ? tabParam : isTable ? (res?.chart === 'timechart' ? 'viz' : 'stats') : 'events'

  // With a table result, the Events tab lists the events the filter matched.
  const filterEvents = useQuery({
    queryKey: ['search', filter, rangeKey, offset, runId, 'filter-events'],
    queryFn: () => {
      const { from, to } = resolveRange(JSON.parse(rangeKey) as TimeRange)
      return api.searchEvents({ query: filter, from, to, limit: LIMIT, offset, order: 'desc' })
    },
    placeholderData: keepPreviousData,
    enabled: queryInvalid === null && isTable && tab === 'events',
    staleTime: 30_000,
  })
  const eventsRes = isTable ? filterEvents.data : res
  const events = eventsRes?.events ?? []
  const timelineTotal = res?.timeline?.reduce((n, b) => n + b.count, 0)

  const run = (query: string) => {
    if (validateQuery(query)) return
    setDraft(query)
    if (query === q && offset === 0) setRunId((n) => n + 1)
    patch({ q: query || undefined, offset: undefined, tab: undefined }, { replace: false })
  }

  const submit = (e?: FormEvent) => {
    e?.preventDefault()
    run(draft.trim())
  }

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      submit()
    }
  }

  const addFilter = (path: string, value: string | number | boolean, negate: boolean) => run(addTerm(draft.trim() || q, path, value, { negate }))

  const zoom = (i: number) => {
    const b = res?.timeline?.[i]
    const span = res?.timeline_span
    if (!b || !span) return
    const to = new Date(Date.parse(b.t) + span * 1000).toISOString()
    patch({ range: undefined, from: undefined, to: undefined, offset: undefined, ...rangeToParams({ preset: 'custom', from: b.t, to }) }, { replace: false })
  }

  const [columns, setColumns] = useLocalStorage<string[]>('homexdr.search.columns', DEFAULT_SEARCH_COLUMNS)
  const toggleColumn = (f: string) => setColumns(columns.includes(f) ? columns.filter((c) => c !== f) : [...columns, f])

  const lines = draft.split('\n').length
  const eventCount = isTable ? timelineTotal : res?.total

  return (
    <>
      <PageHeader title="Search" subtitle="Events from every host and syslog source" />
      <form className="query-bar" onSubmit={submit} role="search">
        <div className="query-input">
          <Icon name="search" size={14} />
          <textarea
            ref={inputRef}
            className={draftError ? 'input invalid' : 'input'}
            value={draft}
            rows={Math.min(8, Math.max(1, lines))}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="index=opnsense action=block | stats count by src | sort -count"
            aria-label="Search"
            aria-invalid={!!draftError}
            spellCheck={false}
            autoComplete="off"
          />
          {draftError ? (
            <div className="query-error" role="alert">
              {draftError.message} (at character {draftError.pos + 1})
            </div>
          ) : null}
        </div>
        <TimeRangePicker
          value={range}
          onChange={(r) => patch({ range: undefined, from: undefined, to: undefined, offset: undefined, ...rangeToParams(r) }, { replace: false })}
        />
        <button type="submit" className="btn primary" disabled={!!draftError} style={{ height: 34 }}>
          Search
        </button>
      </form>
      <details className="query-help" style={{ margin: '8px 0 12px' }}>
        <summary style={{ cursor: 'pointer' }}>
          Search syntax: <code>field=value</code> <code>field!=value</code> <code>field=val*</code> <code>field&gt;10</code> <code>AND</code> <code>OR</code>{' '}
          <code>NOT</code> <code>( )</code>, then <code>| commands</code> · Enter searches, Shift+Enter adds a line
        </summary>
        <div className="help-grid">
          <div>
            <h4>Filter</h4>
            <ul className="plain">
              <li>
                <code>field=value</code> or <code>field:value</code>: equal, ignoring case; <code>field!=value</code>; <code>field=val*</code> wildcards;{' '}
                <code>field="two words"</code>; <code>field&gt;1024</code>, <code>field&lt;=443</code>
              </li>
              <li>
                Bare words search the message, command line and file path. <code>AND</code> <code>OR</code> <code>NOT</code> <code>-term</code> <code>( )</code>; adjacent
                terms are ANDed.
              </li>
              <li>
                Splunk names work: <code>index</code> (event.module), <code>sourcetype</code>, <code>host</code>, <code>src</code>, <code>dest</code>, <code>dest_port</code>,{' '}
                <code>user</code>, <code>action</code>, <code>bytes</code>, <code>_time</code>. A bare unknown name such as <code>LogonType</code> means{' '}
                <code>data.LogonType</code>.
              </li>
            </ul>
          </div>
          <div>
            <h4>Commands</h4>
            <table className="help-commands">
              <tbody>
                {COMMAND_HELP.map(([cmd, what]) => (
                  <tr key={cmd}>
                    <td>
                      <code>| {cmd}</code>
                    </td>
                    <td>{what}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <h4>Examples</h4>
        <div className="stack" style={{ gap: 4 }}>
          {EXAMPLES.map((ex) => (
            <div key={ex.q} className="row" style={{ gap: 8 }}>
              <button type="button" className="linklike mono xsmall" style={{ textAlign: 'left' }} onClick={() => run(ex.q)}>
                {ex.q}
              </button>
              <span className="faint xsmall">{ex.note}</span>
            </div>
          ))}
        </div>
      </details>

      {queryInvalid ? (
        <section className="panel">
          <ErrorState error={new Error(`Query error: ${queryInvalid.message}`)} title="Invalid query" />
        </section>
      ) : search.isPending ? (
        <section className="panel">
          <Loading label="Searching…" />
        </section>
      ) : search.isError ? (
        <section className="panel">
          <ErrorState error={search.error} onRetry={() => search.refetch()} title="Search failed" />
        </section>
      ) : res ? (
        <>
          <section className="panel timeline-panel" style={{ opacity: search.isFetching ? 0.6 : 1 }}>
            <div className="panel-header">
              <span className="small muted">
                {eventCount !== undefined ? plural(eventCount, 'event') : 'Events'} · {describeRange(range).toLowerCase()} · {res.took_ms} ms
              </span>
              {search.isFetching ? <Spinner small /> : null}
            </div>
            {res.timeline?.length ? (
              <div style={{ padding: '2px 12px 6px' }}>
                <Histogram data={res.timeline} spanSec={res.timeline_span ?? 3600} onSelect={zoom} />
              </div>
            ) : null}
          </section>
          <ButtonTabs
            tabs={[
              { id: 'events', label: `Events${eventCount !== undefined ? ` (${formatNumber(eventCount)})` : ''}` },
              { id: 'stats', label: `Statistics${isTable ? ` (${formatNumber(res.rows?.length ?? 0)})` : ''}`, icon: 'table' },
              { id: 'viz', label: 'Visualization', icon: 'chart' },
            ]}
            active={tab}
            onChange={(t) => patch({ tab: t, offset: undefined }, { replace: true })}
          />
          {tab === 'events' ? (
            <div className="search-layout">
              <FieldsSidebar
                events={events}
                filter={filter}
                range={range}
                selected={columns}
                onToggleColumn={toggleColumn}
                onAddFilter={addFilter}
                onRun={run}
              />
              <EventsPanel
                res={eventsRes}
                loading={isTable && filterEvents.isPending}
                error={isTable ? filterEvents.error : null}
                fetching={isTable ? filterEvents.isFetching : search.isFetching}
                columns={columns}
                setColumns={setColumns}
                offset={offset}
                onOffset={(o) => patch({ offset: o || undefined }, { replace: false })}
                onAddFilter={addFilter}
                hasQuery={!!q}
              />
            </div>
          ) : !isTable ? (
            <section className="panel">
              <EmptyState title="This search returns events, not a table">
                <p style={{ margin: '0 0 8px' }}>Add a command after | to get statistics and charts, for example:</p>
                <div className="stack" style={{ gap: 4, alignItems: 'center' }}>
                  {[`${filter} | stats count by host.name`, `${filter} | timechart count by event.module`, `${filter} | top limit=10 event.action`].map((s) => (
                    <button key={s} type="button" className="linklike mono xsmall" onClick={() => run(s.trim())}>
                      {s.trim()}
                    </button>
                  ))}
                </div>
              </EmptyState>
            </section>
          ) : tab === 'stats' ? (
            <section className="panel" style={{ opacity: search.isFetching ? 0.6 : 1 }}>
              <StatsTable columns={res.columns ?? []} rows={res.rows ?? []} truncated={res.truncated} />
            </section>
          ) : (
            <section className="panel" style={{ opacity: search.isFetching ? 0.6 : 1 }}>
              <VizPanel res={res} onRun={run} filter={filter} />
            </section>
          )}
        </>
      ) : null}
    </>
  )
}

function EventsPanel({
  res,
  loading,
  error,
  fetching,
  columns,
  setColumns,
  offset,
  onOffset,
  onAddFilter,
  hasQuery,
}: {
  res: SearchResponse | undefined
  loading: boolean
  error: Error | null
  fetching: boolean
  columns: string[]
  setColumns: (c: string[]) => void
  offset: number
  onOffset: (o: number) => void
  onAddFilter: (path: string, value: string | number | boolean, negate: boolean) => void
  hasQuery: boolean
}) {
  const events = res?.events ?? []
  const available = useMemo(() => {
    const s = new Set(COMMON_FIELDS)
    for (const e of events.slice(0, 50)) for (const p of leafPaths(e)) s.add(p)
    return [...s].sort((a, b) => (a === '@timestamp' ? -1 : b === '@timestamp' ? 1 : a.localeCompare(b)))
  }, [events])
  const [open, setOpen] = useState<Set<string>>(new Set())
  const toggle = (id: string) =>
    setOpen((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })

  return (
    <section className="panel" style={{ minWidth: 0 }}>
      <div className="panel-header">
        <span className="small muted">{res?.total !== undefined ? plural(res.total, 'event') : ''}</span>
        <span className="row">
          {fetching ? <Spinner small /> : null}
          <ColumnChooser available={available} columns={columns} onChange={setColumns} />
        </span>
      </div>
      {error ? (
        <ErrorState error={error} title="Search failed" />
      ) : loading ? (
        <Loading label="Loading events…" />
      ) : events.length === 0 ? (
        <EmptyState title="No events match">{hasQuery ? 'Try a longer time range, a wildcard, or fewer terms.' : 'No events in this time range yet.'}</EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table fixed compact" style={{ minWidth: 28 + columns.reduce((n, c) => n + (colWidth(c) ?? 320), 0) }}>
              <colgroup>
                <col style={{ width: 28 }} />
                {columns.map((c) => (
                  <col key={c} style={{ width: colWidth(c) }} />
                ))}
              </colgroup>
              <thead>
                <tr>
                  <th aria-label="Expand" />
                  {columns.map((c) => (
                    <th key={c} className="truncate" title={c}>
                      {COLUMN_LABELS[c] ?? c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((e, idx) => {
                  const isOpen = open.has(e.id)
                  const extra = res?.extra?.[idx]
                  return (
                    <Fragment key={e.id}>
                      <tr className={isOpen ? 'clickable selected' : 'clickable'} onClick={() => toggle(e.id)}>
                        <td className="expander">
                          <button
                            type="button"
                            className="btn ghost icon sm"
                            aria-expanded={isOpen}
                            aria-label={isOpen ? 'Collapse event' : 'Expand event'}
                            onClick={(ev) => {
                              ev.stopPropagation()
                              toggle(e.id)
                            }}
                          >
                            <Icon name={isOpen ? 'chevronDown' : 'chevronRight'} size={12} />
                          </button>
                        </td>
                        {columns.map((c) => {
                          const v = cellValue(e, c)
                          const mono = c === '@timestamp' || c === 'summary' || c.includes('command_line') || c.includes('.ip') || c.includes('path')
                          return (
                            <td key={c} className={mono ? 'truncate cmd' : 'truncate'} title={v}>
                              {v || <span className="empty-cell">—</span>}
                            </td>
                          )
                        })}
                      </tr>
                      {isOpen ? (
                        <tr className="detail-row">
                          <td colSpan={columns.length + 1}>
                            <div className="stack" style={{ gap: 8 }}>
                              <div className="row small">
                                <span className="muted">Click a value to add it to the query, Alt-click (or −) to exclude it.</span>
                                {e.process?.entity_id && e.host?.id ? (
                                  <Link to={`/hosts/${encodeURIComponent(e.host.id)}/process/${encodeURIComponent(e.process.entity_id)}`}>
                                    <Icon name="tree" size={12} /> Process tree
                                  </Link>
                                ) : null}
                                {e.host?.id ? <Link to={`/hosts/${encodeURIComponent(e.host.id)}`}>Host {e.host.name}</Link> : null}
                                <span className="mono xsmall faint">id {e.id}</span>
                              </div>
                              {extra && Object.keys(extra).length ? (
                                <dl className="computed-fields">
                                  {Object.entries(extra).map(([k, v]) => (
                                    <Fragment key={k}>
                                      <dt className="mono xsmall">{k}</dt>
                                      <dd className="mono xsmall">{v === null || v === undefined ? '—' : Array.isArray(v) ? v.join(', ') : String(v)}</dd>
                                    </Fragment>
                                  ))}
                                </dl>
                              ) : null}
                              <FieldTree value={e} onFilter={onAddFilter} />
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
          <Pager offset={offset} limit={LIMIT} total={res?.total} shown={events.length} onChange={onOffset} />
        </>
      )}
    </section>
  )
}

function ColumnChooser({ available, columns, onChange }: { available: string[]; columns: string[]; onChange: (c: string[]) => void }) {
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: globalThis.KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])
  const shown = available.filter((f) => f.toLowerCase().includes(filter.toLowerCase()))
  const toggle = (f: string) => {
    if (columns.includes(f)) onChange(columns.filter((c) => c !== f))
    else onChange([...columns, f])
  }
  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn sm" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="true">
        <Icon name="columns" size={12} /> Columns ({columns.length})
      </button>
      {open ? (
        <div className="menu-pop columns">
          <div style={{ padding: 4 }}>
            <input className="input" style={{ width: '100%' }} placeholder="Find field" value={filter} onChange={(e) => setFilter(e.target.value)} autoFocus aria-label="Find field" />
          </div>
          <div className="row" style={{ padding: '2px 8px 6px', justifyContent: 'space-between' }}>
            <button type="button" className="linklike xsmall" onClick={() => onChange(DEFAULT_SEARCH_COLUMNS)}>
              Reset to default
            </button>
            <span className="xsmall faint">{columns.length} shown</span>
          </div>
          <div className="menu-sep" />
          {shown.map((f) => (
            <label key={f} className="menu-item checkbox">
              <input type="checkbox" checked={columns.includes(f)} onChange={() => toggle(f)} disabled={columns.length === 1 && columns.includes(f)} />
              <span className="mono xsmall">{f}</span>
              {COLUMN_LABELS[f] ? <span className="faint xsmall">{COLUMN_LABELS[f]}</span> : null}
            </label>
          ))}
          {shown.length === 0 ? <div className="menu-label">No fields match</div> : null}
        </div>
      ) : null}
    </div>
  )
}
