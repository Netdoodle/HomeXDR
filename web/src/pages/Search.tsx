import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Fragment, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api, type Event } from '../api'
import { FieldTree } from '../components/FieldTree'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { Pager } from '../components/Misc'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { TimeRangePicker } from '../components/TimeRangePicker'
import { COLUMN_LABELS, COMMON_FIELDS, DEFAULT_SEARCH_COLUMNS, eventSummary, fieldString, leafPaths } from '../lib/fields'
import { formatNumber, plural } from '../lib/format'
import { useDocumentTitle, useLocalStorage, useUrlState } from '../lib/hooks'
import { addTerm, validateQuery } from '../lib/query'
import { describeRange, formatTimestamp, rangeFromParams, rangeToParams, resolveRange, type TimeRange } from '../lib/time'

const LIMIT = 100

const EXAMPLES = [
  'event.category:process AND process.name:powershell.exe AND NOT user.name:SYSTEM',
  'event.category:network AND destination.port:>=1024 AND network.direction:outbound',
  'dns.question.name:*.example',
  'event.action:ssh-login AND event.outcome:failure',
  'file.path:"C:\\Users\\alex\\AppData\\Roaming\\*"',
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

export function SearchPage() {
  useDocumentTitle('Search')
  const [sp, patch] = useUrlState()
  const q = sp.get('q') ?? ''
  const range = rangeFromParams(sp, '24h')
  const offset = Number(sp.get('offset') ?? 0) || 0
  const [draft, setDraft] = useState(q)
  const [runId, setRunId] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Keep the box in sync when the URL changes (back/forward, links from other pages).
  useEffect(() => setDraft(q), [q])

  const draftError = validateQuery(draft)
  const rangeKey = JSON.stringify(range)

  const search = useQuery({
    queryKey: ['search', q, rangeKey, offset, runId],
    queryFn: () => {
      const { from, to } = resolveRange(JSON.parse(rangeKey) as TimeRange)
      return api.searchEvents({ query: q, from, to, limit: LIMIT, offset, order: 'desc' })
    },
    placeholderData: keepPreviousData,
    enabled: validateQuery(q) === null,
    staleTime: 30_000,
  })

  const run = (query: string) => {
    if (validateQuery(query)) return
    if (query === q && offset === 0) setRunId((n) => n + 1)
    patch({ q: query || undefined, offset: undefined }, { replace: false })
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    run(draft.trim())
  }

  const addFilter = (path: string, value: string | number | boolean, negate: boolean) => {
    const next = addTerm(draft.trim() || q, path, value, { negate })
    setDraft(next)
    run(next)
  }

  const [columns, setColumns] = useLocalStorage<string[]>('homexdr.search.columns', DEFAULT_SEARCH_COLUMNS)
  const events = search.data?.events ?? []
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

  const queryInvalid = validateQuery(q)

  return (
    <>
      <PageHeader title="Search" subtitle="Events from every host and syslog source" />
      <form className="query-bar" onSubmit={submit} role="search">
        <div className="query-input">
          <Icon name="search" size={14} />
          <input
            ref={inputRef}
            className={draftError ? 'input invalid' : 'input'}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="event.category:process AND process.name:powershell.exe"
            aria-label="Query"
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
          Query syntax: <code>field:value</code> <code>field:val*</code> <code>field:"quoted value"</code> <code>field:&gt;10</code> <code>AND</code>{' '}
          <code>OR</code> <code>NOT</code> <code>( )</code> · bare words search message, command line and file path
        </summary>
        <div className="stack" style={{ gap: 4, marginTop: 6 }}>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              type="button"
              className="linklike mono xsmall"
              onClick={() => {
                setDraft(ex)
                run(ex)
              }}
            >
              {ex}
            </button>
          ))}
        </div>
      </details>

      <section className="panel">
        <div className="panel-header">
          <span className="small muted">
            {search.data ? (
              <>
                {search.data.total !== undefined ? plural(search.data.total, 'event') : `${formatNumber(events.length)}+ events`} ·{' '}
                {describeRange(range).toLowerCase()} · {search.data.took_ms} ms
              </>
            ) : (
              describeRange(range)
            )}
          </span>
          <span className="row">
            {search.isFetching ? <Spinner small /> : null}
            <ColumnChooser available={available} columns={columns} onChange={setColumns} />
          </span>
        </div>
        {queryInvalid ? (
          <ErrorState error={new Error(`Query error: ${queryInvalid.message}`)} title="Invalid query" />
        ) : search.isPending ? (
          <Loading label="Searching…" />
        ) : search.isError ? (
          <ErrorState error={search.error} onRetry={() => search.refetch()} title="Search failed" />
        ) : events.length === 0 ? (
          <EmptyState title="No events match">
            {q ? 'Try a longer time range, a wildcard, or fewer terms.' : 'No events in this time range yet.'}
          </EmptyState>
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
                  {events.map((e) => {
                    const isOpen = open.has(e.id)
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
                                <FieldTree value={e} onFilter={addFilter} />
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
            <Pager offset={offset} limit={LIMIT} total={search.data?.total} shown={events.length} onChange={(o) => patch({ offset: o || undefined }, { replace: false })} />
          </>
        )}
      </section>
    </>
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
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
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
