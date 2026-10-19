import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Fragment, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { api, queryKeys, TERMINAL_COMMAND_STATUSES, type CommandRecord, type Host, type Row } from '../api'
import { CommandStatusBadge } from '../components/Badges'
import { FieldTree } from '../components/FieldTree'
import { Icon } from '../components/Icon'
import { Pager, RelTime } from '../components/Misc'
import { EmptyState, QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { commandLabel, commandParamsSummary } from '../lib/commands'
import { formatTimestamp } from '../lib/time'

export function HostCommands({ host }: { host: Host }) {
  const q = useQuery({
    queryKey: queryKeys.hostCommands(host.id),
    queryFn: () => api.hostCommands(host.id),
    // Poll while anything is still in flight.
    refetchInterval: (query) =>
      query.state.data?.commands.some((c) => !TERMINAL_COMMAND_STATUSES.includes(c.status)) ? 2000 : 30_000,
  })
  const [open, setOpen] = useState<string | null>(null)
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Command history</h2>
        <span className="row">
          {q.isFetching && !q.isPending ? <Spinner small /> : null}
          <Link className="btn sm" to={`/hosts/${encodeURIComponent(host.id)}?tab=actions`}>
            <Icon name="plus" size={12} /> New action
          </Link>
        </span>
      </div>
      <QueryView
        query={q}
        isEmpty={(d) => d.commands.length === 0}
        empty={<EmptyState title="No commands sent to this host yet">Response actions and artifact collections appear here with their status.</EmptyState>}
      >
        {(d) => (
          <div className="table-wrap">
            <table className="table fixed" style={{ minWidth: 820 }}>
              <colgroup>
                <col style={{ width: 28 }} />
                <col style={{ width: 150 }} />
                <col style={{ width: 130 }} />
                <col />
                <col style={{ width: 104 }} />
                <col style={{ width: 90 }} />
                <col style={{ width: 96 }} />
              </colgroup>
              <thead>
                <tr>
                  <th aria-label="Expand" />
                  <th>Issued</th>
                  <th>Action</th>
                  <th>Parameters / result</th>
                  <th>Status</th>
                  <th>By</th>
                  <th>Finished</th>
                </tr>
              </thead>
              <tbody>
                {d.commands.map((c) => {
                  const isOpen = open === c.id
                  const summary = commandParamsSummary(c)
                  return (
                    <Fragment key={c.id}>
                      <tr className={isOpen ? 'clickable selected' : 'clickable'} onClick={() => setOpen(isOpen ? null : c.id)}>
                        <td className="expander">
                          <button
                            type="button"
                            className="btn ghost icon sm"
                            aria-expanded={isOpen}
                            aria-label={isOpen ? 'Collapse' : 'Expand'}
                            onClick={(e) => {
                              e.stopPropagation()
                              setOpen(isOpen ? null : c.id)
                            }}
                          >
                            <Icon name={isOpen ? 'chevronDown' : 'chevronRight'} size={12} />
                          </button>
                        </td>
                        <td className="mono small truncate" title={formatTimestamp(c.issued_at)}>
                          <RelTime iso={c.issued_at} absolute />
                        </td>
                        <td className="truncate">
                          {commandLabel(c.type)}
                          {c.hunt_id ? (
                            <Link to={`/hunts/${encodeURIComponent(c.hunt_id)}`} className="xsmall" style={{ marginLeft: 6 }} onClick={(e) => e.stopPropagation()}>
                              hunt
                            </Link>
                          ) : null}
                        </td>
                        <td className="truncate cmd" title={c.error ?? summary}>
                          {c.error ? <span className="danger-text">{c.error}</span> : summary || <span className="empty-cell">—</span>}
                          {c.row_count ? <span className="muted"> · {c.row_count} rows</span> : null}
                        </td>
                        <td>
                          <CommandStatusBadge status={c.status} />
                        </td>
                        <td className="truncate">{c.issued_by}</td>
                        <td>
                          <RelTime iso={c.completed_at} />
                        </td>
                      </tr>
                      {isOpen ? (
                        <tr className="detail-row">
                          <td colSpan={7}>
                            <CommandDetail command={c} />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </QueryView>
    </section>
  )
}

function CommandDetail({ command: c }: { command: CommandRecord }) {
  const toast = useToast()
  const [downloading, setDownloading] = useState(false)
  const done = c.status === 'completed'
  const fileName = String((c.params as { path?: string })?.path ?? 'file').split(/[\\/]/).pop() || 'file'
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="grid grid-2">
        <div>
          <div className="small muted" style={{ marginBottom: 4 }}>Parameters</div>
          <FieldTree value={c.params ?? {}} />
        </div>
        <div>
          <div className="small muted" style={{ marginBottom: 4 }}>Lifecycle</div>
          <dl className="kv small">
            <dt>Command ID</dt>
            <dd className="mono">{c.id}</dd>
            <dt>Issued</dt>
            <dd>{formatTimestamp(c.issued_at)} by {c.issued_by}</dd>
            <dt>Delivered</dt>
            <dd>{c.delivered_at ? formatTimestamp(c.delivered_at) : '—'}</dd>
            <dt>Completed</dt>
            <dd>{c.completed_at ? formatTimestamp(c.completed_at) : '—'}</dd>
            <dt>Expires</dt>
            <dd>{formatTimestamp(c.expires_at)}</dd>
            {c.error ? (
              <>
                <dt>Error</dt>
                <dd className="danger-text">{c.error}</dd>
              </>
            ) : null}
          </dl>
        </div>
      </div>
      {c.output !== undefined && c.output !== null && !(typeof c.output === 'object' && Object.keys(c.output as object).length === 0) ? (
        <div>
          <div className="small muted" style={{ marginBottom: 4 }}>Output</div>
          <FieldTree value={c.output} />
        </div>
      ) : null}
      {c.type === 'file.get' && done ? (
        <div className="row">
          <button
            type="button"
            className="btn sm"
            disabled={downloading}
            onClick={async () => {
              setDownloading(true)
              try {
                await api.downloadCommandFile(c.id, fileName)
              } catch (e) {
                toast.error(e)
              } finally {
                setDownloading(false)
              }
            }}
          >
            {downloading ? <Spinner small /> : <Icon name="download" size={12} />} Download {fileName}
          </button>
          <span className="muted xsmall">Handle files from hosts with care: open them only in a safe environment.</span>
        </div>
      ) : null}
      {c.type === 'artifact.collect' && done ? <CommandRows id={c.id} /> : null}
    </div>
  )
}

const ROWS_LIMIT = 50

export function RowsTable({ rows, columns, extraFirst }: { rows: Row[]; columns?: string[]; extraFirst?: (r: Row, i: number) => ReactNode }) {
  const cols = columns?.length ? columns : [...new Set(rows.flatMap((r) => Object.keys(r)))]
  return (
    <div className="table-wrap" style={{ maxHeight: 520, overflowY: 'auto' }}>
      <table className="table compact">
        <thead>
          <tr>
            {extraFirst ? <th>Host</th> : null}
            {cols.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {extraFirst ? <td className="nowrap">{extraFirst(r, i)}</td> : null}
              {cols.map((c) => {
                const v = r[c]
                const s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
                return (
                  <td key={c} className="cmd" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s}>
                    {s === '' ? <span className="empty-cell">—</span> : s}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CommandRows({ id }: { id: string }) {
  const [offset, setOffset] = useState(0)
  const q = useQuery({
    queryKey: queryKeys.commandRows(id, offset),
    queryFn: () => api.commandRows(id, ROWS_LIMIT, offset),
    placeholderData: keepPreviousData,
  })
  return (
    <div>
      <div className="small muted" style={{ marginBottom: 4 }}>Rows</div>
      <div className="panel">
        <QueryView query={q} compact isEmpty={(d) => d.rows.length === 0} empty={<EmptyState title="The artifact returned no rows" compact />}>
          {(d) => (
            <>
              <RowsTable rows={d.rows} />
              <Pager offset={offset} limit={ROWS_LIMIT} total={d.total} shown={d.rows.length} onChange={setOffset} />
            </>
          )}
        </QueryView>
      </div>
    </div>
  )
}
