// The running-process list on the Kill process card: asks the agent for its process list
// (the process.list artifact), then lets the user filter it and pick a process to kill.

import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { api, TERMINAL_COMMAND_STATUSES, type Host, type Row } from '../api'
import { actionAllowed } from '../lib/commands'
import { formatNumber, plural } from '../lib/format'
import { filterProcs, sortProcs, toProcRows, type ProcRow, type ProcSort } from '../lib/processPicker'
import { useHostAction } from './ActionDialog'
import { Icon } from './Icon'
import { RelTime } from './Misc'

const PAGE = 1000
const SHOWN = 300

async function allRows(id: string): Promise<Row[]> {
  const out: Row[] = []
  for (let offset = 0; ; offset += PAGE) {
    const page = await api.commandRows(id, PAGE, offset)
    out.push(...page.rows)
    if (page.rows.length < PAGE || out.length >= page.total) return out
  }
}

const SORTS: { key: ProcSort; label: string }[] = [
  { key: 'name', label: 'Name' },
  { key: 'pid', label: 'PID' },
  { key: 'user', label: 'User' },
  { key: 'start', label: 'Started' },
]

export function ProcessPicker({ host, onPick }: { host: Host; onPick: (p: ProcRow) => void }) {
  const collect = useHostAction(host.id)
  const [cmdId, setCmdId] = useState<string | null>(null)
  const [text, setText] = useState('')
  const [sort, setSort] = useState<ProcSort>('name')
  const [desc, setDesc] = useState(false)
  const [shown, setShown] = useState(SHOWN)
  const allowed = actionAllowed(host, 'artifact.collect')

  const cmd = useQuery({
    queryKey: ['command', cmdId],
    queryFn: () => api.getCommand(cmdId!),
    enabled: !!cmdId,
    refetchInterval: (q) => (q.state.data && TERMINAL_COMMAND_STATUSES.includes(q.state.data.status) ? false : 1500),
  })
  const status = cmd.data?.status
  const done = status === 'completed'
  const rows = useQuery({
    queryKey: ['command', cmdId, 'rows'],
    queryFn: () => allRows(cmdId!),
    enabled: !!cmdId && done,
    staleTime: Infinity,
  })
  const procs = useMemo(() => toProcRows(rows.data ?? []), [rows.data])
  const visible = useMemo(() => sortProcs(filterProcs(procs, text), sort, desc), [procs, text, sort, desc])

  const load = () => {
    setShown(SHOWN)
    collect.mutate(
      { type: 'artifact.collect', params: { name: 'process.list', params: { hash: 'false' } } },
      { onSuccess: (c) => setCmdId(c.id) },
    )
  }
  const busy = collect.isPending || (!!cmdId && !status) || (!!status && !TERMINAL_COMMAND_STATUSES.includes(status)) || rows.isFetching

  const setSortKey = (k: ProcSort) => {
    if (k === sort) setDesc(!desc)
    else {
      setSort(k)
      setDesc(false)
    }
  }

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn"
          onClick={load}
          disabled={!allowed || busy}
          title={allowed ? undefined : 'artifact.collect is not allowed by the agent’s local policy'}
        >
          <Icon name="refresh" size={14} /> {cmdId ? 'Refresh list' : 'Show running processes'}
        </button>
        {!allowed ? (
          <span className="hint">The agent’s local policy does not allow artifact.collect, so it cannot list processes. Enter a PID below instead.</span>
        ) : busy ? (
          <span className="hint">
            {collect.isPending
              ? 'Sending…'
              : status === 'queued'
                ? host.status === 'offline'
                  ? `Queued. ${host.hostname} is offline, so the list arrives when it reconnects.`
                  : 'Waiting for the agent to pick it up…'
                : 'Collecting processes…'}
          </span>
        ) : done && cmd.data?.completed_at ? (
          <span className="hint">
            {plural(procs.length, 'process', 'processes')}, collected <RelTime iso={cmd.data.completed_at} />
          </span>
        ) : null}
      </div>

      {collect.isError ? <div className="callout danger">Could not ask the agent: {(collect.error as Error).message}</div> : null}
      {status && status !== 'completed' && TERMINAL_COMMAND_STATUSES.includes(status) ? (
        <div className="callout danger">
          The process list {status === 'expired' ? 'expired before the agent picked it up' : `${status}`}
          {cmd.data?.error ? `: ${cmd.data.error}` : '.'}
        </div>
      ) : null}
      {rows.isError ? <div className="callout danger">Could not read the list: {(rows.error as Error).message}</div> : null}

      {done && rows.data ? (
        <>
          <input
            type="search"
            className="input"
            placeholder="Filter by name, PID, user or command line"
            aria-label="Filter processes"
            value={text}
            onChange={(e) => {
              setText(e.target.value)
              setShown(SHOWN)
            }}
          />
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="table" style={{ minWidth: 620 }}>
              <thead>
                <tr>
                  {SORTS.map((s) => (
                    <th key={s.key} aria-sort={sort === s.key ? (desc ? "descending" : "ascending") : "none"} style={{ padding: 0 }}>
                      <button type="button" className="th-sort" onClick={() => setSortKey(s.key)} style={{ whiteSpace: "nowrap" }}>
                        {s.label}
                        {sort === s.key ? (desc ? ' ▾' : ' ▴') : ''}
                      </button>
                    </th>
                  ))}
                  <th style={{ padding: 0 }}>
                    <span className="th-sort" style={{ cursor: "default", textTransform: "none" }}>
                      Command line
                    </span>
                  </th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="muted small">
                      {procs.length ? 'No processes match this filter.' : 'The agent returned no processes.'}
                    </td>
                  </tr>
                ) : (
                  visible.slice(0, shown).map((p, i) => (
                    <tr key={`${p.pid}|${p.entity_id}|${i}`}>
                      <td className="truncate" title={p.executable || p.name} style={{ maxWidth: 200 }}>
                        {p.name}
                        {p.children ? <span className="faint xsmall"> · {plural(p.children, 'child', 'children')}</span> : null}
                      </td>
                      <td className="mono small">{p.pid}</td>
                      <td className="truncate small" style={{ maxWidth: 140 }}>{p.user || '—'}</td>
                      <td className="small">{p.start ? <RelTime iso={p.start} /> : '—'}</td>
                      <td className="mono xsmall truncate" title={p.command_line} style={{ maxWidth: 320 }}>
                        {p.command_line || '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button type="button" className="btn sm danger" onClick={() => onPick(p)} title={`Kill ${p.name} (PID ${p.pid})`}>
                          <Icon name="kill" size={12} /> Kill…
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {visible.length > shown ? (
            <div className="pager">
              <span>
                Showing {formatNumber(shown)} of {formatNumber(visible.length)}
              </span>
              <button type="button" className="btn sm" onClick={() => setShown(shown + SHOWN)}>
                Show more
              </button>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  )
}
