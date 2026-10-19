import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import { api, isApiError, PROCESS_EVENT_CATEGORIES, queryKeys, type Host, type ProcessEventCategory, type ProcessNode } from '../api'
import { EventTable } from '../components/EventTable'
import { Icon, type IconName } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { ButtonTabs, ExpandableText, KV, RelTime } from '../components/Misc'
import { ResponseButtons } from '../components/ResponseButtons'
import { EmptyState, ErrorState, Loading, QueryView, Spinner } from '../components/States'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { collapsibleIds, countNodes, defaultCollapsed, flattenTree, totalEventCount, type FlatRow } from '../lib/processTree'
import { formatDateTime, formatTimestamp } from '../lib/time'

const CAT_ICON: Record<ProcessEventCategory, IconName> = {
  network: 'network',
  file: 'file',
  registry: 'registry',
  dns: 'dns',
  library: 'library',
}

export function ProcessTreePage() {
  const { id: hostId = '', entityId = '' } = useParams()
  const [depth, setDepth] = useState(3)
  const tree = useQuery({
    queryKey: queryKeys.processTree(hostId, entityId, depth),
    queryFn: () => api.processTree(hostId, entityId, depth),
    placeholderData: keepPreviousData,
  })
  const hostQ = useQuery({ queryKey: queryKeys.host(hostId), queryFn: () => api.getHost(hostId) })
  const root = tree.data?.root

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<string>(entityId)
  const [fullCmd, setFullCmd] = useState<Set<string>>(new Set())

  // Reset view state whenever a new tree arrives for a different target.
  useEffect(() => {
    if (root) setCollapsed(defaultCollapsed(root, depth, entityId))
    setSelected(entityId)
  }, [root, entityId, depth])

  const rows = useMemo(() => (root ? flattenTree(root, collapsed, entityId) : []), [root, collapsed, entityId])
  const target = rows.find((r) => r.role === 'target')?.node
  const selectedNode = rows.find((r) => r.node.entity_id === selected)?.node ?? target
  useDocumentTitle(target ? `${target.name} (${target.pid})` : 'Process tree')

  const toggle = (id: string) =>
    setCollapsed((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })

  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/hosts">Hosts</Link>
        <Icon name="chevronRight" size={10} />
        <Link to={`/hosts/${encodeURIComponent(hostId)}`}>{hostQ.data?.hostname ?? hostId}</Link>
        <Icon name="chevronRight" size={10} />
        <span>Process tree</span>
      </div>
      <PageHeader
        title={target ? <span className="mono">{target.name} <span className="muted">PID {target.pid}</span></span> : 'Process tree'}
        subtitle={root ? `${formatNumber(countNodes(root))} processes · ancestors, the process and ${depth} levels of descendants` : undefined}
        actions={
          <>
            {tree.isFetching && !tree.isPending ? <Spinner small /> : null}
            <label className="row small muted">
              Depth
              <select className="select" value={depth} onChange={(e) => setDepth(Number(e.target.value))} aria-label="Descendant depth">
                {[1, 2, 3, 4, 5, 8].map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="btn sm" onClick={() => setCollapsed(new Set())} disabled={!root}>
              Expand all
            </button>
            <button type="button" className="btn sm" onClick={() => root && setCollapsed(new Set(collapsibleIds(root).filter((id) => id !== root.entity_id)))} disabled={!root}>
              Collapse all
            </button>
          </>
        }
      />
      {tree.isPending ? (
        <div className="panel">
          <Loading label="Building process tree…" />
        </div>
      ) : tree.isError ? (
        <div className="panel">
          {isApiError(tree.error) && tree.error.status === 404 ? (
            <EmptyState title="Process not found">No process with this entity ID is known on this host. It may be older than the retention window.</EmptyState>
          ) : (
            <ErrorState error={tree.error} onRetry={() => tree.refetch()} />
          )}
        </div>
      ) : (
        <div className="split">
          <section className="panel ptree" aria-label="Process tree">
            {rows.map((r) => (
              <TreeRow
                key={r.node.entity_id}
                row={r}
                selected={selectedNode?.entity_id === r.node.entity_id}
                onSelect={() => setSelected(r.node.entity_id)}
                onToggle={() => toggle(r.node.entity_id)}
                full={fullCmd.has(r.node.entity_id)}
                onToggleFull={() =>
                  setFullCmd((s) => {
                    const n = new Set(s)
                    if (n.has(r.node.entity_id)) n.delete(r.node.entity_id)
                    else n.add(r.node.entity_id)
                    return n
                  })
                }
              />
            ))}
          </section>
          <aside className="side">
            {selectedNode ? <NodePanel node={selectedNode} hostId={hostId} host={hostQ.data} isTarget={selectedNode.entity_id === entityId} /> : null}
          </aside>
        </div>
      )}
    </>
  )
}

function TreeRow({
  row,
  selected,
  onSelect,
  onToggle,
  full,
  onToggleFull,
}: {
  row: FlatRow
  selected: boolean
  onSelect: () => void
  onToggle: () => void
  full: boolean
  onToggleFull: () => void
}) {
  const n = row.node
  const cls = ['prow', row.role, selected ? 'selected' : ''].join(' ')
  return (
    <div
      className={cls}
      onClick={onSelect}
      role="treeitem"
      aria-level={row.depth + 1}
      aria-expanded={row.hasChildren ? !row.collapsed : undefined}
      aria-selected={selected}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') onSelect()
        if ((e.key === 'ArrowRight' && row.collapsed) || (e.key === 'ArrowLeft' && row.hasChildren && !row.collapsed)) {
          e.preventDefault()
          onToggle()
        }
      }}
    >
      <span className="guides" aria-hidden="true">
        {row.guides.map((g, i) => (
          <span key={i} className={g ? 'guide line' : 'guide'} />
        ))}
        {row.depth > 0 ? <span className={row.isLast ? 'guide conn last' : 'guide conn'} /> : null}
      </span>
      {row.hasChildren ? (
        <button
          type="button"
          className={row.collapsed ? 'twisty' : 'twisty open'}
          aria-label={row.collapsed ? `Expand ${n.name}` : `Collapse ${n.name}`}
          onClick={(e) => {
            e.stopPropagation()
            onToggle()
          }}
        >
          <Icon name="chevronRight" size={12} />
        </button>
      ) : (
        <span className="twisty" aria-hidden="true" />
      )}
      <div className="pmain">
        <div className="pline">
          <span className="pname mono">{n.name}</span>
          <span className="pmeta">PID {n.pid}</span>
          {n.user ? <span className="pmeta truncate-inline" style={{ maxWidth: 220 }}>{n.user}</span> : null}
          {row.role === 'target' ? <span className="role-label">target</span> : row.role === 'ancestor' ? <span className="role-label">ancestor</span> : null}
          {n.alert_count > 0 ? (
            <span className="badge count alerts" title={`${n.alert_count} alerts`}>
              <Icon name="alert" size={10} /> {n.alert_count}
            </span>
          ) : null}
          {n.end ? <span className="pmeta">exited {n.exit_code !== undefined ? `(${n.exit_code})` : ''}</span> : null}
          {row.collapsed ? <span className="pmeta">+{row.hiddenCount} hidden</span> : null}
          <span className="pcounts">
            {PROCESS_EVENT_CATEGORIES.map((c) => {
              const v = n.event_counts?.[c] ?? 0
              return (
                <span key={c} className={v ? 'ecount' : 'ecount zero'} title={`${v} ${c} events`}>
                  <Icon name={CAT_ICON[c]} size={10} />
                  {v}
                </span>
              )
            })}
          </span>
        </div>
        {n.command_line ? (
          <div className="pline">
            <span className={full ? 'pcmd full' : 'pcmd truncated'} title={full ? undefined : n.command_line}>
              {n.command_line}
            </span>
            {n.command_line.length > 90 ? (
              <button
                type="button"
                className="linklike xsmall nowrap"
                onClick={(e) => {
                  e.stopPropagation()
                  onToggleFull()
                }}
              >
                {full ? 'less' : 'more'}
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  )
}

function NodePanel({ node: n, hostId, host, isTarget }: { node: ProcessNode; hostId: string; host?: Host; isTarget: boolean }) {
  const [cat, setCat] = useState<string>('all')
  useEffect(() => setCat('all'), [n.entity_id])
  const category = cat === 'all' ? undefined : (cat as ProcessEventCategory)
  const q = useQuery({
    queryKey: queryKeys.processEvents(hostId, n.entity_id, category),
    queryFn: () => api.processEvents(hostId, n.entity_id, category),
  })
  const total = totalEventCount(n)
  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-header">
          <h2 className="mono">
            {n.name} <span className="muted">({n.pid})</span>
          </h2>
          {!isTarget ? (
            <Link className="small" to={`/hosts/${encodeURIComponent(hostId)}/process/${encodeURIComponent(n.entity_id)}`}>
              Focus this process
            </Link>
          ) : null}
        </div>
        <div className="panel-body stack" style={{ gap: 10 }}>
          <KV
            items={[
              ['Executable', n.executable ? <span className="mono small" style={{ overflowWrap: 'anywhere' }}>{n.executable}</span> : undefined],
              ['Command line', <ExpandableText key="c" text={n.command_line} max={200} />],
              ['User', n.user],
              ['Started', n.start ? <span title={formatTimestamp(n.start)}>{formatDateTime(n.start)} (<RelTime iso={n.start} />)</span> : undefined],
              ['Ended', n.end ? `${formatDateTime(n.end)}${n.exit_code !== undefined ? ` · exit ${n.exit_code}` : ''}` : <span className="ok-text">running</span>],
              ['Signed', n.signed === undefined ? undefined : n.signed ? 'yes' : <span className="danger-text">no</span>],
              ['SHA-256', n.hash_sha256 ? <span className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>{n.hash_sha256}</span> : undefined],
              ['Entity ID', <span key="e" className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>{n.entity_id}</span>],
              ['Alerts', n.alert_count ? <Link to={`/alerts?host=${encodeURIComponent(hostId)}&status=all&q=${encodeURIComponent(n.name)}`}>{n.alert_count}</Link> : '0'],
            ]}
          />
          <div className="row">
            <Link className="btn sm" to={`/search?q=${encodeURIComponent(`process.entity_id:${n.entity_id}`)}&range=7d`}>
              <Icon name="search" size={12} /> All events
            </Link>
            {host ? <ResponseButtons host={host} process={{ pid: n.pid, entity_id: n.entity_id, name: n.name, ended: !!n.end }} small /> : null}
          </div>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Activity</h2>
          <span className="hint">{formatNumber(total)} events</span>
        </div>
        <div style={{ padding: '0 8px' }}>
          <ButtonTabs
            active={cat}
            onChange={setCat}
            tabs={[
              { id: 'all', label: 'All' },
              ...PROCESS_EVENT_CATEGORIES.map((c) => ({ id: c, label: `${c} ${n.event_counts?.[c] ?? 0}` })),
            ]}
          />
        </div>
        <QueryView
          query={q}
          compact
          isEmpty={(d) => d.events.length === 0}
          empty={<EmptyState title={`No ${cat === 'all' ? '' : cat + ' '}activity recorded for this process`} compact />}
        >
          {(d) => <EventTable events={d.events} processLinks={false} dense />}
        </QueryView>
      </section>
    </div>
  )
}
