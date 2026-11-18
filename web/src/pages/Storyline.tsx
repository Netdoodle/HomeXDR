import '@xyflow/react/dist/style.css'
import './storyline.css'
import {
  BaseEdge,
  Background,
  Controls,
  getBezierPath,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useViewport,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import { useQuery } from '@tanstack/react-query'
import ELK from 'elkjs/lib/elk.bundled.js'
import type { ElkNode } from 'elkjs/lib/elk-api'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import {
  api,
  isApiError,
  PROCESS_EVENT_CATEGORIES,
  queryKeys,
  type Host,
  type Storyline,
  type StorylineAlert,
  type StorylineEdge,
  type StorylineEdgeKind,
  type StorylineNode,
} from '../api'
import { SeverityBadge } from '../components/Badges'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { ButtonTabs, ExpandableText, KV, RelTime } from '../components/Misc'
import { ResponseButtons } from '../components/ResponseButtons'
import { EmptyState, ErrorState, Loading } from '../components/States'
import { useDocumentTitle } from '../lib/hooks'
import {
  buildElkGraph,
  collapsedView,
  groupSiblings,
  hasLoadedChildren,
  importantNodes,
  initialOpen,
  isTreeEdge,
  mergeStoryline,
  isDimmed,
  NODE_HEIGHT,
  NODE_WIDTH,
  processView,
  tacticLabel,
  tacticList,
  withoutCrossProcess,
  type GraphItem,
} from '../lib/storyline'
import { formatDateTime, formatTimestamp } from '../lib/time'
import { CAT_ICON } from './ProcessTree'

const elk = new ELK()

/** Below this zoom node names are unreadable, so the first view centres on the focus. */
const MIN_READABLE_ZOOM = 0.45

const KIND_LABEL: Record<StorylineEdgeKind, string> = {
  parent: 'Parent process',
  remote_thread: 'Remote thread',
  process_access: 'Process access',
  process_tampering: 'Process tampering',
  scheduled_task: 'Scheduled task',
  service: 'Service',
  wmi: 'WMI',
}
const SHORT_LABEL: Partial<Record<StorylineEdgeKind, string>> = { scheduled_task: 'task', service: 'service', wmi: 'WMI' }

interface FlowNodeData extends Record<string, unknown> {
  item: GraphItem
  selected: boolean
  highlighted: boolean
  dimmed: boolean
  /** Tooltips of edges from the process to itself (tampering with no other target). */
  selfTips: string[]
  /** Loaded processes hidden below this one (a closed branch). */
  hidden: number
  /** Children not loaded yet: a click fetches them. */
  more: boolean
  /** The branch is open. */
  open: boolean
  loading: boolean
}
type FlowNode = Node<FlowNodeData, 'proc'>

interface FlowEdgeData extends Record<string, unknown> {
  tip: string
  label?: string
  dash?: string
}

function severityVar(s: string): string {
  return `var(--sev-${s || 'high'})`
}

function ProcNode({ data }: NodeProps<FlowNode>) {
  const { item, selected, highlighted, dimmed, selfTips, hidden, more, open, loading } = data
  const n = item.node
  const group = item.members?.length
  const cls = [
    'sl-node',
    n.alert_count > 0 ? 'alerted' : '',
    n.focus ? 'focus' : '',
    n.context || n.outside ? 'ctx' : '',
    n.stub ? 'stub' : '',
    selected ? 'selected' : '',
    highlighted ? 'highlight' : '',
    dimmed ? 'dim' : '',
  ].join(' ')
  const style = n.alert_count > 0 ? ({ '--sl-sev': severityVar(n.max_severity) } as React.CSSProperties) : undefined
  return (
    <div className={cls} style={style} title={n.stub ? 'no start event seen' : item.others ? `${group} other processes with no alert below them (click to show)` : group ? `${group} × ${n.name} (click to expand)` : n.executable || n.name}>
      <Handle type="target" position={Position.Left} className="sl-handle" isConnectable={false} />
      <div className="sl-circle">
        <Icon name={group ? 'tree' : 'settings'} size={22} />
        {!group && n.alert_count > 0 ? (
          <span className="sl-badge" title={`${n.alert_count} alerts`}>
            {n.alert_count}
          </span>
        ) : null}
        {!group && (hidden > 0 || more) ? (
          <span className="sl-more" title={loading ? 'Loading child processes…' : hidden > 0 ? `${hidden} more processes below: click to open` : 'Click to load child processes'}>
            {loading ? '…' : hidden > 0 ? `+${hidden}` : '+'}
          </span>
        ) : null}
        {!group && open && !n.context ? <span className="sl-open" title="Click to close this branch" aria-hidden="true" /> : null}
        {selfTips.length > 0 ? (
          <span className="sl-self" title={selfTips.join('\n')}>
            <Icon name="warning" size={10} />
          </span>
        ) : null}
      </div>
      <div className="sl-name" title={n.name}>
        {item.others ? `${group} other processes` : group ? `${group} × ${n.name}` : n.name}
      </div>
      {group ? <div className="sl-pid">{item.others ? 'no alerts · click to show' : 'same parent'}</div> : <div className="sl-pid">PID {n.pid}</div>}
      {!group ? (
        <div className="sl-counts">
          {PROCESS_EVENT_CATEGORIES.filter((c) => (n.event_counts?.[c] ?? 0) > 0).map((c) => (
            <span key={c} className="sl-count" title={`${n.event_counts[c]} ${c} events`}>
              <Icon name={CAT_ICON[c]} size={10} />
            </span>
          ))}
        </div>
      ) : null}
      <Handle type="source" position={Position.Right} className="sl-handle" isConnectable={false} />
    </div>
  )
}

function edgeTip(e: StorylineEdge): string {
  return `${KIND_LABEL[e.kind]}${e.detail ? `: ${e.detail}` : ''}${e.at ? ` · ${formatTimestamp(e.at)}` : ''}`
}

function CrossEdge({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, data }: EdgeProps<Edge<FlowEdgeData>>) {
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.4 })
  return (
    <g>
      <title>{data?.tip}</title>
      <BaseEdge path={path} markerEnd={markerEnd} style={style} interactionWidth={18} />
      {data?.label ? (
        <text x={lx} y={ly - 4} className="sl-edge-label" textAnchor="middle">
          {data.label}
        </text>
      ) : null}
    </g>
  )
}

const nodeTypes = { proc: ProcNode }
const edgeTypes = { cross: CrossEdge }

export function StorylinePage() {
  const { id: hostParam = '', entityId = '', alertId = '' } = useParams()
  const q = useQuery({
    queryKey: queryKeys.storyline(hostParam, entityId, alertId),
    queryFn: () => (alertId ? api.storyline({ alertId }) : api.storyline({ hostId: hostParam, entityId })),
  })
  const data = q.data
  const hostId = data?.host_id ?? hostParam
  const hostQ = useQuery({ queryKey: queryKeys.host(hostId), queryFn: () => api.getHost(hostId), enabled: !!hostId })
  const focus = data?.nodes.find((n) => n.entity_id === data.focus_entity_id)
  useDocumentTitle(focus ? `Storyline: ${focus.name}` : 'Storyline')

  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        {alertId ? (
          <>
            <Link to="/alerts">Alerts</Link>
            <Icon name="chevronRight" size={10} />
            <Link to={`/alerts/${encodeURIComponent(alertId)}`} className="mono">
              {alertId}
            </Link>
          </>
        ) : (
          <>
            <Link to="/hosts">Hosts</Link>
            <Icon name="chevronRight" size={10} />
            <Link to={`/hosts/${encodeURIComponent(hostId)}`}>{data?.hostname ?? hostId}</Link>
          </>
        )}
        <Icon name="chevronRight" size={10} />
        <span>Storyline</span>
      </div>
      <PageHeader
        title={focus ? <span className="mono">{focus.name} <span className="muted">PID {focus.pid}</span></span> : 'Storyline'}
        subtitle={data ? `${data.nodes.length} processes · ${data.alerts.length} alerts on ${data.hostname || hostId}` : undefined}
        actions={
          data ? (
            <Link className="btn sm" to={`/hosts/${encodeURIComponent(data.host_id)}/process/${encodeURIComponent(data.focus_entity_id)}`}>
              <Icon name="tree" size={12} /> Process tree
            </Link>
          ) : null
        }
      />
      {q.isPending ? (
        <div className="panel">
          <Loading label="Building storyline…" />
        </div>
      ) : q.isError ? (
        <div className="panel">
          {isApiError(q.error) && q.error.status === 404 ? (
            <EmptyState title="Storyline not found">No process or alert with this ID is known. It may be older than the retention window.</EmptyState>
          ) : (
            <ErrorState error={q.error} onRetry={() => q.refetch()} />
          )}
        </div>
      ) : q.data.nodes.length === 0 ? (
        <div className="panel">
          <EmptyState title="No processes in this storyline">No process activity was recorded for this target.</EmptyState>
        </div>
      ) : (
        <ReactFlowProvider>
          <StorylineView data={q.data} host={hostQ.data} />
        </ReactFlowProvider>
      )}
    </>
  )
}

function StorylineView({ data: initial, host }: { data: Storyline; host?: Host }) {
  // The storyline on screen: the server's answer plus deeper branches loaded on click.
  const [data, setData] = useState<Storyline>(initial)
  const [open, setOpen] = useState<Set<string>>(() => initialOpen(initial))
  const [loadingIds, setLoadingIds] = useState<Set<string>>(new Set())
  const [loadError, setLoadError] = useState('')
  useEffect(() => {
    setData(initial)
    setOpen(initialOpen(initial))
  }, [initial])
  const { fitView, setCenter, zoomTo, getNode, getZoom } = useReactFlow<FlowNode, Edge<FlowEdgeData>>()
  const { zoom } = useViewport()
  const [view, setView] = useState<'process' | 'storyline'>('storyline')
  const [cross, setCross] = useState(true)
  const tactics = useMemo(() => tacticList(data), [data])
  const allSlugs = useMemo(() => tactics.map((t) => t.slug), [tactics])
  const [selTactics, setSelTactics] = useState<Set<string>>(() => new Set(allSlugs))
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<string>(data.focus_entity_id)
  const [highlight, setHighlight] = useState<string>('')
  const [drawer, setDrawer] = useState(true)
  const [positions, setPositions] = useState<{ key: string; pos: Map<string, { x: number; y: number }> } | null>(null)

  useEffect(() => {
    setSelected(initial.focus_entity_id)
    setExpanded(new Set())
  }, [initial])
  // Tactics that appear (a new storyline, or a branch loaded with new alerts) start selected.
  const knownSlugs = useRef<Set<string>>(new Set())
  useEffect(() => {
    const fresh = allSlugs.filter((t) => !knownSlugs.current.has(t))
    if (fresh.length === 0) return
    for (const t of fresh) knownSlugs.current.add(t)
    setSelTactics((s) => new Set([...s, ...fresh]))
  }, [allSlugs])

  // Quiet children fold into "other processes" until Expand all.
  const [fold, setFold] = useState(true)
  const important = useMemo(() => (fold ? importantNodes(data) : undefined), [data, fold])
  const { items, edges, hidden } = useMemo(() => {
    let g = { nodes: data.nodes, edges: data.edges }
    if (view === 'process') g = processView(g, data.focus_entity_id)
    if (!cross) g = withoutCrossProcess(g)
    const c = collapsedView(g, open)
    return { ...groupSiblings(c, expanded, important), hidden: c.hidden }
  }, [data, view, cross, expanded, open, important])

  const layoutKey = useMemo(() => items.map((i) => i.id).join(',') + '|' + edges.map((e) => `${e.from}>${e.to}`).join(','), [items, edges])

  useEffect(() => {
    let cancelled = false
    elk
      .layout(buildElkGraph(items, edges) as ElkNode)
      .then((res) => {
        if (cancelled) return
        const pos = new Map<string, { x: number; y: number }>()
        for (const c of res.children ?? []) pos.set(c.id, { x: c.x ?? 0, y: c.y ?? 0 })
        setPositions({ key: layoutKey, pos })
      })
      .catch(() => {
        if (cancelled) return
        const pos = new Map<string, { x: number; y: number }>()
        items.forEach((it, i) => pos.set(it.id, { x: (i % 8) * (NODE_WIDTH + 40), y: Math.floor(i / 8) * (NODE_HEIGHT + 30) }))
        setPositions({ key: layoutKey, pos })
      })
    return () => {
      cancelled = true
    }
  }, [items, edges, layoutKey])

  const ready = positions?.key === layoutKey
  const fitKey = useRef('')
  const fitFor = `${initial.host_id}|${initial.focus_entity_id}|${view}`
  useEffect(() => {
    // Fit once per storyline and view; opening or closing a branch keeps the viewport.
    if (!ready || fitKey.current === fitFor) return
    fitKey.current = fitFor
    // Show the whole graph when it fits at a readable size; otherwise start on the focus
    // process, at a size where names can be read.
    const focusPos = positions?.pos.get(data.focus_entity_id)
    const t = setTimeout(() => {
      void fitView({ padding: 0.2, maxZoom: 1 }).then(() => {
        if (getZoom() >= MIN_READABLE_ZOOM || !focusPos) return
        void setCenter(focusPos.x + NODE_WIDTH / 2, focusPos.y + NODE_HEIGHT / 2, { zoom: 0.85 })
      })
    }, 30)
    return () => clearTimeout(t)
  }, [ready, fitFor, fitView, getZoom, setCenter, positions, data.focus_entity_id])

  const flowNodes: FlowNode[] = useMemo(() => {
    if (!ready || !positions) return []
    return items.map((it) => ({
      id: it.id,
      type: 'proc' as const,
      position: positions.pos.get(it.id) ?? { x: 0, y: 0 },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      draggable: false,
      data: {
        item: it,
        selected: it.id === selected,
        highlighted: it.id === highlight,
        dimmed: isDimmed(it.node, selTactics, allSlugs),
        selfTips: edges.filter((e) => e.from === it.id && e.to === it.id).map(edgeTip),
        hidden: hidden.get(it.id) ?? 0,
        more: !!it.node.more && !hasLoadedChildren(data, it.id),
        open: open.has(it.id) && hasLoadedChildren(data, it.id),
        loading: loadingIds.has(it.id),
      },
    }))
  }, [items, edges, hidden, data, open, loadingIds, positions, ready, selected, highlight, selTactics, allSlugs])

  const flowEdges: Edge<FlowEdgeData>[] = useMemo(() => {
    const accent = 'var(--accent)'
    return edges.filter((e) => e.from !== e.to).map((e, i) => {
      const tip = edgeTip(e)
      const base = { id: `${e.from}>${e.to}:${e.kind}:${i}`, source: e.from, target: e.to }
      if (e.kind === 'parent') {
        return { ...base, type: 'smoothstep', style: { stroke: 'var(--text-faint)', strokeWidth: 1.6 }, data: { tip } }
      }
      const dashed = e.kind === 'remote_thread' || e.kind === 'process_access' || e.kind === 'process_tampering'
      return {
        ...base,
        type: 'cross',
        data: { tip, label: SHORT_LABEL[e.kind] },
        style: { stroke: accent, strokeWidth: 1.8, strokeDasharray: dashed ? '7 5' : '2 4' },
        markerEnd: dashed ? { type: MarkerType.ArrowClosed, color: 'var(--accent)' } : undefined,
      }
    })
  }, [edges])

  // While a new layout runs (a branch opened or closed), keep the last one on screen.
  const lastShown = useRef<{ nodes: FlowNode[]; edges: Edge<FlowEdgeData>[] }>({ nodes: [], edges: [] })
  if (ready) lastShown.current = { nodes: flowNodes, edges: flowEdges }
  const shownNodes = ready ? flowNodes : lastShown.current.nodes
  const shownEdges = ready ? flowEdges : lastShown.current.edges

  // After a branch opens, bring it into view: the process and its new children.
  const revealAfterLayout = useRef('')
  useEffect(() => {
    const id = revealAfterLayout.current
    if (!ready || !id) return
    revealAfterLayout.current = ''
    const ids = [id, ...edges.filter((e) => e.from === id && isTreeEdge(e) && e.to !== id).map((e) => e.to)]
    const t = setTimeout(
      () => void fitView({ nodes: ids.map((x) => ({ id: x })), padding: 0.3, minZoom: MIN_READABLE_ZOOM, maxZoom: Math.max(getZoom(), MIN_READABLE_ZOOM), duration: 250 }),
      30,
    )
    return () => clearTimeout(t)
  }, [ready, layoutKey, edges, fitView, getZoom])

  const selectedItem = items.find((i) => i.id === selected)
  const selectedNode = selectedItem?.members ? undefined : selectedItem?.node ?? data.nodes.find((n) => n.entity_id === selected)
  const nodeAlerts = (id: string) => data.alerts.filter((a) => a.entity_id === id)

  /** Opens or closes the branch below a process, loading it from the server when needed. */
  function toggle(id: string) {
    // The system process above the root stays open: closing it would hide everything.
    if (data.nodes.find((n) => n.entity_id === id)?.context) return
    if (open.has(id) && hasLoadedChildren(data, id)) {
      setOpen((s) => {
        const n = new Set(s)
        n.delete(id)
        return n
      })
      return
    }
    if (hasLoadedChildren(data, id)) {
      revealAfterLayout.current = id
      setOpen((s) => new Set(s).add(id))
      return
    }
    const node = data.nodes.find((n) => n.entity_id === id)
    if (!node?.more || loadingIds.has(id)) return
    setLoadingIds((s) => new Set(s).add(id))
    setLoadError('')
    api
      .storyline({ hostId: data.host_id, entityId: id })
      .then((more) => {
        setData((d) => {
          const merged = mergeStoryline(d, more)
          // Nothing below it after all: stop offering to load.
          return hasLoadedChildren(merged, id)
            ? merged
            : { ...merged, nodes: merged.nodes.map((n) => (n.entity_id === id ? { ...n, more: false } : n)) }
        })
        revealAfterLayout.current = id
        setOpen((s) => new Set(s).add(id))
      })
      .catch((err: unknown) => setLoadError(err instanceof Error ? err.message : String(err)))
      .finally(() =>
        setLoadingIds((s) => {
          const n = new Set(s)
          n.delete(id)
          return n
        }),
      )
  }

  /** Opens every branch above a process so it is on screen. */
  function reveal(id: string) {
    const parentOf = new Map<string, string>()
    for (const e of data.edges) if (isTreeEdge(e) && e.from !== e.to && !parentOf.has(e.to)) parentOf.set(e.to, e.from)
    setOpen((s) => {
      const n = new Set(s)
      const seen = new Set<string>([id])
      for (let cur = parentOf.get(id); cur && !seen.has(cur); cur = parentOf.get(cur)) {
        seen.add(cur)
        n.add(cur)
      }
      return n
    })
  }

  function focusNode(id: string) {
    const nd = getNode(id)
    if (nd) void setCenter(nd.position.x + NODE_WIDTH / 2, nd.position.y + NODE_HEIGHT / 2, { zoom: Math.max(zoom, 0.9), duration: 250 })
  }

  function pickAlert(a: StorylineAlert) {
    // The node may be inside a collapsed group: expand it first.
    const grp = items.find((i) => i.members?.some((m) => m.entity_id === a.entity_id))
    if (grp) setExpanded((s) => new Set(s).add(grp.id))
    reveal(a.entity_id)
    setSelected(a.entity_id)
    setHighlight(a.entity_id)
    setTimeout(() => focusNode(a.entity_id), 60)
  }

  const toggleTactic = (slug: string) =>
    setSelTactics((s) => {
      const n = new Set(s)
      if (n.has(slug)) n.delete(slug)
      else n.add(slug)
      return n
    })

  const pct = Math.round(zoom * 100)

  return (
    <div className="sl-layout">
      <div className={drawer ? 'sl-main' : 'sl-main wide'}>
        {data.truncated ? (
          <div className="callout warn" role="status" style={{ marginBottom: 8 }}>
            This storyline is truncated: only part of the process activity is shown.
          </div>
        ) : null}
        {loadError ? (
          <div className="callout warn" role="alert" style={{ marginBottom: 8 }}>
            Could not load the child processes: {loadError}
          </div>
        ) : null}
        <section className="panel sl-graph-panel" aria-label="Storyline graph">
          <div className="sl-toolbar">
            <ButtonTabs
              active={view}
              onChange={(v) => setView(v as 'process' | 'storyline')}
              tabs={[
                { id: 'process', label: 'Process view' },
                { id: 'storyline', label: 'Storyline view' },
              ]}
            />
            <span className="sl-zoom">
              <Icon name="search" size={12} />
              <input
                type="range"
                min={10}
                max={200}
                value={Math.min(200, Math.max(10, pct))}
                onChange={(e) => void zoomTo(Number(e.target.value) / 100)}
                aria-label="Zoom"
              />
              <span className="small mono">{pct}%</span>
            </span>
            <button type="button" className="btn sm" onClick={() => void fitView({ padding: 0.2, maxZoom: 1, duration: 200 })}>
              Fit to view
            </button>
            <button type="button" className="btn sm" onClick={() => {
                setFold(false)
                setOpen(new Set(data.nodes.map((n) => n.entity_id)))
              }} title="Open every loaded branch">
              Expand all
            </button>
            <button
              type="button"
              className="btn sm"
              onClick={() => {
                setFold(true)
                setExpanded(new Set())
                setOpen(new Set(data.nodes.filter((n) => n.context || n.root).map((n) => n.entity_id)))
              }}
              title="Show only the root process and its children"
            >
              Collapse all
            </button>
            <button type="button" className="btn sm" onClick={() => setDrawer((d) => !d)} aria-expanded={drawer}>
              <Icon name="filter" size={12} /> {drawer ? 'Hide filters' : 'Filters'}
            </button>
          </div>
          <div className="sl-canvas">
            {!ready && shownNodes.length === 0 ? <Loading label="Laying out graph…" compact /> : null}
            <ReactFlow
              nodes={shownNodes}
              edges={shownEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              nodesDraggable={false}
              nodesConnectable={false}
              minZoom={0.1}
              maxZoom={2}
              proOptions={{ hideAttribution: true }}
              onNodeClick={(_, nd) => {
                const it = (nd.data as FlowNodeData).item
                if (it.members) {
                  setExpanded((s) => new Set(s).add(it.id))
                } else {
                  setSelected(nd.id)
                  setHighlight('')
                  toggle(nd.id)
                }
              }}
              onPaneClick={() => setHighlight('')}
              colorMode="system"
            >
              <Background gap={24} />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable className="sl-minimap" nodeColor={(nd) => ((nd.data as FlowNodeData).item.node.alert_count > 0 ? 'var(--danger)' : 'var(--text-faint)')} />
            </ReactFlow>
          </div>
        </section>

        <section className="panel" style={{ marginTop: 'var(--gap)' }}>
          <div className="panel-header">
            <h2>Alerts</h2>
            <span className="hint">{data.alerts.length}</span>
          </div>
          {data.alerts.length === 0 ? (
            <EmptyState title="No alerts in this storyline" compact />
          ) : (
            <ul className="sl-alerts">
              {data.alerts.map((a) => (
                <li key={a.id} className={a.entity_id === highlight ? 'on' : ''}>
                  <button type="button" className="sl-alert-btn" onClick={() => pickAlert(a)} title="Show on graph">
                    <SeverityBadge severity={a.severity} />
                    <span className="sl-alert-title">{a.title}</span>
                    <span className="muted small nowrap">
                      <RelTime iso={a.first_seen} />
                    </span>
                  </button>
                  <Link className="small" to={`/alerts/${encodeURIComponent(a.id)}`}>
                    open
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <aside className={drawer ? 'sl-side' : 'sl-side hidden'} aria-label="Storyline filters and details">
        <section className="panel">
          <div className="panel-header">
            <h2>Filters</h2>
          </div>
          <div className="panel-body stack" style={{ gap: 8 }}>
            <label className="row small">
              <input type="checkbox" checked={cross} onChange={(e) => setCross(e.target.checked)} /> Show cross-process
            </label>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <strong className="small">Behaviour categories</strong>
              {tactics.length > 0 ? (
                <button type="button" className="linklike xsmall" onClick={() => setSelTactics(new Set(allSlugs))}>
                  Select all
                </button>
              ) : null}
            </div>
            {tactics.length === 0 ? <span className="muted small">No behaviour categories in this storyline.</span> : null}
            {tactics.map((t) => (
              <label key={t.slug} className="row small">
                <input type="checkbox" checked={selTactics.has(t.slug)} onChange={() => toggleTactic(t.slug)} /> {t.label}
              </label>
            ))}
          </div>
        </section>
        {selectedNode ? (
          <NodeDetails node={selectedNode} hostId={data.host_id} host={host} alerts={nodeAlerts(selectedNode.entity_id)} />
        ) : (
          <section className="panel">
            <EmptyState title="Select a process" compact>
              Click a node in the graph to see its details.
            </EmptyState>
          </section>
        )}
      </aside>
    </div>
  )
}

function NodeDetails({ node: n, hostId, host, alerts }: { node: StorylineNode; hostId: string; host?: Host; alerts: StorylineAlert[] }) {
  const enc = encodeURIComponent
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="mono">
          {n.name} <span className="muted">({n.pid})</span>
        </h2>
      </div>
      <div className="panel-body stack" style={{ gap: 10 }}>
        <KV
          items={[
            ['Executable', n.executable ? <span className="mono small" style={{ overflowWrap: 'anywhere' }}>{n.executable}</span> : undefined],
            ['Command line', <ExpandableText key="c" text={n.command_line} max={200} />],
            ['User', n.user],
            ['PID', String(n.pid)],
            ['Started', n.start ? <span title={formatTimestamp(n.start)}>{formatDateTime(n.start)}</span> : n.stub ? 'no start event seen' : undefined],
            ['Ended', n.end ? `${formatDateTime(n.end)}${n.exit_code !== null ? ` · exit ${n.exit_code}` : ''}` : <span className="ok-text">running</span>],
            ['Signed', n.signed === null ? undefined : n.signed ? 'yes' : <span className="danger-text">no</span>],
            ['Integrity', n.integrity_level],
            ['Behaviour', n.tactics.length ? n.tactics.map(tacticLabel).join(', ') : undefined],
          ]}
        />
        <div className="sl-evcounts">
          {PROCESS_EVENT_CATEGORIES.map((c) => (
            <span key={c} className={n.event_counts?.[c] ? 'ecount' : 'ecount zero'} title={`${n.event_counts?.[c] ?? 0} ${c} events`}>
              <Icon name={CAT_ICON[c]} size={10} />
              {n.event_counts?.[c] ?? 0}
            </span>
          ))}
        </div>
        {alerts.length > 0 ? (
          <div className="stack" style={{ gap: 4 }}>
            <strong className="small">Alerts</strong>
            {alerts.map((a) => (
              <Link key={a.id} to={`/alerts/${enc(a.id)}`} className="small">
                {a.title}
              </Link>
            ))}
          </div>
        ) : null}
        <div className="row">
          <Link className="btn sm" to={`/hosts/${enc(hostId)}/process/${enc(n.entity_id)}`}>
            <Icon name="tree" size={12} /> Process tree
          </Link>
          <Link className="btn sm" to={`/search?q=${enc(`process.entity_id:${n.entity_id}`)}&range=7d`}>
            <Icon name="search" size={12} /> All events
          </Link>
          {host ? <ResponseButtons host={host} process={{ pid: n.pid, entity_id: n.entity_id, name: n.name, ended: !!n.end }} small /> : null}
        </div>
      </div>
    </section>
  )
}
