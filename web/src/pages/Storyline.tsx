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
  groupSiblings,
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
  const { item, selected, highlighted, dimmed } = data
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
    <div className={cls} style={style} title={n.stub ? 'no start event seen' : group ? `${group} × ${n.name} (click to expand)` : n.executable || n.name}>
      <Handle type="target" position={Position.Left} className="sl-handle" isConnectable={false} />
      <div className="sl-circle">
        <Icon name={group ? 'tree' : 'settings'} size={22} />
        {!group && n.alert_count > 0 ? (
          <span className="sl-badge" title={`${n.alert_count} alerts`}>
            {n.alert_count}
          </span>
        ) : null}
      </div>
      <div className="sl-name" title={n.name}>
        {group ? `${group} × ${n.name}` : n.name}
      </div>
      {group ? <div className="sl-pid">same parent</div> : <div className="sl-pid">PID {n.pid}</div>}
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

function StorylineView({ data, host }: { data: Storyline; host?: Host }) {
  const { fitView, setCenter, zoomTo, getNode } = useReactFlow<FlowNode, Edge<FlowEdgeData>>()
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
    setSelTactics(new Set(allSlugs))
    setSelected(data.focus_entity_id)
    setExpanded(new Set())
  }, [data, allSlugs])

  const { items, edges } = useMemo(() => {
    let g = { nodes: data.nodes, edges: data.edges }
    if (view === 'process') g = processView(g, data.focus_entity_id)
    if (!cross) g = withoutCrossProcess(g)
    return groupSiblings(g, expanded)
  }, [data, view, cross, expanded])

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
  useEffect(() => {
    if (!ready || fitKey.current === layoutKey) return
    fitKey.current = layoutKey
    const t = setTimeout(() => void fitView({ padding: 0.2, maxZoom: 1, duration: 200 }), 30)
    return () => clearTimeout(t)
  }, [ready, layoutKey, fitView])

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
      },
    }))
  }, [items, positions, ready, selected, highlight, selTactics, allSlugs])

  const flowEdges: Edge<FlowEdgeData>[] = useMemo(() => {
    const accent = 'var(--accent)'
    return edges.map((e, i) => {
      const tip = `${KIND_LABEL[e.kind]}${e.detail ? `: ${e.detail}` : ''}${e.at ? ` · ${formatTimestamp(e.at)}` : ''}`
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

  const selectedItem = items.find((i) => i.id === selected)
  const selectedNode = selectedItem?.members ? undefined : selectedItem?.node ?? data.nodes.find((n) => n.entity_id === selected)
  const nodeAlerts = (id: string) => data.alerts.filter((a) => a.entity_id === id)

  function focusNode(id: string) {
    const nd = getNode(id)
    if (nd) void setCenter(nd.position.x + NODE_WIDTH / 2, nd.position.y + NODE_HEIGHT / 2, { zoom: Math.max(zoom, 0.9), duration: 250 })
  }

  function pickAlert(a: StorylineAlert) {
    // The node may be inside a collapsed group: expand it first.
    const grp = items.find((i) => i.members?.some((m) => m.entity_id === a.entity_id))
    if (grp) setExpanded((s) => new Set(s).add(grp.id))
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
            <button type="button" className="btn sm" onClick={() => setDrawer((d) => !d)} aria-expanded={drawer}>
              <Icon name="filter" size={12} /> {drawer ? 'Hide filters' : 'Filters'}
            </button>
          </div>
          <div className="sl-canvas">
            {!ready ? <Loading label="Laying out graph…" compact /> : null}
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
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
