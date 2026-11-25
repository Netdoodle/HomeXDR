// Pure helpers for the Storyline graph page: view filtering, sibling grouping, tactic
// list and the input handed to the ELK layered layout.

import type { Storyline, StorylineEdge, StorylineEdgeKind, StorylineNode } from '../api/types'

export const NODE_WIDTH = 132
export const NODE_HEIGHT = 112
/** More than this many same-named, alert-free siblings collapse into one node. */
export const GROUP_THRESHOLD = 5

const TACTIC_LABELS: Record<string, string> = {
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
  'resource-development': 'Resource Development',
  reconnaissance: 'Reconnaissance',
}

/** "privilege-escalation" -> "Privilege Escalation". */
export function tacticLabel(slug: string): string {
  const known = TACTIC_LABELS[slug]
  if (known) return known
  return slug
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(' ')
}

/** Tactics present on any node or alert, sorted by label. */
export function tacticList(data: Pick<Storyline, 'nodes' | 'alerts'>): { slug: string; label: string }[] {
  const seen = new Set<string>()
  for (const n of data.nodes) for (const t of n.tactics ?? []) seen.add(t)
  for (const a of data.alerts) for (const t of a.tactics ?? []) seen.add(t)
  return [...seen].map((slug) => ({ slug, label: tacticLabel(slug) })).sort((a, b) => a.label.localeCompare(b.label))
}

/** True when the node should be dimmed given the selected tactic filter. */
export function isDimmed(node: Pick<StorylineNode, 'tactics'>, selected: ReadonlySet<string>, all: readonly string[]): boolean {
  if (all.length === 0 || all.every((t) => selected.has(t))) return false
  return !(node.tactics ?? []).some((t) => selected.has(t))
}

export interface GraphData {
  nodes: StorylineNode[]
  edges: StorylineEdge[]
}

/** Drops edges whose endpoints are not both present. */
export function pruneEdges(nodes: StorylineNode[], edges: StorylineEdge[]): StorylineEdge[] {
  const ids = new Set(nodes.map((n) => n.entity_id))
  return edges.filter((e) => ids.has(e.from) && ids.has(e.to))
}

/** Process view: only the focus process, its ancestors and its descendants via parent edges. */
export function processView(data: GraphData, focusId: string): GraphData {
  const parentEdges = data.edges.filter((e) => e.kind === 'parent')
  const parentOf = new Map<string, string[]>()
  const childrenOf = new Map<string, string[]>()
  for (const e of parentEdges) {
    parentOf.set(e.to, [...(parentOf.get(e.to) ?? []), e.from])
    childrenOf.set(e.from, [...(childrenOf.get(e.from) ?? []), e.to])
  }
  const keep = new Set<string>([focusId])
  const walk = (start: string, next: Map<string, string[]>) => {
    const stack = [start]
    while (stack.length) {
      const id = stack.pop() as string
      for (const n of next.get(id) ?? []) {
        if (!keep.has(n)) {
          keep.add(n)
          stack.push(n)
        }
      }
    }
  }
  walk(focusId, parentOf)
  walk(focusId, childrenOf)
  const nodes = data.nodes.filter((n) => keep.has(n.entity_id))
  return { nodes, edges: pruneEdges(nodes, parentEdges) }
}

/** Removes every edge that is not a plain parent -> child edge. */
export function withoutCrossProcess(data: GraphData): GraphData {
  return { nodes: data.nodes, edges: data.edges.filter((e) => e.kind === 'parent') }
}

export interface GraphItem {
  /** entity_id for a process, "group:..." for a collapsed group */
  id: string
  /** the process, or the first member of a group */
  node: StorylineNode
  /** every collapsed member (only for groups) */
  members?: StorylineNode[]
  /** a group of a parent's other children (not one name) */
  others?: boolean
  /** the "+" item under an open branch: shows the next page of its children */
  pager?: { parent: string; remaining: number }
}

export function groupId(parent: string, name: string): string {
  return `group:${parent}:${name}`
}

export function othersId(parent: string): string {
  return `others:${parent}`
}

export function pagerId(parent: string): string {
  return `page:${parent}`
}

/** An open branch with more quiet children than this shows this many at a time. */
export const PAGE_SIZE = 5

/** An open process shows at most this many children before the quiet ones fold away. */
export const MAX_CHILDREN = 6

/**
 * The processes that matter for the first view: the focus, every process with alerts, and
 * every process above them. Their siblings are the ones that fold into "other processes".
 */
export function importantNodes(data: Pick<Storyline, 'nodes' | 'edges'>): Set<string> {
  const parentOf = new Map<string, string>()
  for (const e of data.edges) if (isTreeEdge(e) && e.from !== e.to && !parentOf.has(e.to)) parentOf.set(e.to, e.from)
  const keep = new Set<string>()
  for (const n of data.nodes) {
    if (!n.focus && n.alert_count === 0) continue
    for (let cur: string | undefined = n.entity_id; cur && !keep.has(cur); cur = parentOf.get(cur)) keep.add(cur)
  }
  return keep
}

/**
 * Folds processes to keep the graph readable:
 * - when `keep` is given and a process shows more than MAX_CHILDREN children, the
 *   children outside `keep` (no alert or focus below them) become one "other processes"
 *   item;
 * - more than GROUP_THRESHOLD remaining siblings sharing a name (and a parent) become one
 *   item. Only leaf processes without alerts that are not the focus or root are grouped.
 * Groups listed in `expanded` are left as individual nodes.
 */
export function groupSiblings(
  data: GraphData,
  expanded: ReadonlySet<string> = new Set(),
  keep?: ReadonlySet<string>,
): { items: GraphItem[]; edges: StorylineEdge[] } {
  const hasOut = new Set(data.edges.map((e) => e.from))
  const crossIn = new Set(data.edges.filter((e) => e.kind !== 'parent').map((e) => e.to))
  const byId = new Map(data.nodes.map((n) => [n.entity_id, n]))
  const memberOf = new Map<string, string>()
  const groups = new Map<string, StorylineNode[]>()
  const others = new Set<string>()

  if (keep) {
    const kidsOf = new Map<string, StorylineNode[]>()
    for (const e of data.edges) {
      const n = byId.get(e.to)
      if (!n || !isTreeEdge(e) || e.from === e.to) continue
      const list = kidsOf.get(e.from)
      if (list) {
        if (!list.includes(n)) list.push(n)
      } else kidsOf.set(e.from, [n])
    }
    for (const [parent, list] of kidsOf) {
      const key = othersId(parent)
      if (list.length <= MAX_CHILDREN || expanded.has(key)) continue
      const quiet = list.filter((n) => !keep.has(n.entity_id) && !n.focus && !n.root && n.alert_count === 0 && !crossIn.has(n.entity_id))
      if (quiet.length < 2) continue
      groups.set(key, quiet)
      others.add(key)
      for (const m of quiet) memberOf.set(m.entity_id, key)
    }
  }

  const buckets = new Map<string, StorylineNode[]>()
  for (const n of data.nodes) {
    if (memberOf.has(n.entity_id)) continue
    if (n.alert_count > 0 || n.focus || n.root || !n.parent_entity_id) continue
    if (hasOut.has(n.entity_id) || crossIn.has(n.entity_id)) continue
    const key = groupId(n.parent_entity_id, n.name)
    buckets.set(key, [...(buckets.get(key) ?? []), n])
  }
  for (const [key, list] of buckets) {
    if (list.length > GROUP_THRESHOLD && !expanded.has(key)) {
      groups.set(key, list)
      for (const m of list) memberOf.set(m.entity_id, key)
    }
  }

  const items: GraphItem[] = []
  const emitted = new Set<string>()
  for (const n of data.nodes) {
    const g = memberOf.get(n.entity_id)
    if (!g) {
      items.push({ id: n.entity_id, node: n })
    } else if (!emitted.has(g)) {
      emitted.add(g)
      const members = groups.get(g) as StorylineNode[]
      items.push({ id: g, node: members[0], members, ...(others.has(g) ? { others: true } : {}) })
    }
  }
  const seen = new Set<string>()
  const edges: StorylineEdge[] = []
  for (const e of data.edges) {
    const from = memberOf.get(e.from) ?? e.from
    const to = memberOf.get(e.to) ?? e.to
    // Edges inside a group (a member's child folded into the same group) disappear.
    if (from === to && e.from !== e.to) continue
    const key = `${from}|${to}|${e.kind}`
    if (seen.has(key)) continue
    seen.add(key)
    edges.push({ ...e, from, to })
  }
  return { items, edges }
}

export interface ElkInput {
  id: string
  layoutOptions: Record<string, string>
  children: { id: string; width: number; height: number }[]
  edges: { id: string; sources: string[]; targets: string[]; layoutOptions?: Record<string, string> }[]
}

/** The graph handed to ELK: layered, left to right, orthogonal routing for parent edges. */
export function buildElkGraph(items: GraphItem[], edges: StorylineEdge[]): ElkInput {
  const ids = new Set(items.map((i) => i.id))
  return {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      // Keep the order of the items, so a "+" item stays beneath the list it extends.
      'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
      'elk.direction': 'RIGHT',
      'elk.edgeRouting': 'ORTHOGONAL',
      'elk.spacing.nodeNode': '28',
      'elk.layered.spacing.nodeNodeBetweenLayers': '70',
      'elk.layered.spacing.edgeNodeBetweenLayers': '24',
    },
    children: items.map((i) => ({ id: i.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: edges
      .filter((e) => ids.has(e.from) && ids.has(e.to) && e.from !== e.to)
      .map((e, idx) => ({
        id: `e${idx}`,
        sources: [e.from],
        targets: [e.to],
        layoutOptions: e.kind === 'parent' ? { 'elk.edgeRouting': 'ORTHOGONAL' } : { 'elk.edgeRouting': 'SPLINES' },
      })),
  }
}

// Opening and closing branches -----------------------------------------------------------

/** Edge kinds that make up the branches a click opens: parent links and launches. */
const TREE_KINDS: ReadonlySet<StorylineEdgeKind> = new Set<StorylineEdgeKind>(['parent', 'scheduled_task', 'service', 'wmi'])

export function isTreeEdge(e: Pick<StorylineEdge, 'kind'>): boolean {
  return TREE_KINDS.has(e.kind)
}

function treeChildren(edges: StorylineEdge[]): Map<string, string[]> {
  const out = new Map<string, string[]>()
  for (const e of edges) {
    if (!isTreeEdge(e) || e.from === e.to) continue
    const list = out.get(e.from)
    if (list) {
      if (!list.includes(e.to)) list.push(e.to)
    } else out.set(e.from, [e.to])
  }
  return out
}

/**
 * The branches open at first: the context process, the root, and every process on the
 * way from the root down to the focus, so the focus is on screen and everything else
 * starts closed.
 */
export function initialOpen(data: Pick<Storyline, 'nodes' | 'edges' | 'focus_entity_id'>): Set<string> {
  const open = new Set<string>()
  for (const n of data.nodes) if (n.context || n.root) open.add(n.entity_id)
  const parentOf = new Map<string, string>()
  for (const e of data.edges) if (isTreeEdge(e) && e.from !== e.to && !parentOf.has(e.to)) parentOf.set(e.to, e.from)
  const seen = new Set<string>([data.focus_entity_id])
  for (let cur = parentOf.get(data.focus_entity_id); cur && !seen.has(cur); cur = parentOf.get(cur)) {
    seen.add(cur)
    open.add(cur)
  }
  return open
}

export interface CollapsedGraph extends GraphData {
  /** Per shown process, how many loaded processes are hidden below it (closed branch). */
  hidden: Map<string, number>
  /** Per open process, how many quiet children are held back for the "+" item. */
  paged: Map<string, number>
}

/**
 * Paging of big branches: an open process with more than MAX_CHILDREN children shows its
 * important children (focus, alerts, anything leading to them, cross-process links) and
 * PAGE_SIZE quiet ones, plus PAGE_SIZE for each click on its "+" item (`more`).
 */
export interface PageOptions {
  keep: ReadonlySet<string>
  more: ReadonlyMap<string, number>
}

/**
 * Keeps the processes reachable from the top of the storyline through open branches.
 * A process reached only through a cross-process event (outside) is shown when the
 * process it is linked to is.
 */
export function collapsedView(data: GraphData, open: ReadonlySet<string>, page?: PageOptions): CollapsedGraph {
  const kids = treeChildren(data.edges)
  const byId = new Map(data.nodes.map((n) => [n.entity_id, n]))
  const hasParent = new Set<string>()
  for (const list of kids.values()) for (const k of list) hasParent.add(k)
  const crossIn = new Set(data.edges.filter((e) => !isTreeEdge(e)).map((e) => e.to))
  const quiet = (id: string) => {
    const n = byId.get(id)
    return !!n && !page?.keep.has(id) && !n.focus && !n.root && n.alert_count === 0 && !crossIn.has(id)
  }
  const paged = new Map<string, number>()
  const visible = new Set<string>()
  const stack = data.nodes.filter((n) => !n.outside && !hasParent.has(n.entity_id)).map((n) => n.entity_id)
  while (stack.length) {
    const id = stack.pop() as string
    if (visible.has(id)) continue
    visible.add(id)
    if (!open.has(id)) continue
    let list = (kids.get(id) ?? []).filter((k) => byId.has(k))
    if (page && list.length > MAX_CHILDREN) {
      const q = list.filter(quiet)
      const limit = PAGE_SIZE + (page.more.get(id) ?? 0)
      // A single child left over would only swap for the "+" item.
      if (q.length - limit >= 2) {
        const allow = new Set(q.slice(0, limit))
        list = list.filter((k) => !quiet(k) || allow.has(k))
        paged.set(id, q.length - limit)
      }
    }
    for (const k of list) stack.push(k)
  }
  for (const e of data.edges) {
    if (isTreeEdge(e)) continue
    if (visible.has(e.from) && byId.get(e.to)?.outside) visible.add(e.to)
    if (visible.has(e.to) && byId.get(e.from)?.outside) visible.add(e.from)
  }
  const hidden = new Map<string, number>()
  for (const id of visible) {
    if (open.has(id)) continue
    const seen = new Set<string>()
    const walk = [...(kids.get(id) ?? [])]
    while (walk.length) {
      const k = walk.pop() as string
      if (seen.has(k) || visible.has(k) || !byId.has(k)) continue
      seen.add(k)
      walk.push(...(kids.get(k) ?? []))
    }
    if (seen.size > 0) hidden.set(id, seen.size)
  }
  const nodes = data.nodes.filter((n) => visible.has(n.entity_id))
  return { nodes, edges: pruneEdges(nodes, data.edges), hidden, paged }
}

/** True when the process has loaded children (open or closed). */
export function hasLoadedChildren(data: GraphData, id: string): boolean {
  return data.edges.some((e) => isTreeEdge(e) && e.from === id && e.to !== id)
}

/**
 * Adds a storyline fetched with another process as its focus (its deeper branches) to
 * the one on screen. Processes already shown keep their flags; "more" is cleared on any
 * process the new storyline looked up.
 */
export function mergeStoryline(base: Storyline, add: Storyline): Storyline {
  const byId = new Map(base.nodes.map((n) => [n.entity_id, n]))
  const nodes = base.nodes.map((n) => {
    const other = add.nodes.find((m) => m.entity_id === n.entity_id)
    return other && n.more && !other.more ? { ...n, more: false } : n
  })
  for (const n of add.nodes) {
    if (!byId.has(n.entity_id)) nodes.push({ ...n, focus: false, root: false, context: false })
  }
  const key = (e: StorylineEdge) => `${e.from}|${e.to}|${e.kind}`
  const edgeKeys = new Set(base.edges.map(key))
  const edges = [...base.edges, ...add.edges.filter((e) => !edgeKeys.has(key(e)))]
  const alertIds = new Set(base.alerts.map((a) => a.id))
  const alerts = [...base.alerts, ...add.alerts.filter((a) => !alertIds.has(a.id))]
  return { ...base, nodes, edges, alerts, truncated: base.truncated || add.truncated }
}
