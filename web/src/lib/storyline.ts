// Pure helpers for the Storyline graph page: view filtering, sibling grouping, tactic
// list and the input handed to the ELK layered layout.

import type { Storyline, StorylineEdge, StorylineNode } from '../api/types'

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
}

export function groupId(parent: string, name: string): string {
  return `group:${parent}:${name}`
}

/**
 * Collapses more than GROUP_THRESHOLD siblings sharing a name (and a parent) into one item.
 * Only leaf processes without alerts that are not the focus or root are grouped, and
 * groups listed in `expanded` are left as individual nodes.
 */
export function groupSiblings(data: GraphData, expanded: ReadonlySet<string> = new Set()): { items: GraphItem[]; edges: StorylineEdge[] } {
  const hasOut = new Set(data.edges.map((e) => e.from))
  const crossIn = new Set(data.edges.filter((e) => e.kind !== 'parent').map((e) => e.to))
  const buckets = new Map<string, StorylineNode[]>()
  for (const n of data.nodes) {
    if (n.alert_count > 0 || n.focus || n.root || !n.parent_entity_id) continue
    if (hasOut.has(n.entity_id) || crossIn.has(n.entity_id)) continue
    const key = groupId(n.parent_entity_id, n.name)
    buckets.set(key, [...(buckets.get(key) ?? []), n])
  }
  const memberOf = new Map<string, string>()
  const groups = new Map<string, StorylineNode[]>()
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
      items.push({ id: g, node: members[0], members })
    }
  }
  const seen = new Set<string>()
  const edges: StorylineEdge[] = []
  for (const e of data.edges) {
    const from = memberOf.get(e.from) ?? e.from
    const to = memberOf.get(e.to) ?? e.to
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
