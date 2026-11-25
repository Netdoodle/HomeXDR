import { describe, expect, it } from 'vitest'
import type { StorylineEdge, StorylineNode } from '../api/types'
import { buildElkGraph, collapsedView, groupId, groupSiblings, hasLoadedChildren, importantNodes, initialOpen, isDimmed, mergeStoryline, othersId, PAGE_SIZE, processView, tacticLabel, tacticList, withoutCrossProcess } from './storyline'
import type { Storyline } from '../api/types'

function node(id: string, parent = '', extra: Partial<StorylineNode> = {}): StorylineNode {
  return {
    entity_id: id,
    pid: 1,
    name: `${id}.exe`,
    executable: '',
    command_line: '',
    user: '',
    start: null,
    end: null,
    exit_code: null,
    signed: null,
    integrity_level: '',
    parent_entity_id: parent,
    depth: 0,
    focus: false,
    root: false,
    context: false,
    outside: false,
    stub: false,
    alert_count: 0,
    max_severity: '',
    tactics: [],
    event_counts: { network: 0, file: 0, registry: 0, dns: 0, library: 0 },
    ...extra,
  }
}

const edge = (from: string, to: string, kind: StorylineEdge['kind'] = 'parent'): StorylineEdge => ({ from, to, kind, at: null, event_id: '', detail: '' })

describe('tactics', () => {
  it('prettifies slugs', () => {
    expect(tacticLabel('privilege-escalation')).toBe('Privilege Escalation')
    expect(tacticLabel('some-new-thing')).toBe('Some New Thing')
  })
  it('lists tactics present, sorted by label', () => {
    const nodes = [node('a', '', { tactics: ['persistence', 'defense-evasion'] }), node('b')]
    const alerts = [{ id: '1', title: '', severity: 'low' as const, status: 'new' as const, first_seen: '', last_seen: '', entity_id: 'b', tactics: ['persistence', 'execution'] }]
    expect(tacticList({ nodes, alerts }).map((t) => t.slug)).toEqual(['defense-evasion', 'execution', 'persistence'])
  })
  it('dims only when the selection is partial', () => {
    const all = ['persistence', 'execution']
    const n = node('a', '', { tactics: ['execution'] })
    expect(isDimmed(n, new Set(all), all)).toBe(false)
    expect(isDimmed(n, new Set(['persistence']), all)).toBe(true)
    expect(isDimmed(n, new Set(['execution']), all)).toBe(false)
    expect(isDimmed(n, new Set(), all)).toBe(true)
    expect(isDimmed(n, new Set(), [])).toBe(false)
  })
})

describe('views', () => {
  const nodes = [node('r'), node('a', 'r'), node('f', 'a'), node('c', 'f'), node('sib', 'a'), node('x')]
  const edges = [edge('r', 'a'), edge('a', 'f'), edge('f', 'c'), edge('a', 'sib'), edge('x', 'c', 'remote_thread')]
  it('process view keeps ancestors and descendants of the focus only', () => {
    const v = processView({ nodes, edges }, 'f')
    expect(v.nodes.map((n) => n.entity_id).sort()).toEqual(['a', 'c', 'f', 'r'])
    expect(v.edges.every((e) => e.kind === 'parent')).toBe(true)
    expect(v.edges).toHaveLength(3)
  })
  it('can drop cross-process edges', () => {
    expect(withoutCrossProcess({ nodes, edges }).edges).toHaveLength(4)
  })
})

describe('groupSiblings', () => {
  const kids = (n: number, extra: Partial<StorylineNode> = {}) => Array.from({ length: n }, (_, i) => node(`k${i}`, 'p', { name: 'conhost.exe', ...extra }))
  const parent = node('p', '', { root: true })
  const link = (ns: StorylineNode[]) => ns.map((k) => edge('p', k.entity_id))

  it('collapses more than five identical siblings', () => {
    const ks = kids(6)
    const { items, edges } = groupSiblings({ nodes: [parent, ...ks], edges: link(ks) })
    expect(items).toHaveLength(2)
    expect(items[1].id).toBe(groupId('p', 'conhost.exe'))
    expect(items[1].members).toHaveLength(6)
    expect(edges).toHaveLength(1)
    expect(edges[0].to).toBe(items[1].id)
  })
  it('keeps exactly five', () => {
    const ks = kids(5)
    expect(groupSiblings({ nodes: [parent, ...ks], edges: link(ks) }).items).toHaveLength(6)
  })
  it('does not group nodes with alerts', () => {
    const ks = kids(7, { alert_count: 1 })
    expect(groupSiblings({ nodes: [parent, ...ks], edges: link(ks) }).items).toHaveLength(8)
  })
  it('honours expanded groups', () => {
    const ks = kids(6)
    const r = groupSiblings({ nodes: [parent, ...ks], edges: link(ks) }, new Set([groupId('p', 'conhost.exe')]))
    expect(r.items).toHaveLength(7)
  })
})

describe('buildElkGraph', () => {
  it('builds a left-to-right layered graph and skips dangling edges', () => {
    const items = [node('a'), node('b')].map((n) => ({ id: n.entity_id, node: n }))
    const g = buildElkGraph(items, [edge('a', 'b'), edge('a', 'zzz')])
    expect(g.layoutOptions['elk.direction']).toBe('RIGHT')
    expect(g.layoutOptions['elk.edgeRouting']).toBe('ORTHOGONAL')
    expect(g.children).toHaveLength(2)
    expect(g.edges).toHaveLength(1)
  })
})

describe('opening and closing branches', () => {
  // ctx -> root -> a -> a1 -> focus ; root -> b -> b1 ; root -> t (task launch from b) ; a1 accesses out
  const nodes = [
    node('ctx', '', { context: true }),
    node('root', 'ctx', { root: true }),
    node('a', 'root'),
    node('a1', 'a'),
    node('focus', 'a1', { focus: true }),
    node('b', 'root'),
    node('b1', 'b'),
    node('t', 'svc'),
    node('out', '', { outside: true }),
  ]
  const edges = [
    edge('ctx', 'root'),
    edge('root', 'a'),
    edge('a', 'a1'),
    edge('a1', 'focus'),
    edge('root', 'b'),
    edge('b', 'b1'),
    edge('b', 't', 'scheduled_task'),
    edge('a1', 'out', 'process_access'),
  ]
  const data = { nodes, edges, focus_entity_id: 'focus' }

  it('starts with the root, its children and the path to the focus open', () => {
    const open = initialOpen(data)
    expect([...open].sort()).toEqual(['a', 'a1', 'ctx', 'root'])
    const v = collapsedView(data, open)
    expect(v.nodes.map((n) => n.entity_id).sort()).toEqual(['a', 'a1', 'b', 'ctx', 'focus', 'out', 'root'])
    // b is closed with b1 and the task-launched t below it.
    expect(v.hidden.get('b')).toBe(2)
    expect(v.hidden.has('a')).toBe(false)
  })

  it('opens and closes a branch', () => {
    const open = initialOpen(data)
    open.add('b')
    expect(collapsedView(data, open).nodes.map((n) => n.entity_id)).toContain('t')
    open.delete('a')
    const v = collapsedView(data, open)
    expect(v.nodes.map((n) => n.entity_id)).not.toContain('focus')
    // An outside process goes away with the process it is linked to.
    expect(v.nodes.map((n) => n.entity_id)).not.toContain('out')
    expect(v.hidden.get('a')).toBe(2)
  })

  it('knows which processes have loaded children', () => {
    expect(hasLoadedChildren({ nodes, edges }, 'b')).toBe(true)
    expect(hasLoadedChildren({ nodes, edges }, 'b1')).toBe(false)
    // A cross-process edge is not a child.
    expect(hasLoadedChildren({ nodes, edges: [edge('x', 'y', 'remote_thread')] }, 'x')).toBe(false)
  })

  it('merges a deeper branch loaded later', () => {
    const base: Storyline = {
      host_id: 'h', hostname: 'h', focus_entity_id: 'focus', root_entity_id: 'root', truncated: false,
      nodes: [node('root', '', { root: true }), node('b1', 'root', { more: true })],
      edges: [edge('root', 'b1')],
      alerts: [],
    }
    const add: Storyline = {
      ...base,
      focus_entity_id: 'b1',
      nodes: [node('root', '', { root: true }), node('b1', 'root', { focus: true, more: false }), node('c', 'b1', { more: true })],
      edges: [edge('root', 'b1'), edge('b1', 'c')],
      alerts: [{ id: 'al', title: '', severity: 'high', status: 'new', first_seen: '', last_seen: '', entity_id: 'c', tactics: [] }],
    }
    const m = mergeStoryline(base, add)
    expect(m.focus_entity_id).toBe('focus')
    expect(m.nodes.map((n) => n.entity_id)).toEqual(['root', 'b1', 'c'])
    expect(m.nodes.find((n) => n.entity_id === 'b1')).toMatchObject({ more: false, focus: false })
    expect(m.edges).toHaveLength(2)
    expect(m.alerts.map((a) => a.id)).toEqual(['al'])
  })
})

describe('folding quiet children', () => {
  // root has 10 children; c3 leads to the focus, c7 has an alert, the rest are quiet.
  const kids = Array.from({ length: 10 }, (_, i) => node(`c${i}`, 'root', { name: `tool${i}.exe` }))
  kids[7] = node('c7', 'root', { name: 'tool7.exe', alert_count: 1 })
  const nodes = [node('root', '', { root: true }), ...kids, node('focus', 'c3', { focus: true })]
  const edges = [...kids.map((k) => edge('root', k.entity_id)), edge('c3', 'focus')]

  it('keeps the way to the focus and to alerts', () => {
    expect([...importantNodes({ nodes, edges })].sort()).toEqual(['c3', 'c7', 'focus', 'root'])
  })

  it('folds the other children into one item', () => {
    const { items, edges: out } = groupSiblings({ nodes, edges }, new Set(), importantNodes({ nodes, edges }))
    const ids = items.map((i) => i.id)
    expect(ids).toEqual(['root', othersId('root'), 'c3', 'c7', 'focus'])
    const others = items.find((i) => i.others)
    expect(others?.members).toHaveLength(8)
    expect(out.filter((e) => e.from === 'root').map((e) => e.to).sort()).toEqual(['c3', 'c7', othersId('root')].sort())
  })

  it('shows them once the group is expanded, or without a keep set', () => {
    const keep = importantNodes({ nodes, edges })
    expect(groupSiblings({ nodes, edges }, new Set([othersId('root')]), keep).items).toHaveLength(12)
    expect(groupSiblings({ nodes, edges }).items).toHaveLength(12)
  })

  it('leaves a parent with few children alone', () => {
    const few = { nodes: nodes.slice(0, 4), edges: edges.slice(0, 3) }
    expect(groupSiblings(few, new Set(), new Set(['root'])).items.some((i) => i.others)).toBe(false)
  })
})

describe('collapsedView paging', () => {
  const kids = Array.from({ length: 20 }, (_, i) => `k${i}`)
  const data = {
    nodes: [node('r', '', { root: true }), ...kids.map((k) => node(k, 'r')), ...[node('a', 'r', { alert_count: 1 })]],
    edges: [...kids.map((k) => edge('r', k)), edge('r', 'a')],
  }
  const open = new Set(['r'])
  const keep = new Set(['r', 'a'])

  it('shows the alert child and one page of quiet children', () => {
    const v = collapsedView(data, open, { keep, more: new Map() })
    expect(v.nodes.map((n) => n.entity_id).sort()).toEqual(['a', 'k0', 'k1', 'k2', 'k3', 'k4', 'r'])
    expect(v.paged.get('r')).toBe(20 - PAGE_SIZE)
  })

  it('shows another page per click and stops when little is left', () => {
    const v = collapsedView(data, open, { keep, more: new Map([['r', 10]]) })
    expect(v.nodes.length).toBe(1 + 1 + 15)
    expect(v.paged.get('r')).toBe(5)
    const all = collapsedView(data, open, { keep, more: new Map([['r', 15]]) })
    expect(all.nodes.length).toBe(22)
    expect(all.paged.size).toBe(0)
  })

  it('shows everything without paging options', () => {
    expect(collapsedView(data, open).nodes.length).toBe(22)
  })
})
