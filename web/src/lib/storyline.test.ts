import { describe, expect, it } from 'vitest'
import type { StorylineEdge, StorylineNode } from '../api/types'
import { buildElkGraph, groupId, groupSiblings, isDimmed, processView, tacticLabel, tacticList, withoutCrossProcess } from './storyline'

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
