import { describe, expect, it } from 'vitest'
import { buckets, pickSpan, runPipeline } from './pipeline'

const t0 = Date.parse('2026-10-20T10:00:00Z')
const ev = (min: number, action: string, port: number, size: number) => ({
  '@timestamp': new Date(t0 + min * 60_000).toISOString(),
  event: { module: 'opnsense', action, category: ['network'] },
  destination: { port },
  host: { name: action === 'block' ? 'fw' : 'web' },
  data: { size },
})
const events = [ev(50, 'pass', 53, 50), ev(40, 'pass', 443, 4000), ev(30, 'block', 443, 300), ev(20, 'block', 22, 200), ev(10, 'block', 22, 100)]
const range = { from: t0, to: t0 + 3_600_000 }

describe('mock pipeline', () => {
  it('runs stats with aggregations and sorts by the by-fields', () => {
    const r = runPipeline(events, '| stats count, sum(size) as total, dc(dest_port) by action', range)
    expect(r.mode).toBe('table')
    expect(r.columns?.map((c) => c.name)).toEqual(['action', 'count', 'total', 'dc(dest_port)'])
    expect(r.rows).toEqual([
      ['block', 3, 600, 2],
      ['pass', 2, 4050, 2],
    ])
  })

  it('runs top, sort, head and table', () => {
    expect(runPipeline(events, '| top limit=1 dest_port', range).rows).toEqual([[22, 2, 40]])
    expect(runPipeline(events, '| sort -size | head 2 | table host, size', range).rows).toEqual([
      ['web', 4000],
      ['fw', 300],
    ])
  })

  it('keeps events for event-only commands', () => {
    const r = runPipeline(events, '| dedup action', range)
    expect(r.mode).toBe('events')
    expect(r.events).toHaveLength(2)
  })

  it('pivots timechart series and zero-fills buckets', () => {
    const r = runPipeline(events, '| timechart span=30m count by action', range)
    expect(r.chart).toBe('timechart')
    expect(r.columns?.map((c) => c.name)).toEqual(['_time', 'block', 'pass'])
    expect(r.rows).toEqual([
      ['2026-10-20T10:00:00.000Z', 2, 0],
      ['2026-10-20T10:30:00.000Z', 1, 2],
    ])
  })

  it('rejects commands it does not model', () => {
    expect(() => runPipeline(events, '| eval x = 1', range)).toThrow(/demo mode/)
  })

  it('picks spans and buckets like the server', () => {
    expect(pickSpan(3_600_000)).toBe(60)
    expect(pickSpan(24 * 3_600_000)).toBe(900)
    expect(buckets(t0 + 30_000, t0 + 180_000, 60)).toEqual([t0, t0 + 60_000, t0 + 120_000])
  })
})
