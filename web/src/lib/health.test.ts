import { describe, expect, it } from 'vitest'
import type { FeedView } from '../api/health'
import { feedName, formatGap, sortFeeds } from './health'

const feed = (p: Partial<FeedView>): FeedView => ({
  host_id: 'h',
  hostname: 'tower',
  module: 'm',
  dataset: 'd',
  status: 'ok',
  arrivals: 0,
  usual_gap_sec: 0,
  allowance_sec: 0,
  silent_sec: 0,
  muted: false,
  expected: false,
  can_alert: false,
  ...p,
})

describe('feed helpers', () => {
  it('formats gaps in plain units', () => {
    expect(formatGap(0)).toBe('—')
    expect(formatGap(undefined)).toBe('—')
    expect(formatGap(30)).toBe('under a minute')
    expect(formatGap(720)).toBe('12 min')
    expect(formatGap(6 * 3600)).toBe('6 h')
    expect(formatGap(3 * 86400)).toBe('3 d')
  })

  it('sorts problems first', () => {
    const out = sortFeeds([feed({ dataset: 'a', status: 'muted' }), feed({ dataset: 'b', status: 'ok' }), feed({ dataset: 'c', status: 'silent' })])
    expect(out.map((f) => f.dataset)).toEqual(['c', 'b', 'a'])
  })

  it('names the row about a whole host', () => {
    expect(feedName({ module: '', dataset: '' })).toBe('Anything from this host')
    expect(feedName({ module: 'm', dataset: 'm.d' })).toBe('m.d')
  })
})
