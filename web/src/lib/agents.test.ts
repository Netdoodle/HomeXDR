import { describe, expect, it } from 'vitest'
import { canUpdateNow, certState, decommissionLabel, ruleLabel, shortVersion, timeZones } from './agents'

describe('agent lifecycle helpers', () => {
  it('shortens build versions to commit and date', () => {
    expect(shortVersion('0.0.0-20261021163411.88faa4a')).toBe('88faa4a (Oct 21, 2026)')
    expect(shortVersion('0.1.0')).toBe('0.1.0')
    expect(shortVersion(undefined)).toBe('')
  })

  it('describes rules', () => {
    expect(ruleLabel({ mode: 'n-1' })).toBe('N-1')
    expect(ruleLabel({ mode: 'pinned', version: '0.0.0-20261021163411.88faa4a' })).toBe('Pinned to 88faa4a (Oct 21, 2026)')
    expect(decommissionLabel(0)).toBe('Never')
    expect(decommissionLabel(30)).toBe('After 30 days offline')
  })

  it('offers update now only when an update is due', () => {
    const base = { rule: { mode: 'latest' as const }, source: 'default' }
    expect(canUpdateNow({ ...base, state: 'pending' })).toBe(true)
    expect(canUpdateNow({ ...base, state: 'off' })).toBe(true)
    expect(canUpdateNow({ ...base, state: 'current' })).toBe(false)
    expect(canUpdateNow({ ...base, state: 'ahead' })).toBe(false)
    expect(canUpdateNow(undefined)).toBe(false)
  })

  it('rates certificate expiry', () => {
    const now = Date.parse('2026-10-26T00:00:00Z')
    expect(certState('2027-10-20T00:00:00Z', now)?.level).toBe('ok')
    expect(certState('2026-11-10T00:00:00Z', now)?.level).toBe('warn')
    expect(certState('2026-10-01T00:00:00Z', now)).toMatchObject({ level: 'danger' })
    expect(certState(undefined, now)).toBeNull()
  })

  it('lists time zones with UTC included', () => {
    expect(timeZones()).toContain('UTC')
  })
})
