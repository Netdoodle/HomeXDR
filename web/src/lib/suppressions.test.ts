import { describe, expect, it } from 'vitest'
import type { Alert } from '../api/types'
import { EMPTY_SUPPRESS_FORM, expiryFields, filledConditions, formFromAlert, hasScope, isBroad, isExpired, specFromForm } from './suppressions'

const alert = {
  id: 'a1',
  host_id: 'h1',
  hostname: 'tower',
  process_name: 'wget',
  rule: { id: 'r1', title: 'Wget to tmp', level: 'medium', tags: [] },
  event: { process: { name: 'wget', executable: '/usr/bin/wget', parent: { name: 'php', executable: '/usr/bin/php' } } },
} as unknown as Alert

describe('formFromAlert', () => {
  it('suggests the rule, host, process and parent', () => {
    const f = formFromAlert(alert)
    expect(f.ruleId).toBe('r1')
    expect(f.hostId).toBe('h1')
    expect(f.useHost).toBe(true)
    expect(f.conditions).toEqual([
      { field: 'process.executable', op: 'equals', value: '/usr/bin/wget' },
      { field: 'process.parent.executable', op: 'equals', value: '/usr/bin/php' },
    ])
  })

  it('falls back to names, and to nothing when there is no process', () => {
    const named = { ...alert, event: { process: { name: 'curl', parent: { name: 'cron' } } } } as unknown as Alert
    expect(formFromAlert(named).conditions).toEqual([
      { field: 'process.name', op: 'equals', value: 'curl' },
      { field: 'process.parent.name', op: 'equals', value: 'cron' },
    ])
    const none = { ...alert, process_name: undefined, event: {} } as unknown as Alert
    expect(formFromAlert(none).conditions).toEqual([])
  })
})

describe('spec helpers', () => {
  it('leaves out half-filled conditions', () => {
    expect(filledConditions([{ field: 'a', op: 'equals', value: ' ' }, { field: ' b ', op: 'contains', value: 'x' }])).toEqual([
      { field: 'b', op: 'contains', value: 'x' },
    ])
  })

  it('tells what scope the form has', () => {
    const empty = specFromForm({ ...EMPTY_SUPPRESS_FORM, useRule: false })
    expect(hasScope(empty)).toBe(false)
    const hostOnly = specFromForm({ ...EMPTY_SUPPRESS_FORM, useRule: false, useHost: true, hostId: 'h1' })
    expect(hasScope(hostOnly)).toBe(false)
    const ruleOnly = specFromForm({ ...EMPTY_SUPPRESS_FORM, ruleId: 'r1' })
    expect(hasScope(ruleOnly)).toBe(true)
    expect(isBroad(ruleOnly)).toBe(true)
    const ruleAndHost = specFromForm({ ...EMPTY_SUPPRESS_FORM, ruleId: 'r1', useHost: true, hostId: 'h1' })
    expect(isBroad(ruleAndHost)).toBe(false)
    expect(isBroad(specFromForm(formFromAlert(alert)))).toBe(false)
  })

  it('turns an expiry choice into API fields', () => {
    const now = Date.parse('2026-11-05T00:00:00Z')
    expect(expiryFields('never')).toEqual({ never_expires: true })
    expect(expiryFields('90', now).expires_at).toBe('2027-02-03T00:00:00.000Z')
    expect(isExpired({ expires_at: '2026-11-04T00:00:00Z' }, now)).toBe(true)
    expect(isExpired({ expires_at: '2026-11-06T00:00:00Z' }, now)).toBe(false)
    expect(isExpired({ expires_at: null }, now)).toBe(false)
  })
})
