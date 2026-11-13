import { describe, expect, it } from 'vitest'
import { SETTINGS, choiceLabel, isWeaker, type GroupPolicy } from '../api/groups'

describe('Defender hardening group setting', () => {
  const def = SETTINGS.find((d) => d.key === 'defender_hardening')!

  it('orders choices strongest first', () => {
    expect(def.choices.map((c) => c.value)).toEqual(['enforce', 'audit', 'off'])
    expect(isWeaker(def, 'audit', 'enforce')).toBe(true)
    expect(isWeaker(def, 'off', 'audit')).toBe(true)
    expect(isWeaker(def, 'enforce', 'off')).toBe(false)
    expect(choiceLabel(def, 'audit')).toBe('Audit')
  })

  it('reads and writes the group policy', () => {
    const p: GroupPolicy = { av: { yara: false } }
    const set = def.set(p, 'audit')
    expect(set.av).toEqual({ yara: false, defender_hardening: 'audit' })
    expect(def.get(set)).toBe('audit')
    expect(def.get(def.set(set, undefined))).toBeUndefined()
    expect(def.weaker('Office')).toMatch(/Defender/)
  })
})
