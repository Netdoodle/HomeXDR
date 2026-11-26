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

describe('Decoy files group setting', () => {
  const def = SETTINGS.find((d) => d.key === 'decoys')!

  it('is an inherited on/off switch', () => {
    expect(def.label).toBe('Decoy files')
    expect(def.choices.map((c) => c.value)).toEqual(['on', 'off'])
    expect(isWeaker(def, 'off', 'on')).toBe(true)
    const p: GroupPolicy = { av: {} }
    expect(def.get(p)).toBeUndefined()
    const off = def.set(p, 'off')
    expect(off.decoys).toEqual({ enabled: false })
    expect(def.get(off)).toBe('off')
    expect(def.get(def.set(off, undefined))).toBeUndefined()
    expect(def.weaker('Office')).toBe('will have their decoy files removed (unchanged ones) and no longer raise decoy alerts')
  })
})

describe('Sysmon events group setting', () => {
  const def = SETTINGS.find((d) => d.key === 'sysmon')!

  it('is an inherited on/off switch', () => {
    expect(def.label).toBe('Sysmon events')
    expect(def.choices.map((c) => c.value)).toEqual(['on', 'off'])
    expect(isWeaker(def, 'off', 'on')).toBe(true)
    const p: GroupPolicy = { av: {} }
    expect(def.get(p)).toBeUndefined()
    const off = def.set(p, 'off')
    expect(off.sysmon).toEqual({ enabled: false })
    expect(off.decoys).toBeUndefined()
    expect(def.get(off)).toBe('off')
    expect(def.get(def.set(off, undefined))).toBeUndefined()
    expect(def.weaker('Office')).toMatch(/Sysmon/)
  })
})

describe('Vulnerability management group setting', () => {
  const def = SETTINGS.find((d) => d.key === 'vuln')!

  it('is an inherited on/off switch', () => {
    expect(def.label).toBe('Vulnerability management')
    expect(def.choices.map((c) => c.value)).toEqual(['on', 'off'])
    expect(isWeaker(def, 'off', 'on')).toBe(true)
    const p: GroupPolicy = { av: {} }
    expect(def.get(p)).toBeUndefined()
    const off = def.set(p, 'off')
    expect(off.vuln).toEqual({ enabled: false })
    expect(off.sysmon).toBeUndefined()
    expect(def.get(off)).toBe('off')
    expect(def.get(def.set(off, undefined))).toBeUndefined()
    expect(def.weaker('Red Team')).toMatch(/Vulnerabilities pages/)
  })
})
