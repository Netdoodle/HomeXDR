import { afterEach, describe, expect, it, vi } from 'vitest'
import { uuid } from './uuid'

const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

describe('uuid', () => {
  afterEach(() => vi.restoreAllMocks())

  it('returns a v4 UUID', () => {
    expect(uuid()).toMatch(V4)
  })

  it('works without crypto.randomUUID (plain HTTP pages)', () => {
    vi.spyOn(crypto, 'randomUUID').mockImplementation(() => {
      throw new TypeError('crypto.randomUUID is not a function')
    })
    const seen = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const id = uuid()
      expect(id).toMatch(V4)
      seen.add(id)
    }
    expect(seen.size).toBe(200)
  })
})
