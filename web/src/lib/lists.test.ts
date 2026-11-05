import { describe, expect, it } from 'vitest'
import { factPhrases } from './lists'

describe('factPhrases', () => {
  it('says nothing when nothing is known', () => {
    expect(factPhrases()).toEqual([])
    expect(factPhrases(null)).toEqual([])
    expect(factPhrases({})).toEqual([])
    expect(factPhrases({ domain: {} })).toEqual([])
  })

  it('describes a domain', () => {
    expect(factPhrases({ domain: { registered: 'example.co.uk', rank: 1234, category: 'advertising', newly_registered: true } })).toEqual([
      'Popular site, rank 1,234',
      'Category: advertising',
      'Newly registered',
      'Registered domain example.co.uk',
    ])
  })

  it('describes an IP address', () => {
    expect(factPhrases({ ip: { asn: 13335, as_name: 'CLOUDFLARENET', country: 'US' } })).toEqual(['AS13335 CLOUDFLARENET', 'US'])
  })

  it('describes a MAC address', () => {
    expect(factPhrases({ mac: { vendor: 'Cisco Systems, Inc' } })).toEqual(['Made by Cisco Systems, Inc'])
    expect(factPhrases({ mac: { randomized: true } })).toEqual(['Randomized MAC address, as phones use for privacy'])
  })
})
