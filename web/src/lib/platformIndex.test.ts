import { describe, expect, it } from 'vitest'
import { placeHref, searchPlaces } from './platformIndex'

describe('searchPlaces', () => {
  it('finds every suppressions window', () => {
    const r = searchPlaces('Suppressions', true, 20).map((p) => p.crumbs.join(' > '))
    expect(r[0]).toBe('Settings > Suppressions')
    expect(r).toContain('Settings > Suppressions > Must alert')
    expect(r).toContain('Alerts > Top repeating')
    expect(r).toContain('Settings > Maintenance')
  })
  it('jumps to a section', () => {
    const [p] = searchPlaces('Inactive agents', true)
    expect(p.crumbs).toEqual(['Settings', 'Agent updates', 'Inactive agents'])
    expect(placeHref(p)).toBe('/settings/agents#inactive-agents')
  })
  it('matches a tab name', () => {
    expect(searchPlaces('integrations', false)[0].crumbs).toEqual(['Settings', 'Integrations'])
  })
  it('hides admin places from other roles', () => {
    expect(searchPlaces('inactive agents', false)).toHaveLength(0)
  })
  it('needs two characters', () => {
    expect(searchPlaces('s', true)).toHaveLength(0)
  })
})
