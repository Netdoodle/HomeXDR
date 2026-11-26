import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Host } from '../api/types'
import {
  FAVOURITES_KEY,
  filterEntries,
  isUnraid,
  menuEntries,
  pushRecent,
  readList,
  toggleFavourite,
  writeList,
  type MenuEntry,
} from './hostMenu'

const base: Host = {
  id: 'h1',
  hostname: 'srv',
  kind: 'endpoint',
  os: { platform: 'linux', name: 'Ubuntu' },
  ips: [],
  status: 'online',
  isolated: false,
  enrolled_at: '2025-01-01T00:00:00Z',
  labels: [],
  open_alerts: 0,
}
const host = (over: Partial<Host> = {}): Host => ({ ...base, ...over })
const ids = (es: MenuEntry[]) => es.map((e) => e.item.id)
const find = (es: MenuEntry[], id: string) => es.find((e) => e.item.id === id)

describe('menu availability', () => {
  it('shows every group to an admin on a Linux endpoint, without Defender', () => {
    const es = menuEntries(host(), 'admin')
    expect(ids(es)).toContain('remove')
    expect(ids(es)).toContain('reboot')
    expect(ids(es)).not.toContain('defender')
    expect(es.every((e) => e.availability.state === 'enabled' || e.item.id === 'update-now')).toBe(true)
  })

  it('offers Defender only on Windows', () => {
    expect(ids(menuEntries(host({ os: { platform: 'windows' } }), 'analyst'))).toContain('defender')
  })

  it('disables items above the role with a reason and hides Danger from non-admins', () => {
    const es = menuEntries(host(), 'analyst')
    expect(ids(es)).not.toContain('remove')
    const reboot = find(es, 'reboot')!
    expect(reboot.availability).toEqual({ state: 'disabled', reason: 'Needs the admin role' })
    expect(find(es, 'kill')!.availability.state).toBe('enabled')
    const viewer = menuEntries(host(), 'viewer')
    expect(find(viewer, 'kill')!.availability.state).toBe('disabled')
    expect(find(viewer, 'search')!.availability.state).toBe('enabled')
    expect(find(viewer, 'applications')!.availability.state).toBe('enabled')
  })

  it('gives network devices only search and remove', () => {
    expect(ids(menuEntries(host({ kind: 'network', os: { platform: 'network' } }), 'admin'))).toEqual(['search', 'remove'])
  })

  it('follows the agent policy', () => {
    const es = menuEntries(host({ allowed_actions: ['file.hash', 'file.quarantine'] }), 'admin')
    expect(find(es, 'hash')!.availability.state).toBe('enabled')
    expect(find(es, 'quarantine')!.availability.state).toBe('enabled') // one of its two commands is allowed
    const kill = find(es, 'kill')!.availability
    expect(kill.state === 'disabled' && kill.reason).toContain('local policy')
  })

  it('blocks commands to revoked and decommissioned agents but keeps Remove and Search', () => {
    const revoked = menuEntries(host({ status: 'revoked' }), 'admin')
    expect(find(revoked, 'reboot')!.availability.state).toBe('disabled')
    expect(find(revoked, 'revoke')!.availability.state).toBe('disabled')
    expect(find(revoked, 'remove')!.availability.state).toBe('enabled')
    expect(find(revoked, 'search')!.availability.state).toBe('enabled')
    const decom = menuEntries(host({ status: 'decommissioned' }), 'admin')
    expect(find(decom, 'agent-logs')!.availability.state).toBe('disabled')
    expect(find(decom, 'decommission')!.label).toMatch(/Restore/)
    expect(find(decom, 'decommission')!.availability.state).toBe('enabled')
  })

  it('labels Isolate and Release by state', () => {
    expect(find(menuEntries(host(), 'admin'), 'isolate')!.label).toBe('Isolate host')
    const es = menuEntries(host({ isolated: true }), 'admin')
    expect(find(es, 'isolate')!.label).toMatch(/Release/)
    expect(find(es, 'isolate')!.item.action(host({ isolated: true }))).toEqual({ kind: 'command', type: 'host.release' })
  })

  it('enables Update now only when an update is pending', () => {
    expect(find(menuEntries(host(), 'admin'), 'update-now')!.availability.state).toBe('disabled')
    const pending = host({ update: { state: 'behind' } as never })
    expect(find(menuEntries(pending, 'admin'), 'update-now')!.availability.state).toBe('enabled')
  })

  it('detects Unraid', () => {
    expect(isUnraid({ os: { platform: 'linux', name: 'Unraid OS', version: '7.1' } })).toBe(true)
    expect(isUnraid({ os: { platform: 'linux', name: 'Ubuntu' } })).toBe(false)
  })
})

describe('menu search', () => {
  const es = menuEntries(host(), 'admin')
  it('matches labels, sections and keywords, all words', () => {
    expect(ids(filterEntries(es, 'reb'))).toEqual(['reboot'])
    expect(ids(filterEntries(es, 'sha256'))).toEqual(['hash'])
    expect(ids(filterEntries(es, 'agent logs'))).toEqual(['agent-logs'])
    expect(ids(filterEntries(es, 'danger'))).toEqual(['remove'])
    expect(filterEntries(es, 'zzz')).toEqual([])
    expect(filterEntries(es, '  ')).toBe(es)
  })
})

describe('recent and favourites', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('keeps the last five, newest first, without duplicates', () => {
    let l: string[] = []
    for (const id of ['a', 'b', 'c', 'd', 'e', 'f', 'c']) l = pushRecent(l, id)
    expect(l).toEqual(['c', 'f', 'e', 'd', 'b'])
  })

  it('toggles favourites', () => {
    expect(toggleFavourite(['a'], 'b')).toEqual(['a', 'b'])
    expect(toggleFavourite(['a', 'b'], 'a')).toEqual(['b'])
  })

  it('survives storage that throws or holds junk', () => {
    const boom = () => {
      throw new Error('blocked')
    }
    vi.stubGlobal('localStorage', { getItem: boom, setItem: boom })
    expect(readList(FAVOURITES_KEY)).toEqual([])
    expect(() => writeList(FAVOURITES_KEY, ['a'])).not.toThrow()
    vi.stubGlobal('localStorage', { getItem: () => '{"x":1}', setItem: () => undefined })
    expect(readList(FAVOURITES_KEY)).toEqual([])
    vi.stubGlobal('localStorage', { getItem: () => '["a",3,"b"]', setItem: () => undefined })
    expect(readList(FAVOURITES_KEY)).toEqual(['a', 'b'])
  })
})
