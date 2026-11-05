import { describe, expect, it } from 'vitest'
import type { DetectorSettings, Device } from '../api/network'
import { addressSearchHref, behaviorUpdate, deviceName, filterDevices, ipSortKey, parseLines, sortDevices } from './network'

const dev = (p: Partial<Device>): Device => ({
  id: p.id ?? 'x',
  ips: p.ip ? [{ ip: p.ip, first_seen: '', last_seen: '' }] : [],
  sources: [],
  known: false,
  new: false,
  first_seen: '2026-11-01T00:00:00Z',
  last_seen: '2026-11-05T00:00:00Z',
  ...p,
})

describe('device list', () => {
  const list = [
    dev({ id: 'a', ip: '192.168.20.10', hostname: 'printer', vendor: 'Brother', known: true, last_seen: '2026-11-05T01:00:00Z', first_seen: '2026-11-01T00:00:00Z' }),
    dev({ id: 'b', ip: '192.168.20.9', name: 'Kitchen cam', mac: 'aa:bb:cc:dd:ee:ff', new: true, last_seen: '2026-11-05T03:00:00Z', first_seen: '2026-11-04T00:00:00Z' }),
    dev({ id: 'ip:192.168.10.5', ip: '192.168.10.5', last_seen: '2026-11-05T02:00:00Z', first_seen: '2026-11-02T00:00:00Z' }),
  ]

  it('names a device by the best name it has', () => {
    expect(deviceName(list[1])).toBe('Kitchen cam')
    expect(deviceName(list[0])).toBe('printer')
    expect(deviceName(list[2])).toBe('192.168.10.5')
    expect(deviceName(dev({ id: 'z', host_name: 'tower' }))).toBe('tower')
  })

  it('searches every field, all words', () => {
    expect(filterDevices(list, 'brother', '').map((d) => d.id)).toEqual(['a'])
    expect(filterDevices(list, 'AA:BB', '').map((d) => d.id)).toEqual(['b'])
    expect(filterDevices(list, '192.168.20', '').length).toBe(2)
    expect(filterDevices(list, '192.168.20 cam', '').map((d) => d.id)).toEqual(['b'])
    expect(filterDevices(list, 'nothing', '')).toEqual([])
  })

  it('filters new and known', () => {
    expect(filterDevices(list, '', 'new').map((d) => d.id)).toEqual(['b'])
    expect(filterDevices(list, '', 'known').map((d) => d.id)).toEqual(['a'])
    expect(filterDevices(list, '', 'unknown').length).toBe(2)
  })

  it('sorts without changing the original', () => {
    expect(sortDevices(list, 'last_seen').map((d) => d.id)).toEqual(['b', 'ip:192.168.10.5', 'a'])
    expect(sortDevices(list, 'first_seen')[0].id).toBe('b')
    expect(sortDevices(list, 'name').map((d) => d.id)).toEqual(['ip:192.168.10.5', 'b', 'a'])
    expect(sortDevices(list, 'ip').map((d) => d.id)).toEqual(['ip:192.168.10.5', 'b', 'a'])
    expect(list[0].id).toBe('a')
  })

  it('sorts addresses by number and missing ones last', () => {
    expect(ipSortKey('192.168.20.9') < ipSortKey('192.168.20.10')).toBe(true)
    expect(ipSortKey('192.168.20.9') < ipSortKey(undefined)).toBe(true)
    expect(ipSortKey('fd00::1') < ipSortKey(undefined)).toBe(true)
  })

  it('links to a search for the address', () => {
    expect(decodeURIComponent(addressSearchHref('192.168.20.9'))).toBe('/search?q=source.ip:"192.168.20.9" OR destination.ip:"192.168.20.9"')
  })
})

describe('settings', () => {
  it('reads entries from lines or commas', () => {
    expect(parseLines(' 192.168.20.0/24\n\n192.168.10.0/24, 10.0.0.0/8 ')).toEqual(['192.168.20.0/24', '192.168.10.0/24', '10.0.0.0/8'])
    expect(parseLines('  ')).toEqual([])
  })

  it('sends only what differs from the defaults', () => {
    const d = (p: Partial<DetectorSettings>): DetectorSettings => ({
      id: 'x',
      title: '',
      about: '',
      enabled: true,
      values: { a: 1, b: 2 },
      lists: { l: [] },
      thresholds: [
        { key: 'a', label: '', help: '', default: 1, min: 0, max: 9 },
        { key: 'b', label: '', help: '', default: 2, min: 0, max: 9 },
      ],
      list_defs: [{ key: 'l', label: '', help: '', kind: 'ip' }],
      ...p,
    })
    expect(behaviorUpdate([d({})])).toEqual({ detectors: { x: {} } })
    expect(behaviorUpdate([d({ enabled: false, values: { a: 1, b: 5 }, lists: { l: ['1.1.1.1'] } })])).toEqual({
      detectors: { x: { enabled: false, values: { b: 5 }, lists: { l: ['1.1.1.1'] } } },
    })
  })
})
