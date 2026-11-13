import { describe, expect, it } from 'vitest'
import type { Event, IntelResult } from '../api/types'
import { coverageLine, eventIndicators, flagEmoji, indicatorInField, investigateHref, investigateTargets, sortedResults, worldDotsPath, worldPoint } from './intel'

describe('indicators in event fields', () => {
  it('offers network indicators', () => {
    expect(indicatorInField('destination.ip', '8.8.8.8')).toBe('8.8.8.8')
    expect(indicatorInField('source.ip', '2606:4700::1111')).toBe('2606:4700::1111')
    expect(indicatorInField('destination.domain', 'evil.example.com')).toBe('evil.example.com')
    expect(indicatorInField('dns.question.name', 'evil.example.com')).toBe('evil.example.com')
    expect(indicatorInField('tls.server_name', 'evil.example.com')).toBe('evil.example.com')
    expect(indicatorInField('http.url', 'https://evil.example.com/a')).toBe('https://evil.example.com/a')
  })

  it('offers hashes only in hash fields', () => {
    const sha = 'a'.repeat(64)
    expect(indicatorInField('process.hash.sha256', sha)).toBe(sha)
    expect(indicatorInField('file.hash.md5', 'b'.repeat(32))).toBe('b'.repeat(32))
    expect(indicatorInField('id', sha)).toBeNull()
    expect(indicatorInField('process.hash.sha256', 'nothex')).toBeNull()
  })

  it('leaves out values that only look like indicators', () => {
    expect(indicatorInField('process.name', 'notepad.exe')).toBeNull()
    expect(indicatorInField('file.path', 'report.pdf')).toBeNull()
    expect(indicatorInField('host.name', 'tower.lan')).toBeNull()
    expect(indicatorInField('host.ip', '192.168.1.5')).toBeNull()
    expect(indicatorInField('message', 'hello world')).toBeNull()
    expect(indicatorInField('destination.port', 443)).toBeNull()
    expect(indicatorInField('network.community_id', '1:abc:def')).toBeNull()
  })

  it('links to the page with the indicator escaped', () => {
    expect(investigateHref('https://a.example/x?y=1')).toBe('/investigate?q=https%3A%2F%2Fa.example%2Fx%3Fy%3D1')
  })
})

describe('lookup display', () => {
  const r = (name: string, state: IntelResult['state'], risk?: number) => ({ source: name, name, state, risk, checked_at: '' }) as IntelResult

  it('puts the most concerning sources first and context last', () => {
    const out = sortedResults([r('geo', 'ok'), r('low', 'ok', 5), r('none', 'no_data'), r('high', 'ok', 90), r('zero', 'ok', 0)])
    expect(out.map((x) => x.name)).toEqual(['high', 'low', 'zero', 'geo'])
  })

  it('describes coverage', () => {
    expect(coverageLine({ checked: 8, with_data: 7, no_data: 1, failed: 0, needs_key: 4, pending: 0 })).toBe('Checked 8 sources: 7 with data, 1 with nothing. 4 more need an API key.')
    expect(coverageLine({ checked: 1, with_data: 0, no_data: 0, failed: 1, needs_key: 1, pending: 2 })).toBe(
      'Checking 2 more… Checked 1 source: 0 with data, 0 with nothing, 1 failed. 1 more needs an API key.',
    )
  })

  it('places coordinates on the map', () => {
    const { width, height, path } = worldDotsPath()
    expect(path.startsWith('M')).toBe(true)
    expect(worldPoint(84, -180)).toEqual({ x: 0, y: 0 })
    expect(worldPoint(-58, 180)).toEqual({ x: width, y: height })
    expect(worldPoint(-90, 0).y).toBe(height) // Antarctica clamps to the bottom edge
  })

  it('makes flags from country codes', () => {
    expect(flagEmoji('us')).toBe('🇺🇸')
    expect(flagEmoji('')).toBe('')
    expect(flagEmoji('USA')).toBe('')
  })
})

describe('indicators in an alert', () => {
  it('lists public addresses, domains and hashes, once each', () => {
    const sha = 'd'.repeat(64)
    const e = {
      source: { ip: '192.168.1.5' },
      destination: { ip: '8.8.8.8', domain: 'evil.example.com' },
      dns: { question: { name: 'evil.example.com' } },
      process: { hash: { sha256: sha } },
      file: { hash: { sha256: sha } },
    } as unknown as Event
    expect(eventIndicators(e)).toEqual([
      { label: 'Destination IP', value: '8.8.8.8' },
      { label: 'Domain', value: 'evil.example.com' },
      { label: 'Process SHA-256', value: sha },
    ])
    expect(eventIndicators(undefined)).toEqual([])
  })

  it('keeps private addresses out', () => {
    for (const ip of ['10.0.0.1', '127.0.0.1', '172.16.0.1', '172.31.255.1', '192.168.0.1', '169.254.1.1', '100.64.0.1', 'fe80::1', 'fd00::1', '::1']) {
      expect(eventIndicators({ destination: { ip } } as unknown as Event)).toEqual([])
    }
    expect(eventIndicators({ destination: { ip: '172.32.0.1' } } as unknown as Event)).toHaveLength(1)
  })
})

describe('investigateTargets', () => {
  it('lists addresses, hashes and the host, marking private ones', () => {
    const t = investigateTargets({
      id: 'x',
      '@timestamp': '2026-11-12T09:03:27Z',
      source: { ip: '192.168.20.178' },
      destination: { ip: '8.219.91.229', domain: 'example.org' },
      process: { name: 'md5sum', hash: { sha256: 'a'.repeat(64), md5: 'b'.repeat(32) } },
      host: { name: 'Tower2', ip: ['127.0.0.1', '172.17.0.1', '192.168.20.20'] },
    } as never)
    expect(t.map((x) => [x.label, x.value, !!x.local])).toEqual([
      ['Source', '192.168.20.178', true],
      ['Destination', '8.219.91.229', false],
      ['Domain', 'example.org', false],
      ['Process SHA-256', 'a'.repeat(64), false],
      ['Process MD5', 'b'.repeat(32), false],
      ['Host Tower2', '192.168.20.20', true],
    ])
    // Source and destination addresses can be blocked; the host's own address cannot.
    expect(t.filter((x) => x.ip).map((x) => x.value)).toEqual(['192.168.20.178', '8.219.91.229'])
  })
  it('skips values that are not indicators', () => {
    expect(investigateTargets({ id: 'x', '@timestamp': '', process: { hash: { md5: 'nope' } } } as never)).toEqual([])
  })
})
