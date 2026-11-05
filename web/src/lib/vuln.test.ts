import { describe, expect, it } from 'vitest'
import { missingData, packageLabel } from './vuln'

describe('missingData', () => {
  const kev = { enabled: true, entries: 1768 }
  const host = { host_id: 'h', hostname: 'tower', packages: 380 }

  it('is empty when the page has what it needs', () => {
    expect(missingData({ kev, hosts: [host] })).toEqual([])
  })

  it('names what is missing', () => {
    expect(missingData({ kev: { enabled: false, entries: 0 }, hosts: [host] })[0]).toContain('turned off')
    expect(missingData({ kev: { enabled: true, entries: 0 }, hosts: [host] })[0]).toContain('not been downloaded')
    expect(missingData({ kev: { enabled: true, entries: 0, error: 'Could not look up www.cisa.gov.' }, hosts: [host] })[0]).toContain('www.cisa.gov')
    expect(missingData({ kev, hosts: [] })[0]).toContain('No agents')
    expect(missingData({ kev, hosts: [{ ...host, packages: 0 }] })[0]).toContain('tower has sent no software list')
    expect(missingData({ kev, hosts: [{ ...host, packages: 0, note: 'no package database' }] })[0]).toContain('no package database')
  })
})

describe('packageLabel', () => {
  it('labels images and the operating system', () => {
    expect(packageLabel({ package: 'openssl', package_type: 'slackware' })).toBe('openssl')
    expect(packageLabel({ package: 'lscr.io/linuxserver/plex', package_type: 'docker' })).toBe('lscr.io/linuxserver/plex (Docker image)')
    expect(packageLabel({ package: 'Unraid OS', package_type: 'os' })).toBe('Unraid OS (operating system)')
  })
})
