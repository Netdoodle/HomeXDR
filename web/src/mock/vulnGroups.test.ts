// Runs the mock API for the per-group Vulnerability management switch.

import { describe, expect, it } from 'vitest'
import { handleMockRequest } from './server'

async function call(method: string, path: string, body?: unknown) {
  const res = await handleMockRequest(method, new URL(path, 'http://mock.test'), new Headers({ 'X-HomeXDR-CSRF': '1' }), body === undefined ? null : JSON.stringify(body))
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

describe('mock vulnerability management per group', () => {
  it('hides the hosts of a group that turns it off, and brings them back', async () => {
    let v = (await call('GET', '/api/groups')).body
    expect(v.global.vuln).toBe(true)
    const parent = v.groups.find((g: { name: string }) => g.name === 'Infrastructure Assets')
    const child = v.groups.find((g: { name: string }) => g.name === 'Linux Servers')
    expect(child.effective.vuln).toEqual({ value: true })
    const before = (await call('GET', '/api/vulnerabilities')).body
    expect(before.hosts.some((h: { hostname: string }) => h.hostname === 'web01')).toBe(true)

    v = (await call('PATCH', `/api/groups/${parent.id}`, { policy: { ...parent.policy, vuln: { enabled: false } } })).body
    expect(v.groups.find((g: { id: string }) => g.id === child.id).effective.vuln).toEqual({ value: false, group_id: parent.id, group_name: 'Infrastructure Assets' })
    const after = (await call('GET', '/api/vulnerabilities')).body
    expect(after.hosts.some((h: { hostname: string }) => h.hostname === 'web01' || h.hostname === 'pihole')).toBe(false)
    expect(after.findings.some((f: { hostname: string }) => f.hostname === 'web01' || f.hostname === 'pihole')).toBe(false)
    expect(after.summary.open).toBeLessThan(before.summary.open)

    await call('PATCH', `/api/groups/${parent.id}`, { policy: parent.policy })
    const back = (await call('GET', '/api/vulnerabilities')).body
    expect(back.summary.open).toBe(before.summary.open)
  })
})
