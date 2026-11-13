// Runs the mock API for host firewall control, so the mock console has working data.

import { describe, expect, it } from 'vitest'
import { handleMockRequest } from './server'

async function call(method: string, path: string, body?: unknown) {
  const res = await handleMockRequest(
    method,
    new URL(path, 'http://mock.test'),
    new Headers({ 'X-HomeXDR-CSRF': '1' }),
    body === undefined ? null : JSON.stringify(body),
  )
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

describe('mock host firewall', () => {
  it('lists blocks with their scope and the hosts', async () => {
    const r = await call('GET', '/api/firewall')
    expect(r.status).toBe(200)
    expect(r.body.blocks.length).toBeGreaterThan(0)
    expect(r.body.blocks.some((b: { scope: string; group_id: string }) => b.group_id && b.scope.includes('DTS Assets'))).toBe(true)
    expect(r.body.hosts.every((h: { platform: string }) => ['windows', 'linux', 'darwin'].includes(h.platform))).toBe(true)
  })

  it('adds, refuses bad and duplicate addresses, and removes', async () => {
    expect((await call('POST', '/api/firewall/blocks', { cidr: '0.0.0.0/0' })).status).toBe(400)
    expect((await call('POST', '/api/firewall/blocks', { cidr: '192.168.1.10' })).status).toBe(400) // the server
    const add = await call('POST', '/api/firewall/blocks', { cidr: '203.0.113.200', note: 'test' })
    expect(add.status).toBe(200)
    const b = add.body.blocks.find((x: { cidr: string }) => x.cidr === '203.0.113.200')
    expect(b.direction).toBe('both')
    expect((await call('POST', '/api/firewall/blocks', { cidr: '203.0.113.200' })).status).toBe(400)
    const del = await call('DELETE', `/api/firewall/blocks/${b.id}`)
    expect(del.body.blocks.some((x: { cidr: string }) => x.cidr === '203.0.113.200')).toBe(false)
  })

  it('shows the global switch on the groups page', async () => {
    await call('PUT', '/api/settings/firewall', { enabled: false })
    expect((await call('GET', '/api/groups')).body.global.firewall).toBe(false)
    await call('PUT', '/api/settings/firewall', { enabled: true })
    expect((await call('GET', '/api/groups')).body.global.firewall).toBe(true)
  })
})
