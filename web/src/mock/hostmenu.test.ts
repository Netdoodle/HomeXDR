// Runs the mock API behind the host Actions menu: new command types, the Applications
// list, the vulnerability rescan and removing a host with an authenticator code.

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

const hostByName = async (name: string) => {
  const { body } = await call('GET', '/api/hosts')
  return (body.hosts as { id: string; hostname: string }[]).find((h) => h.hostname === name)!
}

describe('mock host actions', () => {
  it('accepts the new command types and checks the power delay', async () => {
    const win = await hostByName('DESKTOP-7QK2M4')
    for (const type of ['agent.restart', 'agent.logs', 'agent.flush_queue']) {
      const r = await call('POST', `/api/hosts/${win.id}/actions`, { type, params: {} })
      expect(r.status, type).toBe(200)
      expect(r.body.type).toBe(type)
      expect(r.body.status).toBe('queued')
    }
    expect((await call('POST', `/api/hosts/${win.id}/actions`, { type: 'host.reboot', params: { delay_sec: 0, message: 'bye' } })).status).toBe(200)
    expect((await call('POST', `/api/hosts/${win.id}/actions`, { type: 'host.shutdown', params: {} })).status).toBe(200)
    expect((await call('POST', `/api/hosts/${win.id}/actions`, { type: 'host.reboot', params: { delay_sec: 3601 } })).status).toBe(400)
    expect((await call('POST', `/api/hosts/${win.id}/actions`, { type: 'host.reboot', params: { delay_sec: -1 } })).status).toBe(400)
    // This server's local policy does not allow shutting it down.
    const linux = await hostByName('srv-docker01')
    expect((await call('POST', `/api/hosts/${linux.id}/actions`, { type: 'host.shutdown', params: {} })).status).toBe(409)
  })

  it('lists applications for endpoints and none for network devices', async () => {
    const linux = await hostByName('srv-docker01')
    const r = await call('GET', `/api/hosts/${linux.id}/applications`)
    expect(r.status).toBe(200)
    expect(r.body.total).toBe(r.body.applications.length)
    expect(r.body.applications.length).toBeGreaterThan(5)
    expect(r.body.applications[0]).toMatchObject({ type: 'deb' })
    const names: string[] = r.body.applications.map((a: { name: string }) => a.name.toLowerCase())
    expect(names).toEqual([...names].sort())
    expect(r.body.reported_at).toBeTruthy()
    const fw = await hostByName('fw-opnsense')
    expect((await call('GET', `/api/hosts/${fw.id}/applications`)).body).toEqual({ applications: [], total: 0, reported_at: null })
    expect((await call('GET', '/api/hosts/nope/applications')).status).toBe(404)
  })

  it('starts a vulnerability rescan', async () => {
    const linux = await hostByName('srv-docker01')
    expect((await call('POST', `/api/hosts/${linux.id}/vuln-rescan`)).body).toEqual({ started: true, scope: 'all' })
    expect((await call('POST', '/api/hosts/nope/vuln-rescan')).status).toBe(404)
  })

  it('removes a host only with two-factor on, the typed name and a fresh authenticator code', async () => {
    const pi = await hostByName('pi-media')
    const remove = (b: object) => call('POST', `/api/hosts/${pi.id}/remove`, b)
    const ok = { confirm_hostname: 'PI-media', totp_code: '123456' }

    const first = await remove(ok)
    expect(first.status).toBe(403)
    expect(first.body.error).toContain('two-factor')

    const pw = 'a long enough password'
    await call('POST', '/api/account/totp/setup', { password: pw })
    const enabled = await call('POST', '/api/account/totp/enable', { code: '123456' })
    const recovery: string = enabled.body.recovery_codes[0]

    expect((await remove({ ...ok, confirm_hostname: 'other' })).status).toBe(400)
    expect((await remove({ ...ok, totp_code: '000000' })).status).toBe(403)
    expect((await remove({ ...ok, totp_code: recovery })).status).toBe(403)
    expect((await call('GET', `/api/hosts/${pi.id}`)).status).toBe(200)

    await call('POST', `/api/hosts/${pi.id}/actions`, { type: 'file.hash', params: { path: '/etc/passwd' } })
    expect((await remove(ok)).status).toBe(204)
    expect((await call('GET', `/api/hosts/${pi.id}`)).status).toBe(404)
    expect((await call('GET', `/api/hosts/${pi.id}/commands`)).status).toBe(404)
    expect((await remove(ok)).status).toBe(404)
    expect((await call('GET', '/api/hosts')).body.hosts.some((h: { id: string }) => h.id === pi.id)).toBe(false)
  })
})
