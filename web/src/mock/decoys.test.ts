// Runs the mock API for decoy files: the agent config's list and the per-group switch.

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

describe('mock decoy files', () => {
  it('saves the list and refuses bad paths', async () => {
    const cfg = (await call('GET', '/api/agent-config')).body
    expect(cfg.decoys.files.some((f: { path: string }) => /desktop/i.test(f.path))).toBe(false)
    const files = [...cfg.decoys.files, { os: 'linux', path: ' /srv/share/keys.txt ', hidden: true }]
    const ok = await call('PUT', '/api/agent-config', { ...cfg, decoys: { ...cfg.decoys, files } })
    expect(ok.status).toBe(200)
    expect(ok.body.decoys.files.at(-1)).toEqual({ os: 'linux', path: '/srv/share/keys.txt', hidden: true })
    const bad = await call('PUT', '/api/agent-config', { ...cfg, decoys: { ...cfg.decoys, files: [{ os: 'windows', path: 'C:\\a\\..\\b.txt', hidden: false }] } })
    expect(bad.status).toBe(400)
    expect((await call('PUT', '/api/agent-config', cfg)).status).toBe(200)
  })

  it('shows the Global switch and group overrides on the groups page', async () => {
    const cfg = (await call('GET', '/api/agent-config')).body
    await call('PUT', '/api/agent-config', { ...cfg, decoys: { ...cfg.decoys, enabled: false } })
    let v = (await call('GET', '/api/groups')).body
    expect(v.global.decoys).toBe(false)
    const parent = v.groups.find((g: { name: string }) => g.name === 'DTS Assets')
    const child = v.groups.find((g: { name: string }) => g.name === 'Marketing Dept')
    expect(child.effective.decoys).toEqual({ value: false })
    // The child inherits its parent's override over Global.
    v = (await call('PATCH', `/api/groups/${parent.id}`, { policy: { ...parent.policy, decoys: { enabled: true } } })).body
    expect(v.groups.find((g: { id: string }) => g.id === child.id).effective.decoys).toEqual({ value: true, group_id: parent.id, group_name: 'DTS Assets' })
    // Its own value beats its parent's.
    v = (await call('PATCH', `/api/groups/${child.id}`, { policy: { ...child.policy, decoys: { enabled: false } } })).body
    expect(v.groups.find((g: { id: string }) => g.id === child.id).effective.decoys.value).toBe(false)
    // Put things back.
    await call('PATCH', `/api/groups/${child.id}`, { policy: child.policy })
    await call('PATCH', `/api/groups/${parent.id}`, { policy: parent.policy })
    await call('PUT', '/api/agent-config', cfg)
    expect((await call('GET', '/api/groups')).body.global.decoys).toBe(true)
  })
})
