// Runs the mock API for the noise features, so the mock console has working data.

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

describe('mock suppressions', () => {
  it('hides suppressed alerts unless asked for by name', async () => {
    const all = await call('GET', '/api/alerts?limit=1000')
    expect(all.body.alerts.some((a: { status: string }) => a.status === 'suppressed')).toBe(false)
    const hidden = await call('GET', '/api/alerts?status=suppressed')
    expect(hidden.body.total).toBeGreaterThan(0)
  })

  it('lists the noisiest shapes without taking the alert detail route', async () => {
    const r = await call('GET', '/api/alerts/noise')
    expect(r.status).toBe(200)
    expect(r.body.shapes.length).toBeGreaterThan(0)
    expect(r.body.shapes[0].sample_alert_id).toBeTruthy()
  })

  it('previews, refuses no scope, wants a confirm for a whole rule, and applies', async () => {
    const shapes = (await call('GET', '/api/alerts/noise')).body.shapes
    const ruleId = shapes[0].rule_id
    const spec = { rule_id: ruleId, conditions: [{ field: 'process.executable', op: 'equals', value: shapes[0].process }] }

    const preview = await call('POST', '/api/suppressions/preview', spec)
    expect(preview.status).toBe(200)
    expect(preview.body.matches).toBeGreaterThan(0)

    expect((await call('POST', '/api/suppressions/preview', {})).status).toBe(400)
    expect((await call('POST', '/api/suppressions', { rule_id: ruleId, reason: 'x' })).status).toBe(400)
    expect((await call('POST', '/api/suppressions', spec)).status).toBe(400)

    const created = await call('POST', '/api/suppressions', { ...spec, reason: 'a scheduled job', apply: true })
    expect(created.status).toBe(200)
    expect(created.body.closed).toBe(preview.body.matches)

    const id = created.body.suppression.id
    const patched = await call('PATCH', `/api/suppressions/${id}`, { enabled: false })
    expect(patched.body.enabled).toBe(false)
    expect((await call('DELETE', `/api/suppressions/${id}`)).status).toBe(204)
  })

  it('edits the must-alert list', async () => {
    const r = await call('PUT', '/api/settings/noise', { must_alert_rules: ['a', ' a ', 'b'] })
    expect(r.body.must_alert_rules).toEqual(['a', 'b'])
  })
})

describe('mock notifications', () => {
  it('returns no secrets, and keeps them when saved blank', async () => {
    const got = await call('GET', '/api/settings/notifications')
    expect(got.body.channels[0].url_set).toBe(true)
    expect(got.body.channels[0]).not.toHaveProperty('url')

    const { status: _status, channels, ...rest } = got.body
    const saved = await call('PUT', '/api/settings/notifications', {
      ...rest,
      channels: [
        { id: channels[0].id, kind: channels[0].kind, name: 'Renamed', enabled: true },
        { kind: 'webhook', name: 'Hook', enabled: true, url: 'https://hooks.example.test/secret-path', token: 'tok' },
      ],
    })
    expect(saved.status).toBe(200)
    expect(saved.body.channels[0].name).toBe('Renamed')
    expect(saved.body.channels[0].url_set).toBe(true)
    expect(saved.body.channels[1].url_host).toBe('hooks.example.test')
    expect(JSON.stringify(saved.body)).not.toContain('secret-path')

    const test = await call('POST', `/api/settings/notifications/channels/${saved.body.channels[0].id}/test`, {})
    expect(test.body.ok).toBe(true)
  })

  it('refuses a channel with no URL', async () => {
    const { status: _status, ...rest } = (await call('GET', '/api/settings/notifications')).body
    const bad = await call('PUT', '/api/settings/notifications', { ...rest, channels: [{ kind: 'ntfy', name: 'x', enabled: true }] })
    expect(bad.status).toBe(400)
  })
})
