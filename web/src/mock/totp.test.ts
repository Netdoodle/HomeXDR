// Runs the mock API for two-factor login, so the mock console behaves like the server.

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

describe('mock two-factor login', () => {
  it('turns on, asks for a code at login, spends recovery codes once, turns off', async () => {
    const pw = 'a long enough password'
    expect((await call('POST', '/api/auth/login', { username: 'admin', password: pw })).status).toBe(200)
    expect((await call('GET', '/api/account/totp')).body).toEqual({ enabled: false, recovery_left: 0 })

    const setup = await call('POST', '/api/account/totp/setup', { password: pw })
    expect(setup.body.secret).toBeTruthy()
    expect(setup.body.uri).toContain('otpauth://totp/HomeXDR:admin')
    expect((await call('POST', '/api/account/totp/enable', { code: '000000' })).status).toBe(403)
    const enabled = await call('POST', '/api/account/totp/enable', { code: '123456' })
    expect(enabled.body.recovery_codes).toHaveLength(10)
    const codes: string[] = enabled.body.recovery_codes

    // The password step now returns a token instead of a session.
    const login = await call('POST', '/api/auth/login', { username: 'admin', password: pw })
    expect(login.body.mfa_required).toBe(true)
    expect(login.body.user).toBeUndefined()
    expect((await call('POST', '/api/auth/mfa', { mfa_token: login.body.mfa_token, code: '999999' })).status).toBe(401)
    expect((await call('POST', '/api/auth/mfa', { mfa_token: login.body.mfa_token, code: codes[0] })).status).toBe(200)
    const again = await call('POST', '/api/auth/login', { username: 'admin', password: pw })
    expect((await call('POST', '/api/auth/mfa', { mfa_token: again.body.mfa_token, code: codes[0] })).status).toBe(401)
    expect((await call('GET', '/api/account/totp')).body).toEqual({ enabled: true, recovery_left: 9 })

    expect((await call('POST', '/api/account/totp/disable', { password: pw, code: '123456' })).status).toBe(200)
    expect((await call('GET', '/api/account/totp')).body.enabled).toBe(false)
    expect((await call('POST', '/api/auth/login', { username: 'admin', password: pw })).body.user).toBeTruthy()
  })
})
