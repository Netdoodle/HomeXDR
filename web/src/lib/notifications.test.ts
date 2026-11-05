import { describe, expect, it } from 'vitest'
import type { NotifySettings } from '../api/notifications'
import { channelProblem, draftFromSettings, newChannelDraft, updateFromDraft } from './notifications'

const settings: NotifySettings = {
  channels: [
    { id: 'c1', kind: 'ntfy', name: 'Phone', enabled: true, url_set: true, url_host: 'ntfy.sh', token_set: true, password_set: false },
    { id: 'c2', kind: 'email', name: 'Mail', enabled: false, url_set: false, token_set: false, password_set: true, smtp_host: 'mail.example.test', smtp_port: 587, smtp_user: 'me', from: 'a@example.test', to: 'b@example.test' },
  ],
  severity_routes: { critical: 'now', medium: 'digest' },
  rule_routes: [{ prefix: 'health:', route: 'now' }],
  rate_per_hour: 10,
  digest_enabled: true,
  digest_time: '07:00',
  timezone: '',
  heartbeat: false,
  console_url: 'https://xdr.example.test',
  status: { pending: 0, sent_24h: 0, failed_24h: 0, overflow_1h: 0, last_sent_at: null, recent_failures: [], last_digest_at: null, next_digest_at: null },
}

describe('notification form', () => {
  it('sends no secret fields unless the owner typed one', () => {
    const u = updateFromDraft(draftFromSettings(settings))
    expect(u.channels[0]).toEqual({ id: 'c1', kind: 'ntfy', name: 'Phone', enabled: true })
    expect(u.channels[1]).not.toHaveProperty('password')
    expect(u.channels[1].smtp_host).toBe('mail.example.test')
    expect(u.rate_per_hour).toBe(10)
  })

  it('sends a typed secret, and a request to clear one', () => {
    const d = draftFromSettings(settings)
    d.channels[0].url = ' https://ntfy.sh/new '
    d.channels[0].clearToken = true
    d.channels[1].password = 'pw'
    const u = updateFromDraft(d)
    expect(u.channels[0].url).toBe('https://ntfy.sh/new')
    expect(u.channels[0].clear_token).toBe(true)
    expect(u.channels[1].password).toBe('pw')
  })

  it('never reads secrets back into the form', () => {
    const d = draftFromSettings(settings)
    expect(d.channels[0].url).toBe('')
    expect(d.channels[0].token).toBe('')
    expect(d.channels[1].password).toBe('')
  })

  it('drops rule routes with no prefix', () => {
    const d = draftFromSettings(settings)
    d.ruleRoutes.push({ prefix: '  ', route: 'log' })
    expect(updateFromDraft(d).rule_routes).toEqual([{ prefix: 'health:', route: 'now' }])
  })

  it('says what a channel still needs', () => {
    expect(channelProblem(newChannelDraft('ntfy'))).toMatch(/URL/)
    expect(channelProblem(draftFromSettings(settings).channels[0])).toBeNull()
    expect(channelProblem(newChannelDraft('email'))).toMatch(/mail server/)
    expect(channelProblem({ ...newChannelDraft('email'), smtpHost: 'm' })).toMatch(/From/)
    expect(channelProblem({ ...newChannelDraft('email'), smtpHost: 'm', from: 'a@b.c', to: 'd@e.f' })).toBeNull()
  })
})
