import { describe, expect, it } from 'vitest'
import type { ArtifactDef, Event, Host, Rule } from '../api/types'
import { validateAgentConfig } from './agentConfig'
import { artifactDefaults, normalizeArtifactParams, validateArtifactParams } from './artifacts'
import { actionAllowed, commandParamsSummary, describeCommand } from './commands'
import { eventSummary, leafPaths } from './fields'
import { huntTargetHosts } from './hunts'
import { AUTONOMY_CHOICES, DATA_CHOICES, eventSearchHref, formatTokens, TRIGGER_CHOICES, triggerChoice } from './ai'
import { formatSizeSetting } from './format'
import { agentUrlOptions, buildInstallCommands, normalizeAgentUrl, shellQuote } from './install'

describe('AI analyst helpers', () => {
  it('offers the three trigger levels with notes', () => {
    expect(TRIGGER_CHOICES.map((c) => c.value)).toEqual(['medium', 'high', 'informational'])
    expect(triggerChoice('medium')?.note).toMatch(/cost/)
    expect(triggerChoice('low')).toBeUndefined()
    expect(TRIGGER_CHOICES.every((c) => c.note.length > 0)).toBe(true)
  })

  it('only offers built options for data and autonomy', () => {
    expect(DATA_CHOICES.filter((c) => !c.planned).map((c) => c.value)).toEqual(['as-is', 'local'])
    expect(DATA_CHOICES.find((c) => c.value === 'redact')?.planned).toBe(true)
    expect(AUTONOMY_CHOICES.filter((c) => !c.planned).map((c) => c.value)).toEqual(['annotate'])
  })

  it('links evidence to a search over the event ID', () => {
    const href = eventSearchHref('06abc"x', '2026-10-20T05:00:00Z')
    const sp = new URLSearchParams(href.split('?')[1])
    expect(href.startsWith('/search?')).toBe(true)
    expect(sp.get('q')).toBe('id:"06abc\\"x"')
    expect(sp.get('range')).toBe('custom')
    expect(sp.get('from')).toBe('2026-09-20T05:00:00.000Z')
  })

  it('formats token counts', () => {
    expect(formatTokens(950)).toBe('950')
    expect(formatTokens(21_400)).toBe('21k')
    expect(formatTokens(1_250_000)).toBe('1.3M')
  })
})

describe('formatSizeSetting', () => {
  it('keeps the units a size was configured in', () => {
    expect(formatSizeSetting(1e12)).toBe('1 TB')
    expect(formatSizeSetting(2 ** 40)).toBe('1 TiB')
    expect(formatSizeSetting(500e9)).toBe('500 GB')
    expect(formatSizeSetting(64 * 2 ** 20)).toBe('64 MiB')
  })
})

describe('install commands', () => {
  it('normalizes agent URLs', () => {
    expect(normalizeAgentUrl('homexdr.lan')).toBe('https://homexdr.lan:8443')
    expect(normalizeAgentUrl('https://homexdr.lan:9443/')).toBe('https://homexdr.lan:9443')
    expect(normalizeAgentUrl('[fd00::10]')).toBe('https://[fd00::10]:8443')
  })

  it('offers agent_url first and one entry per server name', () => {
    expect(agentUrlOptions({ agent_url: 'https://homexdr.lan:8443', server_names: ['homexdr.lan', '192.168.1.10', 'fd00::10'] })).toEqual([
      'https://homexdr.lan:8443',
      'https://192.168.1.10:8443',
      'https://[fd00::10]:8443',
    ])
    // server names inherit a non-default agent port
    expect(agentUrlOptions({ agent_url: 'https://Master:28443', server_names: ['Master', 'localhost'] })).toEqual([
      'https://master:28443',
      'https://localhost:28443',
    ])
  })

  it('builds the documented Linux, macOS and Windows commands', () => {
    const c = buildInstallCommands('https://homexdr.lan:8443', 'hxe_abc123', 'sha256:00ff')
    expect(c.linux).toBe('curl -fsSLk https://homexdr.lan:8443/v1/install/linux.sh | sudo sh -s -- --token hxe_abc123 --ca-pin sha256:00ff')
    expect(c.macos).toBe('curl -fsSLk https://homexdr.lan:8443/v1/install/macos.sh | sudo sh -s -- --token hxe_abc123 --ca-pin sha256:00ff')
    expect(c.windows).toBe('homexdr-agent.exe install --server https://homexdr.lan:8443 --token hxe_abc123 --ca-pin sha256:00ff')
  })

  it('adds the update key to the Linux and macOS commands only', () => {
    const c = buildInstallCommands('https://homexdr.lan:8443', 'hxe_abc123', 'sha256:00ff', 'ed25519:AbC+/9=')
    expect(c.linux).toBe(
      'curl -fsSLk https://homexdr.lan:8443/v1/install/linux.sh | sudo sh -s -- --token hxe_abc123 --ca-pin sha256:00ff --update-key ed25519:AbC+/9=',
    )
    expect(c.macos).toContain('--update-key ed25519:AbC+/9=')
    expect(c.windows).not.toContain('update-key')
  })

  it('quotes unsafe shell values', () => {
    expect(shellQuote("a b'c")).toBe(`'a b'"'"'c'`)
  })
})

describe('artifact params', () => {
  const def: ArtifactDef = {
    name: 'file.find',
    description: '',
    platforms: ['linux'],
    columns: [],
    params: [
      { name: 'root', type: 'string', required: true, description: '' },
      { name: 'max_depth', type: 'int', default: '5', description: '' },
      { name: 'hash', type: 'bool', default: 'false', description: '' },
    ],
  }

  it('fills defaults and validates types', () => {
    const v = artifactDefaults(def)
    expect(v).toEqual({ root: '', max_depth: '5', hash: 'false' })
    expect(validateArtifactParams(def, v)).toEqual({ root: 'Required' })
    expect(validateArtifactParams(def, { ...v, root: '/etc', max_depth: 'x' })).toEqual({ max_depth: 'Must be a whole number' })
  })

  it('drops values equal to defaults', () => {
    expect(normalizeArtifactParams(def, { root: '/etc', max_depth: '5', hash: 'true' })).toEqual({ root: '/etc', hash: 'true' })
  })
})

const host = (over: Partial<Host>): Host => ({
  id: 'h1',
  hostname: 'web01',
  kind: 'endpoint',
  os: { platform: 'linux' },
  ips: [],
  status: 'online',
  isolated: false,
  enrolled_at: '',
  labels: [],
  open_alerts: 0,
  ...over,
})

describe('commands', () => {
  it('describes kills, including the entity-ID safety check', () => {
    const d = describeCommand({ type: 'process.kill', params: { pid: 42, entity_id: 'e1', tree: true } }, { hostname: 'web01' })
    expect(d.danger).toBe(true)
    expect(d.effects[0]).toContain('PID 42 on web01 and every process it started')
    expect(d.effects.join(' ')).toContain('reused PID is never hit')
  })

  it('summarizes params for history', () => {
    expect(commandParamsSummary({ type: 'artifact.collect', params: { name: 'file.find', params: { root: '/etc' } } })).toBe('file.find root=/etc')
    expect(commandParamsSummary({ type: 'process.kill', params: { pid: 7, tree: true } })).toBe('PID 7 (tree)')
  })

  it('respects local policy and host kind', () => {
    expect(actionAllowed(host({ allowed_actions: ['host.isolate'] }), 'process.kill')).toBe(false)
    expect(actionAllowed(host({ allowed_actions: undefined }), 'process.kill')).toBe(true)
    expect(actionAllowed(host({ kind: 'network' }), 'host.isolate')).toBe(false)
  })
})

describe('hunt targets', () => {
  const hosts = [
    host({ id: 'a', labels: ['server'] }),
    host({ id: 'b', os: { platform: 'windows' } }),
    host({ id: 'c', kind: 'network', os: { platform: 'network' } }),
    host({ id: 'd', status: 'revoked' }),
  ]
  it('selects endpoints by label, id, platform or all', () => {
    expect(huntTargetHosts(hosts, { all: true }).map((h) => h.id)).toEqual(['a', 'b'])
    expect(huntTargetHosts(hosts, { labels: ['server'] }).map((h) => h.id)).toEqual(['a'])
    expect(huntTargetHosts(hosts, { platform: 'windows' }).map((h) => h.id)).toEqual(['b'])
    expect(huntTargetHosts(hosts, { host_ids: ['b', 'c'] }).map((h) => h.id)).toEqual(['b'])
  })
})

describe('event helpers', () => {
  const e = {
    id: '1',
    '@timestamp': '2026-10-19T10:00:00Z',
    agent: {},
    host: { name: 'web01' },
    event: { kind: 'event', category: ['network'], action: 'connect' },
    source: { ip: '10.0.0.5', port: 50000 },
    destination: { ip: '203.0.113.7', port: 443, domain: 'example.org' },
    network: { transport: 'tcp' },
    dns: undefined,
  } as unknown as Event

  it('summarizes network events', () => {
    expect(eventSummary(e)).toBe('connect TCP 10.0.0.5:50000 → example.org:443')
  })

  it('lists leaf paths without array indices', () => {
    const paths = leafPaths({ a: { b: 1, c: [1, 2] }, d: [{ e: 'x' }, { f: 'y' }] })
    expect([...paths].sort()).toEqual(['a.b', 'a.c', 'd.e', 'd.f'])
  })
})

describe('agent config validation', () => {
  it('flags bad values', () => {
    const problems = validateAgentConfig({
      version: 1,
      heartbeat_interval_sec: 1,
      inventory_interval_sec: 3600,
      batch: { max_events: 500, flush_interval_ms: 2000 },
      sensors: {} as never,
      fim: { enabled: true, interval_sec: 3600, max_file_size: 1 },
      filters: [{ field: '', op: 'regex', value: 'x' }],
      spool_max_bytes: 512 << 20,
    })
    expect(problems).toHaveLength(3)
  })
})

describe('response normalization', () => {
  it('accepts Go-cased logsource keys and drops empty values', async () => {
    const { normalizeLogsource, normalizeRule } = await import('../api/normalize')
    expect(normalizeLogsource({ Category: 'process_creation', Product: 'windows', Service: '' })).toEqual({
      category: 'process_creation',
      product: 'windows',
    })
    expect(normalizeLogsource(null)).toEqual({})
    const raw = { id: 'x', title: 't', level: 'low', enabled: true, source: 'custom', logsource: { product: 'linux' } }
    const r = normalizeRule(raw as unknown as Rule)
    expect(r.tags).toEqual([])
    expect(r.mitre).toEqual([])
  })
})
