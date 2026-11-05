// Mock doctor and self-check results.

import type { DoctorReport, SelfCheckResult, SelfCheckState } from '../api/health'
import type { MockRoute } from './health'

const now = () => new Date().toISOString()

function doctorReport(): DoctorReport {
  const results: DoctorReport['results'] = [
    { id: 'state_db', name: 'Settings database', status: 'ok', message: 'Reachable and writable.' },
    { id: 'event_store', name: 'Event store', status: 'ok', message: 'clickhouse is reachable and writable.' },
    { id: 'disk', name: 'Disk and retention', status: 'ok', message: '412.0 GiB free on the data disk; events use 38.2 GiB with no size cap; events are kept for 30 days; free space on ClickHouse’s own disk is not checked here.' },
    { id: 'rules', name: 'Detection rules', status: 'ok', message: '2412 of 2571 rules enabled. 159 could not load, which is normal for large community rule sets: see the Rules page.' },
    { id: 'rule_repos', name: 'Rule repositories', status: 'ok', message: '1 in use, last checked 3 hours ago.' },
    { id: 'syslog', name: 'Syslog intake', status: 'ok', message: 'Receiving logs from opnsense, under a minute ago.' },
    { id: 'agent_release', name: 'Signed agent release', status: 'ok', message: 'Version 0.9.2 is signed, so agents can update themselves.' },
    { id: 'agents', name: 'Agents', status: 'warn', message: 'Not on this server’s agent release (0.9.2): tower runs 0.9.1.', fix: 'See Settings > Agent updates, or use Update now on the host page.' },
    { id: 'ai', name: 'AI analyst', status: 'warn', message: 'Ready, but no MCP runner has checked in since the server started.', fix: 'Start the MCP runner on the PC that has your Claude plan. See docs/ai-analyst.md.' },
    { id: 'feeds', name: 'Data sources', status: 'warn', message: 'Silent: tower: network.dns.', fix: 'Open the Data health page for details on each source.' },
  ]
  const count = (s: string) => results.filter((r) => r.status === s).length
  return { at: now(), ok: count('ok'), warn: count('warn'), fail: count('fail'), results }
}

function selfCheck(): SelfCheckResult {
  return {
    at: now(),
    took_ms: 4210,
    rules: 2412,
    fired: 2407,
    rate: 99.79,
    failed: 5,
    failures: [
      { rule_id: 'a1b2c3d4-0000-4000-8000-000000000001', title: 'Sample rule with an empty value', reason: 'none of 1 events built from its selection matched it' },
      { rule_id: 'a1b2c3d4-0000-4000-8000-000000000002', title: 'Sample rule that needs a field set and absent', reason: 'its selection needs a field to be both set and absent' },
    ],
    pipeline: { passed: true, message: 'A hit on a temporary store made an alert, and a repeat folded into it.' },
    coverage: {
      days: 7,
      events: 3120,
      sources: 12,
      rules: 2412,
      can_fire: 318,
      cannot_fire: 2094,
      note: '',
      groups: [
        { logsource: 'windows / process_creation', rules: 1320, can_fire: 0, no_events: 1320, missing_field: 0 },
        { logsource: 'windows / security', rules: 402, can_fire: 0, no_events: 402, missing_field: 0 },
        { logsource: 'windows / registry_set', rules: 240, can_fire: 0, no_events: 240, missing_field: 0 },
        { logsource: 'linux / process_creation', rules: 244, can_fire: 201, no_events: 0, missing_field: 43, missing: [{ field: 'ParentCommandLine', rules: 31 }, { field: 'CurrentDirectory', rules: 12 }] },
        { logsource: 'linux / network_connection', rules: 42, can_fire: 39, no_events: 0, missing_field: 3, missing: [{ field: 'Initiated', rules: 3 }] },
        { logsource: 'firewall', rules: 12, can_fire: 12, no_events: 0, missing_field: 0 },
      ],
      missing: [{ field: 'ParentCommandLine', rules: 31 }, { field: 'CurrentDirectory', rules: 12 }, { field: 'Initiated', rules: 3 }],
    },
    previous: { at: new Date(Date.now() - 7 * 86400_000).toISOString(), rules: 2412, fired: 2407, rate: 99.79, cannot_fire: 2101, pipeline: true },
    regression: false,
  }
}

let last: SelfCheckResult | undefined

export function registerHealthCheckMocks(route: MockRoute) {
  route('GET', '/api/doctor', () => doctorReport(), { role: 'admin' })
  route('GET', '/api/selfcheck', (): SelfCheckState => ({ running: false, last }), { role: 'admin' })
  route(
    'POST',
    '/api/selfcheck',
    (): SelfCheckState => {
      last = selfCheck()
      return { running: false, last }
    },
    { role: 'admin' },
  )
}
