// Types for the console REST API. Source of truth: docs/api.md, shared/event/event.go
// and shared/api/{agent,artifacts}.go. Keep field names identical to the JSON tags.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export type Role = 'admin' | 'analyst' | 'viewer'
export const ROLES: Role[] = ['admin', 'analyst', 'viewer']

export interface User {
  id: string
  username: string
  role: Role
  created_at: string
  last_login?: string
}

export interface SetupStatus {
  needs_setup: boolean
  version: string
}

export interface TimeBucket {
  t: string
  count: number
}

export interface Overview {
  hosts_total: number
  hosts_online: number
  hosts_isolated: number
  alerts_open: number
  alerts_by_severity: Record<Severity, number>
  events_total: number
  events_timeline: TimeBucket[]
  alerts_timeline: TimeBucket[]
  top_rules: { rule_id: string; title: string; severity: Severity; count: number }[]
  top_hosts: { host_id: string; hostname: string; alerts: number }[]
  events_by_category: { category: string; count: number }[]
}

// ---------------------------------------------------------------------------------------
// Hosts

export type Platform = 'windows' | 'linux' | 'darwin' | 'network'
export type HostStatus = 'online' | 'offline' | 'isolated' | 'revoked'
export type SensorState = 'running' | 'degraded' | 'failed' | 'disabled'

export interface HostSensor {
  name: string
  impl: string
  state: SensorState
  error?: string
  events: number
}

export interface Host {
  id: string
  hostname: string
  kind: 'endpoint' | 'network'
  os: { platform: Platform; family?: string; name?: string; version?: string; kernel?: string }
  arch?: string
  ips: string[]
  macs?: string[]
  agent_version?: string
  status: HostStatus
  isolated: boolean
  last_seen?: string
  enrolled_at: string
  labels: string[]
  sensors?: HostSensor[]
  queue_events?: number
  allowed_actions?: string[]
  open_alerts: number
  boot_time?: string
  cpus?: number
  memory_bytes?: number
}

export interface HostFilter {
  q?: string
  status?: string
  label?: string
  platform?: string
}

// ---------------------------------------------------------------------------------------
// Commands

export type CommandType =
  | 'process.kill'
  | 'host.isolate'
  | 'host.release'
  | 'file.quarantine'
  | 'file.restore'
  | 'file.get'
  | 'file.hash'
  | 'artifact.collect'

export const COMMAND_TYPES: CommandType[] = [
  'process.kill',
  'host.isolate',
  'host.release',
  'file.quarantine',
  'file.restore',
  'file.get',
  'file.hash',
  'artifact.collect',
]

export type CommandStatus = 'queued' | 'delivered' | 'running' | 'completed' | 'failed' | 'rejected' | 'expired'

export const TERMINAL_COMMAND_STATUSES: CommandStatus[] = ['completed', 'failed', 'rejected', 'expired']

// Param shapes from shared/api/agent.go.
export interface KillParams {
  pid: number
  entity_id?: string
  tree?: boolean
}
export interface IsolateParams {
  allow?: string[]
}
export interface QuarantineParams {
  path: string
}
export interface RestoreParams {
  id: string
}
export interface FileGetParams {
  path: string
  max_bytes?: number
}
export interface FileHashParams {
  path: string
}
export interface ArtifactParams {
  name: string
  params?: Record<string, string>
}

export type CommandRequest =
  | { type: 'process.kill'; params: KillParams }
  | { type: 'host.isolate'; params: IsolateParams }
  | { type: 'host.release'; params: Record<string, never> }
  | { type: 'file.quarantine'; params: QuarantineParams }
  | { type: 'file.restore'; params: RestoreParams }
  | { type: 'file.get'; params: FileGetParams }
  | { type: 'file.hash'; params: FileHashParams }
  | { type: 'artifact.collect'; params: ArtifactParams }

// Result shapes (CommandRecord.output) from shared/api/agent.go.
export interface KillResult {
  killed: number[]
}
export interface QuarantineResult {
  id: string
  original_path: string
  sha256: string
  size: number
}
export interface FileHashResult {
  path: string
  size: number
  md5: string
  sha1: string
  sha256: string
}

export interface CommandRecord {
  id: string
  host_id: string
  hostname: string
  type: CommandType | string
  params: any
  status: CommandStatus
  issued_by: string
  issued_at: string
  expires_at: string
  delivered_at?: string
  completed_at?: string
  error?: string
  output?: unknown
  row_count?: number
  hunt_id?: string
}

export type Row = Record<string, unknown>

// ---------------------------------------------------------------------------------------
// Events (shared/event.Event)

export interface EventHash {
  md5?: string
  sha1?: string
  sha256?: string
}
export interface EventCodeSignature {
  exists: boolean
  valid?: boolean
  trusted?: boolean
  subject_name?: string
  status?: string
}
export interface EventPE {
  original_file_name?: string
  company?: string
  product?: string
  description?: string
  file_version?: string
  imphash?: string
}
export interface EventUser {
  id?: string
  name?: string
  domain?: string
  target?: EventUser
}
export interface EventProcess {
  entity_id?: string
  pid?: number
  name?: string
  executable?: string
  command_line?: string
  args?: string[]
  working_directory?: string
  start?: string
  end?: string
  exit_code?: number
  user?: EventUser
  hash?: EventHash
  code_signature?: EventCodeSignature
  pe?: EventPE
  integrity_level?: string
  elevated?: boolean
  session_id?: number
  tty?: string
  parent?: EventProcess
}
export interface EventFile {
  path?: string
  name?: string
  directory?: string
  extension?: string
  old_path?: string
  target_path?: string
  type?: string
  size?: number
  mode?: string
  owner?: string
  group?: string
  mtime?: string
  ctime?: string
  hash?: EventHash
  code_signature?: EventCodeSignature
  pe?: EventPE
}
export interface EventEndpoint {
  ip?: string
  port?: number
  domain?: string
  mac?: string
  bytes?: number
  packets?: number
}
export interface EventMitreItem {
  id: string
  name?: string
}

export interface Event {
  id: string
  '@timestamp': string
  agent: { id?: string; version?: string; type?: string }
  host: {
    id?: string
    name?: string
    hostname?: string
    os?: { platform: string; family?: string; name?: string; version?: string; kernel?: string }
    ip?: string[]
    mac?: string[]
    architecture?: string
  }
  event: {
    kind: string
    category?: string[]
    type?: string[]
    action?: string
    outcome?: string
    module?: string
    dataset?: string
    provider?: string
    code?: string
    severity?: number
    original?: string
    ingested?: string
    duration?: number
  }
  message?: string
  tags?: string[]
  labels?: Record<string, string>
  process?: EventProcess
  file?: EventFile
  dll?: { path?: string; name?: string; hash?: EventHash; code_signature?: EventCodeSignature; pe?: EventPE }
  registry?: {
    hive?: string
    key?: string
    path?: string
    value?: string
    data?: { type?: string; strings?: string[] }
  }
  network?: {
    transport?: string
    type?: string
    protocol?: string
    direction?: string
    community_id?: string
    bytes?: number
    packets?: number
  }
  source?: EventEndpoint
  destination?: EventEndpoint
  dns?: {
    type?: string
    question: { name?: string; type?: string }
    response_code?: string
    answers?: { name?: string; type?: string; data?: string; ttl?: number }[]
    resolved_ip?: string[]
  }
  http?: { method?: string; url?: string; host?: string; user_agent?: string; status_code?: number }
  tls?: { server_name?: string; version?: string; ja3?: string; ja4?: string; subject?: string; issuer?: string }
  user?: EventUser
  service?: {
    name?: string
    display_name?: string
    type?: string
    start_type?: string
    path?: string
    account?: string
    state?: string
  }
  rule?: {
    id?: string
    name?: string
    category?: string
    ruleset?: string
    version?: string
    description?: string
    reference?: string
  }
  threat?: { framework?: string; tactics?: EventMitreItem[]; techniques?: EventMitreItem[] }
  observer?: { name?: string; type?: string; vendor?: string; product?: string; hostname?: string; ip?: string[] }
  log?: { level?: string; logger?: string; file_path?: string; facility?: string; app_name?: string }
  package?: {
    name?: string
    version?: string
    vendor?: string
    architecture?: string
    install_path?: string
    installed?: string
    type?: string
  }
  data?: Record<string, unknown>
}

export interface SearchRequest {
  query: string
  from?: string
  to?: string
  host_id?: string
  limit?: number
  offset?: number
  order?: 'asc' | 'desc'
}

export interface SearchResponse {
  events: Event[]
  total?: number
  took_ms: number
}

export interface TimelineFilter {
  from?: string
  to?: string
  category?: string
  limit?: number
}

// ---------------------------------------------------------------------------------------
// Process trees

export type ProcessEventCategory = 'network' | 'file' | 'registry' | 'dns' | 'library'
export const PROCESS_EVENT_CATEGORIES: ProcessEventCategory[] = ['network', 'file', 'registry', 'dns', 'library']

export interface ProcessNode {
  entity_id: string
  pid: number
  name: string
  executable?: string
  command_line?: string
  user?: string
  start?: string
  end?: string
  exit_code?: number
  parent_entity_id?: string
  hash_sha256?: string
  signed?: boolean
  alert_count: number
  event_counts: Record<ProcessEventCategory, number>
  children: ProcessNode[]
  is_target?: boolean
}

// ---------------------------------------------------------------------------------------
// Alerts

export type AlertStatus = 'new' | 'in_progress' | 'resolved' | 'false_positive'
export const ALERT_STATUSES: AlertStatus[] = ['new', 'in_progress', 'resolved', 'false_positive']

export interface MitreMapping {
  tactic?: string
  technique_id?: string
  technique?: string
}

export interface AlertNote {
  author: string
  text: string
  at: string
}

export interface Alert {
  id: string
  created_at: string
  updated_at: string
  first_seen: string
  last_seen: string
  count: number
  status: AlertStatus
  severity: Severity
  risk_score: number
  assignee?: string
  rule: {
    id: string
    title: string
    description?: string
    level: Severity
    tags: string[]
    references?: string[]
    false_positives?: string[]
  }
  mitre: MitreMapping[]
  host_id: string
  hostname: string
  process_entity_id?: string
  process_name?: string
  command_line?: string
  user?: string
  event_ids: string[]
  event?: Event
  events?: Event[]
  notes: AlertNote[]
}

export interface AlertFilter {
  status?: string
  severity?: string
  host_id?: string
  rule_id?: string
  q?: string
  limit?: number
  offset?: number
}

export interface AlertPatch {
  status?: AlertStatus
  assignee?: string
}

// ---------------------------------------------------------------------------------------
// Rules

export interface Rule {
  id: string
  title: string
  description?: string
  status?: string
  level: Severity
  enabled: boolean
  source: 'builtin' | 'custom'
  tags: string[]
  author?: string
  references?: string[]
  logsource: { product?: string; category?: string; service?: string }
  mitre: MitreMapping[]
  hits_24h: number
  updated_at: string
  yaml?: string
}

/** A rule file (or stored custom rule) that failed to compile; returned by GET /api/rules. */
export interface RuleLoadError {
  path: string
  error: string
}

export interface RuleFilter {
  q?: string
  enabled?: string
  level?: string
  source?: string
}

export interface RuleValidateResponse {
  ok: boolean
  error?: string
  rule?: Rule
}

export interface RuleTestResponse {
  matches: Event[]
  scanned: number
}

// ---------------------------------------------------------------------------------------
// Artifacts and hunts

export interface ArtifactArg {
  name: string
  type: 'string' | 'int' | 'bool' | string
  default?: string
  required?: boolean
  description: string
}

export interface ArtifactDef {
  name: string
  description: string
  platforms: string[]
  params?: ArtifactArg[]
  columns: string[]
}

export interface HuntTarget {
  all?: boolean
  labels?: string[]
  host_ids?: string[]
  platform?: string
}

export type HuntStatus = 'running' | 'stopped' | 'completed'

export interface Hunt {
  id: string
  artifact: string
  params: Record<string, string>
  description?: string
  target: HuntTarget
  status: HuntStatus
  created_by: string
  created_at: string
  expires_at: string
  stats: { scheduled: number; completed: number; failed: number; rows: number }
}

export interface HuntCreate {
  artifact: string
  params?: Record<string, string>
  description?: string
  target: HuntTarget
  expires_hours?: number
}

export interface HuntResultRow {
  host_id: string
  hostname: string
  row: Row
}

// ---------------------------------------------------------------------------------------
// Settings and admin

export interface ServerSettings {
  version: string
  agent_url: string
  ca_pin: string
  server_names: string[]
  event_store: 'clickhouse' | 'sqlite'
  /** 0 = no time limit */
  retention_days: number
  /** size cap for stored events; 0 = no cap */
  retention_max_bytes: number
  /** current size of the event store, when the store could report it */
  event_store_bytes?: number
  syslog_addr: string
  /** release public key agents pin for signed automatic updates; empty when not set up */
  update_key?: string
  agent_release: AgentReleaseStatus
}

export interface AgentReleaseStatus {
  version?: string
  signed: boolean
  update_key?: string
  /** why agents are not offered this release */
  problem?: string
}

export interface EnrollmentToken {
  id: string
  name: string
  token?: string
  created_at: string
  created_by: string
  expires_at?: string
  max_uses?: number
  uses: number
  labels: string[]
}

export interface EnrollmentTokenCreate {
  name: string
  expires_hours?: number
  max_uses?: number
  labels?: string[]
}

export interface AuditEntry {
  id: string
  at: string
  user: string
  action: string
  target: string
  details: unknown
}

export interface SyslogSource {
  ip: string
  name: string
  kind: string
  last_seen: string
  count: number
}

export interface Integrations {
  syslog: {
    listening: boolean
    addr: string
    received: number
    parsed: number
    failed: number
    sources: SyslogSource[]
  }
}

export interface Health {
  status: string
  event_store: string
}

// AgentConfig (shared/api.AgentConfig).
export interface AgentConfig {
  version: number
  heartbeat_interval_sec: number
  inventory_interval_sec: number
  batch: { max_events: number; flush_interval_ms: number }
  sensors: {
    process: { enabled: boolean; hash_executables: boolean }
    network: { enabled: boolean }
    file: { enabled: boolean; paths?: string[]; exclude?: string[] }
    registry: { enabled: boolean }
    dns: { enabled: boolean }
    library: { enabled: boolean }
    auth: { enabled: boolean }
    eventlog: { enabled: boolean; channels?: string[] }
  }
  fim: { enabled: boolean; paths?: string[]; exclude?: string[]; interval_sec: number; max_file_size: number }
  logs?: { path: string; format?: string; dataset?: string }[]
  filters?: { category?: string; field: string; op: string; value: string }[]
  spool_max_bytes: number
}
