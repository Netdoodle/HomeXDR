// Typed wrappers for every endpoint in docs/api.md.

import { http, rawRequest } from './client'
import { normalizeRule, normalizeRuleRepo, normalizeValidate } from './normalize'
import type {
  AgentLifecycle,
  AgentLifecycleView,
  AISettings,
  AISettingsUpdate,
  MCPToken,
  AITriage,
  AgentConfig,
  Alert,
  AlertFilter,
  AlertPatch,
  AlertTriageResponse,
  ArtifactDef,
  AuditEntry,
  CommandRecord,
  CommandRequest,
  EnrollmentToken,
  EnrollmentTokenCreate,
  Event,
  Health,
  Host,
  HostFilter,
  Hunt,
  HuntCreate,
  HuntResultRow,
  Integrations,
  Overview,
  ProcessEventCategory,
  ProcessNode,
  Role,
  Row,
  Rule,
  RuleFilter,
  RuleLoadError,
  RuleRepo,
  RuleRepoFile,
  RuleRepoSettings,
  RuleRepoSkip,
  RuleTestResponse,
  RuleValidateResponse,
  SearchRequest,
  SearchResponse,
  ServerSettings,
  SetupStatus,
  TimelineFilter,
  User,
} from './types'

const enc = encodeURIComponent

// Setup and auth -------------------------------------------------------------------------

export const setupStatus = () => http.get<SetupStatus>('/api/setup/status')
export const setup = (username: string, password: string) =>
  http.post<{ user: User }>('/api/setup', { username, password })
export const login = (username: string, password: string) =>
  http.post<{ user: User }>('/api/auth/login', { username, password })
export const logout = () => http.post<void>('/api/auth/logout')
export const me = () => http.get<{ user: User }>('/api/auth/me')

// Overview -------------------------------------------------------------------------------

export const overview = (hours = 24) => http.get<Overview>('/api/stats/overview', { hours })

// Hosts ----------------------------------------------------------------------------------

export const listHosts = (f: HostFilter = {}) =>
  http.get<{ hosts: Host[]; total: number }>('/api/hosts', { ...f })
export const getHost = (id: string) => http.get<Host>(`/api/hosts/${enc(id)}`)
export const updateHostLabels = (id: string, labels: string[]) =>
  http.patch<Host>(`/api/hosts/${enc(id)}`, { labels })
export const revokeHost = (id: string) => http.del(`/api/hosts/${enc(id)}`)
export const decommissionHost = (id: string) => http.post<Host>(`/api/hosts/${enc(id)}/decommission`)
export const recommissionHost = (id: string) => http.post<Host>(`/api/hosts/${enc(id)}/recommission`)
export const updateHostNow = (id: string) => http.post<Host>(`/api/hosts/${enc(id)}/update-now`)
export const getAgentLifecycle = () => http.get<AgentLifecycleView>('/api/settings/agent-lifecycle')
export const putAgentLifecycle = (l: AgentLifecycle) => http.put<AgentLifecycleView>('/api/settings/agent-lifecycle', l)
export const hostAction = (id: string, cmd: CommandRequest) =>
  http.post<CommandRecord>(`/api/hosts/${enc(id)}/actions`, cmd)
export const hostCommands = (id: string) =>
  http.get<{ commands: CommandRecord[] }>(`/api/hosts/${enc(id)}/commands`)
export const hostTimeline = (id: string, f: TimelineFilter = {}) =>
  http.get<{ events: Event[] }>(`/api/hosts/${enc(id)}/timeline`, { ...f })

// Commands -------------------------------------------------------------------------------

export const getCommand = (id: string) => http.get<CommandRecord>(`/api/commands/${enc(id)}`)
export const commandRows = (id: string, limit = 100, offset = 0) =>
  http.get<{ rows: Row[]; total: number }>(`/api/commands/${enc(id)}/rows`, { limit, offset })
export const commandDownloadUrl = (id: string) => `/api/commands/${enc(id)}/download`

/** Fetches a file.get upload and hands it to the browser as a download. */
export async function downloadCommandFile(id: string, fallbackName: string) {
  const res = await rawRequest('GET', commandDownloadUrl(id))
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') ?? ''
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd)
  const name = m ? decodeURIComponent(m[1]) : fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

// Events ---------------------------------------------------------------------------------

export const searchEvents = (req: SearchRequest) => http.post<SearchResponse>('/api/events/search', req)
export const getEvent = (id: string) => http.get<Event>(`/api/events/${enc(id)}`)

// Process trees --------------------------------------------------------------------------

export const processTree = (hostId: string, entityId: string, depth = 3) =>
  http.get<{ root: ProcessNode }>('/api/process-tree', { host_id: hostId, entity_id: entityId, depth })
export const processEvents = (hostId: string, entityId: string, category?: ProcessEventCategory, limit = 200) =>
  http.get<{ events: Event[] }>('/api/process-events', { host_id: hostId, entity_id: entityId, category, limit })

// Alerts ---------------------------------------------------------------------------------

export const listAlerts = (f: AlertFilter = {}) =>
  http.get<{ alerts: Alert[]; total: number }>('/api/alerts', { ...f })
export const getAlert = (id: string) => http.get<Alert>(`/api/alerts/${enc(id)}`)
export const patchAlert = (id: string, patch: AlertPatch) => http.patch<Alert>(`/api/alerts/${enc(id)}`, patch)
export const getAlertTriage = (id: string) => http.get<AlertTriageResponse>(`/api/alerts/${enc(id)}/triage`)
export const requestAlertTriage = (id: string) => http.post<AITriage>(`/api/alerts/${enc(id)}/triage`, {})
export const bulkAlerts = (ids: string[], patch: AlertPatch) =>
  http.post<{ updated: number }>('/api/alerts/bulk', { ids, ...patch })
export const addAlertNote = (id: string, text: string) => http.post<Alert>(`/api/alerts/${enc(id)}/notes`, { text })

// Rules ----------------------------------------------------------------------------------

export const listRules = async (f: RuleFilter = {}) => {
  const res = await http.get<{ rules: Rule[] | null; total: number; load_errors?: RuleLoadError[] | null }>('/api/rules', { ...f })
  return { ...res, rules: (res.rules ?? []).map(normalizeRule), load_errors: res.load_errors ?? [] }
}
export const getRule = async (id: string) => normalizeRule(await http.get<Rule>(`/api/rules/${enc(id)}`))
export const createRule = async (yaml: string) => normalizeRule(await http.post<Rule>('/api/rules', { yaml }))
export const updateRule = async (id: string, yaml: string) => normalizeRule(await http.put<Rule>(`/api/rules/${enc(id)}`, { yaml }))
export const setRuleEnabled = async (id: string, enabled: boolean) =>
  normalizeRule(await http.patch<Rule>(`/api/rules/${enc(id)}`, { enabled }))
export const deleteRule = (id: string) => http.del(`/api/rules/${enc(id)}`)
export const validateRule = async (yaml: string) => normalizeValidate(await http.post<RuleValidateResponse>('/api/rules/validate', { yaml }))
export const testRule = (yaml: string, hours?: number) => http.post<RuleTestResponse>('/api/rules/test', { yaml, hours })
/** Re-read the server's rules folder now (it is also checked once a minute). */
export const reloadRules = async () => {
  const res = await http.post<{ total: number; enabled: number; load_errors?: RuleLoadError[] | null }>('/api/rules/reload', {})
  return { ...res, load_errors: res.load_errors ?? [] }
}

// Rule repositories ----------------------------------------------------------------------

export const listRuleRepos = async () => {
  const res = await http.get<{ repos: RuleRepo[] | null }>('/api/rule-repos')
  return (res.repos ?? []).map(normalizeRuleRepo)
}
export const getRuleRepo = async (id: string) => normalizeRuleRepo(await http.get<RuleRepo>(`/api/rule-repos/${enc(id)}`))
/** Adds a repository and starts the first download (`syncing` until it finishes). */
export const addRuleRepo = async (s: Partial<RuleRepoSettings> & { url: string }) =>
  normalizeRuleRepo(await http.post<RuleRepo>('/api/rule-repos', s))
export const patchRuleRepo = async (id: string, s: Partial<RuleRepoSettings>) =>
  normalizeRuleRepo(await http.patch<RuleRepo>(`/api/rule-repos/${enc(id)}`, s))
export const deleteRuleRepo = (id: string) => http.del(`/api/rule-repos/${enc(id)}`)
/** Every rule in the installed download (for choosing folders), and the chosen ones that are not loaded. */
export const ruleRepoFiles = async (id: string) => {
  const res = await http.get<{ files: RuleRepoFile[] | null; skipped: RuleRepoSkip[] | null }>(`/api/rule-repos/${enc(id)}/files`)
  return { files: res.files ?? [], skipped: res.skipped ?? [] }
}
/** Enables or disables every loaded rule of a repository. */
export const setRuleRepoRulesEnabled = (id: string, enabled: boolean) =>
  http.post<{ changed: number }>(`/api/rule-repos/${enc(id)}/rules/enabled`, { enabled })
/** Looks for a new version without installing it. */
export const checkRuleRepo = async (id: string) => normalizeRuleRepo(await http.post<RuleRepo>(`/api/rule-repos/${enc(id)}/check`, {}))
/** Downloads and installs the newest version in the background. */
export const updateRuleRepo = async (id: string) => normalizeRuleRepo(await http.post<RuleRepo>(`/api/rule-repos/${enc(id)}/update`, {}))

// Artifacts and hunts --------------------------------------------------------------------

export const listArtifacts = () => http.get<{ artifacts: ArtifactDef[] }>('/api/artifacts')
export const createHunt = (h: HuntCreate) => http.post<Hunt>('/api/hunts', h)
export const listHunts = () => http.get<{ hunts: Hunt[] }>('/api/hunts')
export const getHunt = (id: string) => http.get<Hunt>(`/api/hunts/${enc(id)}`)
export const stopHunt = (id: string) => http.post<Hunt>(`/api/hunts/${enc(id)}/stop`)
export const huntResults = (id: string, opts: { host_id?: string; limit?: number; offset?: number } = {}) =>
  http.get<{ rows: HuntResultRow[]; total: number }>(`/api/hunts/${enc(id)}/results`, { ...opts })

// Settings and admin ---------------------------------------------------------------------

export const serverSettings = () => http.get<ServerSettings>('/api/settings/server')
export const getAISettings = () => http.get<AISettings>('/api/settings/ai')
export const putAISettings = (s: AISettingsUpdate) => http.put<AISettings>('/api/settings/ai', s)
export const testAISettings = (s: AISettingsUpdate) => http.post<{ ok: boolean; model?: string; error?: string }>('/api/settings/ai/test', s)
export const listAIModels = (s: AISettingsUpdate) => http.post<{ models: string[]; error?: string }>('/api/settings/ai/models', s)
export const listMCPTokens = () => http.get<{ tokens: MCPToken[] }>('/api/settings/ai/mcp-tokens')
export const createMCPToken = (name: string) => http.post<MCPToken>('/api/settings/ai/mcp-tokens', { name })
export const deleteMCPToken = (id: string) => http.del<void>(`/api/settings/ai/mcp-tokens/${enc(id)}`)
export const listTokens = () => http.get<{ tokens: EnrollmentToken[] }>('/api/enrollment-tokens')
export const createToken = (t: EnrollmentTokenCreate) => http.post<EnrollmentToken>('/api/enrollment-tokens', t)
export const deleteToken = (id: string) => http.del(`/api/enrollment-tokens/${enc(id)}`)
export const getAgentConfig = () => http.get<AgentConfig>('/api/agent-config')
export const putAgentConfig = (c: AgentConfig) => http.put<AgentConfig>('/api/agent-config', c)
export const listUsers = () => http.get<{ users: User[] }>('/api/users')
export const createUser = (u: { username: string; password: string; role: Role }) => http.post<User>('/api/users', u)
export const patchUser = (id: string, p: { role?: Role; password?: string }) => http.patch<User>(`/api/users/${enc(id)}`, p)
export const deleteUser = (id: string) => http.del(`/api/users/${enc(id)}`)
export const audit = (limit = 100, offset = 0) =>
  http.get<{ entries: AuditEntry[]; total: number }>('/api/audit', { limit, offset })
export const integrations = () => http.get<Integrations>('/api/integrations')
export const health = () => http.get<Health>('/healthz')
