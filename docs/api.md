# Console REST API

Served by `homexdr-server` on the HTTP listener (default `:8080`) under `/api`. The web
console is served from `/` on the same listener. This document is the contract between
`server/` and `web/`; change both together.

Conventions:

- JSON in and out. Timestamps are RFC 3339 strings in UTC.
- Errors: non-2xx status with `{"error": "human readable message"}`.
- Auth: session cookie `homexdr_session` (HttpOnly, SameSite=Strict). `401` when missing or
  expired. The UI redirects to `/login` on 401.
- CSRF: every non-GET request must send `X-HomeXDR-CSRF: 1`, otherwise `403`.
- Roles: `admin` (everything), `analyst` (triage, search, response actions, hunts),
  `viewer` (read-only). `403` when the role is insufficient.
- Lists take `limit` (default 100, max 1000) and `offset`, and return `total` when cheap.

## Setup and auth

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/setup/status` | | `{"needs_setup": bool, "version": string}` |
| POST | `/api/setup` | `{"username","password"}` | `{"user": User}` (only when no users exist; logs in) |
| POST | `/api/auth/login` | `{"username","password"}` | `{"user": User}` + cookie |
| POST | `/api/auth/logout` | | `204` |
| GET | `/api/auth/me` | | `{"user": User}` |

```ts
type User = { id: string; username: string; role: "admin" | "analyst" | "viewer"; created_at: string; last_login?: string }
```

Passwords must be at least 10 characters. Login is rate limited per username and IP.

## Overview

`GET /api/stats/overview?hours=24`

```ts
type Overview = {
  hosts_total: number; hosts_online: number; hosts_isolated: number;
  alerts_open: number;
  alerts_by_severity: { critical: number; high: number; medium: number; low: number; informational: number };
  events_total: number;                       // in the window
  events_timeline: { t: string; count: number }[];   // hourly buckets
  alerts_timeline: { t: string; count: number }[];
  top_rules: { rule_id: string; title: string; severity: Severity; count: number }[];
  top_hosts: { host_id: string; hostname: string; alerts: number }[];
  events_by_category: { category: string; count: number }[];
}
type Severity = "critical" | "high" | "medium" | "low" | "informational"
```

## Hosts

| Method | Path | Notes |
|---|---|---|
| GET | `/api/hosts?q=&status=&label=&platform=&include_decommissioned=` | `{"hosts": Host[], "total": n}`; `q` matches hostname/IP. Decommissioned agents are left out unless `status=decommissioned` or `include_decommissioned=true` |
| GET | `/api/hosts/{id}` | `Host` |
| PATCH | `/api/hosts/{id}` | `{"labels": string[]}` → `Host` (analyst+) |
| DELETE | `/api/hosts/{id}` | revokes the agent certificate (admin) → `204` |
| POST | `/api/hosts/{id}/decommission` | → `Host` (admin, audited): hides an endpoint agent until it reconnects |
| POST | `/api/hosts/{id}/recommission` | → `Host` (admin, audited): restores it now |
| POST | `/api/hosts/{id}/update-now` | → `Host` (admin, audited): offer the agent its target release at the next heartbeat, ignoring the maintenance window and staged rollout |
| POST | `/api/hosts/{id}/actions` | `{"type": CommandType, "params": {...}}` → `CommandRecord` (analyst+) |
| GET | `/api/hosts/{id}/commands` | `{"commands": CommandRecord[]}` newest first |
| GET | `/api/hosts/{id}/timeline?from=&to=&category=&limit=` | `{"events": Event[]}` newest first |

```ts
type Host = {
  id: string;                      // agent id
  hostname: string;
  kind: "endpoint" | "network";    // network = syslog source (firewall, IDS)
  os: { platform: "windows" | "linux" | "darwin" | "network"; family?: string; name?: string; version?: string; kernel?: string };
  arch?: string; ips: string[]; macs?: string[];
  agent_version?: string;
  status: "online" | "offline" | "isolated" | "revoked" | "decommissioned";   // online = heartbeat within 3 intervals
  isolated: boolean;
  last_seen?: string; enrolled_at: string;
  cert_expires?: string;           // the agent's client certificate (renewed automatically)
  decommissioned_at?: string;
  update_now_at?: string;          // "Update now" requested and not yet fulfilled
  update_offered?: string; update_offered_at?: string;   // last release offered
  update_error?: string;           // "<version>: <error>" from the agent's last failed install
  update?: HostUpdate;             // endpoint agents only (below)
  labels: string[];
  sensors?: { name: string; impl: string; state: "running" | "degraded" | "failed" | "disabled"; error?: string; events: number }[];
  queue_events?: number;
  allowed_actions?: string[];
  open_alerts: number;
  boot_time?: string; cpus?: number; memory_bytes?: number;
}
type UpdateRule = { mode: "latest" | "n-1" | "pinned" | "off"; version?: string };  // version: pinned only
type HostUpdate = {
  rule: UpdateRule;
  source: string;                  // "default" or the label whose rule applies
  target?: string;                 // release version the policy picks
  state: "current" | "pending" | "updating" | "failed" | "ahead" | "off" | "none";
  reason?: string;                 // e.g. "waiting for the maintenance window (02:00-05:00 UTC)"
}
```

## Commands (response actions and collections)

`CommandType` is one of `process.kill`, `host.isolate`, `host.release`,
`file.quarantine`, `file.restore`, `file.get`, `file.hash`, `artifact.collect`.
There is no arbitrary-command type. Params match `shared/api/agent.go` (`KillParams`, `IsolateParams`, ...). The
server rejects types not in the host's `allowed_actions` with `409`.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/commands/{id}` | `CommandRecord` |
| GET | `/api/commands/{id}/rows?limit=&offset=` | `{"rows": object[], "total": n}` (artifact output) |
| GET | `/api/commands/{id}/download` | the uploaded file (`file.get`), as `application/octet-stream` |

```ts
type CommandRecord = {
  id: string; host_id: string; hostname: string; type: string; params: any;
  status: "queued" | "delivered" | "running" | "completed" | "failed" | "rejected" | "expired";
  issued_by: string; issued_at: string; expires_at: string;
  delivered_at?: string; completed_at?: string;
  error?: string; output?: any; row_count?: number;
  hunt_id?: string;
}
```

## Events

`POST /api/events/search`

```ts
// request
{ query: string; from?: string; to?: string; host_id?: string; limit?: number; offset?: number;
  order?: "asc" | "desc"; timeline?: boolean }
// response
{
  mode: "events" | "table";
  events: Event[];                       // events mode (empty for tables)
  extra?: Record<string, unknown>[];     // eval / rex fields, one per event
  total: number;                         // matching events, or table rows
  columns?: { name: string; type: "string" | "number" | "time" | "bool" | "array" }[];
  rows?: unknown[][];                    // table mode; times are RFC 3339 strings
  truncated?: boolean;                   // more than 10,000 rows
  chart?: "timechart";                   // rows are _time, then one column per series
  timeline?: { t: string; count: number }[];  // with timeline: true, the filter's events over time
  timeline_span?: number;                // bucket size in seconds of timeline / the timechart
  took_ms: number;
}
```

`query` is a filter, optionally followed by Splunk-style commands
(`index=opnsense | stats count by src`); see [search.md](search.md) for the full language.
It is compiled server-side into a single parameterized SQL query; user values never become
SQL text. `from` defaults to 24 hours ago when neither bound is given. An invalid query, or
one the database rejects (a type error, a resource limit), returns 400 with the reason.

Filter summary:

- `field:value` or `field=value` (case-insensitive), `field!=value`, `field:val*` wildcards,
  `field:"quoted value"` (literal; `\"` and `\\` escape), `field:>10` or `field>10`
- `AND`, `OR`, `NOT` (uppercase), `&&`, `||`, `!`, `-term`, parentheses; adjacent terms are ANDed
- Bare words do a substring match on `message`, `process.command_line` and `file.path`
- Field names are ECS paths from `shared/event`; Splunk names such as `index`, `src`,
  `dest_port` are accepted, and bare unknown names mean `data.<name>`
- An empty query returns the newest events

Example: `event.category:process AND process.name:powershell.exe AND NOT user.name:SYSTEM`

`GET /api/events/{id}` → `Event` (the `shared/event.Event` JSON shape).

## Process trees

`GET /api/process-tree?host_id=&entity_id=&depth=3`

Returns the ancestors of `entity_id` up to the root, the process itself, and descendants
up to `depth` levels.

```ts
type ProcessNode = {
  entity_id: string; pid: number; name: string; executable?: string; command_line?: string;
  user?: string; start?: string; end?: string; exit_code?: number;
  parent_entity_id?: string;
  hash_sha256?: string; signed?: boolean;
  alert_count: number;
  event_counts: { network: number; file: number; registry: number; dns: number; library: number };
  children: ProcessNode[];
  is_target?: boolean;     // the requested entity
}
// response
{ root: ProcessNode }
```

`GET /api/process-events?host_id=&entity_id=&category=&limit=` → `{"events": Event[]}`:
the network/file/registry/dns events attributed to one process.

## Alerts

| Method | Path | Notes |
|---|---|---|
| GET | `/api/alerts?status=&severity=&host_id=&rule_id=&q=&limit=&offset=` | `{"alerts": Alert[], "total": n}`; `status` and `severity` accept comma lists |
| GET | `/api/alerts/{id}` | `Alert` with `events` (up to 20 matching events) |
| PATCH | `/api/alerts/{id}` | `{"status"?, "assignee"?}` → `Alert` (analyst+) |
| POST | `/api/alerts/bulk` | `{"ids": string[], "status"?, "assignee"?}` → `{"updated": n}` |
| POST | `/api/alerts/{id}/notes` | `{"text"}` → `Alert` |
| GET | `/api/alerts/{id}/triage` | `{"triage": AITriage \| null, "available": bool, "reason"?: string}` (AI analyst, below) |
| POST | `/api/alerts/{id}/triage` | queue an AI investigation → `202 AITriage` (analyst+); `409` if one is queued/running or the analyst is not set up |

```ts
type Alert = {
  id: string; created_at: string; updated_at: string;
  first_seen: string; last_seen: string; count: number;      // de-duplicated hits
  status: "new" | "in_progress" | "resolved" | "false_positive";
  severity: Severity; risk_score: number;                       // 0-100
  assignee?: string;
  rule: { id: string; title: string; description?: string; level: Severity; tags: string[]; references?: string[]; false_positives?: string[] };
  mitre: { tactic?: string; technique_id?: string; technique?: string }[];
  host_id: string; hostname: string;
  process_entity_id?: string; process_name?: string; command_line?: string; user?: string;
  event_ids: string[];
  event?: Event;                 // the first matching event
  events?: Event[];              // detail view only
  notes: { author: string; text: string; at: string }[];
  ai_triage?: { status: AITriageStatus; verdict?: AIVerdict; confidence?: "low" | "medium" | "high" };
}
```

Risk score from severity: informational 10, low 21, medium 47, high 73, critical 99.

## AI analyst

See [ai-analyst.md](ai-analyst.md). The AI only writes its report; nothing here lets it
change alerts or anything else.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/settings/ai` | `AISettings` (admin) |
| PUT | `/api/settings/ai` | `AISettingsUpdate` → `AISettings` (admin); audited without the key |
| POST | `/api/settings/ai/test` | `AISettingsUpdate` → `{"ok": bool, "model"?: string, "error"?: string}` (admin): a minimal request with the given values |
| POST | `/api/settings/ai/models` | `AISettingsUpdate` → `{"models": string[], "error"?: string}` (admin): the models the selected provider offers |
| GET | `/api/settings/ai/mcp-tokens` | `{"tokens": MCPToken[]}` (admin) |
| POST | `/api/settings/ai/mcp-tokens` | `{"name"}` → `MCPToken` with `token` (`hxm_...`), shown once (admin, audited) |
| DELETE | `/api/settings/ai/mcp-tokens/{id}` | 204 (admin, audited): revokes the token |

The MCP endpoint is outside `/api` and takes `Authorization: Bearer hxm_...` instead of a
session; it answers only while `mcp_enabled` is on:

| Method | Path | |
|---|---|---|
| POST | `/mcp` | MCP Streamable HTTP (JSON responses, no sessions): `initialize`, `ping`, `tools/list`, `tools/call` |
| GET | `/mcp/status` | `{"engine", "auto_trigger", "pending", "run", "ready", "not_ready_reason"}` for the MCP runner; `X-HomeXDR-Runner: <name>` records the runner |

```ts
type AIVerdict = "benign" | "suspicious" | "malicious" | "inconclusive"
type AITriageStatus = "queued" | "running" | "done" | "failed" | "refused" | "skipped"
type AITriage = {
  alert_id: string; status: AITriageStatus; trigger: "auto" | "manual"; requested_by?: string;
  provider?: string; model?: string; verdict?: AIVerdict; confidence?: "low" | "medium" | "high";
  report?: {
    verdict: AIVerdict; confidence: string; severity_assessment: Severity; summary: string; analysis: string;
    evidence: { event_id: string; observation: string }[]; mitre: { technique_id: string; name: string }[];
    recommended_actions: { action: string; reason: string }[]; open_questions: string[];
  };
  transcript?: { tool: string; input: any; output: string; error?: boolean; at: string; ms: number }[];
  error?: string; tool_calls: number;
  usage: { input_tokens: number; output_tokens: number; cache_read_tokens: number };
  created_at: string; started_at?: string; finished_at?: string;
}
type AISettings = {
  enabled: boolean; provider: "anthropic" | "openai" | "gemini" | "local"; model: string; base_url?: string;
  min_severity: Severity; daily_limit: number; max_tool_calls: number;
  key_set: boolean; key_source?: "settings" | "environment"; key_hint?: string;   // selected provider; keys are never returned
  keys: Record<string, { set: boolean; source?: "settings" | "environment"; hint?: string }>;
  ready: boolean; not_ready_reason?: string;
  providers: { id: string; name: string; available: boolean; default_base_url?: string;
               needs_key: boolean; needs_base_url: boolean; key_env: string }[];
  default_model: string; auto_today: number;
  engine: "api" | "mcp";          // who runs investigations: the server (API) or an MCP client
  mcp_enabled: boolean;           // the /mcp endpoint answers MCP tokens
  mcp_auto_trigger: boolean;      // engine mcp: queue new alerts for the MCP runner
  mcp: { pending: number; tokens: number; runner_name?: string; runner_seen_at?: string };
}
type MCPToken = { id: string; name: string; token?: string; created_at: string; created_by: string; last_used_at?: string }
// Alerts' ai_triage records also carry engine: "api" | "mcp".
// AISettingsUpdate: the editable fields of AISettings (including base_url and the engine
// and MCP switches), plus api_key
// (sets the selected provider's key when not empty) and clear_api_key. Other providers'
// keys are kept.
```

## Rules

| Method | Path | Notes |
|---|---|---|
| GET | `/api/rules?q=&enabled=&level=&source=&repo=` | `{"rules": Rule[], "total": n, "load_errors": {path, error}[]}`; `load_errors` lists rule files that could not be loaded; `source` is `builtin`, `custom` or `repo`, `repo` a rule repository ID |
| GET | `/api/rules/{id}` | `Rule` including `yaml` |
| POST | `/api/rules` | `{"yaml"}` → `Rule` (admin); validates and compiles first |
| PUT | `/api/rules/{id}` | `{"yaml"}` → `Rule` (admin, custom rules only) |
| PATCH | `/api/rules/{id}` | `{"enabled": bool}` → `Rule` (admin, any rule; kept by rule ID across reloads and repository updates) |
| DELETE | `/api/rules/{id}` | custom only → `204` |
| POST | `/api/rules/reload` | admin; re-reads the rules folder now → `{"total", "enabled", "load_errors"}` (the folder is also checked every minute) |
| POST | `/api/rules/validate` | `{"yaml"}` → `{"ok": bool, "error"?: string, "rule"?: Rule}` |
| POST | `/api/rules/test` | `{"yaml", "hours"?: number}` → `{"matches": Event[], "scanned": n}`: runs the rule over recent stored events |

```ts
type Rule = {
  id: string; title: string; description?: string; status?: string; level: Severity;
  enabled: boolean; source: "builtin" | "custom" | "repo";
  tags: string[]; author?: string; references?: string[];
  logsource: { product?: string; category?: string; service?: string };
  mitre: { tactic?: string; technique_id?: string; technique?: string }[];
  hits_24h: number; updated_at: string;
  yaml?: string;
  repo?: { id: string; name: string; path: string; url?: string };  // source "repo": file, and link upstream
}
```

## Rule repositories

Sigma rule collections the server downloads and keeps updated: a public git repository
(GitHub, GitLab, Gitea/Forgejo, Bitbucket) or a `.zip` / `.tar.gz` URL. See
[rules/README.md](../rules/README.md#importing-a-rule-repository).

| Method | Path | Notes |
|---|---|---|
| GET | `/api/rule-repos` | `{"repos": RuleRepo[]}` in precedence order |
| POST | `/api/rule-repos` | `RuleRepoSettings` (only `url` required) → `201 RuleRepo` (admin, audited); starts the first download, `syncing` is true until it finishes |
| GET | `/api/rule-repos/{id}` | `RuleRepo` |
| PATCH | `/api/rule-repos/{id}` | any `RuleRepoSettings` fields → `RuleRepo` (admin, audited). A new `url` or `ref` downloads again; other changes reload the files already downloaded |
| DELETE | `/api/rule-repos/{id}` | `204` (admin); removes its files and rules, keeps enabled/disabled choices |
| POST | `/api/rule-repos/{id}/check` | → `RuleRepo` (admin): looks for a new version without installing it (`update_available`, `latest_version`) |
| POST | `/api/rule-repos/{id}/update` | → `202 RuleRepo` (admin): downloads and installs the newest version in the background |

Check, update and delete answer `409` while the repository is being updated. Download and
network failures are not request errors: they are recorded in `error` and retried within an
hour.

```ts
type RuleRepoSettings = {
  url: string;                 // repository or archive URL; "owner/repo" means GitHub.
                               // A folder link (…/tree/<branch>/<folder>) fills ref and paths.
  name?: string;               // default: from the URL
  ref?: string;                // branch, tag or commit; "" = default branch (ignored for archives)
  paths?: string[];            // folders to load; [] = whole repository
  min_level?: Severity | "";   // skip rules below this level
  statuses?: ("stable" | "test" | "experimental" | "deprecated" | "unsupported")[];
                               // [] = all but deprecated and unsupported
  enable_rules?: boolean;      // rules start enabled (default true)
  auto_update?: boolean;       // install new versions when found (default true);
                               // false = only report them
  interval_hours?: number;     // 1–720, default 24
  enabled?: boolean;           // default true
}
type RuleRepo = Required<RuleRepoSettings> & {
  id: string; kind: "git" | "archive";
  version?: string;            // installed commit, or "sha256:<hex>" of an archive
  latest_version?: string;     // newest version found by the last check
  update_available: boolean; syncing: boolean;
  checked_at?: string; installed_at?: string; next_check_at?: string;
  error?: string;              // last failure
  files: number;               // .yml/.yaml files downloaded
  folders: { path: string; files: number }[];  // up to 3 levels, for choosing paths
  added: number; removed: number;              // rule IDs the last update added and removed
  rules: number; rules_enabled: number;        // loaded from this repository
  filtered: number;            // skipped by min_level or statuses
  duplicates: number;          // skipped because another source has the rule ID
  load_errors: number;         // files that failed to load (listed in GET /api/rules)
  browse_url?: string;         // installed version upstream (git)
  created_at: string; created_by: string;
}
```

## Artifacts and hunts

| Method | Path | Notes |
|---|---|---|
| GET | `/api/artifacts` | `{"artifacts": ArtifactDef[]}` (catalog from `shared/api/artifacts.go`) |
| POST | `/api/hunts` | `{"artifact", "params"?, "description"?, "target": {"all"?: bool, "labels"?: string[], "host_ids"?: string[], "platform"?: string}, "expires_hours"?: number}` → `Hunt` (analyst+) |
| GET | `/api/hunts` | `{"hunts": Hunt[]}` |
| GET | `/api/hunts/{id}` | `Hunt` |
| POST | `/api/hunts/{id}/stop` | → `Hunt` |
| GET | `/api/hunts/{id}/results?host_id=&limit=&offset=` | `{"rows": {host_id, hostname, row: object}[], "total": n}` |

```ts
type Hunt = {
  id: string; artifact: string; params: Record<string,string>; description?: string;
  target: { all?: boolean; labels?: string[]; host_ids?: string[]; platform?: string };
  status: "running" | "stopped" | "completed";
  created_by: string; created_at: string; expires_at: string;
  stats: { scheduled: number; completed: number; failed: number; rows: number };
}
```

A hunt queues one `artifact.collect` command per matching host, and also for matching hosts
that enroll or come online before it expires.

## Settings and admin

| Method | Path | Notes |
|---|---|---|
| GET | `/api/settings/server` | `ServerSettings` (below) |
| GET | `/api/enrollment-tokens` | `{"tokens": EnrollmentToken[]}` (admin; `token` value omitted) |
| POST | `/api/enrollment-tokens` | `{"name", "expires_hours"?, "max_uses"?, "labels"?}` → `EnrollmentToken` with `token` (shown once) |
| DELETE | `/api/enrollment-tokens/{id}` | `204` |
| GET | `/api/agent-config` | `AgentConfig` (default config, `shared/api.AgentConfig` shape) |
| PUT | `/api/agent-config` | `AgentConfig` → `AgentConfig` (admin; bumps `version`) |
| GET | `/api/settings/agent-lifecycle` | `AgentLifecycleView` (admin) |
| PUT | `/api/settings/agent-lifecycle` | `AgentLifecycle` → `AgentLifecycleView` (admin, audited); `400` with the problem when invalid |
| GET | `/api/users` | `{"users": User[]}` (admin) |
| POST | `/api/users` | `{"username","password","role"}` → `User` (admin) |
| PATCH | `/api/users/{id}` | `{"role"?, "password"?}` → `User` (admin, or self for password) |
| DELETE | `/api/users/{id}` | `204` (admin; cannot delete self) |
| GET | `/api/audit?limit=&offset=` | `{"entries": {id, at, user, action, target, details}[], "total": n}` (admin) |
| GET | `/api/integrations` | `{"syslog": {"listening": bool, "addr", "received": n, "parsed": n, "failed": n, "sources": {ip, name, kind, last_seen, count}[]}}` |

```ts
type ServerSettings = {
  version: string; agent_url: string; ca_pin: string; server_names: string[];
  event_store: "clickhouse" | "sqlite";
  retention_days: number;          // 0 = no time limit
  retention_max_bytes: number;     // size cap, 0 = none
  event_store_bytes?: number;      // current size on disk
  syslog_addr: string;
  update_key?: string;             // release public key for signed agent updates
  agent_release: { version?: string; signed: boolean; update_key?: string; problem?: string };
}
type EnrollmentToken = {
  id: string; name: string; token?: string; created_at: string; created_by: string;
  expires_at?: string; max_uses?: number; uses: number; labels: string[];
}
type AgentLifecycle = {
  decommission_after_days: number; // 0 = never; endpoint agents offline this long are decommissioned
  updates: {
    default: UpdateRule;
    labels: { label: string; rule: UpdateRule }[];             // first match wins
    staged: { enabled: boolean; canary_label: string; delay_hours: number };
    window: { enabled: boolean; start: string; end: string; timezone: string };  // "HH:MM", IANA zone
  };
}
type AgentLifecycleView = {
  settings: AgentLifecycle;
  releases: { version: string; commit?: string; commit_time: number; archived_at: string;
              bundled: boolean; files: string[]; agents: number }[];   // newest first
  release_status: ServerSettings["agent_release"];
  canary_agents: number; decommissioned_agents: number;
}
```

See [protocol.md](protocol.md#agent-updates) for how the policy picks and offers releases.

The settings page shows ready-to-copy install commands built from `agent_url`, `ca_pin`
and a token:

```
# Linux (--update-key only when the server has a signed release)
curl -fsSLk https://<server>:8443/v1/install/linux.sh | sudo sh -s -- --token <token> --ca-pin <pin> [--update-key <key>]
# Windows (elevated PowerShell)
homexdr-agent.exe install --server https://<server>:8443 --token <token> --ca-pin <pin>
```

## Health

`GET /healthz` (no auth) → `{"status": "ok", "event_store": "ok" | "error: ..."}`.
