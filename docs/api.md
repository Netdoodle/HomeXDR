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
| GET | `/api/hosts?q=&status=&label=&platform=` | `{"hosts": Host[], "total": n}`; `q` matches hostname/IP |
| GET | `/api/hosts/{id}` | `Host` |
| PATCH | `/api/hosts/{id}` | `{"labels": string[]}` → `Host` (analyst+) |
| DELETE | `/api/hosts/{id}` | revokes the agent certificate (admin) → `204` |
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
  status: "online" | "offline" | "isolated" | "revoked";   // online = heartbeat within 3 intervals
  isolated: boolean;
  last_seen?: string; enrolled_at: string;
  labels: string[];
  sensors?: { name: string; impl: string; state: "running" | "degraded" | "failed" | "disabled"; error?: string; events: number }[];
  queue_events?: number;
  allowed_actions?: string[];
  open_alerts: number;
  boot_time?: string; cpus?: number; memory_bytes?: number;
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
{ query: string; from?: string; to?: string; host_id?: string; limit?: number; offset?: number; order?: "asc" | "desc" }
// response
{ events: Event[]; total?: number; took_ms: number }
```

Query language (translated server-side into parameterized SQL; never string-concatenated):

- `field:value` exact match (case-insensitive for strings), `field:val*` / `*val` / `*val*`
  wildcards, `field:"quoted value"` (matched literally: `*` and `?` are not wildcards inside
  quotes; `\"` and `\\` escape), `field:>10`, `field:<=443`
- A field name ends at the first colon, so `file.path:C:\Temp\x.exe` needs no quotes
- `AND`, `OR`, `NOT` (uppercase only), `-term`, parentheses; adjacent terms are ANDed
- Bare words do a substring match on `message`, `process.command_line` and `file.path`
- Field names are ECS paths from `shared/event` (`process.name`, `destination.ip`,
  `event.category`, `host.name`, `data.LogonType`, ...)
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
}
```

Risk score from severity: informational 10, low 21, medium 47, high 73, critical 99.

## Rules

| Method | Path | Notes |
|---|---|---|
| GET | `/api/rules?q=&enabled=&level=&source=` | `{"rules": Rule[], "total": n, "load_errors": {path, error}[]}`; `load_errors` lists rule files that could not be loaded |
| GET | `/api/rules/{id}` | `Rule` including `yaml` |
| POST | `/api/rules` | `{"yaml"}` → `Rule` (admin); validates and compiles first |
| PUT | `/api/rules/{id}` | `{"yaml"}` → `Rule` (admin, custom rules only) |
| PATCH | `/api/rules/{id}` | `{"enabled": bool}` → `Rule` (admin, any rule) |
| DELETE | `/api/rules/{id}` | custom only → `204` |
| POST | `/api/rules/reload` | admin; re-reads the rules folder now → `{"total", "enabled", "load_errors"}` (the folder is also checked every minute) |
| POST | `/api/rules/validate` | `{"yaml"}` → `{"ok": bool, "error"?: string, "rule"?: Rule}` |
| POST | `/api/rules/test` | `{"yaml", "hours"?: number}` → `{"matches": Event[], "scanned": n}`: runs the rule over recent stored events |

```ts
type Rule = {
  id: string; title: string; description?: string; status?: string; level: Severity;
  enabled: boolean; source: "builtin" | "custom";
  tags: string[]; author?: string; references?: string[];
  logsource: { product?: string; category?: string; service?: string };
  mitre: { tactic?: string; technique_id?: string; technique?: string }[];
  hits_24h: number; updated_at: string;
  yaml?: string;
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
| GET | `/api/settings/server` | `{"version", "agent_url", "ca_pin", "server_names": string[], "event_store": "clickhouse"\|"sqlite", "retention_days": n, "syslog_addr"}` |
| GET | `/api/enrollment-tokens` | `{"tokens": EnrollmentToken[]}` (admin; `token` value omitted) |
| POST | `/api/enrollment-tokens` | `{"name", "expires_hours"?, "max_uses"?, "labels"?}` → `EnrollmentToken` with `token` (shown once) |
| DELETE | `/api/enrollment-tokens/{id}` | `204` |
| GET | `/api/agent-config` | `AgentConfig` (default config, `shared/api.AgentConfig` shape) |
| PUT | `/api/agent-config` | `AgentConfig` → `AgentConfig` (admin; bumps `version`) |
| GET | `/api/users` | `{"users": User[]}` (admin) |
| POST | `/api/users` | `{"username","password","role"}` → `User` (admin) |
| PATCH | `/api/users/{id}` | `{"role"?, "password"?}` → `User` (admin, or self for password) |
| DELETE | `/api/users/{id}` | `204` (admin; cannot delete self) |
| GET | `/api/audit?limit=&offset=` | `{"entries": {id, at, user, action, target, details}[], "total": n}` (admin) |
| GET | `/api/integrations` | `{"syslog": {"listening": bool, "addr", "received": n, "parsed": n, "failed": n, "sources": {ip, name, kind, last_seen, count}[]}}` |

```ts
type EnrollmentToken = {
  id: string; name: string; token?: string; created_at: string; created_by: string;
  expires_at?: string; max_uses?: number; uses: number; labels: string[];
}
```

The settings page shows ready-to-copy install commands built from `agent_url`, `ca_pin`
and a token:

```
# Linux
curl -fsSLk https://<server>:8443/v1/install/linux.sh | sudo sh -s -- --token <token> --ca-pin <pin>
# Windows (elevated PowerShell)
homexdr-agent.exe install --server https://<server>:8443 --token <token> --ca-pin <pin>
```

## Health

`GET /healthz` (no auth) → `{"status": "ok", "event_store": "ok" | "error: ..."}`.
