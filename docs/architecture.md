# HomeXDR architecture

HomeXDR is a self-hosted EDR/XDR with a built-in SIEM, sized for homelabs. It does
detection and response without a kernel driver: Windows telemetry comes from ETW and the
Event Log, Linux telemetry from eBPF (with netlink/procfs fallbacks), and network
telemetry from OPNsense and Suricata over syslog.

```
 Endpoints                                Server (docker compose)                     Browser
 ┌───────────────────────┐   HTTPS+mTLS   ┌──────────────────────────────────────┐
 │ homexdr-agent          │ ─────────────► │ agent API :8443                       │
 │  sensors ─► filters    │  events, hb,   │   enroll · heartbeat · events ·       │
 │  ─► disk spool ─► send │  long-poll cmd │   commands (signed, long-poll)        │
 │  command runner        │ ◄───────────── │                                       │
 │  (local policy gate)   │                │ ingest ─► enrich ─► detect (Sigma)    │
 └───────────────────────┘                │    │                    │             │
 ┌───────────────────────┐  syslog 514    │    ▼                    ▼             │   ┌─────────┐
 │ OPNsense / Suricata    │ ─────────────► │ syslog :5514 ─► decoders              │   │ web UI  │
 │ any syslog device      │                │                                       │◄──│ :8080   │
 └───────────────────────┘                │ event store: ClickHouse | SQLite      │   └─────────┘
                                           │ state store: SQLite (hosts, alerts,   │
                                           │   rules, commands, hunts, users)      │
                                           └──────────────────────────────────────┘
```

## Repository layout

| Path | What | Module |
|---|---|---|
| `shared/` | Event schema, agent wire protocol, Community ID, version | `github.com/Netdoodle/homexdr/shared` |
| `agent/` | Endpoint agent (`homexdr-agent`) for Windows and Linux, macOS later | `github.com/Netdoodle/homexdr/agent` |
| `server/` | Server (`homexdr-server`): ingest, detection, storage, REST API, syslog | `github.com/Netdoodle/homexdr/server` |
| `web/` | Web console (React + TypeScript + Vite), embedded into the server image | — |
| `rules/` | Built-in detection rules in Sigma format | — |
| `deploy/` | `docker-compose.yml`, example `.env`, install scripts | — |
| `docs/` | Design docs | — |

Each Go module has a `replace github.com/Netdoodle/homexdr/shared => ../shared`
directive, so modules build independently without a `go.work` file.

## Data flow

1. **Sensors** on the agent emit `event.Event` records (see `shared/event`).
2. The agent applies **filters** from its central config, then appends events to an
   on-disk **spool** (bounded by `spool_max_bytes`, oldest segments dropped first) so
   nothing is lost while the server is unreachable.
3. A sender drains the spool in batches to `POST /v1/events` as gzip NDJSON.
4. The server **ingest** stage overwrites `agent.id` with the identity from the client
   certificate, fills `host.*` from the host registry, sets `event.ingested`, and fills
   `network.community_id` if the agent did not.
5. **Detection** evaluates every event against enabled Sigma rules (field names mapped from
   Sigma/Sysmon conventions to HomeXDR's ECS-style fields). Matches become **alerts**,
   de-duplicated per (rule, host, process entity) within a window.
6. Events go to the **event store** (ClickHouse by default; SQLite for tiny installs and
   tests). Alerts, hosts, rules, commands and users live in the SQLite **state store**.
7. Analysts use the **web console** to triage alerts, explore process trees, search
   events, run artifacts and hunts, and take response actions.
8. Response actions become **signed commands** that the agent picks up by long-polling,
   verifies, checks against its local policy, executes and reports back.

## Ports

| Port | Purpose | Notes |
|---|---|---|
| 8443/tcp | Agent API | TLS with the server's own CA. Client certs required except `/v1/enroll`. |
| 8080/tcp | Web console + REST API | Plain HTTP; put it behind your reverse proxy for HTTPS. |
| 514/udp+tcp → 5514 | Syslog intake | RFC 3164/5424, OPNsense `filterlog`, Suricata EVE JSON. |

## Security model

- **Server PKI.** On first start the server creates a CA, a server certificate (SANs from
  `HOMEXDR_SERVER_NAMES`) and an Ed25519 command-signing key in its data volume.
- **Enrollment.** An admin creates an enrollment token in the console. The agent enrolls with
  `--server`, `--token` and `--ca-pin sha256:<hex>` (SHA-256 of the CA certificate's DER),
  sends a CSR, and receives a client certificate with `CN=<agent id>`. Without a pin the
  agent refuses to enroll unless `--insecure-tofu` is given.
- **Commands are signed.** The agent pins the command key at enrollment and rejects any
  command that fails verification, is expired, targets another agent, or was seen before.
- **No remote shell.** Every response action is a fixed, typed operation (kill a process,
  isolate, quarantine a file, run a built-in read-only collector). There is no command that
  runs arbitrary programs, so a compromised server cannot use agents for code execution.
- **Local policy beats the server.** Each agent's local config file lists the action types
  it will run (`allowed_actions`). The server cannot change this file.
- **The agent is visible, not stealthy.** It installs as a normal named service
  (`HomeXDR Agent` / `homexdr-agent.service`), logs what it does, and uninstalls cleanly. It
  does not hide itself or resist removal by the machine's administrator.
- **Isolation never cuts the agent off.** Host isolation always allows the server address,
  loopback, DHCP and DNS, so the host can always be released.
- **Console auth.** Local users with bcrypt passwords and `HttpOnly`, `SameSite=Strict`
  session cookies. Mutating requests need the `X-HomeXDR-CSRF: 1` header. Every response
  action and rule change is written to the audit log.

## Process identity

`process.entity_id` is `event.ProcessEntityID(agentID, pid, startKey)`, where the start key
is a value every sensor on that platform can read for the same process (documented in
`shared/event/ids.go`). Parent references use `process.parent.entity_id`. The server builds
process trees from these IDs.

## Detection: Sigma field mapping

Rules use standard Sigma field names, so SigmaHQ rules work unchanged. The server maps them:

| Sigma field | HomeXDR field |
|---|---|
| `Image` | `process.executable` |
| `CommandLine` | `process.command_line` |
| `ParentImage` | `process.parent.executable` |
| `ParentCommandLine` | `process.parent.command_line` |
| `OriginalFileName` | `process.pe.original_file_name` |
| `Product`, `Company`, `Description` | `process.pe.product`, `.company`, `.description` |
| `User` | `process.user.name` (falls back to `user.name`) |
| `IntegrityLevel` | `process.integrity_level` |
| `CurrentDirectory` | `process.working_directory` |
| `Hashes`, `sha256`, `md5` | `process.hash.*` / `file.hash.*` |
| `TargetFilename` | `file.path` |
| `SourceIp`, `SourcePort` | `source.ip`, `source.port` |
| `DestinationIp`, `DestinationPort`, `DestinationHostname` | `destination.ip`, `.port`, `.domain` |
| `Initiated` | `network.direction == outbound` |
| `Protocol` | `network.transport` |
| `QueryName` | `dns.question.name` |
| `TargetObject` | `registry.path` |
| `Details` | `registry.data.strings` |
| `ImageLoaded` | `dll.path` |
| `Signed` | `dll.code_signature.exists`/`valid` |
| `EventID` | `event.code` |
| `Provider_Name` | `event.provider` |
| `ServiceName`, `ImagePath` | `service.name`, `service.path` |
| `TargetUserName`, `SubjectUserName` | `user.target.name`, `user.name` |
| `LogonType`, `IpAddress`, other EventData | `data.<Name>` (Windows EventData is kept verbatim) |
| `ScriptBlockText` | `data.ScriptBlockText` |

Sigma `logsource` maps to event filters:

| logsource | Matches |
|---|---|
| `category: process_creation` | `event.category` has `process` and `event.type` has `start` |
| `category: network_connection` | `network` + `connection` |
| `category: file_event` | `file` + `creation` (also `change`) |
| `category: file_delete` | `file` + `deletion` |
| `category: registry_set` / `registry_add` / `registry_delete` / `registry_event` | `registry` + `change` / `creation` / `deletion` / any |
| `category: dns_query` | `dns.question.name` present |
| `category: image_load` | `library` |
| `category: ps_script` | `event.code == 4104` |
| `product: windows` / `linux` / `macos` | `host.os.platform` |
| `service: security` / `system` / `sysmon` / `powershell` | `event.provider` / channel in `data.Channel` |
| `product: opnsense`, `product: suricata` | `event.module` |

Unknown fields fall back to a case-insensitive lookup in `data.*`, so Windows EventData
fields work in rules without mapping.

## Lite mode

With `HOMEXDR_EVENT_STORE=sqlite` the server runs as a single container with no ClickHouse.
It is meant for a handful of hosts or for trying HomeXDR out; ClickHouse is recommended
beyond that.
