# Agent ↔ server protocol (v1)

The JSON shapes live in [`shared/api/agent.go`](../shared/api/agent.go); this document
describes the flows. All traffic is agent-initiated HTTPS to the agent listener (default
`:8443`). Every request carries `X-HomeXDR-Protocol: 1` and `User-Agent: homexdr-agent/<version>`.

## Enrollment

```
agent                                         server
  │  generate ECDSA P-256 key + CSR              │
  │  TLS handshake, verify server chain against  │
  │  CA whose DER SHA-256 == --ca-pin            │
  │── POST /v1/enroll {token, csr_pem, host} ───►│ check token (exists, not expired, uses left)
  │                                              │ create host record, agent_id = event.NewID()
  │◄── 200 {agent_id, cert_pem, ca_pem,         ─│ sign CSR: CN=agent_id, ExtKeyUsage=ClientAuth,
  │         command_key, config}                 │ 1-year validity
  │  store key, cert, CA, command key, config    │
  │  in the data dir (0600 / SYSTEM-only ACL)    │
```

- The server's TLS handshake presents `[server cert, CA cert]`, so the agent can check the
  CA against the pin before sending anything. The server cert must chain to that CA with the
  ServerAuth key usage; the hostname is not checked, because the private, pinned CA only ever
  issues one server certificate, and that way agents keep working when the server's IP changes.
- Labels from the request are added to the enrollment token's labels.
- `401` bad or expired token, `409` token used up, `400` malformed CSR.
- The agent's stored identity survives restarts and upgrades. Re-enrolling creates a new host.
- The certificate renews itself before it expires (see [Certificate renewal](#certificate-renewal)),
  so an enrolled agent never needs re-enrolling unless it is revoked.

## Steady state

The agent runs three loops, each with jittered exponential backoff (1s → 5min) on failure:

1. **Heartbeat** — `POST /v1/heartbeat` with `Heartbeat` every
   `heartbeat_interval_sec`. The reply may carry a newer `AgentConfig`, which the agent
   applies (restarting affected sensors) and reports as `status.config_version`, and an
   `update` offer (see [Agent updates](#agent-updates)).
2. **Events** — `POST /v1/events`, body gzip NDJSON of `event.Event`, at most
   `MaxEventBatchBytes` uncompressed, sent when `batch.max_events` is reached or every
   `batch.flush_interval_ms`. `202` with `EventsResponse` means the batch is durable and the
   agent deletes it from the spool. `413` means split and retry; `4xx` other than `408/429`
   means drop the batch (logged); `5xx`/network errors mean retry later.
3. **Commands** — `GET /v1/commands?wait=30` long-poll. `200` returns `[]SignedCommand`;
   `204` means nothing pending. The server marks returned commands `delivered`.

## Certificate renewal

Agent certificates are valid for a year. Before each heartbeat the agent checks its own:
once a third of the lifetime is left (about four months), it generates a new key and CSR and
calls `POST /v1/renew {csr_pem}` → `200 {cert_pem}`, retrying hourly on failure.

- **Authentication.** The request is authenticated with the current client certificate,
  which may have expired: the server checks that it chains to the CA and names a known,
  unrevoked agent, but not its dates. An agent that was offline past its expiry renews the
  moment it is back (retrying every five minutes) instead of being locked out. Revoked agents
  get `403`. Every other endpoint answers an expired certificate with
  `401 "certificate expired: renew it at /v1/renew"`.
- **Switch-over.** The server signs the CSR with `CN=<agent_id>` (the CSR's subject is
  ignored) and records the new serial as pending. It accepts both the current and the pending
  certificate until the agent first uses the new one, then makes it current; older
  certificates are refused with `403 "certificate superseded"`. Each renewal is audited as
  `agent.cert.renew`.
- **Crash safety.** The agent writes the new key and certificate to `agent.renew` in its
  data dir first, then replaces `agent.key` and `agent.crt`. If it stops in between, the next
  start finishes the swap from `agent.renew` (after checking the certificate against the
  stored CA and agent ID). New TLS connections pick up the renewed certificate without a
  restart.
- `homexdr-agent status` shows the expiry and when renewal starts; the console shows the
  expiry on the host page.

## Decommissioning

Endpoint agents that have not checked in for the configured number of days (Settings →
Agent updates → Inactive agents; off by default) are decommissioned by an hourly sweep, or
manually from the host page. A decommissioned agent keeps its identity and history but is
hidden from host lists, counts and dashboards (`GET /api/hosts?status=decommissioned` or
`include_decommissioned=true` still lists it). Nothing changes on the agent's side: the next
request it makes with its certificate, renewal included, restores it, and the audit log
records `agent.recommission`. Network sources (syslog) are never decommissioned.

## Commands

For each `SignedCommand` the agent:

1. Verifies `Signature` over `Payload` with the pinned Ed25519 command key.
2. Decodes `Payload` as `Command` and checks `AgentID == own id`, `now < ExpiresAt`, and that
   `ID` is not in its persisted seen-ID set (last 1000 IDs).
3. Checks `Type` against the local `allowed_actions` policy.
4. On any failure posts `CommandResult{status: "rejected", error: ...}` and stops.
5. Otherwise posts `running`, executes, and posts `completed` or `failed` with `Output`.

Artifact rows are streamed to `POST /v1/commands/{id}/rows` (gzip NDJSON, each line an
object whose keys follow the artifact's `columns`) before the final result, which carries
`row_count`. `file.get` uploads the raw file to `POST /v1/commands/{id}/upload?name=<path>`
(max 100 MiB by default) before posting the result with a `FileHashResult` as output.

When a command reaches a final status, the server (not the agent) records an event
(`event.module: response`, `event.action: <type>`) so it appears in the host timeline.
`file.restore` returns the restored file's `QuarantineResult`.

Commands delivered to an agent that never posts a final result are marked `failed` by the
server 24 hours after they expire, with the error "no result from agent".

## Downloads

The agent listener also serves, without a client certificate:

- `GET /v1/ca.crt` the CA certificate (PEM), checked against the pin by the install script
- `GET /v1/download/homexdr-agent-<os>-<arch>[.exe]` agent binaries bundled in the image
- `GET /v1/download/agent-release.json` and `agent-release.json.sig`, the signed release
  manifest (see below)
- `GET /v1/releases/<version>/<name>` the same files for an archived release (see below)
- `GET /v1/install/linux.sh` an install script that fetches `/v1/ca.crt`, checks it against
  `--ca-pin`, then downloads the binary and `SHA256SUMS` over TLS verified by that CA, checks
  the checksum, and runs `homexdr-agent install`. Fetching the script itself (`curl -k`) is the
  one unverified step; review the script once, or copy the agent binary manually, if that
  matters on your network.

## Agent updates

Agents can update themselves, but only when their local config allows it and only to
releases signed with a key the server never holds. This keeps the security model: a
compromised server can offer an update, but it cannot make an agent run a binary that the
release key did not sign.

- **Release manifest.** The image build writes `agent-release.json` next to the bundled
  binaries (`homexdr-server release-manifest`): `version`, `commit`, `commit_time` (Unix
  seconds) and, per binary, its `sha256` and `size` (`api.AgentRelease`).
- **Signature.** The host that builds the image signs the manifest's exact bytes with an
  Ed25519 release key (`deploy/update/homexdr-update.sh`, using `openssl pkeyutl -sign
  -rawin`) and writes `agent-release.<sha256 of manifest>.sig` (base64) and
  `update-key.pub` (`ed25519:<base64>`) into a folder mounted read-only into the server
  (`HOMEXDR_SIGNATURES_DIR`). The private key stays on the host.
- **Release archive.** When the bundled release's signature verifies with `update-key.pub`,
  the server copies the manifest, signature and binaries (checking each SHA-256) into
  `<data dir>/releases/<version>/` (`HOMEXDR_RELEASES_DIR`). Each archived release is
  re-verified on every load. The newest five are kept (`HOMEXDR_RELEASES_KEEP`, at least 2),
  plus the bundled release and any version a policy pins, so the server can offer the release
  before the newest (N-1) or a pinned one after it has been redeployed.
- **Offer.** The update policy (below) picks a target from the archive. When an agent may
  update now, the heartbeat reply carries `update: {version, commit_time, path}`, where
  `path` is `/v1/releases/<version>/` and holds that release's manifest, signature and
  binaries. Agents from before the archive ignore `path` and fetch the bundled release from
  `/v1/download/`. The agent checks that `path` is exactly `/v1/releases/<one segment>/` and
  that the manifest's version matches the offer.
- **Update policy** (Settings → Agent updates, admin only):
  - The first *label rule* matching one of the agent's labels applies, else the *default*
    rule. A rule is `latest`, `n-1` (the archived release before the newest), `pinned` (one
    archived version) or `off`.
  - Agents never downgrade, so an agent already running a build newer than its target is
    left alone (shown as "ahead"). To move a group back, pin the version it runs now.
  - *Maintenance window*: offers are made only between a start and end time (`HH:MM`, may
    wrap past midnight) in an IANA time zone. Agents that check in outside it wait.
  - *Staged rollout*: agents with the canary label get a new release first. Everyone else
    waits until the release has been archived for the delay (default 24 hours), at least
    one canary runs it, and no canary reported an install error for it. With no canary
    agents, only the delay applies.
  - *Update now* on a host page offers that agent its target at the next heartbeat,
    regardless of window and staging (and the latest release if its rule is `off`).
  - The agent reports the last failed install as `status.update_error`
    (`<version>: <error>`); the host then shows "failed" for that version, and canaries with
    one hold back the rollout.
- **Local policy.** The agent acts on the offer only with `"auto_update": true` and an
  `update_key` in its local config (set with `--update-key` at enrollment). Otherwise it
  logs the offer once and keeps running.
- **Install.** The agent fetches the manifest and signature, verifies the signature with
  its own `update_key`, refuses releases whose `commit_time` is not later than its own build
  (no downgrades), downloads `homexdr-agent-<os>-<arch>`, checks the SHA-256 and size from
  the manifest, runs `<new binary> version` as a start check, keeps the running binary as
  `<binary>.prev`, renames the new one into place and re-executes itself (same PID, so
  systemd or another supervisor sees the same process continue).
- **Rollback.** An `update.json` marker in the data dir counts the new version's start-ups
  until its first successful heartbeat. If it starts more than three times without one,
  the agent moves `<binary>.prev` back, restarts into it and skips that version for 24
  hours. A failed download or check is retried after an hour.
- **Platforms.** Linux (and macOS once it has a platform layer). Windows agents cannot
  replace their running executable yet and ignore the offer.

