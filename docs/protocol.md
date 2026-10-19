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
- Certificates are renewed by re-enrolling for now (renewal endpoint is future work).

## Steady state

The agent runs three loops, each with jittered exponential backoff (1s → 5min) on failure:

1. **Heartbeat** — `POST /v1/heartbeat` with `Heartbeat` every
   `heartbeat_interval_sec`. The reply may carry a newer `AgentConfig`, which the agent
   applies (restarting affected sensors) and reports as `status.config_version`.
2. **Events** — `POST /v1/events`, body gzip NDJSON of `event.Event`, at most
   `MaxEventBatchBytes` uncompressed, sent when `batch.max_events` is reached or every
   `batch.flush_interval_ms`. `202` with `EventsResponse` means the batch is durable and the
   agent deletes it from the spool. `413` means split and retry; `4xx` other than `408/429`
   means drop the batch (logged); `5xx`/network errors mean retry later.
3. **Commands** — `GET /v1/commands?wait=30` long-poll. `200` returns `[]SignedCommand`;
   `204` means nothing pending. The server marks returned commands `delivered`.

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
- `GET /v1/install/linux.sh` an install script that fetches `/v1/ca.crt`, checks it against
  `--ca-pin`, then downloads the binary and `SHA256SUMS` over TLS verified by that CA, checks
  the checksum, and runs `homexdr-agent install`. Fetching the script itself (`curl -k`) is the
  one unverified step; review the script once, or copy the agent binary manually, if that
  matters on your network.
