# HomeXDR

Self-hosted EDR/XDR with a built-in SIEM, built for homelabs.

- **Endpoint detection and response without a kernel driver.** Windows telemetry from ETW
  and the Event Log; Linux telemetry from eBPF with netlink/procfs fallbacks. macOS is planned.
- **Sigma detections.** Built-in rules plus any SigmaHQ rule, mapped onto an ECS-style schema.
- **Process trees, timelines and search** across every host.
- **Response actions:** kill process trees, isolate hosts, quarantine and fetch files,
  run built-in collection artifacts and fleet-wide hunts.
- **Network correlation.** Ingests OPNsense `filterlog` and Suricata EVE over syslog and
  joins them to endpoint processes by Community ID.
- **Docker-first backend.** `docker compose up` runs the server and ClickHouse. A single
  container "lite" mode uses SQLite. Retention by age, by size, or both.
- **Automatic updates.** A cron job on the Docker host rebuilds and redeploys the server
  when the git branch moves, with health checks and rollback. Agents that opt in update
  themselves to releases signed with a key the server never holds.

> Status: early development. Not ready for production use.

## Quick start

```bash
cd deploy
cp .env.example .env    # set HOMEXDR_SERVER_NAMES to the name/IP agents will use
docker compose up -d
```

Open `http://<server>:8080`, create the admin account, then create an enrollment token
under **Settings** and copy the install command for each host.

To keep the server and agents updated from git, see [deploy/update](deploy/update/README.md).
For Unraid hosts, see [deploy/unraid](deploy/unraid/README.md).

## Docs

- [Architecture](docs/architecture.md)
- [Agent protocol](docs/protocol.md)
- [Console REST API](docs/api.md)

## Building from source

Requires Go 1.25+ and Node 20+.

```bash
cd agent && go build ./cmd/homexdr-agent
cd server && go build ./cmd/homexdr-server
cd web && npm ci && npm run build
```

## License

Apache-2.0. See [LICENSE](LICENSE).
