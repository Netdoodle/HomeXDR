# homexdr-agent

The HomeXDR endpoint agent. It runs as a normal, visible system service
(`homexdr-agent.service` on Linux, `HomeXDR Agent` on Windows), collects telemetry,
runs read-only collectors, and performs a small fixed set of response actions that the
host's owner triggers from their own console. It logs everything it does and uninstalls
cleanly. See [`docs/architecture.md`](../docs/architecture.md) and
[`docs/protocol.md`](../docs/protocol.md) for the system design.

## Layout

| Package | What |
|---|---|
| `cmd/homexdr-agent` | CLI: `enroll`, `install`, `uninstall`, `run`, `status`, `version` |
| `internal/config` | Local config file (the local policy) |
| `internal/identity`, `internal/enroll` | Key, certificates, pinned CA and command key; enrollment with CA pinning |
| `internal/state` | Runtime state: central config, isolation, seen command IDs |
| `internal/transport` | mTLS client for the agent API (pinned CA only) |
| `internal/spool` | Disk queue of events (segment files, size-bounded, survives restarts) |
| `internal/pipeline` | Stamping and central-config filters between sensors and spool |
| `internal/supervisor` | Runs sensors, restarts them with backoff or on config change |
| `internal/commands` | Signed-command verification (signature, agent, expiry, replay, policy) and dispatch |
| `internal/fileops` | Quarantine, restore, hash, file.get |
| `internal/sensors/{fim,logtail,inventory}` | Cross-platform sensors |
| `internal/collect` | Cross-platform collectors (`file.find`) |
| `internal/core` | The runtime that wires it all together |
| `internal/platform` | The core/OS boundary; `linux`, `windows`, `darwin` implement it |

### Linux platform

| Sensor | Primary | Fallback |
|---|---|---|
| process | eBPF `tp_btf/sched_process_exec` + `sched_process_exit` (argv, exit code, parent, uid) | netlink proc connector (`procconn`, initial PID namespace only), then `/proc` polling (`procfs`); both reported as `degraded` |
| network | eBPF `inet_sock_set_state` (outbound) + `inet_csk_accept` return (inbound), with PID | `/proc/net/tcp{,6}` polling |
| file | fanotify filesystem marks (create, delete, rename, close-after-write; with PID) | recursive inotify (no PID) |
| auth | journald (`journalctl -f -o json`, auth/authpriv facilities) | `/var/log/auth.log` or `/var/log/secure` |
| dns, library | not implemented on Linux (reported as unavailable) | |

Process entity IDs use the start time in clock ticks (`/proc/<pid>/stat` field 22). The
eBPF programs report `task->group_leader->start_boottime`, which the agent divides by
`1e9 / USER_HZ`, giving the identical value; `TestEBPFStartKeyMatchesProc` checks this
against a live process. PIDs are translated to the agent's own PID namespace in BPF, so
the agent also works inside containers and WSL.

Isolation uses a dedicated nftables table `inet homexdr` (or `HOMEXDR-*` iptables chains
when `nft` is missing) that allows loopback, the server's IPs and port, DNS to the
configured resolvers, DHCP, IPv6 neighbour discovery and the allow lists, and drops
everything else, including forwarded traffic. Release deletes the table.

## Build

Requires Go 1.26+. The eBPF objects are committed, so no clang is needed:

```sh
cd agent
go build -o homexdr-agent ./cmd/homexdr-agent                       # current OS
GOOS=linux GOARCH=arm64 go build -o homexdr-agent-linux-arm64 ./cmd/homexdr-agent
GOOS=windows go build -o homexdr-agent.exe ./cmd/homexdr-agent
```

Set the version with
`-ldflags "-X github.com/Netdoodle/homexdr/shared/version.Version=v0.1.0"`.

### Regenerating the eBPF programs

The C sources are in `internal/platform/linux/bpf/` (`process.bpf.c`, `network.bpf.c`).
They use CO-RE against a small hand-written header (`hx_vmlinux.h`) instead of a full
`vmlinux.h`. After editing them, rebuild the objects and Go bindings on Linux with
clang, llvm-strip and the libbpf headers installed (`apt install clang llvm libbpf-dev`):

```sh
cd agent/internal/platform/linux/bpf
go generate ./...
```

This runs `bpf2go` (cilium/ebpf v0.22.0) for amd64 and arm64 and rewrites the
`*_bpfel.go` / `*_bpfel.o` files. Commit them.

The eBPF path needs kernel BTF (`/sys/kernel/btf/vmlinux`), Linux 5.8+ (ring buffer)
and root (or CAP_BPF + CAP_PERFMON). Otherwise the agent falls back as described above.

### Tests

```sh
go test ./...                                           # any OS
sudo go test ./internal/platform/linux/                 # also runs the live eBPF, fanotify, kill and journald tests
sudo HOMEXDR_NETNS_TEST=1 go test -run NFTRulesetInNetns ./internal/platform/linux/
```

The last one loads the generated isolation ruleset with the real `nft` binary into a
throwaway network namespace (never the host's own) and removes it again.

## Install

The console's settings page shows the CA pin and creates enrollment tokens. On Linux the
server's install script downloads the binary over a pinned connection and runs
`homexdr-agent install`. Manually, as root:

```sh
install -m 0755 homexdr-agent /usr/local/bin/homexdr-agent
homexdr-agent install --server https://xdr.example.lan:8443 \
  --token <enrollment token> --ca-pin sha256:<hex> [--labels lab,linux]
```

`install` enrolls (unless already enrolled), writes `/etc/systemd/system/homexdr-agent.service`
(`Restart=always`) and runs `systemctl enable --now`. On Windows, run the same command
from an elevated PowerShell.

`enroll` refuses to run without `--ca-pin` unless you pass `--insecure-tofu`, in which
case it prints the pin it trusted so you can compare it with the console. After
enrollment the stored CA is the only trusted root.

Other commands:

```sh
homexdr-agent run        # foreground (what the service runs); --config <path> for a non-default file
homexdr-agent status     # enrollment, service, isolation, queue and sensor status
homexdr-agent version
```

## Config file and local policy

`/etc/homexdr/agent.json` (Linux) or `%ProgramData%\HomeXDR\agent.json` (Windows),
mode 0600:

```json
{
  "server_url": "https://xdr.example.lan:8443",
  "ca_pin": "sha256:9c9f...",
  "allowed_actions": ["process.kill", "host.isolate", "host.release", "file.quarantine",
                      "file.restore", "file.get", "file.hash", "artifact.collect"],
  "isolation_allow": ["192.168.1.10", "10.0.0.0/24"],
  "log_level": "info",
  "data_dir": "/var/lib/homexdr"
}
```

- **`allowed_actions` is the local policy.** Only these command types run; anything else
  is rejected and reported as `rejected`. Leaving the key out means all of the above; an
  empty list (`[]`) allows nothing (telemetry only). The server cannot change this file;
  it only learns the list from heartbeats so the console can hide disallowed actions.
  Restart the agent after editing it.
- `isolation_allow` lists IPs/CIDRs that stay reachable while the host is isolated, in
  addition to the server, DNS, DHCP and loopback (e.g. your admin workstation).
- Everything else (sensors, filters, FIM paths, log files, batching, spool size) is the
  central config, set in the console and delivered with heartbeats.

Every command is checked before it runs: Ed25519 signature with the command key pinned
at enrollment, addressed to this agent, not expired, not seen before (the last 1000 IDs
are persisted), and allowed by the local policy. There is no command that runs arbitrary
programs.

The data dir (`/var/lib/homexdr`, mode 0700) holds the agent key and certificates,
`state.json`, the event spool, the FIM baseline, read offsets, `status.json` and the
quarantine (`quarantine/<id>/file` with permissions removed, plus `meta.json`).

## Uninstall

```sh
homexdr-agent uninstall           # stop and remove the service, keep identity and data
homexdr-agent uninstall --purge   # also delete the config file and the data directory
```

Uninstall always removes isolation rules first, so a host is never left cut off.
`--purge` also deletes quarantined files. Remove the binary afterwards
(`rm /usr/local/bin/homexdr-agent`) and revoke the host in the console.
