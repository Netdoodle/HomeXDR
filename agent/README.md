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
| `internal/selfupdate` | Signed self-update: verify the release, swap the binary, re-exec, roll back if it keeps crashing |
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
| dns | eBPF on `udp_sendmsg`/`udpv6_sendmsg` (queries to port 53) and `udp_recvmsg`/`udpv6_recvmsg` (answers from port 53), with PID; BPF trampolines (fentry/fexit), else kprobes | AF_PACKET capture of UDP port 53 (`afpacket`, no PID, agent's network namespace only), reported as `degraded` |
| library | not implemented on Linux (reported as unavailable) | |

Process entity IDs use the start time in clock ticks (`/proc/<pid>/stat` field 22). The
eBPF programs report `task->group_leader->start_boottime`, which the agent divides by
`1e9 / USER_HZ`, giving the identical value; `TestEBPFStartKeyMatchesProc` checks this
against a live process. PIDs are translated to the agent's own PID namespace in BPF, so
the agent also works inside containers and WSL.

The DNS sensor emits one event per query (`event.category: network`, `event.type:
protocol`, `network.protocol: dns`): it waits up to 5 s for the answer, then reports
`dns.type: answer` with `dns.response_code`, `dns.answers`, `dns.resolved_ip` and
`event.duration`, or `dns.type: query` alone. The eBPF programs copy the first 512
bytes of each message in the context of the process doing the I/O, so a lookup through
a local stub resolver (systemd-resolved on 127.0.0.53) is attributed to the
application, and the stub's upstream query to the stub. Messages are parsed in Go
(`dnsparse.go`; names lowercased, without the trailing dot). Identical queries (same
process, name and type) within 1 s are reported once. The agent's own lookups are not
reported. Not covered: DNS over TCP, DoT and DoH (encrypted, invisible to a port 53
hook), mDNS/LLMNR, and answers to sockets bound to port 53 (DNS servers' own sockets).

Isolation uses a dedicated nftables table `inet homexdr` (or `HOMEXDR-*` iptables chains
when `nft` is missing) that allows loopback, the server's IPs and port, DNS to the
configured resolvers, DHCP, IPv6 neighbour discovery and the allow lists, and drops
everything else, including forwarded traffic. Release deletes the table.

### Windows platform

| Sensor | Primary | Fallback |
|---|---|---|
| process | Sysmon: `Microsoft-Windows-Sysmon/Operational`, events 1 (create) and 5 (terminate), from standalone Sysmon or the Sysmon feature built into Windows | Security log: events 4688 (create) and 4689 (exit); reported as `degraded` while process creation auditing or command lines are off |

Both sources are Windows Event Log channels (`event.module: eventlog`), read in pure Go
through `wevtapi.dll`. Events use the same names as on Linux (`event.action` `exec` and
`exit`, `event.dataset: process`), with `event.provider` and `event.code` set to the
source's provider and event ID and the record's channel and record ID in
`data.winlog.channel` and `data.winlog.record_id`. Reading either log needs SYSTEM or
administrator rights; the service runs as SYSTEM.

What each source needs:

- **Sysmon**: installed, with a configuration that logs events 1 and 5. Sysmon supplies
  the hashes (per its `HashAlgorithms` setting), version resource fields, integrity level,
  working directory and the parent's command line itself. The agent adds the user's SID
  (read from the process while it runs) and, when `hash_executables` is on and Sysmon
  gave no SHA-256, hashes the executable.
- **Security log**: "Audit Process Creation" (success) for 4688, "Audit Process
  Termination" for 4689, and "Include command line in process creation events" for
  command lines. `homexdr-agent install` turns all three on and prints what it changed;
  `uninstall` restores the settings from before the first install (saved in
  `C:\ProgramData\HomeXDR\audit-before-install.json`). To set them by hand, as
  administrator:

  ```bat
  auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
  auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030} /success:enable
  reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  ```

  A domain Group Policy that sets these wins at its next refresh. The agent fills in what
  4688 lacks: the version resource of the image (`process.pe.*`, read from the file
  itself rather than its language resource, cached by path, size and modification time),
  the working directory and session from the live process, the command line from the live
  process when auditing leaves it out (only for processes still running when the event
  is read, which is why the sensor stays `degraded` until command lines are on), the
  SHA-256 when `hash_executables` is on (the same 128 MiB limit as on Linux, computed off
  the event path), and the parent's command line and user from the process table. No
  imphash or code signature on this path.

The sensor uses Sysmon when its channel exists and is enabled, and otherwise the
Security log; it notices Sysmon being installed or removed within a minute. With the
Security log it reads the audit policy (`AuditQuerySystemPolicy` and the registry value)
every minute and keeps subscribing whatever it finds, so events flow as soon as the
policy is turned on; its status message says what is missing. The running agent never
changes the policy; only `install` and `uninstall` do (`hostsetup.go`, through the
setters in `audit.go`).

`process.user` carries the SID (`user.id`), name and domain. In 4688 the account is the
target account when the process was started for another user (`runas`, services), else
the creator's. LocalSystem, LOCAL SERVICE and NETWORK SERVICE get their canonical names
(`NT AUTHORITY\SYSTEM`; Security events name LocalSystem after the computer account).
`process.integrity_level` is `low`, `medium`, `high` or `system` (`untrusted` below
low). `process.elevated` is true for a full token of a split administrator (4688
`%%1937`), false for a limited one (`%%1938`), and follows the integrity level otherwise
(`%%1936`, which covers SYSTEM, services, standard users and UAC turned off; also for
Sysmon).

Process entity IDs use the creation time as a FILETIME. For a start event the agent reads
it with `GetProcessTimes` when a process with that PID exists and was created within 5 s
before the event; anything else is a different process that reused the PID, and then the
event's time (Sysmon's `UtcTime`, else the record's `TimeCreated`) stands in. The key is
kept in a process table (filled from a snapshot of the running processes at startup,
bounded to 65,536 entries, exited processes kept for a minute) so exit events and
children get the same ID; Sysmon's `ProcessGuid` links children to parents even across
PID reuse. A parent whose creation time is later than its child's is normally a newer
process that reused the PID, but a clock set back after boot (a PC that reads the
hardware clock as local time until NTP corrects it) gives every boot-time process such a
time. So a parent is still accepted when its executable matches the one the event names,
or when its creation time is later than now, which only a clock change can produce.
Like on Linux, processes already running at startup produce no events, and the
exit of a process the sensor never saw and that is gone is dropped. Once a minute, running
entries whose process has disappeared are marked exited, for exits that are never logged.

Each subscription keeps a bookmark in `<data dir>\eventlog\process-<channel>.bookmark`,
saved every 5 s and on stop. After a restart the sensor resumes after the last record it
handled, so records logged while the agent was stopped are still reported. Without a
usable bookmark it starts at new records, with the bookmark set to the newest matching
record already in the log. Switching sources deletes the other source's bookmark, so a
later fallback does not replay an old backlog. The Event Log reader (`evtlog.go`) is
meant to be reused by the next Windows sensors.

**eventlog sensor.** Forwards every record from the channels listed in the central
config (agent config → Windows Event Log; by default Security, System, Sysmon, both
PowerShell logs, Defender, Task Scheduler, WMI, BITS and Code Integrity). Each channel has
its own subscription and bookmark. A channel that is not installed (Sysmon on most PCs)
is noted in the status and checked again every 5 minutes; a disabled or unreadable one
makes the sensor `degraded` and is retried every minute. Records keep their EventData
verbatim in `event.data` under the names Windows uses (`TargetUserName`, `LogonType`,
`ScriptBlockText`, ...), unnamed values go to `data.Data` (the classic "Windows
PowerShell" log), and `data.Channel` names the log, so Sigma rules for Windows logs need
no mapping. `event.dataset` is `windows.<Sigma service>` (`windows.security`,
`windows.powershell-classic`, `windows.windefend`, ...), which is how the server matches
`logsource: service:`; `event.provider` and `event.code` are the provider and event ID.
Logons (4624, 4625, 4634, 4647, 4648) also get ECS `authentication` fields (`user.*`,
`source.ip`, outcome), account and group changes (4720-4740, 4728/4732/4756) `iam`
fields, and service installs (7045, 4697) `service.*`. Left out: 4688/4689 and Sysmon 1/5
while the process sensor runs, Windows Filtering Platform connections (5156-5158),
Credential Manager reads (5379) and PowerShell console startup notices
(40961/40962/53504).

Not covered yet on Windows: the network, file, registry, DNS and library sensors
(Sysmon's network, file, registry and DNS events are forwarded by the eventlog sensor
but not yet mapped to those categories), host isolation, the artifact collectors and
self-update; the core reports those kinds as unavailable. `process.kill` works: it
checks the entity ID (creation time) through the same handle it terminates with, kills
children before parents with `tree`, and refuses system-critical processes (`csrss.exe`,
`lsass.exe`, `services.exe`, ...). File quarantine, restore, hash and get are
cross-platform.

`homexdr-agent install` (from an elevated prompt) enrolls, sets up auditing as above and
registers the **HomeXDR Agent** service (`HomeXDRAgent`, LocalSystem, automatic start),
which runs `<exe> run`. The Service Control Manager restarts it 5 s after an unexpected
stop. Under the service the log goes to `<data dir>\logs\agent.log` (rotated at 10 MB).
The config file and data directory get a protected ACL that only SYSTEM and
Administrators can open, instead of inheriting `C:\ProgramData`'s, which every user can
read. `uninstall` stops and deletes the service, restores the audit settings, and with
`--purge` deletes the config and data.

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

The C sources are in `internal/platform/linux/bpf/` (`process.bpf.c`, `network.bpf.c`,
`dns.bpf.c`).
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
and root (or CAP_BPF + CAP_PERFMON). The DNS programs need 5.14+ (they read
`iov_iter.iter_type`); they use BPF trampolines where the kernel has them (x86-64,
arm64 6.0+) and kprobes otherwise. Otherwise the agent falls back as described above.

### Tests

```sh
go test ./...                                           # any OS
sudo go test ./internal/platform/linux/                 # also runs the live eBPF, DNS, fanotify, kill and journald tests
sudo HOMEXDR_NETNS_TEST=1 go test -run NFTRulesetInNetns ./internal/platform/linux/
go test -fuzz FuzzParseDNS -fuzztime 1m ./internal/platform/linux/
go test ./internal/platform/windows/                    # on Windows: Event Log parsing, process mapping and live Application log tests
```

The Windows live tests write records to the Application log as a normal user and check
that a subscription receives them and that a saved bookmark resumes without duplicates or
gaps. Run them from an elevated prompt to also run the sensor against the Security log or
Sysmon; unelevated, those are skipped. No test changes the audit policy.

The live DNS tests answer their own queries with a throwaway server on 127.0.0.77:53
(and `[::1]:53`); `TestDNSSensorGetent` also resolves example.com with `getent` through
the host's resolver.

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

Add `--update-key ed25519:<base64>` (shown on the console's settings page once the server
has a signed release) to let the agent update itself; see [Automatic updates](#automatic-updates).

On Unraid, which has no systemd and keeps its root file system in RAM, use the plugin in
[`deploy/unraid`](../deploy/unraid/README.md) instead of `install`.

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
  "data_dir": "/var/lib/homexdr",
  "auto_update": true,
  "update_key": "ed25519:<release public key, base64>"
}
```

- **`allowed_actions` is the local policy.** Only these command types run; anything else
  is rejected and reported as `rejected`. Leaving the key out means all of the above; an
  empty list (`[]`) allows nothing (telemetry only). The server cannot change this file;
  it only learns the list from heartbeats so the console can hide disallowed actions.
  Restart the agent after editing it.
- `isolation_allow` lists IPs/CIDRs that stay reachable while the host is isolated, in
  addition to the server, DNS, DHCP and loopback (e.g. your admin workstation).
- `auto_update` and `update_key` let the agent install new versions the server offers,
  but only releases signed with that key, a release key kept on the host that builds the
  server, not in the server. Leave them out to update by hand.
- Everything else (sensors, filters, FIM paths, log files, batching, spool size) is the
  central config, set in the console and delivered with heartbeats.

Every command is checked before it runs: Ed25519 signature with the command key pinned
at enrollment, addressed to this agent, not expired, not seen before (the last 1000 IDs
are persisted), and allowed by the local policy. There is no command that runs arbitrary
programs.

The data dir (`/var/lib/homexdr`, mode 0700) holds the agent key and certificates,
`state.json`, the event spool, the FIM baseline, read offsets, `status.json` and the
quarantine (`quarantine/<id>/file` with permissions removed, plus `meta.json`).

## Automatic updates

With `auto_update` on, the agent checks each heartbeat for an update offer. It then
verifies the release manifest's Ed25519 signature with its own `update_key`, refuses
anything not newer than its own build, downloads the binary over the pinned connection,
checks its SHA-256, runs `<new binary> version`, keeps the current binary as
`homexdr-agent.prev` and re-executes itself with the same PID. If the new version keeps
restarting without reaching the server (more than three starts), the agent puts the
previous binary back and skips that version for a day. `homexdr-agent status` shows
whether automatic updates are on and whether an update is waiting for confirmation.
Details: [docs/protocol.md](../docs/protocol.md#agent-updates). Windows agents do not
update themselves yet.

## Uninstall

```sh
homexdr-agent uninstall           # stop and remove the service, keep identity and data
homexdr-agent uninstall --purge   # also delete the config file and the data directory
```

Uninstall always removes isolation rules first, so a host is never left cut off.
`--purge` also deletes quarantined files. Remove the binary afterwards
(`rm /usr/local/bin/homexdr-agent`) and revoke the host in the console.
