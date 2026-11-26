# Detection rules

HomeXDR loads [Sigma](https://sigmahq.io/) rules from three places:

- this directory (in the Docker image: `/usr/share/homexdr/rules`, set with
  `HOMEXDR_RULES_DIR`), read recursively;
- rule repositories imported in the console, such as SigmaHQ, which the server downloads and
  keeps up to date (below);
- custom rules written in the console, stored in the database.

## Rules HomeXDR ships

`rules/homexdr/` holds rules for what community rule sets leave out on a homelab: Docker and
Unraid hosts, SSH, DNS lookups from a resolver's query log, OPNsense (audit and firewall logs), macOS security events,
the agents' decoy files, and attempts to switch HomeXDR's own monitoring off. They load with the server and are tested
in `server/internal/detect/homexdr_rules_test.go`, `homexdr_rules2_test.go`, `homexdr_rules3_test.go`,
`homexdr_rules_macos_test.go`, `homexdr_rules_defender_test.go`, `homexdr_rules_decoy_test.go`
and (the correlation rules) `correlation_test.go`.
They are also published at [Netdoodle/HomeXDR-SIGMA-rules](https://github.com/Netdoodle/HomeXDR-SIGMA-rules).

The OPNsense rules need its audit log: **System → Settings → Logging → Remote**, add `audit`
to the destination's Applications.

| Rule | Level | Fires on |
|---|---|---|
| Nsenter Into The Host's Namespaces | high | `nsenter -t 1`: a container breakout or a root shell outside every limit |
| Container Started With Host-Level Access | medium | `docker run` with `--privileged`, `--pid=host`, `-v /:/`, the Docker socket or `SYS_ADMIN` |
| Docker Socket Used From Inside A Container | medium | the docker CLI or `curl --unix-socket docker.sock` inside a container |
| SSH Authorized Keys Changed From The Command Line | medium | writing, copying or downloading an `authorized_keys` file |
| Unraid Boot Script Modified | high | writing to `/boot/config/go`, which runs as root at every boot |
| Unraid Plugin Installed From A URL | low | `plugin install https://...plg` from outside Unraid's own servers |
| DNS Lookup Of A Reverse Tunnel Service | medium | ngrok, Cloudflare quick tunnels, localtunnel, serveo, pinggy, bore |
| DNS Lookup Of A Tor Onion Or Tor2web Gateway | high | `.onion` names and Tor2web gateways |
| DNS Lookup Of An Anonymous Paste Or File Upload Service | low | transfer.sh, file.io, 0x0.st, pastebin and similar |
| SSH Login From A Public Address | high | a successful SSH login from outside private and Tailscale ranges |
| Root SSH Login With A Password | medium | root or Administrator logging in over SSH with a password |
| SSH Login With A Key HomeXDR Does Not Know | low | a key login whose key has no name under Settings -> Maintenance |
| HomeXDR Agent Stopped Or Removed On Linux | high | `pkill`, `systemctl stop`, `plugin remove` or `uninstall` of the agent |
| HomeXDR Agent Stopped Or Removed On Windows | high | `sc stop`/`delete`, `Stop-Service`, `taskkill` or `uninstall` of the agent service |
| Defender Attack Surface Reduction Rule Blocked An Action | medium | Defender event 1121: an ASR rule in block mode stopped something ([Defender hardening](../docs/antivirus.md#defender-hardening)) |
| Defender Network Protection Blocked A Connection | medium | Defender event 1126 |
| Defender Controlled Folder Access Blocked A Write | low | Defender event 1123 (only where Controlled Folder Access blocks) |
| Sysmon Or Process Auditing Turned Off | high | `sysmon -u`, `auditpol` disabling or clearing, `wevtutil sl ... /e:false` on the logs HomeXDR reads |
| Package Installed Inside A Running Container | medium | `apk add`, `apt-get install`, `pip install` and similar after a container's start-up minutes |
| Download Piped To A Shell Inside A Container | high | `curl ... \| sh` and `sh -c "$(wget ...)"` inside a container |
| Web Application In A Container Started A Shell Or Network Tool | medium | nginx, PHP-FPM, Node.js, Python or Java in a container starting `sh`, `curl`, `nc` and similar |
| Interactive Shell Opened In A Container | low | `docker exec ... sh`, including the Unraid console button |
| SSH Server Configured To Allow Root Or Password Logins | medium | setting `PermitRootLogin`, `PasswordAuthentication` or `PermitEmptyPasswords` to yes |
| Unraid User Script Or Cron File Written From The Command Line | medium | writing a User Scripts script or a plugin `.cron` file on the flash drive |
| Virtual Machine Defined From The Command Line | low | `virsh define`/`create`/`autostart` and `virt-install` |
| DNS Lookup Of A DNS-over-HTTPS Provider | low | dns.google, cloudflare-dns.com, Quad9, NextDNS and other DoH servers |
| DNS Lookup Of A Dynamic DNS Name | low | duckdns, no-ip, dynu and other free dynamic DNS names |
| OPNsense Web GUI Login Failed | medium | a failed web interface login (needs the OPNsense audit log) |
| OPNsense Web GUI Login | low | a web interface login (needs the OPNsense audit log) |
| OPNsense Configuration Changed | low | any configuration change, with user, address and page (needs the OPNsense audit log) |
| Remote Admin Or Database Port Allowed In From The Internet | high | the firewall passing SSH, RDP, VNC, SMB, Telnet, WinRM, Docker or a database port from a public address to a device inside (needs logging on the pass or port forward rule) |
| Windows File Sharing Connection To The Internet | medium | the firewall passing port 445 or 139 from inside to a public address |
| Telnet Connection To The Internet | medium | the firewall passing port 23 or 2323 from inside to a public address, as Mirai-type botnets do |
| SSH Login Tried For A User That Does Not Exist From Inside The Network | medium | a failed SSH login for an unknown user name from a private address |
| DNS Lookup Of A Cryptocurrency Mining Pool | high | nanopool, supportxmr, moneroocean, 2miners, f2pool, nicehash and other pools |
| DNS Lookup Of A Remote Desktop Service | low | AnyDesk, TeamViewer, RustDesk, ScreenConnect, Splashtop, LogMeIn and similar |
| XProtect Detected Malware On macOS | high | Apple's XProtect reporting known malware |
| Launch Daemon Or Agent Added On macOS | medium | a new, unmanaged launch daemon or agent registered with background task management |
| Sensitive Privacy Permission Granted On macOS | medium | Full Disk Access, Accessibility, Screen Recording or Input Monitoring granted (macOS 15.4+) |
| Gatekeeper Overridden On macOS | medium | the user opening a file Gatekeeper blocked (macOS 15+) |
| User Added To The Admin Group On macOS | high | an account added to `admin` (macOS 14+) |
| HomeXDR Agent Stopped Or Removed On macOS | high | `launchctl bootout`/`unload`/`disable`, `pkill` or `uninstall` of the agent |
| Download Piped To A Shell On macOS | medium | `curl ... \| sh`, `bash -c "$(curl ...)"`, base64 into a shell, or `do shell script` running curl, when run as one command line |
| Browser Passwords, Cookies, Keychains Or Wallets Copied On macOS | high | `cp`, `ditto`, `zip`, `sqlite3` and similar on Chrome and Firefox logins and cookies, keychains or crypto wallets, as infostealers do |
| Archive Uploaded With Curl From A Temporary Folder On macOS | medium | `curl -F file=@/tmp/x.zip` and similar uploads of an archive from `/tmp`, `/var/folders` or `/Users/Shared` |
| Privacy Database Edited Directly On macOS | high | `sqlite3` writing to a `TCC.db`, or a file copied over one: privacy permissions granted without a prompt |
| Gatekeeper Or Quarantine Turned Off From The Command Line | high | `spctl --master-disable` or `--global-disable`, or `LSQuarantine` set to no |
| Remote Login Or Screen Sharing Turned On From The Command Line | medium | `systemsetup -setremotelogin on`, `launchctl load` of SSH or Screen Sharing, or the Remote Desktop `kickstart -activate` |
| Certificate Trusted As A Root From The Command Line On macOS | medium | `security add-trusted-cert` |
| Web Proxy Set From The Command Line On macOS | medium | `networksetup -setwebproxy`, `-setsecurewebproxy`, `-setsocksfirewallproxy` or `-setautoproxyurl` |
| Login Or Logout Hook Set On macOS | high | `defaults write com.apple.loginwindow LoginHook` or `LogoutHook` |
| Shell Startup File Changed By A Program In A Temporary Or Hidden Folder | medium | a program in `/tmp`, `/var/folders`, `/Users/Shared`, `/Volumes` or a hidden folder changing `.zshrc`, `.zprofile`, `.bash_profile` and similar |
| Launch Job Loaded From A Temporary Or Hidden Folder On macOS | high | `launchctl load`, `bootstrap` or `submit` of a job in `/tmp`, `/var/folders`, `/Users/Shared` or a hidden folder |
| Program Started From A Hidden File Or Folder On macOS | medium | a program run from a hidden file in a home folder (`~/.helper`) or a hidden folder in `/tmp`, `/Users/Shared` or Application Support |
| Office App Started A Shell Or Script On macOS | high | Word, Excel or PowerPoint starting a shell, `osascript`, Python, Perl, Ruby or curl |
| Application Firewall Turned Off On macOS | medium | `socketfilterfw --setglobalstate off` or `com.apple.alf globalstate 0` |
| System Logs Erased On macOS | high | `log erase`, logging switched off with `log config`, or the log, audit or diagnostics folders deleted |
| Sudo Rule Added From The Command Line On macOS | medium | `tee`, `cp`, `mv` or a redirect writing `/etc/sudoers` or `/etc/sudoers.d` |
| Many Failed Logins From One Address | medium | correlation: 20 or more failed SSH logins or Windows logons from one address within 5 minutes |
| Process Connected To Many Ports On One Address | medium | correlation: one process trying 25 or more ports on one address within a minute (a port scan) |
| Decoy File Modified, Deleted Or Renamed | critical | a change, deletion, rename or replacement of a decoy file the agent placed ([decoys.md](../docs/decoys.md)) |
| Decoy File Opened | high | a decoy file opened or read (Linux agents only) |

The two correlation rules count events of a base rule in the same file: **Failed Login From
An Address** and **Outbound Connection By A Process**. Those base rules raise no alerts of
their own (see [Threshold and correlation rules](#threshold-and-correlation-rules)).

The Docker rules match what Unraid's Docker manager runs when it updates a privileged
container; those commands carry `labels.maintenance: docker-update`, which Settings ->
Maintenance can quiet ([maintenance.md](../docs/maintenance.md)).

## Importing a rule repository

The quickest way to add community rules is **Rules → Import rules** in the console (admins).
Pick a preset or paste a URL, and HomeXDR downloads the rules, loads the ones it can run and
keeps them updated:

- **SigmaHQ: Windows and Linux**: the default branch of
  [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), folders `rules/windows` and
  `rules/linux`, medium level and above (about 2,400 rules).
- **SigmaHQ Core release**: SigmaHQ's curated release package (`sigma_core.zip`): stable and
  test rules of high and critical level, about 1,200 for Windows and Linux.
- **Any other source**: a public git repository on GitHub, GitLab, Gitea/Forgejo (Codeberg)
  or Bitbucket, or a link to a `.zip` / `.tar.gz` of Sigma rules. A link to a folder
  (`https://github.com/SigmaHQ/sigma/tree/master/rules/linux`) fills in the branch and folder.

For each repository you choose:

| Setting | |
|---|---|
| Branch, tag or commit | Default branch when empty. A commit pins the rules to that version. |
| Folders | Only rules in these folders are loaded; empty means the whole repository. After the first download, **Edit** shows the download as a folder tree with tick boxes: each folder shows how many of its rules pass the level and status filters and how many the engine cannot run, and a summary shows what the selection loads, by product. A repository added without folders opens this tree as soon as its first download finishes. |
| Minimum level, statuses | Rules below the level or with other Sigma statuses are skipped. Deprecated and unsupported rules are skipped unless ticked. |
| New rules | Whether rules from the repository start enabled or disabled. |
| Updates | **Automatic**: each check installs a new version as soon as it finds one. **Manual**: checks only report "Update available", and nothing changes until an admin clicks **Update**. |
| Check interval | Every hour to weekly (daily by default). |

The server needs no git: it reads the newest commit of the branch from the repository's
smart-HTTP endpoint (what `git ls-remote` uses) and downloads the host's archive of that
commit; archive URLs are re-downloaded only when their ETag or content changes. Only
`.yml`/`.yaml` files are kept, under `<data>/rule-repos/<id>`. A download is staged next to
the installed copy and swapped in only when complete, so a failed update leaves the
installed rules running; failures show on the repository and are retried within an hour.
**Check** looks for a new version without installing it; **Update** installs now in either
mode. Changes are written to the audit log (`rule_repo.*`, by `system` for scheduled updates).

Rules you enable or disable by hand keep that choice across updates, because the choice is
stored by rule ID. Repository rules are read-only; **Copy as custom** makes an editable copy
with a new ID. When two sources contain the same rule ID, the rules folder wins over custom
rules, custom rules over repositories, and an earlier repository over a later one; the
repository card counts the rules it skipped this way, and **Why … not loaded** lists each one
with the reason (the other source, or the unsupported feature). **Enable all** and **Disable
all** on the card switch every loaded rule of the repository at once; like switching one by
hand, the choice is kept through updates, and rules that appear later still start as set for
the repository.

Every enabled rule runs on every event, so load the platforms you collect rather than the
whole repository. Rules that use features the engine does not support yet (`|expand`,
aggregations other than `count()`, "fewer than" thresholds; see
[below](#threshold-and-correlation-rules)) are skipped and listed on the **Rules** page with the
reason. In a file that holds several rules, each is loaded or skipped on its own. SigmaHQ rules are published under the Detection Rule License (DRL) 1.1, which
requires attribution; HomeXDR shows each rule's author and links to its file upstream.

## Mounting rules into the rules folder

Rules can also be mounted next to the built-in directory, for example to use a checkout you
manage yourself. In `deploy/docker-compose.yml`:

```yaml
    volumes:
      - /opt/sigma/rules/windows/process_creation:/usr/share/homexdr/rules/sigmahq/windows:ro
      - /opt/sigma/rules/linux:/usr/share/homexdr/rules/sigmahq/linux:ro
```

The server checks the rules folder once a minute and reloads it when a file is added,
removed or changed, so no restart is needed. Admins can also apply changes immediately with
**Rules → Reload rules folder** (or `POST /api/rules/reload`). To keep a mounted folder
current, update it from the host on a schedule (for example a cron job or an Unraid User
Script); HomeXDR picks up the new files on its next check. Disable noisy rules from the
console; the setting is kept across restarts and updates.

## Writing rules

Use Sigma's `logsource` categories (`process_creation`, `network_connection`,
`file_event`, `registry_set`, `dns_query`, `image_load`, ...) with `product: windows`,
`linux` or `macos`, or `product: opnsense` / `suricata` for network sources. Fields that are
not in the mapping table fall back to Windows EventData names (`data.<Name>`) and then to
HomeXDR's own dotted field paths (`process.parent.name`, `destination.port`, ...).

Test a rule against stored events before saving it with **Rules → New rule → Test**.

## Threshold and correlation rules

Some things only show as a pattern: ten failed logins in a minute, one process touching fifty
ports. HomeXDR runs two kinds of rules for these. Both keep counting windows in the server's
memory and raise one alert when the condition is met.

### Sigma correlation rules

A [Sigma correlation rule](https://github.com/SigmaHQ/sigma-specification) has a
`correlation` block instead of `detection`, and refers to ordinary rules (its base rules) by
`id` or by `name`:

```yaml
title: Failed SSH login
id: 5e0f5a3c-0000-4000-8000-000000000001
name: ssh_failed_login
logsource: {category: authentication}
detection:
  selection:
    event.action: ssh_login
    event.outcome: failure
  condition: selection
level: low
---
title: SSH brute force from one address
id: 5e0f5a3c-0000-4000-8000-000000000002
correlation:
  type: event_count
  rules:
    - ssh_failed_login
  group-by:
    - source.ip
  timespan: 1m
  condition:
    gte: 10
level: high
```

| Key | |
|---|---|
| `type` | `event_count` (how many events matched), `value_count` (how many distinct values of `condition.field` they had), `temporal` (all the rules matched, in any order), `temporal_ordered` (all matched, in the order listed). |
| `rules` | Base rules by `id` or `name`. A rule in the same file wins over one elsewhere with the same name; otherwise any loaded rule counts: the rules folder, custom rules and rule repositories. |
| `group-by` | Event fields to count separately by, such as `source.ip` or `host.id`. A missing field counts as empty. `aliases` maps a group-by name to a different field per base rule. |
| `timespan` | The window: a whole number of seconds, minutes, hours or days (`30s`, `5m`, `1h`, `1d`), up to 90 days. |
| `condition` | `gt`, `gte` or `eq` and a number, plus `field` for `value_count`. Optional for `temporal` (default: every rule); not allowed for `temporal_ordered`. |
| `generate` | `true` lets the base rules raise their own alerts as well. |

A scan detector with `value_count`:

```yaml
correlation:
  type: value_count
  rules: [outbound_connection]
  group-by: [host.id, process.executable, destination.ip]
  timespan: 1m
  condition:
    gte: 25
    field: destination.port
```

And a sequence with `temporal_ordered` (a failed login, then a successful one, from one
address within 10 minutes):

```yaml
correlation:
  type: temporal_ordered
  rules: [ssh_failed_login, ssh_successful_login]
  group-by: [source.ip]
  timespan: 10m
```

### The `count()` aggregation

Older Sigma rules put a count in the condition, with `timeframe`. The rule is then its own
base rule: the part before `|` selects events, and only the threshold raises an alert.

```yaml
detection:
  selection:
    event.action: ssh_login
    event.outcome: failure
  timeframe: 1m
  condition: selection | count() by SourceIp > 10
```

`count()` counts events; `count(User)` counts distinct values of a field (like
`value_count`). `by` takes one field or a comma-separated list, and the operator is `>`, `>=`
or `=`.

### How they behave

- **Base rules stay quiet.** A rule that a loaded correlation rule refers to raises no alert of
  its own unless that correlation sets `generate: true`, as Sigma specifies. A correlation
  rule runs whether or not its base rules are enabled; disable the correlation rule to stop it.
- **Event time.** Windows follow the events' own timestamps, not the server's clock, so events
  that arrive a little out of order (a batch from an agent that was offline) still count
  together as long as they fall inside one window.
- **One alert per window.** When a group (for example one source address) meets the
  condition, it raises one alert, and stays quiet while the condition keeps holding until a
  whole timespan has passed since that alert. After that the next burst alerts again, and
  like any repeat it folds into the open alert for that group.
- **What the alert holds.** The correlation rule's title, id, tags and level; with no level,
  the highest level among its base rules. The description starts with what happened, for
  example `20 events matching "Failed Login From An Address" within 5m (threshold >= 20) for
  source.ip=192.168.1.66.`, and the alert's event is the one that met the condition. Each
  group value gets its own alert.
- **Limits.** Each correlation rule keeps at most 10,000 groups (the least recently updated
  is dropped when a new one arrives) and each group at most 1,000 timestamps or values, so
  thresholds go up to 1,000. Windows live in memory: a server restart starts them empty. A
  rule reload that leaves a correlation rule unchanged keeps its windows.
- **Errors.** A correlation rule whose base rule is not loaded (wrong name, filtered out of a
  repository, a duplicate id) is listed on the **Rules** page with the reason, like any rule
  that fails to load. Custom correlation rules are checked when they are saved.
- **Testing.** **Test** in the rule editor shows the events the selection matches for a
  `count()` rule. It does not run windows, and finds nothing for a correlation rule.

Not supported (the rule is listed with the reason and not loaded):

- "fewer than" thresholds: `lt`/`lte` and `<`/`<=` (for example "fewer than 3 heartbeats an
  hour"). They need the window to close with no event to trigger the check;
- the `value_sum`, `value_avg`, `value_percentile` and `value_median` correlation types;
- correlations of correlation or `count()` rules;
- `min()`, `max()`, `avg()`, `sum()` and `near` aggregations, and `timeframe` without an
  aggregation;
- time spans in months or years.
