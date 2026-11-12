# Detection rules

HomeXDR loads [Sigma](https://sigmahq.io/) rules from three places:

- this directory (in the Docker image: `/usr/share/homexdr/rules`, set with
  `HOMEXDR_RULES_DIR`), read recursively;
- rule repositories imported in the console, such as SigmaHQ, which the server downloads and
  keeps up to date (below);
- custom rules written in the console, stored in the database.

## Rules HomeXDR ships

`rules/homexdr/` holds rules for what community rule sets leave out on a homelab: Docker and
Unraid hosts, SSH, DNS lookups from a resolver's query log, OPNsense, and attempts to switch
HomeXDR's own monitoring off. They load with the server and
are tested in `server/internal/detect/homexdr_rules_test.go` and `homexdr_rules2_test.go`.
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
whole repository. Rules that use features the engine does not support yet (aggregations,
correlations, `|expand`) are skipped and listed on the **Rules** page with the
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
