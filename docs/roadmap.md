# Roadmap

Features we want in HomeXDR but haven't built yet, roughly in the order we plan to do
them. When one ships, move it to "Done" with its commit and a link to its docs.

## Next up

### Two-factor login (TOTP)
An authenticator-app code on top of the password, since an admin session controls every
endpoint. QR enrollment, one-time recovery codes, a command-line reset for a locked-out
admin, and an option to require it for admins (or everyone).

### Built-in HTTPS for the console
Serve the console over TLS directly, so a password and session never cross the LAN in the
clear when the console is opened without the reverse proxy. A certificate from the
server's own CA (as for agents) with a "download CA certificate" step so browsers trust
it, or an ACME (Let's Encrypt) certificate for anyone with a domain. HTTP then only
redirects.

### Threshold and correlation rules
Rules today match single events. Add counts over a time window ("ten failed SSH logins
from one address in a minute", "Telnet to 20 addresses"), and Sigma's `count()`,
`timeframe` and correlation rules (`event_count`, `value_count`, `temporal`), which the
rule engine currently refuses. Several of the brute-force and scanning rules become far
more precise with them.

### Decoys
Traps an intruder touches but nobody legitimate does, each raising a high alert: fake
credential files (`.aws/credentials`, SSH keys, a `passwords.xlsx`), an unused listening
port on each agent, and canary tokens. The ransomware bait files (under Later) become
part of this.

### Security reviews
Reviews still to do, with fixes as they turn up:
- the agent's platform sensors (about 17,000 lines, run as root or SYSTEM on every host)
- host firewall control, backup and restore, notifications and the AdGuard integration
- the live server configuration on the home server

### Push host firewall blocks to OPNsense
Send the addresses blocked under Settings → Firewall to OPNsense as an alias, for a
network-wide block that also covers devices without the agent.

## Vulnerability scanner (agent + network)

A scanner in the style of commercial vulnerability management tools, in four steps.

1. **On-host (agent).** Windows software inventory (registry, Store apps, build and patch
   level). Linux packages already work; add the kernel and distro release. Matching:
   - Linux packages: OSV.dev and the distros' security trackers (aware of backported fixes)
   - Windows: Microsoft's monthly security-update data (build to CVE)
   - third-party Windows apps: NVD CVEs by product and version, with a confidence level
2. **Network scanner (server), for devices without the agent.** Targets come from the
   device inventory (DHCP, NetFlow, ARP). Port scan, banner and TLS detection, CVE matching
   by product and version, and safe checks only: default-login pages, anonymous FTP,
   Telnet, old TLS and weak ciphers, exposed UPnP or admin panels. Scheduled per VLAN and
   rate-limited, written in Go inside HomeXDR (no nmap dependency).
3. **Console.** Per-host and per-device findings, filters (known exploited, fix available,
   internet-facing), a risk score per asset from CVSS + CISA KEV + FIRST EPSS, fix
   guidance, scan schedules and history, and alerts on new known-exploited findings.
4. **Configuration checks.** A small CIS-style set: SMBv1, RDP without network-level
   authentication, firewall or Defender off, automatic updates off, blank passwords.

Limits: findings on devices without the agent rest mostly on version matching, so they are
marked confirmed or likely.

## Offline protection

Today an agent without a connection to the server only records: the antivirus verdict, kill
and quarantine are decided on the server, and events wait in the agent's spool until it
reconnects. Microsoft Defender keeps protecting Windows hosts on its own. The plan is for the
agent to enforce a signed policy bundle by itself while offline:

- **Hash blocklist and verdict cache.** Known-bad hashes are killed and quarantined on
  launch; the server's recent verdicts (good and bad) travel with the bundle, so a file it
  already judged is not re-checked.
- **IOC firewall rules.** Known-bad addresses and domains blocked in the host's own firewall
  (Windows Filtering Platform, nftables), from the threat feeds and the server's lists.
- **Sticky isolation.** An isolated host stays isolated across reboots and lost connections
  until the server releases it.
- **Local detections.** A small set of high-confidence rules evaluated on the agent, raised
  as alerts when it reconnects.
- The bundle is signed with the release key, has an expiry, and the agent reports which
  version it enforces.

Related: agents away from home reach the server over Tailscale. Add the Tailscale address and
MagicDNS name to `HOMEXDR_SERVER_NAMES` so the agent certificate covers them, and point those
agents at the MagicDNS name; the spool covers the gaps.

## macOS agent, next steps

- **Developer ID signing and notarization**, so Full Disk Access survives updates and an
  MDM profile can grant it (on Apple silicon, today's ad-hoc signature ties the grant to
  one build; unsigned Intel builds keep it).
- **DNS sensor**: the shared DNS parser over a pf/BPF capture of port 53 (no process), or
  mDNSResponder's log.
- **Login items and background tasks** in `persistence.autoruns` (`sfltool dumpbtm`).
- **Network events without polling**, through a Network Extension (needs signing).
- **A `.pkg` installer** for people who don't want to paste a command.

## Later

- **Map Sysmon's other events.** Network (3), file (11, 23, 26), registry (12-14), DNS (22),
  image load (7) and process access/injection (8, 10) to their categories, so the SigmaHQ
  rules for them fire. Needs a Sysmon config that logs them.
- **Scan new executables when they're written**, not only when they run.
- **Ransomware protection.** Bait files (part of Decoys, above), detection of mass renames and encryption,
  automatic isolation, and rollback from Volume Shadow Copy snapshots.
- **Incident view.** Group related alerts and the process tree into one attack timeline.
- **Live response.** A restricted set of signed, logged commands: processes, connections,
  services, autoruns, fetching files.
- **Windows artifact collectors.** Startup items, services, scheduled tasks, installed
  software.
- **Optional uninstall protection.** Removing the agent needs a code from the console.
- **Linux:** flag programs running from memory (memfd) or from deleted files. The agent
  currently strips the "(deleted)" marker.
- **Full PowerShell script block logging** as an install option.
- **More DNS resolvers.** NextDNS (cloud, API key) for devices away from home, and
  reading two resolvers at once (for example two Pi-holes).

## Not planned (needs Microsoft partnership or signing)

- Blocking before execution with HomeXDR's own kernel driver (needs an EV certificate and
  Microsoft signing; Microsoft is moving security products out of the kernel).
- Replacing Defender in Windows Security (Microsoft antivirus partners only).
- Memory scanning for injected code (needs a protected, specially signed driver).

## Done

- Security fixes: getting files from hosts is admin only, quarantine refuses
  operating-system files, AI keys from the environment only go to approved endpoints,
  enrollment tokens expire and are single-use by default, and CI checks Go dependencies
  for known vulnerabilities (govulncheck)
- Windows network isolation through Windows Filtering Platform filters that Windows
  Firewall rules can't override; the server connection always stays open:
  [agent/README.md](../agent/README.md#windows-platform)
- Defender hardening: 14 curated ASR rules, Network Protection and Controlled Folder Access
  (audit), Off/Audit/Enforce globally or per group, Off puts back the previous settings,
  alerts on ASR and Network Protection blocks:
  [antivirus.md](antivirus.md#defender-hardening)
- Host firewall control: blocked addresses everywhere or per group, applied as Windows
  Firewall rules (group "HomeXDR"), nftables (`inet homexdr_block`) and pf, "Block this IP
  everywhere" from an alert: [firewall.md](firewall.md)
- Windows App Control: confirmed malware becomes an "allow everything, deny these files"
  policy applied with CiTool (no reboot), Off/Audit/Enforce globally or per group:
  [antivirus.md](antivirus.md#windows-app-control)
- Groups: enrollment tokens with a group, group filters on Hosts and Alerts, malware
  response and AI analyst overrides: [groups.md](groups.md)
- Host groups (organisation › parent › child) with per-group ClamAV and YARA switches:
  [groups.md](groups.md); Defender and HomeXDR detections of one file share one alert:
  [antivirus.md](antivirus.md#microsoft-defender-and-homexdr-on-the-same-file)
- YARA scanning next to ClamAV: YARA Forge core rules updated daily, your own rules,
  hacking-tool and suspicious matches alert only: [antivirus.md](antivirus.md#yara-rules)
- macOS agent (Intel and Apple silicon): eslogger process, auth, file and security events
  with polling and unified-log fallbacks, lsof network polling, pf isolation, launchd,
  collectors and six macOS rules: [agent/README.md](../agent/README.md#macos-platform)
- Threat map: internet sources reaching the firewall by country, network and port
- Investigate menu on search results, event tables, alerts and hosts: addresses, domains,
  URLs, process and file hashes, the host's address

- Maintenance tuning: SSH key names and maintenance suppressions per key, Docker update and
  appdata backup tagging, container start-up window: [maintenance.md](maintenance.md)
- Console search for pages, settings and sections; copy buttons on alert and host fields

- Defender health alerts (protection off, signatures more than 3 days old) from Defender's own health reports
- AI analyst cost controls: high and above, 20 a day, test hosts skipped; `ai-analyst frugal`
- DNS resolver query log for Pi-hole v6 and Technitium DNS Server, beside AdGuard Home:
  [network-visibility.md](network-visibility.md)
- AdGuard Home history import: [network-visibility.md](network-visibility.md)
- Dashboard top rules open their alerts
- Data retention page: usage, disk, next falloff, changes behind two confirmation steps:
  [retention.md](retention.md)
- Cloud backup to S3-compatible storage (cold archives, import back): [retention.md](retention.md)
- Windows process sensor, service install, audit setup (2676a77): `agent/README.md`
- Windows eventlog sensor: Security, PowerShell, Defender and more (cdfd6ca)
- Antivirus: hash reputation + ClamAV, automatic kill and quarantine (e962f3d):
  [antivirus.md](antivirus.md)
- Microsoft Defender actions from the console (d22c66f): [antivirus.md](antivirus.md)
- Investigate page: IOC lookups in threat intel and in your own events (638ff03):
  [intel.md](intel.md)
