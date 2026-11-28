# Roadmap

Features we want in HomeXDR but haven't built yet, roughly in the order we plan to do
them. When one ships, move it to "Done" with its commit and a link to its docs.

## Next up

### Sign-in: passkeys and single sign-on
Two-factor codes are in. Next: passkeys (Face ID, Touch ID, Windows Hello, security keys),
which cannot be phished and need the console on HTTPS, and sign-in through an identity
provider (OIDC: Okta, Microsoft Entra, Authentik, Authelia) for people who run one. An
option to require two-factor login for admins.

### Follow-ups to correlation rules and decoys
- Correlation conditions "fewer than N" (lt/lte), which need windows evaluated as they
  close, and value_sum/avg; windows survive a server restart.
- Decoys: report reads on Windows (file auditing on the decoys) and macOS (Endpoint
  Security open events); an unused listening port on each agent and canary tokens; remove
  decoys on uninstall.

### Security reviews
The agent's sensors and the integrations (host firewall, backup, notifications, DNS
resolvers) were reviewed in November 2026 and the quick fixes are in. Found and still open:
- **Labels a local user can forge.** On Linux the `maintenance`, `ssh_session`, `ssh_key`
  and container labels are derived from a process's own arguments, name or cgroup, and
  from log lines any user can write. They feed alert suppression, so they must come from
  facts a user cannot set (root-owned sshd by path, runtime-owned cgroups). On Windows SSH
  tagging trusts the image name `sshd.exe`, and `sshd-session.exe` is not recognised.
- **The Windows program-data folder.** Only the data folder and the config file get a
  locked-down ACL. The parent folder must be created, owned and protected by the installer,
  which should refuse a folder someone else made first.
- **Executable hash cache.** The cache key (file identity, size, modification time) can be
  kept the same by the file's owner while the content changes. Add the change time (file
  ID and USN on Windows) and do not cache files a user can write.
- **File event rate limit.** One limit covers every path, so a flood in a temp folder can
  hide a write to a system path. Limit per tree and never drop system paths.
- **Network paths on Windows.** File details for a program started from a network share
  are read on the event reader, which a slow share can stall.
- **Links in tailed and integrity-monitored paths**, which only matters when an
  administrator points them at a folder a user can write.

Reviews still to do:
- the rest of the agent: the network sensors, software inventory, enrollment and self-update
- syslog and NetFlow ingestion
- the live server configuration on the home server

### Agents away from home
Started November 2026 ([away-from-home.md](away-from-home.md)). A second agent listener
for a port forward requires a valid, unrevoked agent certificate in the TLS handshake and
serves only enrolled agents' routes; enrollment, installer scripts and the CA certificate
stay on the local listener. One name with split DNS works at home and away. The host page shows each host's last
address and listener, and Data health counts refused connections with an alert on a sudden
rise. Still to do:
- **Penetration testing of the open port** (TLS settings, handshake floods, what an
  attacker with a stolen device's certificate can reach).

### Data saver on metered networks
Detect a metered or low-data connection (Windows connection cost, macOS expensive and
constrained paths, NetworkManager's metered flag on Linux) and hold the large transfers
until an unmetered one: antivirus file uploads, artifact collection, inventory and agent
updates. Events, alerts and response commands are still sent immediately, so nothing is
lost, only delayed. Holding antivirus uploads is a group setting (default: hold), and the
host page shows when a host is on a metered network.

### Push host firewall blocks to OPNsense
Send the addresses blocked under Settings → Firewall to OPNsense as an alias, for a
network-wide block that also covers devices without the agent.

### Ingest logs from any firewall or platform
OPNsense/pfSense filterlog, Suricata EVE, DHCP, DNS and sshd syslog were the first sources
parsed into network events. Built from each vendor's documented log format, and not yet
tested against real devices ("community tested" once someone confirms them), are FortiGate,
Palo Alto, Sophos, MikroTik and Ubiquiti (UniFi gateways and EdgeRouters) firewall logs. They
all become `event.module:firewall` with the same fields, so detections and the exposure views
work for every vendor. Any product that can send CEF or LEEF is also read: a line with
addresses and an allow/deny verdict becomes a firewall event, anything else keeps its fields
as `cef.<vendor>` or `leef.<vendor>`. Other formats are still stored as plain syslog lines
that cannot be correlated.
An admin can bind a sender to one parser under Settings → Integrations (for example to
show pfSense instead of OPNsense, or to stop decoding a noisy device); a line that parser
cannot read still goes through auto-detection.
The goal is to bring in any source and join it to endpoint activity. Correlation already
works on normalized fields (5-tuple, Community ID, IP/MAC, host name, user, DNS name,
hash), so the work is getting every source into that schema. In phases:
1. **Decoder registry and common formats.** Replace the hardcoded dispatch in the syslog
   package with a registry of decoders (match and decode). Add generic decoders for CEF,
   LEEF, key=value, CSV and JSON, driven by a table that maps vendor field names to ours
   and normalizes actions to allowed/denied. Always compute the Community ID for network
   events. Let an admin bind a sender IP to a parser on Data health; auto-detection stays
   the fallback.
2. **More ways in.** An authenticated HTTP endpoint for JSON/NDJSON and syslog over TLS, so
   shippers such as Vector, Fluent Bit and Logstash can deliver anything.
3. **Parsers as data.** Declarative YAML parsers (how to recognize, extract and map) with
   sample lines as their tests, shared through the rule repository so the community can
   add vendors without writing Go. A "paste a line, see the event" tester in the console,
   and per-source parse rates on Data health so unparsed sources are visible.
4. **Better entity resolution.** IP-to-host mapping at the time of the event (agent
   addresses, DHCP leases, ARP), NAT-aware fields (pre-NAT addresses, interface
   direction), more join keys (user, domain, file hash, MAC) so identity, DNS and proxy
   logs correlate too, and detection rules written against the normalized fields so they
   work for every vendor.

## Vulnerability scanner (agent + network)

A scanner in the style of commercial vulnerability management tools. Linux packages are done
(shipped 2026-11-26, see [vulnerabilities.md](vulnerabilities.md)): OSV distro advisories for
Debian, Ubuntu, Alpine, Rocky and AlmaLinux, a risk score from CVSS x likelihood (internet
exposure from the firewall log, attack vector, EPSS, CISA KEV), and the Vulnerabilities page.
The rest is split into phases below, in the order we plan to build them. Each phase ships on
its own and has a "done when" line.

| Phase | What | Status |
|---|---|---|
| 1 | Windows software inventory and matching | Not started |
| 2 | Docker image contents | Not started |
| 3 | Network scanner for devices without the agent | Not started |
| 4 | Per-port exposure | Not started |
| 5 | Configuration checks | Not started |
| 6 | macOS applications | Not started |

### Phase 1: Windows
- **Inventory (agent):** installed programs from the registry (both 32 and 64 bit), Store
  apps, OS build number and installed patches (KB list). Sent like the Linux package list.
- **OS matching:** Microsoft's monthly security-update data, mapping build and patch level to
  CVEs, with the fixing KB shown as the fix.
- **Third-party apps:** NVD CVEs by product and version (CPE), marked confirmed or likely.
  Reuses the NVD lookup that already runs for Unraid's release (the privacy switch applies).
- **Console:** Windows hosts appear on the Vulnerabilities pages with the same risk score,
  and the per-group Vulnerability management switch covers them.
- **Done when:** a Windows host shows OS and third-party findings with a fix, tested on the
  Windows test VM.

### Phase 2: Docker image contents
Today only the image name and tag are known. Read the package list inside each running
image (apk, dpkg, rpm databases) from the agent and match it with the existing Linux
matcher, so findings name the container and image. Done when a container's vulnerable
package shows up under its host with the image tag.

### Phase 3: Network scanner (server)
For devices without an agent. Targets come from the device inventory (DHCP, NetFlow, ARP).
Port scan, banner and TLS detection, CVE matching by product and version, and safe checks
only: default-login pages, anonymous FTP, Telnet, old TLS and weak ciphers, exposed UPnP or
admin panels. Scheduled per VLAN, rate limited, written in Go inside HomeXDR (no nmap
dependency). Scans only ranges the admin lists. Done when a scheduled scan of one VLAN
creates findings on agentless devices, each marked confirmed or likely.

### Phase 4: Per-port exposure
Today exposure is judged per host from the firewall log. Make it per listening port, using
the agent's listening-socket list and port forwards seen in the firewall log, so a CVE in a
service that is not reachable from outside is scored lower than one that is.

### Phase 5: Configuration checks
A small CIS-style set: SMBv1, RDP without network-level authentication, firewall or Defender
off, automatic updates off, blank passwords. Shown as findings with a fix, not as alerts.

### Phase 6: macOS applications
App inventory (bundles and Homebrew) matched by product and version through NVD, marked
confirmed or likely. The macOS OS release itself is covered by Apple's security releases.

### Cross-cutting
- Per-host and per-device filters (known exploited, fix available, internet-facing), scan
  schedules and history, and an alert on a new known-exploited finding.
- Findings on devices without the agent rest mostly on version matching, so they are
  marked confirmed or likely.
- Not planned: Slackware and Unraid packages (no advisory feed has fixed versions) and Red Hat
  Enterprise Linux itself.

## Active Directory

Domain controller visibility, directory-aware detections, and later a directory connector.
Phases 1 and 2 need only the agent and the firewall log, so they come first. Each phase
ships on its own and has a "done when" line. Phase 3 uses the GOAD lab
(github.com/Orange-Cyberdefense/GOAD) as the test target.

| Phase | What | Status |
|---|---|---|
| 1 | DC audit setup and event coverage | Done, verified on a real DC |
| 2 | AD detection rule pack | Not started |
| 3 | Test lab and walkthrough | Not started |
| 4 | Directory sync (identity inventory) | Not started |
| 5 | Identity view and attack paths | Not started |
| 6 | Domain-aware response actions | Not started |
| 7 | Entra ID and hybrid sources | Not started |

### Phase 1: DC audit setup and event coverage
- **Detect domain controllers:** the agent sees the NTDS service and tags the host
  "Domain controller".
- **Audit gaps:** the console lists which audit subcategories are off on a DC (Kerberos
  service ticket operations, directory service access and changes, account management,
  logon) with the exact `auditpol` and GPO settings. HomeXDR does not change policy.
- **Missing events:** map 4662 (object access, used by DCSync), 4742 (computer account
  changed), 4741 (computer created), 4729, 4733 and 4757 (group member removed), 5136
  (directory object modified), 4738 field detail, 4771 (Kerberos pre-auth failed), and
  4673.
- **Kerberos fields:** parse ticket encryption type, service name, client address and
  failure code into searchable ECS-style fields.
- **Optional channels:** Directory Service, DNS Server and AD CS (certificate services) logs.
- **Done when:** a DC shows the tag, the audit-gap check, and parsed Kerberos and directory
  events, verified on a real DC.
- **Status (November 2026):** done and verified on a real Windows Server 2025 domain
  controller (a throwaway test forest). The agent tags the host
  (`roles: ["domain_controller"]`), reports `dc_audit_gaps` with the `auditpol` fix per
  subcategory, maps the events above, and fills `kerberos.*` fields. On the test DC the
  audit read found six gaps. After the fixes were applied and the agent restarted, the list
  came back empty. The real EventData field names matched the mapping for 4662, 4720, 4738,
  4741, 4742, 4728, 4729, 4732, 4733, 4756, 4757, 4768, 4769, 4771, 4776 and 5136, so no
  mapping changes were needed. Public Sigma AD rules already fire on this data.
  Not yet covered: the optional Directory Service, DNS Server and AD CS channels.

### Phase 2: AD detection rule pack
- **Credential and ticket abuse:** Kerberoasting (4769 with RC4 tickets for user accounts),
  AS-REP roasting (4768 without pre-auth), DCSync (4662 with replication rights from a
  non-DC), password spraying (many 4625 or 4771 across accounts from one source), golden
  ticket indicators, and NTLM relay or coercion indicators.
- **Directory changes:** privileged group changes (Domain Admins, Enterprise Admins, Schema
  Admins, AdminSDHolder), computer account creation and abuse (4741, 4742), GPO changes
  (5136), SID history, unconstrained delegation changes, AD CS template abuse (ESC1 and
  similar), and audit log cleared on a DC.
- **Each rule** has a false-positive note and an ATT&CK tag.
- **Public rules:** a documented, tested import path for public Sigma AD rules, with a list of
  which ones work and which need fields HomeXDR does not map yet.
- **Done when:** each rule fires on its attack in the test lab and stays quiet on normal DC
  traffic.

### Phase 3: Test lab and walkthrough
- A write-up for running GOAD with HomeXDR agents on its domain controllers and servers, in
  `docs/`.
- A table of GOAD attack techniques: what HomeXDR detects, what it misses, and why.
- A short list of known gaps that feeds back into Phase 2.
- **Done when:** the table comes from an actual run, not from reading the code.

### Phase 4: Directory sync (identity inventory)
- An optional read-only LDAP connector with a service account, set up in the console.
  Credentials are stored encrypted, like other secrets.
- Imports users, groups, computers, OUs, trusts and GPO links on a schedule, with change
  tracking, so an admin can see who was added to a group and when.
- Matches imported computers to enrolled hosts, and users to logon events.
- LDAPS or Kerberos bind only. Plain LDAP is refused unless explicitly allowed.
- **Done when:** an alert shows the account's groups and last logon, and the host list shows
  which machines are domain joined.

### Phase 5: Identity view and attack paths
- A user page with logons by host, group memberships, privileged status and recent alerts.
- Flags for risky accounts: stale privileged accounts, accounts with SPNs, accounts without
  pre-auth, unconstrained delegation, and passwords that never expire.
- A simple path view built from sessions and group membership, such as "this admin logged
  on to this workstation". It is not a BloodHound replacement, and the docs say so.
- **Done when:** the lab shows a path from a compromised workstation to a Domain Admin session.

### Phase 6: Domain-aware response actions
- Disable an account, force a password reset, remove an account from a group, and revoke a
  user's sessions.
- Each action needs the admin role, is written to the audit log, needs confirmation in the
  console, and is off by default.
- **Done when:** each action works end to end in the lab, and the audit log records who ran it.

### Phase 7: Entra ID and hybrid sources
- Ingest Entra ID sign-in and audit logs and Microsoft 365 audit logs.
- Overlaps with the cloud and SaaS log ingestion gap, so it shares that work.
- **Done when:** a hybrid sign-in appears next to the on-prem logon for the same user.

### Cross-cutting
- An AD health page: audit gaps, DCs without an agent, and rule coverage.
- Retention guidance for DC logs, which are high volume.
- Not planned: managing AD itself (creating users or editing GPOs), and replacing
  PingCastle or Purple Knight for AD misconfiguration scoring.

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

- **Developer ID signing and notarization**, so an MDM profile can grant Full Disk Access
  and Gatekeeper accepts the download. (Full Disk Access already survives updates with the
  self-signed certificate in `deploy/macsign`.)
- **DNS with process and encrypted lookups**: the BPF sensor shipped (port 53, no process),
  but it cannot see a Mac's own lookups when macOS upgrades to encrypted DNS. mDNSResponder's
  log has the process and query type but hides the names.
- **Network events without polling**, through a Network Extension (needs signing).
- **A `.pkg` installer** for people who don't want to paste a command.

## Later

- **Map Sysmon's other events.** Remote threads (8), process access (10) and tampering
  (25) are mapped and turned on by the agent. Still to do: network (3), file (11, 23, 26),
  registry (12-14), DNS (22) and image load (7), so the SigmaHQ rules for them fire; the
  agent's Sysmon config would log them too.
- **Scan new executables when they're written**, not only when they run.
- **Ransomware protection.** Bait files (part of Decoys, above), detection of mass renames and encryption,
  automatic isolation, and rollback from Volume Shadow Copy snapshots.
- **Incident view.** The storyline graph groups an attack chain's alerts; still to do: a
  timeline across hosts, and finding who created the task or service that started a
  storyline's root.
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

- November 2026: a per-group **Vulnerability management** switch (inherited, On by default)
  that leaves a group's hosts out of the Vulnerabilities pages and counts while their software
  inventory is still collected ([vulnerabilities.md](vulnerabilities.md#leaving-hosts-out)).
- November 2026: the alert storyline, a graph of the whole attack chain around an alert
  with cross-process links, scheduled-task, service and WMI launches, alerts and ATT&CK
  tactics per process ([storyline.md](storyline.md)); Windows agents turn on Sysmon (the
  built-in Windows feature) and configure remote-thread, process-access and tampering
  events, per group ([sysmon.md](sysmon.md)).
- November 2026: optional two-factor login (authenticator codes with recovery codes and an
  admin reset), built-in HTTPS for the console (HomeXDR CA or your own certificate files,
  optional redirect), threshold and correlation rules (Sigma `count()` and correlation
  rules), decoy files on every agent, the Task Scheduler log turned on by the Windows
  install, and host addresses plus refused-connection monitoring for agents away from home.
- Security fixes (November 2026 review): install commands check the downloaded script's
  SHA-256 before running it; sign-in and two-factor limits hold under parallel requests,
  count IPv6 per /64 and cap wrong codes per account with an alert; syslog messages no
  longer rename named network devices; expired agent certificates renew only within 180
  days of expiry; backup import checks each archive against the hash and size recorded
  when it was made (or its manifest, on a server without the record), rejects events
  outside the day and caps the decompressed size, and inserts nothing unless every event
  passes ([retention.md](retention.md)).
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
