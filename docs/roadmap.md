# Roadmap

Features we want in HomeXDR but haven't built yet, roughly in the order we plan to do
them. When one ships, move it to "Done" with its commit and a link to its docs.

## Next up

### Windows: block known malware before it runs (App Control)
Turn the antivirus blocklist and confirmed malware hashes into a Windows App Control
(WDAC) deny policy ("allow everything, deny these hashes"), pushed to each PC with
`CiTool` so it applies without a reboot. Windows' own code integrity then refuses to start
those files. Test on the VM first: edition support on Pro, policy size limits, and a
one-click way to remove the policy.

### Defender health and hardening
- Alerts when Defender's real-time protection is off or signatures are more than a few days old.
- Hardening profiles in the agent config, audit mode first: Attack Surface Reduction rules,
  Controlled Folder Access and Network Protection.

### Windows network isolation
Isolate a Windows host with one click, through Windows Filtering Platform filters that
Windows Firewall rules can't override. The connection to HomeXDR always stays open.

### Host firewall control
Manage HomeXDR-owned Windows Firewall rules (their own "HomeXDR" group, removed on
uninstall), with per-label policies from the console and "block this IP everywhere" from an
alert. The same block policies apply on Linux through the agent's nftables table.
Optionally push blocks to OPNsense for network-wide effect.

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

## Later

- **Map Sysmon's other events.** Network (3), file (11, 23, 26), registry (12-14), DNS (22),
  image load (7) and process access/injection (8, 10) to their categories, so the SigmaHQ
  rules for them fire. Needs a Sysmon config that logs them.
- **Scan new executables when they're written**, not only when they run.
- **Ransomware protection.** Bait files, detection of mass renames and encryption,
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
