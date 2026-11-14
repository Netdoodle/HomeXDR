# Antivirus

HomeXDR judges every program that starts on an enrolled host and, when one is malware,
has the agent stop it and quarantine the file. Settings → Antivirus turns it on or off,
chooses the response and lists recent detections.

## How a program is judged

The agents' process events carry the executable's SHA-256 (`process.hash.sha256`; on
Windows from Sysmon or computed by the agent, on Linux computed by the agent when
`hash_executables` is on). For each hash, in order:

1. **Allowlist and blocklist.** Hashes you list under Settings → Antivirus. A blocked
   hash is malware wherever it runs; an allowed one is never checked.
2. **Stored verdict.** Each file is judged once for all hosts (`av_verdicts` table). A
   file found clean is scanned again when it runs more than 7 days later, so newer
   signatures get a chance.
3. **Operating system files are left alone.** Programs under `C:\Windows\System32`,
   `SysWOW64`, `WinSxS`, `C:\Program Files\WindowsApps` and similar, or `/usr`, `/bin`,
   `/sbin`, `/lib` on Linux, are not looked up or uploaded. The blocklist still applies.
4. **Threat intel.** The hash (never the file) is looked up with the sources set up under
   Settings → Threat intel: MalwareBazaar, VirusTotal, ThreatFox, OTX with their keys, and
   CIRCL hashlookup without one. A malicious verdict is a detection; a file CIRCL knows
   from a software distribution is "known good" and not uploaded.
5. **ClamAV and YARA.** A program nobody vouches for is uploaded from the host (a
   `file.get` command issued by `antivirus`, up to the size limit, 64 MB by default) and
   scanned by a ClamAV daemon and the YARA scanner, both next to the server. ClamAV's
   signatures cover known samples; YARA's community rules describe malware families and
   tools by their code and strings, so they often catch new builds that have no signature
   yet. The upload is deleted after the scan. If either scanner fails, no verdict is
   stored and the file is tried again the next time it runs. A host that cannot hand a
   file over (too large, gone, not allowed) is not asked for it again for a day; other
   hosts that run the same file are still asked.

### Scanner switches

Settings → Antivirus turns ClamAV and YARA on or off for every host; host groups can
override either for their hosts (Settings → Groups, [groups.md](groups.md)). A detection
by a scanner that is off for a host's group raises nothing on that host, and a file found
clean without a scanner a host's group wants is scanned again when that host runs it.

## Microsoft Defender and HomeXDR on the same file

When Defender and HomeXDR's antivirus both detect one file on one host, they share one
alert instead of two. Defender's detection events (1006, 1007, 1008, 1015, 1116 to 1119,
through the eventlog sensor) and HomeXDR's detection both carry a link key, the host and
the file path (case-insensitive on Windows; for a file inside an archive, the archive).
Whichever comes second folds into the open alert of the first: the alert lists it under
**Also detected by** with its rule, source and hit count, its events join the alert's,
and the alert takes the higher severity of the two. Defender's later events about the same
file (the action it took, 1117) fold in the same way, and detections of different files on
one host stay separate alerts. A closed alert no longer absorbs anything: a later detection
opens a new one.

## YARA rules

The scanner (`homexdr-yara`, its own container) downloads the [YARA Forge](https://yarahq.github.io/)
**core** package once a day: about 5,000 rules from public collections that passed YARA
Forge's quality, score and age checks, chosen for few false positives. A new package
replaces the old one only after it compiles.

What a match does depends on the kind of rule, read from its name:

| Rule | Example | Verdict source | Response |
|---|---|---|---|
| Malware family, exploit, APT tooling | `MALPEDIA_Win_Agent_Tesla_Auto` | `yara` | Like any detection: critical alert, stop and quarantine |
| Hacking or remote-admin tool (`HKTL`, `Hacktool`, `TOOL`, `PUA`) | `SIGNATURE_BASE_HKTL_Mimikatz` | `yara:tool` | High alert "Hacking tool detected", **never stopped automatically** |
| Generic suspicious trait (`SUSP`, `INDICATOR`, packed, anomaly) | `SIGNATURE_BASE_SUSP_PS1_JAB_Pattern` | `yara:suspicious` | Medium alert "Suspicious program", **never stopped automatically** |

Tools and generic traits match programs people run on purpose (admin tools, packed
installers), so HomeXDR leaves those for you to judge: stop and quarantine from the host
page, or allowlist the hash. When several rules match, the most serious one names the
detection ("… (+2 more)").

**Your own rules.** Put `*.yar` or `*.yara` files in the folder mounted at `/rules`
(`deploy/yara-rules` with the stock compose file). They are picked up within a minute, in
the `custom` namespace, and count as malware unless their name says tool or suspicious as
above. If they don't compile, the package keeps working without them and Settings →
Antivirus shows the compiler's error.

Scanner settings (environment of the `yara` service):

| Variable | Default | |
|---|---|---|
| `YARA_FORGE_URL` | core package | Another package (`…/yara-forge-rules-extended.zip`, `-full.zip`: more rules, more false positives), or `off` for your rules only |
| `YARA_UPDATE_HOURS` | 24 | How often to check for a new package |
| `YARA_MAX_MB` | 100 | Largest file accepted |
| `YARA_PARALLEL` | 2 | Files scanned at once |

## Response

With "Stop the process and its children, quarantine the file" (the default), a
detection sends two signed commands, the same ones a person can send from the host
page: `process.kill` with the process' entity ID and `tree: true`, then
`file.quarantine`. The kill checks the entity ID, so a PID reused since the event is
never hit, and system-critical Windows processes are refused. Operating-system files are
never quarantined (the process is still stopped; see the agent README). A quarantined file can be
restored from the host's page. Either way a **critical** alert "Malware detected:
<signature>" is raised (rule `av:malware`, dataset `homexdr.av`), with the hash, path,
source and what was done in its data. YARA matches for hacking tools and suspicious
traits are the exception: they raise "Hacking tool detected" (`av:hacktool`, high) or
"Suspicious program" (`av:suspicious`, medium) and are never stopped automatically (see
[YARA rules](#yara-rules)). The host's local policy must allow the actions
(`file.get`, `process.kill`, `file.quarantine`; all are allowed by default).

A detection can be undone with **Forget** under Recent detections (for a false
positive): the verdict is removed and the file is judged again the next time it runs.
Add the hash to the allowlist to stop it being checked at all.

## What it is not

There is no kernel driver, so HomeXDR cannot block a program before it starts: it acts
within seconds after. It also does not scan files that are only written, not run. Keep
Windows Defender (or another real-time antivirus) on. Only Microsoft's antivirus partners
can replace Defender in Windows Security, and Defender's detections reach HomeXDR anyway
through the eventlog sensor (alert "Windows Defender Threat Detected").

## Windows App Control

HomeXDR stops malware seconds after it starts. App Control goes further on Windows: every
file the antivirus confirmed as malware goes into a Windows App Control (WDAC) policy,
"HomeXDR block list", on each Windows host, and Windows' own code integrity then refuses
to start it, on every PC and not only the one where it was found.

| Mode | What Windows does |
|---|---|
| Off (default) | No HomeXDR policy; an applied one is removed |
| Audit | Runs the file and logs CodeIntegrity event 3076 ("would have been blocked") |
| Enforce | Refuses to run the file; logs event 3077 |

The mode is under Settings → Antivirus ("Windows App Control for confirmed malware") and
can be overridden per group (Settings → Groups). Start with Audit, check the
`Microsoft-Windows-CodeIntegrity/Operational` log, then enforce.

**What is blocked.** Malicious verdicts (ClamAV, YARA malware rules, threat intel, the
blocklist) whose Authenticode hash is known, minus allowlisted hashes. YARA matches for
hacking tools and suspicious traits are never blocked. App Control matches files by their
Authenticode hash (the PE file without its signature), not the SHA-256 HomeXDR shows
elsewhere, so a file joins the list once that hash is known: the server computes it for
every file it fetches to scan, after checking that the upload really has the SHA-256 the
agent reported. The hash is never taken from an agent's word, because the list goes to
every Windows host and one compromised agent could otherwise have any program blocked
everywhere. Malware known only from threat intel or the blocklist, which the server never
fetches, is still stopped and quarantined where it runs but is not on the App Control
list. Settings → Antivirus → Windows App Control lists the blocked files and each Windows
host's state.

**How it is applied.** The server checks every minute whether each Windows host's policy
matches its group's mode and the current list, and sends a signed `appcontrol.apply`
command when it does not. The agent writes the policy (allow everything, deny these
Authenticode SHA-256 and SHA-1 hashes, user-mode only), compiles it with
`ConvertFrom-CIPolicy` and activates it with `CiTool --update-policy`: no reboot. Script
enforcement is off in the policy, so PowerShell keeps its full language mode. Off (or an
empty list) removes it with `CiTool --remove-policy`. HomeXDR only ever touches its own
policy ID (`{E4AB46CA-CD05-4CB9-8AEB-D62DFD1225F2}`). Needs Windows 11 22H2 or later
(Pro is enough; tested on Windows 11 Pro 25H2).

Agents enrolled before App Control need `appcontrol.apply` in `allowed_actions` in their
`agent.json` (the host shows "Not allowed" until then). To remove the policy by hand on a
PC: `CiTool --remove-policy "{E4AB46CA-CD05-4CB9-8AEB-D62DFD1225F2}"`.

## Microsoft Defender actions

On Windows hosts the host page's Actions tab has a **Microsoft Defender** card. It sends
`defender.action` commands, a fixed set of operations that the agent runs through
Defender's own PowerShell module and `MpCmdRun.exe`:

| Action | What Defender does |
|---|---|
| `status` | Reports real-time protection, Tamper Protection, signature version and age, and the threats it knows (merged by threat ID, with any per-threat action set on the host) |
| `scan` `quick` / `full` | Starts the scan in the background; detections arrive as alerts (Defender events 1116/1117 through the eventlog sensor) |
| `scan` `path` | Scans one file and reports whether it found a threat |
| `update` | Updates signatures now |
| `remove_threats` | Cleans every active threat (`Remove-MpThreat`) |
| `allow_threat` | For a false positive: sets the threat ID's action to Allow (`ThreatIDDefaultAction`) and restores its files from Defender's quarantine |
| `block_threat` | Undoes an allow: the threat is quarantined again when found |

The threat ID is in the Defender alert's event data (`Threat ID`). These work with
Tamper Protection on (tested on Windows 11 25H2). HomeXDR never turns Defender off. Like
every action, `defender.action` must be in the agent's `allowed_actions` (it is in the
default list for new agents; add it to `agent.json` on hosts enrolled earlier) and is
recorded in the audit log.

## Defender hardening

Microsoft Defender Antivirus has protections that are off on a fresh Windows install:
Attack Surface Reduction (ASR) rules, Network Protection and Controlled Folder Access.
HomeXDR can turn on a fixed, curated set of them on every Windows host, globally (Settings
→ Antivirus, "Microsoft Defender hardening") or per group (Settings → Groups):

| Mode | ASR rules | Network Protection | Controlled Folder Access |
|---|---|---|---|
| Off (default) | Put back as they were before HomeXDR | Put back | Put back |
| Audit | Audit (event 1122) | Audit (event 1125) | Audit (event 1124) |
| Enforce | Block (event 1121), except the PSExec/WMI rule, which stays in audit | Block (event 1126) | Audit (event 1124) |

Start with Audit, search the Defender log for 1122 and 1125 events
(`event.dataset:windows.windefend`) for a week or two, then enforce.

**The ASR rules.** GUIDs are from Microsoft's
[ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference):

| Rule | GUID |
|---|---|
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block credential stealing from the Windows local security authority subsystem (lsass.exe) | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office applications from injecting code into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Block Office communication application from creating child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| Block process creations originating from PSExec and WMI commands (audit only) | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |

Left out on purpose: "Block executable files from running unless they meet a prevalence,
age, or trusted list criterion" and "Use advanced protection against ransomware" (both
block new, unknown programs, such as your own builds), "Block use of copied or
impersonated system tools" (heuristic, blocks portable tools), "Block rebooting machine in
Safe Mode" and "Block Webshell creation for Servers" (Exchange servers only). The
PSExec/WMI rule stays in audit even under Enforce because it breaks remote management
tools and installers that start processes through WMI.

**Controlled Folder Access stays in audit mode**, in both Audit and Enforce: in block mode
it stops every program Defender does not know from saving into Documents, Pictures, the
Desktop and the other protected folders, which breaks ordinary programs (games, editors,
your own scripts) until each one is allowed. The audit events still show what ransomware-
like writes happen. To block, turn it on by hand on a host
(`Set-MpPreference -EnableControlledFolderAccess Enabled`); HomeXDR does not weaken a
setting that was stronger before it touched it (below), and the "Defender Controlled
Folder Access Blocked A Write" rule alerts on its blocks.

**How it is applied.** Like App Control: the server checks every minute whether each
Windows host's applied mode matches its group's, and sends a signed `defender.harden`
command when it does not. The command carries only the mode and a version (the profile
revision); the rule list is built into the agent, so the command cannot change any other
Defender setting. The agent uses Defender's PowerShell module: `Add-MpPreference
-AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions` per rule (rules
you set yourself for other GUIDs are never touched; `Set-MpPreference` would replace the
whole list), and `Set-MpPreference -EnableNetworkProtection` /
`-EnableControlledFolderAccess`. It then reads everything back with `Get-MpPreference`
and reports what Defender actually has. A setting Defender kept (a Group Policy or MDM
setting overrides local ones, the cmdlet was refused) is listed on the host's row and the
host shows **Partly applied**; it is tried again daily. Defender in passive mode (another
antivirus is the active one) fails the command: these protections only work when Defender
is the active antivirus.

**What Off puts back.** The first time HomeXDR changes a setting, the agent records the
value from before in `defender-hardening.json` in its data directory (for example
`C:\ProgramData\HomeXDR\data\`). Turning a mode on never weakens a setting that was stronger
before (a rule you already had in Block stays in Block under Audit). Off is only sent to
hosts HomeXDR hardened; it puts each setting back to its recorded value (an ASR rule that
was not configured is removed from Defender's list again), but only where the setting still
has the value HomeXDR gave it: one you changed by hand afterwards is left alone and named
in the result. The record is then deleted. Uninstalling the agent does not undo the
hardening: set the host's group to Off first.

**Alerts.** Defender's events reach HomeXDR through the eventlog sensor. Blocks raise
alerts from three shipped rules: "Defender Attack Surface Reduction Rule Blocked An
Action" (1121, medium), "Defender Network Protection Blocked A Connection" (1126, medium)
and "Defender Controlled Folder Access Blocked A Write" (1123, low). Audit events (1122,
1124, 1125) are searchable but raise no alert. The rule GUID is in the event's `ID` field.
To exempt a program from one rule, add an ASR exclusion on the host
(`Add-MpPreference -AttackSurfaceReductionOnlyExclusions 'C:\Path\tool.exe'`), or move the
host to a group with hardening Off or Audit.

**Checking and undoing by hand** (elevated PowerShell on the host):

```powershell
# What Defender has now: rule GUIDs and actions (0 off, 1 block, 2 audit, 6 warn),
# Network Protection and Controlled Folder Access (0 off, 1 on, 2 audit)
$p = Get-MpPreference
0..($p.AttackSurfaceReductionRules_Ids.Count - 1) | ForEach-Object {
  "$($p.AttackSurfaceReductionRules_Ids[$_]) $($p.AttackSurfaceReductionRules_Actions[$_])" }
$p.EnableNetworkProtection; $p.EnableControlledFolderAccess
# What HomeXDR changed and the values from before
Get-Content C:\ProgramData\HomeXDR\data\defender-hardening.json
# Undo one rule / everything by hand
Remove-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Set-MpPreference -EnableNetworkProtection Disabled -EnableControlledFolderAccess Disabled
```

Agents enrolled before this feature need `defender.harden` in `allowed_actions` in their
`agent.json` (the host shows "Not allowed" until then). Every command is in the audit log
(`defender.harden`).

## Setup

`deploy/docker-compose.yml` runs `clamav/clamav` and the YARA scanner (built from
`deploy/yara/Dockerfile`) next to the server, and sets `HOMEXDR_CLAMD_ADDR=clamav:3310`
and `HOMEXDR_YARA_ADDR=yara:3320`. Either scanner can be left out by removing its service
and variable; with neither there is no file scanning, but the blocklist, stored verdicts
and threat intel still work. ClamAV needs about 1.5 GB of memory and downloads its
signatures (about 110 MB) on first start; `freshclam` inside the container keeps them
current. The YARA scanner needs about 100 MB and compiles its rules in a few seconds on
start. The updater (`deploy/update`) rebuilds the scanner image after each server update.

Custom signatures go in ClamAV's database directory as `*.hsb` files (one
`sha256:size:Name` line per file) and are loaded at clamd's next reload
(`docker exec <clamav container> clamdscan --reload`).

## API

| Method | Path | Role | |
|---|---|---|---|
| GET | `/api/antivirus` | viewer | Settings, ClamAV and YARA status, verdict counts, recent detections |
| GET | `/api/appcontrol` | viewer | App Control: global mode, blocked files, each Windows host's mode and state |
| GET | `/api/defender/hardening` | viewer | Defender hardening: global mode, profile revision, each Windows host's mode (and the group it comes from), status, message, failures and settings as Defender reports them |
| PUT | `/api/settings/antivirus` | admin | Settings: `enabled`, `action` (`quarantine` or `alert`), `scan_unknown`, `use_clamav`, `use_yara`, `app_control` (`off`, `audit`, `enforce`), `defender_hardening` (`off`, `audit`, `enforce`), `use_intel`, `max_file_mb`, `blocked_hashes`, `allowed_hashes` |
| DELETE | `/api/antivirus/verdicts/{sha256}` | analyst | Forget a verdict |
