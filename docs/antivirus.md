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
   stored and the file is tried again the next time it runs.

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
never hit, and system-critical Windows processes are refused. A quarantined file can be
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
| PUT | `/api/settings/antivirus` | admin | Settings: `enabled`, `action` (`quarantine` or `alert`), `scan_unknown`, `use_clamav`, `use_yara`, `use_intel`, `max_file_mb`, `blocked_hashes`, `allowed_hashes` |
| DELETE | `/api/antivirus/verdicts/{sha256}` | analyst | Forget a verdict |
