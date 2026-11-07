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
5. **ClamAV.** A program nobody vouches for is uploaded from the host (a `file.get`
   command issued by `antivirus`, up to the size limit, 64 MB by default) and streamed
   to a ClamAV daemon next to the server. The upload is deleted after the scan.

## Response

With "Stop the process and its children, quarantine the file" (the default), a
detection sends two signed commands, the same ones a person can send from the host
page: `process.kill` with the process' entity ID and `tree: true`, then
`file.quarantine`. The kill checks the entity ID, so a PID reused since the event is
never hit, and system-critical Windows processes are refused. A quarantined file can be
restored from the host's page. Either way a **critical** alert "Malware detected:
<signature>" is raised (rule `av:malware`, dataset `homexdr.av`), with the hash, path,
source and what was done in its data. The host's local policy must allow the actions
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

## Setup

`deploy/docker-compose.yml` runs `clamav/clamav` next to the server and sets
`HOMEXDR_CLAMD_ADDR=clamav:3310`. Without `HOMEXDR_CLAMD_ADDR` there is no file
scanning; the blocklist, stored verdicts and threat intel still work. ClamAV needs about
1.5 GB of memory and downloads its signatures (about 110 MB) on first start; `freshclam`
inside the container keeps them current.

Custom signatures go in ClamAV's database directory as `*.hsb` files (one
`sha256:size:Name` line per file) and are loaded at clamd's next reload
(`docker exec <clamav container> clamdscan --reload`).

## API

| Method | Path | Role | |
|---|---|---|---|
| GET | `/api/antivirus` | viewer | Settings, ClamAV status, verdict counts, recent detections |
| PUT | `/api/settings/antivirus` | admin | Settings: `enabled`, `action` (`quarantine` or `alert`), `scan_unknown`, `use_intel`, `max_file_mb`, `blocked_hashes`, `allowed_hashes` |
| DELETE | `/api/antivirus/verdicts/{sha256}` | analyst | Forget a verdict |
