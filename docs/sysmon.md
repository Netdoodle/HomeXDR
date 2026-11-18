# Sysmon on Windows agents

The Windows agent reads process starts and exits from Sysmon when it is there (otherwise
from the Security log). Sysmon can also report what one process does to another: start a
thread in it, open it with access that allows reading or writing its memory, or replace
its image. These cross-process events feed the storyline graph. Windows does not log
them by default, so the agent can set Sysmon up for you.

This is controlled by the **Sysmon events** setting, on by default. Linux and macOS agents
ignore it.

## What the agent turns on

With the setting on, every 10 minutes and whenever the setting changes, the agent looks at
Sysmon and does one of these:

| What it finds | What it does |
|---|---|
| No Sysmon, and Windows has the Sysmon optional feature (Windows 11) | Turns the feature on (`dism.exe /online /enable-feature /featurename:Sysmon /limitaccess /norestart`), then installs Sysmon with HomeXDR's configuration (`sysmon.exe -accepteula -i <config>`). If Windows asks for a restart, the sensor status says so and the agent installs Sysmon after the restart |
| No Sysmon and no Sysmon feature (Windows 10 and older) | Nothing. The status says Sysmon is not available; install it from Sysinternals yourself if you want cross-process events |
| Sysmon with no rules (its defaults) | Applies HomeXDR's configuration (`sysmon.exe -c <config>`) |
| Sysmon with HomeXDR's configuration | Nothing, unless HomeXDR's configuration changed (a newer agent): then it applies the new one |
| Sysmon with rules someone else wrote | Nothing. The status says HomeXDR left it unchanged and which events the storyline needs |

The agent never downloads anything: DISM runs with `/LimitAccess`, so a feature whose files
were removed from Windows is reported, not fetched. It runs `dism.exe` and `sysmon.exe` only
by their full paths in the Windows folders (`%SystemRoot%\System32\sysmon.exe`, or a
standalone Sysmon in `%SystemRoot%`), each with a time limit, and checks their exit codes.
The configuration file is written to the agent's data folder (readable only by SYSTEM and
Administrators) right before it is applied.

HomeXDR recognises its own configuration by the hash Sysmon records for the applied file
(`HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\ConfigHash`) and by the file
it was applied from. Sysmon "with no rules" means it has no rules and no configuration
hash, the state `sysmon -c` reports as "No rules installed".

## Which events

HomeXDR's configuration keeps the volume low. It logs:

| Event | What | Filter |
|---|---|---|
| 1, 5 | Process start and exit | None: every process. Hashes are SHA256 and IMPHASH |
| 8 | CreateRemoteThread: a process starts a thread in another | All, except console control handlers and session start (`csrss.exe`, `wininit.exe`), Microsoft Defender and the HomeXDR agent |
| 10 | ProcessAccess: a process opens another | Anything opening `lsass.exe`, and any process opened with access that lets the opener write into it (`PROCESS_VM_WRITE` with `PROCESS_VM_OPERATION`, such as 0x1F0FFF, 0x1F3FFF, 0x143A). Query-only access (0x1000, 0x1400 and similar) and accesses by `csrss.exe`, `wininit.exe`, Microsoft Defender and the agent are left out |
| 25 | ProcessTampering: a process image is hollowed out or replaced | None |

Network connections, image loads, file, registry and DNS events stay off.
`PROCESS_ALL_ACCESS` (0x1FFFFF) is not logged for every target, because Windows gives it to
every parent on the child it creates; injection with it still shows up as event 8 or 25.
On an idle Windows 11 test PC the configuration logged no events 8, 10 or 25 in two and a
half minutes apart from the test's own; without the filters the same PC logged about 380
events 10 a minute.

The process sensor maps the events to process events (`event.category: process`,
`event.module: eventlog`, `event.provider: Microsoft-Windows-Sysmon`, `event.code` the
Sysmon event ID):

| Event | `event.type` | `event.action` | `process` | `target` |
|---|---|---|---|---|
| 8 | `change` | `remote-thread-created` | the process starting the thread | `target.process` (the process it runs in) with `start_address`, `start_module`, `start_function` |
| 10 | `access` | `process-accessed` | the process opening the other | `target.process` with `granted_access` (Sysmon's hex, e.g. `0x1f3fff`) and `call_trace` |
| 25 | `change` | `process-tampered` | the tampered process, with its parent | `tampering` (Sysmon's Type, e.g. "Image is replaced"); no target process |

Both processes get the entity IDs of the process tree when the agent knows them (through
Sysmon's process GUIDs), so the storyline can link them. Events the agent itself causes
are dropped. With the process sensor on, the Windows Event Log sensor leaves Sysmon events
1, 5, 8, 10 and 25 out, so they are not reported twice.

## Status

The host page lists a **sysmon** sensor:

- *running*: "Sysmon installed and configured by HomeXDR", "Sysmon configured by HomeXDR",
  "Sysmon has a configuration HomeXDR did not write, so HomeXDR left it unchanged", or
  "Sysmon is not available on this Windows version".
- *degraded*: a restart of Windows is needed to finish turning the feature on, or something
  failed (the message says what, for example Sysmon rejecting the configuration). The
  agent tries again at the next check.
- *disabled*: the setting is off for this host; the message says what was undone.

## Turning it off

Sysmon events can be turned off for everyone (Settings → Agent config → Sysmon events) or
per host group (Settings → Groups → Sysmon events: Inherit, On or Off, see
[groups.md](groups.md)). The server sends each host's value with every heartbeat and the
agent keeps it across restarts.

Turning it off undoes only what HomeXDR did. Before its first change the agent writes
`C:\ProgramData\HomeXDR\sysmon-before-homexdr.json` with what was there (whether the
feature was on, whether Sysmon was installed, whether it had no rules or HomeXDR's), and
then what it changed:

- Sysmon that HomeXDR installed is uninstalled (`sysmon.exe -u`).
- Sysmon that had no rules before gets its defaults back (`sysmon.exe -c --`).
- The Windows feature, if HomeXDR turned it on, is turned off again (a restart may be
  needed to finish).
- Sysmon whose configuration someone else replaced meanwhile is left installed and
  unchanged, and so is the feature it needs.

`homexdr-agent uninstall` does the same after stopping the service.
