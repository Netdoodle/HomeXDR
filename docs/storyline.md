# Alert storylines

A storyline is the whole attack chain around one process, drawn as a graph: where it came
from, what it ran, which other processes it reached into, what it set up to run later, and
which alerts fired anywhere along the way. Open it from an alert (the alert's process is
the focus) or from any process. The server builds it on request from the stored events;
nothing is precomputed. The API is `GET /api/storyline` ([api.md](api.md#storylines)), and
the AI analyst gets a condensed version (four levels of descendants) from its
`get_storyline` tool.

## What the graph shows

**Nodes** are processes. Each carries its PID, name, executable, command line, user, start
and end time, exit code, signature and integrity level when the agent reported them, the
alerts raised on it (count, highest severity, ATT&CK tactics) and how many network, file,
registry, DNS and library events it produced. Flags say what the node is:

| Flag | Meaning |
|---|---|
| `focus` | The process the storyline was asked for (the alert's process). |
| `root` | Where the chain starts (see below). `depth` counts from it: 0 is the root, 1 its children, and so on. |
| `context` | The system process just above the root (`explorer.exe`, `services.exe`, `sshd`, ...), shown for orientation at depth -1. Its other children are not walked. |
| `outside` | A process outside the lineage, in the graph only because of a cross-process event with a node. It takes the depth of the node it touches. |
| `more` | Its children were not looked up (past the depth limit or the node cap). A storyline with this process as its focus has them; the console loads it when the branch is opened. |
| `stub` | No start or end event was found for it; it was built from what other events said (a child naming its parent, a cross-process event). Fields may be missing. |

**Edges** link nodes:

| Kind | From → to | Evidence (`event_id`) | `detail` |
|---|---|---|---|
| `parent` | parent → child | the child's start event | |
| `remote_thread` | creator → process the thread was created in | the event | start module, function and address |
| `process_access` | opener → process opened | the event | granted access mask (`0x1fffff`) |
| `process_tampering` | actor → process tampered with | the event | the kind of tampering (`Image is replaced`) |
| `scheduled_task`, `service`, `wmi` | the process that set it up → the process launched | the launched process's start event | the creating command line |

Repeated cross-process events between the same two processes and of the same kind are one
edge, carrying the first event's time, evidence and detail. A tampering event that names no
other process is an edge from the process to itself.

**Alerts** lists the alerts on any node, open and closed (suppressed ones are left out),
newest first, each with its process and tactics.

## Opening and closing branches in the console

The graph opens small: the root, its children, and the processes on the way down to the
focus, so the alert's process is on screen. Every other branch starts closed, with a
"+N" badge counting the processes below it. Clicking a process opens its next level of
children; clicking an open one closes its branch. A branch past what the server sent (a
`more` process, shown with a plain "+") is loaded from the server when it is opened.
Processes started through a task, service or WMI count as children of the process that set
them up. A process linked only by a cross-process event is shown while the process it is
linked to is. **Expand all** opens every loaded branch, **Collapse all** goes back to the
root and its children, and picking an alert in the list opens the branches above it.

## How the root is chosen

The server walks up from the focus through its parents until the next parent is a system
process, and calls the topmost process below it the root. That system parent becomes the
context node. A system process is a Windows service (any process `services.exe` started, such
as the OpenSSH server `sshd.exe`: it runs for as long as the machine and starts unrelated
work, so each of its children is a storyline of its own) or one of these, by name and in
any case:

- Windows: `System`, `smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`,
  `services.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`, `userinit.exe`,
  `wmiprvse.exe`, `taskhostw.exe`, `taskeng.exe`
- Linux and macOS: `systemd`, `init`, `launchd`, `cron`, `crond`, `sshd`,
  `sshd-session`, `login`, `kthreadd`, and `containerd-shim*`

So a macro that started `cmd.exe` and then PowerShell has Word as its root and
`explorer.exe` as context; a command typed over SSH has the login shell as its root and
`sshd` as context; a cron job has its `sh -c` as root. Shells are never system processes,
so an interactive shell is a root rather than being climbed past. When the focus is itself
a system process, it is its own root and its parent is the context.

The walk stops after 12 parents (the graph is then marked `truncated`), at a parent that
never reported (a stub, which becomes the root), or when the lineage loops.

From the root, descendants are added level by level down to `depth` levels (default 6,
at most 10); the focus's own descendants are walked to the same depth below the focus, so
a focus deep in the chain still shows what it ran. The focus's ancestors up to the root are
always included.

## Cross-process links

For every node except the context, the server reads the cross-process events in which it
is either the actor or the target: a remote thread created (Sysmon event 8), a process
opened (event 10) or process tampering (event 25). The other process becomes an `outside`
node if it is not in the graph already, filled from its own start event when there is one.
The context node is left out of the lookup because system processes such as `lsass.exe`
are opened by much of the system, which would bury the chain; a link from a node to
`lsass.exe` still shows, from the node's side.

These events come only from Windows agents with Sysmon installed and configured to log
events 8, 10 and 25 (see [sysmon.md](sysmon.md)). Event 10 is noisy unless the Sysmon
configuration filters it. Linux and macOS storylines have parent links only for now.
Events whose target process the agent could not identify (no entity ID) are left out.

## Launched via a task, service or WMI (best effort)

A process that schedules a task or installs a service does not become the parent of what
runs later: the Task Scheduler, the Service Control Manager or WMI does. The storyline
tries to link them anyway, one hop:

1. A node (not context or outside) whose command line sets something up: `schtasks
   /create`, `at HH:MM`, `Register-ScheduledTask` (scheduled task); `sc create`, `sc config`,
   `New-Service` (service); `wmic process call create`, `Invoke-WmiMethod` or
   `Invoke-CimMethod` on `Win32_Process` `Create`, a `CommandLineEventConsumer` (WMI). Up
   to 10 such creators are followed.
2. Process starts on the same host within 24 hours after the creator started, whose parent
   is `svchost.exe` (the Task Scheduler's: one whose command line names another service
   with `-s` is skipped), `taskeng.exe` or `taskhostw.exe` for tasks, `services.exe` for
   services, or `wmiprvse.exe` for WMI. The parent's name comes from the start event,
   which the Windows agent fills in.
3. Of those, the ones the creating command names: the launched process's whole command
   line appears in it, or its executable path does (for programs under `C:\Windows\`, its
   arguments must appear too, since tasks and services run those all the time), or its
   file name and arguments do. Quotes, case and repeated spaces are ignored.

Each match is added with its own descendants and an edge of kind `scheduled_task`,
`service` or `wmi` from the creator; its depth is the creator's plus one. Launched
processes are not followed as creators themselves.

This is a heuristic. It misses commands it cannot read (encoded PowerShell, a script file
that runs `schtasks`, environment variables such as `%TEMP%` in the path, COM or API calls
instead of command lines), tasks that run later than 24 hours, and the reverse direction
(it does not look for the creator of the task that started the focus). It can link a
process that merely runs the same program with the same arguments in that window. Cron
and systemd timers on Linux are not linked yet.

## Limits

- At most 500 nodes. When more would be added, or more children or cross-process events
  exist than were read (500 children per level, 2,000 cross-process events), the graph says
  `truncated: true`.
- At most 200 alerts listed; per-node alert counts are exact.
- Processes whose start events were deleted by retention appear as stubs, or not at all.
- Entity IDs are per host: a storyline never crosses hosts. Lateral movement shows as the
  remote side's processes in their own storyline.
