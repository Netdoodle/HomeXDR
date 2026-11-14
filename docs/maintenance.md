# Maintenance tuning

Maintenance work looks like an attack. An automation account edits files under `/etc`, a container
update downloads into `/tmp`, and a backup job stops every service. **Settings → Maintenance** names that
work and quiets the alerts it raises, without hiding the same behaviour from anything else.

## How it works

Agents label every process start with where it came from:

| Label | Set by | Meaning |
|---|---|---|
| `labels.ssh_session` | Linux and Windows agents | PID of the SSH session the process descends from |
| `labels.ssh_key` | Agents, completed by the server | SHA256 fingerprint of the key that session logged in with |
| `labels.ssh_key_name` | Server | The name you gave that key |
| `labels.maintenance` | Agents | `docker-update` (Unraid's Docker manager, CA Auto Update) or `appdata-backup` (appdata backup plugin) |
| `labels.maintenance` | Server | `container-start`: anything a container runs in its first minutes after HomeXDR first sees it |

The agent walks each new process's ancestry once and caches it, so every command a session or an update
script starts carries the label, however deep it runs. The SSH key comes from the login record:

- **Linux:** sshd's `Accepted publickey ... ssh2: ED25519 SHA256:...` line, from journald, `/var/log/auth.log`
  or `/var/log/secure`. On systems that log sshd only to `/var/log/syslog` (Unraid), the agent reads that.
  The fingerprint is in the line with OpenSSH 9 and later, or with `LogLevel VERBOSE`.
  A session's first commands often start before that line is written, so the agent holds their start
  events for up to 1.5 seconds of a new session (off its event-reading path) until the line appears.
- **Windows:** OpenSSH Server's `OpenSSH/Operational` channel, event 4. It is in the default Event Log
  channel list; add it under **Settings → Agent config** if your config lists channels explicitly.

Logins show up as `event.action:ssh_login` with the key under `labels.ssh_key`.

## Quieting it

Each SSH key seen in the last 30 days is listed with its logins, users, hosts and source addresses. Name a key,
then turn on maintenance, until turned off or for a while (1 hour to 7 days). The three container sources work
the same way.

Turning maintenance on creates an ordinary suppression on the label, such as `labels.ssh_key equals SHA256:...`.
It appears on **Settings → Suppressions** with its hit count, and the events are still stored and searchable.
Must-alert rules and critical alerts are never suppressed. Deleting or disabling the suppression there turns
maintenance off here.

## What it does not cover

- Commands run through a password login are labelled with their session, but have no key to name.
- A container's start-up window begins when HomeXDR first sees the container. Containers already running when
  the server starts are not treated as new.
- Container start-up covers every container, including a newly installed one you do not trust yet. Prefer the
  Docker update source, and turn on start-up only for an update window.
