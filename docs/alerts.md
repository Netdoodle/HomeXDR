# Alerts: grouping and suppressions

HomeXDR tries to give you one alert for one thing that is happening, not one for every time
it happens. This page covers how repeats are grouped, how to hide harmless ones, and how the
AI analyst's daily budget is protected from them.

## How repeats are grouped

A new hit folds into an open alert when it has the same **rule**, **host** and **process
shape**. The alert's hit count goes up and no new alert is raised.

The process shape is the program and what started it: the process's executable (or its name
if the executable is unknown) plus its parent's executable (or name). So each run of a
scheduled job folds into one alert, but `wget` started by `php` and `wget` started by a shell
are two different alerts.

Not every event says what started the process. On Linux only process starts carry a parent;
file and network events do not. For those:

- With a command line, the command line takes the parent's place. A job repeats its command
  line, so its runs fold. Someone else's `wget` has a different one, so it does not.
- Without one, each process gets its own alert, as a network event usually does.
- Events from logs have only a process name, and fold by that name.

Events with no process at all fold by rule and host. Findings the server works out itself,
such as a silent feed, fold by what they are about.

An open alert keeps absorbing repeats until it is closed or goes quiet for 24 hours. After
that, the next hit raises a new alert.

## Suppressions

A suppression closes matching hits as they arrive. Use one when something harmless keeps
firing and you have checked what it is. A suppressed hit:

- is stored with the status `suppressed`, so you can still find it,
- folds into one row per shape per day, so the table stays small,
- is never sent to notifications, and never queued for the AI analyst (a person can still ask
  for an investigation on its page),
- does not count in the dashboard, and is hidden from the alert list unless you pick the
  **Suppressed** filter.

### Creating one

Open an alert and choose **Suppress similar**. The form starts with this alert's rule, host,
process and parent, and you can change any of it. It shows how many open alerts match as you
type, with a few examples. You can also tick **also close the matching open alerts**. You
need the admin role.

The **Top repeating** panel on the Alerts page shows the noisiest shapes, with a button that
goes straight to the same form. **Settings > Suppressions** lists every suppression with its
hits and expiry, and lets you turn it off or delete it.

### What one matches

| Part | Meaning |
|---|---|
| Rule | Only this rule ID. Optional. |
| Host | Only this host. Optional. |
| Conditions | Every one must hold. Each is a field, a comparison and a value. |
| Reason | Why this is safe to hide. Required. |
| Expires | 90 days by default. You can pick another time, or never. Expired ones stop matching on their own. |

Comparisons are `equals`, `contains`, `startswith` and `endswith`. Values must match exactly,
including upper and lower case, so a suppression never covers more than it spells out. An
event without the field does not match.

Fields use the same names as Sigma rules and search: `process.executable`,
`process.command_line`, `process.parent.executable`, `process.parent.command_line`,
`file.path`, `destination.ip` and so on.

### Containers

On Linux the agent records which container an event's process runs in: `container.id`,
`container.name`, `container.runtime` and `container.image.name` / `container.image.tag`. It
reads the container from `/proc/<pid>/cgroup` (Docker, containerd, CRI-O, Podman and LXC
layouts) and asks Docker for the name and image, from the container's `config.v2.json` or the
Docker socket. Name and image lookups are Docker only; other runtimes give the ID alone.
Processes on the host itself have no `container` fields, so a condition on them never matches
the host.

To quiet what a container image does every time it starts, scope a suppression to the image
and keep a process condition, for example `container.image.name` equals `binhex/arch-sonarr`
with `process.command_line` starts with `sed -i -e "s~umask`. The image alone would also hide
a real attack inside that container for this rule. **Suppress similar** adds the image
(without its tag, so updates keep matching) when the alert has one.

**Conditions on `process.parent.*` never match Linux file or network events**, because those
events have no parent. For a rule on file events, use `process.command_line` instead. The
preview count shows you whether your conditions match.

HomeXDR refuses a suppression with no scope. It needs a rule or at least one condition, since
a host alone would hide everything on that host. A rule with no host and no condition hides
that rule everywhere, so it needs an extra confirmation (`confirm_broad` in the API).

The server re-reads the list every 30 seconds, and at once after a change in the console.

### Must alert

Some things should never be hidden, whatever a suppression says:

- **Critical alerts** are never suppressed.
- **Rules you list** under **Settings > Suppressions > Must alert** always alert too.

When a suppression matches one of these, the hit stays a normal alert. The alert says so at
the top, the suppression's row shows how many hits it kept, and the audit log records it as
`suppression.override`. Previews count such alerts separately, and applying a suppression
leaves them open.

## Cleaning up a backlog

If alerts have piled up, `homexdr-server suppress-apply` creates suppressions from a file and
closes the open alerts they match, with a note on each. It is safe to run while the server is
running: it closes alerts in small batches, and the server picks up the new suppressions
within 30 seconds. Running it again creates no duplicates.

Always run it with `--dry-run` first. That prints the counts and changes nothing.

```sh
docker compose cp spec.json homexdr:/data/spec.json
docker compose exec homexdr homexdr-server suppress-apply --file /data/spec.json --dry-run
docker compose exec homexdr homexdr-server suppress-apply --file /data/spec.json
```

The file uses the same fields as `POST /api/suppressions`. It can be a list, an object with a
`suppressions` list, or a single suppression. If any entry is invalid, nothing changes.

```json
{"suppressions": [
  {
    "reason": "Unraid plugin check, every few minutes",
    "host_id": "HOST-ID-OF-THE-SERVER",
    "conditions": [
      {"field": "process.parent.command_line", "op": "contains", "value": "plugin check user.scripts.plg"}
    ]
  },
  {
    "reason": "The same job's file events, which do not name a parent",
    "host_id": "HOST-ID-OF-THE-SERVER",
    "conditions": [
      {"field": "process.executable", "op": "equals", "value": "/usr/bin/wget"},
      {"field": "process.command_line", "op": "contains", "value": "/tmp/plugins/"}
    ]
  }
]}
```

Check these values against your own alerts. A condition that is slightly wrong matches nothing,
and the dry run shows that as a count of 0.

## The AI analyst's daily limit

Two things keep repeats from using up the day's investigations:

- **Reused verdicts.** If the AI called an alert benign in the last 7 days, a new alert with
  the same rule, host and process shape gets a copy of that report. It says clearly which alert
  and date it came from. It costs no AI call and does not count against the limit. Only benign
  verdicts are reused, never a reused one, and never for a critical alert. **Investigate again**
  asks for a fresh look.
- **Room for serious alerts.** Alerts below high may use 80% of the daily limit. The rest is
  kept for high and critical alerts, so a noisy morning cannot leave a serious alert unread.

Alerts raised before this grouping existed keep their old key. They stop absorbing hits and
cannot lend their verdicts to new alerts, so close them with `suppress-apply` or by hand.
