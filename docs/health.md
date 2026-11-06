# Data health

A monitor that has quietly stopped seeing data looks the same as a quiet network. The
**Data health** page (`/health`) tells them apart.

## Data sources

A source is one (host, module, dataset), such as Tower / `procfs` / `process.procconn`. Each
host also has a row for "anything from this host". The page shows, per source, when it was
last seen, its usual gap, how long it may stay silent, and its status:

| Status | Meaning |
|---|---|
| OK | Arriving as usual. |
| Silent | Quiet for longer than its allowance. An alert is open. |
| Learning | Not enough history to judge yet, so it cannot alert. |
| Never seen | A feed that should exist has never sent a row. Shown with an explanation, no alert. |
| Quiet feed | An alert-only feed such as Suricata. Rows only appear when something matched, so a quiet IDS may just mean nothing matched. |
| Host offline | The host is offline, so this source is not being timed. |
| Muted | You chose to never be alerted about it. |

### How silence is judged

- **Allowance:** three times the source's usual longest gap, at least 15 minutes and at most 7
  days. The usual longest gap is the second longest of its daily longest gaps over the last 14
  days, so one reboot does not set the baseline. With under five days of gaps, it is the longest.
- **Trust:** a source can alert only after it has been seen for at least 24 hours and has arrived
  at least 20 times.
- **First start:** baselines start from one aggregated query over the last 30 days of events
  (rows per source per hour), not from zero. Gaps read this way have hour resolution and get
  finer as data arrives.
- **Outages stay out of the baseline.** A gap the source was reported silent for is not counted as
  its usual pattern.

### Time away does not count

- **Server downtime.** On start, every source's clock moves forward by the time since the last
  saved tick, and no alert is raised for the first 15 minutes, so agents can reconnect. This is a
  shift rather than a reset to zero: a source that was already 9 minutes silent is still 9 minutes
  silent, so frequent restarts cannot hide a dead feed. If the time of the last tick is unknown,
  the clocks simply restart.
- **The machine slept,** or two checks were more than two minutes apart: the same shift.
- **The event store is down.** Clocks stand still and nothing is raised.
- **A host is offline.** You get one finding for the host, not one per dataset, and its sources'
  clocks stand still. The host's own allowance is measured the same way, so a laptop that sleeps
  every night does not alert every night.
- **Decommissioned hosts** are ignored and any open alert about them is resolved.

### Alerts

`health:feed-silent` is a medium alert raised through the normal findings path, so suppressions,
notifications and the AI analyst treat it like any other. The entity is `host/module/dataset`, or
`host/host` for the host as a whole. When the source returns, HomeXDR resolves its own alert with
a note saying how long it was gone. Reported silence survives a restart: the alert is not raised
again until the source has come back and gone quiet again.

### Your choices

- **Mute** a source: it never alerts, and any open alert about it is resolved.
- **Expected** a source: it may alert even without a learned pattern. A never-seen feed then alerts
  after 24 hours; a quiet feed such as Suricata after 7 days.

### Known collector feeds

`inventory.software.list` and `inventory.services.list` on every agent, and `suricata.alert` on any
network host whose OPNsense filter log is arriving, are shown as "never seen" until they first send
a row. They do not alert unless you mark them expected.

The agent's own reason is shown if it gave one. Agents used to send these lists silently empty on
Unraid and Slackware. They now read `/var/log/packages` for software, the Docker socket for the
images containers run, and `/etc/rc.d` for services. A system with no package database or service
manager the agent can read reports that on its inventory sensor, so the host page says why.

### Digest

`Core.FeedHealthDigest` returns a title and lines ready for the daily digest. It lists silent
sources and counts never-seen ones, and returns no lines when there is nothing to say.

## Doctor

**Data health > Doctor**, `GET /api/doctor` and `homexdr-server doctor` run the same checks. The
command exits 1 if any check fails, and takes `--json`. Each check gives a plain message and a
suggested fix: settings database, event store (it writes one small row and reads it back), disk and
retention, rules and load errors, rule repositories, syslog intake, signed agent release, agent
certificates and versions, AI analyst and MCP runner, and data sources.

Inside a container: `docker exec homexdr homexdr-server doctor`. The command line sees the same
databases as the server, but not what only the running process knows, so it cannot say when the
MCP runner last checked in.

A feature adds a check from its own file, with no change here:

```go
func init() {
	core.RegisterDoctorCheck(core.DoctorCheck{ID: "my_feature", Name: "My feature", Run: myCheck})
}
```

Secrets never appear: messages are scrubbed of the event store's address and of any credentials in
a URL.

## Self-check

**Data health > Self-check**, `POST /api/selfcheck` and `homexdr-server selfcheck` answer "can my
rules actually fire?". The command exits 1 on a regression or when the pipeline check fails, and
takes `--json`. A run writes nothing to your events and creates no real alerts; only its result is
saved, in the settings database, to compare with the next run.

1. **Rule logic.** For each enabled rule, it builds an event from the rule's own selection (no
   hand-written content) and evaluates it through the engine. The number is the detection rate. A
   miss means the rule cannot fire on anything, for example a condition that contradicts itself.
2. **Can they fire on your data?** It samples up to 200 of each source's newest events from the
   last 7 days and works out how many rules could fire on them, grouped by log source: either no
   event of that kind arrives, or those events lack a field the rule needs. This is the number that
   matters most. Many SigmaHQ rules are for Windows, so a Linux and firewall install cannot fire
   them. Because it is a sample, a rare field can be missed.
3. **Pipeline.** It sends a hit through a real ingest into a temporary store and checks that it
   makes an alert and that a repeat folds into it. With no rules loaded, it uses a small built-in
   test rule that matches only a marker field.

A regression is a detection rate that fell by more than 0.05 points, or a pipeline check that passed
last time and fails now. Adding a rule set the engine cannot fully run can count, since the rate
falls; check the failure list.

`TestSelfCheck` in `server/internal/core` runs the same machinery on fixed rules, so CI fails if a
change to the engine or the alert path stops rules firing or alerts folding.
