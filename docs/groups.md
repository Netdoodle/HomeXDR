# Host groups

Settings → Groups arranges enrolled hosts in a tree:

```
Netdoodle (Global: the organisation)
├── DTS Assets            (parent group)
│   └── Marketing Dept    (child group)
└── Infrastructure Assets
    └── Linux Servers
```

The top is your organisation (rename it from "Global" with **Rename** on its row). Under
it are parent groups, and under those child groups; groups go two levels deep. Each host
is in one group, or in none (it then follows the organisation's settings). Put hosts in a
group from the group's **Hosts** button or from the **Group** panel on the host page, or
have them land there when they enroll: an enrollment token can name a group (Settings →
Enrollment, "Group for enrolled hosts").

The Hosts and Alerts pages filter by group; a parent group includes its child groups, and
"Netdoodle (no group)" shows hosts in none. The host count on the Groups page links to the
filtered Hosts page.

## Settings that groups override

| Setting | Global value | Per group |
|---|---|---|
| Antivirus: scan with ClamAV | Settings → Antivirus | Inherit, On or Off |
| Antivirus: scan with YARA | Settings → Antivirus | Inherit, On or Off |
| Antivirus: malware response | Settings → Antivirus ("When malware is found") | Inherit, Stop and quarantine, or Alert only |
| AI analyst: investigate alerts automatically | Investigate (whenever the AI analyst is set up and automatic investigations are on) | Inherit, Investigate or Off |

A group set to **Inherit** takes the value from its parent group; a parent group set to
Inherit takes it from the organisation. The nearest group that sets a value wins, so
Marketing Dept can turn YARA back on even when DTS Assets turned it off. The host page
shows each value and the group it comes from.

Choosing weaker protection than a group would adopt from above (a scanner off, alert only
instead of stop and quarantine, AI investigations off) asks first: the dialog names where
the setting comes from, how many hosts it affects (child groups that set it themselves are
not) and what they lose. A group's AI analyst switch can only narrow what Settings → AI
analyst allows: it never turns the AI analyst on.

What a switch changes:

- A file seen only on hosts with a scanner off is not scanned with it.
- A file is judged once for the whole fleet. When a host whose group wants a scanner runs
  a file that was found clean without that scanner, the file is scanned again.
- A detection by a scanner that is off for a host's group raises no alert and no response
  on that host; other hosts that run the same file still get theirs.
- Blocklist, threat intel lookups and stored detections by them apply everywhere.

## Changing the tree

Deleting a group moves its hosts to its parent group (or to no group); a parent group can
only be deleted once it has no child groups. Every change is in the audit log
(`group.create`, `group.update`, `group.delete`, `host.group`, `org.rename`).

## API

| Method | Path | Role | |
|---|---|---|---|
| GET | `/api/groups` | viewer | Organisation, global values, groups in tree order with host counts and effective settings |
| PUT | `/api/org` | admin | `{"name"}` |
| POST | `/api/groups` | admin | `{"name", "parent_id"}` (`""` for a parent group) |
| PATCH | `/api/groups/{id}` | admin | `{"name"}`, `{"parent_id"}`, `{"policy": {"av": {"clamav": false, "yara": true, "action": "alert"}, "ai": {"auto": false}}}` (leave a key out to inherit) |
| GET | `/api/hosts?group=`, `/api/alerts?group=` | viewer | A group ID (with its child groups) or `none` |
| POST | `/api/enrollment-tokens` | admin | `group_id` puts enrolled hosts in that group |
| DELETE | `/api/groups/{id}` | admin | Hosts move up a level |
| PUT | `/api/hosts/group` | admin | `{"host_ids": [...], "group_id"}` (`""` for no group) |
