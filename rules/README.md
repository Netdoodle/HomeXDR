# Detection rules

HomeXDR loads [Sigma](https://sigmahq.io/) rules from three places:

- this directory (in the Docker image: `/usr/share/homexdr/rules`, set with
  `HOMEXDR_RULES_DIR`), read recursively;
- rule repositories imported in the console, such as SigmaHQ, which the server downloads and
  keeps up to date (below);
- custom rules written in the console, stored in the database.

## Importing a rule repository

The quickest way to add community rules is **Rules → Import rules** in the console (admins).
Pick a preset or paste a URL, and HomeXDR downloads the rules, loads the ones it can run and
keeps them updated:

- **SigmaHQ: Windows and Linux**: the default branch of
  [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), folders `rules/windows` and
  `rules/linux`, medium level and above (about 2,400 rules).
- **SigmaHQ Core release**: SigmaHQ's curated release package (`sigma_core.zip`): stable and
  test rules of high and critical level, about 1,200 for Windows and Linux.
- **Any other source**: a public git repository on GitHub, GitLab, Gitea/Forgejo (Codeberg)
  or Bitbucket, or a link to a `.zip` / `.tar.gz` of Sigma rules. A link to a folder
  (`https://github.com/SigmaHQ/sigma/tree/master/rules/linux`) fills in the branch and folder.

For each repository you choose:

| Setting | |
|---|---|
| Branch, tag or commit | Default branch when empty. A commit pins the rules to that version. |
| Folders | Only rules in these folders are loaded; empty means the whole repository. After the first download the edit dialog lists the repository's folders with rule counts. |
| Minimum level, statuses | Rules below the level or with other Sigma statuses are skipped. Deprecated and unsupported rules are skipped unless ticked. |
| New rules | Whether rules from the repository start enabled or disabled. |
| Updates | **Automatic**: each check installs a new version as soon as it finds one. **Manual**: checks only report "Update available", and nothing changes until an admin clicks **Update**. |
| Check interval | Every hour to weekly (daily by default). |

The server needs no git: it reads the newest commit of the branch from the repository's
smart-HTTP endpoint (what `git ls-remote` uses) and downloads the host's archive of that
commit; archive URLs are re-downloaded only when their ETag or content changes. Only
`.yml`/`.yaml` files are kept, under `<data>/rule-repos/<id>`. A download is staged next to
the installed copy and swapped in only when complete, so a failed update leaves the
installed rules running; failures show on the repository and are retried within an hour.
**Check** looks for a new version without installing it; **Update** installs now in either
mode. Changes are written to the audit log (`rule_repo.*`, by `system` for scheduled updates).

Rules you enable or disable by hand keep that choice across updates, because the choice is
stored by rule ID. Repository rules are read-only; **Copy as custom** makes an editable copy
with a new ID. When two sources contain the same rule ID, the rules folder wins over custom
rules, custom rules over repositories, and an earlier repository over a later one; the
repository card counts the rules it skipped this way.

Every enabled rule runs on every event, so load the platforms you collect rather than the
whole repository. Rules that use features the engine does not support yet (aggregations,
correlations, `|expand`, `|fieldref`) are skipped and listed on the **Rules** page with the
reason. SigmaHQ rules are published under the Detection Rule License (DRL) 1.1, which
requires attribution; HomeXDR shows each rule's author and links to its file upstream.

## Mounting rules into the rules folder

Rules can also be mounted next to the built-in directory, for example to use a checkout you
manage yourself. In `deploy/docker-compose.yml`:

```yaml
    volumes:
      - /opt/sigma/rules/windows/process_creation:/usr/share/homexdr/rules/sigmahq/windows:ro
      - /opt/sigma/rules/linux:/usr/share/homexdr/rules/sigmahq/linux:ro
```

The server checks the rules folder once a minute and reloads it when a file is added,
removed or changed, so no restart is needed. Admins can also apply changes immediately with
**Rules → Reload rules folder** (or `POST /api/rules/reload`). To keep a mounted folder
current, update it from the host on a schedule (for example a cron job or an Unraid User
Script); HomeXDR picks up the new files on its next check. Disable noisy rules from the
console; the setting is kept across restarts and updates.

## Writing rules

Use Sigma's `logsource` categories (`process_creation`, `network_connection`,
`file_event`, `registry_set`, `dns_query`, `image_load`, ...) with `product: windows`,
`linux` or `macos`, or `product: opnsense` / `suricata` for network sources. Fields that are
not in the mapping table fall back to Windows EventData names (`data.<Name>`) and then to
HomeXDR's own dotted field paths (`process.parent.name`, `destination.port`, ...).

Test a rule against stored events before saving it with **Rules → New rule → Test**.
