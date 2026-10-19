# Detection rules

HomeXDR loads [Sigma](https://sigmahq.io/) rules from this directory (in the Docker
image: `/usr/share/homexdr/rules`, set with `HOMEXDR_RULES_DIR`). Every `.yml` / `.yaml`
file below it is read recursively at startup. Rules added in the console are stored in the
database as custom rules.

## Using the SigmaHQ community rules

The engine uses standard Sigma field names (see the mapping table in
[docs/architecture.md](../docs/architecture.md)), so rules from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) can be loaded directly. SigmaHQ rules are
published under the Detection Rule License (DRL) 1.1, which requires attribution; they are
not bundled here.

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/sigma
```

Mount the folders you want next to the built-in directory, for example in
`deploy/docker-compose.yml`:

```yaml
    volumes:
      - /opt/sigma/rules/windows/process_creation:/usr/share/homexdr/rules/sigmahq/windows:ro
      - /opt/sigma/rules/linux:/usr/share/homexdr/rules/sigmahq/linux:ro
```

Start with a few categories rather than the whole repository: every enabled rule runs on
every event. Rules that use features the engine does not support yet (aggregations,
correlations, `|expand`, `|fieldref`) are skipped and listed on the **Rules** page with the
reason. Disable noisy rules from the console; the setting is kept across restarts.

## Keeping rules up to date

The server checks the rules folder once a minute and reloads it when a file is added,
removed or changed, so no restart is needed. Admins can also apply changes immediately with
**Rules → Reload rules folder** (or `POST /api/rules/reload`).

To keep a mounted folder current automatically, update it from the host on a schedule
(for example a cron job or an Unraid User Script that syncs the rule repository you use).
HomeXDR picks up the new files on its next check. Enabled/disabled choices are stored by
rule ID, so they survive updates.

## Writing rules

Use Sigma's `logsource` categories (`process_creation`, `network_connection`,
`file_event`, `registry_set`, `dns_query`, `image_load`, ...) with `product: windows`,
`linux` or `macos`, or `product: opnsense` / `suricata` for network sources. Fields that are
not in the mapping table fall back to Windows EventData names (`data.<Name>`) and then to
HomeXDR's own dotted field paths (`process.parent.name`, `destination.port`, ...).

Test a rule against stored events before saving it with **Rules → New rule → Test**.
