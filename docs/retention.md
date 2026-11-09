# Data retention

**Data retention** in the sidebar shows how much event history HomeXDR keeps and when
the oldest events are removed, and lets an administrator change the limits.

## Limits

Two limits apply, and whichever is reached first removes events, a whole UTC day at a
time, oldest first. Today's events are never removed.

- **Time limit (days).** A day's events go once its last event is older than the limit.
  ClickHouse enforces it with its table TTL and, for days stored before a change, the
  server drops expired daily partitions itself (every 6 hours and right after a change).
- **Size cap (bytes).** Every 10 minutes, the oldest days are dropped until the events
  fit (ClickHouse: compressed bytes on disk; SQLite: pages in use).

The server environment sets the starting values (`HOMEXDR_RETENTION_DAYS`,
`HOMEXDR_RETENTION_MAX_SIZE`). Once they are changed on this page, the stored setting
wins over the environment, including after restarts. The page says which one is in
effect.

## What the page shows

- **Next falloff.** The date events are next removed and which day goes, from the
  earlier of:
  - **time limit:** the oldest day + the limit + 1 day
  - **size cap:** an estimate, from the free room under the cap divided by the average
    daily volume of the last 7 complete days
- **Storage.** Events against the size cap, and the disk holding them (ClickHouse's data
  disk, or the server's data directory with SQLite).
- **Figures.** Events stored, oldest day, average per day, and how many days of history
  the cap holds at that rate.

## Changing retention

**Review changes** asks the server for a preview, then two confirmation steps follow:

1. **Review.**
   - Current against new settings, and the new next falloff.
   - Exactly which events would be deleted (count, size, date range) and where history
     would start.
   - Warnings: permanent deletion, no backup, alerts losing their events, a shorter
     window to find an intrusion, a cap too small for a week of events, a cap larger
     than the disk.
   - An acknowledgement checkbox.
2. **Confirm.** A reduction (a shorter limit, a smaller cap, or anything that deletes
   events) needs `DELETE EVENTS` typed. Increases need only the click.

The server enforces the same rules: `PUT /api/settings/retention` needs
`"acknowledge": true`, plus `"confirm_phrase": "DELETE EVENTS"` for a reduction.
Deletion starts right away and normally finishes within minutes. The change is recorded
in the audit log (`settings.retention`).

## API

| Method | Path | Role | |
|---|---|---|---|
| GET | `/api/retention` | viewer | Settings, usage per day, disk, falloff dates |
| POST | `/api/retention/preview` | admin | `{days, max_bytes}`: what the change would delete, and warnings |
| PUT | `/api/settings/retention` | admin | `{days, max_bytes, acknowledge, confirm_phrase}` |

## Cloud backup (cold storage)

The **Cloud backup** section on the Data retention page archives events to an
S3-compatible bucket you own: Amazon S3, Backblaze B2, Wasabi, Cloudflare R2, MinIO, iDrive
e2, Storj and similar.

- **One archive per completed UTC day.** Today is archived tomorrow, after the chosen
  local hour.
  - Archive: `<prefix>/events/YYYY/MM/DD/homexdr-events-YYYYMMDD.ndjson.zst`, the day's
    events as newline-delimited JSON (the same JSON HomeXDR stores), zstd-compressed and
    streamed to the bucket with a multipart upload.
  - Manifest: `....manifest.json` next to it, with the event count, size, SHA-256 and the
    sources left out.
- **Leave out sources.** Event modules can be skipped, for example `netflow`, which is
  often most of the volume.
- **Storage class.** On AWS, Glacier Instant Retrieval keeps archives cold but directly
  importable. Glacier Flexible and Deep Archive are cheaper but must be restored in AWS
  before an import. Manifests always use the default class.
- **Backfill.** "Also archive the days already stored" uploads existing history too.
- **No local effect.** Backups never delete anything locally; retention does that. The
  retention preview and the Next falloff card say whether the days about to be removed
  have an archive.
- **Test bucket.** Writes, reads back and deletes a small object, so the key needs
  read, write, list and delete rights on the bucket.
- **Credentials.** The secret key is stored on the server and never shown again.

**Archives are cold.** HomeXDR does not search the bucket. To work with an archived day,
**Import** it from **Archived days**. Its events go back into the event store as they
were, without running detection rules on them again (no new alerts), and search, hunts,
process trees and investigations see them. Import rules:

- A day the store still has events for can't be imported (no duplicates).
- A day older than the time limit is refused, because it would be purged again.
- Imported days count against the size cap.

The archive format is plain NDJSON, so it can also be read without HomeXDR:
`zstd -dc homexdr-events-20261108.ndjson.zst | jq`.

| Method | Path | Role | |
|---|---|---|---|
| GET | `/api/backup` | admin | Settings (without the secret), archive counts, waiting days, last run, errors |
| PUT | `/api/settings/backup` | admin | Settings; an empty `secret` keeps the saved one, `clear_secret` removes it |
| POST | `/api/backup/test` | admin | Write, read and delete a test object |
| POST | `/api/backup/run` | admin | Archive every waiting day now |
| GET | `/api/backup/archives` | admin | Archives in the bucket and whether each day is in HomeXDR |
| POST | `/api/backup/import` | admin | `{day}`: import an archived day in the background |
