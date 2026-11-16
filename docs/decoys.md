# Decoy files

Every HomeXDR agent places a few decoy files on its host: a password list in Documents,
backup codes on the Desktop, a spare cloud credentials file. They look like the files people
forget about, and nothing legitimate has a reason to touch them. Ransomware working through
user folders and attackers looking for credentials go for exactly such files first, so a
decoy that is changed, deleted, renamed or (on Linux) opened raises an alert.

Decoys are on by default for every agent. They are switched off or tuned in
**Settings → Agent config → Decoy files**.

## The files are fake

Everything in a decoy is made up: host names under `.internal`, private addresses, random
passwords, keys that belong to no account. **No real secret is ever written.** Each file
also contains the host's canary marker, a random 20-character string generated once per
host and kept in the agent's data folder. If that string turns up somewhere else (a paste
site, a log, network traffic), the file came from that host.

**The files are safe to delete.** Deleting one on a host that is still monitored raises the
alert below once; the agent then puts it back.

## What is created where

A decoy is written only if its folder already exists and no file is at that path. The agent
never overwrites, changes or removes a file it did not create, and the only folders it may
create are `Backup` and `.aws` below.

| OS | Per user | Shared |
|---|---|---|
| Windows | `C:\Users\<name>\Documents\Passwords.xlsx`, `C:\Users\<name>\Desktop\backup-codes.txt` | `C:\ProgramData\Backup\credentials.csv` (the `Backup` folder is created if missing) |
| Linux | `~/Documents/passwords.txt`, `~/.aws/credentials.bak` (`.aws` is created with mode 0700 if missing) | `/var/backups/db-credentials.sql` (if `/var/backups` exists) |
| macOS | `~/Documents/Passwords.txt`, `~/Desktop/backup-codes.txt` | |

- **Windows users**: each real profile under `C:\Users`, one that has an `NTUSER.DAT`.
  `Public`, `Default`, `Default User` and `All Users` are skipped. The files inherit the
  folder's permissions. `Passwords.xlsx` holds comma-separated text; it only has to look
  right in a folder listing.
- **Linux users**: each folder under `/home` owned by an existing user other than root, and
  `/root`. Files are owned by that user, mode 0600.
- **macOS users**: each folder under `/Users` except `Shared` and hidden folders. Files are
  owned by that user.

**Extra decoy paths** (absolute file paths, one per line, up to 32) add decoys anywhere else,
for example on a file share. Each is created only if its folder exists and the file does not,
and is owned by the folder's owner on Linux and macOS. An agent skips paths that are not
absolute on its own OS, so one list can hold paths for Windows and Unix hosts. Removing a path
from the list removes that decoy if nobody changed it.

The agent never follows a symbolic link when it creates, checks or removes a decoy: on Linux
and macOS it refuses a folder that is a link (a user could otherwise point their Documents
folder at a system folder), and on Windows it refuses links and junctions.

## What is detected

The agent checks every decoy each **check interval** (60 seconds by default, at least 15):
it looks at the file without reading it, and hashes it (SHA-256) only when its size or
modification time changed.

| | Windows | Linux | macOS |
|---|---|---|---|
| Changed (content, or replaced by another file) | at the next check | at once | at the next check |
| Deleted | at the next check | at once | at the next check |
| Renamed | at the next check | at once | at the next check |
| Permissions or owner changed | | at once | |
| Opened or read | | at once | |

On Linux the agent watches each decoy with inotify, which reports opens and reads as they
happen. Windows and macOS have no equally cheap way to see reads of single files, so there
only changes, deletions and renames are detected.

A rename is recognised when a file in the same folder is the same file (same inode or NTFS
file ID) or has the decoy's name with an extension added (`Passwords.xlsx.locked`).
Otherwise a missing decoy is reported as deleted. If the folder holding a decoy is itself
gone (a removed profile, an unmounted home folder) nothing is reported; the decoy is
checked again once the folder is back.

The agent's own work is never reported: creating a decoy, and the read when it hashes one,
happen while the inotify watch on that file is removed.

A deleted or renamed decoy is put back (with new made-up contents) after the event is
sent. A changed decoy is left as it is, and later changes to it are reported too.

Each decoy reports at most one event per minute of each type, so a program reading a decoy
in a loop does not flood the server.

## Events and alerts

Events have `event.module: decoy`, `event.dataset: decoy.event`, `event.category: file`,
`event.type` `change`, `deletion`, `rename` or `access`, the label `decoy: true`,
`file.path`, the user whose folder it is in (`user.name`) and a message such as
"Decoy file was modified: C:\Users\bob\Desktop\backup-codes.txt". A rename carries the new
name in `data.decoy.renamed_to`.

Two built-in rules turn them into alerts (`rules/homexdr/decoy`):

| Rule | Level | Fires on |
|---|---|---|
| Decoy File Modified, Deleted Or Renamed | critical | `change`, `deletion` or `rename` on any OS |
| Decoy File Opened | high | `access` on Linux |

Things that can open a decoy without bad intent, on Linux: backup software that reads whole
home folders, desktop search indexers (GNOME Tracker, KDE Baloo), and you opening one by
hand. Once you have checked what it is, open the alert and choose **Suppress similar**
([alerts.md](alerts.md#suppressions)).

## Status

The host page lists the `decoy` sensor with how many decoys are in place, for example
"3 decoy files". The agent keeps what it created in `decoys.json` in its data folder
(mode 0600): each decoy's path, size, modification time and SHA-256 when it was written, and
the canary marker. After a restart it picks the same decoys up again, and reports anything
that happened to them while it was stopped.

## Turning decoys off

Switch **Decoy files** off in Settings → Agent config and save. Each agent then removes the
decoys it created whose content is unchanged (and the `Backup` or `.aws` folder it created,
if that is empty). A decoy someone changed is left in place, and the host page shows it as
"1 decoy file left in place because someone changed them"; delete it by hand if you want.

Uninstalling the agent does not remove decoys. They are plain files and safe to delete.
