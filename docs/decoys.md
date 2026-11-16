# Decoy files

Every HomeXDR agent places a few decoy files on its host: a password list in Documents, a
spare cloud credentials file, an old database dump. They look like the files people forget
about, and nothing legitimate has a reason to touch them. Ransomware working through user
folders and attackers looking for credentials go for exactly such files first, so a decoy
that is changed, deleted, renamed or (on Linux) opened raises an alert.

Decoys are on by default for every agent. Where they go, and the switch for all hosts, are
in **Settings → Agent config → Decoy files**. A host group can turn them on or off for its
hosts under **Settings → Groups** ([below](#turning-decoys-off)).

## The files are fake

Everything in a decoy is made up: host names under `.internal`, private addresses, random
passwords, keys that belong to no account. **No real secret is ever written.** Each file
also contains the host's canary marker, a random 20-character string generated once per
host and kept in the agent's data folder. If that string turns up somewhere else (a paste
site, a log, network traffic), the file came from that host.

**The files are safe to delete.** Deleting one on a host that is still monitored raises the
alert below once; the agent then puts it back.

## Choosing where decoys go

The decoy list in Settings → Agent config has one section per platform (Windows, Linux,
macOS); each agent uses the entries for its own OS. Add a path with **+** under its
platform, remove one with **×**, and **Restore defaults** puts the list below back. The
defaults are:

| OS | Path |
|---|---|
| Windows | `{home}\Documents\Passwords.xlsx`, `C:\ProgramData\Backup\credentials.csv` |
| Linux | `{home}/Documents/passwords.txt`, `{home}/.aws/credentials.bak`, `/var/backups/db-credentials.sql` |
| macOS | `{home}/Documents/Passwords.txt` |

A path is either absolute (`/srv/share/passwords.txt`, `D:\Shares\Finance\logins.csv`)
or starts with **`{home}`**, which stands for each user's home folder: the agent places one
decoy per user. The rules, checked by the console and again by the server:

- `{home}` only at the start, followed by the platform's separator; otherwise a drive and
  `\` (`C:\...`) on Windows, or `/` on Linux and macOS;
- `\` as the separator on Windows and `/` on Linux and macOS, nothing else;
- no wildcards (`*`, `?`), no `.` or `..` folders, no empty folder names, and a file name
  at the end;
- on Windows no `<`, `>`, `"`, `|`, and no colon after the drive letter (no alternate data
  streams);
- at most 260 characters per path, at most 64 paths in all, each listed once per platform.

The content is chosen by the file name: `.xlsx`, `.xls` and `.csv` get a password list,
`.sql` a database dump with user grants, `credentials...` in an `.aws` folder an AWS
credentials file, a name with `code` in it backup codes, and anything else a password note.

**Users.** `{home}` is expanded to:

- **Windows**: each real profile under `C:\Users`, one that has an `NTUSER.DAT`.
  `Public`, `Default`, `Default User` and `All Users` are skipped. The files inherit the
  folder's permissions. `Passwords.xlsx` holds comma-separated text; it only has to look
  right in a folder listing.
- **Linux**: each folder under `/home` owned by an existing user other than root, and
  `/root`. Files are owned by that user, mode 0600.
- **macOS**: each folder under `/Users` except `Shared` and hidden folders. Files are
  owned by that user.

A decoy at an absolute path is owned by the owner of its folder on Linux and macOS. A path
inside the agent's own data folder is refused.

**Folders.** A decoy is written only if no file is at that path, and only if its folder
exists, or the folder's parent exists: then the agent creates just that last folder (mode
0700, owned by the user under a home folder, otherwise by the owner of the folder it is
created in; on Windows it inherits the parent's permissions). It never creates more than
one folder, and never a user's home folder itself. The agent never overwrites, changes or
removes a file it did not create.

**Hidden.** Each path has a **Hidden** option:

| OS | What it does |
|---|---|
| Windows | Sets the hidden attribute (`FILE_ATTRIBUTE_HIDDEN`), as `attrib +h` does |
| macOS | Sets the hidden flag (`UF_HIDDEN`), as `chflags hidden` does |
| Linux | Nothing: Linux has no hidden attribute. Start the file name with a dot instead (`{home}/.passwords.txt`) |

Turning the option on or off later adds or removes the attribute on decoys already in
place, but only on unchanged ones, and only on the file the agent created (same volume and
file ID or inode, reached without following links). The attribute is not part of what the
checks compare, so the agent's own change raises no event.

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
"Decoy file was modified: C:\Users\bob\Documents\Passwords.xlsx". A rename carries the new
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
"3 decoy files", and how many decoys taken off the list were left in place because someone
changed them ("3 decoy files; 1 decoy file no longer in the list was left in place because
someone changed it"). The agent keeps what it created in `decoys.json` in its data folder
(mode 0600): each decoy's path, size, modification time and SHA-256 when it was written, and
the canary marker. After a restart it picks the same decoys up again, and reports anything
that happened to them while it was stopped.

## Changing the list

When a path is removed from the list (or changed, which removes the old path and adds the
new one), each agent removes the decoys it created there whose content is unchanged, and
the folder it created for them if that is empty. A decoy someone changed is left in place,
is no longer checked or reported, and is counted on the host page as above; delete it by
hand if you want. If the path is added back, the agent checks that file again. A decoy
whose folder is unavailable at the time (a home folder that is not mounted) is dealt with
once the folder is back.

### Desktop decoys

Earlier versions also placed `backup-codes.txt` on each user's Desktop (Windows and macOS).
The defaults no longer have them, and a saved agent config from before configurable paths
gets the new defaults (plus its old "extra decoy paths", converted: a path with a drive
letter becomes a Windows entry, any other a Linux and a macOS entry). So after the update
every agent removes its Desktop decoys that nobody changed, and leaves changed ones in
place as described above. Add `{home}\Desktop\backup-codes.txt` (Windows) or
`{home}/Desktop/backup-codes.txt` (macOS) back to the list to keep them.

## Turning decoys off

The **Decoy files** switch in Settings → Agent config is the Global value. A host group can
override it under Settings → Groups (On, Off or Inherit; a child group inherits its parent
group's choice unless it sets its own), see [groups.md](groups.md). The server works out
each host's value from its group and sends it with every heartbeat reply
(`decoys_enabled`), so a change reaches every agent within a heartbeat interval; the agent
keeps the last value across restarts.

When decoys are off for a host, its agent removes the decoys it created whose content is
unchanged (and the folders it created for them, if they are empty). A decoy someone changed
is left in place, and the host page shows it as "1 decoy file left in place because someone
changed them"; delete it by hand if you want. Switching back on places the decoys again.

Uninstalling the agent does not remove decoys. They are plain files and safe to delete.
