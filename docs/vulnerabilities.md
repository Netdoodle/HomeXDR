# Known-exploited software

The **Vulnerabilities** page (`/vulnerabilities`) compares each host's newest software list with
[CISA's catalog of known exploited vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(KEV). It lists host, package, version, CVE, the date CISA added it, CISA's deadline for U.S.
agencies, whether it is known to be used in ransomware, and how confident the match is.

## What it needs

- **Software lists from agents** (`inventory.software.list`, every few hours). Agents read dpkg, rpm,
  apk, pacman and Slackware (including Unraid) packages, and the images of containers on the local
  Docker socket. The page says which hosts have sent none, and the agent's reason if it gave one.
- **The catalog.** It downloads daily as an [offline list](lists.md), on by default. If the download
  is blocked, the page and the doctor say so.

Lists are compared every hour and soon after the catalog changes.

## How matching works

The catalog names a vendor and a product, with no version ranges, so matching is deliberately
conservative. A name matches only when the vendor and product are the same word (Sudo / Sudo), or
through a small alias table (Linux / Kernel is `kernel`, Apache / HTTP Server is `httpd` or
`apache2`). A product name alone is not enough: WordPress and Drupal both have one called "Core".
Names ignore case and punctuation, and a Docker image goes by its last part
(`lscr.io/linuxserver/plex` is `plex`). The table is in `server/internal/vuln/catalog.go`.

- **Possible match** is the default. It only means the name is the same, and your version may well
  be fine. It raises no alert.
- **Confirmed** means a version check agrees. There are two kinds:
  - **The catalog's own words.** Some descriptions state one limit ("Exim before 4.70"). Slackware,
    Unraid and pacman packages, the operating system's own version, and Docker images tagged with a
    full version such as `1.27.3` are compared with it. A version past the limit is dropped. This
    is skipped for Debian, Red Hat and Alpine packages, because they fix old versions without raising
    the number, and for a description with several limits or a range. Slackware can also patch without
    raising the number, so check before acting on an old-looking version.
  - **OSV**, if you turn it on.

Each confirmed match raises `vuln:kev`, a high alert, one per host and CVE. When the newest software
list no longer shows it, HomeXDR resolves the alert with a note.

A host that has sent no software list in 14 days keeps its previous results.

## Optional: OSV

Off by default. When on, the names and versions of **possibly matching packages only** are sent to
`api.osv.dev`, an outside service run by Google, never a host's whole software list. If OSV lists that
exact version as affected by the CVE, the match becomes confirmed. OSV knows Debian, Ubuntu and
Alpine packages. It has no data for Slackware, Unraid or Docker images, so on such a host this check
does nothing. If `api.osv.dev` is blocked, the page says so and matches stay as they were.

HomeXDR does not download OSV's whole database, so it has no distro-aware version data of its own.
