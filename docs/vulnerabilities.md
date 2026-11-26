# Vulnerabilities

The **Vulnerabilities** page (`/vulnerabilities`) lists the known vulnerabilities in the software
your agents report, scored by real risk. Vulnerabilities do not raise alerts: the page has its
own summary, a list of new critical and high findings from the last 7 days, charts, and the full
list of findings. (Older versions raised a `vuln:kev` alert; those are resolved at start with a
note.)

## Where the data comes from

All of it is downloaded ahead of time as [offline lists](lists.md). Nothing about your hosts is
sent anywhere, unless you turn on the optional OSV check below.

| Source | What it gives | Download |
|---|---|---|
| Distro security advisories (OSV) | For Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux: which CVEs affect which package, and the version that fixed it, release by release. Distros fix old versions without raising the upstream number, and these advisories account for that. Most records carry a CVSS vector. | OSV's per-distro export, daily. Only the distros your hosts run: Debian 85 MB, Alpine 9 MB, Rocky 6 MB, AlmaLinux 8 MB, **Ubuntu about 850 MB** |
| Exploit prediction scores (FIRST EPSS) | For every CVE, the chance it is exploited in the next 30 days | One CSV, daily, about 2 MB |
| Known exploited vulnerabilities (CISA KEV) | The CVEs CISA has seen used in attacks, and which are used by ransomware | One JSON file, daily |

The software lists are the agents' `inventory.software.list` (dpkg, rpm, apk, pacman and
Slackware/Unraid packages, and local Docker images), every few hours. Debian and Alpine
advisories name source packages (`openssl`, not `libssl3`), so agents also report each package's
source package.

## How matching works

- **Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux hosts** (coverage "full"). Each distro
  package is compared with its distro's advisories using that distro's own version rules
  (dpkg, apk or rpm). A package older than the fixed version is affected; an advisory with no
  fixed version means no fix is released yet. Debian's "unimportant" issues are left out.
  These findings are **confirmed**.
- **Everything else** (coverage "KEV only": Slackware and Unraid packages, pacman, Docker
  images, and the operating system itself on hosts without distro advisories). Only CISA's
  catalog applies, matched by name, as before:
  - The catalog names a vendor and product with no version ranges, so a name matches only when
    vendor and product are the same word, or through a small alias table in
    `server/internal/vuln/catalog.go`. A Docker image goes by the last part of its name.
  - **Possible** is the default: the name is the same, and your version may well be fine.
  - **Confirmed** when the catalog's description states one limit ("Exim before 4.70") and the
    version number can be trusted (Slackware, Unraid, pacman, the OS version, and Docker images
    tagged like `1.27.3`), or when the optional OSV check agrees.

A host that has sent no software list in 14 days keeps its previous results.

## The risk score

**Risk = CVSS × likelihood ÷ 10**, both 0–10. CVSS says how bad the flaw is if used. Likelihood
says how likely it is to be used against this host. Each finding shows how its score was worked
out. No AI is involved: the same facts always give the same score.

**CVSS** comes from the advisory's CVSS 3.x vector. A CVSS 4.0 vector is scored with the 3.1
formula from the metrics they share, which is close but not exact. With no vector, the distro's
own rating stands in (critical 9, high 7.5, medium 5.5, low 3), and failing that 5.0, marked
"estimated". Name matches against CISA's catalog have no CVSS and are estimated at 7.5.

**Likelihood** starts from where the host can be reached from and how the flaw is attacked:

| | Host takes connections from the internet | LAN only |
|---|---|---|
| Attacked over the network (or not known) | 7 | 3 |
| From the same network segment | 3.5 | 2.5 |
| Needs code already running on the host | 1.5 | 1.5 |
| Needs physical access | 0.5 | 0.5 |

Then:

- **EPSS**: +1 at 1% or more, +2 at 10%, +3 at 50%.
- **CISA KEV**: on an internet-facing host with a network flaw, at least 9.5; otherwise +3.
  Known ransomware use adds 0.5.
- The result is kept between 0.5 and 10.

**Bands**: critical from 8, high from 6, medium from 3, low below that.

For example, a CVSS 9.8 flaw on a LAN-only host with a low EPSS scores 9.8 × 3 ÷ 10 = **2.9
(low)**. The same flaw on a port-forwarded host scores 9.8 × 7 ÷ 10 = **6.9 (high)**, and if CISA
has seen it exploited, 9.8 × 9.5 ÷ 10 = **9.3 (critical)**.

### Internet exposure

A host counts as internet-facing when the firewall passed connections to it from public
addresses in the last 7 days: port forwards and other open inbound rules. This is read from the
OPNsense firewall log every 6 hours, matching the hosts' addresses. Without the firewall log,
every host counts as LAN only.

Exposure is judged per host: a port-forwarded web server raises every network-reachable CVE on
that host, not just the web server's. Tracing an open port to the package listening on it is not
done yet.

## Status and history

- **Open** findings count everywhere.
- **Accepted** (admins, with a note) are risks you decided to live with. They stay accepted on
  later scans and leave the counts and charts.
- **Fixed** findings are gone from the newest software list: updated, removed, or the advisory
  changed. They are kept for 30 days, then forgotten. A fixed finding that comes back opens again.

Each scan stores the day's counts (open by band, new, fixed) for the charts, for 180 days.
Scans run every hour and soon after a list updates; the distro advisories are only re-read when a
download changes or hosts gain packages.

## Optional: OSV online check

Off by default. When on, the names and versions of **possibly matching packages only** (name
matches against CISA's catalog) are sent to `api.osv.dev`, a service run by Google, never a
host's whole software list. If OSV lists that exact version as affected by the CVE, the match
becomes confirmed. It does nothing for Slackware, Unraid or Docker images, which OSV has no data
for.

## Not covered yet

- Docker images: only the image name and tag are known, not the packages inside.
- Slackware and Unraid: no advisory feed has fixed versions for them.
- Windows and macOS applications.
- Red Hat Enterprise Linux itself (Rocky and AlmaLinux are covered).
