# Offline lists

Public lists downloaded ahead of time, so questions about a domain, an IP address or a MAC address
are answered on this server. A lookup never touches the network, and nothing about your network
leaves it. **Settings > Offline lists** shows each list's source, licence, last update, entry count
and last error, with a toggle and a refresh button.

The results appear on **Investigate** and in an alert's **Indicators** panel, and other features
read them through `enrich.Lookup` (`c.Enrich`).

## The lists

Each source's URL, file format and licence page were checked from the owner's PC on 2026-11-05.

| List | Default | Source | Format | Licence |
|---|---|---|---|---|
| Registrable domain | built in | Public suffix list inside `golang.org/x/net/publicsuffix` | no download | MPL 2.0, compiled in |
| Tranco popular sites | on | `https://tranco-list.eu/top-1m.csv.zip`, weekly | zip of `rank,domain` lines, 22 MB unpacked | No licence of its own. Free, with credit asked for. Built from Cisco Umbrella, Majestic (CC BY 3.0), Farsight, Chrome UX Report (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0) |
| MAC vendors | on | `https://standards-oui.ieee.org/oui/oui.csv`, monthly. If IEEE refuses, `https://www.wireshark.org/download/automated/data/manuf` | CSV, or Wireshark's tab-separated file | IEEE's public listing |
| IP networks | on | `https://iptoasn.com/data/ip2asn-combined.tsv.gz`, weekly | tab-separated range, AS number, country, name | Public domain (PDDL v1.0) |
| Known exploited vulnerabilities | on | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, daily | JSON. See [vulnerabilities.md](vulnerabilities.md) | U.S. government data |
| Website categories (UT1) | **off** | `https://dsi.ut-capitole.fr/blacklists/download/<category>.tar.gz`, weekly | tar.gz holding `<category>/domains` | **Not confirmed.** The files were reachable, but the licence page answered 503 on the day it was checked. It stays off until you have read their terms |
| Newly registered domains | **off** | `https://raw.githubusercontent.com/WhoisFreaks/daily-newly-registered-domains/main/<date>-free-newly-registered-domains.csv`, daily, 30 days kept | one domain per line | **None stated** in the repository |

The choice of sources and of UT1's categories comes from tapwatch's `feeds.py` (MIT licensed).

## Downloads

- Over HTTPS only, with a size cap per file and a plain User-Agent. A redirect to plain HTTP is refused.
- With `If-None-Match` and `If-Modified-Since`, so an unchanged file costs one small request.
- Written to a new folder, parsed, and checked for a minimum number of entries. Only then does it
  replace the current copy, which becomes the last good copy: `<data>/lists/<id>/current` and
  `last-good`. A failed or bad download changes nothing. If the current copy is damaged at start, the
  last good one loads instead.
- After a failure, a list is tried again within 6 hours.

**If your firewall blocks a source,** the last error says so in plain words, naming the host: for
example that it could not be looked up or resolved to `0.0.0.0`, as a DNS blocklist answers. Allow
that host on the firewall or turn the list off. The doctor shows the same.

## Memory

Lists are sorted byte slices searched by bisection, with no pointers for the garbage collector to
follow. Measured with a million Tranco-shaped domains (`TestMillionDomainsMemory`,
`BenchmarkDomainLookup`): 37 MB, against 100 MB and more for a Go map, and about 215 ns a lookup.
Other lists are smaller. A list that is off takes no memory.
