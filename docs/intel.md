# Investigating indicators

**Investigate** answers "is this bad, and did it touch anything of mine?" for an IP address,
domain, URL or file hash. Paste the indicator (defanged forms such as `hxxps://evil[.]com`
work), or follow a link from an alert's **Indicators** panel or the radar icon on an event field.

A lookup shows:

- **A score and verdict**, with what they rest on, and a short written brief.
- **In your environment:** the events, hosts, processes and alerts that mention the indicator
  in the last 7 to 365 days, and whether it is one of your own hosts' addresses. This searches
  only your own data, and nothing leaves the server.
- **Whois and network**, with a map for IP addresses.
- **What each source said**, the most concerning first, with a link to the source's own page.
  Sources with nothing to say are chips in the Sources panel rather than empty cards.

## Sources

| Service | Key | Looks up | Tells you |
|---|---|---|---|
| VirusTotal | required, free | IP, domain, URL, hash | Verdicts from about 90 engines |
| AbuseIPDB | required, free | IP | Community abuse reports |
| abuse.ch: URLhaus, MalwareBazaar, ThreatFox | required, free (one key) | IP, domain, URL, hash | Known malware URLs, samples and IOCs |
| GreyNoise | optional | IP | Internet scanners, and whether they look malicious |
| CIRCL hashlookup | none | hash | Known files from software distributions and NSRL |
| AlienVault OTX | optional | IP, domain, URL, hash | Community threat reports |
| Pulsedive | optional | IP, domain, URL | Risk rating, threats and feeds |
| Shodan InternetDB | none | IP | Open ports, hostnames and known CVEs |
| ProxyCheck | optional | IP | VPN, proxy and Tor exits |
| urlscan.io | optional | IP, domain, URL | Public scans: hosting, TLS, domain age |
| ipwho.is | none | IP | Location and network |
| WHOIS (RDAP) | none | IP, domain | Registration data |

Without any keys, lookups work but the verdict is often "No known signal". For a firmer
answer, add free keys for VirusTotal, AbuseIPDB and abuse.ch in **Settings → Threat intel**.
Keys are stored on the server, sent only to their own service, and never shown again. Each
service can be switched off there.

Your network has to reach these services. A DNS filter can block some of them, and that source
then shows as failed.

## The score

Sources with a reputation signal give a risk from 0 to 100, and each has a weight: VirusTotal,
AbuseIPDB and abuse.ch count most, then GreyNoise and CIRCL, then OTX, Pulsedive and
InternetDB. The score is 60% the strongest signal from a heavily weighted source plus 40% the
weighted average, so one solid report is not averaged away by sources that simply have not seen
the indicator. A single VirusTotal engine barely counts, because one engine is routinely wrong.
ProxyCheck, urlscan, ipwho.is and WHOIS are context and do not affect the score.

| Verdict | Means |
|---|---|
| Malicious | Score 75 or more |
| Suspicious | Score 45 to 74 |
| Low risk | Score 20 to 44: weak signals only |
| Clean | Under 20, and a heavily weighted source had data |
| No known signal | Under 20, but only lightly weighted sources had data: weak evidence |
| Unknown | No reputation source had data. This does not mean safe: new or targeted infrastructure has no history |
| Internal | A private address or internal name, not sent anywhere |

The score summarizes other people's reports and is not a decision. The brief is generated from
the same data by fixed rules, not by an AI model, so it costs nothing and cannot invent
anything. Shared hosting, CDNs and VPNs are often reported for what their neighbors did.

## What leaves your network

A lookup sends the indicator, and nothing else, to the services that are switched on. It only
happens when someone investigates an indicator or the AI analyst does, and each one is in the
audit log (`intel.lookup`) with the services it went to. HomeXDR asks those services about the
indicator; it never contacts the indicator itself, so a lookup does not tip off an attacker's
server, though the services may record the query and some share what they are asked about.

These are never sent anywhere:

- Private and reserved addresses (RFC 1918, loopback, link-local, CGNAT, documentation ranges).
- Internal names (`.local`, `.lan`, `.home`, `.internal`, `.corp`, `.arpa` and similar).
- Domains you list under **Internal domains**, with their subdomains.

For those, only your own events are searched. Answers are saved and reused for a day by default
(**Reuse answers for**) to save your quotas; **Re-check** always asks again.

## The AI analyst

The analyst has a `lookup_indicator` tool, in both the built-in engine and over MCP, that returns
the same report with the indicator's sightings. It uses saved answers and your quotas, and its
lookups appear in the audit log as `ai-analyst`. Turn it off with **Let the AI analyst look up
indicators**. Like its other tools it only reads, and it treats what the services return as
evidence rather than instructions.
