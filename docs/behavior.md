# Behaviour detection

Sigma rules look at one event at a time. Behaviour detectors look across many: a device checking in on a timer, an upload far
above its normal, a sweep across a subnet.

Their findings are alerts like any other, so suppressions, notifications and the AI analyst treat them alike. All are low or medium
severity: they should earn your trust first. Each explains itself in plain words, with the numbers behind it.

**The Devices page** shows each detector's status. **Settings → Network** has a toggle and thresholds for each.

Thresholds and benign service lists are starting points taken from measurements on one home network. They have not
yet been measured on yours, so tune them in **Settings → Network** as findings come in.

## Detectors

| Detector | Rule | Severity | Needs | Learning |
|---|---|---|---|---|
| Beaconing | `net:beaconing` | Medium, or low if the domain is popular | NetFlow; partial on firewall rows | None |
| DNS tunnelling | `net:dns-tunnel` | Medium | Unbound logs, the AdGuard Home query log or Suricata DNS | None |
| DNS bypass | `net:dns-bypass` | Low | NetFlow; partial on firewall rows | 3 days |
| Upload spike | `net:upload-spike` | Medium | NetFlow only | 7 days |
| Unusual port | `net:unusual-port` | Low | NetFlow; partial on firewall rows | 7 days |
| Internal scan | `net:internal-scan` | Medium | Firewall rows or NetFlow | None |
| Rogue DHCP server | `net:rogue-dhcp` | Medium | Firewall rows or NetFlow | 3 days |
| Exposed service | `net:exposure` | Medium | Firewall rows or NetFlow | 3 days |

### Status

| Status | Meaning |
|---|---|
| Running | It has what it needs |
| Running, partial data | It runs on firewall rows, which rarely name the device behind NAT. Most traffic is invisible to it until NetFlow is on |
| Learning | It is recording what is normal and reports nothing until the date shown |
| Needs data | Its input does not exist yet. The page says what to turn on |
| Off / Error / Not run yet | As they say. An error shows the message and tries again next run |

Learning starts when a detector first has its input. It starts again when NetFlow first arrives, since flows are a far wider view than firewall
rows and would otherwise flood it with things it had never seen.

Anything seen while learning counts as normal, **including anything bad that was already there**.

### Beaconing

The same device, address and port, at very even gaps. Defaults: at least 10 check-ins, over at least 600 seconds, spread of gaps at most 15% of
their average, average gap at least 5 seconds, reported once in 7 days. Looks back 12 hours once an hour, so a check-in slower than about an hour is not seen.

Left out because they are regular by design: UDP on NTP, STUN and Tailscale ports; TCP 5223 and 5228 (phone push); destinations whose name is a known push
service, endpoint security agent, time service or relay. Names come from Suricata TLS and HTTP events, when those exist. Without a name, a port or
address is all it has, so more ordinary services get through.

Also left out: a popular domain that a second device also uses; any destination three or more devices use; and one long connection cut into equal parts by
the exporter's timers, which keeps one source port where real check-ins use many. A popular domain used by one device stays, at low severity, because popular
services get used for control channels too. At most 3 reports per device and port a day.

### DNS tunnelling

Per device and domain over the last hour: 20 different names with a label of 30 or more characters, or 100 different names of which half look random (a label of
12 or more characters, 3.5 bits of entropy per character or more). Left out: domains on the popularity list, a built-in list of CDNs that number their hosts, and local
names (`.arpa`, `.local`, `.lan` and so on). Some security and anti-spam products look up names like this; add them under **Domains to leave out**.

### DNS bypass

A device using port 53 or 853 to anything but the firewall or an approved resolver. Blocked attempts count, and the alert shows how many were allowed and blocked. Encrypted DNS over HTTPS on
port 443 looks like any other web traffic and is not seen.

### Upload spike

Compares each complete clock hour, 30 minutes after it ends, with the same hour of day on earlier days. Reports at 10 times the device's own normal and at least 500 MB, once
it has 5 samples for that hour and has finished learning. Hours are UTC. Keeps the last 14 samples per hour of day, in the database.

### Unusual port

An internet connection on a TCP or low UDP port no device here has used. Web, DNS and NTP ports are normal from the start. Left out: UDP at or above 1024, since games and calls open new ports
constantly, and replies from a service on your network, recognised by the source port being lower than the destination port. A port becomes part of normal once reported, so the next device on it stays quiet.

### Internal scan

Reaching 30 other home addresses, or 30 ports on one address, in 30 minutes. Traffic on discovery ports is left out, and so are replies. **Traffic inside one VLAN never reaches the firewall, so only
scans crossing VLANs are seen**, unless an agent runs on the scanning device. Add monitoring tools under **Devices to leave out**.

### Rogue DHCP server

A home address sending from port 67 to port 68, other than the firewall or an approved server. It relies on the firewall or a flow exporter seeing the reply. A rogue server reaching clients on its own switch, without the
firewall seeing the broadcast, is not visible here.

### Exposed service

An allowed connection from a public address to a home address and port. Firewall rows are reliable for this, since they log the packet that opens a connection, but only for rules with logging on. With NetFlow,
replies look the same as new connections, so only TCP to a port below 1024 from a higher port counts. Services on the firewall itself, such as a reverse proxy, are not internal and do not count. List yours under
**Expected services**, or let the learning period pick them up.

## Limits on load

Detectors run one at a time, one every 90 seconds at most, each no more than every 15 minutes (beaconing, hourly). So a slow one delays the next detector and never ingest. Searches use the event store's memory caps, over
bounded windows, with at most 10,000 result rows. Each run stops after 3 minutes and raises at most 20 findings; the rest wait for the next run. What a detector has learned is kept in SQLite (`behavior_state`), at most 20,000 entries each.

One new event store method exists for this, `ConnTimes`, on both backends: the beaconing detector needs raw times between connections, which a table result cannot give.

NetFlow events are checked against your Sigma rules like everything else.
