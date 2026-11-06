# Network visibility

HomeXDR sees the network through what the firewall sends it. By default that is `filterlog` and Suricata
over syslog. Firewall logs have one big gap: traffic to the internet is logged after NAT, so almost every
outbound row carries the firewall's WAN address and not the device's. Measured on one home network over
48 hours: 789,274 outbound pass rows from the WAN address, and 264 rows that named a LAN device.

Three optional sources fill the gap. Each one is off until you turn it on.

| Source | What it gives you | What needs it |
|---|---|---|
| **Unbound query logs** | Which device looked up which name | DNS tunnelling, device inventory |
| **DHCP logs** | IP, MAC and hostname of each device | Device inventory: real names, new-device alerts with a MAC, rogue server context |
| **NetFlow** | Every connection by its real LAN address, with bytes and packets | Beaconing, upload spike, unusual port, DNS bypass, internal scan |

Without them, the detectors run on what exists and the [behaviour page](behavior.md) says what is missing.

> **These steps are unverified on the owner's firewall.** They come from the OPNsense 26.1 documentation
> and from the log formats each program documents. No live sample of these logs existed when the decoders
> were written. Menu names can differ slightly between versions. After enabling a source, use the
> "Check it works" line in its section. If a line is not decoded it is still stored as generic syslog, so nothing
> is lost; send a sample and the decoder can be corrected.

HomeXDR never changes the firewall. All of these are changes you make yourself.

## Unbound query logs

Only useful when Unbound answers your devices. If AdGuard Home or another resolver listens on port 53 in front
of it, or Unbound is turned off, Unbound's log names that resolver and not the device, so skip this section.
DNS from such a resolver is not collected yet.

1. **Services → Unbound DNS → Advanced**: turn on **Log Replies**. Each reply line names the client, the
   name, the type, the result, the time taken and whether it came from cache.
2. Leave **Log Queries** off. It adds a second, smaller row for every lookup and tells HomeXDR nothing more.
   OPNsense warns that query logging can slow a busy resolver.
3. **System → Settings → Logging → Remote**: edit the destination that sends to HomeXDR. Under
   **Applications**, add `unbound`. Under **Levels**, make sure informational messages are included.

Check it works: search for `event.module:dns`. Each row should have a `source.ip` of a device and a
`dns.question.name`.

Only clients that use this resolver appear. A device with a hardcoded public resolver shows up through
NetFlow and the DNS bypass detector instead.

## DHCP logs

First find out which DHCP server you run. It is whichever of these pages has your subnets on it:

| Service | Page | Logs as |
|---|---|---|
| ISC DHCP | **Services → ISC DHCPv4** | `dhcpd` |
| Kea | **Services → Kea DHCP → Kea DHCPv4** | `kea-dhcp4` |
| dnsmasq | **Services → Dnsmasq DNS & DHCP** | `dnsmasq-dhcp` or `dnsmasq` |

Then, in **System → Settings → Logging → Remote**, add that program to the destination's **Applications**.
The exact name in the list can differ from the table. If you cannot find it, leave **Applications** empty for a
day, which sends everything, and look at what arrives. Informational messages must be included in **Levels**.

ISC and dnsmasq log the hostname with each lease. Kea logs it only at debug level, so with Kea a device's
identity is its MAC address unless you raise Kea's logging.

Check it works: renew a lease on any device, then search for `event.module:dhcp`. The row should have
`source.ip`, `source.mac` and, except on Kea, `source.domain`.

## NetFlow

### On the server

Set these in `.env` and recreate the container:

```
HOMEXDR_NETFLOW_ADDR=:2055
# Only needed if different from HOMEXDR_SYSLOG_ALLOW:
HOMEXDR_NETFLOW_ALLOW=192.168.20.1
```

The compose files publish `2055/udp` already (`HOMEXDR_NETFLOW_PORT` changes the host port). With
`HOMEXDR_NETFLOW_ADDR` empty, nothing listens on it. Allow only the firewall: anyone who can send to this port
can write events.

### On the firewall

**Reporting → NetFlow**:

| Setting | Value | Why |
|---|---|---|
| **Interfaces** | Every internal VLAN (for example Main, MGMT, IoT, Reolink, Guest). **Not WAN.** | Internal interfaces see the device's real address, before NAT |
| **Egress only** | Empty | On an internal interface, egress-only would hide everything a device sends, including uploads |
| **Capture local** | As it is today | Only feeds the firewall's own Insight reports |
| **Version** | 9 | Version 5 has no IPv6 |
| **Destinations** | `<homexdr address>:2055`, for example `192.168.20.20:2055` | |

### Why these interfaces

- **If WAN is already captured** for the firewall's own Insight reports, you can leave it. Its rows name no home
  address, so the device inventory and the detectors ignore them, but they are still stored, which adds volume.
- **Why not WAN:** a flow on WAN carries the WAN address after NAT, so it names no device. It would also count every
  internet connection a second time. OPNsense's documentation warns about this same double count.
- **What you get per connection:** NetFlow records one direction per row. A download appears as a device-to-server
  row and a server-to-device row, both with the LAN address. HomeXDR labels each row `outbound`, `inbound` or `internal`
  from its addresses.
- **Traffic between VLANs appears twice:** once entering the firewall on one VLAN and once leaving on the other. That is
  expected and harmless here. Upload totals count only traffic to the internet, and the scan detector counts distinct
  hosts and ports, not rows.
- **Traffic inside one VLAN is not seen at all:** a switch or access point delivers it without touching the firewall. A
  scan between two devices on the same VLAN stays invisible unless an agent runs on one of them.

Check it works: **Settings → Integrations** shows the exporter under NetFlow / IPFIX intake within a minute. Then
search for `event.module:netflow network.direction:outbound`; `source.ip` should be a LAN address. If it shows your WAN
address, WAN is among the selected interfaces.

Templates are sent only now and then. Flows that arrive first wait until the template does, so an empty table for
the first few minutes after a restart is normal.

### Volume

A home network produces thousands of flows an hour, not millions, but every one is stored as an event. The
receiver holds a bounded queue and counts what it drops under **Lost** on the integrations page. If the event store
grows too fast, set `HOMEXDR_RETENTION_MAX_SIZE`.

## Addresses HomeXDR ignores

The device inventory and the detectors share one view of the home network, set under
**Settings → Network**. By default every private IPv4 address counts except `172.16.0.0/12` (where Docker bridges live),
multicast, broadcast, and the firewall's own addresses. See [devices.md](devices.md).
