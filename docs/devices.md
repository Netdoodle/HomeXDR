# Device inventory

The **Devices** page lists what is on your home network, whether or not it runs an agent. Nothing has to be installed:
devices are worked out from what HomeXDR already receives.

| Source | What it adds |
|---|---|
| DHCP logs | The device's MAC address and the name it gave. This is what makes identity reliable |
| Firewall logs, NetFlow, DNS logs, Suricata | Addresses in use, and when they were last active |
| Agents | Links the device to its host page |

Turn sources on with [network-visibility.md](network-visibility.md). With firewall logs alone, most entries show
**no MAC yet**: an address, not yet a device.

## How a device is identified

Identity follows the DHCP name, then the MAC, then the IP:

1. An address with no MAC becomes a provisional record, `ip:<address>`.
2. When DHCP links that address to a MAC, the record merges into the MAC's record. Its name, note and history carry over.
3. A new **randomized** MAC giving a name HomeXDR already knows stays that device, so a phone rotating its private address
   stays one device. Names many devices share, such as `iPhone` or `localhost`, do not count. Two real MACs with the same name stay
   two devices.

## What is not a device

Only private addresses inside your home subnets count. These never do: multicast, broadcast, loopback, link-local, the
firewall's own addresses, and `172.16.0.0/12`, where Docker bridges live. An agent's address counts only in a subnet also seen on
the wire, so bridges and tunnels on the host stay out. Private addresses on the firewall's WAN interface, such as a cable modem's, are
ignored too.

An address that has only received traffic is marked as such and raises no alert: a sweep of a subnet would otherwise invent a device
for every address in it. Such records go after 7 days. Records with no MAC go after 90 days of silence, unless you have named them.

IPv6 addresses count only inside a subnet you list. Phones rotate them constantly, so they make poor identities.

## Settings

**Settings → Network** (admin):

- **Home subnets**: empty means automatic, as described above. List them once you know them; the page shows what has been seen.
- **Never count these**: a guest network, say. These are ignored by the detectors too.
- **Firewall addresses**: learned from its logs. The sender of `filterlog` is the firewall, and the same last number is assumed on its other
  VLANs in that range (seeing `192.168.20.1` implies `192.168.10.1`). Add any that does not fit.
- **Alert on new devices**: on by default.
- **Learning days**: 3 by default.

## New-device alerts

`net:new-device` is a low-severity alert. It goes out about 10 minutes after a device first appears, which gives DHCP time to name it.

- Nothing goes out during the learning period, which starts the first time this feature runs. Everything seen in it counts as normal.
- A device with an agent, or one you have marked as known, is never new.
- A new address with no MAC raises the alert too, and says plainly that it is not proof of a new device. Without DHCP logs, a device you
  know that gets a new address looks exactly the same.
- A randomized MAC with no usable name can raise this each time it rotates. The alert says so.
- At most 10 go out per pass, so a burst spreads out over a few minutes rather than arriving at once.

## How it stays cheap

The inventory lives in memory and takes no database action per event. Changes are written every 30 seconds, in one transaction, and it holds
at most 4096 devices. The page says when that limit is reached. After a restart it reloads from the database; the firewall's learned addresses are
relearned from its next log line.
