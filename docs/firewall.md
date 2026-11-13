# Host firewall control

Block IP addresses and networks in every enrolled host's own firewall, from **Settings >
Firewall** or with **Block this IP everywhere** in an alert's Investigate menu. HomeXDR owns
its rules and never touches anything else in the host's firewall, nor the isolation rules.

## Block policies

Each entry is an IPv4 or IPv6 address or CIDR with a note, who added it and when, a direction
and a scope:

- **Scope**: everywhere (the organisation, "Global") or one group. A group's entries apply to
  the group and its child groups. An entry whose group is deleted applies to no host; the
  Firewall page says so.
- **Direction**: both ways (the default), inbound only (connections the address opens to the
  host) or outbound only (connections the host opens to the address).
- **On or off per group**: `firewall.enabled` under Settings > Groups (Inherit, Block or Off),
  with the global value on the Firewall page. On by default. A host whose group turns it off
  gets an empty rule set, which removes HomeXDR's rules.

A host's rule set is every Global entry plus the entries of its group and that group's parent.

### What is refused

The server checks every address when it is added, and again before sending a rule set; the
agent checks the whole set once more before it touches the firewall (`shared/hostfw`).

| Refused | Why |
|---|---|
| IPv4 broader than /8, IPv6 broader than /32 (so `0.0.0.0/0` and `::/0`) | A /8 is 16 million addresses; a /32 is a large provider's whole IPv6 allocation. Anything broader is a mistake, not a block |
| Loopback, link-local, multicast, broadcast, unspecified (`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `255.255.255.255`, `::`, `::1`, `fe80::/10`, `ff00::/8`) | Blocking them breaks the host itself |
| Anything covering the HomeXDR server | The server's addresses: those in `HOMEXDR_SERVER_NAMES` (names are resolved), the host of `HOMEXDR_AGENT_URL` and the server's interface addresses. The agent refuses the same for the addresses it connects to, so a bad rule set cannot cut it off from the server that would remove it |
| More than 1000 entries in all | The agent accepts at most 1000 addresses |

Overlapping entries are merged on the host (a network swallows the addresses inside it). Your
router or DNS server is not protected: blocking it cuts the host off from DNS. If the server's
address changes so that an existing entry covers it, the entry is left out of every rule set
and the Firewall page shows why.

## How it reaches the hosts

A loop on the server (every minute, and at once when an entry or the global switch changes) works out each Windows, Linux
and macOS host's rule set, with a version (a hash of the set). When the version differs from
the one the agent last applied, it sends a signed `firewall.apply` command with the complete
set; an empty set removes everything. Like App Control, each host shows `applied`, `pending`
(sent), `failed` (tried again after 30 minutes, or at once when the set changes), `not_allowed`
(the agent's local policy leaves `firewall.apply` out of `allowed_actions`, or the agent is
too old), `offline`, `off` or `empty` (nothing to block). The command is a fixed, typed
operation: the agent only ever turns validated addresses into block rules. It cannot be sent
by hand from the host page.

The agent saves the last rule set in `firewall.json` in its data directory and applies it
again when it starts, because nftables and pf rules do not survive a reboot.

### Windows

Windows Firewall rules in their own group, **HomeXDR**, made with the NetSecurity PowerShell
module (`New-NetFirewallRule -Group HomeXDR -Action Block -RemoteAddress ...`). Addresses are
batched, at most 100 per rule: one or more inbound rules and one or more outbound rules,
named `HomeXDR-<version>-in-1` and so on. A new version's rules are added before the old
version's are removed, so there is no moment without blocks; a set already in place is left
alone. Block rules win over allow rules in Windows Firewall. If the firewall is off for a
profile, the result says so: the rules do nothing there. Windows keeps the rules across
reboots.

### Linux

An nftables table of its own, `inet homexdr_block` (isolation uses `inet homexdr`), with
interval sets for each direction and family and drop rules in the input, output and forward
hooks, so containers and VMs on the host are covered too. The whole table is replaced in one
atomic `nft -f` transaction. Addresses blocked both ways are dropped outright; one-way blocks
use `ct direction original`. There is no iptables fallback: without `nft` the command fails
and says so.

### macOS

A pf anchor, `com.apple/001.HomeXDR-block`, with tables and `block drop quick` rules. pf is
enabled with a reference token of its own (`pf-block.token` in the data directory), so
removing the blocks never turns off pf that isolation or another program needs. pf keeps
state: connections that were already open continue until they close.

## Removing the rules

`homexdr-agent uninstall` removes HomeXDR's rules on every platform. To remove them by hand:

```
# Windows (elevated PowerShell)
Remove-NetFirewallRule -Group HomeXDR

# Linux
nft delete table inet homexdr_block

# macOS
sudo pfctl -a com.apple/001.HomeXDR-block -F all
```

Remove the agent's `firewall.json` too, or a running agent puts them back on its next start
(until the server sends it a new set).

## Limits

- Not tested on real hosts yet: the rule rendering is unit tested, but Windows Firewall,
  nftables and pf behaviour has not been checked live.
- Windows and macOS keep connections that were open before a block; Linux drops them.
- Blocks are host firewall rules: a user with administrator rights on the host can remove
  them. They protect hosts with the agent only.
- Pushing the blocks to OPNsense, for a network-wide block, is not done yet (roadmap).
