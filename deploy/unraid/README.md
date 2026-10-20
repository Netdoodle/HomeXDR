# HomeXDR agent on Unraid

Unraid runs from RAM and has no systemd, so `homexdr-agent install` does not survive a
reboot there. `homexdr-agent.plg` is a small Unraid plugin that does the boot-time setup
instead. Unraid installs every plugin in `/boot/config/plugins` at boot, and this one:

- keeps the agent binary, its config (local policy) and its data (identity, event spool)
  in `AGENT_DIR` on a pool or array disk, so the agent's own signed updates persist;
- starts the agent when the array's disks are mounted and stops it before they are
  unmounted, so it never holds the array open;
- runs it under a small supervisor that restarts it if it exits, and logs to the system
  log with the tag `homexdr-agent`;
- on first start, downloads the agent from the server (checking the CA pin and the
  checksum) and enrolls with a one-time token, which it then removes from the flash drive.

The agent uses its `/proc`, netlink and AF_PACKET fallbacks on Unraid, whose kernel has
no BTF for eBPF.

## Install

1. In the console, create an enrollment token (**Settings → Enrollment**) and note the
   agent API address, the CA pin and, if the server has a signed release, the update key.
2. Copy the plugin to the flash drive and install it:

   ```bash
   cp homexdr-agent.plg /boot/config/plugins/
   plugin install /boot/config/plugins/homexdr-agent.plg
   ```

3. Edit `/boot/config/plugins/homexdr-agent/homexdr-agent.cfg`: `AGENT_DIR` (for example
   `/mnt/cache/appdata/homexdr-agent`), `SERVER`, `CA_PIN`, `TOKEN`, `UPDATE_KEY` and
   `ALLOWED_ACTIONS`. On the server that runs HomeXDR itself, leave `host.isolate` out of
   `ALLOWED_ACTIONS`: isolating that host would cut every other agent off.
4. Start it: `/usr/local/emhttp/plugins/homexdr-agent/scripts/rc.homexdr-agent start`.

Check it with `homexdr-agent status` or
`/usr/local/emhttp/plugins/homexdr-agent/scripts/rc.homexdr-agent status`, and in the system
log (`grep homexdr-agent /var/log/syslog`).

## Remove

Remove the plugin on the **Plugins** page (or `plugin remove homexdr-agent.plg`). That
stops the agent and removes the service; its identity and data stay in `AGENT_DIR`. Delete
that folder and revoke the host in the console to remove it completely.
