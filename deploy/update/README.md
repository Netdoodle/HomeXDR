# Automatic server and agent updates

`homexdr-update.sh` keeps a Docker Compose install of HomeXDR in step with a git branch.
Run it from cron on the Docker host as root. Each run fetches the branch; when it has
moved, the script:

1. builds the server image from that commit (`docker build --pull`, with the version,
   commit and commit time stamped in);
2. signs the agent release manifest bundled in the image with the **release key**, and
   writes the signature and public key to the signatures folder the server mounts
   read-only;
3. recreates the server container (`docker compose up -d --no-deps`; ClickHouse is not
   touched) and waits up to `HEALTH_TIMEOUT` seconds for it to report healthy;
4. if it does not, puts the previous image back, deletes the new release's signature (so
   no agent installs it) and skips that commit until a newer one arrives;
5. keeps the last few builds, and copies a newer version of itself from the repository.

Agents enrolled with `--update-key` (or with `auto_update` and `update_key` in their
config) then install the new agent from their next heartbeat. See
[docs/protocol.md](../../docs/protocol.md#agent-updates).

## The release key

The script creates an Ed25519 key on first use (`SIGNING_KEY`, default
`release-signing.key` next to `update.conf`) and prints its public key with
`homexdr-update.sh --print-key`. Keep it on the host, outside every Docker volume, and
back it up: agents trust only releases signed with it. If you lose it, create a new one and
update `update_key` in each agent's config.

Anyone who can push to the tracked branch can get code onto the server and, through
signed releases, onto agents with automatic updates. Protect the branch accordingly.

## Setup

```bash
mkdir -p /opt/homexdr-update
cp deploy/update/homexdr-update.sh deploy/update/update.conf.example /opt/homexdr-update/
cd /opt/homexdr-update && cp update.conf.example update.conf   # set COMPOSE_DIR, REPO_URL, ...
```

The compose file must use `image: homexdr/server:local` for the server (with
`pull_policy: never` or a `build:` section) and mount the signatures folder:

```yaml
    volumes:
      - ./signatures:/usr/share/homexdr/signatures:ro
```

For a private repository, create a read-only deploy key and add it to the repository
(GitHub: Settings → Deploy keys), then set `GIT_SSH_KEY` and `KNOWN_HOSTS`:

```bash
ssh-keygen -t ed25519 -N '' -C homexdr-updater -f /opt/homexdr-update/deploy-key
ssh-keyscan -t ed25519 github.com > /opt/homexdr-update/known_hosts   # compare with GitHub's published fingerprint
```

Run it once by hand, then schedule it:

```bash
/opt/homexdr-update/homexdr-update.sh --force
echo '*/15 * * * * root /opt/homexdr-update/homexdr-update.sh >/dev/null 2>&1' > /etc/cron.d/homexdr-update
```

On **Unraid**, keep the folder on the flash drive (for example `/boot/config/homexdr`),
which survives reboots, and add the schedule as
`/boot/config/plugins/dynamix/homexdr-update.cron`:

```
*/15 * * * * bash /boot/config/homexdr/homexdr-update.sh >/dev/null 2>&1
```

then run `update_cron`. Failures and updates show up as Unraid notifications.

Logs go to syslog (tag `homexdr-update`); the last build's output is in
`$COMPOSE_DIR/update/build.log` and deployed versions in `$COMPOSE_DIR/update/history`.
`homexdr-update.sh --check` reports whether an update is waiting.
