#!/bin/bash
# HomeXDR server updater. Run it from cron on the Docker host (as root). When the tracked
# git branch has new commits it:
#
#   1. builds the server image from that commit (the image bundles the agent binaries),
#   2. signs the agent release manifest with the release key, so agents that opted in to
#      automatic updates install the new agent (docs/protocol.md, "Agent updates"),
#   3. recreates the server container and waits for it to report healthy,
#   4. rolls back to the previous image if it does not, and skips that commit afterwards.
#
# Usage:
#   homexdr-update.sh               update if the branch moved (what cron runs)
#   homexdr-update.sh --force       rebuild and redeploy the branch head even if unchanged
#   homexdr-update.sh --check       only say whether an update is available
#   homexdr-update.sh --print-key   print the release public key (creating the key if needed)
#
# Settings are read from update.conf next to this script, or from $HOMEXDR_UPDATE_CONF
# (see update.conf.example). The release signing key stays on the host: the server
# container only gets the signatures and the public key, read-only.

set -uo pipefail

SCRIPT="$(readlink -f "$0")"
CONF="${HOMEXDR_UPDATE_CONF:-$(dirname "$SCRIPT")/update.conf}"

log() {
  echo "$(date '+%F %T') $*" >&2
  logger -t homexdr-update -- "$*" 2>/dev/null || true
}

# notify uses Unraid's notification system when it is there (no-op elsewhere).
notify() {
  local n=/usr/local/emhttp/webGui/scripts/notify
  [ "${NOTIFY:-1}" = 1 ] && [ -x "$n" ] || return 0
  "$n" -e "HomeXDR" -s "$1" -d "$2" -i "${3:-normal}" >/dev/null 2>&1 || true
}

fail() {
  log "ERROR: $*"
  notify "HomeXDR update failed" "$*" alert
  return 1
}

load_conf() {
  [ -r "$CONF" ] || { echo "homexdr-update: missing $CONF (copy update.conf.example)" >&2; return 1; }
  # shellcheck source=/dev/null
  . "$CONF"
  : "${COMPOSE_DIR:?set COMPOSE_DIR in $CONF}"
  SERVICE="${SERVICE:-homexdr}"
  IMAGE="${IMAGE:-homexdr/server}"
  REPO_URL="${REPO_URL:-git@github.com:Netdoodle/homexdr.git}"
  BRANCH="${BRANCH:-main}"
  SRC_DIR="${SRC_DIR:-$COMPOSE_DIR/src}"
  SIGNING_KEY="${SIGNING_KEY:-$(dirname "$CONF")/release-signing.key}"
  SIGNATURES_DIR="${SIGNATURES_DIR:-$COMPOSE_DIR/signatures}"
  KEEP_IMAGES="${KEEP_IMAGES:-3}"
  HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-300}"
  STATE_DIR="${STATE_DIR:-$COMPOSE_DIR/update}"
  mkdir -p "$STATE_DIR"
  GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=20"
  [ -n "${GIT_SSH_KEY:-}" ] && GIT_SSH_COMMAND+=" -o IdentitiesOnly=yes -i $GIT_SSH_KEY"
  [ -n "${KNOWN_HOSTS:-}" ] && GIT_SSH_COMMAND+=" -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes"
  export GIT_SSH_COMMAND
}

compose() {
  docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_DIR/docker-compose.yml" "$@"
}

# --- release key and signatures ---

ensure_key() {
  [ -s "$SIGNING_KEY" ] && return 0
  mkdir -p "$(dirname "$SIGNING_KEY")"
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$SIGNING_KEY") || return 1
  log "created release signing key $SIGNING_KEY; back it up, agents trust only this key"
}

public_key() {
  echo "ed25519:$(openssl pkey -in "$SIGNING_KEY" -pubout -outform DER | tail -c 32 | base64 -w0)"
}

# sign_release <image>: signs the image's agent release manifest. Prints the signature path.
sign_release() {
  local image=$1 tmp cid sum sig
  tmp=$(mktemp -d) || return 1
  cid=$(docker create "$image") || { rm -rf "$tmp"; return 1; }
  docker cp "$cid:/usr/share/homexdr/downloads/agent-release.json" "$tmp/manifest.json" >/dev/null
  local rc=$?
  docker rm "$cid" >/dev/null
  [ $rc = 0 ] || { rm -rf "$tmp"; fail "image has no agent release manifest"; return 1; }
  ensure_key || { rm -rf "$tmp"; return 1; }
  mkdir -p "$SIGNATURES_DIR"
  sum=$(sha256sum "$tmp/manifest.json" | cut -d' ' -f1)
  sig="$SIGNATURES_DIR/agent-release.$sum.sig"
  if openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" -in "$tmp/manifest.json" -out "$tmp/sig.bin" &&
    { base64 -w0 "$tmp/sig.bin"; echo; } >"$sig.tmp" && mv "$sig.tmp" "$sig"; then
    public_key >"$SIGNATURES_DIR/update-key.pub.tmp" && mv "$SIGNATURES_DIR/update-key.pub.tmp" "$SIGNATURES_DIR/update-key.pub"
    chmod 644 "$sig" "$SIGNATURES_DIR/update-key.pub"
    rm -rf "$tmp"
    echo "$sig"
    return 0
  fi
  rm -rf "$tmp" "$sig.tmp"
  fail "could not sign the agent release"
}

# --- health ---

# wait_healthy <image id>: waits until the service runs that image and is healthy.
wait_healthy() {
  local want=$1 deadline=$((SECONDS + HEALTH_TIMEOUT)) cid img st
  while [ $SECONDS -lt $deadline ]; do
    cid=$(compose ps -q "$SERVICE" 2>/dev/null)
    if [ -n "$cid" ]; then
      img=$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null)
      st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)
      [ "$img" = "$want" ] && [ "$st" = healthy ] && return 0
    fi
    sleep 5
  done
  return 1
}

prune_images() {
  docker image ls "$IMAGE" --format '{{.CreatedAt}}|{{.Tag}}' | sort -r |
    awk -F'|' '$2 != "local" && $2 != "previous" && $2 != "<none>" {print $2}' |
    tail -n +$((KEEP_IMAGES + 1)) |
    while read -r tag; do docker rmi "$IMAGE:$tag" >/dev/null 2>&1; done
  docker image prune -f --filter "label=org.opencontainers.image.title=homexdr-server" >/dev/null 2>&1
  # Signatures are tiny, but there is no need for more than the last 20.
  ls -1t "$SIGNATURES_DIR"/agent-release.*.sig 2>/dev/null | tail -n +21 | xargs -r rm -f
}

# --- main ---

main() {
  local force=0 check=0
  case "${1:-}" in
    --force) force=1 ;;
    --check) check=1 ;;
    --print-key) load_conf && ensure_key && public_key; return ;;
    "") ;;
    *) echo "usage: $0 [--force|--check|--print-key]" >&2; return 2 ;;
  esac
  load_conf || return 1

  exec 9>"$STATE_DIR/lock"
  flock -n 9 || { echo "another update is running"; return 0; }

  if [ ! -d "$SRC_DIR/.git" ]; then
    log "cloning $REPO_URL ($BRANCH) into $SRC_DIR"
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$SRC_DIR" || { fail "git clone failed"; return 1; }
  fi
  git -C "$SRC_DIR" fetch --quiet origin "$BRANCH" || { fail "git fetch failed"; return 1; }
  local commit deployed
  commit=$(git -C "$SRC_DIR" rev-parse --short=12 FETCH_HEAD) || return 1
  deployed=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE:local" 2>/dev/null)

  if [ "$commit" = "$deployed" ] && [ $force = 0 ]; then
    [ $check = 1 ] && echo "up to date ($commit)"
    return 0
  fi
  if [ $check = 1 ]; then
    echo "update available: ${deployed:-nothing deployed} -> $commit"
    return 0
  fi
  if [ $force = 0 ] && [ "$(cat "$STATE_DIR/failed" 2>/dev/null)" = "$commit" ]; then
    return 0 # this commit failed before; wait for the next one (or --force)
  fi

  git -C "$SRC_DIR" checkout --quiet --force --detach FETCH_HEAD && git -C "$SRC_DIR" clean -qfdx ||
    { fail "git checkout failed"; return 1; }
  local commit_time version
  commit_time=$(git -C "$SRC_DIR" log -1 --format=%ct)
  version=$(git -C "$SRC_DIR" describe --tags --match 'v[0-9]*' 2>/dev/null) ||
    version="0.0.0-$(date -u -d "@$commit_time" +%Y%m%d%H%M%S).${commit:0:7}"

  log "building $IMAGE:$commit ($version), currently deployed: ${deployed:-none}"
  if ! docker build --pull --progress=plain -t "$IMAGE:$commit" \
    --build-arg VERSION="$version" --build-arg COMMIT="$commit" --build-arg COMMIT_TIME="$commit_time" \
    "$SRC_DIR" >"$STATE_DIR/build.log" 2>&1; then
    echo "$commit" >"$STATE_DIR/failed"
    fail "build of $commit failed; see $STATE_DIR/build.log"
    return 1
  fi

  local sig
  sig=$(sign_release "$IMAGE:$commit") || sig=""

  local new_id prev_id
  new_id=$(docker image inspect -f '{{.Id}}' "$IMAGE:$commit")
  prev_id=$(docker image inspect -f '{{.Id}}' "$IMAGE:local" 2>/dev/null)
  [ -n "$prev_id" ] && docker tag "$prev_id" "$IMAGE:previous"
  docker tag "$new_id" "$IMAGE:local"
  log "deploying $version"
  compose up -d --no-build --no-deps "$SERVICE" >>"$STATE_DIR/build.log" 2>&1

  if ! wait_healthy "$new_id"; then
    echo "$commit" >"$STATE_DIR/failed"
    [ -n "$sig" ] && rm -f "$sig" # never offer agents a release whose server was rolled back
    if [ -n "$prev_id" ]; then
      docker tag "$prev_id" "$IMAGE:local"
      compose up -d --no-build --no-deps "$SERVICE" >>"$STATE_DIR/build.log" 2>&1
      wait_healthy "$prev_id" && log "rolled back to the previous image"
    fi
    fail "$version did not become healthy within ${HEALTH_TIMEOUT}s; rolled back"
    return 1
  fi
  rm -f "$STATE_DIR/failed"
  echo "$commit $version $(date -u +%FT%TZ)" >>"$STATE_DIR/history"
  log "deployed $version ($commit)${sig:+, agent release signed}"
  [ "${NOTIFY_SUCCESS:-1}" = 1 ] && notify "HomeXDR updated" "Server and bundled agents are now $version" normal
  prune_images

  # Keep this updater current too. Safe while running: bash has already read main().
  local repo_copy="$SRC_DIR/deploy/update/homexdr-update.sh"
  if [ -f "$repo_copy" ] && ! cmp -s "$repo_copy" "$SCRIPT"; then
    cp "$repo_copy" "$SCRIPT.new" && mv "$SCRIPT.new" "$SCRIPT" && log "updated $SCRIPT from the repository"
  fi
  return 0
}

main "$@"; exit $?
