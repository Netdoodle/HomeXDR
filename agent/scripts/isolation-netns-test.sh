#!/bin/bash
# Live test of host isolation on Linux, without touching the machine's own network.
#
# Creates a throwaway network namespace joined to the host namespace by a veth pair,
# starts two listeners on the host side (8443 = "server", 9999 = anything else), and runs
# TestIsolationLiveInNetns inside the namespace with the real nft/iptables binaries.
# Everything is removed on exit. Needs root, iproute2, nft or iptables, python3 and Go.
#
#   sudo agent/scripts/isolation-netns-test.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
cd "$(dirname "$0")/.."

NS="hxiso-$$"
HOST_IF="hxa$$"
NS_IF="hxb$$"
HOST_IP=10.199.0.1
NS_IP=10.199.0.2
TEST_BIN="$(mktemp -d)/linux.test"
PIDS=()

cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	ip netns delete "$NS" 2>/dev/null || true
	ip link delete "$HOST_IF" 2>/dev/null || true
	rm -rf "$(dirname "$TEST_BIN")"
}
trap cleanup EXIT

go test -c -o "$TEST_BIN" ./internal/platform/linux/

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up

for port in 8443 9999; do
	python3 -m http.server "$port" --bind "$HOST_IP" >/dev/null 2>&1 &
	PIDS+=($!)
done
sleep 1

for fw in nft iptables; do
	echo "== isolation with $fw"
	ip netns exec "$NS" env HOMEXDR_ISOLATION_LIVE=1 HOMEXDR_ISOLATION_SERVER="$HOST_IP" HOMEXDR_ISOLATION_FW="$fw" \
		"$TEST_BIN" -test.run 'TestIsolationLiveInNetns' -test.v -test.count=1
done
