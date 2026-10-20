package agentapi

import (
	"net/http"
	"strings"
)

// linuxInstall installs the agent on Linux. It verifies the server's CA against the pin
// before downloading anything else, so the binary is fetched over a verified TLS
// connection. Fetching this script itself with `curl -k` is the one unverified step; to
// avoid it, download the script once and review it, or copy the agent binary manually.
const linuxInstall = `#!/bin/sh
# HomeXDR agent installer for Linux.
#   sh install.sh --token <enrollment token> --ca-pin sha256:<hex> [--labels a,b]
#                 [--update-key ed25519:<base64>]   enable signed automatic updates
set -eu
SERVER="__SERVER__"
TOKEN=""
PIN=""
LABELS=""
UPDATE_KEY=""
die() { echo "homexdr: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --ca-pin) PIN="$2"; shift 2 ;;
    --labels) LABELS="$2"; shift 2 ;;
    --update-key) UPDATE_KEY="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$TOKEN" ] || die "--token is required"
[ -n "$PIN" ] || die "--ca-pin is required"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh ...)"
command -v curl >/dev/null || die "curl is required"
command -v openssl >/dev/null || die "openssl is required to verify the server certificate"
command -v sha256sum >/dev/null || die "sha256sum is required"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
BIN="homexdr-agent-linux-$ARCH"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Fetch the CA and check it against the pin.
curl -fsSLk "$SERVER/v1/ca.crt" -o "$TMP/ca.crt" || die "cannot reach $SERVER"
GOT="sha256:$(openssl x509 -in "$TMP/ca.crt" -outform der | sha256sum | cut -d' ' -f1)"
[ "$GOT" = "$PIN" ] || die "CA pin mismatch: server presented $GOT"

# 2. Download the agent over verified TLS and check its checksum.
curl -fsSL --cacert "$TMP/ca.crt" "$SERVER/v1/download/$BIN" -o "$TMP/$BIN" || die "download failed"
curl -fsSL --cacert "$TMP/ca.crt" "$SERVER/v1/download/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "checksum download failed"
(cd "$TMP" && grep " $BIN\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch"

# 3. Install, enroll and start the service.
install -m 0755 "$TMP/$BIN" /usr/local/bin/homexdr-agent
set -- install --server "$SERVER" --token "$TOKEN" --ca-pin "$PIN"
[ -n "$LABELS" ] && set -- "$@" --labels "$LABELS"
[ -n "$UPDATE_KEY" ] && set -- "$@" --update-key "$UPDATE_KEY"
/usr/local/bin/homexdr-agent "$@"
echo "homexdr: agent installed and enrolled"
`

func (h *Handler) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(linuxInstall, "__SERVER__", shellSafe(h.c.Cfg.AgentURL), 1)))
}

func (h *Handler) caCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(h.c.PKI.CAPEM)
}

// shellSafe keeps only characters that are safe inside a double-quoted shell string.
func shellSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case strings.ContainsRune(":/.-_[]", r):
			return r
		}
		return -1
	}, s)
}
