package agentapi

import (
	"net/http"
	"strings"
)

// unixInstall installs the agent on Linux and macOS (served as linux.sh and macos.sh). It verifies the server's CA against the pin
// before downloading anything else, so the binary is fetched over a verified TLS
// connection. Fetching this script itself with `curl -k` is the one unverified step; to
// avoid it, download the script once and review it, or copy the agent binary manually.
const unixInstall = `#!/bin/sh
# HomeXDR agent installer for Linux and macOS.
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
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS $(uname -s)" ;;
esac
if command -v sha256sum >/dev/null; then SHA="sha256sum"
elif command -v shasum >/dev/null; then SHA="shasum -a 256"
else die "sha256sum or shasum is required"; fi
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [ "$OS" = darwin ]; then
  MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
  [ "$MAJOR" -ge 13 ] 2>/dev/null || echo "homexdr: macOS $(sw_vers -productVersion) has no eslogger; the agent will poll instead (macOS 13 or later recommended)" >&2
fi
BIN="homexdr-agent-$OS-$ARCH"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Fetch the CA and check it against the pin.
curl -fsSLk "$SERVER/v1/ca.crt" -o "$TMP/ca.crt" || die "cannot reach $SERVER"
GOT="sha256:$(openssl x509 -in "$TMP/ca.crt" -outform der | $SHA | cut -d' ' -f1)"
[ "$GOT" = "$PIN" ] || die "CA pin mismatch: server presented $GOT"

# 2. Download the agent over verified TLS and check its checksum.
curl -fsSL --cacert "$TMP/ca.crt" "$SERVER/v1/download/$BIN" -o "$TMP/$BIN" || die "download failed"
curl -fsSL --cacert "$TMP/ca.crt" "$SERVER/v1/download/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "checksum download failed"
(cd "$TMP" && grep " $BIN\$" SHA256SUMS | $SHA -c - >/dev/null) || die "checksum mismatch"

# 3. Install, enroll and start the service.
mkdir -p /usr/local/bin
install -m 0755 "$TMP/$BIN" /usr/local/bin/homexdr-agent
set -- install --server "$SERVER" --token "$TOKEN" --ca-pin "$PIN"
[ -n "$LABELS" ] && set -- "$@" --labels "$LABELS"
[ -n "$UPDATE_KEY" ] && set -- "$@" --update-key "$UPDATE_KEY"
/usr/local/bin/homexdr-agent "$@"
echo "homexdr: agent installed and enrolled"
if [ "$OS" = darwin ]; then
  echo "homexdr: now give /usr/local/bin/homexdr-agent Full Disk Access (System Settings > Privacy & Security >"
  echo "homexdr: Full Disk Access, +, then Cmd-Shift-G to type the path) and restart it with:"
  echo "homexdr:   sudo launchctl kickstart -k system/com.homexdr.agent"
fi
`

func (h *Handler) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(unixInstall, "__SERVER__", shellSafe(h.c.Cfg.AgentURL), 1)))
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
