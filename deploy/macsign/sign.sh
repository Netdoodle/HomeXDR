#!/bin/sh
# Signs the darwin agent builds in a Docker build, with the patched quill (quill-pin-leaf.patch).
# Secrets (BuildKit): macsign_p12 and macsign_pass. Without them the builds stay ad-hoc
# signed (the Go linker's signature), which macOS treats as a new program on every update.
# usage: sign.sh <identifier> <binary>...
set -eu
id=$1; shift
p12=/run/secrets/macsign_p12
if [ ! -s "$p12" ]; then
  echo "macsign: no certificate, leaving the macOS agents ad-hoc signed"
  exit 0
fi
export QUILL_SIGN_PASSWORD="$(cat /run/secrets/macsign_pass 2>/dev/null || true)"
export QUILL_SIGN_FAIL_WITHOUT_FULL_CHAIN=false # self-signed: there is no chain to Apple
for f in "$@"; do
  quill sign "$f" --p12 "$p12" --identity "$id" --timestamp-server "" </dev/null >/dev/null 2>&1 ||
    { echo "macsign: quill failed on $f" >&2; exit 1; }
  # quill exits 0 even when it could not sign, so look at the result: the code signature
  # must carry the identifier and a certificate.
  d=$(quill describe "$f" </dev/null 2>&1)
  echo "$d" | grep -q "ID: *$id\$" && echo "$d" | grep -q "Certificate 1:" ||
    { echo "macsign: $f was not signed as $id" >&2; exit 1; }
done
echo "macsign: signed $# agent(s) as $id"
