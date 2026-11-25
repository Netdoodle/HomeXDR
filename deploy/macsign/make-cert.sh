#!/bin/sh
# Creates the self-signed code signing identity for the macOS agent: macsign.p12 (+ password
# file) in the given folder. Keep it with release-signing.key and back it up: replacing it
# changes the signature's requirement, so macOS asks for Full Disk Access again once.
# usage: make-cert.sh <dir>
set -eu
dir=${1:?usage: make-cert.sh <dir>}
[ -s "$dir/macsign.p12" ] && exit 0
mkdir -p "$dir"
umask 077
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/o.cnf" <<CNF
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=HomeXDR macOS agent
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
CNF
openssl req -x509 -newkey rsa:3072 -nodes -days 7300 -config "$tmp/o.cnf" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
openssl rand -hex 16 >"$dir/macsign.pass"
openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -out "$dir/macsign.p12" \
  -passout "file:$dir/macsign.pass"
