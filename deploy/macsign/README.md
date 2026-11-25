# macOS agent signing

macOS ties a program's Full Disk Access to its code identity. The Go linker's ad-hoc
signature (`Identifier=a.out`, requirement = the exact build hash) makes every update a new
program, so Apple silicon Macs lose the grant after each update. Signing every build with one
certificate and one identifier (`com.homexdr.agent`) keeps it.

The Docker build does this when it is given the BuildKit secrets `macsign_p12` and
`macsign_pass`; without them the agents stay ad-hoc signed and the build still succeeds.

```sh
docker build --secret id=macsign_p12,src=macsign.p12 --secret id=macsign_pass,src=macsign.pass -t homexdr/server .
```

- `make-cert.sh <dir>`: creates a self-signed code signing certificate (`macsign.p12`,
  `macsign.pass`), valid for 20 years. `deploy/update/homexdr-update.sh` runs it on the build
  host. A project that publishes images (CI) keeps the certificate in a secret instead.
- `sign.sh`: signs the darwin builds with [quill](https://github.com/anchore/quill) and
  checks the result (quill exits 0 even when it did not sign).
- `quill-pin-leaf.patch`: quill v0.7.1 writes the designated requirement as
  `identifier "x"` only. macOS stores that requirement when Full Disk Access is granted, and
  then accepts any program claiming the identifier, even an ad-hoc signed one. The patch adds
  `certificate leaf = H"<sha1>"` for non-Apple certificates, so only builds signed with the
  certificate match. The Dockerfile applies it when it builds quill.

Tested on an M3 Mac (macOS 27): builds swapped at one path kept Full Disk Access, and an
ad-hoc binary with the same identifier was refused.

Replacing the certificate, or going from ad-hoc to signed builds, makes macOS ask for Full
Disk Access once more. Hosts that share one image must share the certificate; two servers
with different certificates give agents that move between them one more prompt.
