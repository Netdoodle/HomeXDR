# HTTPS for the web console

By default the console listens on plain HTTP (port 8080), so passwords and session cookies
cross your network in clear text unless a reverse proxy adds TLS. The server can also serve
the console over HTTPS itself. It is optional and off by default.

## Turn it on

Set the HTTPS listen address in `.env` and recreate the container:

```
HOMEXDR_CONSOLE_HTTPS_ADDR=:8448
```

The compose files already publish `8448/tcp` (change the host port with
`HOMEXDR_CONSOLE_HTTPS_PORT`). Open `https://<server>:8448/`. The startup log says which
certificate is in use ("console HTTPS enabled").

With nothing else set, the console uses the server certificate issued by HomeXDR's own CA,
the same one the agent API uses. It covers the names in `HOMEXDR_SERVER_NAMES`, so use one of
those names in the browser address. Browsers do not know this CA, so install it first (below)
or accept the warning once. The session cookie is `Secure` on HTTPS requests. The server does
not send HSTS in this mode, so a browser that has not installed the CA is never locked out.

## Trust the HomeXDR CA

Download the certificate from the login page or Settings > My account ("Download the HomeXDR
CA certificate"), or fetch `http://<server>:8080/api/ca.crt`. It is a public certificate,
not a secret. Check that its fingerprint matches the CA pin in the server log if you want
to be sure it is the right one. Then:

- **Windows:** double-click the file > Install Certificate > Local Machine > "Place all
  certificates in the following store" > Trusted Root Certification Authorities. Restart the
  browser.
- **macOS:** open the file in Keychain Access (System keychain), double-click the certificate,
  expand Trust and set "When using this certificate" to Always Trust.
- **Linux:** Debian/Ubuntu: copy it to `/usr/local/share/ca-certificates/homexdr-ca.crt` and
  run `sudo update-ca-certificates`. Fedora: copy it to `/etc/pki/ca-trust/source/anchors/`
  and run `sudo update-ca-trust`. Firefox keeps its own store: Settings > Privacy & Security
  > Certificates > View Certificates > Authorities > Import. Chrome on Linux: Settings >
  Privacy and security > Security > Manage certificates > Authorities > Import.
- **iOS:** open the downloaded file in Safari and allow the profile, install it in Settings >
  General > VPN & Device Management, then enable full trust in Settings > General > About >
  Certificate Trust Settings.
- **Android:** Settings > Security > Encryption & credentials > Install a certificate > CA
  certificate, and pick the file. Some versions place this under "More security settings".

## Use your own certificate

For a certificate your browsers already trust (for example from certbot or acme.sh), point
the server at the PEM files. Both must be set, together with the HTTPS address:

```
HOMEXDR_CONSOLE_HTTPS_ADDR=:8448
HOMEXDR_CONSOLE_TLS_CERT=/certs/fullchain.pem
HOMEXDR_CONSOLE_TLS_KEY=/certs/privkey.pem
```

Mount the directory into the container, for example in a `docker-compose.override.yml`:

```yaml
services:
  homexdr:
    volumes:
      - /etc/letsencrypt/live/homexdr.example.com:/certs:ro
```

(With certbot the files in `live/` are links into `archive/`; mount `/etc/letsencrypt` and
point the variables at the `live/` paths inside it.)

The server fails to start if the files are set but invalid. While running, it checks the files'
modification time at most once a minute and loads a renewed certificate without a restart. If
a new file is bad, the previous certificate stays in use and a warning is logged. In this mode
responses carry `Strict-Transport-Security: max-age=15552000`.

## Redirect plain HTTP to HTTPS

```
HOMEXDR_CONSOLE_HTTP_REDIRECT=true
```

The plain HTTP listener then answers every request with a `308` redirect to the same host on
the HTTPS port, except `/healthz`. The container health check calls `/healthz` over plain
HTTP, so it keeps working. Only turn this on once HTTPS works for your browsers; the CA
download link on the login page is also redirected, so install the CA first.

The redirect points at the published HTTPS port (`HOMEXDR_CONSOLE_HTTPS_PORT` in the
compose files, passed to the server as `HOMEXDR_CONSOLE_HTTPS_PUBLIC_PORT`), so it works
when the container's ports are mapped to different numbers on the host.

Leave the redirect off when a reverse proxy reaches the console over plain HTTP: the proxy's
requests would be redirected too.
