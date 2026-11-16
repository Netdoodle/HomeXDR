# Agents away from home

Laptops keep reporting, and keep taking response actions, when they leave the home
network. The console stays on the local network; only the agent API is published, on a
second listener that accepts nothing but enrolled agents.

## How it is protected

The server runs two agent listeners:

| Listener | Setting | Who can connect | What it serves |
|---|---|---|---|
| Local | `HOMEXDR_AGENT_ADDR` (`:8443`) | Anyone on the network | Everything: enrollment, installer scripts, the CA certificate, agent routes |
| Internet | `HOMEXDR_AGENT_EXTERNAL_ADDR` (for example `:8444`) | Enrolled agents only | Reports, commands, certificate renewal, agent updates |

On the internet listener:

- **The TLS handshake requires an agent certificate.** It must be issued by the server's
  own CA for client authentication and still be valid, and the agent it names must exist
  and not be revoked. Anything else is dropped before HTTP, so a scanner sees a TLS server
  that ends every connection and nothing more.
- **Holding the certificate is not enough.** The handshake proves the client has the
  certificate's private key, which is created on the device at enrollment and never leaves
  it.
- **Only TLS 1.3**, and at most 512 open connections.
- **Enrollment, the installer scripts and the CA certificate do not exist there.** Enroll
  devices at home. A leaked enrollment token cannot be used from the internet.
- **Revoking a host** in the console stops its connections at the next handshake.

Agents pin the server's CA, so a proxy or a fake server with a publicly trusted certificate
is refused in the other direction too. That also means the port cannot sit behind a
reverse proxy or a tunnel that ends TLS: forward it as plain TCP.

Agents renew their certificate when a third of its life is left (about four months before
it expires), over either listener. An agent whose certificate has already expired can only
renew from home.

## Setting it up

The agent has one server address, so it must work both at home and away. Use one name with
split DNS and the same port number on both sides:

1. **Pick a name**, for example `xdr.example.com`.
2. **Public DNS:** point it at your WAN address (DNS only, not proxied).
3. **Local DNS:** override it to the server's LAN address.
4. **Server settings** (`.env`):
   ```
   HOMEXDR_SERVER_NAMES=xdr.example.com,192.168.1.50
   HOMEXDR_AGENT_URL=https://xdr.example.com:8443
   HOMEXDR_AGENT_EXTERNAL_ADDR=:8444
   ```
   Changing the names re-issues the server certificate; agents trust the CA, so they
   accept it.
5. **Port forward:** WAN TCP 8443 to the server's port 8444. Inside, the name resolves to
   the server and port 8443 reaches the local listener; outside, port 8443 on the WAN
   address reaches the internet listener.
6. **Agents:** new agents enroll with the agent URL above. Existing ones need `server_url`
   in their `agent.json` changed to it, then a restart.

Check it from outside (a phone hotspot): `curl -v https://xdr.example.com:8443/` should fail
in the TLS handshake, and the host page should keep showing the laptop as online.

## Watching it

**Host page.** Each host shows a "Last address", for example `203.0.113.5 (internet
listener)` or `192.168.1.42 (local network)`: the address the agent's last heartbeat came
from and which listener it reached. A laptop that shows the internet listener is away
from home. The Revoke button beside it is the same one as under Danger zone.

**Refused connections.** Every scanner that finds the internet listener fails the TLS
handshake. That is normal and is not alerted one by one; the server only counts them.
When the internet listener is on, Data health has an "Internet agent listener" section
with the refused connections this hour, in the last full hour and in the last 24 hours,
and the top five source addresses over 24 hours. The counts are kept in memory, in hourly
buckets, so they start again at zero when the server restarts.

**Alert.** The server raises a medium alert, "Many refused connections on the internet
agent listener", when the last full hour had at least 50 refused connections and at least
three times the average hourly count of the 23 hours before it. The details give the
count, the average and the top sources. It is raised at most once every 6 hours. A steady
level of noise, however high, does not trigger it; a sudden rise does.
