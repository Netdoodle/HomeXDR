# Notifications and the daily digest

HomeXDR can tell you about alerts on your phone, in a chat or by mail, and send a summary once
a day. It is off until you add a channel under **Settings > Notifications**. You need the admin
role.

## Channels

| Channel | What you need |
|---|---|
| ntfy | A topic URL, such as `https://ntfy.sh/a-long-random-topic`, on ntfy.sh or your own server. Optional bearer token. |
| Discord | A webhook URL, from the channel's settings under Integrations. |
| Email | An SMTP server that offers STARTTLS, plus From and To addresses. Optional username and password. HomeXDR refuses to send mail if the server does not offer STARTTLS, and it checks the server's certificate. |
| Webhook | Any URL. It gets a JSON POST for each message. Optional bearer token. |

URLs, tokens and passwords are write-only. The API and the logs never show them, only whether
one is set. Error messages have them removed.

**Send test** sends a message straight away and shows the result. It tests what is saved, so
save your changes first.

A webhook message looks like this:

```json
{
  "kind": "alert",
  "title": "[HIGH] Wget to tmp on tower",
  "body": "Severity: high\nRule: Wget to tmp\n...",
  "severity": "high",
  "rule_id": "...",
  "alert_id": "...",
  "link": "https://xdr.example.com/alerts/..."
}
```

`kind` is `alert`, `digest`, `notice` (about notifications themselves) or `test`.

## Routing

Each new alert goes to one of three places:

| Route | Meaning |
|---|---|
| Alert now | Sent to every enabled channel straight away. |
| Daily digest | Counted in the next digest. |
| Log only | Stays in the console. The digest shows only a total. |

| Severity | Default |
|---|---|
| Critical, high | Alert now |
| Medium | Daily digest |
| Low, informational | Log only |

**Exceptions by rule ID** override this. `health:` matches every rule ID that starts with it,
and `net:new-device` matches that one. The longest match wins.

Only a new alert notifies. A repeat that folds into an open alert does not, and suppressed
alerts never do. See [alerts.md](alerts.md).

## Rate cap

At most 10 alerts an hour go out straight away (you can change this). Past that, alerts go to
the digest, which says how many, and you get one message saying the limit was reached. That
message means a flood cannot melt your phone, but it also cannot go unnoticed until morning.
The cap counts alerts, not channels, and it applies to critical alerts too.

## The daily digest

Sent once a day at the time you pick. If you leave the time zone blank it uses the server's,
and in a container that is often UTC, so set a name like `Europe/Prague`.

It covers what happened since the last one:

- alerts by severity, and by rule,
- how many alerts went over the rate cap,
- the top repeating shapes,
- how many hits were suppressed,
- what the AI analyst said, with the alerts it did not call benign,
- sections other features add.

If nothing at all happened, no digest is sent, unless you turn on **Send it even when there is
nothing to say**. Then silence never means something is broken. A digest missed while the
server was down goes out when it comes back. The first one comes at the next scheduled time
after you add a channel.

## Delivery

Sending never holds up ingest. A new alert only adds a row to an outbox in the state database,
and a background loop does the sending, so messages survive a restart.

A failed message is retried after 30 seconds, then with the wait doubling up to an hour, for 9
tries in all (about four hours). After that it is marked as failed. **Delivery status** shows
what is waiting, what was sent, and the latest errors. A message for a channel you removed or
turned off is dropped, and so is one for an alert that was suppressed while it waited. Finished
messages are deleted after 30 days.

## Safety

Alert content comes from monitored systems, so an attacker may have written it. Before anything
is sent:

- Indicators are defanged: `hxxp`, `[://]` and `example[.]com`. Nothing from an alert becomes
  something you can tap. The only live link is the one to your own console, built from the
  **Console address** setting.
- Line breaks, control characters and invisible characters are removed, so a value cannot fake
  extra lines in a message or disguise itself. Long values are cut short.
- Discord markdown is escaped and mentions are off, so a value cannot ping `@everyone`.
- Webhook redirects are not followed.

The AI analyst has no part in any of this.

## For developers: adding to the digest

Other features can add a section once, at startup:

```go
c.Notify.AddDigestSection("Feed health", func(ctx context.Context, since time.Time) ([]string, error) {
    return []string{"Unbound has been silent for 3 hours"}, nil
})
```

Return no lines to leave the section out. A section with lines counts as something to say. A
section that returns an error is logged and left out of that digest. Lines are cleaned and
defanged when the digest is built.
