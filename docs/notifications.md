# Notifications

Locked mode (Linux). The daemon can tell you when something needs a person: an
approval waits, a limit is hit, the audit chain is broken, lockdown changes. It
sends to a webhook, an SMTP server or a local command. Sending never delays or
blocks the request that caused it.

## Config

In `/etc/saiife/config.toml`:

```toml
[notify]
# Which events are sent. All six when this line is absent.
on = ["approval_created", "limit_reached", "error_denied_burst", "chain_break", "lockdown"]

# A webhook: the URL is https, and may hold a token, so it can live in the vault.
[notify.targets.chat]
type = "webhook"
url_secret = "notify-chat-url"   # a vault secret holding the URL
# url = "https://hooks.example.com/saiife"   # or the URL itself, but not both

# Mail: implicit TLS on 465, STARTTLS on 587 or 25. The secret has kind basic.
[notify.targets.mail]
type = "smtp"
host = "smtp.example.com"
port = 587
from = "saiife@example.com"
to = ["ops@example.com"]
secret = "notify-smtp"

# A program: root-owned, in a root-owned directory chain.
[notify.targets.pager]
type = "command"
path = "/usr/local/libexec/saiife-page"
```

- A webhook gets a JSON `POST` (below). A plain `http://` URL is refused.
- SMTP is a small built-in client: `AUTH PLAIN` only, over TLS. Mail over a
  plain connection is refused. Each step has a 10 second limit.
- A command is run without a shell, with no arguments, an empty environment
  and `/` as its working directory. It gets the event as one line of the same
  JSON on its standard input (below). It must be owned by root, not
  writable by group or others, not a symlink, and so must each directory
  above it. It has 10 seconds, and is ended (with anything it started) after
  that.
- A mail has the subject `[saiife] <event>` and a plain-text body with one
  `field: value` line per field.

The webhook body (and the command's standard input):

```json
{"event": "approval_created", "id": 42, "service": "erp",
 "operation": "invoices.create", "uid": 1001, "host": "build-3",
 "summary": "approval #42 needed: erp invoices.create"}
```

Fields that do not apply (`id` for a lockdown, `service` for a chain break) are
left out.

## Events

| Event | Sent when |
|-------|-----------|
| `approval_created` | a new approval request is made (not when the same command is asked again) |
| `limit_reached` | a connector call hits a limit; the first per window for each user, service and limit |
| `error_denied_burst` | 10 or more `error_denied` guard records from one user within 60 seconds; at most once per user per 10 minutes |
| `chain_break` | the daemon's check of the audit chain at start fails |
| `forward_failing` | defined for audit-log forwarding; nothing sends it yet |
| `lockdown` | lockdown is turned on or off |

`limit_reached` is sent once per window for each user, service and limit. The
window is the limit's own: 60 seconds for `requests_per_minute`,
`amount_per_request` and the other limit errors without a period; 1 hour for
`writes_per_hour`; 1 day for `deletes_per_day`, `amount_per_day` and
`bulk_per_session`. It is also sent when a limit stops an approved request at
send time.

## Rate limits

- At most one send per target per kind of event in 60 seconds, except
  `approval_created`, which is always sent.
- The daemon holds at most 256 unsent events. When more come, the oldest is
  dropped and counted.
- A failed send is tried once more at once, and then given up.
- Every outcome is a `notify` record in the audit log: `sent`, `failed` or
  `dropped`. A failure never blocks the request that caused it.

## What is never sent

A notification carries the event, the request id, the service, the operation,
the user id, the host, and a one-line summary that is masked and at most 200
characters. It never carries request parameters, bodies, headers, results,
credentials, or a link that approves anything. For a command request the
summary names only the rule that asked (`command request (core.git/force-push)`),
never the command text. To approve, a person runs
`saiife approve` on the machine, and has to be an approver there.
