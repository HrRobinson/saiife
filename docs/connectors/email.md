# Email connector

Connector id `email`, SMTP send and IMAP read, built into `saiife-broker`
(`crates/broker/connectors/email.toml`). It uses the broker's mail transport,
not HTTPS, so there is no proxy path: only the four named operations work.
The service starts with everything denied: each capability below needs an
`allow` (or `ask`) entry in the policy.

## Setup

```sh
saiife secret add mailbox --kind basic --service email   # mailbox user name and password
```

The user name and password (or an app password) go out only in the SMTP
`AUTH PLAIN` or the IMAP `AUTHENTICATE PLAIN` exchange, after TLS. The admin
sets the server parameters in the service config; the agent cannot:

| Parameter | Meaning |
|---|---|
| `smtp_host` (required) | SMTP server, a bare lower-case host name |
| `smtp_port` | default 465 (implicit TLS) or 587 (STARTTLS) |
| `smtp_tls` | `implicit` (default) or `starttls` (required, never optional) |
| `imap_host` (required) | IMAP server, a bare lower-case host name |
| `imap_port` | default 993 (implicit TLS) or 143 (STARTTLS) |
| `imap_tls` | `implicit` (default) or `starttls` |
| `from` (required) | the sender address of every message |

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `mail.send` | `mail:write` | write | SMTP; params `to` (one address) and `subject`; the body is plain UTF-8 text, at most 256 KiB |
| `folders.list` | `folders:read` | read | IMAP `LIST` |
| `mail.list` | `mail:read` | read | params `folder`, `since`, `unseen`, `limit` (1..100), `before_uid` |
| `mail.get` | `mail:read` | read | params `folder`, `uid`; text, html, and attachment names, types and sizes (never attachment content) |

Notes:

- **One recipient per call.** `to` is a single address, so a rule such as
  `when = { to = "*@acme.com" }` and the qualifier `to=<address>` cover every
  recipient. The sender is the admin's `from`.
- **Reads never change the mailbox.** Folders are opened with `EXAMINE`
  (read-only) and messages are fetched with `BODY.PEEK`, so the `\Seen` flag is
  not set. There is no delete, move or flag operation.
- **Pagination.** `mail.list` returns the newest messages first. While more
  may remain, the answer holds `next_before_uid`; pass it as `before_uid` for
  the next page.
- `since` uses only its date part, because IMAP compares dates.

## Suggested policy: read-only

`/etc/saiife/policy.d/email.toml`:

```toml
[services.email]
connector = "email"
secret = "mailbox"
params = { smtp_host = "smtp.acme.com", imap_host = "imap.acme.com", from = "bot@acme.com" }
allow = ["mail:read", "folders:read"]

[services.email.limits]
requests_per_minute = 30
```

## Suggested policy: every write under `ask`

```toml
[services.email]
connector = "email"
secret = "mailbox"
params = { smtp_host = "smtp.acme.com", imap_host = "imap.acme.com", from = "bot@acme.com" }
allow = ["mail:read", "folders:read"]
ask   = ["mail:write"]

[services.email.limits]
requests_per_minute = 30
writes_per_hour = 10
```

## Sending to one domain only

To let the agent write to your own domain and refuse every other recipient:

```toml
[services.email]
connector = "email"
secret = "mailbox"
params = { smtp_host = "smtp.acme.com", imap_host = "imap.acme.com", from = "bot@acme.com" }
allow = ["mail:read", "folders:read"]

[[services.email.rule]]
capability = "mail:write"
when = { to = "*@acme.com" }
action = "allow"
```

Notes on matching:

- The recipient is checked strictly: a domain of proper labels (no empty
  label, no trailing dot, no leading or trailing `-`), and no `%` or `!` in
  the local part.
- The domain of `to` is lower-cased before the rule looks, so `A@ACME.COM`
  matches `*@acme.com`. Apart from that, `when` matching is case-sensitive:
  the local part keeps its case, so write patterns for the case you expect.
- If `mail:write` is also under `ask`, every send is asked about, matching
  rule or not: `ask` is the stricter verdict.
- An omitted `folder` is `INBOX` before the policy decides, so a rule on
  `folder=INBOX` also covers calls that leave it out.

## Limits

- Sends count toward `writes_per_hour`; set it. A mailbox that can send is a
  spam relay if a policy lets it.
- The server's own limits are separate; a refusal comes back as an upstream
  failure with a short, masked reason.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the mailbox
password lives in the root-owned vault and never reaches the agent; calls go
through the gateway, which adds it. A project config can add `deny` and `ask`
entries but cannot add an `allow` or change the secret, the hosts or `from`.

- **The password is vault-only.** There is no mask shape for a mailbox
  password, so it is protected by staying in the vault and by exact-value
  masking of every answer, record and error.
- **Prefer a dedicated mailbox** (or an app password) for the agent, not a
  person's mailbox. Whatever the account can read, the agent can read.
- **Reads use `EXAMINE`**: nothing is marked as read, deleted or moved.
- **One recipient per call**, so allow rules can name the recipient.
- To keep addresses away from the model, redact the sender and recipient
  fields:

  ```toml
  [services.email.redact]
  fields = ["*.from", "*.to"]
  ```

Use `saiife api email mail.list folder=INBOX limit=20`, or the gateway at
`/v1/api`; the exit codes are those of `saiife api` (2 denied, 4 limit
reached).
