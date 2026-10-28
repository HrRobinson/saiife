# Slack connector

Connector id `slack`, the Slack Web API, built into `saiife-broker`
(`crates/broker/connectors/slack.toml`). The service starts with everything
denied: each capability below needs an `allow` (or `ask`) entry in the policy.

Methods follow the Slack API reference (<https://api.slack.com/methods>). This
page and the test fixtures were written offline, in the documented shape;
check them against the reference when Slack changes a method.

## Setup

```sh
saiife secret add slack-bot --kind token --service slack   # the bot token (xoxb-...)
```

Give the Slack app only the scopes you allow here (`channels:read`,
`channels:history`, `users:read`, `chat:write`, ...). The token goes out only
in the `Authorization: Bearer` header. Requests go only to `slack.com`.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `conversations.list` | `channels:read` | read | `GET /conversations.list`; query `limit`, `cursor`, `types`, `exclude_archived` |
| `conversations.history` | `messages:read` (`channel=<id>`) | read | `GET /conversations.history`; query `channel`, `limit`, `cursor`, `oldest`, `latest`, `inclusive` |
| `conversations.replies` | `messages:read` (`channel=<id>`) | read | `GET /conversations.replies`; query `channel`, `ts`, `limit`, `cursor` |
| `users.list` | `users:read` | read | `GET /users.list`; query `limit`, `cursor` |
| `users.info` | `users:read` | read | `GET /users.info`; query `user` |
| `chat.postMessage` | `messages:write` (`channel=<id>`) | write | `POST /chat.postMessage`, built JSON body `channel`, `text`, `thread_ts` |

Notes:

- **Errors are `200`.** Slack answers most errors as `200 {"ok": false,
  "error": "channel_not_found"}`. The broker passes the body on, so check
  `ok` in the response, not the exit code alone.
- **Channels are qualifiers.** `messages:read` and `messages:write` carry
  `channel=<id>`, so a rule can name channels: `messages:write:channel=C0123456789`.
  Channel ids are `C...`, `G...` or `D...` (upper-case letters and digits).
- **`chat.postMessage`** takes `channel`, `text` (1 to 4000 characters, line
  breaks allowed) and an optional `thread_ts` (`1700000000.000100`) to reply
  in a thread. The agent cannot send a body of its own, so no blocks,
  attachments or other fields.
- **Pagination** is a cursor: pass `response_metadata.next_cursor` back as
  `cursor`. An empty cursor is the last page.
- Slack text can contain `<!channel>` and `<!here>`, so a post can notify a whole channel. That is why `messages:write` belongs under `ask`.
- Agents may send `Accept`; every other request header is dropped.

## Suggested policy: read-only

`/etc/saiife/policy.d/slack.toml`:

```toml
[services.slack]
connector = "slack"
secret = "slack-bot"
allow = ["channels:read", "users:read", "messages:read"]
deny  = ["messages:write"]

[services.slack.limits]
requests_per_minute = 50

[services.slack.redact]
fields = ["profile.email", "profile.phone"]
```

`users:read` returns names and emails; drop it, or keep the `redact` fields,
if the agent does not need them.

## Suggested policy: every write under `ask`

```toml
[services.slack]
connector = "slack"
secret = "slack-bot"
allow = ["channels:read", "users:read", "messages:read"]
ask   = ["messages:write"]

[services.slack.limits]
requests_per_minute = 50
writes_per_hour = 30

[services.slack.redact]
fields = ["profile.email", "profile.phone"]
```

To limit the agent to one channel, replace `messages:read` with
`messages:read:channel=C0123456789` (and allow `messages:write` the same way
if it may post unattended). A call for any other channel is then denied. This
is a pattern on the qualifier, so it belongs in the policy you write, not in
the suggested blocks above, which name no channel.

## Limits

- Writes count toward `writes_per_hour`. No operation has an amount.
- Slack's own rate limits (about one message per second per channel for
  `chat.postMessage`, tiered limits for the rest) are separate; a `429` from
  Slack is passed on.
- At most 4 upstream calls to Slack are in flight at once.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the token
lives in the root-owned vault and never reaches the agent; calls go through
the gateway, which adds it. A project config can add `deny` and `ask` entries
but cannot add an `allow` or change the secret. Use `saiife api slack
conversations.history channel=C0123456789 limit=20`, or the gateway at
`/v1/api`; the exit codes are those of `saiife api` (2 denied, 4 limit
reached).
