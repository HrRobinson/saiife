# Discord connector

Connector id `discord`, Discord API v10, built into `saiife-broker`
(`crates/broker/connectors/discord.toml`). The service starts with everything
denied: each capability below needs an `allow` (or `ask`) entry in the policy.

Endpoints follow the Discord developer reference
(<https://discord.com/developers/docs/resources/message>). This page and the
test fixtures were written offline, in the documented shape; check them
against the reference when Discord changes the API.

## Setup

```sh
saiife secret add discord-bot --kind token --service discord   # the bot token
```

The token goes out only in the header `Authorization: Bot <token>`. Requests go
only to `discord.com`. The bot needs the permissions you allow here (View
Channel, Read Message History, Send Messages).

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `guilds.channels` | `channels:read` (`guild=<id>`) | read | `GET /guilds/{guild_id}/channels` |
| `channels.get` | `channels:read` (`channel=<id>`) | read | `GET /channels/{channel_id}` |
| `messages.list` | `messages:read` (`channel=<id>`) | read | `GET /channels/{channel_id}/messages`; query `limit`, `before`, `after` |
| `messages.create` | `messages:write` (`channel=<id>`) | write | `POST /channels/{channel_id}/messages`, built JSON body `content` |

Notes:

- Ids are snowflakes: 1 to 20 digits. `limit`, `before` and `after` are
  digits too.
- **Channels and guilds are qualifiers**, so a rule can name them:
  `messages:write:channel=1100000000000000001`.
- **`messages.create`** takes `content` (1 to 2000 characters, line breaks
  allowed). The agent cannot send a body of its own, and the broker adds
  `"allowed_mentions": {"parse": []}`: the message pings nobody, so an agent
  cannot send `@everyone`, `@here` or a notifying role or user mention.
- **Pagination:** the list has no `next` field. Pass the id of the last (the
  oldest) message as `before=<id>` for the next page; the page size is `limit`
  (Discord allows 1 to 100).
- Agents may send `Accept`; every other request header is dropped.

## Suggested policy: read-only

`/etc/saiife/policy.d/discord.toml`:

```toml
[services.discord]
connector = "discord"
secret = "discord-bot"
allow = ["channels:read", "messages:read"]
deny  = ["messages:write"]

[services.discord.limits]
requests_per_minute = 50
```

## Suggested policy: every write under `ask`

```toml
[services.discord]
connector = "discord"
secret = "discord-bot"
allow = ["channels:read", "messages:read"]
ask   = ["messages:write"]

[services.discord.limits]
requests_per_minute = 50
writes_per_hour = 30
```

To limit the agent to one channel, replace `messages:read` with
`messages:read:channel=1100000000000000001`, and allow `messages:write` the
same way if it may post unattended. A call for any other channel is then
denied. Likewise `channels:read:guild=<id>` names a guild.

## Limits

- Writes count toward `writes_per_hour`. No operation has an amount.
- Discord's own rate limits are per route and per channel; a `429` from
  Discord is passed on.
- At most 4 upstream calls to Discord are in flight at once.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the token
lives in the root-owned vault and never reaches the agent; calls go through
the gateway, which adds it. A project config can add `deny` and `ask` entries
but cannot add an `allow` or change the secret. Use `saiife api discord
messages.list channel_id=1100000000000000001 limit=20`, or the gateway at
`/v1/api`; the exit codes are those of `saiife api` (2 denied, 4 limit
reached).
