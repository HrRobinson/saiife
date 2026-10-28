# Linear connector

The `linear` connector reaches the Linear GraphQL API through `saiifed`. The
agent never sees the API key and never sends GraphQL: every operation is a
fixed document in the manifest (`crates/broker/connectors/linear.toml`), and
the agent supplies variables only.

- Base URL `https://api.linear.app`, the only host the connector may call.
- Auth: `header` `Authorization` with the raw personal API key (no `Bearer`
  prefix). The vault entry is a `token` secret.
- Every operation is `POST /graphql`. `/v1/proxy` cannot reach them
  (`unknown_operation`); use `saiife api linear <operation> k=v` or `/v1/api`.
- Vendor reference: <https://linear.app/developers/graphql>,
  <https://linear.app/developers/pagination>.

## Operations

| Operation | Capability | Qualifier | Variables |
|---|---|---|---|
| `teams.list` | `teams:read` | | `first` (1..100), `after` |
| `issues.list` | `issues:read` | `team={team}` | `team` (the team key, such as `ENG`), `first`, `after` |
| `issues.get` | `issues:read` | | `id` (a UUID or an identifier such as `ENG-101`) |
| `issues.create` | `issues:write` | `team={team_id}` | `team_id`, `title`, `description` |
| `issues.comment` | `issues:write` | | `issue_id`, `body` |

A variable value is always a JSON string or number in `variables`; it can
never change the document. There is no update, delete, archive, search or
project operation. A call that matches no operation is denied as
`unknown_operation`.

A GraphQL answer can be HTTP 200 with an `errors` array. saiife passes it on
as the vendor sent it.

## Pagination

`teams.list` and `issues.list` return `data.<root>.pageInfo`. saiife returns
`next` as `after=<endCursor>` while `hasNextPage` is true; the last page has
no `next`. The cursor is a body variable, so pass it back as `after=<cursor>`.

```bash
saiife api linear issues.list team=ENG first=50
saiife api linear issues.list team=ENG first=50 after=<cursor>
saiife api linear issues.create team_id=<team uuid> title="Crash on save"
```

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny. A
qualified `allow` such as `issues:read:team=ENG` never matches a call without
the qualifier. `issues.list` requires `team`, so an unqualified call is
refused by Linear (`team` is a required variable) and by a qualified rule.
`issues.create` is qualified by the team id (a UUID), not the key.

## Suggested policy: read-only

```toml
[services.linear]
connector = "linear"
secret = "linear-main"
allow = ["teams:read", "issues:read"]
```

## Suggested policy: every write under `ask`

```toml
[services.linear]
connector = "linear"
secret = "linear-main"
allow = ["teams:read", "issues:read"]
ask   = ["issues:write"]
```

To open reads on one team only, use `allow = ["teams:read", "issues:read:team=ENG"]`.
`issues.get` has no team qualifier, so that policy denies it; allow
`issues:read` instead when `issues.get` is needed.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s`. Redirects go to the same host only.
- Per-service `limits` count requests that were sent upstream. Linear's own
  complexity and rate limits come back as errors in the answer.
- The key is masked (raw, base64, URL-encoded and hex) in every response.

## Locked mode

In locked mode (Linux) the agent reaches Linear only through `saiifed`. The
key lives in the daemon's vault (`saiife secret add linear-main`) and never
reaches the agent's environment, files or audit records. A project overlay can
only add `deny` and `ask`. Every call is one `connector` audit record. On
macOS the commands print `saiife: locked mode needs Linux in this version
(macOS: v2.1)` and exit 5.

Use a personal API key with the narrowest scope Linear offers (read for a
read-only policy), so a policy mistake is bounded by the key.
