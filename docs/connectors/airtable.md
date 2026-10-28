# Airtable connector

The `airtable` connector reaches the Airtable Web API (records) through
`saiifed`. The agent never sees the token. The manifest is
`crates/broker/connectors/airtable.toml`.

- Base URL `https://api.airtable.com/v0`, the only host the connector may call.
- Auth: `bearer`, a personal access token (a `token` secret).
- Vendor reference: <https://airtable.com/developers/web/api/introduction>.

## Operations

Every operation carries the qualifier `base={base_id}`, so
`saiife api airtable records.create base_id=app... table=Tasks` is the
capability `records:write:base=app...`, and a rule can scope writes to one base.

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `records.list` | `records:read` | read | `GET /{base_id}/{table}` |
| `records.get` | `records:read` | read | `GET /{base_id}/{table}/{record_id}` |
| `records.create` | `records:write` | write | `POST /{base_id}/{table}` |
| `records.update` | `records:write` | write | `PATCH /{base_id}/{table}/{record_id}` |
| `records.delete` | `records:delete` | delete | `DELETE /{base_id}/{table}/{record_id}` |

Parameters:

- `base_id`: `app` followed by letters and digits. `record_id`: `rec` followed
  by letters and digits. `table`: a table id (`tbl...`) or a name of letters,
  digits, space, `_` and `-`.
- `records.list`: `pageSize` (1..100), `maxRecords`, `view`,
  `filterByFormula`, `offset`.
- `records.create` and `records.update`: a JSON body such as
  `{"fields":{"Name":"Ada"}}`. The body is not constrained: an agent with
  `records:write` can set any field the token can write.

There is no `bases.list`: `GET /meta/bases` has the same shape as
`GET /{base_id}/{table}`, so a proxied `/meta/bases` would be ambiguous. It
resolves to `records.list` and `base_id=meta` is then refused. There is no
batch (multi-record) operation.

## Pagination

A list answer carries `offset` while there is another page. saiife returns it
as `next: offset=<cursor>`; the last page has no `offset`. The cursor looks like
`itr.../rec...`; pass it back unchanged.

```bash
saiife api airtable records.list base_id=appAbCdEfGhIjKlMn table=Tasks pageSize=50
saiife api airtable records.list base_id=appAbCdEfGhIjKlMn table=Tasks offset=<cursor>
```

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny. A
qualified `allow` such as `records:read:base=appAbCdEfGhIjKlMn` never matches
a call that has no qualifier.

## Suggested policy: read-only

```toml
[services.airtable]
connector = "airtable"
secret = "airtable-main"
allow = ["records:read"]
```

## Suggested policy: every write under `ask`

```toml
[services.airtable]
connector = "airtable"
secret = "airtable-main"
allow = ["records:read"]
ask   = ["records:write", "records:delete"]
```

To restrict the service to one base, use
`allow = ["records:read:base=appAbCdEfGhIjKlMn"]`, and give the token access to
that base only.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s`. Redirects go to the same host only.
- Per-service `limits` count requests that were sent upstream. Airtable allows
  5 requests per second per base; more come back as 429.
- The token is masked (raw, base64, URL-encoded and hex) in every response.

## Locked mode

In locked mode (Linux) the agent reaches Airtable only through `saiifed`. The
token lives in the daemon's vault and never reaches the agent's environment,
files or audit records. A project overlay can only add `deny` and `ask`. Every
call is one `connector` audit record. On macOS the commands print
`saiife: locked mode needs Linux in this version (macOS: v2.1)` and exit 5.

Create the token with only the scopes the policy needs (`data.records:read`,
and `data.records:write` only if you allow writes).
