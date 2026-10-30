# Zendesk connector

The `zendesk` connector reaches the Zendesk Support API v2 (tickets, ticket
comments, users, search) through `saiifed`. The agent never sees the API
token. The manifest is `crates/broker/connectors/zendesk.toml`, embedded at
build time.

- Base URL `https://{subdomain}.zendesk.com/api/v2`. The host list is
  `*.zendesk.com`. `subdomain` is a service param set by the admin
  (`[services.zendesk.params]`), never by the agent: it is lower-case letters,
  digits and `-`, so it cannot change the host.
- Auth: `basic`. Zendesk API tokens are used as `<email>/token` (the user
  name) plus the token (the password). The vault entry is a `basic` secret
  with `username = "agent@acme.com/token"` and `password = <API token>`.
- Request headers the agent may send: `Content-Type`, `Accept`.
  `Authorization`, `Cookie` and `Host` are always dropped.
- Vendor reference:
  <https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/>,
  <https://developer.zendesk.com/api-reference/introduction/pagination/>,
  <https://developer.zendesk.com/api-reference/introduction/security-and-auth/>.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `tickets.list` | `tickets:read` | read | `GET /tickets` |
| `tickets.get` | `tickets:read` | read | `GET /tickets/{ticket_id}` |
| `tickets.comments` | `tickets:read` | read | `GET /tickets/{ticket_id}/comments` |
| `tickets.create` | `tickets:write` | write | `POST /tickets` |
| `tickets.update` | `tickets:write` | write | `PUT /tickets/{ticket_id}` |
| `users.get` | `users:read` | read | `GET /users/{user_id}` |
| `search` | `search:read` | read | `GET /search.json` |

Parameters:

- `tickets.list`, `tickets.comments`: `page[size]` (1 to 100), `page[after]`
  (the cursor) and `sort`.
- `search`: `query` (Zendesk search syntax), `sort_by`, `sort_order`, `page`
  (1 to 1000) and `per_page`.
- `tickets.create`: a JSON body such as
  `{"ticket":{"subject":"Printer on fire","comment":{"body":"Help"}}}`.
- `tickets.update`: the ticket id and a JSON body such as
  `{"ticket":{"status":"solved"}}`. Send `Content-Type: application/json`.

There is no delete, merge, bulk or user write operation. A call that matches
no operation is denied as `unknown_operation`. No operation has an `amount`
field, so amount caps do not apply.

### The write body is not constrained

saiife validates the ids and headers of `tickets.create` and `tickets.update`,
not the JSON body. An agent with `tickets:write` can set any ticket field the
token may write: assignee, requester, status, tags and public comments (a
public comment is an email to the customer). Keep `tickets:write` under `ask`.

## Pagination

`tickets.list` and `tickets.comments` use Zendesk cursor pagination. When
`meta.has_more` is `true`, saiife returns `meta.after_cursor` as `next`: the
CLI prints `next: page[after]=<cursor>` on stderr and `/v1/api` sets
`X-Saiife-Next`. Pass it back as `page[after]=<cursor>`. `search` is
page-numbered: count `page` yourself (Zendesk stops at 1000 results).

```bash
saiife api zendesk tickets.list 'page[size]=100'
saiife api zendesk tickets.list 'page[size]=100' 'page[after]=eyJvIjoiaWQifQ=='
saiife api zendesk search query='type:ticket status:open' per_page=50
saiife api zendesk tickets.update ticket_id=35436 --body @solve.json
```

## Capabilities and policy

Capabilities are `<object>:<verb>`. Policy order is deny, then ask, then allow;
nothing matching means deny. Both policies below go in
`/etc/saiife/policy.d/zendesk.toml`.

## Suggested policy: read-only

```toml
[services.zendesk]
connector = "zendesk"
secret = "zendesk-prod"
allow = ["tickets:read", "users:read", "search:read"]

[services.zendesk.params]
subdomain = "acme"
```

`tickets.create` and `tickets.update` are denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.zendesk]
connector = "zendesk"
secret = "zendesk-prod"
allow = ["tickets:read", "users:read", "search:read"]
ask   = ["tickets:write"]

[services.zendesk.params]
subdomain = "acme"
```

Both policies are exercised by `crates/broker/tests/zendesk.rs`.

To keep customer data away from the agent, redact fields in the response:

```toml
[services.zendesk.redact]
fields = ["email", "phone"]
```

Redaction paths match as a suffix anywhere in the JSON tree. A non-JSON answer
on a service with `redact` is withheld.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s` (`[gateway] upstream_timeout`). Redirects are followed
  to the same host only, at most 3.
- Per-service `limits` in the policy count requests that were sent upstream,
  whatever their status. Zendesk's own rate limits (per plan) still apply and
  come back as 429.
- The API token and the basic-auth pair are masked (raw, base64, URL-encoded
  and hex forms) in every response before the agent sees them.

## Locked mode

In locked mode (Linux and macOS) the agent user reaches Zendesk only through `saiifed`:
`saiife api zendesk ...`, or `gateway.sock` at `/v1/api` and `/v1/proxy`.
The credential lives in the daemon's vault (`saiife secret add zendesk-prod
--kind basic`, or `saiife connect zendesk`) and never reaches the agent's
environment, files or audit records. A project overlay can only add `deny` and
`ask`; in locked mode its `allow` is ignored. Every call is one `connector`
audit record.

Create a dedicated agent user in Zendesk with a role limited to what the policy
needs, and an API token for it, so a policy mistake is bounded by the token.
