# Intercom connector

The `intercom` connector reaches the Intercom REST API (contacts and
conversations) through `saiifed`. The agent never sees the access token. The
manifest is `crates/broker/connectors/intercom.toml`.

- Base URL `https://{host}`, where `host` is an admin service param and one of
  `api.intercom.io` (US), `api.eu.intercom.io` or `api.au.intercom.io`. No
  other host can be called.
- Auth: `bearer`, an Intercom access token (a `token` secret).
- `Intercom-Version` is set by saiife from the admin param `api_version`
  (for example `2.11`). The agent cannot change it.
- Vendor reference:
  <https://developers.intercom.com/docs/references/rest-api/api.intercom.io/contacts>,
  <https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations>.

## Setup

```toml
[services.intercom]
connector = "intercom"
secret = "intercom-main"

[services.intercom.params]
host = "api.eu.intercom.io"
api_version = "2.11"
```

`host` must be one of the three regional hosts; `api_version` must look like
`2.11`. Both are required.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `contacts.list` | `contacts:read` | read | `GET /contacts` |
| `contacts.get` | `contacts:read` | read | `GET /contacts/{contact_id}` |
| `conversations.list` | `conversations:read` | read | `GET /conversations` |
| `conversations.get` | `conversations:read` | read | `GET /conversations/{conversation_id}` |
| `conversations.reply` | `conversations:write` | write | `POST /conversations/{conversation_id}/reply` |

`*.list` take `per_page` (1..150) and `starting_after` (the cursor).
`conversations.reply` builds its body: `type` is always `admin`, and the
agent supplies `message_type` (`comment` reaches the customer, `note` is
internal), `admin_id` and `body`. A raw body is refused (`bad_param`).

There is no contact create, update, delete or search, and no conversation
close or assign, in this version.

## Pagination

List answers carry `pages.next.starting_after` while there is another page.
saiife returns it as `next: starting_after=<cursor>`; the last page has no
`pages.next`.

```bash
saiife api intercom contacts.list per_page=50
saiife api intercom contacts.list per_page=50 starting_after=<cursor>
saiife api intercom conversations.reply conversation_id=215467000000001 \
  message_type=note admin_id=3156780 body="Checked with ops."
```

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny.
Contacts hold personal data. To keep it from the agent, redact in the answer:

```toml
[services.intercom.redact]
fields = ["email", "phone"]
```

## Suggested policy: read-only

```toml
[services.intercom]
connector = "intercom"
secret = "intercom-main"
allow = ["contacts:read", "conversations:read"]

[services.intercom.params]
host = "api.intercom.io"
api_version = "2.11"
```

## Suggested policy: every write under `ask`

```toml
[services.intercom]
connector = "intercom"
secret = "intercom-main"
allow = ["contacts:read", "conversations:read"]
ask   = ["conversations:write"]

[services.intercom.params]
host = "api.intercom.io"
api_version = "2.11"
```

A reply of type `comment` is sent to the customer, so keep it under `ask`.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s`. Redirects go to the same host only.
- Per-service `limits` count requests that were sent upstream. Intercom's own
  rate limits come back as 429.
- The token is masked (raw, base64, URL-encoded and hex) in every response.

## Locked mode

In locked mode (Linux and macOS) the agent reaches Intercom only through `saiifed`. The
token lives in the daemon's vault and never reaches the agent's environment,
files or audit records. Service params are admin-only, so a project overlay
cannot point the connector at another host. A project overlay can only add
`deny` and `ask`. Every call is one `connector` audit record.
