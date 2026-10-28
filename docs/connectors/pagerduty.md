# PagerDuty connector

Connector id `pagerduty`, REST API v2, built into `saiife-broker`
(`crates/broker/connectors/pagerduty.toml`). The service starts with
everything denied: each capability below needs an `allow` (or `ask`) entry in
the policy.

Paths follow the PagerDuty API reference
(<https://developer.pagerduty.com/api-reference/>). This page and the test
fixtures were written offline, in the documented shape; check them against
the reference when PagerDuty changes an endpoint.

## Setup

```sh
saiife secret add pagerduty-main --kind token --service pagerduty   # a REST API key
```

The key goes out only as `Authorization: Token token=<key>`. Use a read-only
key for the read-only policy.

`from` is the email address of a PagerDuty user. PagerDuty requires it in the
`From` header of write requests, and the broker sends it on every request. The
admin sets it in the service config; the agent cannot. Incident changes are
recorded as made by that user. The broker also fixes `Accept` to
`application/vnd.pagerduty+json;version=2`; an agent value for either header
is overridden.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `incidents.list` | `incidents:read` | read | `GET /incidents`; query `limit` (1..100), `offset`, `since`, `until`, `urgencies` (`high`, `low`) |
| `incidents.get` | `incidents:read` | read | `GET /incidents/{incident_id}` |
| `incidents.notes` | `incidents:read` | read | `GET /incidents/{incident_id}/notes` |
| `incidents.create` | `incidents:write` | write | `POST /incidents`, JSON body |
| `incidents.update` | `incidents:write` | write | `PUT /incidents/{incident_id}`, JSON body (acknowledge, resolve, reassign) |
| `notes.create` | `incidents:write` | write | `POST /incidents/{incident_id}/notes`, JSON body |
| `services.list` | `services:read` | read | `GET /services`; query `limit`, `offset`, `query` |
| `oncalls.list` | `oncalls:read` | read | `GET /oncalls`; query `limit`, `offset`, `since`, `until` |

Notes:

- `incident_id` is the incident's id (capital letters and digits, such as
  `PT4KHLK`).
- Agents may send `Content-Type`; every other request header is dropped or
  fixed by the broker.
- **Pagination** is offset based. A list answer holds `offset`, `limit` and
  `more`; while `more` is true, the next page is `offset + limit`. The
  summary on stderr prints it as `next: offset=...`.
- Array filters such as `statuses[]` are not supported (query names are plain
  words); filter the answer instead.
- `incidents.update` can resolve an incident or hand it to someone else.
  Keep it under `ask`.

## Suggested policy: read-only

`/etc/saiife/policy.d/pagerduty.toml`:

```toml
[services.pagerduty]
connector = "pagerduty"
secret = "pagerduty-main"
params = { from = "ops@acme.com" }
allow = ["incidents:read", "services:read", "oncalls:read"]

[services.pagerduty.limits]
requests_per_minute = 60
```

## Suggested policy: every write under `ask`

```toml
[services.pagerduty]
connector = "pagerduty"
secret = "pagerduty-main"
params = { from = "ops@acme.com" }
allow = ["incidents:read", "services:read", "oncalls:read"]
ask   = ["incidents:write"]

[services.pagerduty.limits]
requests_per_minute = 60
writes_per_hour = 20
```

## Limits

- Writes count toward `writes_per_hour`.
- PagerDuty's own rate limit (960 requests a minute per account) is
  separate; a `429` is passed on.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the key lives
in the root-owned vault and never reaches the agent; calls go through the
gateway, which adds it. A project config can add `deny` and `ask` entries but
cannot add an `allow` or change the secret or the `from` address. Use
`saiife api pagerduty incidents.list limit=25`, or the gateway at `/v1/api`;
the exit codes are those of `saiife api` (2 denied, 4 limit reached).
