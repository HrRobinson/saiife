# Sentry connector

Connector id `sentry`, Web API, built into `saiife-broker`
(`crates/broker/connectors/sentry.toml`). It works with sentry.io and with
self-hosted Sentry. The service starts with everything denied: each
capability below needs an `allow` (or `ask`) entry in the policy.

Paths follow the Sentry API reference (<https://docs.sentry.io/api/>). This
page and the test fixtures were written offline, in the documented shape;
check them against the reference when Sentry changes an endpoint.

## Setup

```sh
saiife secret add sentry-main --kind token --service sentry   # an auth token (internal integration)
```

The token goes out only as `Authorization: Bearer`. Give the integration the
narrowest scopes you can (`project:read`, `event:read`; `event:write` only if
you allow `issues:write`).

`host` is the bare hostname: `sentry.io` or, for a regional or self-hosted
instance, for example `sentry.acme.com`. The admin sets it in the service
config; the agent cannot. It must be lower case, with no scheme, port, path
or user part, and it is the only host the service contacts.

`org` is the organization slug and is a path parameter. To keep the agent in
one organization, pin it with `fixed = { org = "acme" }` as the policies below
do.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `projects.list` | `projects:read` | read | `GET /organizations/{org}/projects/`; query `cursor` |
| `issues.list` | `issues:read` | read | `GET /projects/{org}/{project}/issues/`; query `query`, `statsPeriod` (`24h`, `14d`), `cursor` |
| `issues.get` | `issues:read` | read | `GET /organizations/{org}/issues/{issue_id}/` |
| `issues.events` | `events:read` | read | `GET /organizations/{org}/issues/{issue_id}/events/`; query `cursor`, `full` |
| `events.latest` | `events:read` | read | `GET /organizations/{org}/issues/{issue_id}/events/latest/` |
| `issues.update` | `issues:write` | write | `PUT /organizations/{org}/issues/{issue_id}/`, JSON body (`{"status": "resolved"}`) |

Notes:

- `issues.list` carries the qualifier `project={project}` (the project slug),
  so a rule can be limited to one project: `allow = ["issues:read:project=web"]`.
  The other issue routes are organization-wide and have no project in the
  path, so they carry no qualifier; `issues:read` without a qualifier covers
  them all.
- `issue_id` is an integer. Slugs are lower case letters, digits, `-` and `_`.
- **Events can hold personal data** (user emails, IP addresses, request
  bodies, breadcrumbs). Keep `events:read` under `ask`, or add `redact`
  fields.
- **Pagination** is the `Link` header with a `cursor`. A `rel="next"` entry
  marked `results="false"` is the last page; the broker stops there.

## Suggested policy: read-only

`/etc/saiife/policy.d/sentry.toml`:

```toml
[services.sentry]
connector = "sentry"
secret = "sentry-main"
params = { host = "sentry.io" }
fixed = { org = "acme" }
allow = ["projects:read", "issues:read"]

[services.sentry.limits]
requests_per_minute = 60
```

`events:read` is left out on purpose: events can hold personal data.

## Suggested policy: every write under `ask`

```toml
[services.sentry]
connector = "sentry"
secret = "sentry-main"
params = { host = "sentry.io" }
fixed = { org = "acme" }
allow = ["projects:read", "issues:read"]
ask   = ["events:read", "issues:write"]

[services.sentry.limits]
requests_per_minute = 60
writes_per_hour = 30
```

## Limits

- Writes count toward `writes_per_hour`.
- Sentry's own rate limits are separate; a `429` from Sentry is passed on.
- `issues.update` sends whatever JSON the agent gives (status, assignee,
  `isBookmarked`...). Keep it under `ask`.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the token
lives in the root-owned vault and never reaches the agent; calls go through
the gateway, which adds it. A project config can add `deny` and `ask`
entries but cannot add an `allow` or change the secret, the host or the
pinned organization. Use `saiife api sentry issues.list project=web`, or the
gateway at `/v1/api`; the exit codes are those of `saiife api` (2 denied, 4
limit reached).
