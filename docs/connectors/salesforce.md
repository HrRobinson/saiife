# Salesforce connector

Connector id `salesforce`, the Salesforce REST API for one org, built into
`saiife-broker` (`crates/broker/connectors/salesforce.toml`). It authenticates
with OAuth2: the vault holds a connected app's client id and secret and a
refresh token, and the daemon gets short-lived access tokens itself. The
service starts with everything denied: each capability below needs an
`allow` (or `ask`) entry in the policy.

Paths follow the Salesforce REST API Developer Guide
(<https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/>).
This page and the test fixtures were written offline, in the documented
shape; check them against the reference when Salesforce changes an endpoint.

- Base URL `https://{instance_host}/services/data/{api_version}`.
- `instance_host` is the org's My Domain host, for example
  `acme.my.salesforce.com`, or `acme--dev.sandbox.my.salesforce.com` for a
  sandbox. It must match `^[a-z0-9-]+(\.sandbox)?\.my\.salesforce\.com$`:
  lower case, no scheme, port, path or user part. `login.salesforce.com`,
  instance hosts such as `na1.salesforce.com`, and scratch orgs are refused.
- `api_version` is the REST version, for example `v60.0`; it must match
  `^v[0-9]{2,3}\.0$`.
- Both are required, and both are set by the admin in the service config;
  the agent cannot set either. The instance host is the only host the
  service ever contacts, for the API and for the token endpoint. A redirect
  to another host is refused.
- Request headers the agent may send: `Content-Type`, `Accept`.
  `Authorization`, `Cookie` and `Host` are always dropped, and so is every
  `Sforce-*` header.

## Setup

### 1. A connected app and an integration user

Create a connected app (Setup, App Manager, New Connected App) with OAuth
enabled and **only these two scopes**:

- `Manage user data via APIs (api)`
- `Perform requests at any time (refresh_token, offline_access)`

Do not add `full`, `web` or any other scope. Set the refresh token policy to
"valid until revoked" or to an expiry you are prepared to renew by hand.

Then create a dedicated **integration user** and get the refresh token while
logged in as that user, not as an admin. The connector can read and change
exactly what that user can: **its profile and permission sets bound what
SOQL can read**. The `sobject` qualifier only narrows the record operations,
not `query` (see [SOQL](#soql)). Give the user read access to the objects and
fields the agent needs and nothing more; leave "View All Data" and "Modify
All Data" off.

### 2. The paste flow

Get a refresh token for the integration user with the connected app (the
OAuth web server flow, done once, outside saiife), then paste the three
values:

```sh
saiife secret add salesforce --kind oauth2 --service salesforce
```

The command prompts for `client_id` (echoed), then for `client_secret` and
`refresh_token` without echo. For scripts, `--from-file <path>` or
`--from-env <VAR>` read a JSON object with exactly the keys `client_id`,
`client_secret` and `refresh_token`. There is no device flow.

`saiife connect salesforce --param instance_host=acme.my.salesforce.com
--param api_version=v60.0` stores the same `oauth2` secret and writes a
deny-all policy file to edit.

The daemon refreshes the access token on first use, when it is about to
expire, and once after a `401`. It sends the refresh to
`https://{instance_host}/services/oauth2/token` and keeps the access token
in memory only; it is never written to the vault, a record or a log. A
token response whose `instance_url` is missing or names another host is
refused. The general rules are in [OAuth2 secrets](README.md#oauth2-secrets).

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `query` | `query:read` | read | `GET /query?q=<SOQL>` |
| `query.more` | `query:read` | read | `GET /query/{locator}` |
| `sobjects.list` | `sobjects:read` | read | `GET /sobjects` |
| `sobjects.describe` | `sobjects:read` | read | `GET /sobjects/{sobject}/describe` |
| `records.get` | `records:read` | read | `GET /sobjects/{sobject}/{id}`; query `fields` (comma-separated names of the object's own fields) |
| `records.create` | `records:write` | write | `POST /sobjects/{sobject}`, JSON body |
| `records.update` | `records:write` | write | `PATCH /sobjects/{sobject}/{id}`, JSON body |
| `records.delete` | `records:delete` | delete | `DELETE /sobjects/{sobject}/{id}` |

Notes:

- `sobjects.describe` and the `records.*` operations carry the qualifier
  `sobject={sobject}`, so a rule can be limited to one object:
  `allow = ["records:read:sobject=Account"]`.
- `sobject` is an API name (`Account`, `My_Object__c`): a letter, then
  letters, digits and `_`, at most 80 characters. Control characters,
  `/`, `?`, `%` and `*` are refused, so the qualifier is always one plain
  name.
- Salesforce treats object names case-insensitively. `deny` and `ask`
  qualifiers ignore case too, so `deny = ["records:delete:sobject=Account"]`
  also stops `sobject=account`. `allow` compares case exactly: write the
  name as Salesforce spells it.
- `id` is a 15- or 18-character record id.
- There is no `queryAll`, SOSL search, composite, bulk, Apex REST or tooling
  operation. On the proxy path those paths are unknown operations.

### SOQL

`query` sends the agent's SOQL as the `q` parameter. `q` is printable ASCII
(space to `~`) and at most 4000 bytes; control characters, line breaks and
non-ASCII characters are refused. For a non-ASCII value, match with `LIKE`
and a wildcard, or read the record by id.

A SOQL query can name any object, and semi-joins and relationship queries
reach further. The `sobject` qualifier does not apply to it. What a query
returns is bounded only by the integration user's profile and sharing. Both
suggested policies therefore put `query:read` under `ask`, so a person sees
each query before it runs. Allow it only when the profile already limits
the user to data the agent may read.

`FOR UPDATE` and `FOR VIEW` are permitted in a query. They have minor side
effects: `FOR UPDATE` locks the returned records for the rest of the
transaction, and `FOR VIEW` updates their `LastViewedDate`. The person who
approves the query sees the clause.

`records.get` with `fields` names only the object's own fields: `fields` is
`[A-Za-z0-9_,]`, with no `.`, so a relationship such as
`Account.Owner.Email` is refused. Relationship data needs `query`, which is
under `ask`.

**Pagination.** Salesforce returns no `next` parameter. A result with
`"done": false` has a `nextRecordsUrl` such as
`/services/data/v60.0/query/01gD0000002HU6KIAW-2000`. Pass its last segment
as the locator:

```sh
saiife api salesforce query.more locator=01gD0000002HU6KIAW-2000
```

The locator is one path segment (`[A-Za-z0-9]{15,18}-[0-9]{1,9}`), never a
path. It has the same capability as `query`, so under the suggested policies
each page is asked for too. That is on purpose: a locator names a result set
on the server, and asking for each page means an agent cannot walk a result
set it was not shown.

## Suggested policy: read-only

`/etc/saiife/policy.d/salesforce.toml`:

```toml
[services.salesforce]
connector = "salesforce"
secret = "salesforce"
params = { instance_host = "acme.my.salesforce.com", api_version = "v60.0" }
allow = ["sobjects:read", "records:read"]
ask   = ["query:read"]

[services.salesforce.limits]
requests_per_minute = 60
```

To give the agent only some objects, qualify the reads:
`allow = ["sobjects:read", "records:read:sobject=Account", "records:read:sobject=Case"]`.

## Suggested policy: every write under `ask`

```toml
[services.salesforce]
connector = "salesforce"
secret = "salesforce"
params = { instance_host = "acme.my.salesforce.com", api_version = "v60.0" }
allow = ["sobjects:read", "records:read"]
ask   = ["query:read", "records:write", "records:delete"]

[services.salesforce.limits]
requests_per_minute = 60
writes_per_hour = 30
deletes_per_day = 10
```

## Rotation

- **Refresh token rotation.** If the connected app issues a new refresh
  token on each refresh, the daemon writes the new one to the vault before
  it uses the new access token. A refresh that is in flight while you run
  `saiife secret rotate` never overwrites your new value.
- **Replacing the credential.** Revoke the old refresh token in Salesforce
  (the user's "OAuth Connected Apps" list, or the connected app's usage
  page), get a new one with the web server flow, and run
  `saiife secret rotate salesforce`. It prompts for the three values again
  and drops the cached access token. The same applies when you rotate the
  consumer secret of the connected app.
- **A lost rotated token.** If the daemon could not store a rotated refresh
  token and stopped before it could retry, refreshes fail with `http_400`
  (`invalid_grant`). Get a new refresh token and run
  `saiife secret rotate salesforce`. See
  [OAuth2 secrets](README.md#oauth2-secrets) and
  [notifications](../notifications.md#events).

## refresh_failed

When the daemon cannot get an access token, the call is denied
`refresh_failed`, the audit log gets a `secret` record with
`event = "refresh_failed"` (the secret name, the service and a `reason`;
never a response body), and a `refresh_failed` notification is sent, at
most once per secret per hour. The reasons:

| Reason | Usually means |
|---|---|
| `http_400` | `invalid_grant`: the refresh token was revoked, expired, or replaced by a rotation the vault lost, or the user's IP range or login hours block it. `invalid_client_id` or `invalid_client`: wrong `client_id` or `client_secret` |
| `http_<other>` | the token endpoint failed; Salesforce's status page may say why |
| `network` | the instance host is unreachable |
| `bad_response` | the answer was not a usable token response |
| `instance_mismatch` | `instance_url` is missing or names another host: `instance_host` is set to the wrong org |
| `persist` | a rotated refresh token could not be written to the vault; fix the vault, the next call writes it |

After a failure the daemon backs off for 5 seconds, doubling up to
5 minutes, and calls in that time are denied with the same reason. A
successful refresh or `saiife secret rotate` ends the backoff. Details:
[notifications](../notifications.md#events).

A `401` from the API itself (`INVALID_SESSION_ID`, a session ended by an
admin or a timeout) is not a refresh failure: the daemon refreshes once and
sends the request once more, and the record has `auth_retry: true`. A second
`401` is returned as is (exit 1).

## Limits

- Writes count toward `writes_per_hour`, deletes toward `deletes_per_day`.
- Salesforce's daily API request limit is separate; its `403`
  `REQUEST_LIMIT_EXCEEDED` is passed on.
- A token refresh is not a counted request.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the client
secret and the refresh token live in the root-owned vault, and the access
token lives only in the daemon's memory; none of them reaches the agent.
Calls go through the gateway, which adds the access token. A project config
can add `deny` and `ask` entries but cannot add an `allow` or change the
secret, the instance host or the API version. Use
`saiife api salesforce records.get sobject=Account id=001D000000IRFmaIAH`,
or the gateway at `/v1/api`; the exit codes are those of `saiife api`
(1 upstream error, 2 denied, 3 pending approval, 4 limit reached).
