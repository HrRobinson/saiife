# Connectors

In locked mode (Linux), the agent never holds a credential for a brokered
service; it holds its own model-provider login unless you run a local model.
For a brokered service it asks the
saiife daemon to make the call. The daemon checks the call against the
policy, adds the credential from its vault, sends the request, and masks
the response before the agent sees it. Every call writes one `connector`
record to the audit log.

```
saiife api --list [<service>] [--json]
saiife api <service> <operation> [k=v ...] [--body @file|-] [--json]
```

The upstream data goes to stdout. A one-line summary goes to stderr:

```
saiife: erp invoices.list → 200 (4211 bytes, 182 ms)
```

When a response has another page, stderr also prints the parameters for
it, for example `next: since_id=42`.

| Exit | Meaning |
|---|---|
| 0 | done |
| 1 | the upstream answered with status 400 or higher (the body is still on stdout), or the upstream failed |
| 2 | denied (`saiife: denied (<rule>)`) |
| 3 | pending approval (plan 11) |
| 4 | a limit was reached (`saiife: limit reached (<limit>)`) |
| 5 | saiife is unavailable (no daemon, no locked config) |

## The pipeline

Each call goes through these steps, in this order (spec §6.7.1). Steps 3–8
never touch the network, so a denied call costs no upstream request.

1. **Identify.** The uid comes from the socket's peer credentials. The
   session is found by attribution. The project is what the client reports.
2. **Scope.** The uid's single `[[scope]]` must list the service.
3. **Resolve** the operation.
4. **Validate** the parameters against the manifest's types.
5. **Policy.** Any `deny` wins, then `ask`, then `allow`. Nothing matching
   means deny.
6. **Limits.** Rate, count and amount limits apply.
7. **Ask.** Until plan 11, `ask` is a deny with rule `approval_not_available`.
8. **Send.** The request goes upstream with the vault credential. The client
   always sends `Accept-Encoding: identity`, and a compressed answer is
   refused.
9. **Mask** every vault value and v1 pattern, redact fields, and cut the
   response at `max_response_bytes`.
10. **Record** the call, then return the result.

## Deny rules

| Rule | Why |
|---|---|
| `no_scope` | the uid is in no scope, or its scope does not list the service |
| `scope_conflict` | the uid matches more than one scope |
| `unknown_operation` | no operation has that id, or matches that method and path |
| `bad_path` | the proxy path holds `..`, `%2e`, `%2f`, `//`, a backslash, or another host |
| `bad_param` | an unknown parameter, a parameter fixed by the policy, a value of the wrong type, or a body for an operation without one |
| `bad_body` | a JSON body that does not parse, or that repeats a key |
| `bad_amount` | an operation that moves money, without a readable amount |
| `deny:<pattern>` | a `deny` pattern matched |
| `default_deny` | no `allow` matched |
| `approval_not_available` | the call matched `ask` (approvals come with plan 11) |
| `policy_invalid` | the daemon has no valid policy, or a service config is broken |
| `vault_unavailable` | the vault key is missing, or the vault cannot be decrypted |
| `upstream_unavailable` | the daemon could not build its HTTPS client at start (no trusted roots) |
| `secret_missing` | the service names no secret, or a secret the vault does not hold or cannot use for this auth kind |
| `secret_not_allowed_for_service` | the secret's `allowed_services` does not list the service |
| `redirect_refused` | the upstream redirected to another origin. The answer is withheld: exit 1 |
| `redact_non_json` | the service redacts fields but the answer is not JSON. It is withheld: exit 1 |

Limits deny with `limit` set to the name of the limit, for example
`requests_per_minute`, `writes_per_hour`, `deletes_per_day`,
`bulk_per_session`, `amount_per_request`, `amount_per_day`,
`amount_missing`, `amount_currency` or `concurrency` (all 4 upstream slots of
the service stayed busy for a whole upstream timeout). A request that was sent counts,
whatever its status. Limits are rebuilt from the last 24 hours of
`connector` records when the daemon starts, so a restart does not reset
them.

## Connectors as MCP tools, and third-party MCP servers

`saiife mcp` lists the operations an agent may call as typed MCP tools
(`shopify_orders_list`) and sends each call through this same pipeline, with
`via = "mcp"` in the record. Third-party MCP servers can run behind the
daemon too, with their tokens in the vault. Where a service has a connector
here, use the connector rather than a gateway server. See [MCP](../mcp.md).

## Trusting a private CA

`/etc/saiife/ca/*.pem` adds root certificates for upstreams, next to the
system store. The directory and every `.pem` file in it must be owned by
root and not writable by group or others. Symlinks are not followed. If
any of this fails, the daemon starts without these CAs. It writes a
`daemon` record with `event = "ca_refused"` and the reason, and the system
roots still work.

## Limits of the control socket

An answer travels as base64 in a frame of at most 16 MiB, so
`max_response_bytes` above about 11 MiB cannot be returned over
`saiife api`. A request body is at most 700 KiB. Large numbers in masked
JSON responses lose precision, because JSON bodies are re-serialized after
masking.

## Gateway

Besides `saiife api`, the daemon serves the same pipeline over HTTP/1.1, for
scripts and tools that speak HTTP. The routes are `/v1/api/<service>/<op>`
(a JSON body `{params, body, wait}`) and `/v1/proxy/<service>/<path>` (the raw
path and query, passed to the matching operation).

- **`gateway.sock`** sits next to `saiife.sock` in the daemon's socket
  directory, mode 0666. The peer uid comes from the socket's credentials, so
  nothing the client sends can claim another identity. `X-Forwarded-*` and
  proxy headers are ignored.
- **Optional TCP listener.** `[gateway] tcp = "127.0.0.1:<port>"` opens a
  loopback listener; the default is none, and an address that is not
  loopback (`127.0.0.0/8`, `::1`) is a config error. Every request needs
  `Authorization: Bearer <token>`. Get a token with `saiife api token`: it is
  bound to your uid, valid for 12 hours, and the daemon stores only its
  SHA-256. The header is consumed and never forwarded upstream. A missing,
  expired or unknown token answers 401.
- Agent-supplied `Authorization`, `Cookie` and `Host` headers are dropped.
  Statuses: 200, 202, 403 `{"error":"denied","rule":...}`, 429, 502, 503. The
  upstream status is in `X-Saiife-Upstream-Status`.
- **No project overlay over HTTP.** A project's `.saiife/config.toml` is read
  by the `saiife` client and sent with the call, so HTTP calls, which never
  pass through the client, carry no project overlay. The system policy still
  applies in full; only a project's extra `deny` and `ask` rules are absent.

## Connectors

- [Shopify](shopify.md): orders, products, customers, refunds, discounts.
- [HubSpot](hubspot.md): contacts, companies and deals.
- [GitHub](github.md): repositories, issues and pull requests.
- [GitLab](gitlab.md): projects, issues, merge requests and pipelines.
- [Sentry](sentry.md): projects, issues and events.
- [PagerDuty](pagerduty.md): incidents, notes, services and on-calls.
- [Stripe](stripe.md): customers, charges, payment intents, invoices and
  refunds (amount caps).
- [Slack](slack.md): conversations, messages and users.
- [Discord](discord.md): guilds, channels and messages.
- [Linear](linear.md): issues, projects and teams over fixed GraphQL
  operations.
- [Intercom](intercom.md): contacts and conversations.
- [Zendesk](zendesk.md): tickets, ticket comments, users and search.
- [Airtable](airtable.md): records (list, get, create, update, delete).
- [Segment](segment.md): track, identify, group and batch events.
- [WooCommerce](woocommerce.md): orders, products, customers and refunds
  (amount caps).
- [Email](email.md): send with SMTP, read with IMAP.
- [Salesforce](salesforce.md): SOQL queries, object metadata and records
  (OAuth2).
- [Amazon S3](aws-s3.md): list, get, head, put and delete objects (SigV4;
  opt-in STS mode with `saiife run --cloud`).
- [AWS STS](aws-sts.md): `GetCallerIdentity` (SigV4).
- [Google Cloud Storage](gcp-storage.md): list, get, download, upload and
  delete objects (service account).
- [Azure Resource Manager](azure-arm.md): resource groups, resources and
  VMs, VM restart (service principal).
- [Azure Blob Storage](azure-blob.md): list, get, put and delete blobs
  (service principal).
- [Generic HTTP connector and outbound webhooks](http.md): any other API,
  configured by hand.

To use one, run `saiife connect <service>`. It stores the secret (or reuses
an existing one with `--secret <name>`, if that secret allows the service)
and writes a policy file that starts deny-all.

## Environments

An environment overlays packs and service settings on the system config and
is bound to a scope, for example one for staging and one for production. See
[environments](../environments.md).

## Collections

A collection is a saved list of calls in `.saiife/collections/`, run with
`saiife api collection run <name>`. Each step goes through the full pipeline.
See [collections](../collections.md).

## OAuth2 secrets

An `oauth2` secret holds `client_id`, `client_secret` and `refresh_token`
(`saiife secret add <name> --kind oauth2`). The daemon gets access tokens
from the connector's token endpoint on the service's own host and keeps
them in memory only. When the manifest's host is an instance parameter, a
token response must name that instance in `instance_url`, or it is refused.
After a 401 the daemon refreshes once and sends the request once more. A
failed refresh starts a backoff of 5 seconds to 5 minutes (see
[notifications](../notifications.md#events)).

Some services issue a new refresh token on each refresh. The daemon writes
it to the vault before it uses the new access token, and at shutdown it
waits up to 5 seconds for a refresh in flight. If that write fails, stderr
says `<secret>: rotated refresh token not persisted; do not restart the
daemon`; fix the vault and the next call writes it. If the token was lost
anyway (refresh calls fail with `http_400` or `http_401`), get a new
refresh token from the service and run `saiife secret rotate <secret>`.

## Answer frame size

The control socket accepts requests of up to 1 MiB, but an answer may be up
to 16 MiB (`MAX_ANSWER_FRAME`). A client that reads answers must allow for
that size.
