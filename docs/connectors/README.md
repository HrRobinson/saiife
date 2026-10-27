# Connectors

In locked mode (Linux), an agent never holds an API credential. It asks the
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
- [Generic HTTP connector and outbound webhooks](http.md): any other API,
  configured by hand.

To use one, run `saiife connect <service>`. It stores the secret (or reuses
an existing one with `--secret <name>`, if that secret allows the service)
and writes a policy file that starts deny-all.

## Answer frame size

The control socket accepts requests of up to 1 MiB, but an answer may be up
to 16 MiB (`MAX_ANSWER_FRAME`). A client that reads answers must allow for
that size.
