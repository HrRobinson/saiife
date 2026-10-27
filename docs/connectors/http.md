# Generic HTTP connector

`connector = "http"` connects an in-house API that has no manifest. The
service config defines the operations itself. The rest of the pipeline is
the same as for any connector: scope, policy, limits, the vault credential,
masking and the audit record (see [README](README.md)).

```toml
# /etc/saiife/policy.d/erp.toml
[services.erp]
connector = "http"
base_url = "https://erp.acme.internal/api"
secret = "erp-token"
auth = { kind = "header", name = "X-Api-Key" }

allow = ["invoices:read"]
ask   = ["invoices:write"]

[services.erp.limits]
requests_per_minute = 60
writes_per_hour = 20

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/v2/invoices"
query = ["status", "from", "to"]

[[services.erp.operation]]
id = "invoices.get"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/v2/invoices/{invoice_id}"

[[services.erp.operation]]
id = "invoices.create"
capability = "invoices:write"
kind = "write"
method = "POST"
path = "/v2/invoices"
body = "json"
```

## The fields

- `base_url` must be `https://`. It may not hold credentials or `{...}`
  placeholders. Its host is the only host requests go to. Redirects are
  followed only for `GET` and `HEAD`, only to the same origin, and at most 3
  times.
- `auth` is `header` (with `name`), `bearer` or `basic`. Add the secret
  with the matching kind:

  ```
  saiife secret add erp-token --kind header --service erp --from-file /root/erp.key
  ```

  | `auth.kind` | Vault kind | Sent as |
  |---|---|---|
  | `header` | `header` (`value`) | `<name>: <value>` |
  | `bearer` | `token` (`token`) | `Authorization: Bearer <token>` |
  | `basic` | `basic` (`username`, `password`) | `Authorization: Basic …` |

- Each `[[services.<name>.operation]]` has an `id`, a `capability`
  (`resource:verb`), a `kind` (`read`, `write`, `delete` or `bulk`, used by
  the limits), a `method`, a `path`, the allowed `query` parameter names,
  and `body = "json"` when it takes a body.
- `{name}` in a path is a path parameter. It is percent-encoded and may not
  contain `/`. Every parameter is a string.
- Agents may send only `Content-Type` and `Accept`. Agent-supplied
  `Authorization`, `Cookie` and `Host` headers are always dropped.
- A JSON body is parsed strictly: a repeated key is refused (`bad_body`).
  The parsed body is re-serialized, and that form is sent with
  `Content-Type: application/json`.

Calling it:

```
saiife api erp invoices.list status=open
saiife api erp invoices.get invoice_id=2026-0042
saiife api erp invoices.create --body @invoice.json
```

## Outbound webhooks

An outbound webhook is a `POST` to a fixed URL. Put the URL in `base_url`
and use the path `/`. The request then goes to `base_url` followed by `/`.
If the endpoint must not end in `/`, move its last segment into `path`
instead (`base_url = ".../T000"`, `path = "/B000"`).

```toml
[services.deploy-hook]
connector = "http"
base_url = "https://hooks.example.com/services/T000/B000"
secret = "deploy-hook-token"
auth = { kind = "bearer" }
ask = ["hook:write"]

[[services.deploy-hook.operation]]
id = "send"
capability = "hook:write"
kind = "write"
method = "POST"
path = "/"
body = "json"
```

```
saiife api deploy-hook send --body @message.json
```

The agent cannot change the URL. It can only choose the body.

## Suggested policy

Start read-only. Put every write under `ask`. Until approvals arrive
(plan 11), `ask` means deny with `approval_not_available`, so writes stay
off until you decide otherwise.

```toml
[services.erp]
allow = ["*:read"]
ask   = ["*:write", "*:delete"]

[services.erp.limits]
requests_per_minute = 60
writes_per_hour = 20
deletes_per_day = 0
max_response_bytes = 1_048_576

[services.erp.redact]
fields = ["customer.email", "customer.phone"]
```

A project's `.saiife/config.toml` may tighten this with `deny` and `ask`
entries for a service. In locked mode it can never add `allow`.

## What the audit log shows

Each call writes one `connector` record:

```json
{"kind":"connector","tool":"api","input":"erp invoices.list status=open","decision":"allow",
 "service":"erp","operation":"invoices.list","capability":"invoices:read","env":"prod",
 "params":{"status":"open"},"body_sha256":null,"body_bytes":0,"status":200,
 "resp_bytes":4211,"duration_ms":182,"secret":"erp-token","limit":null,"via":"cli",
 "op_kind":"read","amount":null, "...": "common fields"}
```

The record holds the masked parameters and the SHA-256 and size of the
body. It never holds the body or a secret value.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the secret
named in `secret` lives in the root-owned vault and never reaches the agent;
calls go through the gateway, which adds it. A project config can add `deny`
and `ask` entries but cannot add an `allow`, define or change an operation,
or change `base_url` or the secret. Services and their operations are
defined by an admin in `/etc/saiife/policy.d/`. Use `saiife api erp
invoices.list status=open`, or the gateway at `/v1/api`; the exit codes are
those of `saiife api` (2 denied, 4 limit reached).
