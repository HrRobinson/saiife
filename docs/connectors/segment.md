# Segment connector

The `segment` connector sends events to the Segment Tracking API (the HTTP
API source) through `saiifed`. The agent never sees the source write key. The
manifest is `crates/broker/connectors/segment.toml`, embedded at build time.
The Segment Public API (workspace management) is out of scope.

- Base URL `https://{host}/v1`. `host` is a service param set by the admin,
  one of `api.segment.io` (US) and `events.eu1.segmentapis.com` (EU). Those two
  are the only hosts the connector may call.
- Auth: `basic_token`. Segment wants the write key as the Basic user name with
  an empty password; saiife sends `Basic base64(<write key>:)`. The vault entry
  is a `token` secret holding the write key.
- Request headers the agent may send: `Content-Type`, `Accept`.
  `Authorization`, `Cookie` and `Host` are always dropped.
- Vendor reference:
  <https://segment.com/docs/connections/sources/catalog/libraries/server/http-api/>.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `track` | `events:write` | write | `POST /v1/track` |
| `identify` | `users:write` | write | `POST /v1/identify` |
| `group` | `groups:write` | write | `POST /v1/group` |
| `batch` | `events:write` | bulk | `POST /v1/batch` |

Each takes a JSON body in Segment's documented shape, for example
`{"userId":"u-1","event":"Order Completed","properties":{"total":12}}`.
`batch` takes `{"batch":[{"type":"track",...},...]}`. Send
`Content-Type: application/json`.

Segment's Tracking API only accepts data; it has no read endpoint. There is no
read operation, so there is nothing a read-only policy can allow. A call that
matches no operation is denied as `unknown_operation`.

### The body is not constrained

saiife validates the headers and path of these operations, not the JSON body.
An agent with `events:write` can send any event name and properties into your
analytics and downstream destinations, and `identify` can overwrite user traits.
The write key is scoped to one source, so create a source for the agent.

## Capabilities and policy

Capabilities are `<object>:<verb>`. Policy order is deny, then ask, then allow;
nothing matching means deny. Both policies below go in
`/etc/saiife/policy.d/segment.toml`.

## Suggested policy: read-only

```toml
[services.segment]
connector = "segment"
secret = "segment-prod"

[services.segment.params]
host = "api.segment.io"
```

The read-only policy is empty on purpose: Segment is write-only, so there is no
read capability to allow. Every operation is denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.segment]
connector = "segment"
secret = "segment-prod"
ask   = ["events:write", "users:write", "groups:write"]

[services.segment.params]
host = "api.segment.io"
```

`events:write` covers both `track` and the bulk `batch`.

Both policies are exercised by `crates/broker/tests/segment.rs`.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s` (`[gateway] upstream_timeout`). Redirects are followed
  to the same host only, at most 3.
- Per-service `limits` in the policy count requests that were sent upstream,
  whatever their status. Segment's own limits (500 KB per request, 32 KB per
  message) still apply.
- The write key and its `key:` basic-auth form are masked (raw, base64,
  URL-encoded and hex forms) in every response before the agent sees them.

## Locked mode

In locked mode (Linux) the agent user reaches Segment only through `saiifed`:
`saiife api segment ...`, or `gateway.sock` at `/v1/api` and `/v1/proxy`.
The write key lives in the daemon's vault (`saiife secret add segment-prod`,
or `saiife connect segment`) and never reaches the agent's environment, files
or audit records. A project overlay can only add `deny` and `ask`; in locked
mode its `allow` is ignored. Every call is one `connector` audit record. On
macOS the commands print `saiife: locked mode needs Linux in this version
(macOS: v2.1)` and exit 5.
