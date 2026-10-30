# HubSpot connector

The `hubspot` connector reaches the HubSpot CRM v3 objects API (contacts,
companies, deals) through `saiifed`. The agent never sees the token. The
manifest is `crates/broker/connectors/hubspot.toml`, embedded at build time.

- Base URL `https://api.hubapi.com`, the only host the connector may call.
- Auth: `bearer`, a HubSpot private app token. The vault entry is a `token`
  secret.
- Request headers the agent may send: `Content-Type`, `Accept`.
  `Authorization`, `Cookie` and `Host` are always dropped.
- Vendor reference (paths and shapes):
  <https://developers.hubspot.com/docs/api/crm/contacts>,
  <https://developers.hubspot.com/docs/api/crm/companies>,
  <https://developers.hubspot.com/docs/api/crm/deals>.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `contacts.list` | `contacts:read` | read | `GET /crm/v3/objects/contacts` |
| `contacts.get` | `contacts:read` | read | `GET /crm/v3/objects/contacts/{contact_id}` |
| `contacts.update` | `contacts:write` | write | `PATCH /crm/v3/objects/contacts/{contact_id}` |
| `companies.list` | `companies:read` | read | `GET /crm/v3/objects/companies` |
| `companies.get` | `companies:read` | read | `GET /crm/v3/objects/companies/{company_id}` |
| `deals.list` | `deals:read` | read | `GET /crm/v3/objects/deals` |
| `deals.get` | `deals:read` | read | `GET /crm/v3/objects/deals/{deal_id}` |
| `deals.update` | `deals:write` | write | `PATCH /crm/v3/objects/deals/{deal_id}` |

Parameters:

- `*.list`: `limit` (1 to 100), `after` (the cursor), `properties`
  (comma-separated property names), `archived` (`true` or `false`).
- `*.get`: the object id (an integer, one path segment) and optionally
  `properties` and `archived`.
- `*.update`: the object id and a JSON body such as
  `{"properties":{"firstname":"Augusta"}}`. Send `Content-Type: application/json`.

There is no create, delete, search, batch or association operation in
wave 1. A call that matches no operation is denied as `unknown_operation`.
No operation has an `amount` field, so amount caps do not apply to HubSpot
in this version (a deal `amount` property is data, not a spend).

### The update body is not constrained

saiife validates the object id and the headers of `contacts.update` and
`deals.update`, but not the JSON body. An agent with `contacts:write` or
`deals:write` can set any property HubSpot lets the token write, including
`hubspot_owner_id`, `lifecyclestage` and `hs_*` properties. Keep both write
capabilities under `ask` (or denied), and limit the private app's scopes.

## Pagination

List answers carry `paging.next.after` when there is another page. saiife
returns it as `next`: the CLI prints `next: after=<cursor>` on stderr and
`/v1/api` sets `X-Saiife-Next`. Pass it back as `after=<cursor>` for the next
page. The last page has no `paging` key and no `next`.

```bash
saiife api hubspot contacts.list limit=100 properties=email,firstname
saiife api hubspot contacts.list limit=100 after=52
saiife api hubspot contacts.update contact_id=51 --body @patch.json
```

## Capabilities and policy

Capabilities are `<object>:<verb>`. Policy order is deny, then ask, then allow;
nothing matching means deny. Both policies below go in
`/etc/saiife/policy.d/hubspot.toml`.

## Suggested policy: read-only

```toml
[services.hubspot]
connector = "hubspot"
secret = "hubspot-prod"
allow = ["contacts:read", "companies:read", "deals:read"]
```

`contacts.update` and `deals.update` are denied (`default_deny`). The
manifest has no delete operation, so there is nothing to deny by name.

## Suggested policy: every write under `ask`

```toml
[services.hubspot]
connector = "hubspot"
secret = "hubspot-prod"
allow = ["contacts:read", "companies:read", "deals:read"]
ask   = ["contacts:write", "deals:write"]
```

Until plan 11 lands, `ask` answers deny with `rule = "approval_not_available"`.
Both policies are exercised by `crates/broker/tests/hubspot.rs`.

To keep personal data away from the agent, redact fields in the response:

```toml
[services.hubspot.redact]
fields = ["properties.email", "properties.phone"]
```

Redaction paths match as a suffix anywhere in the JSON tree. A non-JSON answer
on a service with `redact` is withheld.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s` (`[gateway] upstream_timeout`). Redirects are followed
  to the same host only, at most 3.
- Per-service `limits` in the policy (rate, bulk per session) count requests
  that were sent upstream, whatever their status. HubSpot's own API limits
  (burst and daily, per private app) still apply and come back as 429.
- The token is masked (raw, base64, URL-encoded and hex forms) in every
  response before the agent sees it.

## Locked mode

In locked mode (Linux and macOS) the agent user reaches HubSpot only through `saiifed`:
`saiife api hubspot ...`, or `gateway.sock` at `/v1/api` and `/v1/proxy`.
The token lives in the daemon's vault (`saiife secret add hubspot-prod`, or
`saiife connect hubspot`) and never reaches the agent's environment, files or
audit records. A project overlay can only add `deny` and `ask`; in locked mode
its `allow` is ignored. Every call is one `connector` audit record.

Create a private app in HubSpot with only the scopes the policy needs
(`crm.objects.contacts.read`, `crm.objects.companies.read`,
`crm.objects.deals.read`, and the `.write` scopes only if you allow writes), so
a policy mistake is bounded by the token.
