# Shopify connector

Connector id `shopify`, Admin REST API version `2026-07`, built into
`saiife-broker` (`crates/broker/connectors/shopify.toml`). The service starts
with everything denied: each capability below needs an `allow` (or `ask`)
entry in the policy.

Paths follow the Shopify Admin REST reference
(<https://shopify.dev/docs/api/admin-rest/2026-07/>). This page and the test
fixtures were written offline, in the documented shape; check them against
the reference when you bump the API version.

## Setup

```sh
saiife secret add shopify-prod --kind token --service shopify   # the Admin API access token (shpat_...)
```

The token goes out only in the `X-Shopify-Access-Token` header. `shop` is the
store's subdomain (`acme` for `acme.myshopify.com`). The admin sets it in the
service config; the agent cannot. It must match `^[a-z0-9-]+$`, and requests
go only to `*.myshopify.com`.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `orders.list` | `orders:read` | read | `GET /orders.json`; query `status` (`open`, `closed`, `cancelled`, `any`), `limit` (1..250), `since_id`, `created_at_min`, `page_info` |
| `orders.get` | `orders:read` | read | `GET /orders/{order_id}.json` |
| `products.list` | `products:read` | read | `GET /products.json`; query `status` (`active`, `archived`, `draft`), `limit` (1..250), `since_id`, `created_at_min`, `page_info` |
| `products.get` | `products:read` | read | `GET /products/{product_id}.json` |
| `products.update` | `products:write` | write | `PUT /products/{product_id}.json`, JSON body |
| `customers.list` | `customers:read` | read | `GET /customers.json`; query `limit` (1..250), `since_id`, `created_at_min`, `page_info` |
| `customers.export` | `customers:export` | bulk | `GET /customers/search.json`; query `query` (1..256 characters), `limit` (1..250), `order` (`<field> asc` or `<field> desc`), `page_info` |
| `refunds.create` | `refunds:write` | write | `POST /orders/{order_id}/refunds.json`, JSON body, amount-checked |
| `discounts.create` | `discounts:write` | write | `POST /price_rules.json`, JSON body |

Notes:

- `*_id` path parameters are integers.
- Agents may send `Content-Type`, `Accept` and `Idempotency-Key`; every other
  request header is dropped.
- **Pagination** is the `Link` header. The `rel="next"` URL holds a
  `page_info` value; pass it back as `page_info=...` (with the same `limit`)
  to get the next page. Shopify refuses other filters together with
  `page_info`.
- **`customers.export`**: the REST API has no export endpoint (exports are
  GraphQL bulk operations, which saiife does not expose in this version). The
  operation is the largest REST read of customers, the search at 250 per page.
  It is kind `bulk`, so `bulk_per_session` limits it, and it has its own
  capability so that `customers:read` does not include it.
- **Warning: `customers:export` reads every customer's personal data**
  (names, emails, phones, addresses). Keep it denied, or under `ask` with
  `bulk_per_session = 1` and `redact` on the contact fields. Do not allow it
  to an unattended agent.
- **`discounts:write` and `products:write` have no amount cap.** A discount
  or a price change can cost money and the caps do not see it. Keep both
  under `ask`.
- **Set amount caps in the shop's currency.** A refund in another currency
  is denied (`amount_currency`), and the agent-declared `refund.currency` is
  not trusted beyond that.
- **`discounts.create`** is the price-rule `POST` only. Adding discount codes
  to the rule (`POST /price_rules/{id}/discount_codes.json`) is not in this
  version.
- **`refunds.create`** is checked against the amount caps: the amounts are
  the sum of `refund.transactions[].amount` (decimal strings in major units)
  with `refund.currency`. A body without a currency or an amount is refused.

## Suggested policy: read-only

`/etc/saiife/policy.d/shopify.toml`:

```toml
[services.shopify]
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme" }
allow = ["orders:read", "products:read"]
deny  = ["customers:export"]

[services.shopify.limits]
requests_per_minute = 60
bulk_per_session = 1

[services.shopify.redact]
fields = ["customer.email", "customer.phone"]
```

`customers:read` is left out on purpose: customer records hold personal
data. Add it only if the agent needs it, and keep the `redact` fields.

## Suggested policy: every write under `ask`

```toml
[services.shopify]
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme" }
allow = ["orders:read", "products:read"]
ask   = ["products:write", "refunds:write", "discounts:write", "customers:export"]

[services.shopify.limits]
requests_per_minute = 60
writes_per_hour = 50
bulk_per_session = 1
amount_per_day = { max = 500, currency = "EUR" }

[services.shopify.redact]
fields = ["customer.email", "customer.phone"]
```

Until plan 11 ships approvals, an `ask` is answered with a deny
(`rule = "approval_not_available"`). To let an unattended agent issue small
refunds, move `refunds:write` from `ask` to `allow`: `amount_per_day` still
caps the total, in EUR major units, and a refund in another currency is
denied.

## Limits

- Writes count toward `writes_per_hour`; `customers.export` counts toward
  `bulk_per_session`.
- `amount_per_day` and `amount_per_request` apply to `refunds.create` only.
  `discounts.create` and `products.update` have no amount (the discount value is
  a string with a sign and a type, so it cannot be capped as money).
- Shopify's own rate limit (a leaky bucket, 2 requests per second on the
  standard plan) is separate; a `429` from Shopify is passed on.
- At most 4 upstream calls to Shopify are in flight at once.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the token
lives in the root-owned vault and never reaches the agent; calls go through
the gateway, which adds it. A project config can add `deny`
and `ask` entries (for example `deny = ["products:write"]`) but cannot add an
`allow` or change the secret or the shop. Use `saiife api shopify
orders.list status=open limit=50`, or the gateway at `/v1/api`; the
exit codes are those of `saiife api` (2 denied, 4 limit reached).
