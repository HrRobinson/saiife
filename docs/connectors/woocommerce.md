# WooCommerce connector

The `woocommerce` connector reaches the WooCommerce REST API v3 (orders,
products, customers, refunds) of one shop through `saiifed`. The agent never
sees the consumer key or secret. The manifest is
`crates/broker/connectors/woocommerce.toml`, embedded at build time.

- Base URL `https://{host}/wp-json/wc/v3`. `host` is a service param set by the
  admin: a bare lower-case hostname, and the only host the connector may call.
  The agent cannot change it, and a redirect to another host is refused.
- Auth: `basic`, the REST API consumer key (user name) and consumer secret
  (password). The vault entry is a `basic` secret. Query-string
  authentication (`consumer_key=...` in the URL) is not supported, because it
  would put the secrets in URLs.
- `currency` is a required service param (for example `EUR`): the shop's
  currency, which refund amounts are counted in.
- Request headers the agent may send: `Content-Type`, `Accept`.
  `Authorization`, `Cookie` and `Host` are always dropped.
- Vendor reference: <https://woocommerce.github.io/woocommerce-rest-api-docs/>.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `orders.list` | `orders:read` | read | `GET /orders` |
| `orders.get` | `orders:read` | read | `GET /orders/{order_id}` |
| `orders.update` | `orders:write` | write | `PUT /orders/{order_id}` |
| `products.list` | `products:read` | read | `GET /products` |
| `products.get` | `products:read` | read | `GET /products/{product_id}` |
| `products.update` | `products:write` | write | `PUT /products/{product_id}` |
| `customers.list` | `customers:read` | read | `GET /customers` |
| `refunds.create` | `refunds:write` | write | `POST /orders/{order_id}/refunds` |

Parameters:

- `*.list`: `page`, `per_page` (1 to 100) and filters such as `status`,
  `search`, `after`, `orderby`, `order`.
- `*.get`: the id (an integer).
- `orders.update`: the order id and the params `status` (one of `pending`,
  `processing`, `on-hold`, `completed`, `cancelled`, `failed`; not `refunded`)
  and `customer_note` (up to 1000 characters, may span lines). saiife builds
  the JSON body; there is no raw body, so an order update cannot refund an
  order or change line items, fees or totals. Refunds go through
  `refunds.create` and its amount cap.
- `products.update`: the id and a JSON body such as
  `{"regular_price":"24.00"}`. Send `Content-Type: application/json`.
- `refunds.create`: the order id and the params `amount` (a decimal string,
  required) and `reason` (optional, may span lines). saiife builds the JSON
  body; there is no raw body, so the agent cannot send `line_items` or
  `meta_data`. `api_refund` is fixed to `false`: WooCommerce would otherwise
  also refund through the payment gateway, so the refund only records it and
  money moves through your payment provider.

There is no delete, create or batch operation for orders, products or
customers. A call that matches no operation is denied as `unknown_operation`.

### Refund amounts

`refunds.create` carries an `amount` spec: the body field `amount` (a decimal
string in major units) in the `currency` service param. Amount limits (`max`
per call, daily caps) count it. A refund with no `amount` is denied
(`bad_amount`).

### The product update body is not constrained

saiife validates the ids and headers of `products.update`, not the JSON body.
With `products:write` an agent can change prices and stock. Keep both under `ask`, and give the REST key the least
permission (Read, or Read/Write only if you allow writes).

## Pagination

List answers carry a `Link` header with `rel="next"` while there is another
page. saiife returns the next page's `page` (and your other query params) as
`next`: the CLI prints `next: page=2` on stderr and `/v1/api` sets
`X-Saiife-Next`. Pass it back for the next page. The last page has no `next`.

```bash
saiife api woo orders.list per_page=100 status=processing
saiife api woo orders.list per_page=100 status=processing page=2
saiife api woo refunds.create order_id=727 amount=10.00 reason='wrong size'
```

## Capabilities and policy

Capabilities are `<object>:<verb>`. Policy order is deny, then ask, then allow;
nothing matching means deny. Both policies below go in
`/etc/saiife/policy.d/woocommerce.toml`.

## Suggested policy: read-only

```toml
[services.woo]
connector = "woocommerce"
secret = "woo-prod"
allow = ["orders:read", "products:read", "customers:read"]

[services.woo.params]
host = "shop.acme.com"
currency = "EUR"
```

All three write capabilities are denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.woo]
connector = "woocommerce"
secret = "woo-prod"
allow = ["orders:read", "products:read", "customers:read"]
ask   = ["orders:write", "products:write", "refunds:write"]

[services.woo.params]
host = "shop.acme.com"
currency = "EUR"
```

Both policies are exercised by `crates/broker/tests/woocommerce.rs`.

To keep customer data away from the agent, redact fields in the response:

```toml
[services.woo.redact]
fields = ["email", "phone", "billing", "shipping"]
```

Redaction paths match as a suffix anywhere in the JSON tree. A non-JSON answer
on a service with `redact` is withheld.

## Limits

- At most 4 upstream calls in flight per service.
- Responses over `max_response_bytes` (default 5 242 880) are cut off.
- Upstream timeout `30s` (`[gateway] upstream_timeout`). Redirects are followed
  to the same host only, at most 3.
- Per-service `limits` in the policy (rate, bulk per session, amount caps) count
  requests that were sent upstream, whatever their status.
- The consumer key, the secret and the basic-auth pair are masked (raw, base64,
  URL-encoded and hex forms) in every response before the agent sees them.

## Locked mode

In locked mode (Linux) the agent user reaches the shop only through `saiifed`:
`saiife api woo ...`, or `gateway.sock` at `/v1/api` and `/v1/proxy`. The
consumer key and secret live in the daemon's vault (`saiife secret add woo-prod
--kind basic`, or `saiife connect woocommerce`) and never reach the agent's
environment, files or audit records. A project overlay can only add `deny` and
`ask`; in locked mode its `allow` is ignored. Every call is one `connector`
audit record. On macOS the commands print `saiife: locked mode needs Linux in
this version (macOS: v2.1)` and exit 5.
