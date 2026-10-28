# Stripe connector

Connector id `stripe`, Stripe API v1, built into `saiife-broker`
(`crates/broker/connectors/stripe.toml`). The service starts with everything
denied: each capability below needs an `allow` (or `ask`) entry in the policy.

Paths follow the Stripe API reference (<https://docs.stripe.com/api>). This
page and the test fixtures were written offline, in the documented shape;
check them against the reference when Stripe changes the API.

## Setup

```sh
saiife secret add stripe-prod --kind token --service stripe   # a restricted key (rk_live_...) or secret key
```

Use a **restricted key** with only the read permissions you allow here, and
`Refunds: write` only if you allow `refunds:write`. The key goes out only in
the `Authorization: Bearer` header. Requests go only to `api.stripe.com`.

The service needs the admin parameter `currency`, the three-letter upper-case
code of the account's currency (`EUR`). It is set in the service config; the
agent cannot set it. Stripe amounts are integers in the currency's minor unit
(cents), and the broker reads a refund's amount in that currency.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `customers.list` | `customers:read` | read | `GET /customers`; query `limit` (1..100), `starting_after`, `email` |
| `customers.get` | `customers:read` | read | `GET /customers/{customer_id}` |
| `charges.list` | `charges:read` | read | `GET /charges`; query `limit`, `starting_after`, `customer`, `payment_intent` |
| `charges.get` | `charges:read` | read | `GET /charges/{charge_id}` |
| `payment_intents.list` | `payment_intents:read` | read | `GET /payment_intents`; query `limit`, `starting_after`, `customer` |
| `payment_intents.get` | `payment_intents:read` | read | `GET /payment_intents/{payment_intent_id}` |
| `invoices.list` | `invoices:read` | read | `GET /invoices`; query `limit`, `starting_after`, `customer`, `status` |
| `invoices.get` | `invoices:read` | read | `GET /invoices/{invoice_id}` |
| `refunds.list` | `refunds:read` | read | `GET /refunds`; query `limit`, `starting_after`, `charge`, `payment_intent` |
| `refunds.create` | `refunds:write` | write | `POST /refunds`, built form body, amount-checked |

Notes:

- Ids are checked by prefix: `cus_`, `ch_` or `py_`, `pi_`, `in_`, `re_`.
- Agents may send `Idempotency-Key` and `Accept`; every other request
  header is dropped. Send an `Idempotency-Key` on every refund so a retry
  cannot refund twice.
- **Pagination** is a cursor: `starting_after` is the id of the last object
  of the page, and the response's `has_more` says whether there is another
  page.
- **`refunds.create`** takes the call parameters `payment_intent` or `charge`,
  `amount` (an integer from 1 to 99999999, minor units) and `reason`
  (`duplicate`, `fraudulent`, `requested_by_customer`). The agent cannot send
  a body of its own: the broker builds the form body (`amount=500&charge=ch_...`).
  **A refund without `amount` is denied** (`bad_amount`), because a full
  refund has no amount the caps could count.
- **Set amount caps in the account currency.** The currency is the admin
  `currency` parameter; the agent cannot choose it.

## Suggested policy: read-only

`/etc/saiife/policy.d/stripe.toml`:

```toml
[services.stripe]
connector = "stripe"
secret = "stripe-prod"
params = { currency = "EUR" }
allow = ["customers:read", "charges:read", "payment_intents:read", "invoices:read", "refunds:read"]
deny  = ["refunds:write"]

[services.stripe.limits]
requests_per_minute = 60

[services.stripe.redact]
fields = ["email", "phone", "address", "shipping", "billing_details"]
```

## Suggested policy: every write under `ask`

```toml
[services.stripe]
connector = "stripe"
secret = "stripe-prod"
params = { currency = "EUR" }
allow = ["customers:read", "charges:read", "payment_intents:read", "invoices:read", "refunds:read"]
ask   = ["refunds:write"]

[services.stripe.limits]
requests_per_minute = 60
writes_per_hour = 20
amount_per_day = { max = 500, currency = "EUR" }

[services.stripe.redact]
fields = ["email", "phone", "address", "shipping", "billing_details"]
```

An `ask` waits for a human to approve the refund. To let an unattended agent
issue small refunds, move `refunds:write` to `allow`: `amount_per_day` still
caps the total, in EUR, and `amount_per_request` can cap each refund.

## Limits

- Writes count toward `writes_per_hour`. `amount_per_day` and
  `amount_per_request` apply to `refunds.create`.
- Stripe's own rate limit (100 operations per second in live mode) is
  separate; a `429` from Stripe is passed on.
- At most 4 upstream calls to Stripe are in flight at once.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the key lives
in the root-owned vault and never reaches the agent; calls go through the
gateway, which adds it. A project config can add `deny` and `ask` entries but
cannot add an `allow` or change the secret or the currency. Use `saiife api
stripe customers.list limit=10`, or the gateway at `/v1/api`; the exit codes
are those of `saiife api` (2 denied, 4 limit reached).
