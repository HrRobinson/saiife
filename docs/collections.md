# Collections

A collection is a saved list of connector calls, kept in the project as
`.saiife/collections/<name>.toml`. It is a named request, not a flow engine:
the steps run in order and nothing branches.

```toml
name = "open-orders-report"

[[step]]
service = "shopify"
operation = "orders.list"
params = { status = "{{status}}", limit = "250" }
```

```
saiife api collection list [--json]
saiife api collection run <name> [k=v ...]
```

## Rules

- Each step is one ordinary `saiife api` call. It passes through the whole
  pipeline: scope, parameter checks, policy, limits, approvals, masking and
  the audit record. A collection can do no more than its steps could do one
  by one, so an agent may write one. Each record carries the collection's
  name.
- `{{var}}` placeholders (`[a-z_][a-z0-9_]{0,31}`) are filled from the
  `k=v` arguments. They are allowed only in `params` values and in string
  values of a step `body`; `service` and `operation` cannot hold one. Every
  variable is checked before the first step runs, and a value is inserted
  as text, never parsed again, so it cannot name another service or
  operation.
  A missing or an unused variable is an error.
- Unknown keys are refused at the top and in a step. A collection has at
  most 32 steps, and its file is at most 64 KiB.
- A step that is denied, limited or pending stops the run, with that step's
  exit code. A pending step prints its request id. There is no resume.
- `--wait` and `--body` do not apply to a collection.
- stdout is a JSON array with `step`, `service`, `operation`, `status` and
  `data` for each step that was answered. stderr has one summary line per
  step.
