# Plan 14 — Connector waves 2 and 3, environments, collections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fourteen new connectors reach the broker the same way wave 1 did: wave 2 (Stripe, Slack, Linear, Sentry, GitLab, PagerDuty, Discord) and wave 3 (Salesforce with OAuth2, Intercom, Zendesk, Airtable, Segment, WooCommerce, Email with SMTP send and IMAP read). Each one ships with a manifest, typed parameters, masking for its token shapes, an offline mock-backed test suite and a docs page. Admins bind an **environment** to a scope, which overlays packs and service settings, and the effective-policy hash names it. Agents run **collections**: saved, named requests in `.saiife/collections/<name>.toml`, where every step goes through the full pipeline.

**Architecture:**
- Wave 1 showed that the §8.4 schema fits plain REST with a fixed host. The new connectors need a few more manifest features, and Task 1 adds all of them to `crates/broker` before any connector lands:
  - host placeholders taken from admin params;
  - a header-auth `prefix`, and a `basic_token` auth kind;
  - fixed request `headers`;
  - bodies built from typed `body_params` and `body_const`, in JSON, form or GraphQL form;
  - `Cursor.more`, `Offset` pagination, and stopping on Link `results="false"`;
  - an `amount.currency_param`.
- After that, a connector task is only TOML, fixtures, golden files, tests and a docs page.
- Built-in manifests are listed by a `build.rs` scan of `connectors/`, so the connector tasks share no file.
- Two connectors need their own machinery:
  - **Email** adds a `transport = "mail"` backend in the broker. It holds the SMTP client, moved from `daemon/smtp.rs`, and a small IMAP client.
  - **Salesforce** adds the `oauth2` vault kind, and a daemon token cache that refreshes access tokens and stores rotated refresh tokens.
- Environments live in `policy` (tokio-free). The daemon keeps one `PolicySnapshot` per environment. Collections are a CLI loop over ordinary `api.call`s.

**Tech Stack:** Rust workspace. New dependencies, in `broker` only:
- `imap-proto = "=0.16.7"` (2026-04-21): it uses `nom ^7`, which reuses `nom 7.1.3`, already in Cargo.lock. 0.17.0 (2026-09-28) would pull `nom 8`.
- `mail-parser = { version = "=0.11.9", default-features = false }` (2026-09-09). 1.0.0 is from 2026-10-24, which is younger than 14 days.

Everything else reuses what the broker already pins: tokio 1.53.2, rustls ring, tokio-rustls, base64, zeroize, sha2.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §15.2 row 14;
- §6.8.3 waves 2 and 3;
- §6.6 (the `oauth2` kind; "OAuth2 refresh tokens are refreshed by the daemon. A failed refresh is a `secret`/`refresh_failed` record and a notification");
- §6.8.1 and §8.4 (schema additions);
- §6.8 (`connect` with "an OAuth2 device or paste flow");
- §6.9.4 (Stripe refunds);
- §6.11 (environments);
- §6.12 (collections);
- §6.7.2 (`saiife api collection list|run`);
- §7 rows `saiife env`, `saiife api collection`;
- §8.1 `[[scope]] env`;
- §8.2 `env`;
- §9.2 A17;
- §17 question 2.

Plans 10 (the wave-1 pattern), 11 and 12 set the style.

## Global Constraints

- **No privileged or process-control tools on the dev machine.** Never run sudo, root, systemctl, polkit tools, docker, kill, pkill, killall or pgrep. This holds for implementers and reviewers. CI-only scripts are validated with `bash -n` only.
- **Test isolation:** set `TMPDIR` and `SAIIFE_TEST_TMP` to a short dir made by `mktemp -d -p /home/jonas/projects/personal/saiife`, and remove it afterwards. Never use /tmp, the real home or `~/.claude`.
- **Internet:** implementers may use web access ONLY to fetch public reference data, such as vendor API docs (to check paths) and documented example responses for fixtures. Tests themselves never use the network.
- **No internet in tests.** Every upstream is a loopback mock with an `rcgen` certificate, trusted through `Upstream::with_roots`, with names resolved through the injected `Resolver`:
  - HTTPS, the Salesforce token endpoint, and SMTP and IMAP over TLS.
  - `scripts/test-offline.sh` stays green.
  - Fixtures are shaped from each vendor's documented examples. The docs URL goes in a comment at the top of the manifest, as in wave 1.
- **Hook path untouched:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free. The new mask rules live in `audit` (Task 2) and the environment code in `policy` (Task 3); both are sync. `scripts/bench-check.sh` medians for `saiife check` stay within +1 ms of `main`.
- **`#![forbid(unsafe_code)]`** in `broker`. Secret values never appear in a record, an error, a log line, `Debug` output or a panic. Each new test greps its audit files and stderr for every secret value it used.
- **Commits:**
  - The branch is `plan-14-connectors` from `main`.
  - Each task is committed in its worktree and cherry-picked onto the plan branch, with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Never commit `.superpowers/`.
  - **Never commit token-shaped test literals** (GitHub push protection blocks `sk_live_…`, `xoxb-…`, `glpat-…` and the like). Build them at runtime with `concat!`/`format!`, as `mask.rs` does with `format!("ghp_{}", …)`.
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`.
  - No tags.
- **Spec values, verbatim:**
  - Wave 2: "Stripe, Slack, Linear, Sentry, GitLab, PagerDuty, Discord".
  - Wave 3: "Salesforce (OAuth2), Intercom, Zendesk, Airtable, Segment, WooCommerce, Email (SMTP send; IMAP read)".
  - "Each connector ships with a docs page (operations, capabilities, a suggested read-only policy) and an offline test suite against a mock server built from the vendor's documented responses." "The suggested policy on each docs page puts every write under `ask`."
  - Environments: "An environment adds packs and overrides service settings (secret, parameters, rule lists, limits) on top of the base config. It cannot turn off a default-on pack." `[[scope]] env = "prod"`. "The project path never chooses it." `saiife env use <name> --scope <scope>` "needs admin rights and rewrites that binding". "The current environment is part of the effective-policy hash." Developer and personal broker modes: `saiife env use <name>` "writes `env = "<name>"` into `.saiife/config.toml`". `saiife env list` "shows the environments and which one applies here".
  - Collections: `.saiife/collections/<name>.toml` with `name` and `[[step]] service, operation, params`. "Collections may be written by the agent: each step still goes through the full pipeline." `saiife api collection run <name> [k=v …]` "fills `{{var}}` placeholders". "They are named requests, not a flow engine."
  - Vault kind `oauth2`; the record is `secret`/`refresh_failed`.
  - `saiife api` exit codes: 0 done, 1 upstream ≥ 400, 2 denied, 3 pending, 4 limit, 5 unavailable.
- **Decisions this plan makes** (each is restated in its task):
  1. **`base_url` hosts come in two forms.** Service params are admin-only, so in both forms the pin stays an admin decision.
     - **Whole-host placeholder.** A `hosts` entry may be `{param}`. The param must be declared `required` with an anchored hostname `pattern`, and the `base_url` host must be exactly that placeholder. This serves GitLab, Sentry, WooCommerce, Salesforce and Email.
     - **Fixed host list.** `hosts` lists literal hosts or `*.suffix` globs (the wave-1 form). The `base_url` host may be a fixed host, a whole-host `{param}` that must match one listed entry, or a label template such as `{subdomain}.zendesk.com`. The filled host is checked against the list at build time, as `checked_uri` does today. This serves Zendesk (`*.zendesk.com`), Intercom (three regional hosts) and Segment (two hosts).
     - Plan 15 adds the in-label placeholder form for cloud hosts on top of this schema; it does not redefine it.
  2. **Built bodies.**
     - `body_params = { name = "<type>" }` are typed call params placed into the body, with a dotted name nesting into objects. `body_const = { "a.b" = <toml value> }` holds fixed fields. When `body_params` is set, an agent-supplied raw body is refused (`bad_param`).
     - `body = "form"` encodes the built object Stripe-style (`a[b]=v`).
     - `graphql = "<query>"` sends `{"query": <fixed>, "variables": <built>}`. The agent can never send its own GraphQL.
     - A qualifier may name a `body_params` key, which is how Slack and Discord channels become qualifiers (§6.9.1).
     - Operations with `graphql` are named-only: proxy resolution skips them, and they are exempt from the path-shape uniqueness check.
  3. **Amounts without a body currency:** `amount = { field, currency_param, unit }` takes the currency from an admin service param (Stripe, WooCommerce). This is mutually exclusive with `currency_field`. A Stripe refund must carry `amount`; a full refund without one is denied `bad_amount` (fail closed, as today).
  4. **Pagination:**
     - `Cursor { param, next, more? }`. `next` may use `[-1]` (the last array element), and `more` is a JSON bool path; `false` means last page.
     - `Offset { param, limit_field, more }` sets the next offset to `body[param] + body[limit_field]` when `body[more]` is true (PagerDuty).
     - A Link `rel="next"` carrying `results="false"` is the last page (Sentry).
     - An empty cursor string is the last page (Slack).
     - Salesforce and Discord return no `next`. Their docs pages show the follow-up call (`query.more locator=…`, `before=<id>`).
  5. **Auth additions:**
     - `header` auth takes an optional `prefix`, printable ASCII: PagerDuty `Token token=`, Discord `Bot `, Linear raw `Authorization`.
     - A new kind `basic_token` sends `Basic base64(token + ":")`, for the Segment write key.
     - A new kind `oauth2` carries `token_path`.
     - Vault `token` secrets serve `bearer`, `header` with `secret_field = "token"`, and `basic_token`. `basic` serves `basic`, and `oauth2` serves `oauth2`.
  6. **Fixed headers:** `headers = { Name = "literal or {param}" }` are set by the broker after the agent's headers and win over them (PagerDuty `Accept` and `From`, `Intercom-Version`).
  7. **Built-in list:** `crates/broker/build.rs` writes `$OUT_DIR/builtin.rs` from `connectors/*.toml`, sorted, skipping `test-echo.toml`. Connector tasks add files only.
  8. **OAuth2 (Salesforce):**
     - Paste flow only: `secret add --kind oauth2` prompts for `client_id`, `client_secret` and `refresh_token` without echo. A device flow is not built (the spec says "or").
     - The access token lives **only in daemon memory** (`Zeroizing`), never in the vault.
     - The token endpoint is `https://{instance_host}{token_path}` with `token_path = "/services/oauth2/token"`, so it is pinned to the admin host.
     - A refresh happens on first use, when the cached token is older than `expires_in` (or 15 min when it is absent) minus 60 s, and once on an upstream 401. A 401 retries the request once; Salesforce refuses an invalid session before doing anything.
     - Refreshes are single-flight per secret.
     - The response's `instance_url` host must equal `instance_host`, or the refresh fails.
     - A rotated `refresh_token` is written to the vault **before** the access token is used. If that write fails, the new token is kept in memory, the call is denied `vault_unavailable`, and `refresh_failed` is recorded (`reason = "persist"`). The next call retries the write.
     - Failures are a `secret`/`refresh_failed` record (name, service, reason; never a body) and a `refresh_failed` notification (new `Event::RefreshFailed`, in the default `on` list), at most once per secret per hour.
     - `secret rotate`/`remove` drops the cache entry.
  9. **Email:**
     - `transport = "mail"`. The operations are `mail.send` (write, **one** `to` per call, so `when = { to = "*@acme.com" }` and the qualifier `to={to}` work), `folders.list`, `mail.list` and `mail.get` (read).
     - `From` is the admin param `from`. The body is plain text (`body = "text"`, UTF-8, at most 256 KiB).
     - IMAP uses implicit TLS (993) or **required** STARTTLS (143), `EXAMINE` (never `SELECT`) and `BODY.PEEK`, so reads never set `\Seen`. Auth is `AUTHENTICATE PLAIN`, or `LOGIN` only after TLS.
     - No delete, move or flag operations.
     - The proxy path is refused for mail (`unknown_operation`).
     - IMAP crate: hand-rolled IO over the broker's TLS (like `smtp.rs`) with `imap-proto` as the parser, and `mail-parser` for MIME. No IMAP client crate, because `async-imap` would add async-std/futures stacks.
  10. **Environments:**
      - `[environments.<name>]` sits in the system config: `/etc` in locked mode, and the personal broker's config.
      - Its keys are `guard.packs` (added) and `services.<svc>.{secret, params, fixed, allow, ask, deny, rule, limits, redact}`. Each key that is present replaces the base value, except `params`, `fixed` and `limits`, which merge per field. `connector`, `base_url` and `operation` cannot be overridden (`deny_unknown_fields`).
      - An environment may only name services that exist in the base config.
      - A `[[scope]] env` that names no defined environment refuses the policy.
      - In locked mode, `env use --scope` is **root only**: it edits the root-owned file that holds the scope, with `toml_edit`, then calls `policy.reload`. Admin-group members get `needs root: <file> is root-owned`.
      - In developer mode, a project `env` naming an undefined environment is a warning, and the base config is used.
  11. **Collections:**
      - `{{var}}` is allowed in `params` values and in string values of an optional inline `body` table, never in `service` or `operation`.
      - Names are `[a-z0-9_-]{1,64}`, and the file stem must equal `name`. At most 32 steps; the file is at most 64 KiB.
      - A missing or an unused variable is an error before any step runs. A filled value is literal: no re-expansion.
      - Steps run in order. The run stops at the first step that is not done, with that step's exit code. A pending step prints its id and stops; there is no resume.
      - Output is a JSON array of `{step, service, operation, status, data}`.
      - Each `api.call` carries `collection = "<name>"`, recorded as attribution only.
      - `collection`, `result`, `token` and `saiife` are reserved service names (a config error).
  12. **Records:** connector records gain `env` (or null) and `collection` (or null). Guard records in locked mode use the hash of the env-applied policy.
  13. **Spec notes.** These depart from the spec text. Task 14 adds them to the spec, and the owner confirms them (Owner handwork):
      - §6.11 says `env use --scope` "needs admin rights". This plan makes it **root only**, because the binding lives in root-owned `/etc` files the daemon cannot write.
      - §6.8 offers "an OAuth2 device or paste flow". This plan builds the **paste flow only**; there is no device flow.

## Review Focus

1. **A host param that escapes the pin**, such as `gitlab.acme.com@evil.test`, `evil.test/x`, `evil.test:8443` or an uppercase or trailing-dot variant. Expected: refused at policy load by the param pattern check. A redirect to another host is still refused at send (Task 1: `host_param_must_be_bare_hostname`, `host_placeholder_pins_admin_host`).
2. **A rotated Salesforce refresh token that gets lost**, or two cold calls racing. Expected: one refresh. The new refresh token is in the vault before the access token is used. A failed vault write keeps it in memory and records `refresh_failed`. A token response whose `instance_url` points elsewhere is refused (Task 7: `concurrent_cold_calls_refresh_once`, `rotated_refresh_token_persisted_first`, `persist_failure_keeps_token_in_memory`, `instance_url_mismatch_refused`).
3. **A collection value that tries to become structure**, such as a `{{var}}` value holding `}}{{other}}`, `\r\n`, or a `service=` override. Expected: the value is literal and never re-expanded. Placeholders in `service`/`operation` are refused. Each step is an ordinary `api.call` with the full pipeline (Task 5: `filled_value_is_literal`, `placeholder_in_operation_refused`, `each_step_is_one_api_call`).
4. **An environment that loosens what it must not**: removing a default-on pack, a project picking `env` in locked mode, a scope bound to an undefined environment, or an override of `connector`/`base_url`. Expected: refused or ignored. Each environment has its own policy hash in the records (Task 3: `env_cannot_drop_default_pack`, `locked_project_env_ignored`, `scope_env_undefined_refuses_policy`, `env_cannot_override_connector`, `hash_differs_per_env`).
5. **A hostile mail server**: no STARTTLS offered, a 2 GiB literal, a never-ending line, or CRLF in `subject` or `to`. Expected: refused before credentials are sent, cut at the read limit, step timeouts, and `bad_value` before connecting (Task 6: `starttls_missing_refused_before_auth`, `literal_over_limit_refused`, `crlf_in_subject_rejected`, `examine_never_select`).

---

## Task order and parallelism

**Plan 16 merges first; this plan rebases onto it and owns the integration rows.** The rows that depend on plan 16 are: Task 3's per-env validation through `check_services_owned`/`load_policy`, Task 3's Developer-mode env choice through `Ctx.mode`, and Task 4's use of `cli::broker::resolve`. New `CtxInit` fields use `..` defaults.

- **Wave 1, in parallel:**
  - Task 1 (broker schema; the critical path);
  - Task 2 (mask shapes);
  - Task 3 (environments core).
- **Wave 2, after Task 1:**
  - Tasks 4 (env CLI; also needs 3), 5, 6, 7, 8, 9, 10 and 11, in parallel.
  - Tasks 6 and 7 both edit `pipeline.rs` step 9: land 6 first and rebase 7.
  - Tasks 8–11 also need Task 2 for their mask tests.
- **Wave 3:**
  - Task 12 (Salesforce; needs 7);
  - Task 13 (Email; needs 6);
  - Task 14 (index, docs check, `connect` kinds; needs 8–13).
- **Last:** the gates, the whole-branch review, one fix wave, push, PR and CI. The owner merges.

**Shared files with plan 16 (personal broker, built in parallel).** Every change to these is additive. `crates/policy/src/system.rs` is not shared: plan 16 does not touch it.
- `crates/daemon/src/vault.rs`: `Kind::OAuth2` variant.
- `crates/daemon/src/secret_ops.rs`: `parse_kind`/`field_names` arms.
- `crates/daemon/src/ops.rs`: per-env snapshots in `GatewayPolicy`.
- `crates/daemon/src/api_ops.rs`: `spec_for` arms, snapshot choice, the `collection` arg, `oauth_token`.
- `crates/cli/src/secret_cmd.rs`: oauth2 prompts.
- `crates/cli/src/connect_cmd.rs`: `secret_kind` arms.
- `crates/cli/src/main.rs`: the `env` subcommand.
- `crates/cli/src/api_cmd.rs`: `collection` dispatch and `call_one` (Task 5). Plan 16 changes how the CLI connects (`cli::broker::connect`); `call_one` takes the connected client.
- `crates/daemon/src/start.rs`: per-env snapshots are built where plan 16's `load_policy` runs (Task 3).

No change to `crates/ipc/src/msg.rs`.

---

### Task 1: broker schema additions for waves 2 and 3

**Files:**
- Create: `crates/broker/build.rs`, `crates/broker/tests/schema.rs`, `crates/broker/tests/docs_pages.rs`.
- Modify:
  - `crates/broker/src/manifest.rs`: `BUILTIN` from `include!(concat!(env!("OUT_DIR"), "/builtin.rs"))`, plus the new keys and checks;
  - `crates/broker/src/request.rs`: hosts, auth, headers, body building, `next_cursor`;
  - `crates/broker/src/params.rs`: body params validated like query params;
  - `crates/broker/src/resolve.rs`: proxy skips `graphql` ops;
  - `crates/broker/src/amount.rs`;
  - `crates/broker/src/pipeline.rs`: body section, `next_page`;
  - `crates/daemon/src/api_ops.rs`: `spec_for`, so `Kind::Token` also matches `basic_token`.

**Interfaces (produces):** the semantics are those of decisions 1–7; only the types are given here.
- `AuthSpec` gains `prefix: Option<String>` and `token_path: Option<String>`. `AUTH_KINDS` adds `basic_token` and `oauth2`.
- `Manifest` gains `headers: BTreeMap<String, String>` and `transport: Transport` (`#[serde(default)] enum Transport { Https, Mail }`). `check()` refuses `Mail` until Task 6.
- `Operation` gains `body_params: BTreeMap<String, String>`, `body_const: BTreeMap<String, toml::Value>` and `graphql: Option<String>`. `body` takes `json | form | text`; `text` is mail only.
- `Pagination::Cursor` gains `more: Option<String>`, and there is a new `Pagination::Offset { param, limit_field, more }`.
- `AmountSpec` changes to `currency_field: Option<String>` plus `currency_param: Option<String>`.
- `request.rs`:
  - `pub fn build_body(op: &Operation, params: &BTreeMap<String, String>) -> Result<Option<Value>, BrokerError>`
  - `pub fn form_encode(v: &Value) -> Result<String, BrokerError>`
- `amount::extract` gains `svc_params: &BTreeMap<String, String>`.
- `body_sha256` is the hash of the bytes sent, and the amount is read from the strict JSON before form encoding.

- [ ] **Step 1: Failing tests** in `tests/schema.rs`, using inline test manifests:
  - `host_placeholder_pins_admin_host`: `hosts = ["{host}"]` with `params.host = "gitlab.acme.test"` builds; a redirect to `other.test` is refused.
  - `host_param_must_be_bare_hostname`: the table `gitlab.acme.com@evil.test`, `evil.test/x`, `evil.test:8443`, `EVIL.test.` and `` (empty) fails `catalog::validate`.
  - `host_placeholder_needs_required_pattern`: `Manifest::check` errors without `required` or without `pattern`.
  - `header_prefix_applied`: `Authorization: Token token=<v>`.
  - `prefix_refused_on_bearer`.
  - `basic_token_encodes_token_colon`.
  - `fixed_headers_override_agent`: an agent `From: x` is replaced by `{from}`, and `Accept` is the fixed value.
  - `body_params_build_nested_json`: `incident.title` gives `{"incident":{"title":…}}`, merged with `body_const`.
  - `raw_body_refused_when_body_params`.
  - `graphql_envelope`: `{"query": <fixed>, "variables": {"first": 10, "after": "x"}}`.
  - `graphql_op_not_reachable_by_proxy`.
  - `two_graphql_ops_same_path_allowed`.
  - `qualifier_from_body_param`: `messages:write:channel=C1`.
  - `form_encode_stripe_nesting`: `{"metadata":{"a":"1"},"amount":500}` gives `amount=500&metadata%5Ba%5D=1`, sorted.
  - `form_body_amount_checked_and_hash_of_sent_bytes`.
  - `currency_param_amount`: `currency_param = "currency"` with `params.currency = "EUR"` and `amount = 1250` (minor) gives `(1250, "EUR")`.
  - `both_currency_keys_refused`.
  - `cursor_more_false_stops`.
  - `cursor_last_element_path`: `data[-1].id` with `has_more = true` gives `starting_after=<id>`.
  - `empty_cursor_is_last_page`.
  - `offset_next`: `offset=25, limit=25, more=true` gives `offset=50`, and `more=false` gives `None`.
  - `link_results_false_is_last_page`.
  - `build_rs_lists_every_connector_file`: `builtin()` ids equal the `connectors/*.toml` stems without `test-echo`.
- [ ] **Step 2: Failing tests** in `tests/docs_pages.rs`. They apply to every built-in manifest, so each connector task is checked for free:
  - `every_connector_has_a_docs_page`: `docs/connectors/<id>.md` exists and contains `## Locked mode` and `## Suggested policy`.
  - `docs_policies_validate`: every ```` ```toml ```` block on the page that starts with `[services.` parses as a policy fragment. It is merged into a minimal `version = 2` config and passes `catalog::validate` with **zero warnings**.
  - `docs_writes_under_ask`: the policy block headed "every write under `ask`" decides `Ask` for every `write`/`delete`/`bulk` op of the manifest.
  - Fix wave-1 pages only where these tests show drift.
- [ ] **Step 3:** run `cargo test -p saiife-broker`. It fails.
- [ ] **Step 4:** implement. Then run `cargo test --workspace` (wave-1 golden files unchanged) and clippy with `-D warnings`.
- [ ] **Step 5:** commit `feat(broker): manifest schema for waves 2 and 3 (host params, built bodies, pagination, auth prefixes)`.

### Task 2: mask shapes for the new services

**Files:** Modify `crates/audit/src/mask.rs`: add the new rules as **one** alternation regex after the GitHub rules, for one extra pass on the hook path.

**Shapes:**
- Stripe: `(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}` and `whsec_[A-Za-z0-9]{24,}`.
- Slack: `xox[abposr]-[A-Za-z0-9-]{10,}` and `xapp-[A-Za-z0-9-]{10,}`. The path of a `hooks.slack.com/services/` URL.
- Linear: `lin_(?:api|oauth)_[A-Za-z0-9]{32,}`.
- Sentry: `sntr[ysu]_[A-Za-z0-9+/=_-]{20,}`.
- GitLab: `gl(?:pat|dt|ptt|rt|oas)-[A-Za-z0-9_-]{20,}`.
- Discord: bot tokens `[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}`, and the path of a `discord(?:app)?.com/api/webhooks/<id>/` URL.
- Salesforce: `00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{80,}`.
- Intercom: `dG9rO[A-Za-z0-9+/=_-]{20,}`.
- Airtable: `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`.
- WooCommerce: `c[ks]_[a-f0-9]{40}`.

PagerDuty keys, Zendesk tokens, Segment write keys and mail passwords have no distinctive shape. They are masked by the vault-value forms only, and each docs page says so.

- [ ] **Step 1: failing tests:**
  - `wave2_wave3_shapes_masked`: a table, with every literal built at runtime with `format!`.
  - `near_misses_untouched`: `sk_live_short`, `xoxb-`, `lin_api_` with 10 chars, and a plain `pat` word.
  - `one_extra_pass_only`: count `RULES` (the old count plus 1).
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** `cargo test -p saiife-audit`, then `scripts/bench-check.sh` vs `main`, which stays within +1 ms.
- [ ] **Step 5:** commit `feat(audit): mask token shapes of the wave 2 and 3 services`.

### Task 3: environments in `policy` and the daemon

**Files:**
- Create: `crates/policy/src/environment.rs`.
- Modify:
  - `crates/policy/src/system.rs`: `environments: BTreeMap<String, EnvironmentCfg>`, and the reserved service names from decision 11;
  - `crates/policy/src/load.rs`: validation;
  - `crates/policy/src/effective.rs`: `effective_policy` takes `env: Option<&str>` and emits `"env"`;
  - `crates/policy/src/lib.rs`;
  - `crates/daemon/src/ops.rs`: `GatewayPolicy { snap, by_env: BTreeMap<String, PolicySnapshot> }` with `fn snapshot_for(&self, env: Option<&str>) -> &PolicySnapshot`;
  - `crates/daemon/src/start.rs`: per-env snapshots are built next to plan 16's `load_policy`;
  - `crates/daemon/src/api_ops.rs`: the snapshot is chosen for `api.call` and `api.list`;
  - `crates/broker/src/pipeline.rs::record`: the `env` field.

**Interfaces:**
- `pub struct EnvironmentCfg { pub guard: EnvGuard /* packs: Vec<String> */, pub services: BTreeMap<String, ServiceOverride> }`, with `deny_unknown_fields`.
- `pub struct ServiceOverride { secret: Option<String>, params: BTreeMap<..>, fixed: BTreeMap<..>, allow: Option<Vec<String>>, ask: Option<Vec<String>>, deny: Option<Vec<String>>, rule: Option<Vec<RuleCfg>>, limits: Option<LimitsCfg>, redact: Option<RedactCfg> }`. The merge follows decision 10.
- `pub fn apply(cfg: &SystemConfig, env: &str) -> Result<SystemConfig, PolicyError>`.
- `pub fn env_for<'a>(cfg: &'a SystemConfig, dir: &dyn Directory, user: &str) -> Result<Option<&'a str>, PolicyError>`: the env of the user's single scope.
- Load refuses:
  - an undefined `[[scope]] env`;
  - an override of a service that is not in the base;
  - an `apply` that fails;
  - any applied config that fails `catalog::validate`. The daemon runs this at load and at reload for every environment, through plan 16's `check_services_owned`/`load_policy` (after the rebase onto plan 16), so a personal-broker config gets the same checks.
- **Choosing the snapshot:**
  - When `Ctx.mode` is Locked, the caller's scope `env` (from `env_for`) chooses it. A project `env` in the call is ignored.
  - When `Ctx.mode` is Developer (personal broker, plan 16), the project `env` that the client sends with `api.call` chooses it (spec §6.11). The client reads it from `.saiife/config.toml` and sends it as the `env` arg. An undefined name falls back to the base snapshot, with a warning in the answer.
  - `api.list` uses `snapshot_for(env)` under the same rule, so the list matches what `api.call` allows.
- The guard packs are `base ∪ env`, so a default-on pack can never be removed: the overlay has no remove key.

- [ ] **Step 1: failing tests:**
  - `spec_example_applies`: the §6.11 staging and prod blocks give `shopify.secret = "shopify-staging"`, `params.shop = "acme-staging"`, prod `ask = ["products:write"]`, and packs including `iac.terraform`.
  - `env_cannot_drop_default_pack`.
  - `env_cannot_override_connector` (`connector = "http"` in an override is an unknown-key error).
  - `env_unknown_service_refused`.
  - `scope_env_undefined_refuses_policy`.
  - `hash_differs_per_env`, and also against no env.
  - `locked_project_env_ignored`: the existing note is kept, and the scope env wins.
  - `reserved_service_names_refused`.
  - Daemon: `api_call_uses_scope_env_snapshot` (staging secret vs prod secret against two mock upstreams) and `record_carries_env_and_its_hash`.
  - Daemon: `developer_mode_project_env_picks_snapshot`. With `Ctx.mode` Developer, `api.call` carrying `env = "staging"` uses the staging secret. In Locked mode the same arg is ignored.
  - Daemon: `api_list_uses_env_snapshot`. An op allowed only in staging is listed for a staging caller and not for a prod caller.
  - `personal_config_envs_validated_via_load_policy`: a bad env override in a personal config is refused through `load_policy`.
- [ ] Steps 2–4: fail, implement, then `cargo test --workspace` and the tokio gate (`policy` stays tokio-free).
- [ ] **Step 5:** commit `feat(policy): environments bound per scope, in the effective-policy hash`.

### Task 4: `saiife env list|use`, and environments in the guard and the policy tools

**Files:**
- Create: `crates/cli/src/env_cmd.rs`, `crates/cli/tests/env_cmd.rs`.
- Modify:
  - `crates/cli/src/main.rs`: the `Env { List { json }, Use { name, scope: Option<String> } }` subcommand;
  - `crates/cli/src/check_managed.rs::policy_for`: the packs and hash of the current user's env;
  - `crates/cli/src/policy_cmd.rs`: `policy test`/`show` use the example user's env.

**Interfaces:**
- `env list`:
  - prints `name  packs+  services overridden  bound to scopes`, and marks `*` on the one that applies here;
  - "here" is, in locked mode, the caller's scope env through `env_for` and the system directory; in developer mode, the project `env`;
  - `--json` gives `[{name, applies, scopes, packs, services}]`.
- `env use <name> --scope <s>` (locked):
  - root only, per decision 10;
  - finds the file that defines `[[scope]] name = s`, among `config.toml` and `policy.d/*.toml`, and sets `env` with `toml_edit`;
  - the write is atomic (temp file, fsync, rename), keeping mode and owner;
  - it refuses an undefined `<name>`, then calls `policy.reload` and prints its result.
- Config location: `env list` and `env use` find the personal broker's config (and decide between locked and personal) through plan 16's `cli::broker::resolve`. There is no path logic of their own.
- `env use <name>` (developer or personal broker): writes `env = "<name>"` into `.saiife/config.toml` with `toml_edit`. It refuses an undefined name when a system config defines environments.

- [ ] **Step 1: failing tests:**
  - `list_marks_applying_env_developer`
  - `list_json_shape`
  - `use_developer_writes_project_key_keeps_comments`
  - `use_locked_non_root_refused` (in tests, the test user is not root)
  - `use_locked_rewrites_scope_binding`, through a test seam `SAIIFE_TEST_ASSUME_ROOT`, gated on `debug_assertions` (not `cfg(test)`) because the integration test drives the CLI binary, on files in the test dir. A release build ignores it, which `release_ignores_assume_root_seam` checks through a `cfg!(debug_assertions)` unit test of the gate function.
  - `list_personal_config_via_broker_resolve`
  - `use_undefined_env_refused`
  - `check_managed_hash_includes_env`
  - `policy_test_example_uses_scope_env`
- [ ] Steps 2–5. Run `scripts/bench-check.sh` (the guard path changed). Commit `feat(cli): saiife env list and env use`.

### Task 5: collections

**Files:**
- Create: `crates/cli/src/collection.rs` (parse and fill), `crates/cli/tests/collection.rs`.
- Modify:
  - `crates/cli/src/api_cmd.rs`: `args[0] == "collection"` goes to `list`/`run`, like `result`. The single-call body is refactored into `fn call_one(d: &mut Daemon, service, operation, params: Map, body: Option<Vec<u8>>, collection: Option<&str>) -> Result<(u8, Value), Stop>`.
  - `crates/daemon/src/api_ops.rs`: optional `collection` arg, validated `[a-z0-9_-]{1,64}`.
  - `crates/broker/src/pipeline.rs`: `Call.collection: Option<String>` in the record. The 14 `Call {` literals are updated.

**Interfaces:**
- `pub struct Collection { pub name: String, pub step: Vec<Step> }` and `pub struct Step { pub service: String, pub operation: String, pub params: BTreeMap<String, String>, pub body: Option<toml::Table> }`, with `deny_unknown_fields`.
- `pub fn load(project_root: &Path, name: &str) -> Result<Collection, CollectionError>`.
- `pub fn fill(c: &Collection, vars: &BTreeMap<String, String>) -> Result<Vec<FilledStep>, CollectionError>`. This follows decision 11. The placeholder grammar is `\{\{([a-z_][a-z0-9_]{0,31})\}\}`; any other `{{` is an error.
- The project root is found by the existing `project.rs` lookup, walking up from the current directory.
- `api collection list` prints `name  steps  services`.
- `api collection run` follows decision 11. stderr gets one summary line per step.

- [ ] **Step 1: failing tests:**
  - `spec_example_parses` (§6.12)
  - `fill_params_and_body_strings`
  - `filled_value_is_literal`: a value `}}{{other}}` stays as is
  - `missing_var_error_before_any_call`
  - `unused_var_error`
  - `placeholder_in_operation_refused`
  - `name_must_match_file_stem`
  - `too_many_steps_refused`
  - `oversize_file_refused`
  - `each_step_is_one_api_call`: against a fake daemon socket, N steps make N `api.call` frames, each with `collection`
  - `stops_at_first_non_done_with_its_exit_code`: a deny gives 2, a pending step gives 3 and prints the id
  - `record_carries_collection` (pipeline test)
  - `reserved_name_collection_not_a_service`
- [ ] Steps 2–5. Commit `feat(api): collections of named requests through the full pipeline`.

### Task 6: mail transport (SMTP send, IMAP read)

**Files:**
- Create: `crates/broker/src/mail/{mod.rs, smtp.rs, imap.rs, message.rs}`, `crates/broker/tests/mail_transport.rs`.
- Move `crates/daemon/src/smtp.rs` to `broker/src/mail/smtp.rs`. The daemon keeps `pub use saiife_broker::mail::smtp` for notifications; its tests move with it.
- Modify:
  - `crates/broker/src/manifest.rs`: `Transport::Mail` is accepted, with no `base_url`, `hosts = ["{smtp_host}", "{imap_host}"]` and no proxy;
  - `crates/broker/src/pipeline.rs`: step 9 dispatches `Transport::Mail` to `mail::run` instead of `up.send`;
  - `crates/broker/Cargo.toml`: `imap-proto`, `mail-parser`, pinned with the date comment.

**Interfaces:**
- `pub async fn mail::run(up: &Upstream, m: &Manifest, op: &Operation, svc: &BTreeMap<String, String>, params: &BTreeMap<String, String>, body: Option<Bytes>, auth: &AuthMaterial, read_limit: usize) -> Result<UpstreamResponse, BrokerError>`.
  - It returns a synthetic `200 application/json`, so step 10 masks it unchanged.
  - Errors map to a 502 `UpstreamFailed`, with server replies cut to 200 bytes and masked.
- Service params: `smtp_host`, `smtp_port` (`int:1..65535`), `smtp_tls = "enum:implicit,starttls"`, `imap_host`, `imap_port`, `imap_tls`, `from` (address).
- Each protocol step has a 10 s timeout (the `smtp::STEP` value), and reply lines are at most 8 KiB.
- `imap.rs` is a session over decision 9. Lists use `ENVELOPE FLAGS RFC822.SIZE`; `mail.get` uses `BODY.PEEK[]`, with each literal at most `read_limit`.
- `message.rs` produces the `mail.get` JSON with mail-parser: `{uid, from, to, cc, subject, date, text, html, attachments: [{name, type, size}]}`, with no attachment content. It also composes the outgoing message: RFC 5322 headers, quoted-printable UTF-8, dot-stuffing.

- [ ] **Step 1: failing tests**, against loopback rcgen TLS mock servers written in the test, scripted line by line:
  - `smtp_send_one_recipient_golden_transcript`
  - `starttls_missing_refused_before_auth`, for both SMTP and IMAP
  - `crlf_in_subject_rejected` (`params::validate` already refuses control characters; assert that nothing connects)
  - `examine_never_select`: the mock fails the test on `SELECT`
  - `fetch_uses_body_peek`
  - `literal_over_limit_refused`: an announced `{2147483648}` is refused before reading
  - `endless_line_times_out_or_cuts`
  - `mail_list_next_before_uid`
  - `message_json_text_html_attachments_meta`
  - `password_never_in_error_or_record`
  - `mail_proxy_path_unknown_operation`
  - the existing daemon notification SMTP tests pass from their new home
- [ ] Steps 2–5. Commit `feat(broker): mail transport with SMTP send and read-only IMAP`.

### Task 7: the `oauth2` vault kind and daemon token refresh

**Files:**
- Create: `crates/daemon/src/oauth.rs`, `crates/broker/src/oauth2.rs` (pure: build the token request, parse the response).
- Modify:
  - `crates/daemon/src/vault.rs`: `Kind::OAuth2`, fields `client_id`, `client_secret`, `refresh_token`;
  - `crates/daemon/src/secret_ops.rs`: `parse_kind`, `field_names`, and `rotate`/`remove` call `TokenCache::forget`;
  - `crates/daemon/src/api_ops.rs`: `spec_for`, and `DaemonEnv::oauth_token`;
  - `crates/broker/src/pipeline.rs`: step 9 handles oauth2 auth and the 401 retry;
  - `crates/policy/src/system.rs`: `Event::RefreshFailed`;
  - `crates/cli/src/secret_cmd.rs`: oauth2 prompts, with no echo for the secret and the refresh token.
- Remove the `oauth2` arm of "comes with plans 14–15" in both files; `aws`, `gcp_sa` and `azure_sp` keep it, now as "comes with plan 15".

**Interfaces:**
- `broker::oauth2`:
  - `pub fn token_request(spec: &AuthSpec, m: &Manifest, svc_params: &BTreeMap<String, String>, fields: &BTreeMap<String, Zeroizing<String>>) -> Result<Built, BrokerError>`: a form POST `grant_type=refresh_token&client_id&client_secret&refresh_token`, host-pinned through `checked_uri`.
  - `pub fn parse_token(body: &[u8], expect_host: &str) -> Result<Token, RefreshError>`, with `Token { access: Zeroizing<String>, refresh: Option<Zeroizing<String>>, ttl: Duration }`.
- `pipeline::Env` gains `fn oauth_token<'a>(&'a self, secret: &'a str, service: &'a str, spec: &'a AuthSpec, svc_params: &'a BTreeMap<String, String>, force: bool) -> TokenFuture<'a>`. Its default returns `Err("secret_missing")`, so the existing fakes compile. The access token joins the masker. On a 401 with oauth2, the pipeline calls it once with `force = true` and resends. The record gets `auth_retry: true`.
- `daemon::oauth::TokenCache`:
  - per-secret `tokio::sync::Mutex` for single flight;
  - an in-memory `Cached { access, obtained, ttl }` plus an optional `pending_refresh` (a rotated token not yet persisted);
  - follows decision 8, and records `secret`/`refresh_failed` with `reason ∈ http_<status> | network | bad_response | instance_mismatch | persist`;
  - notifies at most once per secret per hour.

- [ ] **Step 1: failing tests**, against a mock token endpoint and API (rcgen loopback):
  - `cold_call_refreshes_then_sends`
  - `cached_token_reused_until_ttl`
  - `concurrent_cold_calls_refresh_once` (10 tasks give 1 token POST)
  - `upstream_401_refreshes_once_and_retries_once` (a second 401 is returned as-is, with exit 1)
  - `rotated_refresh_token_persisted_first` (the vault file is re-read and holds the new token before the API mock sees the request)
  - `persist_failure_keeps_token_in_memory` (a read-only vault dir seam)
  - `instance_url_mismatch_refused`
  - `refresh_failed_record_and_notify_once_per_hour`
  - `tokens_never_in_records_or_errors`
  - `rotate_drops_cache`
  - `secret_add_oauth2_fields`
  - `aws_kind_still_refused_with_plan_15`
- [ ] Steps 2–5. Commit `feat(daemon): oauth2 secrets with daemon-side token refresh`.

---

## Connector tasks (8–13)

Every connector task follows plan 10's Part C shape:
- Files:
  - `crates/broker/connectors/<id>.toml`, with the vendor docs URLs in the top comment;
  - `crates/broker/tests/<id>.rs`;
  - `crates/broker/tests/fixtures/<id>/*.json`;
  - `crates/broker/tests/golden/<id>_*.http`;
  - `docs/connectors/<id>.md`, with Setup, Operations and capabilities, Suggested policy: read-only, Suggested policy: every write under `ask`, Limits, Locked mode (as in `hubspot.md`, plus the minimal vendor token scopes and the vault-only masking note where Task 2 has no shape), and Tests.
- Tests per connector:
  - `every_builtin_manifest_loads`, with the op table asserted;
  - a golden request per op (method, URL, headers, auth placement);
  - fixture parse;
  - pagination `next`;
  - for each write: `default_deny`, allowed by the policy, and the amount where marked;
  - `<id>_secret_masked_in_response`: the fixture is echoed with the vault value and its Task 2 shape;
  - one pipeline end-to-end test against a loopback mock.
- Docs and policy validity are covered by Task 1's `docs_pages.rs`.
- The implementer checks each path against the vendor's current reference. The plan fixes the ids, capabilities and kinds; the vendor fixes the paths.

### Task 8: Stripe, Slack, Discord (built bodies, body qualifiers)

- **Stripe:**
  - `base_url = "https://api.stripe.com/v1"`, `bearer`.
  - `request_headers = ["Idempotency-Key", "Accept"]`, `body = "form"`.
  - Param `currency` (`^[A-Z]{3}$`, required).
  - Pagination is `Cursor { param = "starting_after", next = "data[-1].id", more = "has_more" }`.
  - Operations:
    - `customers.list|get` → `customers:read`
    - `charges.list|get` → `charges:read`
    - `payment_intents.list|get` → `payment_intents:read`
    - `invoices.list|get` → `invoices:read`
    - `refunds.list` → `refunds:read`
    - `refunds.create` → `refunds:write`, write, `body_params = { payment_intent, charge, amount = "int:1..99999999", reason = "enum:duplicate,fraudulent,requested_by_customer" }`, `amount = { field = "amount", currency_param = "currency", unit = "minor" }`
  - Extra tests: `refund_without_amount_denied_bad_amount` and `refund_amount_cap_end_to_end` (`amount_per_day = { max = 500, currency = "EUR" }`).
- **Slack:**
  - `base_url = "https://slack.com/api"`, `bearer`.
  - Cursor `response_metadata.next_cursor` with param `cursor`.
  - Operations:
    - `conversations.list` → `channels:read`
    - `conversations.history`, `conversations.replies` → `messages:read`, qualifier `channel={channel}`
    - `users.list`, `users.info` → `users:read`
    - `chat.postMessage` → `messages:write`, `body_params = { channel, text, thread_ts }`, qualifier `channel={channel}`
  - The docs note that Slack answers errors as `200 {"ok": false}`.
- **Discord:**
  - `base_url = "https://discord.com/api/v10"`, header `Authorization` with prefix `Bot `.
  - Operations:
    - `guilds.channels` → `channels:read:guild={guild_id}`
    - `channels.get` → `channels:read`, qualifier `channel={channel_id}`
    - `messages.list` → `messages:read`, qualifier channel; `limit`, `before`, `after` are `string:[0-9]{1,20}`
    - `messages.create` → `messages:write`, qualifier channel, `body_params = { content = "string:(?s).{1,2000}" }`, `body_const = { "allowed_mentions.parse" = [] }`
  - The `allowed_mentions` constant means no `@everyone` from an agent.
- Commit `feat(connectors): Stripe, Slack and Discord (wave 2)`.

### Task 9: GitLab, Sentry, PagerDuty (host params, prefixed auth, offset pagination)

- **GitLab:**
  - `base_url = "https://{host}/api/v4"`, `hosts = ["{host}"]`, header `PRIVATE-TOKEN`, Link pagination.
  - `project_id` is `int` only: a URL-encoded path would need `%2F`, which path params refuse. The docs explain how to find the id.
  - Qualifier `project={project_id}`.
  - Operations:
    - `projects.get` → `projects:read`
    - `issues.list|get` → `issues:read`
    - `issues.create`, `issues.comment` → `issues:write`
    - `merge_requests.list|get` → `merge_requests:read`
    - `pipelines.list` → `pipelines:read`
- **Sentry:**
  - `base_url = "https://{host}/api/0"`, `bearer`, Link pagination with `results="false"` (Task 1).
  - `org` is a path param. The suggested policy pins it with `fixed = { org = "acme" }`.
  - Qualifier `project={project}` on project routes.
  - Operations:
    - `projects.list` → `projects:read`
    - `issues.list|get` → `issues:read`
    - `issues.events`, `events.latest` → `events:read`
    - `issues.update` → `issues:write` (PUT, json)
- **PagerDuty:**
  - `base_url = "https://api.pagerduty.com"`, header `Authorization` with prefix `Token token=`.
  - Fixed headers `Accept = "application/vnd.pagerduty+json;version=2"` and `From = "{from}"`; param `from` is an email address and required.
  - Pagination is `Offset { param = "offset", limit_field = "limit", more = "more" }`.
  - Operations:
    - `incidents.list|get`, `incidents.notes` → `incidents:read`
    - `incidents.create`, `incidents.update`, `notes.create` → `incidents:write`
    - `services.list` → `services:read`
    - `oncalls.list` → `oncalls:read`
- Commit `feat(connectors): GitLab, Sentry and PagerDuty (wave 2)`.

### Task 10: Linear, Intercom, Airtable (GraphQL, cursors)

- **Linear:**
  - `base_url = "https://api.linear.app"`, header `Authorization` with no prefix.
  - Every operation is `POST /graphql` with a fixed `graphql` query.
  - Cursor `data.<root>.pageInfo.endCursor`, with `more = "data.<root>.pageInfo.hasNextPage"` and param `after`.
  - Operations:
    - `teams.list` → `teams:read`
    - `issues.list` (`team` key filter, `first`, `after`) → `issues:read`, qualifier `team={team}`
    - `issues.get` → `issues:read`
    - `issues.create` (`team_id`, `title`, `description`) → `issues:write`, qualifier `team={team_id}`
    - `issues.comment` (`issue_id`, `body`) → `issues:write`
  - Extra test: `agent_cannot_send_graphql` (a raw body is refused, and `/v1/proxy` is unknown).
- **Intercom:**
  - `base_url = "https://{host}"`, `hosts = ["api.intercom.io", "api.eu.intercom.io", "api.au.intercom.io"]`, with `host` an enum param.
  - `bearer`, fixed header `Intercom-Version = "{api_version}"` (required, `^[0-9]+\.[0-9]+$`).
  - Cursor `pages.next.starting_after`.
  - Operations:
    - `contacts.list|get` → `contacts:read`
    - `conversations.list|get` → `conversations:read`
    - `conversations.reply` → `conversations:write`
- **Airtable:**
  - `base_url = "https://api.airtable.com/v0"`, `bearer`, Cursor `offset`.
  - Qualifier `base={base_id}` on every operation.
  - Operations:
    - `records.list|get` → `records:read`
    - `records.create`, `records.update` → `records:write`
    - `records.delete` → `records:delete`, kind delete
  - There is no `bases.list`: `/meta/bases` would be ambiguous with `/{base_id}/{table}` for proxy resolution.
- Commit `feat(connectors): Linear, Intercom and Airtable (waves 2 and 3)`.

### Task 11: Zendesk, Segment, WooCommerce (basic-style auth)

- **Zendesk:**
  - `base_url = "https://{subdomain}.zendesk.com/api/v2"`, `hosts = ["*.zendesk.com"]`.
  - `basic`, with the username `<email>/token` (the docs say so).
  - Cursor `meta.after_cursor`, with `more = "meta.has_more"` and param `page[after]`.
  - Operations:
    - `tickets.list|get`, `tickets.comments` → `tickets:read`
    - `tickets.create`, `tickets.update` → `tickets:write`
    - `users.get` → `users:read`
    - `search` → `search:read`
- **Segment (Tracking API only; the Public API is out of scope):**
  - `base_url = "https://{host}/v1"`, with `host` = `enum:api.segment.io,events.eu1.segmentapis.com`, and `basic_token`.
  - Operations:
    - `track` → `events:write`
    - `identify` → `users:write`
    - `group` → `groups:write`
    - `batch` → `events:write`, kind bulk
  - The docs say Segment is write-only, so its read-only policy is empty and states that.
- **WooCommerce:**
  - `base_url = "https://{host}/wp-json/wc/v3"`, `hosts = ["{host}"]`.
  - `basic` with the consumer key and secret. Query-string auth is not supported, because it would put secrets in URLs.
  - Link pagination; param `currency` is required.
  - Operations:
    - `orders.list|get` → `orders:read`
    - `orders.update` → `orders:write`
    - `products.list|get` → `products:read`
    - `products.update` → `products:write`
    - `customers.list` → `customers:read`
    - `refunds.create` → `refunds:write`, `amount = { field = "amount", currency_param = "currency", unit = "major" }`
- Commit `feat(connectors): Zendesk, Segment and WooCommerce (wave 3)`.

### Task 12: Salesforce (OAuth2)

- `base_url = "https://{instance_host}/services/data/{api_version}"`.
- `hosts = ["{instance_host}"]`, with `instance_host` matching `^[a-z0-9-]+(\.sandbox)?\.my\.salesforce\.com$`.
- `api_version` matches `^v[0-9]{2,3}\.0$` and is required.
- `auth = [{ kind = "oauth2", token_path = "/services/oauth2/token" }]`.
- Qualifier `sobject={sobject}` on record and describe operations.
- Operations:
  - `query` (`q`, a string of at most 4000 bytes) and `query.more` (`locator`) → `query:read`
  - `sobjects.list`, `sobjects.describe` → `sobjects:read`
  - `records.get` → `records:read`
  - `records.create`, `records.update` → `records:write`
  - `records.delete` → `records:delete`
- Extra tests:
  - `end_to_end_with_token_refresh`: the mock token endpoint plus the API, through the pipeline and the Task 7 fake env;
  - `session_expired_401_retry`;
  - `query_more_locator_single_segment`.
- The docs cover:
  - a connected app with only the `api` and `refresh_token` scopes, and an integration user whose profile bounds what SOQL can read;
  - the paste flow;
  - rotation;
  - `refresh_failed`.
- Commit `feat(connectors): Salesforce REST with OAuth2 refresh (wave 3)`.

### Task 13: Email

- `email.toml` uses `transport = "mail"` and the Task 6 params, with `basic` (mailbox username and password, or an app password).
- Operations:
  - `mail.send` → `mail:write`, qualifier `to={to}`, `body = "text"`, params `to` (`string:[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}`) and `subject` (`string:.{1,998}`)
  - `folders.list` → `folders:read`
  - `mail.list` (`folder`, `since` as a `datetime`, `unseen`, `limit = "int:1..100"`, `before_uid`) → `mail:read`, qualifier `folder={folder}`, with Cursor `next_before_uid` and param `before_uid`
  - `mail.get` (`folder`, `uid`) → `mail:read`, qualifier `folder={folder}`
- Extra tests:
  - `send_only_to_allowed_domain`: `[[services.email.rule]] capability = "mail:write" when = { to = "*@acme.com" } action = "allow"` allows `a@acme.com` and denies `a@evil.test`.
  - `reads_leave_seen_flag_unset`.
  - `writes_per_hour_caps_send`.
- The docs' locked-mode section covers:
  - the mailbox password is vault-only (no shape);
  - prefer a dedicated mailbox;
  - reads use `EXAMINE`;
  - one recipient per call;
  - the redact example `fields = ["*.from", "*.to"]` for minimization.
- Commit `feat(connectors): Email with SMTP send and IMAP read (wave 3)`.

### Task 14: index, `connect` kinds, docs

**Files:**
- `docs/connectors/README.md`: the list of all 18 connectors, an "Environments" section and a "Collections" section;
- new `docs/environments.md` and `docs/collections.md`;
- `crates/cli/src/connect_cmd.rs::secret_kind`: `oauth2` → `oauth2`, `basic_token` → `token`, prefixed header → `token`; a mail manifest asks for the host params;
- `crates/cli/tests/connect_cmd.rs`;
- `CHANGELOG.md` (Unreleased);
- `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`: add the decision-13 spec notes to §6.8 and §6.11;
- `crates/cli/tests/docs_wording.rs`: the new pages exist and are linked from the README.

- [ ] **Step 1: failing tests:**
  - `connect_every_builtin_generates_deny_all`: for each built-in manifest, `connect` with test params writes a file that validates and decides `default_deny` for every operation;
  - `connect_salesforce_prompts_oauth2_fields`;
  - `new_pages_linked`.
- [ ] Steps 2–5. Commit `docs(connectors): waves 2 and 3 index, environments and collections`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`, clippy `-D warnings`, the tokio gate;
  - `cargo test --workspace` and `scripts/test-offline.sh` with TMPDIR and SAIIFE_TEST_TMP set;
  - the macOS-target check (`RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-apple-darwin` with a fake `cc`);
  - `scripts/bench-check.sh` vs `main`;
  - `cargo build --release --locked` for the static musl target: `imap-proto`, `nom` and `mail-parser` are pure Rust.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR, CI. The owner merges. No tag.

## Owner handwork

- [ ] Smoke-test each connector once against a real account, read-only first: Stripe test mode, a Slack workspace, Linear, Sentry, gitlab.com, a PagerDuty trial, a Discord test guild, Intercom, Zendesk, Airtable, a Segment source, a WooCommerce test shop, and a real IMAP/SMTP mailbox (an app password).
- [ ] Salesforce: create a connected app (scopes `api` and `refresh_token`, refresh token rotation on), get a refresh token, run `saiife secret add --kind oauth2`, and confirm that one refresh and one rotation persist.
- [ ] Confirm the spec notes: `env use --scope` is root only (spec: "admin rights"), and OAuth2 is paste flow only (spec: "device or paste").
- [ ] Confirm the API versions to put in the docs' suggested params: Salesforce `api_version` and `Intercom-Version`.
- [ ] §17 question 2 (which connectors first): this plan builds all of them. Choose which pages to promote in the README.

## Self-review

- **Spec coverage:**
  - Waves 2 and 3 are Tasks 8–13, each with the §6.8 docs page and an offline suite.
  - OAuth2 refresh and `refresh_failed` are Task 7.
  - The `connect` paste flow is Tasks 7 and 14.
  - Amount caps for Stripe and WooCommerce refunds are Tasks 1, 8 and 11.
  - §6.11 environments, including locked binding, `env use`, `env list` and the hash, are Tasks 3–4.
  - §6.12 collections and §6.7.2 `api collection` are Task 5.
  - A17 (switching to a looser environment needs admin) is Task 4, `use_locked_non_root_refused`.
- **Types:**
  - `AuthSpec.prefix`/`token_path`, `Transport`, `body_params`/`body_const`/`graphql`, `Pagination::Offset`, `AmountSpec.currency_param`, `Env::oauth_token`, `GatewayPolicy::snapshot_for`, `environment::{apply, env_for}` and `Call.collection` are each defined once (Tasks 1, 3, 5, 7) and used by the same name later.
- **Proportion:** connectors are tables, not code. The algorithms the tests do not pin are named in the decisions: refresh ordering, form nesting, environment merge.

## Appendix: red-team cases for the owner's suite

- A16: `{{var}}` injection that rewrites a collection step into another service.
- A17: an agent edits `.saiife/config.toml env = "staging"` in locked mode. The scope env must still apply, and the record hash must show it.
- An agent sends raw GraphQL to Linear through `/v1/proxy/linear/graphql`.
- An agent attaches `@everyone` to a Discord message through `content`; `allowed_mentions` must hold.
- An agent mails out of the allowed domain through a `to` of the form `a@acme.com,b@evil.test` or `a@acme.com\r\nBcc:`.
- A Salesforce token response that points `instance_url` at an attacker host.
