# Plan 10 — Vault, gateway, connector wave 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In locked mode on Linux, an agent user reaches Shopify, HubSpot, GitHub and any admin-defined HTTP API only through `saiifed`. The CLI is `saiife api`, and the HTTP gateway is `gateway.sock`. The credential comes from an encrypted vault owned by the daemon user. Every request passes scope, the policy, limits and amount caps. Responses are masked and redacted, and every request is one `connector` record. Admins get `saiife secret`, `saiife connect` and `saiife secret import`. Agents get `saiife run --secret` where a secret allows it.

**Architecture:** One new crate, `broker` (tokio, hyper, rustls). It holds the connector manifests (embedded `connectors/*.toml` plus local ones from `/etc/saiife/connectors/`), parameter validation, operation resolution (named operations and proxy paths), limits and amounts, upstream request building, the HTTPS client, and response masking and redaction. It also holds `pipeline::handle`, which runs spec §6.7.1 steps 3–12 over traits, so every step can be tested without a daemon or network. The tokio-free `policy` crate gains typed service config, capability matching and the deny > ask > allow decision, so `policy test` (plan 12) can use them without a daemon. `daemon` gains the vault, `secret.*`/`api.*` ops, session attribution from `/proc`, and the hyper gateway server on `gateway.sock` (plus an optional loopback TCP listener with bearer tokens). The CLI gains `secret`, `connect`, `api` and `run --secret`. `ask` matches are **denied** in this plan (`rule = "approval_not_available"`). Plan 11 turns them into pending requests.

**Tech Stack:** Rust workspace. New crate `saiife-broker`. New dependencies:
- `broker`: `hyper` 1 (`client`, `http1`), `hyper-util`, `http-body-util`, `rustls` with the **`ring`** provider (no `aws-lc-rs`: the static musl build has no cmake/C toolchain), `hyper-rustls` or `tokio-rustls`, `rustls-native-certs`, `rustls-pemfile`, `percent-encoding`, `base64`, `hex`, `globset` (or the hand matcher from Task 1).
- `daemon`: `chacha20poly1305` (XChaCha20-Poly1305), `zeroize`, `hyper` (`server`, `http1`), plus `broker`.
- `cli`: `rustix` `termios` for no-echo input.
- dev: `rcgen`, for self-signed test certificates.

Pin each to the newest release older than 14 days, as the `tokio = "=1.53.2"` pin in `crates/daemon/Cargo.toml` does, with the same comment.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §6.6 (the locked-mode vault; personal broker mode comes after v2.0)
- §6.7 (all of it; `api result` and `--wait` only parse until plan 11)
- §6.8 (wave 1)
- §6.9.1–6.9.4
- §6.14
- §7 rows `secret`, `connect`, `api`, `api token`, `run --secret`
- §8.1 `[services.*]`, `[secrets.*]` and `[gateway]`
- §8.4, §8.5 (connector and secret records), §8.7 (the `api.*`, `secret.*` and `secret.lease` ops), §8.8, §8.9
- §9.2 A11–A14 and A20
- §13 (connectors, fuzzing)
- §14 point 6

Plans 9a (`2026-10-22-plan-9a-daemon-core.md`) and 9b (`2026-10-22-plan-9b-locked-linux.md`) set the style.

## Global Constraints

- **No root, no privileged probing.** Nothing runs sudo, root, systemd, docker or writes to `/etc /opt /var /run`. No agent *executes* kill/pkill/killall/pgrep/sudo/su/systemctl/loginctl/crontab, not even to probe them (2026-10-22 incident). Reading `/proc/<pid>/stat` of the test's own children is fine. Session tests use a fake proc root.
- **Test isolation:** point `HOME`, `PATH`, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` at tempdirs. Scratch goes under `mktemp -d -p /home/jonas/projects/personal/saiife` (`/tmp` has a quota). Never `saiife init` on the real home or the repo. Never touch `~/.claude`. The daemon runs as the test user with `--config <tmp>/config.toml --state-dir <tmp>/state` (9a), plus `--credentials-dir <tmp>/creds` (new, Task 4). Admin ops in tests authorize through `[admin] groups = [<test user's primary group>]`.
- **No internet in tests.** Upstreams are loopback mock servers with an `rcgen` certificate trusted through `[gateway]`'s CA option or the test seam `Upstream::with_roots`. Host names resolve through an injected `Resolver` (Task 7). The CI `offline` job (`scripts/test-offline.sh`, `unshare -rn`) must stay green. Add `-p saiife-broker` to it.
- **Hook path untouched:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free. The CI gate `no tokio in hook crates` is unchanged and must still print 0. `saiife check` medians in `scripts/bench-check.sh` stay within +1 ms of `main`.
- **`#![forbid(unsafe_code)]`** in `broker`. OS calls go through `rustix`.
- **Linux only:** the daemon side is `cfg(target_os = "linux")`, as in 9a. On macOS, `saiife api|secret|connect|run --secret` print `saiife: locked mode needs Linux in this version (macOS: v2.1)` and exit 5. The workspace builds and tests green on `macos-latest`. `broker` itself is portable and its tests run there too.
- **Fail closed everywhere:** any error in steps 1–8 means deny. A missing or invalid vault key, an undecryptable vault, an invalid policy or a manifest error means every connector call is denied with the matching `rule`, and audit keeps working.
- **Secret values never leave the daemon** except in the upstream request and in a `secret.lease` answer (§6.14). They never appear in a record, an error message, a log line, `secret list`, `Debug` output or a panic message. Secret bytes live in `Zeroizing` buffers. A test greps each new test's audit files and stderr for each secret value used.
- **Spec values, verbatim:**
  - Pipeline order is §6.7.1 steps 1–12. Steps 1–8 never touch the network.
  - Policy order: any matching `deny`, then `ask`, then `allow`; no match means deny. Rule names: `no_scope`, `scope_conflict`, `unknown_operation`, `limit = "<name>"`.
  - Agent-supplied `Authorization`, `Cookie` and `Host` are always dropped. Redirects are followed to the same host only, at most 3. Upstream timeout defaults to `30s` (`[gateway] upstream_timeout`). `max_response_bytes` defaults to 5 242 880.
  - Masked forms of each vault value in use: raw, base64 (standard and URL-safe, padded and unpadded), URL-encoded, and hex (lower and upper). Each is replaced with `[MASKED]`. Redacted fields become `"[REDACTED]"`.
  - `saiife api` exit codes: 0 done, 1 upstream status ≥ 400, 2 denied, 3 pending, 4 limit reached, 5 saiife unavailable. JSON goes to stdout and a one-line summary to stderr.
  - Gateway paths and statuses are those of §8.8: 200, 202, 403 `{"error":"denied","rule":…}`, 429, 502, 503. The upstream status goes in `X-Saiife-Upstream-Status`.
  - Vault file: `magic "SAIIFEV1" || u8 version (1) || 24-byte nonce || XChaCha20-Poly1305(key, nonce, aad = magic||version, JSON)`, at `<state>/vault/vault.bin`, 0600 in a 0700 dir. Written to a temp file, fsynced, renamed, fsync of the dir, with a new nonce on every write.
  - Vault key: `$CREDENTIALS_DIRECTORY/vault-key`, exactly 32 bytes.
  - Path parameters are percent-encoded and may not contain `/`. Proxy paths with `..`, `%2e`, `%2f`, `//`, an absolute URL or another host are rejected.
  - Connector pool: at most 4 upstream calls in flight per service (§4.1).
  - `api token`: bound to the uid, valid 12 h, stored hashed (SHA-256) by the daemon.
- **Decisions this plan makes** (the spec leaves them open; each is restated in the owning task):
  1. `ask` → deny with `rule = "approval_not_available"` until plan 11.
  2. Secret kinds in v2.0 wave 1: `token` `{token}`, `basic` `{username, password}`, `header` `{value}`. `oauth2`, `aws`, `gcp_sa` and `azure_sp` are refused with `kind <k> comes with plans 14–15`.
  3. `secret_use` is the `secret` field of each connector record, not a second record. `run --secret` leases write their own `secret` record (`event = "secret_use"`).
  4. The project overlay (deny/ask only in locked mode) is read by the client and sent in `api.call` as `overlay`. Because it can only tighten, the daemon trusts it. In locked mode it ignores `allow`.
  5. Field-redaction paths match as a **suffix** of the key path anywhere in the JSON tree. Arrays are transparent, and `*` matches one key. A response that is not JSON on a service with `redact` is withheld (`rule = "redact_non_json"`, HTTP 502, exit 1).
  6. Limits count requests that were **sent** upstream, whatever their status. The null session is its own bucket, so `bulk_per_session` with no session counts per uid over 24 h.
  7. Amounts are compared in minor units through an ISO 4217 exponent table (default 2; 0 for `JPY KRW CLP ISK VND`; 3 for `BHD JOD KWD OMR TND`). A cap's `max` is in major units.
  8. Pagination: the daemon returns `next` (the params for the next page). The CLI prints `next: k=v` on stderr, and `/v1/api` sets `X-Saiife-Next`. `/v1/proxy` passes `Link` through, masked.

## Review Focus

1. **A vault value in an encoding the mask misses, or cut at the truncation boundary.** Example: a token echoed in a GitHub error body as base64url without padding, or a token straddling byte 5 242 880. Expected: `[MASKED]` in every case. The body is read up to `max + 64 KiB`, masked, and only then cut (Task 8: `masks_secret_straddling_cut`, `masks_base64url_unpadded`).
2. **A vault that cannot be decrypted** (key regenerated by a reinstall, a corrupt file). Expected: connectors are denied with `vault_unavailable`, and `secret add` **refuses** with `vault cannot be read; restore it or remove <path> by hand`. It never replaces the vault with a new, empty one (Task 4: `add_refuses_when_vault_undecryptable`).
3. **A redirect that leaves the pinned origin**: another host, the same host on another port, `https → http`, or a `Location` holding userinfo. Expected: the redirect is not followed, the answer is 502, and `rule = "redirect_refused"` is recorded (Task 7: `redirect_other_port_refused`, `redirect_downgrade_refused`).
4. **Injection through parameters and headers**: CRLF in a query value or in an allowed header, a double-encoded `%252f` in a path parameter, a Unicode `／` (U+FF0F), a header named `authorization` in lower case, a `Host` header sent through the proxy. Expected: rejected or dropped before anything is sent (Task 2: `path_param_double_encoded_slash_rejected`; Task 7: `crlf_in_header_value_rejected`, `lowercase_authorization_dropped`).
5. **A daemon restart inside a limit window.** Expected: counters rebuilt from the last 24 h of connector records. A 61st request in the same minute after a restart is still denied (Task 3: `rebuild_from_records_keeps_window`; Task 9 e2e: `limit_survives_restart`).

---

## Task order and parallelism

Part A (no network): Tasks 1, 2, 3, 4 and 6 are independent and run in parallel worktrees. Task 5 needs 4.
Part B: Task 7 needs 2. Task 8 needs nothing (pure). Task 9 needs 1–8. Task 10 needs 9. Task 11 needs 10.
Part C: Tasks 12, 13 and 14 need 9 and run in parallel. Task 15 needs 5 and 12. Task 16 needs 5. Task 17 needs 5 and 15.
Last: the whole-branch review and one fix wave, then `scripts/bench-check.sh` on an idle machine, push, CI, PR.

---

## Part A — config, vault, limits (no network)

### Task 1: `policy` — typed services, capabilities, decision

**Files:**
- Create: `crates/policy/src/service.rs`, `crates/policy/src/capability.rs`, `crates/policy/src/decide.rs`
- Modify: `crates/policy/src/system.rs` (`services: BTreeMap<String, ServiceCfg>`, new `secrets: BTreeMap<String, SecretCfg>`), `crates/policy/src/load.rs` (typed parse, `DuplicateService` unchanged), `crates/policy/src/lib.rs`, `crates/policy/src/effective.rs` (hash includes typed services and secrets via `Serialize`)

**Interfaces:**
- Produces (`service.rs`), all `#[serde(deny_unknown_fields)]`:
  - `pub struct ServiceCfg { pub connector: String, pub secret: Option<String>, pub params: BTreeMap<String, String>, pub base_url: Option<String>, pub auth: Option<AuthCfg>, pub allow: Vec<String>, pub ask: Vec<String>, pub deny: Vec<String>, pub rule: Vec<RuleCfg>, pub fixed: BTreeMap<String, String>, pub limits: LimitsCfg, pub redact: RedactCfg, pub operation: Vec<HttpOperationCfg> }`
  - `pub struct AuthCfg { pub kind: String, pub name: Option<String> }`. Kinds: `header`, `bearer`, `basic`.
  - `pub struct RuleCfg { pub capability: String, pub when: BTreeMap<String, String>, pub action: Action }`, with `pub enum Action { Allow, Ask, Deny }`.
  - `pub struct LimitsCfg { pub requests_per_minute: Option<u32>, pub writes_per_hour: Option<u32>, pub deletes_per_day: Option<u32>, pub bulk_per_session: Option<u32>, pub max_response_bytes: Option<u64>, pub amount_per_day: Option<AmountCap>, pub amount_per_request: Option<AmountCap> }`, with `pub struct AmountCap { pub max: u64, pub currency: String }`.
  - `pub struct RedactCfg { pub fields: Vec<String> }`
  - `pub struct HttpOperationCfg { pub id: String, pub capability: String, pub kind: String, pub method: String, pub path: String, pub query: Vec<String>, pub body: Option<String> }`
  - `pub struct SecretCfg { pub run_allow: Vec<PathBuf> }`
  - The key `profile` anywhere in a service, scope or secret is refused: `reserved for v3`.
- Produces (`capability.rs`):
  - `pub struct Capability { pub resource: String, pub verb: String, pub qualifier: Option<String> }` with `pub fn parse(s: &str) -> Result<Capability, PolicyError>`. Verbs: `read write delete export admin`.
  - `pub fn matches(pattern: &str, cap: &Capability) -> bool`. `*` matches exactly one segment. The qualifier is a glob where `*` does not cross `/`. A pattern without a qualifier matches any qualifier.
- Produces (`decide.rs`):
  - `pub struct Request<'a> { pub capability: &'a Capability, pub params: &'a BTreeMap<String, String> }`
  - `pub enum Verdict { Allow, Ask, Deny { rule: String } }`
  - `pub fn decide(svc: &ServiceCfg, overlay: Option<&ServiceOverlay>, mode: Mode, req: &Request) -> Verdict`. Overlay `allow` counts only when `mode != Mode::Locked`. A `when` value is a glob on the named param, and a missing param means no match. The deny rule name is `deny:<pattern>`, or `default_deny`.
- Consumes: `ServiceOverlay`, `Mode` from `project.rs`.

- [ ] **Step 1: Failing tests** (table tests in each module):
  - `capability_star_is_one_segment`: `orders:*` matches `orders:read`. `*` alone is not a valid pattern. `*:delete` matches `products:delete`.
  - `qualifier_glob_does_not_cross_slash`: `issues:write:repo=acme/*` matches `repo=acme/web`, not `repo=acme/web/x`, not `repo=other/web`.
  - `order_deny_ask_allow_default`: the §8.1 shopify example gives `orders:read` → Allow, `products:write` → Ask, `customers:export` → Deny, `products:delete` → Deny (`*:delete`), `inventory:read` → Deny `default_deny`.
  - `rule_when_matches_param_glob`: the §6.9.1 table form.
  - `locked_overlay_allow_ignored` and `developer_overlay_allow_counts`.
  - `overlay_deny_beats_system_allow`.
  - `typed_services_reject_unknown_key` (`allwo = []` → error naming the key and the file).
  - `profile_key_reserved`.
  - `run_allow_refuses_interpreters`: `run_allow = ["/usr/bin/python3"]` → error. The refused basenames are `sh bash dash zsh fish ksh csh tcsh busybox env python python3 perl ruby node deno bun php lua tclsh osascript`, plus any `python3.*`.
  - `policy_hash_changes_with_service`: editing one `allow` entry changes `policy_hash`.
- [ ] **Step 2:** `cargo test -p saiife-policy` → the new tests fail.
- [ ] **Step 3:** Implement. Existing tests that build `services` as `toml::Table` move to `ServiceCfg`.
- [ ] **Step 4:** `cargo test --workspace` green. `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 5:** Commit `feat(policy): typed services, capabilities and the deny/ask/allow decision`.

### Task 2: `crates/broker` — manifests, parameters, operation resolution

**Files:**
- Create: `crates/broker/Cargo.toml` (`saiife-broker`), `crates/broker/src/{lib.rs, manifest.rs, params.rs, resolve.rs, catalog.rs}`, `crates/broker/connectors/test-echo.toml` (built only under `cfg(test)`, through `include_str!` in a test module)
- Modify: `Cargo.toml` workspace (members is already `crates/*`)

**Interfaces:**
- Produces (`manifest.rs`):
  - `pub struct Manifest { pub id: String, pub version: u32, pub title: String, pub base_url: String, pub hosts: Vec<String>, pub auth: Vec<AuthSpec>, pub request_headers: Vec<String>, pub params: BTreeMap<String, ParamSpec>, pub operation: Vec<Operation> }`, the §8.4 schema with `deny_unknown_fields`.
  - `pub struct Operation { pub id: String, pub capability: String, pub qualifier: Option<String>, pub kind: OpKind, pub method: String, pub path: String, pub path_params: BTreeMap<String, String>, pub query: BTreeMap<String, String>, pub body: Option<String>, pub pagination: Option<Pagination>, pub amount: Option<AmountSpec> }`
  - `pub enum OpKind { Read, Write, Delete, Bulk }` and `pub enum Pagination { LinkHeader, Cursor { param: String, next: String } }`. `next` is a JSON path such as `paging.next.after`.
  - `pub struct AmountSpec { pub field: String, pub currency_field: String, pub unit: Unit }`, with `pub enum Unit { Major, Minor }`.
  - `pub struct AuthSpec { pub kind: String, pub name: Option<String>, pub secret_field: String }`
  - `pub fn builtin() -> &'static [Manifest]`: parses `include_str!` of every `connectors/*.toml` once. A parse error panics. The test `every_builtin_manifest_loads` turns that into a build-time failure.
  - `pub fn load_local(dir: &Path) -> Result<Vec<Manifest>, BrokerError>`: root-owned files only (the same owner check as `policy::load`). An id equal to a built-in id → `BrokerError::ShadowsBuiltin`.
  - `pub fn from_http_service(name: &str, svc: &ServiceCfg) -> Result<Manifest, BrokerError>`: the generic `http` connector (§6.8.2). `hosts` is the `base_url` host.
- Produces (`params.rs`):
  - `pub enum ParamType { String { pattern: Option<Regex> }, Int { min: Option<i64>, max: Option<i64> }, Enum(Vec<String>), Datetime, Bool }`, parsed from `"string"`, `"int"`, `"int:1..250"`, `"enum:a,b"`, `"datetime"` (RFC 3339), `"bool"`.
  - `pub fn validate(op: &Operation, given: &BTreeMap<String, String>, fixed: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>, BrokerError>`. Unknown → `UnknownParam(name)`. A param in `fixed` given by the agent → `FixedParam(name)`. Any value with a control character (`< 0x20` or `0x7f`) → `BadValue`. Path params may not hold `/`, `%2f`/`%2F` (also after one percent-decoding), U+2215, U+FF0F, `..` or an empty string.
- Produces (`resolve.rs`):
  - `pub fn named<'m>(m: &'m Manifest, id: &str) -> Option<&'m Operation>`
  - `pub fn proxy<'m>(m: &'m Manifest, method: &str, raw_path_and_query: &str) -> Result<(&'m Operation, BTreeMap<String, String>), BrokerError>`. First it rejects (`BrokerError::BadPath`) a `raw` that is not origin-form, or that contains `//`, `..`, `%2e`/`%2E`, `%2f`/`%2F`, `%5c`/`%5C`, `\`, `#`, or a NUL. Then it matches segment-wise against each operation's `path` template with `method` equality. Exactly one match, or `UnknownOperation`.
- Produces (`catalog.rs`):
  - `pub struct Catalog { manifests: BTreeMap<String, Manifest> }` with `pub fn new(builtin, local) -> Catalog` and `pub fn manifest_for(&self, name: &str, svc: &ServiceCfg) -> Result<Cow<Manifest>, BrokerError>`.
  - `pub fn validate(cfg: &SystemConfig, cat: &Catalog) -> Result<Vec<String>, BrokerError>`. It errors on an unknown connector, a missing required manifest param in `params`, or a param in `params` that the manifest does not declare. It warns (returned strings) on an `allow`/`ask`/`deny` pattern that matches no operation's capability.

- [ ] **Step 1: Failing tests:**
  - `every_builtin_manifest_loads`: the list may be empty until Task 12. The test also loads `test-echo.toml`.
  - `unknown_manifest_key_is_error`
  - `param_types_table`: `int:1..250` refuses `0` and `251`; `enum` refuses `Open`; `datetime` refuses `2026-13-01`.
  - `fixed_param_cannot_be_overridden`: the §6.7.1 step 5 example `shop`.
  - `path_param_double_encoded_slash_rejected`: `%252f`, `%2F`, `a/b`, `／`, `..`.
  - `proxy_rejects_traversal_table`: `/../admin`, `/%2e%2e/x`, `/a//b`, `http://evil/x`, `//evil/x`, `/a%2fb`, `/a\b`, `/a#b`.
  - `proxy_matches_template_and_query`: `GET /orders.json?status=open` → `orders.list` with `{status: open}`.
  - `proxy_method_mismatch_is_unknown_operation`
  - `local_manifest_cannot_shadow_builtin` (use `test-echo` as the "built-in" through a constructor seam).
  - `http_service_becomes_manifest`: the §6.8.2 `erp` example.
  - `catalog_validate_missing_required_param`
- [ ] **Step 2:** `cargo test -p saiife-broker` fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace` green. Clippy clean.
- [ ] **Step 5:** Commit `feat(broker): connector manifests, parameter validation and operation resolution`.

### Task 3: `broker` — limits and amounts

**Files:**
- Create: `crates/broker/src/limits.rs`, `crates/broker/src/amount.rs`

**Interfaces:**
- Produces (`amount.rs`):
  - `pub fn exponent(currency: &str) -> u32`: decision 7 table.
  - `pub fn extract(spec: &AmountSpec, body: &serde_json::Value) -> Result<(u64 /*minor*/, String /*currency*/), BrokerError>`. `a.b[].c` sums over the array. Numbers or numeric strings, at most `exponent` decimals. Negative, missing or non-numeric → `BadAmount`.
- Produces (`limits.rs`):
  - `pub struct Key { pub uid: u32, pub service: String, pub session: Option<String> }`
  - `pub struct Event { pub at: OffsetDateTime, pub key: Key, pub kind: OpKind, pub amount_minor: Option<(u64, String)> }`
  - `pub struct Limiter` with:
    - `pub fn new() -> Limiter`
    - `pub fn check_and_commit(&self, k: &Key, kind: OpKind, amount: Option<(u64, &str)>, cfg: &LimitsCfg, now: OffsetDateTime) -> Result<Reservation, &'static str /*limit name*/>`
    - `pub fn rebuild(records: impl Iterator<Item = Event>, now: OffsetDateTime) -> Limiter`
  - Windows: `requests_per_minute` 60 s; `writes_per_hour` 3600 s; `deletes_per_day` and `amount_per_day` 86 400 s; `bulk_per_session` 86 400 s. Each check runs against both the (uid, service) bucket and the (uid, service, session) bucket. Limit names are the config key (`requests_per_minute`, …), plus `amount_per_request` and `amount_currency` (the cap currency differs from the request currency).
  - `deletes_per_day = 0` denies every delete.
  - Check and commit happen under one lock, so two concurrent requests cannot both take the last slot. `Reservation::commit(self)` is called once the request was sent upstream; dropping it uncommitted releases the slot.
- Consumes: `OpKind`, `AmountSpec` (Task 2); `LimitsCfg`, `AmountCap` (Task 1).

- [ ] **Step 1: Failing tests:**
  - `rpm_61st_denied_then_ok_after_window` (injected `now`)
  - `session_bucket_and_uid_bucket_both_apply`: two sessions of one uid share the uid bucket.
  - `null_session_is_one_bucket`
  - `deletes_zero_means_never`
  - `amount_per_day_sums_minor_units`: refunds of 200 + 250 EUR pass, then 100 EUR → `amount_per_day`.
  - `split_refund_still_capped`: 600 × 1 EUR against `max = 500`.
  - `amount_currency_mismatch_denied`
  - `jpy_exponent_zero`
  - `extract_sums_array_path` (`refund.transactions[].amount`)
  - `concurrent_last_slot_once`: 2 threads, 1 slot left → exactly one `Ok`.
  - `rebuild_from_records_keeps_window`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(broker): sliding-window limits and amount caps`.

### Task 4: `daemon` — vault store

**Files:**
- Create: `crates/daemon/src/vault.rs`
- Modify: `crates/daemon/src/lib.rs` (`DaemonOptions.credentials_dir: Option<PathBuf>`), `crates/daemon/src/start.rs` (load the key and open the vault at start; `daemon`/`vault_unavailable` record with `reason`), `crates/cli/src/main.rs` (hidden `--credentials-dir`; default `$CREDENTIALS_DIRECTORY`)

**Interfaces:**
- Produces:
  - `pub enum Kind { Token, Basic, Header }`. Serde: `token`, `basic`, `header`. Fields: decision 2.
  - `pub struct Entry { pub name: String, pub kind: Kind, pub fields: BTreeMap<String, Zeroizing<String>>, pub allowed_services: Vec<String>, pub created_by: u32, pub created: String, pub last_used: Option<String>, pub rotate_after: Option<String> }`. `Debug` is hand-written and prints field names only.
  - `pub enum VaultState { Ready(Vault), Unavailable(String /*reason*/) }`
  - `pub fn open(key_file: &Path, vault_file: &Path) -> VaultState`. Reasons: `no vault key`, `vault key is not 32 bytes`, `vault cannot be decrypted`, `vault file is not a saiife vault`. A missing `vault.bin` with a good key gives `Ready(empty)`.
  - `impl Vault`:
    - `get(&self, name) -> Option<&Entry>`
    - `put(&mut self, e: Entry) -> io::Result<()>`
    - `remove(&mut self, name) -> io::Result<bool>`
    - `list(&self) -> Vec<Meta>`
    - `touch(&mut self, name, ts)`: in memory only. `flush_if_due(now)` writes at most once per 60 s, and on stop.
  - `pub const MAGIC: &[u8; 8] = b"SAIIFEV1"; pub const VERSION: u8 = 1;`
  - Name: `^[a-z0-9][a-z0-9._-]{0,63}$`.
- Consumes: `chacha20poly1305::XChaCha20Poly1305`, `getrandom` (already in the workspace through `system`).

- [ ] **Step 1: Failing tests:**
  - `round_trip_put_reopen`
  - `new_nonce_every_write`: two writes of the same content give different bytes 9..33.
  - `aad_binds_magic_and_version`: flip the version byte → `cannot be decrypted`.
  - `wrong_key_is_unavailable`
  - `short_key_is_unavailable`
  - `atomic_write_leaves_no_temp_on_success` and `failed_rename_keeps_old_vault` (seam: a read-only dir)
  - `file_and_dir_modes_0600_0700`
  - `debug_never_prints_values`: `format!("{:?}", entry)` does not contain the value.
  - `add_refuses_when_vault_undecryptable`: `Unavailable` gives no `put` path. The ops layer (Task 5) asserts the exact message.
  - `last_used_flushed_at_most_once_per_minute`
- [ ] **Step 2:** fail. **Step 3:** implement. Plaintext JSON is built and parsed only inside `Zeroizing<Vec<u8>>`.
- [ ] **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(daemon): encrypted vault file (XChaCha20-Poly1305, atomic writes)`.

### Task 5: `secret` ops and `saiife secret`

**Files:**
- Create: `crates/daemon/src/secret_ops.rs`, `crates/cli/src/secret_cmd.rs`, `crates/cli/tests/secret_cmd.rs`
- Modify: `crates/ipc/src/msg.rs` (op constants `secret.add`, `secret.remove`, `secret.rotate`, `secret.list`; `ErrorCode::VaultUnavailable`), `crates/daemon/src/ops.rs` (dispatch), `crates/cli/src/main.rs`

**Interfaces:**
- Produces (IPC, §8.7). Every op is admin only (`ctx.is_admin`); anyone else gets `Forbidden` and a `secret` record with `decision = "deny"`.
  - `secret.add {name, kind, fields, allowed_services}` → `{}`. The name must not exist yet (`rotate` replaces).
  - `secret.rotate {name, fields}` keeps the kind and services.
  - `secret.remove {name}`
  - `secret.list` → `{secrets: [{name, kind, allowed_services, created_by, created, last_used, rotate_after}]}`
  - `VaultUnavailable` message: `vault cannot be read; restore it or remove <path> by hand`.
- Records: kind `secret`, `tool = "secret"`, `input = "<event> <name>"`, extra `{event: secret_add|secret_rotate|secret_remove, name}`. A record never holds a field value.
- CLI:
  - `saiife secret add <name> --kind token|basic|header --service <s>... [--from-file <p> | --from-env <VAR>]`. At least one `--service`. With neither source flag, it reads each field from the terminal without echo (rustix termios, restored on every path including Ctrl-C), or refuses if stdin is not a tty. One trailing `\n` is stripped from file input.
  - `saiife secret list [--json]`, `saiife secret remove <name>`, `saiife secret rotate <name> [source flags]`
  - Exit codes: 0 ok, 2 refused, 5 daemon unavailable.

- [ ] **Step 1: Failing tests** (cli tests spawn a real daemon on tempdirs, as 9a's `daemon_*` tests do):
  - `add_list_remove_round_trip`
  - `non_admin_add_is_forbidden_and_recorded`: start the daemon with `[admin] groups = []`. The test user is not uid 0, so the op is forbidden.
  - `value_never_in_audit_or_stderr`: grep every audit file and the stderr of every call for the value and its base64.
  - `add_refuses_when_vault_undecryptable`: corrupt `vault.bin` → exit 2 with the exact message, and `vault.bin` stays byte-identical.
  - `unsupported_kind_refused`: `--kind oauth2` → `kind oauth2 comes with plans 14–15`.
  - `from_env_and_from_file`
  - `non_tty_without_source_refuses`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(secret): admin secret add/list/rotate/remove through the daemon`.

### Task 6: `daemon` — session attribution

**Files:**
- Create: `crates/daemon/src/sessions.rs`
- Modify: `crates/daemon/src/ops.rs` (`append` stores the session of each guard record)

**Interfaces:**
- Produces:
  - `pub trait Proc { fn stat(&self, pid: u32) -> Option<ProcStat>; fn cmdline(&self, pid: u32) -> Option<Vec<String>>; }`, with `pub struct ProcStat { pub ppid: u32, pub comm: String, pub start_time: u64 }`. `pub struct RealProc { root: PathBuf }` reads `<root>/<pid>/stat` and `cmdline`; production root is `/proc`. Parse `comm` between the first `(` and the **last** `)`.
  - `pub fn agent_ancestor(p: &dyn Proc, pid: u32) -> Option<(u32, u64)>`: walks up at most 64 levels. A match is a comm in `claude codex gemini`, or `node` with one of those in an argv element's basename. The start time is checked before and after the walk; a change gives `None` (§6.3 fallback).
  - `pub struct Sessions` with:
    - `record(&self, ancestor: (u32, u64), session_id: &str)`: the newest wins, at most 4 096 entries, oldest evicted.
    - `lookup(&self, ancestor) -> Option<String>`
- Consumes: the peer pid from `PeerCred`.

- [ ] **Step 1: Failing tests** use a fake proc tree in a tempdir:
  - `walks_to_claude`
  - `node_with_codex_argv_matches`
  - `comm_with_parens_parsed` (`(a) b)`)
  - `pid_reuse_changes_start_time_gives_none`
  - `loop_and_depth_capped`
  - `double_fork_escape_lands_in_null_session`: the requester's chain ends at pid 1 → `None`.
  - `eviction_at_4096`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(daemon): attribute connector requests to agent sessions via /proc`.

## Part B — upstream, pipeline, entry points

### Task 7: `broker` — request building and the HTTPS client

**Files:**
- Create: `crates/broker/src/request.rs`, `crates/broker/src/upstream.rs`, `crates/broker/tests/golden/` (one `.http` file per golden case), `crates/broker/tests/upstream.rs`

**Interfaces:**
- Produces (`request.rs`):
  - `pub struct Built { pub method: http::Method, pub uri: http::Uri, pub headers: http::HeaderMap, pub body: Option<Bytes> }`
  - `pub fn build(m: &Manifest, op: &Operation, svc_params: &BTreeMap<String, String>, params: &BTreeMap<String, String>, agent_headers: &[(String, String)], body: Option<Bytes>, auth: &AuthMaterial) -> Result<Built, BrokerError>`. It fills `base_url` `{x}` from `svc_params`. The final host must match `hosts` (a glob of one label for `*.`). Agent headers survive only if listed in `request_headers` (case-insensitive). `Authorization`, `Cookie` and `Host` are always dropped. A header value with CR, LF or NUL → `BadValue`. Auth goes into exactly one place, per `AuthSpec.kind` (`header` name, `bearer` → `Authorization: Bearer`, `basic`).
  - `pub struct AuthMaterial { pub kind: String, pub name: Option<String>, pub fields: BTreeMap<String, Zeroizing<String>> }`, built from the manifest's `AuthSpec` and a vault entry's fields. `pub fn values(&self) -> Vec<&str>` feeds the `Masker` (Task 8).
- Produces (`upstream.rs`):
  - `pub trait Resolver: Send + Sync { fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>; }` with `SystemResolver`.
  - `pub struct Upstream` with:
    - `pub fn new(ca_dir: &Path, timeout: Duration) -> Result<Upstream, BrokerError>`: native roots plus every `*.pem` in `ca_dir`, rustls `ring`, HTTP/1.1 only, no proxy env vars read.
    - `pub fn with_roots(roots: RootCertStore, resolver: Arc<dyn Resolver>, timeout) -> Upstream`: the test seam.
    - `pub async fn send(&self, b: Built, read_limit: usize) -> Result<UpstreamResponse, BrokerError>`
  - `pub struct UpstreamResponse { pub status: u16, pub headers: HeaderMap, pub body: Bytes, pub truncated: bool }`. The body is read up to `read_limit` bytes, and `truncated` is set when more was available.
  - Redirects 301/302/303/307/308: followed only when scheme, host and port all equal the original, with no userinfo, and at most 3 times. Otherwise `BrokerError::RedirectRefused`. 303 becomes GET without a body.
  - Only `https` is sent, except when the test seam built the `Upstream` with `allow_http_for_tests`, which is `cfg(test)` only.
- Consumes: Task 2 types.

- [ ] **Step 1: Failing tests:**
  - Golden: `build_shopify_like_orders_list.http`, `build_bearer.http`, `build_basic.http`, `build_path_param_encoded.http` (`order_id = "12 34"` → `%20`). Each compares the method, URL and sorted headers. The auth value in the golden file is `<AUTH>`, and the test substitutes it.
  - `lowercase_authorization_dropped`, `host_and_cookie_dropped`, `crlf_in_header_value_rejected`
  - `base_url_host_must_match_hosts` (`shop = "evil.com#"` is refused by the manifest pattern; a host outside `*.myshopify.com` → error)
  - Upstream tests run a loopback hyper server with an `rcgen` certificate for `acme.example.test` and a resolver mapping it to 127.0.0.1:
    - `sends_over_tls_and_reads_body`
    - `redirect_same_origin_followed_max_3`: a 4th redirect is refused.
    - `redirect_other_host_refused`, `redirect_other_port_refused`, `redirect_downgrade_refused`
    - `timeout_is_enforced`: the server sleeps longer than a 200 ms timeout.
    - `read_limit_sets_truncated`
    - `untrusted_cert_refused`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green (also under `scripts/test-offline.sh`) and clippy clean.
- [ ] **Step 5:** Commit `feat(broker): upstream request building and pinned HTTPS client`.

### Task 8: `broker` — response masking, redaction, truncation

**Files:**
- Create: `crates/broker/src/mask.rs`, `crates/broker/src/redact.rs`

**Interfaces:**
- Produces:
  - `pub struct Masker` with `pub fn new(values: &[&str]) -> Masker`. It builds every form in Global Constraints and skips values shorter than 4 bytes (they would mask noise; the vault refuses such values at add time anyway). `pub fn mask_bytes(&self, b: &[u8]) -> Vec<u8>` uses Aho-Corasick, longest match first. `pub fn mask_text(&self, s: &str) -> String` also applies `saiife_audit::mask::mask`.
  - `pub fn redact(v: &mut serde_json::Value, fields: &[String]) -> usize /*count*/`: decision 5.
  - `pub fn finish(resp: UpstreamResponse, masker: &Masker, redact: &[String], max: usize) -> Result<Finished, BrokerError>`. Order:
    1. mask the bytes,
    2. if `redact` is set, parse the JSON, redact, mask the text pass, and re-serialize; not JSON → `RedactNonJson`,
    3. cut to `max` and set `truncated`.
  - Masks response headers on an allowlist (`Content-Type`, `Link`, `Retry-After`, `ETag`, `X-RateLimit-*`, `RateLimit-*`, `X-Shopify-Shop-Api-Call-Limit`) and drops all others.
  - `pub struct Finished { pub status: u16, pub headers: HeaderMap, pub body: Bytes, pub truncated: bool, pub redacted: usize }`
- Note: Task 9 sets `read_limit = max + 65_536` (Review Focus 1).

- [ ] **Step 1: Failing tests:**
  - `masks_raw_base64_url_hex_forms`, `masks_base64url_unpadded`
  - `masks_secret_straddling_cut`: the value starts at `max - 3`.
  - `v1_patterns_masked_in_text` (a `ghp_…` token that is not in the vault)
  - `redact_suffix_paths`: `customer.email` hits `orders[].customer.email`. `*.billing_address` hits `order.billing_address`, not `billing_address` at the root.
  - `redact_non_json_withheld`
  - `headers_outside_allowlist_dropped`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(broker): mask vault values and v1 patterns, redact fields, cut responses`.

### Task 9: pipeline, `api.call`/`api.list`, connector records, `saiife api`

**Files:**
- Create: `crates/broker/src/pipeline.rs`, `crates/daemon/src/api_ops.rs`, `crates/cli/src/api_cmd.rs`, `crates/cli/tests/api_cmd.rs`, `docs/connectors/README.md`, `docs/connectors/http.md`
- Modify: `crates/ipc/src/msg.rs` (`api.call`, `api.list`, `api.result`), `crates/daemon/src/{ops.rs, start.rs}` (catalog and limiter at start; rebuild from the last 24 h of `connector` records; validate on load and reload, so a broken service config means `policy` `result = "rejected"` and the old policy is kept), `crates/cli/src/main.rs`

**Interfaces:**
- Produces (`pipeline.rs`):
  - `pub struct Call { pub uid: u32, pub user: String, pub session: Option<String>, pub project: String, pub service: String, pub op: OpRef, pub params: BTreeMap<String, String>, pub body: Option<Bytes>, pub headers: Vec<(String, String)>, pub overlay: Option<ServiceOverlay>, pub via: Via }`, with `pub enum OpRef { Named(String), Proxy { method: String, path: String } }` and `pub enum Via { Cli, Http }`.
  - `pub trait Env { fn scope(&self, user: &str) -> Result<Option<Scope>, PolicyError>; fn secret(&self, name: &str, service: &str, auth: &AuthSpec) -> Result<AuthMaterial, &'static str /*rule*/>; }`
  - `pub async fn handle(call: Call, cfg: &PolicySnapshot, cat: &Catalog, lim: &Limiter, env: &dyn Env, up: &Upstream) -> Outcome`. `PolicySnapshot` is the `Arc` taken when the call starts, so a reload in flight cannot mix policies, and the record carries that snapshot's hash.
  - `pub enum Outcome { Done { finished: Finished, next: Option<BTreeMap<String, String>> }, Denied { rule: String }, Limited { limit: &'static str }, UpstreamFailed { reason: String } }`. The `connector` record is built from `call` and the `Outcome` with the exact §8.5 fields, plus `op_kind` and `amount` (`{minor, currency}`), which Task 3's rebuild reads. `params` are masked with `mask_text`. `body_sha256` and `body_bytes` are recorded, never the body.
  - Deny rules beyond the spec's: `policy_invalid`, `vault_unavailable`, `secret_missing`, `secret_not_allowed_for_service`, `approval_not_available`, `redirect_refused`, `redact_non_json`, `bad_param`, `bad_path`.
  - Concurrency: a `tokio::sync::Semaphore` of 4 per service around `send`.
- IPC:
  - `api.call {service, operation | {method, path}, params, body_b64?, headers?, overlay?, project, wait_ms?}` → `{status, body_b64, headers, truncated, next?}`, or an error answer with the new codes `denied` (extra field `rule`), `limited` (extra field `limit`) or `upstream_failed` (`ErrorCode::{Denied, Limited, UpstreamFailed}`; add `pub fn err_with(id, code, message, extra: Map) -> Value` to `msg.rs`). `wait_ms` is accepted and ignored until plan 11.
  - `api.list` → `{services: [{name, operations: [{id, capability, kind, action}]}]}`, for the caller's scope only. A caller with no scope gets an empty list.
  - `api.result` → `Unavailable` with `approvals come in plan 11`.
- CLI:
  - `saiife api --list [<service>] [--json]`
  - `saiife api <service> <operation> [k=v ...] [--body @file|-] [--wait <dur>] [--json]`
  - The client reads `.saiife/config.toml` of the cwd's project root (the same bounded read as 9a Task 1) for `overlay`. Exit codes follow Global Constraints. The stderr summary is `saiife: <service> <operation> → <status> (<bytes> bytes, <ms> ms)`, or `saiife: denied (<rule>)`.
- Docs: `docs/connectors/http.md` covers the generic connector, outbound webhooks as a fixed-URL `POST`, and a suggested policy with every write under `ask`.

- [ ] **Step 1: Failing tests.** Pipeline unit tests use a fake `Env` and the `test-echo` manifest over a loopback `Upstream`. CLI e2e tests use a real daemon, a generic `http` service pointing at a loopback mock, and a vault secret added through Task 5:
  - `no_scope_denied_no_upstream_call`: the mock counts zero hits.
  - `scope_conflict_denied`
  - `unknown_operation_denied`
  - `default_deny_denied`
  - `ask_denied_until_plan_11`
  - `secret_not_allowed_for_service`
  - `limit_reached_exit_4`
  - `limit_survives_restart`
  - `reload_mid_request_uses_start_snapshot` (the hook: the mock blocks until the test reloads)
  - `connector_record_fields_exact`: compare every §8.5 key.
  - `response_value_masked_end_to_end`: the mock echoes the token.
  - `secret_values_absent_from_all_audit_files`
  - `upstream_404_exit_1_and_body_on_stdout`
  - `daemon_down_exit_5`
  - `list_shows_only_scoped_services`
  - `policy_with_unknown_connector_rejected_on_reload`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** `cargo test --workspace` green, `scripts/test-offline.sh` green, clippy clean.
- [ ] **Step 5:** Commit `feat(api): connector pipeline, api.call/api.list and saiife api`.

### Task 10: HTTP gateway on `gateway.sock`

**Files:**
- Create: `crates/daemon/src/gateway.rs`, `crates/daemon/tests/gateway.rs`
- Modify: `crates/daemon/src/start.rs` (bind `<socket_dir>/gateway.sock` 0666 next to `saiife.sock`; `ConnLimits` shared with the control socket), `crates/ipc/src/msg.rs` (`GATEWAY_SOCKET_NAME = "gateway.sock"`)

**Interfaces:**
- Produces: `pub async fn serve(listener: UnixListener, ctx: Arc<Ctx>)`, built on hyper `http1::Builder` with `max_buf_size` 64 KiB for headers, a request body capped at 1 MiB (413 over that), and a 10 s header read timeout. The peer uid comes from `peer_cred` of each accepted stream. Routes and statuses are those of §8.8.
- Mapping:
  - `/v1/api/{s}/{op}` takes a JSON body `{params, body, wait}`.
  - `/v1/proxy/{s}/{rest}` passes the raw path and query of `{rest}` to `OpRef::Proxy`, and agent headers go to `Call.headers`.
  - Both call `pipeline::handle` with `Via::Http`.
  - `Denied` → 403. `Limited` → 429 `{"error":"limit","limit":…}`. `UpstreamFailed` → 502. Policy invalid or vault unavailable → 403 with that rule. Not ready → 503.
  - `/v1/requests/{id}` → 503 `{"error":"approvals come in plan 11"}`.
- Never reads `X-Forwarded-*` or proxy headers for identity. Only the peer uid counts.

- [ ] **Step 1: Failing tests** (hyper client over `UnixStream`):
  - `services_lists_scope`
  - `api_route_200_with_upstream_status_header`
  - `proxy_passthrough_status_and_masked_link`
  - `proxy_traversal_403_bad_path`: the §6.7.1 step 4 table again, sent over HTTP, including raw `%2e%2e` that hyper must not normalize first.
  - `authorization_header_from_agent_not_forwarded`: the mock asserts the vault token, not the agent's.
  - `body_over_1mib_413`
  - `slow_headers_closed_after_10s` (injected 200 ms in the test)
  - `limit_429`
  - `non_scoped_uid_403_no_scope`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(gateway): HTTP/1.1 connector gateway on gateway.sock`.

### Task 11: optional loopback TCP listener and `saiife api token`

**Files:**
- Create: `crates/daemon/src/tokens.rs`
- Modify: `crates/daemon/src/{gateway.rs, start.rs}`, `crates/ipc/src/msg.rs` (`api.token`), `crates/cli/src/api_cmd.rs`

**Interfaces:**
- `[gateway] tcp` empty means no listener. Any value whose IP is not loopback (`127.0.0.0/8`, `::1`) is a config error.
- `api.token` → `{token, expires}`. The token is 32 random bytes as base64url, prefixed `saiife_gw_`. The daemon keeps `sha256(token) → (uid, expires)` in memory and in `<state>/state/gateway-tokens.json` (0600), and drops expired ones at start and hourly. TTL is 12 h.
- On TCP, `Authorization: Bearer <token>` is required and maps to the uid. That header is consumed and never forwarded. A missing, expired or unknown token → 401 `{"error":"token"}`.
- `saiife_gw_` is added to the v1 masking patterns in `crates/audit/src/mask.rs`.

- [ ] **Step 1: Failing tests:**
  - `tcp_off_by_default`
  - `non_loopback_tcp_is_config_error`
  - `token_maps_to_uid`
  - `expired_token_401` (injected clock)
  - `token_hashed_on_disk`: the raw token is absent from the state file.
  - `token_never_forwarded_upstream`
  - `token_masked_in_records`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green and clippy clean.
- [ ] **Step 5:** Commit `feat(gateway): opt-in loopback TCP listener with uid-bound bearer tokens`.

## Part C — connectors and admin tools

Each connector task follows the same shape:
- Files: `crates/broker/connectors/<id>.toml`, `crates/broker/tests/<id>.rs`, `crates/broker/tests/fixtures/<id>/*.json` (responses copied from the vendor's documented examples, with the docs URL in a `_source` key or a sibling `.md`), and `docs/connectors/<id>.md` (operations, capabilities, a suggested **read-only** policy, a second policy with every write under `ask`, limits, the locked-mode section).
- Tests, per operation: golden request (method, URL, headers, auth placement); parse of the fixture response; pagination `next`. For each write: denied by default, allowed by policy, and the amount extracted where the operation has `amount`. Plus `every_builtin_manifest_loads`.
- The implementer checks each path against the vendor's current REST reference and records the URL as a comment at the top of the manifest. The spec fixes the operation ids; the vendor fixes the paths.

### Task 12: Shopify

- `base_url = "https://{shop}.myshopify.com/admin/api/2026-07"`, `hosts = ["*.myshopify.com"]`, auth header `X-Shopify-Access-Token` (`secret_field = "token"`), `request_headers = ["Content-Type", "Accept", "Idempotency-Key"]`, param `shop` `^[a-z0-9-]+$` required. This is exactly §8.4.
- Operations (id → capability, kind):
  - `orders.list` → `orders:read` (link-header)
  - `orders.get` → `orders:read`
  - `products.list` → `products:read` (link-header)
  - `products.get` → `products:read`
  - `products.update` → `products:write`, write
  - `customers.list` → `customers:read`
  - `customers.export` → `customers:export`, bulk
  - `refunds.create` → `refunds:write`, write, `amount = { field = "refund.transactions[].amount", currency_field = "refund.currency", unit = "major" }`
  - `discounts.create` → `discounts:write`, write (price rule plus discount code: the operation is the price-rule `POST`; the docs page says so)
- Extra test: `refund_amount_cap_end_to_end` through the pipeline with `amount_per_day = { max = 500, currency = "EUR" }`.
- Commit: `feat(connectors): Shopify Admin API (wave 1)`.

### Task 13: HubSpot

- `base_url = "https://api.hubapi.com"`, `hosts = ["api.hubapi.com"]`, auth `bearer` (private app token), `request_headers = ["Content-Type", "Accept"]`.
- Operations:
  - `contacts.list`, `contacts.get` → `contacts:read`
  - `contacts.update` → `contacts:write`
  - `companies.list`, `companies.get` → `companies:read`
  - `deals.list`, `deals.get` → `deals:read`
  - `deals.update` → `deals:write`
- Paths are under `/crm/v3/objects/...`. Pagination is `Cursor { param = "after", next = "paging.next.after" }`.
- Commit: `feat(connectors): HubSpot CRM (wave 1)`.

### Task 14: GitHub

- `base_url = "https://api.github.com"`, `hosts = ["api.github.com"]`, auth `bearer`, `request_headers = ["Content-Type", "Accept", "X-GitHub-Api-Version"]`.
- Every repo operation has `qualifier = "repo={owner}/{repo}"`, so `issues:write:repo=acme/*` works (§6.9.1).
- Operations:
  - `repos.get` → `repos:read`
  - `issues.list`, `issues.get` → `issues:read` (link-header)
  - `issues.create`, `issues.comment` → `issues:write`
  - `pulls.list`, `pulls.get` → `pulls:read`
  - `pulls.create` → `pulls:write`
- Extra test: `qualifier_policy_end_to_end`. `issues:write:repo=acme/*` allows `acme/web` and denies `other/web`.
- Commit: `feat(connectors): GitHub REST (wave 1)`.

### Task 15: `saiife connect <service>`

**Files:** Create `crates/cli/src/connect_cmd.rs`, `crates/cli/tests/connect_cmd.rs`.

**Interfaces:**
- `saiife connect <service> [--connector <id>] [--secret <name>] [--param k=v ...] [--config <file>]`. Admin only: the daemon `secret.add` check, plus a write test on `policy.d/`.
  1. Picks the manifest (`--connector`, default `<service>` if a built-in id).
  2. Runs Task 5's secret add flow (`--secret`, default `<service>`, `--service <service>`).
  3. Writes `<config dir>/policy.d/<service>.toml` with `[services.<service>]`, `connector`, `secret`, `params`, and **every operation as a commented-out line** under `# allow`, `# ask` and `# deny`, writes marked `# write`. Written 0644 with `write_new_file`, so an existing file → refuse with `policy.d/<service>.toml exists; edit it`.
  4. Prints `next: edit <path>, then saiife policy reload`.
- `generated_file_denies_everything`: the generated file loads and validates, and every operation decides `Deny default_deny`.

- [ ] Steps: failing tests (`generated_file_denies_everything`, `existing_file_refused`, `unknown_connector_refused`, `required_param_prompted_or_refused`), then fail, implement, green and clippy clean.
- [ ] Commit `feat(connect): set up a service with its secret and a deny-all policy file`.

### Task 16: `saiife run --secret` and `secret.lease`

**Files:** Create `crates/cli/src/run_cmd.rs`, `crates/cli/tests/run_cmd.rs`. Modify `crates/daemon/src/secret_ops.rs` and `crates/ipc/src/msg.rs` (`secret.lease`).

**Interfaces:**
- `secret.lease {name, exe}`. The daemon resolves `exe`: it must be absolute and canonical, a regular file owned by uid 0 and not group- or world-writable, with every parent the same (reuse the `system` crate's root-owned path check). It must be listed in `[secrets.<name>] run_allow`, and the caller must be in a scope. On success → `{value}` (token kind: the token; basic: `user:pass`; header: the value) and a `secret` record `event = "secret_use"`, `input = "run <name> <exe>"`. Otherwise → `Denied { rule: "run_not_allowed" }`, recorded.
- `saiife run --secret <name>[:ENV_VAR] -- <cmd> [args]`. `ENV_VAR` defaults to the name upper-cased, with `-` and `.` turned into `_`. The client resolves `<cmd>` through `PATH` to a canonical path, leases, spawns with the variable set and stdout/stderr piped, masks both streams with a `Masker` for that value (line-buffered, with a carry-over window so a value split across reads is still masked), and exits with the child's code.
- Tests run the daemon with `run_allow` naming a root-owned binary that exists on every CI runner (`/usr/bin/env` is refused as an interpreter, so use `/bin/echo` or `/usr/bin/printenv`), checked by a test helper at test time.

- [ ] Steps: failing tests:
  - `run_masks_value_in_output` (`printenv TOKEN`)
  - `not_listed_refused_and_recorded`
  - `interpreter_in_run_allow_is_config_error`
  - `user_owned_binary_refused` (a copy in a tempdir)
  - `split_value_across_reads_masked`
  - `no_scope_refused`

  Then fail, implement, green and clippy clean.
- [ ] Commit `feat(run): lease a secret into one allowed command, masking its output`.

### Task 17: `saiife secret import`

**Files:** Create `crates/cli/src/import_cmd.rs`, `crates/cli/tests/import_cmd.rs`. Modify `crates/daemon/src/secret_ops.rs` (`secret.add` accepts an optional `backup {path, bytes_b64}` and writes it to `<state>/state/import-backup/<ts>-<sanitized path>` 0600; files older than 7 days are purged at start and daily).

**Interfaces:**
- `saiife secret import --user <name> [--project <dir>]... [--yes-to <path>]...` (admin). It reuses `saiife_system::doctor::secrets::scan_report` on the user's home and project roots. For each finding it shows the path and what was found, never the value, and asks `store as <suggested name>? [y/N/e(dit name)]`.
  - On yes: parse the credential. `.env*`: `KEY=VALUE` lines whose key matches the doctor's `CREDENTIAL_KEYS`, one secret per key. `.git-credentials`: token kind. `.config/gh/hosts.yml`: `oauth_token`. `.npmrc`: `_authToken`. `.vault-token`: whole file.
  - Then `secret.add` with the backup, then rewrite the source with that line removed (or empty the file when the whole file was the secret), keeping owner and mode, through a temp file and rename in the same dir.
  - Then print the suggested `saiife connect` line and `rotate this credential: it was readable by <user>` (§12 step 3).
  - Cloud and kube files (`.aws`, `.config/gcloud`, `.azure`, `.kube/config`, `.docker/config.json`) are listed with `cloud credentials come with plan 15; remove or rotate by hand` and are never touched.
- The source is changed only after the daemon acked the add and the backup. A failed add leaves the source byte-identical.

- [ ] Steps: failing tests on a fake home in a tempdir, run as the test user with an admin group:
  - `env_line_imported_and_removed`
  - `git_credentials_imported`
  - `failed_add_leaves_source_untouched` (vault made unavailable)
  - `aws_listed_not_touched`
  - `backup_written_and_purged_after_7_days` (injected clock)
  - `value_never_printed`

  Then fail, implement, green and clippy clean.
- [ ] Commit `feat(secret): import plaintext credentials into the vault, with backup`.

## Finish

- [ ] **Fuzzing.** Create `fuzz/` (its own `Cargo.toml`, excluded from the workspace) with `cargo-fuzz` targets `ipc_frame` (`saiife_ipc::frame::decode` and `body_len`), `proxy_path` (`resolve::proxy` against all built-in manifests), `params` (`params::validate`) and `gateway_request` (raw bytes into the gateway's routing function, extracted as `gateway::route(&http::Request<Bytes>) -> Route`). Add the CI job `fuzz` (ubuntu, nightly toolchain pinned by date, 60 s per target on PRs) and a scheduled workflow, also job `fuzz`, running 30 min per target nightly. Job ids have no dots. Commit `ci(fuzz): fuzz IPC frames, proxy paths, params and gateway routing`.
- [ ] **Red-team cases for the 9c suite.** Append to the 9c plan's case list, not to code: A11 (a credential file the import left, readable as the agent user, is reported by `doctor`), A12 (the imported key is gone from the home), A13 (the Task 10 traversal table plus header injection via `curl --unix-socket`, as the agent user), A14 (the 61st request in a minute → 429 and a record), A20 (the echoed token comes back `[MASKED]`). Same arrangement as 9c: the owner writes the scripts and Claude reviews them. Commit `docs(plan-9c): red-team cases A11–A14, A20 from plan 10`.
- [ ] **Docs.** `docs/connectors/README.md` lists the four connectors. `README.md` gets one paragraph on brokered services, using §10's wording rule verbatim ("the agent never holds a credential for a brokered service; it holds its own model-provider login unless you run a local model"). `CHANGELOG.md` gets an Unreleased entry.
- [ ] **Gates:** `cargo test --workspace`, `scripts/test-offline.sh`, clippy, fmt, the tokio gate, and `scripts/bench-check.sh` on an idle machine (put the numbers in the PR). Then the whole-branch review (Opus, security focus) and one fix wave, push, CI, PR. The owner merges.

## Appendix: red-team cases for the 9c suite

These cases extend the 9c case list (spec §9.2). They are descriptions, not scripts: the owner writes the scripts and Claude reviews them. Each runs as the agent user against a locked-mode install made by `system install`, as in 9c. In every case the daemon's audit log is the record to check, and the suite fails the case if an expected record is missing.

### A11: a credential file the import left behind

- **Setup.** The agent user's home holds a credential the import did not take: for example a `.env` with an API key that the admin declined at the `store as ...?` prompt, or a cloud file such as `~/.aws/credentials`, which `secret import` lists but never touches. A second key in another file was imported, so the suite can tell the two apart.
- **Attack.** As the agent user, outside any tool call, the script reads the file that was left and recovers the key. This confirms the residual risk the spec names for A11: what was never imported is still readable.
- **Expected result.** The read succeeds (known and documented). `saiife doctor --user <agent>` reports the leftover file as a plaintext credential (a warning, exit code 1 or higher) and names the path, never the value. The imported file no longer contains its credential. The doctor output and the audit log hold no credential value.
- **Record.** The read itself is not seen by the daemon. The suite checks the `doctor` finding, and that the `secret add` (with backup) of the imported credential has a record that holds the name and not the value.

### A12: calling the service with a key found in the home

- **Setup.** One credential was imported with `secret import` and then connected with `saiife connect`. The suite keeps the original value as a test fixture, and it controls a loopback upstream that records which credentials it sees.
- **Attack.** As the agent user, the script searches the home and the project for the imported key: the source file, shell history, editor and tool caches, the environment of its own processes, and `~/.saiife`. It then tries to call the upstream directly with anything it finds.
- **Expected result.** The key is not found anywhere readable by the agent user. The only copies are the vault (encrypted, unreadable to the agent user) and the import backup, which the daemon keeps under its own state directory with owner-only access. The direct call has nothing to use.
- **Record.** The `secret add` record from the import exists. No `connector` record and no upstream request carries a call the agent made on its own, and the original value appears in no file the agent user can read.

### A13: abusing the gateway

- **Setup.** A service is connected with a policy that allows one read operation. A loopback upstream records every request it gets (method, path, headers). The agent user can reach `gateway.sock`, and only that.
- **Attack.** Through `curl --unix-socket`, as the agent user, the script sends the traversal table of Task 10 (a `..` segment, encoded dots, an encoded slash, an encoded backslash, a double slash, an absolute URL, another host, a fragment, a NUL) on `/v1/proxy/...`, including raw forms that a client or server could normalize before the check. It also sends operations that are not listed, and operations that the policy does not allow. It then tries header injection: its own `Authorization`, `Cookie` and `Host`, forwarded and proxy headers that name another uid, and header values with line breaks.
- **Expected result.** Every traversal and unlisted-operation attempt is denied with HTTP 403 and the matching rule (`bad_path`, `unknown_operation` or `default_deny`). The upstream sees none of them. For the allowed read, the upstream sees the vault credential and never the agent's `Authorization` or `Cookie`, and the `Host` is the pinned one. The forwarded headers change nothing about identity: the caller is the uid of the socket peer. An upstream redirect to another host is not followed.
- **Record.** One `connector` record per attempt, with the deny rule, and none for attempts that never parsed as HTTP. The log holds no agent-supplied header values that look like credentials.

### A14: staying within policy but at volume

- **Setup.** A service has `requests_per_minute = 60` and an allowed read operation, with a loopback upstream that counts requests. The suite uses a fixed clock window or starts the minute fresh.
- **Attack.** As the agent user, the script sends 61 allowed requests inside one minute through `saiife api` or the gateway socket, as fast as it can, and then tries again from a second session of the same uid.
- **Expected result.** The first 60 are sent upstream. The 61st is refused with HTTP 429 (exit code 4 for `saiife api`) and `limit = "requests_per_minute"`, and the upstream sees 60 requests. The second session shares the uid's limit and is refused too. After the window passes, requests work again. A restart of the daemon inside the window does not reset the count.
- **Record.** Sixty `connector` records with a sent result, and a `connector` record for the 61st with the limit name and no upstream request. The limit state is rebuilt from the records after a daemon restart.

### A20: reading a response with a secret in it

- **Setup.** A loopback upstream echoes the request's `Authorization` header (the vault token) in its response body, in several encodings: raw, base64 (standard and URL-safe, padded and unpadded), URL-encoded and hex. A second variant puts the token in a header, and a third places it across the truncation boundary of `max_response_bytes`.
- **Attack.** As the agent user, the script calls the echo operation through `saiife api` and through the gateway, and then reads everything it can get back: stdout, stderr, response headers, the `Link` header and any `next` parameters.
- **Expected result.** The token never reaches the agent in any encoding. Each occurrence comes back as `[MASKED]`. The same holds for the token in a header and for the straddling case. Nothing in the agent's reach (its terminal output, the audit log, daemon logs it can read) holds the token.
- **Record.** A `connector` record for each call, with the masked parameters and the size of the response, and no token value anywhere in the audit files. The suite searches every audit file for each encoding of the token.
