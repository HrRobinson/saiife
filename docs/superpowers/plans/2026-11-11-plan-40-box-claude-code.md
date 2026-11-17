# Plan 40: Claude Code in a box: login without the credential in the box (v3 step 3, VM half 6 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Threat-model boundary (2026-11-17).** In-box hardening is best-effort defence in depth: the agent can already run arbitrary code in its box (passwordless sudo, FU4). What is guaranteed: the guard hook's integrity against repo config (`env -i` hooks, root-managed settings), no real credentials in the box, egress only via the gateway, and every change reviewed and landed by touch on the host. Future findings in this class are triaged against this boundary.

> **Reconciled 2026-11-12** against plan 34 as built on `v3-p34` (`ee5e264`; rulings R8, R11, R28) and the v2 vault and broker code on `v3-dev`. Changes:
> 1. **Already in plan 34 (not rebuilt here):** `BoxTemplate.credential_in_box: bool`, parsed from `[agent] credential_in_box`, default `false`, built-in `false` (`crates/boxes/src/template.rs:63`, R8). Task 1 keeps only the subscription gate and the placeholder.
> 2. Names checked: `Login { ApiKey, Subscription }` (`template.rs:38`), `AgentKind::ClaudeCode` (`:33`), `BoxTemplate.credential: String` (`:62`); the built-in `claude-code` has no egress and no secrets (`builtin/claude-code.toml`), so its phone spawn is Signed (R11).
> 3. The CLI has no `saiife secret set`: it is `saiife secret add <name> --kind token --service <service> [--from-file|--from-env]` (`crates/cli/src/secret_cmd.rs:16-35`). Messages, docs and the smoke use that.
> 4. Vault lookup (C8): there is one daemon vault, not one per uid; `api.call` reads `ctx.vault.lock()`, `VaultState::Ready(v)`, `v.get(name)` and requires the calling service in the entry's `allowed_services` (`crates/daemon/src/api_ops.rs:212-232`). The model forwarder does the same with the fixed service name `box-model`, and refuses a secret whose `allowed_services` lacks it.
> 5. Broker pieces exist as named: `Upstream::with_roots` (`crates/broker/src/upstream.rs:311`), `tls_connector_with_alpn` (`:379`), `resolver` (`:386`).
> 6. `box.list` per-box extras are entry keys (R28 puts `error` on each entry, `box_ops.rs:838-856`): the credential mode is an entry key `credential`, not a top-level map.
> 7. Global Constraints: branch `v3-p40`; builds with `CARGO_PROFILE_DEV_DEBUG=0`.

> **Depends on:** plan 34 merged (template `[agent] login` and `credential`, B10, and `credential_in_box`, R8); plan 38 Tasks 6 and 8 (the gateway's model listener on port 5002, `TemplateSetup`); plan 36 (Claude Code baked into the image, the `agent` user, I7) for the smoke run only. Owner rulings: phone spawn of the built-in `claude-code` is a Signed frame only (the model login never enters the box and is not a template secret); land and push still need Face ID (plan 39).

**Goal:** Claude Code runs interactively in its TUI inside the box (§7.7, §7.9) and talks to the model only through the gateway, which adds the real credential:
- **API key:** a vault secret; the box holds a per-box placeholder in `ANTHROPIC_API_KEY`, and the gateway swaps the `x-api-key` header;
- **Claude subscription:** a long-lived token from `claude setup-token`, run on the host by the user and stored as a vault secret; the box holds a placeholder in `CLAUDE_CODE_OAUTH_TOKEN`, and the gateway swaps the `Authorization: Bearer` header;
- if a login kind does not accept the placeholder (the owner's smoke run decides, §13), a template may opt into the fallback, the real token handed to the box, labelled "credential inside box (weaker)" in `box ls` and the audit;
- **subscription login stays off until the owner has checked Anthropic's current terms** for subscription use through a local proxy (§7.9, §13): an owner action, enforced by a constant in code.

**Architecture:**
- **The model forwarder is new gateway code** (`crates/daemon/src/box_gateway/model.rs`): an HTTP/1.1 server (hyper, as the v2 gateway) on the per-box `vsock.sock_5002` listener. It is not the v2 `/v1/proxy` path, because that buffers whole responses and Claude Code streams (SSE). It reuses the broker's pinned rustls client pieces (`Upstream::tls_connector_with_alpn`, `resolver`), so no proxy variable is read and the system roots apply.
- **The box only ever sees a placeholder** unless the template opts into the fallback. The placeholder is random per box, kept in `<box>/placeholder` (0600, daemon-only), written once by the setup source and checked by the forwarder in constant time. A request without the exact placeholder is refused; the credential headers the box sent are always removed before the real one is added.
- **Upstream is fixed** (`https://api.anthropic.com`); the box cannot choose a host for the model path. Any other host goes through plan 38's allow-listed CONNECT proxy, without a secret (§7.4).

**Tech Stack:** Rust; `hyper 1.12`, `hyper-util`, `http-body-util`, `tokio-rustls` (all in `Cargo.lock`, used by the daemon); `ring` for the placeholder and the constant-time compare; `zeroize` for secret values. No new crates.

**Spec:** §7.4 (secrets in v3.0: only the model endpoint and named connectors), §7.7 (task model), §7.8, §7.9 (all), §9.5 (Signed spawn), §13 (O1 answered; the swap is to verify), §15. Plan 34 B10 (`credential` is not a "secret"), plan 38 G8 (lockdown), G10 (audit style). Spike results "What this does not answer": the placeholder swap moved to this plan.

## Decisions

- **C1. Placeholder shape:** the login kind's usual prefix (so a client-side format check passes) + `saiife` + 64 random hex: API key `sk-ant-api03-saiife<64 hex>`, subscription `sk-ant-oat01-saiife<64 hex>`. In code the prefixes are built with `concat!` (no token-shaped literals). It is not a secret: it only works on that box's own listener.
- **C2. Claude Code settings in the box** (internals of Claude Code; the smoke run notices if they change): `ANTHROPIC_BASE_URL=http://127.0.0.1:3129`, the placeholder variable of C1, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_AUTOUPDATER=1`; `/home/agent/.claude.json` seeded on first setup with `{"hasCompletedOnboarding": true, "projects": {"/work": {"hasTrustDialogAccepted": true}}, "customApiKeyResponses": {"approved": ["<last 20 chars of the placeholder>"], "rejected": []}}` so the TUI does not stop on first-run, trust or "use this API key?" screens.
- **C3. Fallback is opt-in per template:** `[agent] credential_in_box = false` (default false; the key and field are plan 34's, `template.rs:63`). With `true`, the setup puts the real value in the same variable, the forwarder passes the box's header only when it equals the vault value, `box ls` prints `credential inside box (weaker)`, and the spawn and every `model` record carry `credential: "in_box"`. The built-in `claude-code` template keeps `false`.
- **C4. Subscription gate:** `pub const SUBSCRIPTION_LOGIN_CLEARED: bool = false;` in `saiife-boxes`. While false, a template with `login = "subscription"` loads, but spawn refuses `Invalid("subscription login is waiting for the owner's terms check (spec §7.9); use login = \"api-key\"")`. The owner flips it (one-line change, its own commit) after the terms check, or, if the terms do not allow it, removes subscription support and documents why.
- **C5. Forwarding rules.** Methods `GET`, `POST`; origin-form targets only; request body ≤ 32 MiB; responses streamed frame by frame with no size cap; connect timeout 10 s; idle timeout 300 s (no total cap: long generations stream). Removed from the request: hop-by-hop headers, `x-api-key`, `authorization`, `cookie`, `proxy-authorization`, `forwarded`, `x-forwarded-*`, `host` (set to `api.anthropic.com`). Removed from the response: hop-by-hop headers, `set-cookie`.
- **C6. Audit:** one `model` record per request: `extra = {box, session, method, path (no query), status, bytes_up, bytes_down, ms, login, credential: "gateway"|"in_box"}`; refusals `model_denied` `{box, reason}` rate-limited like plan 38 G10. Bodies are never recorded.
- **C7. Lockdown** (plan 38 G8): new model requests get `503` with "lockdown is on"; streams in flight are cut within 5 s.
- **C8. Which vault secret:** the template's `credential` name, looked up the way `api.call` looks up a connector secret (`crates/daemon/src/api_ops.rs:212-232`: `ctx.vault.lock()`, `VaultState::Ready`, `get(name)`), and only if the entry's `allowed_services` contains `MODEL_SERVICE = "box-model"` (the owner stores it with `saiife secret add <name> --kind token --service box-model`). The vault is the daemon's one vault; any box whose template names the credential may use it, which is why templates are root-owned in locked mode (plan 34 B11). The value is read per request (a rotated key applies at once) and held in `Zeroizing`.

## Global Constraints

Plan 35's Global Constraints apply (including `CARGO_PROFILE_DEV_DEBUG=0`), with worktree `.worktrees/p40`, branch `v3-p40`, scratch prefix `p40-tN-`. In addition: **never contact Anthropic** in tests: the upstream is a loopback TLS server with an rcgen certificate whose CA the test passes through `Upstream::with_roots`; the forwarder's upstream host and port are a debug-only test override. Never read the owner's real API key or `claude setup-token` output; test secrets are built with `concat!`. Never touch `~/.claude`.

### Fixed values

| Name | Value |
|---|---|
| `MODEL_UPSTREAM` | `https://api.anthropic.com` (host `api.anthropic.com`, port 443) |
| guest model URL | `http://127.0.0.1:3129` (plan 38 `MODEL_TCP`) |
| placeholder | C1; file `<box>/placeholder`, 0600, one line |
| guest env | C2 |
| `.claude.json` seed | C2 (written only when absent) |
| limits | body 32 MiB; connect 10 s; idle 300 s (C5) |
| `SUBSCRIPTION_LOGIN_CLEARED` | `false` (C4) |
| template key | `[agent] credential_in_box = false` (C3; plan 34's) |
| `MODEL_SERVICE` | `"box-model"`: the vault service a model credential must allow (C8) |

## Review Focus

1. **The real credential reaching the box** (gateway mode): in the setup message, in a response header echoed back, in an error body, in `box.term.read` output, on the box's disks. Expected: never; the setup carries only the placeholder, error bodies never quote headers, and the owner's smoke greps the overlay and repo disk for the key (Task 3: `setup_has_no_secret`; Task 2: `errors_never_echo_credentials`; Task 5 smoke `key_not_on_disk`).
2. **A request that tries to choose its own credential or upstream:** no placeholder, another box's placeholder, a placeholder in the wrong header, an absolute-form target `http://evil/`, a `Host: evil` header, `CONNECT`, an `Upgrade` request. Expected: `401` for credential problems and `400`/`405` for the rest, the upstream is always `api.anthropic.com`, and one rate-limited `model_denied` record (Task 2: `missing_placeholder_is_401`, `other_box_placeholder_is_401`, `wrong_header_is_401`, `absolute_target_is_400`, `host_header_is_replaced`, `connect_and_upgrade_are_refused`).
3. **Streaming:** an SSE response of many small events over 60 s, a client that disconnects mid-stream, an upstream that stalls for 301 s. Expected: each event reaches the box as it arrives (not after the end); a client disconnect closes the upstream; a stall ends with the idle timeout and a record with the bytes so far (Task 2: `sse_events_arrive_incrementally`, `client_disconnect_closes_upstream`, `idle_upstream_times_out`).
4. **Login kinds and the gate:** `login = "subscription"` before the owner's terms check; a template with the fallback on; a missing vault secret; a key rotated while a box runs. Expected: subscription refused at spawn with the §7.9 message; fallback labelled in `box ls` and every record; a missing secret answers `503` naming `saiife secret add <name> --kind token --service box-model`; the rotated key is used from the next request (Task 1: `subscription_is_gated`, `fallback_is_labelled`; Task 2: `missing_secret_is_503`, `rotated_key_applies_next_request`).
5. **Lockdown during a long generation.** Expected: the stream is cut within 5 s, the record has outcome `lockdown`, and new requests get `503` (Task 2: `lockdown_cuts_streams`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (template keys, gate, placeholder), Task 2 (model forwarder; needs plan 38 Task 6's listener).
- **Wave 2:** Task 3 (guest setup for Claude Code; needs 1, plan 38 Task 8).
- **Wave 3:** Task 4 (labels in `box ls` and the audit; needs 1–3), Task 5 (smoke fragment and the owner's terms check).

---

### Task 1: template keys, the subscription gate, and the placeholder (size S)

**Files:** Modify `crates/boxes/src/template.rs` (the constant only), `crates/boxes/src/manager.rs` (spawn gate), `crates/boxhost/src/guest.rs` (placeholder).

**Interfaces (Produces):**
```rust
// boxes template.rs: BoxTemplate.credential_in_box is plan 34's (template.rs:63); not added here
pub const SUBSCRIPTION_LOGIN_CLEARED: bool = false;                         // C4
// boxes manager.rs: spawn_changes (manager.rs:318) refuses per C4 before claiming an id, beside the repo-disk check (:320)
// boxhost guest.rs
pub fn placeholder(login: Login) -> String;                                 // C1, 64 hex from ring SystemRandom
pub fn read_or_make_placeholder(paths: &BoxPaths, login: Login) -> io::Result<String>;   // 0600, created once (O_EXCL), then read back
pub fn placeholder_matches(expected: &str, got: &[u8]) -> bool;             // ring::constant_time::verify_slices_are_equal
```
- [ ] **Step 1: Write the failing tests:** (plan 34 already tests that `credential_in_box` defaults to false and parses) `subscription_is_gated` (spawn of a `login = "subscription"` template → `Invalid` with the C4 text, no id claimed), `api_key_spawns`, `placeholder_shape` (prefix per login, 64 hex, two calls differ), `placeholder_file_is_created_once` (second call returns the first value; mode 0600), `placeholder_matches_rules` (equal, one byte off, shorter, longer).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): per-box model placeholder, credential_in_box fallback key, subscription gate (spec §7.9)`.

---

### Task 2: the streaming model forwarder (size L)

**Files:** Modify `crates/daemon/src/box_gateway/model.rs` (replace plan 38's 503 stub), `crates/daemon/src/box_gateway/mod.rs` (hand model connections to it); create `crates/daemon/tests/box_model.rs`.

**Interfaces:**
- Consumes: plan 38 `GatewayHooks` (the accept loop for `MODEL`), `GatewayShared`; Task 1 placeholder; `saiife_broker::upstream::Upstream` (`with_roots` `upstream.rs:311`, `tls_connector_with_alpn(&[b"http/1.1"])` `:379`, `resolver()` `:386`); the vault lookup of C8 (`api_ops.rs:212-232`); `ctx.lockdown`, `ctx.record`.
- Produces:
```rust
pub struct ModelConfig { pub upstream_host: String, pub upstream_port: u16, pub body_max: u64, pub connect_secs: u64, pub idle_secs: u64 }   // C5; host/port overridable in debug builds only
pub async fn serve(stream: UnixStream, id: BoxId, gw: Arc<GatewayShared>);   // hyper http1 server, one task per connection, keep-alive allowed
pub fn rewrite_request(req: &mut http::request::Parts, login: Login, real: &str) -> Result<(), &'static str>;   // C5 removals + the real header; pure, pinned by test
pub fn check_credential(parts: &http::request::Parts, login: Login, expected: &str, in_box_real: Option<&str>) -> Result<(), &'static str>;
pub fn clean_response(parts: &mut http::response::Parts);
```
Per request: lockdown (C7) → `503`; method and target (C5) → `405`/`400`; the box's record and template (`spawn_blocking(mgr.get(id))`) → `login`, `credential`, `credential_in_box`; `check_credential` (gateway mode: the login's header equals the placeholder; fallback: equals the vault value) → `401 "this box's model credential is not valid"` (fixed text, never the header); the vault value (C8; missing, or not allowed for `box-model` → `503 "the vault has no secret <name> for box-model: saiife secret add <name> --kind token --service box-model"`); `rewrite_request`; one TLS connection per box connection to the upstream (reused for keep-alive requests on it); the body through a counting, capped wrapper; the response streamed back through a counting wrapper with the idle timer reset on every frame; the C6 record when the response body ends or errors.

- [ ] **Step 1: Write the failing tests** (`tests/box_model.rs`: a loopback rustls upstream with an rcgen cert, recording each request's headers and serving canned responses; the box side is a hyper client over a `UnixStream` connected to the listener; the vault holds a `concat!`-built test key): `api_key_swap` (upstream sees `x-api-key: <real>` and no placeholder anywhere; the box sees the upstream's body), `subscription_swap` (C4 bypassed through a test-only template flag: upstream sees `authorization: Bearer <real>`), `missing_placeholder_is_401`, `other_box_placeholder_is_401`, `wrong_header_is_401`, `absolute_target_is_400`, `host_header_is_replaced`, `connect_and_upgrade_are_refused`, `cookies_and_forwarded_are_stripped`, `set_cookie_is_stripped`, `body_cap_is_413`, `sse_events_arrive_incrementally` (three events 300 ms apart: the first arrives before the upstream sends the third), `client_disconnect_closes_upstream`, `idle_upstream_times_out` (idle 1 s in the test config), `errors_never_echo_credentials` (every error body checked for the placeholder and the key), `missing_secret_is_503`, `secret_without_box_model_service_is_503` (the entry allows only `github`), `rotated_key_applies_next_request`, `fallback_passes_only_the_real_value`, `records_per_request` (fields of C6, no body, `credential: "gateway"`), `denied_records_are_rate_limited`, `lockdown_cuts_streams`; unit `rewrite_request_is_pinned`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm --test box_model -j 4 -- --test-threads=4` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): streaming model forwarder that swaps the box's placeholder for the vault credential`.

---

### Task 3: guest setup for Claude Code (size M)

**Files:** Modify `crates/daemon/src/box_setup.rs` (plan 38's `TemplateSetup`), `crates/boxhost/src/guest.rs` (`claude_env`, `claude_json_seed`).

**Interfaces:**
- Consumes: Task 1; plan 38 `SetupSource`, `Setup`, `SetupFile`, `claude_settings()`.
- Produces:
```rust
pub fn claude_env(login: Login, value: &str) -> Vec<(String, String)>;   // C2; value = placeholder, or the real secret in fallback mode
pub fn claude_json_seed(placeholder_or_value: &str) -> String;         // C2 JSON, pinned by test
```
`TemplateSetup::setup_for` for `AgentKind::ClaudeCode`: `read_or_make_placeholder` (gateway mode) or the vault value (fallback, C3); `env = claude_env(..)`; files += `/home/agent/.claude.json` (0600; plan 38 sends a setup only to a guest that is not set up yet, G3, so the seed travels once and never overwrites what Claude Code wrote later); command from the template (`["claude"]` for the built-in).

- [ ] **Step 1: Write the failing tests:** `setup_has_placeholder_env` (each C2 variable; `ANTHROPIC_API_KEY` for api-key, `CLAUDE_CODE_OAUTH_TOKEN` for subscription), `setup_has_no_secret` (gateway mode: the serialized `Setup` JSON does not contain the vault value), `fallback_setup_has_the_value` (`credential_in_box = true`), `claude_json_seed_is_pinned`, `hooks_settings_still_present` (plan 38's `settings.json` file is in the files).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): Claude Code setup in the box: placeholder login, first-run seed, model URL`.

---

### Task 4: labels in `box ls` and the audit (size S)

**Files:** Modify `crates/daemon/src/box_ops.rs` (spawn record `extra.credential`; each `box.list` entry gains `credential: "gateway"|"in_box"` beside R28's `error`, `box_ops.rs:838-856`), `crates/cli/src/box_cmd.rs` (`Ls`: a second indented line `  credential inside box (weaker)` for such boxes; `Templates` shows `login` and the fallback).

- [ ] **Step 1: Write the failing tests:** daemon `spawn_record_names_credential_mode` (`gateway` for the built-in, `in_box` for a fallback template), `list_reports_credential_mode` (`boxes[i].credential`; no top-level `credential` key); CLI `fallback_is_labelled` (`box ls` output line), `templates_show_login`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): label boxes whose credential is inside the box (spec §7.9 fallback)`.

---

### Task 5: the smoke fragment and the owner's terms check (size S)

**Files:** Create `scripts/box-smoke.d/50-claude.sh`; modify `scripts/box-smoke.sh` header comment only if the fragment needs a new env knob (`SAIIFE_BOX_SMOKE_SUBSCRIPTION=1`).

Owner-run checks (result keys), for **api-key** always and **subscription** only when `SAIIFE_BOX_SMOKE_SUBSCRIPTION=1` and the owner has temporarily flipped C4 in a local build:
- the vault secret is set by the owner (`saiife secret add anthropic --kind token --service box-model --from-file <file>`; for subscription, the owner runs `claude setup-token` on the host and stores the token the same way);
- `saiife box spawn --task "Reply with the single word ok, then stop."` reaches `running`, then `done` within 120 s (`claude_turn_ok_<kind>`); `saiife box attach` shows the reply without a first-run, trust or API-key prompt (`claude_no_prompt_<kind>`; the owner confirms by eye);
- the audit has `model` records with status 200 and `credential: "gateway"` (`model_records_<kind>`);
- **the placeholder swap works** (§13): the turn succeeding with only the placeholder in the box is the proof (`placeholder_accepted_<kind>`); if it fails for a kind, record the Claude Code error from the terminal and set the template's `credential_in_box = true` only for that kind (the weaker fallback, C3);
- **the key is not in the box:** after `saiife box stop`, `grep -c -a -F -- "$KEY"` over `root.qcow2` and `repo.img` prints `0` (qcow2 stores clusters unencrypted, so plaintext would show) (`key_not_on_disk_<kind>`; the script reads `$KEY` from a file the owner names and never prints it);
- a request from inside the box with the placeholder removed (`say` a `curl` to `http://127.0.0.1:3129/v1/models` with no key) gets `401` (`no_placeholder_401`).

- [ ] **Step 1:** write the fragment; `bash -n`; shellcheck if installed.
- [ ] **Step 2: Commit** `test(boxes): owner smoke for Claude Code in a box with both login kinds`.

---

## Gates

- [ ] `cargo test -p saiife-boxes --features fake -p saiife-boxhost --features fake -p saiife-daemon --features fake-vmm -p saiife --features fake-vmm`, and the daemon and CLI suites without features; `-j 4 -- --test-threads=4`.
- [ ] clippy; `check-unsafe.sh`; `check-windows.sh -p saiife-boxes -p saiife-daemon -p saiife`; tokio gate `0` for `saiife-boxes` and `saiife-boxhost`.
- [ ] `grep -rn 'SUBSCRIPTION_LOGIN_CLEARED: bool = true' crates/` finds nothing on this branch.
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Owner handwork

- [ ] **Terms check (owner action, spec §7.9 and §13):** read Anthropic's current terms for using a Claude subscription through a local proxy (consumer terms, usage policy, Claude Code's own docs on `setup-token` and `ANTHROPIC_BASE_URL`). If allowed, flip `SUBSCRIPTION_LOGIN_CLEARED` in its own commit, citing the terms' date. If not, keep API key only, remove the subscription path before release, and say why in the docs.
- [ ] Run `scripts/box-smoke.sh --only claude` (API key; subscription after the terms check); decide per login kind whether the placeholder swap holds or the fallback is needed (C3).
