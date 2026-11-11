# Plan 28: Workspace wire (W1): signed frames, access levels, pairing, sealing, `BoxSource`: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new tokio-free crate `saiife-wire` (`crates/wire`) holding everything the daemon needs to trust a Workspace browser, with no network, no daemon and no box:
- the signed frame a browser sends (parse, signature, expiry, single-use nonce, machine id, daemon epoch);
- the closed access table of spec §9.5 (`level_for`), where an unknown action is denied;
- pairing: the one-time offer behind the QR code, the browser's proof, the short code both screens show, the device store;
- the end-to-end seal for frames that cross the hub (§9.2);
- the `BoxSource` trait, the seam step 3 (boxes) implements and step 6 builds against, with `FakeBoxSource` and a conformance kit (feature `fake`).

**Architecture:**
- **Pure and synchronous.** Every function takes `now: u64` (Unix seconds) and returns a value; nothing reads a clock, the environment or a socket. The daemon (plan 29) owns files, time and the async wrappers.
- **The daemon is the only judge.** Link and the hub carry frames; they never decide. `Verifier::check` is the gate the daemon calls on every frame; `level_for` is the only access table.
- **Sign the bytes, not a canonical form.** The browser signs the exact UTF-8 body it sends, and the daemon verifies those bytes, then parses them strictly (a duplicate key anywhere is refused). No JSON canonicalizer exists on either side, so JS and Rust can never disagree about one.
- **Crypto is `ring` only**, as plan 26 decided for touch: ECDSA P-256 (WebCrypto's portable curve) for device and machine keys, ECDH P-256 + HKDF-SHA256 + AES-256-GCM for the seal (all three are in WebCrypto; ChaCha20 is not).
- Touch (WebAuthn) verification is **not** here: it is `saiife_touch::verify` (plan 26). This crate only re-exports the types a frame carries.

**Tech Stack:** Rust, `ring =0.17.14`, `sha2 0.10`, `base64 =0.23.1`, `serde`, `serde_json`, `saiife-touch` (path). All already in `Cargo.lock`. No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5, §7.7, §8.3, §9 (all, including §9.6), §11 step 6, §12, §15. Binding contract: `v3-step4-6-contract.md` (coordinator scratchpad). Research: `step6-workspace-research.md` (same place).

## Contract changes

**No name in the contract changes.** `Level`, `level_for`, `BoxSource` and its eleven methods keep their names. These are **additions** (flagged for the owner):

| Item | Addition | Why |
|---|---|---|
| `BoxSource` | `pause`, `resume`, `discard`, `reorder` beside `stop` | §9.3 Steer lists pause and reorder; Review lists Reject (= `discard`, §7.7). |
| `BoxSource::terminal` | takes `after: Option<u64>` and returns a `TermBatch` (poll, not a stream) | The trait is sync and tokio-free; plan 31 polls it. |
| `level` | `spawn_level(&Template) -> Level` | §8.2/§9.5: spawning is Signed from a no-secret template, Touch with secrets or egress. The table cannot see args. |
| `seal` module | new | §9.2 sealed frames; the contract lists no owner for it. Tokio-free, so it lives here; the browser repo shares its vectors. |
| `Frame.epoch` | new field | A replay cache in memory dies with the daemon; an epoch drawn at start makes every older frame stale. |

## Facts checked (2026-11-11)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | `ring 0.17.14`, `sha2 0.10.9`, `base64 0.23.1`, `ed25519-dalek 2.2.0`, `sha1 0.10.7`, `getrandom 0.3.4` are in the lock; no `p256`, `ciborium`, `tungstenite`, `qrcode`. | `Cargo.lock` | No new crate in this plan. |
| F2 | `ring` already used directly: `crates/broker/Cargo.toml:55` (`ring = "=0.17.14"`). | tree | Same line in `crates/wire/Cargo.toml`. |
| F3 | WebCrypto ECDSA signatures are IEEE P1363 (`r ‖ s`, 64 bytes for P-256); `exportKey("raw")` of a P-256 public key is the 65-byte uncompressed point. `ring::signature::ECDSA_P256_SHA256_FIXED` verifies exactly that form against that key. | W3C WebCrypto §ECDSA; ring docs | Device signatures are 64 raw bytes, keys 65 raw bytes. |
| F4 | WebCrypto has ECDH P-256, HKDF and AES-GCM; it has no ChaCha20-Poly1305. | W3C WebCrypto | Seal = ECDH P-256 + HKDF-SHA256 + AES-256-GCM. |
| F5 | `saiife_broker::pipeline::strict_json` (`crates/broker/src/pipeline.rs:424`) refuses duplicate keys with a serde visitor. `saiife-broker` pulls tokio. | tree | Wire copies the visitor (≈60 lines) as `frame::strict_json`; it does not depend on broker. |
| F6 | The "no tokio in hook crates" CI step is `.github/workflows/ci.yml:128-131`. | tree | Task 1 adds `-p saiife-wire`. |
| F7 | `ipc` op names are `pub const OP_*: &str` lines in `crates/ipc/src/msg.rs` (28 today). | tree | Task 3's exhaustiveness test reads that file with `include_str!`. |

## Global Constraints

- **Tokio-free:** `saiife-wire` never depends on tokio (CI gate, Task 1). It may depend on `saiife-touch` (contract), which is tokio-free too.
- **No unsafe:** `[lints] workspace = true`, and `#![forbid(unsafe_code)]` at column 0 of `crates/wire/src/lib.rs` (`scripts/check-unsafe.sh`).
- **Portable:** compiles on Linux, macOS and Windows (`bash scripts/check-windows.sh -p saiife-wire` clean).
- **No new crates:** `ring = "=0.17.14"`, `sha2 = "0.10"`, `base64 = "=0.23.1"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `saiife-touch = { path = "../touch" }`. Dev-deps: none beyond `serde_json`.
- **Base64:** everywhere on the wire it is base64url without padding (`base64::engine::general_purpose::URL_SAFE_NO_PAD`), named `b64u` below. Hex is lowercase.
- **No network, no clock, no env in any test.** `now` is a parameter. Random bytes come from `ring::rand::SystemRandom`, injected as `&dyn ring::rand::SecureRandom` where a test needs determinism.
- **No token-shaped literals** in tests: build fake secrets with `concat!` or from bytes.
- **Hard rules, every task** (in the worktree `.worktrees/p28`, branch `p28-workspace-wire` off `v3-dev`):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p28-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR"
  export CARGO_INCREMENTAL=0
  cargo test -p saiife-wire --features fake -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy -p saiife-wire --all-targets --features fake -j 4 -- -D warnings
  ```
  Remove `$TMPDIR` at the end. Never commit `.superpowers/`. Trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Fixed values (later plans and the browser repo copy these)

| Name | Value |
|---|---|
| `FRAME_VERSION` | `1` |
| `SIG_DOMAIN` | `b"saiife-wire-v1\n"` (signed message = `SIG_DOMAIN ‖ body bytes`) |
| `MAX_BODY_BYTES` | `64 * 1024` |
| `MAX_TTL_SECS` | `300` (`expires_at - issued_at`, the §8.6 challenge lifetime) |
| `SKEW_SECS` | `60` (`issued_at` may be at most this far in the future) |
| nonce | 16 random bytes, `b64u` (22 chars) |
| epoch | 16 random bytes, `b64u`, drawn by the daemon at start |
| `REPLAY_CAP` | `8192` live nonces; when full, new frames are refused (`Busy`), never evicted early |
| `machine_id` | first 32 hex chars of SHA-256(machine public key, 65 raw bytes) |
| `device_id` | `"d-"` + first 16 hex chars of SHA-256(device public key, 65 raw bytes) |
| pair secret | 32 random bytes; offer TTL `300` s; at most `4` open offers |
| `PAIR_PROOF_DOMAIN` | `b"saiife-pair-v1\n"`; proof = HMAC-SHA256(secret, domain ‖ pair_id ‖ device_pub) |
| `SHORT_CODE_DOMAIN` | `b"saiife-pair-code-v1\n"`; code = first 4 bytes BE of SHA-256(domain ‖ machine_pub ‖ device_pub ‖ secret) mod 1 000 000, shown `"NNN NNN"` |
| `SEAL_SALT` | `b"saiife-seal-v1"`; `info = b"saiife-seal-v1 keys" ‖ machine_eph ‖ browser_eph ‖ session_id` |
| seal keys | HKDF output 64 bytes: `[0..32]` browser→machine, `[32..64]` machine→browser |
| seal nonce | 4 zero bytes ‖ u64 BE counter; counters start at 0 and must increase by exactly 1 |

## Review Focus

1. **A frame that verifies but whose action is MachineOnly or unknown** (`policy.reload`, `lockdown.off`, `workspace.revoke`, `""`, `box.stop ` with a trailing space). Expected: refused with `Refused::MachineOnly` or `Refused::UnknownAction`, never routed (Task 3: `every_ipc_op_is_classified`, `near_miss_names_are_unknown`; Task 4: `machine_only_action_is_refused_after_signature`).
2. **A captured frame sent again**: twice in the same epoch, after the replay cache filled, or after a daemon restart. Expected: `Replayed`, `Busy`, `StaleEpoch` respectively, and a refused frame never burns a nonce it did not own (Task 4: `replay_is_refused`, `full_cache_refuses_instead_of_evicting`, `old_epoch_is_stale`, `bad_signature_does_not_burn_the_nonce`).
3. **A body the two sides read differently**: a duplicate `action` key, a float `expires_at`, a 70 KB body, an unknown top-level field, a non-object `args`. Expected: `Malformed` before any field is trusted (Task 2: `duplicate_key_is_refused`, `unknown_field_is_refused`, `oversize_body_is_refused`).
4. **Pairing interfered with on the way**: hub or link swaps the device key, replays a finished offer, or guesses after expiry. Expected: the short codes on the two screens differ, a used or expired offer is `PairExpired`, a bad proof is `PairProof` (Task 5: `swapped_device_key_changes_the_code`, `offer_is_single_use`, `expired_offer_is_refused`).
5. **Display of hostile box data**: a diff path `../../.ssh/id`, a task text with ANSI escapes and RTL overrides, a 3 MB diff. Expected: the fake carries such data and the DTOs cap and flag it (`truncated`), so plans 29/30 must escape it (Task 8: `fake_carries_hostile_display_data`, `diff_is_capped_and_flagged`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (crate).
- **Wave 2 (parallel):** Task 2 (frame + signature), Task 3 (levels), Task 5 (pairing + devices), Task 6 (seal), Task 7 (BoxSource DTOs and trait).
- **Wave 3:** Task 4 (verifier; needs 2 and 3), Task 8 (fake + conformance; needs 7).
- **Last:** gates, whole-branch review, PR to `v3-dev`. Plan 29 starts from this branch.

**Shared files:** `crates/wire/src/lib.rs` and `error.rs`. Task 1 declares every module (empty files with one `//!` line) and every `WireError` variant up front, so later tasks add none.

---

### Task 1: the crate, errors and the CI gate (size S)

**Files:**
- Create: `crates/wire/Cargo.toml`, `crates/wire/src/lib.rs`, `crates/wire/src/error.rs`, `crates/wire/src/b64.rs`; empty `frame.rs`, `sig.rs`, `level.rs`, `verify.rs`, `pair.rs`, `device.rs`, `seal.rs`, `source.rs`, `fake.rs`, `conformance.rs`.
- Modify: `.github/workflows/ci.yml:131` (add `-p saiife-wire` to the `cargo tree` list), `Cargo.lock` (by cargo).

**Interfaces (Produces):**
- `Cargo.toml`: `name = "saiife-wire"`, `description = "saiife Workspace wire: signed frames, access levels, pairing, sealing and the box source seam."`, workspace `edition/version/license/repository`, `[lib] name = "saiife_wire"`, `[features] fake = ["saiife-touch/soft"]`, deps from Global Constraints with the date comment style of `crates/broker/Cargo.toml:30-40` ("ring 0.17.14: already in Cargo.lock through rustls"), `[lints] workspace = true`.
- `lib.rs`: `//!` doc, `#![forbid(unsafe_code)]`, `pub mod b64; pub mod frame; pub mod sig; pub mod level; pub mod verify; pub mod pair; pub mod device; pub mod seal; pub mod source; #[cfg(feature = "fake")] pub mod fake; #[cfg(feature = "fake")] pub mod conformance; mod error; pub use error::WireError; pub use level::{level_for, Level}; pub use source::BoxSource;`.
- `error.rs`: `#[derive(Debug, Clone, PartialEq, Eq)] pub enum WireError` with hand-written `Display` + `std::error::Error` (no thiserror). Variants, `rule()` (the string the daemon puts in an answer's `rule`, plan 29) and Display:

| Variant | `rule()` | Display |
|---|---|---|
| `Malformed(String)` | `bad_frame` | `malformed frame: {0}` |
| `BadSignature` | `bad_signature` | `the frame signature does not verify` |
| `UnknownDevice` | `unknown_device` | `this browser is not paired with this machine` |
| `DevicePending` | `device_pending` | `this browser is waiting for confirmation on the machine` |
| `WrongMachine` | `wrong_machine` | `the frame is for another machine` |
| `StaleEpoch` | `stale_epoch` | `the daemon restarted; reload the page` |
| `Expired` | `expired` | `the frame has expired` |
| `NotYetValid` | `not_yet_valid` | `the frame is from the future; check this device's clock` |
| `Replayed` | `replayed` | `the frame was already used` |
| `Busy` | `busy` | `too many frames in flight; try again shortly` |
| `UnknownAction(String)` | `unknown_action` | `unknown action {0:?}` |
| `MachineOnly(String)` | `machine_only` | `{0} can only be done on the machine` |
| `PairExpired` | `pair_expired` | `this pairing code has expired or was used; run saiife workspace pair again` |
| `PairProof` | `pair_proof` | `the pairing proof does not match` |
| `PairFull` | `pair_full` | `too many open pairing codes; wait for one to expire` |
| `Seal(String)` | `seal` | `sealed channel: {0}` |
| `Store(String)` | `store` | `device store: {0}` |

- `b64.rs`: `pub fn enc(b: &[u8]) -> String`, `pub fn dec(s: &str) -> Result<Vec<u8>, WireError>` (URL_SAFE_NO_PAD; padding or `+/` is `Malformed`), `pub fn dec_n<const N: usize>(s: &str) -> Result<[u8; N], WireError>`, `pub fn hex(b: &[u8]) -> String`.

- [ ] **Step 1: Write the failing tests** in `b64.rs`: `roundtrip_url_safe_no_pad` (bytes `[0xfb, 0xff]` encode to `"-_8"`), `padding_is_malformed` (`dec("AA==")`), `standard_alphabet_is_malformed` (`dec("+/8")`), `dec_n_checks_length` (`dec_n::<16>` of 15 bytes is `Malformed`), and in `error.rs` `every_variant_has_a_rule` (a hand list of all variants; each `rule()` is non-empty, `[a-z_]+`, unique).
- [ ] **Step 2: Run** `cargo test -p saiife-wire` → FAIL (does not compile).
- [ ] **Step 3: Implement** the files above.
- [ ] **Step 4: Run** the tests → PASS; `cargo tree -e normal -p saiife-wire | grep -c tokio` → `0`.
- [ ] **Step 5: Commit** `feat(wire): saiife-wire crate, errors, base64url helpers`.

---

### Task 2: the frame and its signature (size M)

**Files:**
- Modify: `crates/wire/src/frame.rs`, `crates/wire/src/sig.rs`
- Create: `crates/wire/tests/vectors/frame-v1.json`, `crates/wire/tests/frame_vectors.rs`

**Interfaces (Produces):**
```rust
// frame.rs
pub const FRAME_VERSION: u32 = 1;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_TTL_SECS: u64 = 300;
pub const SKEW_SECS: u64 = 60;
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub v: u32,
    pub machine_id: String,
    pub epoch: String,
    pub device_id: String,
    pub action: String,
    pub args: serde_json::Map<String, serde_json::Value>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
/// What link forwards: the exact body bytes as a string, the signature, and
/// for Touch actions the WebAuthn proof (plan 31 fills it).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFrame { pub body: String, pub sig: String, #[serde(default)] pub touch: Option<TouchProof> }
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TouchProof { pub request_id: String, pub credential_id: String, pub authenticator_data: String, pub client_data_json: String, pub signature: String }
pub fn strict_json(b: &[u8]) -> Option<serde_json::Value>;   // copy of broker's visitor (F5)
pub fn parse_body(body: &[u8]) -> Result<Frame, WireError>;
// sig.rs
pub const SIG_DOMAIN: &[u8] = b"saiife-wire-v1\n";
pub fn verify_p256(public_raw: &[u8; 65], body: &[u8], sig_raw: &[u8; 64]) -> bool;
pub struct MachineKey { /* ring EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING */ }
impl MachineKey {
    pub fn generate(rng: &dyn ring::rand::SecureRandom) -> Result<(MachineKey, Vec<u8> /* pkcs8 */), WireError>;
    pub fn from_pkcs8(pkcs8: &[u8], rng: &dyn ring::rand::SecureRandom) -> Result<MachineKey, WireError>;
    pub fn public_raw(&self) -> [u8; 65];
    pub fn machine_id(&self) -> String;
    pub fn sign(&self, domain: &[u8], msg: &[u8], rng: &dyn ring::rand::SecureRandom) -> [u8; 64];
}
pub fn machine_id_of(public_raw: &[u8; 65]) -> String;
pub fn device_id_of(public_raw: &[u8; 65]) -> String;
#[cfg(feature = "fake")] pub struct TestDevice { /* MachineKey inside */ }
#[cfg(feature = "fake")] impl TestDevice {
    pub fn generate() -> TestDevice;
    pub fn public_raw(&self) -> [u8; 65];
    pub fn device_id(&self) -> String;
    pub fn sign_body(&self, body: &str) -> String;           // b64u of the 64-byte sig over SIG_DOMAIN ‖ body
    pub fn frame(&self, f: &Frame) -> SignedFrame;            // body = serde_json::to_string(f)
}
```
- `parse_body`: length ≤ `MAX_BODY_BYTES` first, then `strict_json`, then `serde_json::from_value::<Frame>`; `v != 1`, `expires_at <= issued_at`, `expires_at - issued_at > MAX_TTL_SECS`, a nonce that is not 16 bytes of `b64u`, or an `action` outside `[a-z0-9._]{1,64}` are `Malformed`. Floats fail the `u64` fields by serde.
- `MachineKey::sign` signs `domain ‖ msg` (`domain` is `SIG_DOMAIN` for frames, `seal::HANDSHAKE_DOMAIN` for the seal, `pair::OFFER_DOMAIN` never: offers are not signed).

- [ ] **Step 1: Write the failing tests** (`frame.rs`/`sig.rs` unit tests): `parses_a_valid_body`, `duplicate_key_is_refused` (`{"action":"box.list","action":"box.stop",...}` → `Malformed`), `unknown_field_is_refused` (extra `"admin":true`), `oversize_body_is_refused` (65 537 bytes), `float_time_is_refused` (`"expires_at":1.5`), `ttl_over_300_is_refused`, `bad_action_chars_are_refused` (`"box.stop "`, `"Box.Stop"`, `""`), `signature_roundtrip` (TestDevice signs, `verify_p256` true), `signature_over_other_body_fails`, `signature_without_domain_fails` (sign `body` with no `SIG_DOMAIN` prefix via `MachineKey::sign(b"", ..)` → false), `ids_are_derived` (`machine_id_of` is 32 hex chars, `device_id_of` starts `d-` and has 18 chars).
- [ ] **Step 2: Write `tests/vectors/frame-v1.json`**: generate once with `TestDevice` in a throwaway test, then freeze `{public_raw_b64u, body, sig_b64u, machine_id, device_id}` plus a `"bad_sig_b64u"` (one byte flipped). `tests/frame_vectors.rs::frozen_vector_verifies` reads it with `include_str!` and asserts both outcomes. Plan 30's `node --test` checks the same file, so JS and Rust agree on the signed bytes.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(wire): signed frames: strict parse, P-256 signatures, frozen vector`.

---

### Task 3: the access table (size S)

**Files:** Modify `crates/wire/src/level.rs`.

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level { Signed, Touch, MachineOnly }
pub fn level_for(action: &str) -> Option<Level>;     // closed table; None = deny
pub fn spawn_level(t: &crate::source::Template) -> Level;  // Touch if t.has_secrets || t.has_egress
pub const REMOTE: &[(&str, Level)];                   // the whole remote table, sorted by name
pub const MACHINE_ONLY: &[&str];                       // named so the refusal says "on the machine"
pub mod actions { pub const BOX_OVERVIEW: &str = "box.overview"; /* one const per REMOTE name */ }
```
The table (spec §9.5; "anything that only takes power away is safe remotely"):

| Level | Actions |
|---|---|
| `Signed` (view) | `box.overview`, `box.list`, `box.diff`, `box.term.read`, `box.templates`, `box.inbox`, `approval.list`, `workspace.whoami`, `workspace.touch.begin` (issues a challenge, grants nothing) |
| `Signed` (takes power away) | `box.stop`, `box.pause`, `box.discard` (Reject; also cancels a queued box), `box.reorder`, `approval.reject`, `lockdown.on` |
| `Signed`, raised by `spawn_level` | `box.spawn` |
| `Touch` (UV) | `box.land` (Approve), `approval.approve`, `box.push`, `box.pr`, `box.steer`, `box.revise`, `box.resume` |
| `MachineOnly` | `lockdown.off`, `device.enrol`, `device.remove`, `config.set`, `vault.add`, `connector.add`, `egress.set`, `caps.raise`, `uninstall`, and **every `OP_*` in `crates/ipc/src/msg.rs`** that is not in `REMOTE` (`policy.*`, `secret.*`, `audit.*`, `lockdown.set`, `workspace.*` pairing ops, ...) |

`level_for` looks up `REMOTE` (binary search), then `MACHINE_ONLY`, then `IPC_OPS: &[&str]` (a hand-kept copy of every `OP_*` value in `crates/ipc/src/msg.rs`, all MachineOnly unless in `REMOTE`; wire does not depend on ipc, and `every_ipc_op_is_classified` keeps the copy complete); anything else is `None`. No prefix or wildcard matching.

- [ ] **Step 1: Write the failing tests:**
  - `remote_table_is_sorted_and_unique`.
  - `view_and_stop_are_signed` (`box.overview`, `box.diff`, `box.stop`, `lockdown.on` → `Some(Signed)`).
  - `approve_and_push_need_touch` (`box.land`, `approval.approve`, `box.push`, `box.pr` → `Some(Touch)`).
  - `config_policy_devices_are_machine_only` (`policy.reload`, `policy.show`, `config.set`, `device.enrol`, `device.remove`, `lockdown.off`, `lockdown.set`, `secret.add`, `audit.query` → `Some(MachineOnly)`).
  - `near_miss_names_are_unknown` (`""`, `"box"`, `"box.*"`, `"BOX.LIST"`, `"box.list.x"`, `"box.stop "` → `None`).
  - `every_ipc_op_is_classified`: `include_str!("../../ipc/src/msg.rs")`, collect every `pub const OP_[A-Z_]+: &str = "(...)";` value with a plain line scan (no regex dep), assert `level_for(v).is_some()` for each and that at least 28 were found. A new ipc op without a level fails this test.
  - `signed_actions_are_reads_or_restrictions`: a hand list `RESTRICTIONS = ["box.stop","box.pause","box.discard","box.reorder","approval.reject","lockdown.on"]` and `READS` (the view row); every `Signed` entry of `REMOTE` except `box.spawn` is in one of the two. Adding a Signed action means arguing it here.
  - `spawn_is_raised_by_template` (no secrets/egress → `Signed`; `has_secrets` → `Touch`; `has_egress` → `Touch`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(wire): the closed §9.5 access table; unknown actions are denied`.

---

### Task 4: the verifier and the replay cache (size M)

**Files:** Modify `crates/wire/src/verify.rs`.

**Interfaces:**
- Consumes: `frame::{parse_body, SignedFrame, Frame}`, `sig::verify_p256`, `level_for`, `spawn_level`, `device::{Device, DeviceState}` (Task 5; the verifier takes a lookup closure, so this task stubs devices in tests).
- Produces:
```rust
pub struct ReplayCache { /* BTreeMap<(device_id, nonce), expires_at>, cap */ }
impl ReplayCache { pub fn new(cap: usize) -> ReplayCache; pub fn len(&self) -> usize; }
pub const REPLAY_CAP: usize = 8192;
pub struct Verifier { pub machine_id: String, pub epoch: String, pub replay: ReplayCache }
#[derive(Debug, Clone)]
pub struct Verified { pub frame: Frame, pub device_id: String, pub owner_user: String, pub level: Level }
impl Verifier {
    pub fn new(machine_id: String, epoch: String) -> Verifier;
    /// Order: body parse -> device lookup -> signature -> machine id -> epoch
    /// -> time -> level (None/MachineOnly refused) -> nonce burned last.
    pub fn check(&mut self, sf: &SignedFrame, devices: &dyn Fn(&str) -> Option<crate::device::Device>, now: u64) -> Result<Verified, WireError>;
}
pub fn new_epoch(rng: &dyn ring::rand::SecureRandom) -> String;   // 16 bytes b64u
```
- Order matters: a frame from an unknown device or with a bad signature never touches the replay cache (so a stranger cannot fill it), and nothing burns a nonce before every other check passed. Expired entries are swept on each `check` before the cap test. `Verified.level` for `box.spawn` is the table's `Signed`; the daemon raises it with `spawn_level` once it has the template (plan 29) — `check` never lowers anything.
- A `DeviceState::Pending` device is `DevicePending`; `Revoked` is `UnknownDevice`.

- [ ] **Step 1: Write the failing tests:** `valid_frame_verifies` (returns `Level::Signed` for `box.list`), `unknown_device`, `pending_device_is_refused`, `revoked_device_is_unknown`, `bad_signature_does_not_burn_the_nonce` (bad sig, then the same frame correctly signed verifies), `wrong_machine`, `old_epoch_is_stale`, `expired_at_boundary` (`now == expires_at` → `Expired`), `future_beyond_skew` (`issued_at = now + 61` → `NotYetValid`; `now + 60` passes), `replay_is_refused`, `same_nonce_other_device_is_fine`, `full_cache_refuses_instead_of_evicting` (cap 2: two live frames, third → `Busy`; after `now` passes the first two's expiry, the third passes), `machine_only_action_is_refused_after_signature` (`policy.reload` correctly signed → `MachineOnly`, and its nonce is not burned), `unknown_action_is_refused`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(wire): the frame verifier: device, signature, machine, epoch, time, level, nonce`.

---

### Task 5: pairing and the device store (size M)

**Files:** Modify `crates/wire/src/pair.rs`, `crates/wire/src/device.rs`; create `crates/wire/tests/vectors/pair-v1.json`.

**Interfaces (Produces):**
```rust
// pair.rs
pub const OFFER_TTL_SECS: u64 = 300;
pub const MAX_OPEN_OFFERS: usize = 4;
#[derive(Clone)] pub struct PairOffer { pub pair_id: String /* 8 bytes b64u */, pub secret: [u8; 32], pub machine_id: String, pub machine_pub: [u8; 65], pub expires_at: u64, pub owner_user: String, pub label_hint: Option<String> }
impl std::fmt::Debug for PairOffer { /* never prints `secret` */ }
/// The URL fragment payload: b64u of compact JSON {v:1, pair_id, secret, machine_id, machine_pub}.
pub fn fragment(o: &PairOffer) -> String;
pub fn parse_fragment(s: &str) -> Result<(String, [u8; 32], String, [u8; 65]), WireError>;   // for tests and the CLI's self-check
#[derive(Debug, Clone, serde::Deserialize)] #[serde(deny_unknown_fields)]
pub struct PairRequest { pub pair_id: String, pub device_pub: String, pub label: String, pub proof: String }
pub fn proof(secret: &[u8; 32], pair_id: &str, device_pub: &[u8; 65]) -> [u8; 32];
pub fn short_code(machine_pub: &[u8; 65], device_pub: &[u8; 65], secret: &[u8; 32]) -> String;   // "NNN NNN"
pub struct Offers { /* open offers by pair_id */ }
impl Offers {
    pub fn new() -> Offers;
    pub fn open(&mut self, machine: &crate::sig::MachineKey, owner_user: &str, label_hint: Option<String>, rng: &dyn ring::rand::SecureRandom, now: u64) -> Result<PairOffer, WireError>;
    /// Checks the proof (ring::hmac::verify, constant time) and moves the
    /// offer to "requested": it can never be finished again.
    pub fn request(&mut self, req: &PairRequest, known: &crate::device::DeviceList, now: u64) -> Result<crate::device::Device /* state Pending, owner_user from the offer */, WireError>;
    pub fn status(&self, pair_id: &str, now: u64) -> PairStatus;
    pub fn take(&mut self, pair_id: &str, now: u64) -> Option<crate::device::Device>;   // the requested device, for confirm
}
#[derive(Debug, Clone, PartialEq, serde::Serialize)] #[serde(tag = "state", rename_all = "snake_case")]
pub enum PairStatus { Waiting, Requested { short_code: String, label: String, device_id: String }, Expired }
// device.rs
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)] #[serde(rename_all = "snake_case")]
pub enum DeviceState { Pending, Active, Revoked }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Device { pub id: String, pub label: String, pub owner_user: String, pub public_key: String /* b64u 65 bytes */, pub state: DeviceState, pub added_at: u64, #[serde(default)] pub touch_credentials: Vec<String> /* saiife-touch credential ids, plan 31 */ }
impl Device { pub fn public_raw(&self) -> Result<[u8; 65], WireError>; }
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceList { pub v: u32, pub devices: Vec<Device> }
impl DeviceList {
    pub fn parse(bytes: &[u8]) -> Result<DeviceList, WireError>;   // strict_json; v must be 1
    pub fn to_bytes(&self) -> Vec<u8>;                              // pretty JSON, sorted by id
    pub fn get(&self, id: &str) -> Option<&Device>;
    pub fn upsert(&mut self, d: Device);
    pub fn revoke(&mut self, id: &str) -> bool;                    // Revoked kept as a tombstone
}
```
- `label` is 1–40 chars, printable, no control or bidi characters (`Malformed` otherwise). `device_pub` must parse as an uncompressed P-256 point (`0x04` prefix, 65 bytes, and `ring` accepts it as a key: verify any signature attempt returns cleanly).
- A device key already `Active` or `Pending` in `known` is refused on `request` (`Malformed("device already paired")`).
- File I/O is plan 29's; this module only parses and writes bytes.

- [ ] **Step 1: Write the failing tests:** `fragment_roundtrip`, `debug_hides_the_secret` (`format!("{offer:?}")` does not contain `b64::enc(&secret)`), `good_proof_gives_a_pending_device`, `bad_proof_is_refused`, `offer_is_single_use` (second `request` → `PairExpired`), `expired_offer_is_refused` (`now = expires_at`), `fifth_open_offer_is_refused` (`PairFull`; an expired one frees a slot), `swapped_device_key_changes_the_code`, `code_format` (`^\d{3} \d{3}$`, leading zeros kept), `hostile_label_is_refused` (`"a\u{202e}b"`, `"x\n"`, 41 chars), `device_list_roundtrip_sorted`, `revoked_stays_as_tombstone`, `device_list_refuses_duplicate_keys`.
- [ ] **Step 2: Write `tests/vectors/pair-v1.json`** (fixed `secret`, `pair_id`, `machine_pub`, `device_pub` → `proof_b64u`, `short_code`) and `frozen_pair_vector` in `tests/frame_vectors.rs`. Plan 30 checks the same file in JS.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(wire): pairing offers, proof, short code and the device list`.

---

### Task 6: the seal for frames that cross the hub (size M)

**Files:** Modify `crates/wire/src/seal.rs`; create `crates/wire/tests/vectors/seal-v1.json`.

**Interfaces (Produces):**
```rust
pub const HANDSHAKE_DOMAIN: &[u8] = b"saiife-seal-v1 hello\n";
/// Machine side of one hub session. Link holds it (plan 29); the daemon
/// signs `eph_pub` with the machine key (`workspace.sign`, plan 29) so the
/// browser, which knows `machine_pub` from the QR code, can check it.
pub struct MachineHandshake { /* ring EphemeralPrivateKey (ECDH_P256), eph_pub [u8;65], session_id [u8;16] */ }
impl MachineHandshake {
    pub fn new(rng: &dyn ring::rand::SecureRandom) -> Result<MachineHandshake, WireError>;
    pub fn eph_pub(&self) -> [u8; 65];
    pub fn session_id(&self) -> [u8; 16];
    /// The bytes the machine key signs: session_id ‖ eph_pub.
    pub fn to_sign(&self) -> Vec<u8>;
    /// `browser_sig` is the device key's signature (HANDSHAKE_DOMAIN) over
    /// session_id ‖ machine_eph ‖ browser_eph; `device_pub = None` only for
    /// a pairing session, which may carry `pair` messages and nothing else.
    pub fn finish(self, browser_eph: &[u8; 65], browser_sig: Option<&[u8; 64]>, device_pub: Option<&[u8; 65]>) -> Result<Channel, WireError>;
}
pub struct Channel { /* LessSafeKey rx (browser->machine), tx, next_rx: u64, next_tx: u64, pairing_only: bool */ }
impl Channel {
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8>;            // u64 BE counter ‖ ciphertext ‖ tag
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, WireError>;  // counter must equal next_rx
    pub fn pairing_only(&self) -> bool;
}
#[cfg(feature = "fake")] pub struct TestBrowserEnd { /* the browser half, for tests and the fake hub of plan 29 */ }
```
- AEAD is `ring::aead::AES_256_GCM`; AAD = `b"saiife-seal-v1 " ‖ direction byte (b'b' browser→machine, b'm' machine→browser)`. A counter that is not exactly `next_rx` (replay, reorder, drop) is `Seal("out of order")`; the channel is dead afterwards (every later `open` fails).
- Max plaintext 1 MiB (`Seal("too large")`).

- [ ] **Step 1: Write the failing tests:** `handshake_and_roundtrip` (TestBrowserEnd ↔ Channel both ways), `wrong_device_signature_is_refused`, `replayed_message_kills_the_channel`, `reordered_message_is_refused`, `flipped_bit_is_refused`, `directions_use_different_keys` (a machine→browser message fed back to `open` fails), `pairing_session_is_flagged`.
- [ ] **Step 2: Write `tests/vectors/seal-v1.json`**: fixed private scalars are not settable in ring's ephemeral API, so freeze the **derived** values instead: `{shared_secret_hex, machine_eph, browser_eph, session_id, keys_hex, messages: [{dir, counter, plaintext, sealed_b64u}]}`, produced by a `#[cfg(test)] fn derive_from_shared(shared, ...)` (the HKDF + AEAD half, split out so it is testable alone). `frozen_seal_vector` checks `derive_from_shared` and `open` against it. The browser repo (out of scope) and plan 30 can test WebCrypto HKDF/AES-GCM against the same file.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(wire): end-to-end seal for hub sessions (ECDH P-256, HKDF, AES-GCM)`.

---

### Task 7: the `BoxSource` trait and its types (size M)

This is **the seam with step 3**. The step 3 box plans implement this trait over the box manager; they must cite this task and run Task 8's conformance kit. Change it only through the coordinator.

**Files:** Modify `crates/wire/src/source.rs`.

**Interfaces (Produces):** every type derives `Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize` with `#[serde(rename_all = "snake_case")]`, unless noted.
```rust
/// `[a-z0-9][a-z0-9-]{0,39}`; anything else is refused before a source sees it.
#[derive(Hash, Eq, PartialOrd, Ord)] #[serde(try_from = "String", into = "String")]
pub struct BoxId(String);
impl BoxId { pub fn parse(s: &str) -> Result<BoxId, BoxError>; pub fn as_str(&self) -> &str; }
/// §7.7: queued → starting → running ⇄ paused → done → landed | discarded.
#[derive(Copy, Eq)] pub enum BoxState { Queued, Starting, Running, Paused, Done, Landed, Discarded }
pub struct BoxInfo { pub id: BoxId, pub state: BoxState, pub template: String, pub repo: String /* display name, not a path */, pub task: String, pub created_at: u64, pub started_at: Option<u64>, pub updated_at: u64, pub queue_pos: Option<u32>, pub lands: u32 }
pub struct Load { pub cpu_pct: u8, pub mem_used_mb: u64, pub mem_total_mb: u64 }
pub struct Overview { pub boxes: Vec<BoxInfo> /* sorted: running, paused, done, queued (by queue_pos), starting, then the rest; ties by id */, pub load: Option<Load>, pub slots_total: u32, pub slots_free: u32 }
pub enum FileStatus { Added, Modified, Deleted, Renamed { from: String } }
pub struct FileChange { pub path: String, pub status: FileStatus, pub added: u32, pub removed: u32, pub binary: bool }
pub struct TestResult { pub passed: u32, pub failed: u32, pub skipped: u32, pub summary: String }
pub const MAX_DIFF_BYTES: usize = 2 * 1024 * 1024;
pub struct DiffSummary { pub id: BoxId, pub base_commit: String, pub diff_sha256: String, pub files: Vec<FileChange>, pub unified: String /* at most MAX_DIFF_BYTES, cut at a line end */, pub truncated: bool, pub tests: Option<TestResult> }
/// Plain text lines: the host's headless terminal has already applied every
/// escape; OSC 52 / OSC 8 never reach a client (§9.4).
pub enum TermFrame { Snapshot { seq: u64, rows: u16, cols: u16, lines: Vec<String>, cursor: (u16, u16) }, Delta { seq: u64, lines: Vec<(u16, String)>, cursor: (u16, u16) } }
pub struct TermBatch { pub frames: Vec<TermFrame>, pub next: u64, pub ended: bool }
/// One pending touch-bound action the daemon created (§15: it accepts only
/// actions it created). Not serialized as is: the daemon sends `PendingView`.
#[derive(Debug, Clone)] pub struct PendingAction { pub request_id: u64 /* = record.request_id */, pub class: saiife_touch::TouchClass /* = record.class */, pub box_id: Option<BoxId>, pub summary: String, pub record: saiife_touch::ActionRecord, pub created_at: u64, pub expires_at: u64 /* = record.expires_at */ }
pub struct PendingView { pub request_id: String /* decimal: u64 is not safe in JS */, pub class: String /* TouchClass::name() */, pub box_id: Option<BoxId>, pub summary: String, pub challenge_hex: String, pub short_code: String, pub created_at: u64, pub expires_at: u64 }
impl PendingAction { pub fn view(&self) -> PendingView; }   // challenge_hex = hex(saiife_touch::challenge(&record)); short_code = saiife_touch::short_code(&challenge) (plan 26 D9; §8.3)
#[derive(Copy, Eq)] pub enum Decision { Approve, Reject }
pub struct Template { pub name: String, pub description: String, pub has_secrets: bool, pub has_egress: bool }
#[derive(Copy, Eq)] pub enum Start { Now, Queue }
pub struct SpawnReq { pub template: String, pub repo: String, pub task: String, pub start: Start }
#[derive(Eq)] pub enum BoxError { NotFound, WrongState { state: BoxState }, Invalid(String), Busy, Unavailable(String) }
impl BoxError { pub fn rule(&self) -> &'static str; }   // not_found | wrong_state | invalid | busy | unavailable

/// What the Workspace can see and do with boxes. Implemented by the box
/// manager (step 3) and by `FakeBoxSource`. Every method is synchronous
/// and may block briefly; the daemon calls it from `spawn_blocking`.
/// No method checks access: the daemon has verified the frame and its
/// level (and any touch) before it calls one.
pub trait BoxSource: Send + Sync {
    fn overview(&self) -> Overview;
    fn list(&self) -> Vec<BoxInfo>;
    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, BoxError>;
    fn diff(&self, id: &BoxId) -> Result<DiffSummary, BoxError>;
    fn stop(&self, id: &BoxId) -> Result<(), BoxError>;
    fn pause(&self, id: &BoxId) -> Result<(), BoxError>;
    fn resume(&self, id: &BoxId) -> Result<(), BoxError>;
    fn discard(&self, id: &BoxId) -> Result<(), BoxError>;
    fn reorder(&self, queue: &[BoxId]) -> Result<(), BoxError>;   // the full new order of the queued boxes
    fn steer(&self, id: &BoxId, msg: &str) -> Result<(), BoxError>;
    fn revise(&self, id: &BoxId, comment: &str) -> Result<(), BoxError>;   // done -> running, with the comment as the next prompt
    fn pending_actions(&self) -> Vec<PendingAction>;
    fn complete(&self, request_id: u64, decision: Decision, evidence: Option<saiife_touch::TouchEvidence>) -> Result<(), BoxError>;   // evidence is Some for Approve, None for Reject
    fn templates(&self) -> Vec<Template>;
    fn spawn(&self, req: &SpawnReq) -> Result<BoxId, BoxError>;
}
pub const MAX_STEER_BYTES: usize = 4096;
pub const MAX_TASK_BYTES: usize = 8192;
pub fn check_text(s: &str, max: usize) -> Result<(), BoxError>;   // non-empty, <= max bytes, no NUL, no C0 controls but \n and \t
/// Step 3 has not landed: the daemon's default source.
pub struct NoBoxes;
impl BoxSource for NoBoxes { /* empty lists, slots 0, every action Unavailable("boxes are not available in this version") */ }
```
- **Contract with step 3 (doc comment on the trait, copied into the box plans):** `state` follows §7.7 only; `stop` on a stopped box is `Ok(())` (idempotent); `revise` is only valid in `Done` (`WrongState` otherwise); `complete(Approve)` on `land` adds one commit per §7.7 and never writes a user's repo (§5.1: the CLI does). `diff_sha256` is SHA-256 of the full unified diff before truncation, the value the `land` `ActionRecord` binds.

- [ ] **Step 1: Write the failing tests:** `box_id_rules` (`"a"`, `"b-1"` ok; `""`, `"-a"`, `"A"`, `"a/b"`, `"../x"`, 41 chars refused), `box_id_rejects_on_deserialize`, `state_serializes_snake_case` (`"done"`), `no_boxes_is_empty_and_unavailable`, `check_text_rules` (ESC `\x1b` refused, `\n` ok, 4097 bytes refused), `dto_json_shape` (one `Overview` to JSON, compared to a literal: this pins the names plan 30's JS reads), `pending_view_has_challenge_and_code` (plan 26's Task 2 fixture record: `instance_id = [0x11; 16]`, `request_id = 42`, … ; `challenge_hex == "9759e53f34fc0f4308fe8e0d10a32b4bd0e0d85365c969948afca55866496db6"`, `short_code == "918949"`, `request_id == "42"`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(wire): BoxSource, the seam between boxes and the Workspace`.

---

### Task 8: `FakeBoxSource` and the conformance kit (size M)

**Files:** Modify `crates/wire/src/fake.rs`, `crates/wire/src/conformance.rs`; create `crates/wire/tests/fake_conformance.rs`.

**Interfaces (Produces):**
```rust
// fake.rs (feature "fake")
pub struct FakeBoxSource { /* Mutex<FakeState> */ }
#[derive(Debug, Clone, PartialEq)] pub enum FakeCall { Stop(BoxId), Pause(BoxId), Resume(BoxId), Discard(BoxId), Reorder(Vec<BoxId>), Steer(BoxId, String), Revise(BoxId, String), Complete(u64, Decision, bool /* had evidence */), Spawn(SpawnReq) }
impl FakeBoxSource {
    pub fn empty(now: u64) -> FakeBoxSource;
    /// Four boxes: "b-run" Running, "b-done" Done (with the hostile diff and a
    /// pending `land`), "b-q1" and "b-q2" Queued; two templates:
    /// "claude" (no secrets, no egress) and "claude-gh" (has_secrets).
    pub fn demo(now: u64) -> FakeBoxSource;
    pub fn calls(&self) -> Vec<FakeCall>;
    pub fn set_now(&self, now: u64);
    pub fn with_terminal(self, id: &str, frames: Vec<TermFrame>) -> FakeBoxSource;
}
impl crate::BoxSource for FakeBoxSource { /* §7.7 transitions; WrongState where §7.7 forbids */ }
// conformance.rs (feature "fake"); step 3 calls it from its own tests.
pub struct Fixture<'a> { pub source: &'a dyn crate::BoxSource, pub running: BoxId, pub done: BoxId, pub queued: Vec<BoxId> /* >= 2 */, pub template: String }
pub fn check(fx: &Fixture) -> Result<(), String>;   // every rule below; the message names the rule
```
- The demo `b-done` diff contains: a file `../../.ssh/authorized_keys` (path shown as data, never resolved), a file named `<img src=x onerror=alert(1)>.md`, a line with `\x1b]52;c;` (an OSC 52 attempt) and `\u{202e}` in the task text, and a binary file. Its `unified` is 2.5 MB of generated lines, so `truncated` is true and `unified.len() <= MAX_DIFF_BYTES`.
- `check` rules: `overview().boxes` has the same ids as `list()`; ids parse; the overview order rule of Task 7; `diff`/`terminal`/`stop` of an unknown id are `NotFound`; `revise(running)` is `WrongState`; `stop` twice is `Ok` both times; `reorder` with ids that are not exactly the queued set is `Invalid`; `reorder` reversed shows in `queue_pos`; `spawn` with an unknown template is `Invalid`; `steer` with an ESC byte is `Invalid`; `templates()` names are unique; every `pending_actions()` entry has `expires_at > created_at`, `request_id`, `class` and `expires_at` equal to its record's, and a unique `request_id`; `complete` of an unknown request is `NotFound`. The fake builds its `land` record as a plain `saiife_touch::ActionRecord` literal (its fields are public): class `Land`, `fields = {repo, base_commit, diff_sha256}` (the names plan 26 reserves), a fixed `instance_id`, nonce from the fake's counter, `expires_at = now + 300`.

- [ ] **Step 1: Write the failing tests** (`tests/fake_conformance.rs`, `--features fake`): `demo_passes_conformance` (`check` returns `Ok`), `fake_carries_hostile_display_data`, `diff_is_capped_and_flagged`, `revise_moves_done_to_running`, `complete_approve_lands` (state `Landed`, `lands == 1`, the pending action is gone), `complete_reject_keeps_done`, `spawn_queues_or_starts` (`Start::Queue` → `Queued` with the next `queue_pos`), `terminal_pages_by_seq` (`after = Some(next)` returns only newer frames), `calls_are_recorded`, and `broken_source_fails_conformance` (a test-local wrapper whose `stop` twice errs → `check` names "stop is idempotent").
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(wire): FakeBoxSource and the BoxSource conformance kit`.

---

## Gates (after Task 8)

- [ ] `cargo test -p saiife-wire --features fake -j 4 -- --test-threads=4` and without `--features fake` both pass.
- [ ] `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-wire`.
- [ ] `cargo tree -e normal -p saiife-wire | grep -c tokio` → `0`; `git diff v3-dev -- Cargo.lock` adds only the `saiife-wire` package entry.
- [ ] Whole-branch review against this plan's Review Focus; one fix wave; PR to `v3-dev` (owner merges).

## Out of scope

- The hub relay (`../saiife-hub`) and the Workspace UI in `../saiife.com`: other repos. They consume `tests/vectors/*.json` and the fixed values above.
- WebAuthn assertion verification: `saiife_touch::verify` (plan 26). Daemon wiring, files, IPC ops: plan 29.
