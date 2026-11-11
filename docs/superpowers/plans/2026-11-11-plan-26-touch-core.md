# Plan 26: touch core (verifier crate, touch classes, daemon wiring, audit fields): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A daemon that refuses a touch-class approval unless it comes with a FIDO2 or WebAuthn signature over a challenge bound to that exact pending request. The signature is verified against a device the approver enrolled, and the evidence lands in the audit record. No hardware, network or session bus is used anywhere in this plan.

**Architecture:**
- **`crates/touch` (`saiife-touch`), tokio-free, pure.** It owns:
  - a small CBOR reader for COSE keys and authenticator data;
  - the action record and its challenge (spec §8.3);
  - one verifier for both forms of assertion: CTAP2 from the CLI, and WebAuthn `clientDataJSON` from a browser;
  - the credential file format;
  - the client-side `Touch` trait, which plan 27's HID key implements;
  - a `SoftAuthenticator` (feature `soft`) that signs exactly as a real key does.

  Crypto is `ring` 0.17.14 only, which is already in `Cargo.lock`.
- **The daemon issues and burns challenges; it never trusts the client's digest.**
  - `touch.begin` stores a nonce and an expiry in memory, keyed by what they are for.
  - `approval.decide` rebuilds the action record from the *stored* request, the stored nonce and the stored expiry. It removes the nonce (single use), verifies the assertion, saves the new signature counter, and only then moves the request to `approved`.
  - A daemon restart forgets every live challenge, so an old assertion can never be replayed.
- **Touch classes come from marks in the policy:**
  - `deploy` patterns and `real_system` on a service;
  - `sensitive` on a secret;
  - later, the box classes `land` and `push_protected`, which step 3 sets on its own requests.

  A marked operation is never auto-allowed. The broker turns its `allow` into `ask`, so an approval request (and its touch) always happens.

**Tech Stack:** Rust. `ring = "=0.17.14"`, `serde`, `serde_json`, `base64 = "=0.23.1"` (all already in `Cargo.lock`, at the versions the daemon uses). No new crates. `tempfile` for tests.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §8 (touch approvals), §9.5 (access levels), §11 (step 4), §12 (testing), §15 (honest limits). The binding cross-plan contract is `v3-step4-6-contract.md` in the coordinator's scratchpad. Plan 27 (CLI and HID key) builds on Tasks 1 to 4 and Tasks 6 to 9 of this plan. Plan 28 (`crates/wire`) builds on Tasks 1 to 4 only.

## Contract changes

Each change follows the code or the spec, and the coordinator's return lists it:

| Contract | This plan | Why |
|---|---|---|
| `trait Touch { fn request(&self, a: &ActionRecord) -> Result<TouchEvidence, TouchError>; }`, a daemon-side seam that Hid and browser implement | **Client side:** `trait Touch: Send + Sync { fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError>; fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError>; }`. **Daemon side:** the concrete `daemon::touch::TouchState`, no trait. | The daemon cannot reach the key. In locked mode it runs as another user, and the key's hidraw node belongs to the seat user (uaccess). The browser is JavaScript. Both clients *produce an assertion*, and only the daemon can turn one into evidence. Tests use the real `TouchState` with a `SoftAuthenticator`, so no daemon fake is needed. |
| `enum TouchError { Unavailable, Mismatch, BadSignature, Replayed, Expired, UnknownCredential, Malformed }` | The same 7 variants, **plus** `NotPresent` (UP flag missing) and `NotVerified` (UV needed, missing). Each has `rule()`. | The spec (§8.3) checks UP and UV separately. Folding them into `BadSignature` would tell the user the wrong thing ("set a PIN" is the fix for `NotVerified`). |
| `TouchEvidence { credential_id, kind, user_verified, sign_count, challenge_hex }` | The same 5 fields, **plus** `label`, `via`, `flags`, `auth_data`, `client_data`, `client_data_hash`, `signature`, `preimage_hex`, `action`, and `to_audit()`. | Spec §8.5 lists what the audit `touch` field must carry: the device label, flags, authenticatorData, clientDataJSON, signature, challenge preimage, and `via`. |
| `Assertion::WebAuthn { …, origin }` | `origin` is kept. The verifier requires `clientDataJSON.origin == origin`, **and** `origin` must be one of the credential's enrolled `origins`. | The relay must not choose the origin. The enrolled list is the real check. |
| `verify(creds, a, asr, rp_id, now)` | Unchanged. It is **pure**: it never burns a nonce and never saves a counter, and the daemon's `TouchState::consume` does both. | Plan 28 and plan 31 call the same pure function. |
| "burn nonce (single-use store, persisted)" (research) | An **in-memory** table of live challenges, capped, never persisted. | The daemon accepts only challenges it issued and still holds. After a restart the table is empty, so persistence adds nothing. |
| `ActionRecord { action kind, target ids, summary hash, nonce, expires_at }` | `{ instance_id, request_id, class, summary, fields, nonce, expires_at }`, with `summary` and `fields` inside the digest. | Spec §8.3 names `daemon_instance_id` and `request_id` in the preimage. |

## Facts checked (2026-11-11)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | ctap-hid-fido2 3.6.0 hashes the challenge itself. `get_assertion_command.rs` and `make_credential_command.rs` both build `client_data_hash: util::create_clientdata_hash(challenge)`. `util.rs`: `pub(crate) fn create_clientdata_hash(challenge: Vec<u8>) -> Vec<u8> { // sha256 let hasher = digest::digest(&digest::SHA256, &challenge); hasher.as_ref().to_vec() }` | docs.rs `ctap-hid-fido2/3.6.0/source/src/{util.rs, fidokey/get_assertion/get_assertion_command.rs, fidokey/make_credential/make_credential_command.rs}` | **Rule pinned (D1).** |
| F2 | `Assertion` (3.6.0) has `auth_data: Vec<u8>` (raw authenticatorData), `signature`, `credential_id`, `sign_count`, `flags`. `Attestation` has `auth_data` (raw, with the attested credential data). | `get_assertion_params.rs`, `make_credential_params.rs` | The verifier parses the raw bytes itself and never uses the crate's parsed fields. |
| F3 | `serde_json` is built with `preserve_order` in this workspace (`crates/policy/src/effective.rs:91-92`). A `serde_json::Map` keeps insertion order, and a `BTreeMap<String, String>` still serialises sorted. | code | **D2.** The canonical action JSON is built from a `BTreeMap` and a struct with fixed field order, never from a `Map`. |
| F4 | The audit chain hash is SHA-256 of the line bytes as written (`crates/audit/src/chain.rs:346-352`, `push_line`). `Record.extra` is `#[serde(flatten)]` and keeps unknown keys (`crates/audit/src/record.rs:89-92`). The writer does not mask `extra`. `RECORD_VERSION = 2` (`record.rs:12`). | code | **No version bump.** `touch` is one more `extra` key, like `by_uid` (`approval_ops.rs:557-565`). |
| F5 | The daemon has no instance id today (no `instance_id` anywhere in `crates/daemon/src`). | grep | **D3.** Task 7 adds one: 16 random bytes in `<state>/state/touch/instance_id`, made once. |
| F6 | `may_decide` returns `Ok(())` early when the approver is another principal (`approvers.rs:202-209`). The personal path never calls it (`approval_ops.rs:651-656`). | code | The touch hook goes **after** the `if let Some(why) = refusal` at `approval_ops.rs:688-690`, so it covers every path: personal mode, a second account, and same-user reauth. |
| F7 | The broker turns a verdict into "ask?" at `crates/broker/src/pipeline.rs:918-923`. `cfg = &snap.config` (`:807`) is the environment-applied config. | code | Task 5 escalates `Allow` to ask there. |

### Design decisions (flagged for the owner)

- **D1. The clientDataHash rule.** Let `C = challenge(a)` be the 32-byte SHA-256 of the §8.3 preimage.
  - **CTAP2 (local):** the CLI passes `C` as the `challenge` argument of ctap-hid-fido2, which signs over `clientDataHash = SHA-256(C)` (F1). So the key signs `authData ‖ SHA-256(C)`. The verifier computes `SHA-256(C)` itself. It compares it with the assertion's `client_data_hash` (unequal is `Mismatch`) and verifies the signature over its *own* value.
  - **WebAuthn (browser):** `clientDataJSON.challenge = base64url_nopad(C)`, and `clientDataHash = SHA-256(clientDataJSON bytes)`.
- **D2. Canonical action JSON.** It is `serde_json::to_string` of `struct Canon<'a> { class: &str, fields: &BTreeMap<String, String>, summary: &str }`, with the fields declared in that order: compact, keys sorted. Pinned vector in Task 2.
- **D3. Instance id** is persistent per state dir (F5). A browser assertion for one machine never verifies on another, and a reinstall (a new state dir) invalidates nothing that matters: challenges live 5 minutes.
- **D4. UV.** UV is needed for the classes `land`, `deploy` and `secret:sensitive` (§8.3), and for the admin purposes `touch_enrol`, `touch_remove` and `touch_test`. It is also needed for **every WebAuthn assertion, whatever the class**: §9.5 says "+ touch (UV)" for every remote action, and §15 notes that a synced passkey needs UV to prove who. Enrolment needs UV, so a device that cannot do UV (a key with no PIN) is refused at enrol, not at the first `land`.
- **D5. The sign counter.** When either the stored or the new counter is non-zero, the new one must be **strictly greater** (WebAuthn L2 §7.2 step 21), else `Replayed`. When both are 0, it is accepted (synced passkeys). Spec §8.3 says "non-decreasing". Strict is the WebAuthn rule, and an equal counter is the clone signal (owner check 3).
- **D6. Credentials belong to a uid.** `approval.decide` verifies only against the credentials the deciding peer's uid enrolled. In personal mode, that is the daemon's own uid.
- **D7. Marks** (Task 5):
  - `[services.<name>] deploy = ["<capability pattern>", …]` gives `deploy`;
  - `[services.<name>] real_system = true` gives `egress:external`;
  - `[secrets.<name>] sensitive = true` gives `secret:sensitive` for any service whose (environment-applied) `secret` is that secret.

  §8.2 says a `deploy = true` mark on a connector op. Manifest operations are not config entries, so a pattern list on the service is the form that works for both manifest and manifest-less connectors. Environments cannot set marks (their keys are closed), so an environment cannot remove one. MCP and command requests get no class in v3.0.
- **D8. A class can only get stronger after the ask.** `decide` uses `stronger(stored class, class under the current policy)`. A reload that removes a mark does not drop the touch of a request that is already pending.
- **D9. The short code** on both screens is `format!("{:06}", u32::from_be_bytes([0, c[0], c[1], c[2]]) % 1_000_000)` of `C`.
- **D10. Enrolment** (Task 9) is two touches of the new device:
  1. `make_credential` over `C`, which the daemon parses for the credential id and COSE key (attestation statements are not checked; owner check 4);
  2. a `get_assertion` with the new credential over the same `C`, which proves possession and UV.

  When the uid already has a device, a third assertion over `C` from one of its existing devices is needed. With none, host access is the proof (§8.4).

## Global Constraints

- **Tokio-free:** `saiife-touch`, `saiife-policy` and `saiife-audit` never depend on tokio. Task 1 adds `-p saiife-touch` to the CI step "no tokio in hook crates" (`.github/workflows/ci.yml:131`).
- **No unsafe:** `[lints] workspace = true`, and `#![forbid(unsafe_code)]` at column 0 of `crates/touch/src/lib.rs` (`scripts/check-unsafe.sh`).
- **No new crates.** `saiife-touch` deps: `ring = "=0.17.14"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `base64 = "=0.23.1"`. `[features] soft = []`. Dev-dep `tempfile = "3"`. The daemon adds `saiife-touch = { path = "../touch" }`, plus the dev-dep `saiife-touch = { path = "../touch", features = ["soft"] }`.
- **Never fall back to a password** (§8.4). No device enrolled, no assertion sent, or no live challenge each refuses (`touch_unavailable` / `touch_failed`), and never asks for polkit instead.
- **Fixed values:**
  - local `rp_id = "saiife.local"`, `rp_name = "saiife"`;
  - challenge TTL 300 s, prompt timeout 120 s (§8.6);
  - domain tag `b"saiife-touch-v1"` (15 bytes);
  - at most 32 live challenges in all, and 4 per uid;
  - at most 16 credentials per uid;
  - byte caps: `credential_id` ≤ 1023, `auth_data` ≤ 1024, `signature` ≤ 256, `client_data_json` ≤ 2048.
- **Encodings:** bytes are base64url without padding (`URL_SAFE_NO_PAD`); hashes are lowercase hex.
- **Tests:** no hardware, network, D-Bus or polkit. `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent` in every test command. Every key is a `SoftAuthenticator` or a published vector.
- **Commands for every task** (hard rules), in the worktree `.worktrees/p26`:
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p26-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent
  cargo test -p <crate> -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```
  (`N` is the task number.) Remove `$TMPDIR` at the end. Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Hostile bytes from a key or a browser:**
   - truncated CBOR, indefinite lengths, a length of 2^63, maps nested 100 deep;
   - trailing bytes after authData;
   - a 70 KB `clientDataJSON`.

   Expected: `Malformed`, no panic, no allocation larger than the input (Task 1: `cbor_rejects_hostile_input`; Task 3: `oversized_fields_are_malformed`).
2. **A valid assertion used for something else:** another request, the same request after a policy-irrelevant field changed, another machine (instance id), or a challenge issued to another uid. Expected: `touch_mismatch`, and the request stays pending (Task 3: `assertion_for_another_action_is_mismatch`; Task 8: `touch_for_request_a_cannot_approve_b`, `challenge_of_another_uid_is_refused`).
3. **Replay:** the same assertion sent twice, or sent after a daemon restart. Expected: the second is refused with `touch_failed`, and nothing is sent (Task 8: `same_assertion_twice_is_refused`, `restart_forgets_challenges`).
4. **A policy reload between the ask and the decision** that removes a mark. Expected: the touch is still needed (Task 8: `reload_removing_a_mark_keeps_the_touch`).
5. **A v2 install upgraded:** old request files, old policies, old audit chains. Expected:
   - request files load (with `touch_class` absent);
   - policy hashes are unchanged for configs without marks;
   - an old chain plus new `touch` records verifies with `saiife audit verify` (Task 5: `policy_hash_unchanged_without_marks`; Task 6: `old_request_file_loads`; Task 9: `old_chain_with_touch_records_verifies`).

---

## Task order and parallelism

- **Wave 1:** Task 1.
- **Wave 2 (parallel):** Task 2 and Task 5. Task 5 touches only `policy` and `broker`.
- **Wave 3:** Task 3 (needs 1 and 2).
- **Wave 4:** Task 4 (needs 3). **Merge point 26a:** Tasks 1 to 4 merge to v3-dev, and `saiife-touch`'s API is then frozen for plans 27 and 28.
- **Wave 5:** Task 6 (needs 4 and 5).
- **Wave 6:** Task 7 (needs 6).
- **Wave 7 (parallel):** Task 8 and Task 9. Both need 7, and they touch different arms of `touch_ops.rs` (Task 7 creates the file with both arms stubbed).
- **Last:** the gates, a whole-branch review, one fix wave, push, PR.

**Shared files:**
- `crates/touch/src/lib.rs`: Task 1 declares every module, with empty files.
- `crates/touch/src/error.rs`: complete in Task 1.
- `crates/ipc/src/msg.rs`: Task 7 adds every op constant.

---

### Task 1: the crate, errors, CBOR, COSE keys and authenticator data (size M)

**Files:**
- Create `crates/touch/Cargo.toml`, and in `crates/touch/src/`: `lib.rs`, `error.rs`, `cbor.rs`, `cose.rs`, `authdata.rs`, plus empty `action.rs`, `verify.rs`, `store.rs`, `client.rs` and `soft.rs` (one `//!` line each; `soft` is declared `#[cfg(any(test, feature = "soft"))] pub mod soft;`).
- Modify `.github/workflows/ci.yml:131` (add `-p saiife-touch`) and `Cargo.lock` (by cargo).

**Interfaces (Produces):**
- `Cargo.toml`: `name = "saiife-touch"`, `description = "saiife touch approvals: action-bound FIDO2 and WebAuthn assertions, verified on ring."`, `[lib] name = "saiife_touch"`, the deps from Global Constraints, and `[lints] workspace = true`.
- `lib.rs`: a `//!` doc, `#![forbid(unsafe_code)]`, the modules, and these re-exports: `pub use error::TouchError; pub use action::{ActionRecord, TouchClass, challenge, short_code}; pub use verify::{Assertion, TouchEvidence, verify}; pub use store::{Credential, CredentialFile, CoseAlg}; pub use client::{Touch, TouchRequest, EnrolRequest};`. Constants: `pub const LOCAL_RP_ID: &str = "saiife.local"; pub const RP_NAME: &str = "saiife"; pub const CHALLENGE_TTL_SECS: u64 = 300; pub const PROMPT_TIMEOUT_SECS: u64 = 120;`.
- `error.rs`: `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TouchError { Unavailable, Mismatch, BadSignature, Replayed, Expired, UnknownCredential, Malformed, NotPresent, NotVerified }`, with a hand-written `Display`, `std::error::Error`, and `pub fn rule(&self) -> &'static str`:

| Variant | `rule()` | Display |
|---|---|---|
| `Unavailable` | `touch_unavailable` | `no enrolled touch device answered` |
| `Mismatch` | `touch_mismatch` | `the touch was for a different action, device or origin` |
| `UnknownCredential` | `touch_mismatch` | `this device is not enrolled for you` |
| `BadSignature` | `touch_failed` | `the touch signature does not verify` |
| `Replayed` | `touch_failed` | `the touch was used before (its signature counter did not advance)` |
| `Expired` | `touch_failed` | `no live challenge for this touch: it expired, was used, or the daemon restarted` |
| `Malformed` | `touch_failed` | `the touch data is malformed` |
| `NotPresent` | `touch_failed` | `the device reported no touch` |
| `NotVerified` | `touch_failed` | `this needs user verification on the device (its PIN or fingerprint)` |

- `cbor.rs`: `pub(crate) enum Item<'a> { Uint(u64), Nint(i128), Bytes(&'a [u8]), Text(&'a str), Array(Vec<Item<'a>>), Map(Vec<(Item<'a>, Item<'a>)>), Bool(bool), Null }` and `pub(crate) fn read(input: &'a [u8]) -> Result<(Item<'a>, &'a [u8]), TouchError>` (one item, and the rest of the input).
  - **Rejected** (`Malformed`): indefinite lengths (additional info 31), tags (major type 6), floats and undefined simple values, additional info 28 to 30, a length larger than the bytes left, depth over 8, more than 64 items in one array or map, and non-UTF-8 text.
  - Allocation is bounded by the item count checks, never by a declared length.
- `cose.rs`: `#[derive(Debug, Clone, PartialEq, Eq)] pub enum CoseKey { Es256 { x: [u8; 32], y: [u8; 32] }, Ed25519 { x: [u8; 32] } }`, with:
  - `pub fn parse(bytes: &[u8]) -> Result<(CoseKey, usize), TouchError>` (the key and the bytes used);
  - `pub fn to_cose(&self) -> Vec<u8>`;
  - `pub fn alg(&self) -> CoseAlg`.
  - ES256 is `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, and EdDSA is `{1: 1, 3: -8, -1: 6, -2: x}`. Any other kty, alg or curve is `Malformed`. Unknown extra labels are ignored. `to_cose` writes the keys in the order 1, 3, -1, -2, -3.
- `authdata.rs`: `pub struct AuthData<'a> { pub rp_id_hash: [u8; 32], pub flags: u8, pub sign_count: u32, pub attested: Option<Attested>, raw: &'a [u8] }` and `pub struct Attested { pub aaguid: [u8; 16], pub credential_id: Vec<u8>, pub public_key: CoseKey }`.
  - Flag constants: `UP = 0x01`, `UV = 0x04`, `AT = 0x40`, `ED = 0x80`.
  - `pub fn parse(raw: &[u8]) -> Result<AuthData<'_>, TouchError>`. The layout is 32 + 1 + 4 bytes. With AT, then aaguid(16), a big-endian u16 length L (1..=1023) and the id, then one COSE key. With ED, then one CBOR map, skipped. **Any trailing byte is `Malformed`.**
- `store.rs` (only this type now): `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "lowercase")] pub enum CoseAlg { Es256, Ed25519 }`.

- [ ] **Step 1: failing tests** (unit tests in each file):
  - `cbor_reads_the_basics`: `0x18 0x2a` gives `Uint(42)`; `0x38 0x63` gives `Nint(-100)`; `0x43 1 2 3` gives `Bytes([1,2,3])`; `0xa1 0x01 0x02` gives `Map([(Uint(1), Uint(2))])`; the rest after one item is returned.
  - `cbor_rejects_hostile_input` (Review Focus 1): each of these is `Err(Malformed)`, and none panics:
    - `0x5f` (indefinite bytes);
    - `0xc0 0x00` (a tag);
    - `0xfb` + 8 bytes (a float);
    - `0x5b` + `u64::MAX` (a huge length);
    - `0x42 0x01` (truncated);
    - nine nested `0x81` (depth);
    - an array header of 65 items;
    - text `0x62 0xff 0xfe` (not UTF-8).
  - `cose_es256_round_trip`: `CoseKey::Es256 { x: [1; 32], y: [2; 32] }.to_cose()` parses back to itself, with the byte count equal to the length.
  - `cose_ed25519_round_trip`: the same for `Ed25519 { x: [3; 32] }`.
  - `cose_rejects_other_algs`: alg `-257` (RS256), and crv `2` with alg `-7`, are `Malformed`.
  - `authdata_without_at`: 37 bytes, rpIdHash `[9; 32]`, flags `0x05` and counter `[0,0,1,0]` give `flags == 5`, `sign_count == 256`, and `attested == None`. 38 bytes are `Malformed`.
  - `authdata_with_attested_credential`: rpIdHash, flags `0x45`, counter 0, aaguid `[7; 16]`, length `0x0003`, id `[1,2,3]`, then the ES256 COSE bytes give `Attested { credential_id: [1,2,3], public_key: Es256 {..} }`. The same bytes cut by one byte are `Malformed`.
  - `authdata_skips_extensions`: flags `0x81` + `{ "credProtect": 2 }` CBOR parses; one extra byte after it is `Malformed`.
  - `rules_and_display`: each row of the table above.
- [ ] **Step 2:** `cargo test -p saiife-touch` (commands in Global Constraints); expect FAIL (unresolved items).
- [ ] **Step 3:** implement. The CBOR reader is a recursive function with a `depth` parameter. It reads the header with `u8::checked_*` and `usize::try_from`, and compares a length with `input.len()` before slicing.
- [ ] **Step 4:** the tests pass. `bash scripts/check-unsafe.sh` exits 0. `cargo tree -e normal -p saiife-touch | grep -c tokio` prints `0`. `bash scripts/check-windows.sh -p saiife-touch` is clean.
- [ ] **Step 5:** commit `feat(touch): the saiife-touch crate: errors, a bounded CBOR reader, COSE keys and authenticator data`.

### Task 2: action records, touch classes and the challenge (size S)

**Files:** modify `crates/touch/src/action.rs`.

**Interfaces:**
- Consumes `TouchError` (Task 1).
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)] pub enum TouchClass { Land, PushProtected, Deploy, SecretSensitive, EgressExternal, Enrol, Remove, Test }`, with:
    - `pub fn name(self) -> &'static str`, giving `land`, `push_protected`, `deploy`, `secret:sensitive`, `egress:external`, `touch_enrol`, `touch_remove`, `touch_test`;
    - `pub fn from_name(s: &str) -> Option<TouchClass>`;
    - `pub fn needs_uv(self) -> bool`, true for `Land`, `Deploy`, `SecretSensitive`, `Enrol`, `Remove` and `Test` (D4);
    - `pub fn stronger(a: Option<TouchClass>, b: Option<TouchClass>) -> Option<TouchClass>`: the one that needs UV if exactly one does, else `a`, else `b` (D8).
    - Serde as `name()` (a string), via a hand impl or `#[serde(rename)]`s.
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ActionRecord { pub instance_id: [u8; 16], pub request_id: u64, pub class: TouchClass, pub summary: String, pub fields: BTreeMap<String, String>, pub nonce: [u8; 32], pub expires_at: u64 }`. `expires_at` is in Unix seconds. The field names a request sets are in Task 6. The box plans use `repo`, `base_commit`, `target_ref`, `diff_sha256` and `remote` (reserved here, in a doc comment).
  - `impl ActionRecord`:
    - `pub fn canonical_action(&self) -> String` (D2);
    - `pub fn action_digest(&self) -> [u8; 32]`, which is SHA-256 of `canonical_action()`;
    - `pub fn preimage(&self) -> Vec<u8>`, exactly `b"saiife-touch-v1" ‖ instance_id ‖ request_id.to_be_bytes() ‖ nonce ‖ expires_at.to_be_bytes() ‖ action_digest`, 111 bytes. Every field has a fixed length, so no length prefixes are needed.
  - `pub fn challenge(a: &ActionRecord) -> [u8; 32]`, which is SHA-256 of `a.preimage()` (`ring::digest::SHA256`).
  - `pub fn short_code(c: &[u8; 32]) -> String` (D9).
  - `pub(crate) fn sha256(b: &[u8]) -> [u8; 32]` and `pub(crate) fn hex(b: &[u8]) -> String`, used by later tasks.

- [ ] **Step 1: failing tests.** The fixture is `instance_id = [0x11; 16]`, `request_id = 42`, `class = Deploy`, `summary = "#42 erp payments.create"`, `fields = {service: "erp", operation: "payments.create", body_sha256: "0".repeat(64)}`, `nonce = [0x22; 32]` and `expires_at = 1_800_000_000`. It is inserted out of order, so the test shows that sorting happens.
  - `canonical_action_is_pinned`: equals `{"class":"deploy","fields":{"body_sha256":"<64 zeros>","operation":"payments.create","service":"erp"},"summary":"#42 erp payments.create"}`;
  - `challenge_vector` (computed independently with Python `hashlib`, 2026-11-11):
    - `hex(action_digest) == "88ecaf20f077c770f26a6f953e63558f39df0306fb088ead47646deda999d1b7"`;
    - `preimage().len() == 111`;
    - `hex(challenge) == "9759e53f34fc0f4308fe8e0d10a32b4bd0e0d85365c969948afca55866496db6"`;
    - `short_code == "918949"`;
  - `every_field_changes_the_challenge`: changing any one of instance id, request id, class, summary, a field value, a field key, nonce or expiry gives a different challenge;
  - `class_names_round_trip`: `from_name(c.name()) == Some(c)` for all 8; `from_name("Deploy") == None`;
  - `needs_uv_table` and `stronger_prefers_uv`: `stronger(Some(EgressExternal), Some(Deploy)) == Some(Deploy)`, `stronger(Some(Deploy), None) == Some(Deploy)`, `stronger(None, Some(EgressExternal)) == Some(EgressExternal)`;
  - `non_ascii_summary_is_stable`: the summary `"#1 café"` gives the same digest twice, and `canonical_action` holds the raw UTF-8 (no `\u` escape).
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean.
- [ ] **Step 5:** commit `feat(touch): action records, touch classes and the action-bound challenge (§8.3)`.

### Task 3: the verifier, the client trait and the SoftAuthenticator (size L)

**Files:**
- Modify `crates/touch/src/verify.rs`, `crates/touch/src/client.rs`, `crates/touch/src/soft.rs`, and `crates/touch/src/store.rs` (the `Credential` struct only; the file format is Task 4).
- Create `crates/touch/tests/webauthn_vector.rs` and `crates/touch/tests/vectors/webauthn-l3-es256.json`.

**Interfaces:**
- Consumes Tasks 1 and 2.
- Produces:
  - `store.rs`: `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct Credential`. Bytes are base64url in JSON, through a small `serde(with = "b64")` module. Its fields:
    - `id: Vec<u8>`;
    - `public_key: CoseKey`, serialised as base64url of `to_cose()`;
    - `kind: String` (`"fido2"` or `"webauthn"`);
    - `rp_id: String`;
    - `#[serde(default, skip_serializing_if = "Vec::is_empty")] origins: Vec<String>`;
    - `label: String`;
    - `owner_uid: u32`;
    - `#[serde(default, skip_serializing_if = "Option::is_none")] owner_sid: Option<String>`;
    - `sign_count: u32`;
    - `created: String`;
    - `aaguid: String` (hex).
  - `verify.rs`:
    - `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(tag = "kind", deny_unknown_fields)] pub enum Assertion`, with two variants:
      - `#[serde(rename = "fido2")] Ctap2 { credential_id: Vec<u8>, auth_data: Vec<u8>, signature: Vec<u8>, client_data_hash: [u8; 32] }`;
      - `#[serde(rename = "webauthn")] WebAuthn { credential_id: Vec<u8>, auth_data: Vec<u8>, signature: Vec<u8>, client_data_json: Vec<u8>, origin: String }`.

      Bytes are base64url, and `client_data_hash` is hex. **This JSON is the `touch` argument of `approval.decide` and the form plan 28 carries.**
    - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct TouchEvidence { pub credential_id: String, pub kind: &'static str, pub user_verified: bool, pub sign_count: u32, pub challenge_hex: String, pub label: String, pub via: &'static str, pub flags: u8, pub auth_data: Vec<u8>, pub client_data: Option<Vec<u8>>, pub client_data_hash: [u8; 32], pub signature: Vec<u8>, pub preimage_hex: String, pub action: String }`:
      - `credential_id` is base64url;
      - `via` is `"local"` (fido2) or `"web"` (webauthn);
      - `client_data` is the `clientDataJSON`, for WebAuthn only;
      - `action` is `canonical_action()`.
    - `pub fn verify(creds: &[Credential], a: &ActionRecord, asr: &Assertion, rp_id: &str, now: u64) -> Result<TouchEvidence, TouchError>`: pure. It checks, **in this order**:
      1. **size caps** (Global Constraints), else `Malformed`;
      2. `parse(auth_data)`, else `Malformed`;
      3. a credential whose `id` equals the assertion's, else `UnknownCredential`, then `cred.rp_id == rp_id`, else `Mismatch`;
      4. `now > a.expires_at` is `Expired`;
      5. **client data (D1):**
         - Ctap2: `client_data_hash != sha256(&challenge(a))` is `Mismatch`.
         - WebAuthn: parse `client_data_json` as a JSON object, else `Malformed`. Then `type == "webauthn.get"`, else `Malformed`. Then `challenge == base64url_nopad(challenge(a))`, else `Mismatch`. Then `origin` (the JSON's) `== asr.origin`, and `cred.origins` contains it, else `Mismatch`. Then `crossOrigin == true` is `Mismatch`. The hash is `sha256(client_data_json)`.
      6. `rp_id_hash != sha256(rp_id)` is `Mismatch`;
      7. the signature over `auth_data ‖ hash`, with the hash the verifier computed itself: ES256 by `ring::signature::ECDSA_P256_SHA256_ASN1` on `0x04 ‖ x ‖ y`, Ed25519 by `ring::signature::ED25519`. Failure is `BadSignature`;
      8. without the UP flag, `NotPresent`; without UV when `a.class.needs_uv()` or the assertion is WebAuthn (D4), `NotVerified`;
      9. the counter (D5): `(cred.sign_count != 0 || new != 0) && new <= cred.sign_count` is `Replayed`.

      On success it returns the evidence with the new `sign_count`.
    - `impl TouchEvidence { pub fn to_audit(&self) -> serde_json::Value }`: an object with the keys `via`, `kind`, `cred_id`, `label`, `flags`, `uv`, `sign_count`, `auth_data`, `client_data` (only when present), `client_data_hash`, `signature`, `challenge`, `preimage` and `action`.
  - `client.rs`:
    - `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct TouchRequest { pub rp_id: String, pub challenge: [u8; 32], pub allow: Vec<Vec<u8>>, pub uv: bool, pub summary: String, pub short_code: String }`. `challenge` is hex in JSON, and `allow` is base64url. **This is the answer of `touch.begin`** (Task 7 adds `expires_at` and `class` beside it).
    - `pub struct EnrolRequest { pub rp_id: String, pub rp_name: String, pub user_id: Vec<u8>, pub user_name: String, pub challenge: [u8; 32], pub exclude: Vec<Vec<u8>> }`, with the same serde rules.
    - `pub trait Touch: Send + Sync { fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError>; fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError>; }`. `enrol` returns the raw attestation authData, with AT set.
  - `soft.rs` (`#[cfg(any(test, feature = "soft"))]`): `pub struct SoftAuthenticator`. Its signing key is a ring `EcdsaKeyPair` (P-256) or `Ed25519KeyPair`, kept as PKCS#8. It also has a credential id (16 random bytes) and an `AtomicU32` counter. It has these knobs, all `pub` fields with `Default`-like values:
    - `up: bool` (true), `uv: bool` (true);
    - `counter_step: u32` (1; 0 freezes the counter);
    - `rp_override: Option<String>` (signs as another rp);
    - `type_override: Option<String>` (the WebAuthn `type`).

    Its methods:
    - `new_es256() -> Self`, `new_ed25519() -> Self`;
    - `from_parts(alg: CoseAlg, pkcs8: &[u8], credential_id: Vec<u8>, counter: u32) -> Result<Self, TouchError>`, and `parts(&self) -> (CoseAlg, Vec<u8>, Vec<u8>, u32)`, used by plan 27's test seam file;
    - `credential_id(&self) -> Vec<u8>`, `public_key(&self) -> CoseKey`;
    - `credential(&self, rp_id: &str, owner_uid: u32, label: &str) -> Credential` (kind `fido2`, counter 0, created `"2026-01-01T00:00:00.000Z"`);
    - `web_credential(&self, rp_id: &str, origin: &str, owner_uid: u32) -> Credential`;
    - `assert_ctap(&self, rp_id: &str, challenge: &[u8; 32]) -> Assertion`, which signs `authData ‖ sha256(challenge)` exactly as ctap-hid-fido2 does (D1);
    - `assert_webauthn(&self, rp_id: &str, origin: &str, challenge: &[u8; 32]) -> Assertion`, with `clientDataJSON` exactly `{"type":"webauthn.get","challenge":"<b64url>","origin":"<origin>","crossOrigin":false}`;
    - `impl Touch`: `request` calls `assert_ctap(r.rp_id, r.challenge)` and refuses with `UnknownCredential` when `allow` is non-empty and lacks its id. `enrol` builds authData with AT and its COSE key, and flags UP+UV+AT (`0x45`).

- [ ] **Step 1: failing tests** (unit tests in `verify.rs`; the action fixture from Task 2 with `expires_at = now + 300` and class `Deploy`; `rp = LOCAL_RP_ID`):
  - `ctap_round_trip_es256` and `ctap_round_trip_ed25519`: `verify([soft.credential(rp, 1000, "key")], a, soft.assert_ctap(rp, &challenge(&a)), rp, now)` is `Ok`, with `kind == "fido2"`, `via == "local"`, `user_verified`, `sign_count == 1`, `challenge_hex == hex(challenge(a))`, `preimage_hex.len() == 222`;
  - `webauthn_round_trip`: `web_credential(rp, "https://app.saiife.com", 1000)` and `assert_webauthn` verify. The evidence has `via == "web"` and `client_data == Some(json)`;
  - `assertion_for_another_action_is_mismatch` (Review Focus 2): an assertion over `challenge(a)` checked against `a'` (request id 43; or `instance_id [0x12; 16]`; or one field changed) is `Mismatch`;
  - `wrong_rp_is_mismatch`: `rp_override = Some("evil.example")` is `Mismatch`; a credential with `rp_id = "other"` is `Mismatch`;
  - `unknown_credential`: an assertion from a second soft key is `UnknownCredential`;
  - `tampered_signature_and_auth_data`: one flipped bit in the signature, or in `auth_data` byte 33 (the counter), is `BadSignature`;
  - `client_hash_not_trusted`: a `Ctap2` assertion whose `client_data_hash` equals `sha256(challenge(a))` but whose signature was made over another hash is `BadSignature`;
  - `flags_checked`: `up = false` gives `NotPresent`; `uv = false` with class `Deploy` gives `NotVerified`; `uv = false` with class `EgressExternal` (Ctap2) is `Ok`; `uv = false` with `EgressExternal` over WebAuthn is `NotVerified` (D4);
  - `counter_rules` (D5): stored 5 and new 5 is `Replayed`; stored 5 and new 6 is `Ok`; stored 0 and new 0 (`counter_step = 0`) is `Ok`; stored 5 and new 0 is `Replayed`;
  - `expired`: `now = a.expires_at + 1` is `Expired`; `now == a.expires_at` is `Ok`;
  - `webauthn_client_data_rules`: `type_override = Some("webauthn.create")` is `Malformed`; an origin not in `cred.origins` is `Mismatch`; `origin` in the JSON differing from `asr.origin` is `Mismatch`; `crossOrigin: true` is `Mismatch`; a non-JSON `client_data_json` is `Malformed`;
  - `oversized_fields_are_malformed` (Review Focus 1): `client_data_json` of 70 000 bytes, a 1025-byte `auth_data`, a 257-byte signature and a 1024-byte credential id are each `Malformed`;
  - `assertion_json_shape`: `serde_json::to_value(soft.assert_ctap(..))` has the keys `kind = "fido2"`, `credential_id`, `auth_data`, `signature` and `client_data_hash` (64 hex), and parses back equal; an unknown key is an error;
  - `to_audit_keys`: the object's keys are exactly those listed above;
  - `soft_parts_round_trip`: `from_parts(soft.parts())` signs assertions that verify against the first key's credential, and its counter continues from the saved value.
- [ ] **Step 2: the published vector.** Fetch the W3C WebAuthn Level 3 Recommendation, §16.2 "ES256 Credential with No Attestation" (`https://www.w3.org/TR/webauthn-3/`; public reference data, allowed by the hard rules). Copy its registration authenticator data (for the COSE public key and credential id), and its assertion `challenge`, `clientDataJSON`, `authenticatorData` and `signature`, as hex, into `tests/vectors/webauthn-l3-es256.json`. Add a `"source"` key naming the section and the fetch date. `webauthn_vector.rs::l3_es256_assertion_verifies` checks it through `pub fn verify_parts(cred: &Credential, asr: &Assertion, rp_id: &str, expected_challenge: &[u8], need_uv: bool) -> Result<(u8, u32), TouchError>` (flags and counter; steps 1 to 3 and 5 to 9 of `verify` with a raw challenge; `verify` calls it). Also add `l3_vector_flipped_bit_fails`. **If the page cannot be fetched, skip this step and say so in the task report.** The SoftAuthenticator tests still cover the logic.
- [ ] **Step 3:** run the tests; expect FAIL.
- [ ] **Step 4:** implement. Keep `verify.rs` under about 350 lines (§8.3: "about 300 lines on ring").
- [ ] **Step 5:** the tests pass (`cargo test -p saiife-touch --features soft` too); clippy is clean; the Windows check is clean.
- [ ] **Step 6:** commit `feat(touch): one verifier for CTAP2 and WebAuthn assertions, the client Touch trait, and a SoftAuthenticator`.

### Task 4: the credential file, enrolment parsing and offline re-verification (size S)

**Files:** modify `crates/touch/src/store.rs` and `crates/touch/src/verify.rs` (`reverify`).

**Interfaces:**
- Consumes Tasks 1 to 3.
- Produces:
  - `#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct CredentialFile { pub v: u32, pub credentials: Vec<Credential> }`, with `v == 1`. Methods:
    - `pub fn load(path: &Path) -> io::Result<CredentialFile>`: a missing file is the default with `v = 1`. JSON that does not parse, or `v != 1`, is `InvalidData` naming the path;
    - `pub fn save(&self, path: &Path) -> io::Result<()>`: writes `<path>.tmp` with mode 0600 (Unix), `sync_all`, renames it over `path`, then fsyncs the dir (Unix);
    - `pub fn of_uid(&self, uid: u32) -> Vec<Credential>`;
    - `pub fn add(&mut self, c: Credential) -> Result<(), String>`: refuses a duplicate id (`"already enrolled"`), a 17th credential of one uid (`"at most 16 devices per user"`), and a bad label;
    - `pub fn remove(&mut self, id: &[u8]) -> Option<Credential>`;
    - `pub fn set_count(&mut self, id: &[u8], n: u32) -> bool`.
  - `pub fn check_label(l: &str) -> Result<(), String>`: 1 to 64 characters, no control characters, no Unicode format characters (the same set as `approvals::is_format`; copy the ranges with a comment naming the source, since `saiife-touch` must not depend on the daemon).
  - `pub fn credential_from_attestation(auth_data: &[u8], rp_id: &str, label: &str, owner_uid: u32, owner_sid: Option<String>, created: &str) -> Result<Credential, TouchError>`. It needs AT, UP and `rp_id_hash == sha256(rp_id)` (else `Mismatch`), and an attested key (else `Malformed`). `kind = "fido2"`, and `sign_count` comes from the authData.
  - `pub fn reverify(touch: &serde_json::Value, key: &CoseKey) -> Result<(), TouchError>`: what an auditor runs on an audit `touch` object and the `public_key` of its `touch_enrolled` record. It checks:
    1. `challenge == sha256(preimage)`;
    2. the last 32 bytes of the preimage `== sha256(action)`;
    3. for fido2, `client_data_hash == sha256(challenge)`; for webauthn, `client_data_hash == sha256(client_data)`, and its `challenge` is `base64url(challenge)`;
    4. the signature over `auth_data ‖ client_data_hash`.

- [ ] **Step 1: failing tests:**
  - `file_round_trip`: add two credentials (uids 1000 and 1001), save, and load equal; `of_uid(1000).len() == 1`; the file mode is `0o600` (`#[cfg(unix)]`); no `.tmp` is left;
  - `missing_file_is_empty` and `bad_file_is_invalid_data`: the latter for `{`, `{"v":2,"credentials":[]}`, and an unknown key;
  - `add_limits`: a duplicate id, the 17th device of uid 1000, the labels `""`, 65 chars, `"a\u{202e}b"` and `"a\nb"` are each refused;
  - `from_attestation`: `credential_from_attestation(&soft.enrol(&req)?, LOCAL_RP_ID, "yubikey", 1000, None, ts)` gives a credential whose `public_key == soft.public_key()` and `id == soft.credential_id()`. A wrong `rp_id` gives `Mismatch`; authData without AT gives `Malformed`;
  - `reverify_from_audit`: `reverify(&verify(..)?.to_audit(), &soft.public_key())` is `Ok` for both fido2 and webauthn. Changing `action`, `preimage`, `signature` or `auth_data` in the JSON makes it `Err`.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean; the Windows check is clean.
- [ ] **Step 5:** commit `feat(touch): the credential file, enrolment from attestation data, and offline re-verification for auditors`.
- [ ] **Step 6 (merge point 26a):** run the gates on `saiife-touch` (see Finish), then report "26a ready". The coordinator merges Tasks 1 to 4 to v3-dev, and plans 27 and 28 start from there.

### Task 5: touch marks in the policy, and allow-to-ask in the broker (size M)

**Files:**
- Modify `crates/policy/src/service.rs` (`ServiceCfg`, at `:11-42`; `SecretCfg`, at `:196-198`).
- Create `crates/policy/src/touch.rs`, and modify `crates/policy/src/lib.rs` (`pub mod touch;`).
- Modify `crates/broker/src/pipeline.rs:918-923`.
- Docs: `docs/approvals.md` (a "Touch marks" section with the three keys and one example each).

**Interfaces:**
- Consumes nothing from `saiife-touch`: the policy crate stays light, and classes are `&'static str` here.
- Produces:
  - `ServiceCfg`:
    - `#[serde(default, skip_serializing_if = "Vec::is_empty")] pub deploy: Vec<String>`, capability patterns matched like `ask`, broadly (`capability::matches_with(p, cap, true)`);
    - `#[serde(default, skip_serializing_if = "std::ops::Not::not")] pub real_system: bool`.
  - `SecretCfg`: `#[serde(default, skip_serializing_if = "std::ops::Not::not")] pub sensitive: bool`.
  - `pub fn class_for(cfg: &SystemConfig, service: &str, cap: &Capability) -> Option<&'static str>` in `touch.rs`. `cfg` is environment-applied. It returns the first that holds:
    1. a `deploy` pattern matches: `"deploy"`;
    2. the service's `secret` names a `[secrets.<s>]` with `sensitive`: `"secret:sensitive"`;
    3. `real_system`: `"egress:external"`.

    An unknown service is `None`.
  - `pipeline.rs`: the `Verdict::Allow` arm becomes `stage == Stage::New && saiife_policy::touch::class_for(cfg, &call.service, &cap).is_some()`, with a comment citing §8.2.

- [ ] **Step 1: failing tests** (unit tests in `touch.rs`, plus `crates/broker` pipeline unit tests next to the existing allow and ask cases):
  - `marks_parse`: a config with `[services.erp] deploy = ["deploy:*"]`, `real_system = true` and `[secrets.k] sensitive = true` loads; `[services.erp] deplyo = []` is a load error;
  - `class_order`: `deploy:run` gives `"deploy"`; `orders:read` on a service with secret `k` (sensitive) gives `"secret:sensitive"`; `real_system` alone gives `"egress:external"`; none gives `None`;
  - `env_secret_counts`: with `[environments.prod.services.erp] secret = "k"` and `k` sensitive, `class_for(&apply(&cfg, "prod")?, …)` gives `"secret:sensitive"`, and `class_for` on the base config gives `None`;
  - `env_cannot_set_marks`: `[environments.prod.services.erp] real_system = false` is a load error;
  - `policy_hash_unchanged_without_marks` (Review Focus 5): `policy_hash(effective_policy(..))` of a fixture config without marks equals the value it had before this task (copy the expected hash from a run on the parent commit into the test, with a comment saying so);
  - `allowed_marked_call_asks` (broker): with `allow = ["deploy:*"]` and `deploy = ["deploy:*"]`, a `Stage::New` call gives `Outcome::Pending { .. }` and the mock upstream sees nothing; the same call on an unmarked service gives `Outcome::Done`;
  - `approved_marked_call_sends` (broker): `Stage::Approved` of the same call sends.
- [ ] **Step 2:** run `cargo test -p saiife-policy -p saiife-broker`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo tree -e normal -p saiife-policy | grep -c tokio` prints `0`; clippy is clean.
- [ ] **Step 5:** commit `feat(policy): touch marks (deploy, real_system, sensitive secrets); a marked call always asks`.

### Task 6: the request's touch class, the action record of a request, refusals and the audit field (size M)

**Files:**
- Modify `crates/daemon/Cargo.toml` (deps per Global Constraints).
- Modify `crates/daemon/src/approvals.rs`:
  - `Request` (`:102-173`): add the field;
  - `NewRequest` (`:177-200`): add the field;
  - store create: copy it;
  - add `action_record` and `record_with_touch` after `reauth_detail` (`:393-400`).
- Modify `crates/daemon/src/approvers.rs` (`Refusal` at `:27-41`, `rule()` at `:45-56`, `Display` at `:58-80`).
- Modify every `NewRequest {` literal: `approval_ops.rs:160`, `:215`, `:1142`, `:2006`, `:2147`, and `approvals.rs:1123`, plus any other that `cargo build` names.

**Interfaces:**
- Consumes `saiife_touch::{ActionRecord, TouchClass, TouchError, TouchEvidence}` and `saiife_policy::touch::class_for` (Task 5).
- Produces:
  - `Request.touch_class: Option<String>` and `NewRequest.touch_class: Option<String>`, with `#[serde(default, skip_serializing_if = "Option::is_none")]` on the `Request` field. The store copies it, so it shows in `approval.list` and `approval.show` through `item()`.
  - In `approval_ops.rs:147` `create` (connector), `touch_class = class_for(&env-applied system config, service, &Capability::parse(capability))`, mapped to `String`. Every other create site sets `None`. Step 3 boxes set `land` and `push_protected` themselves.
  - `pub fn action_record(r: &Request, class: TouchClass, instance_id: [u8; 16], nonce: [u8; 32], expires_at: u64) -> ActionRecord` in `approvals.rs`:
    - `summary = reauth_detail(r)`;
    - `request_id = r.id`;
    - `fields`: always `type` and `project`;
    - connector and MCP: also `service`, `operation`, `capability`, `env` (or `env_base = "true"`), `body_sha256`, `body_truncated`, `amount` (`"<minor> <currency>"`), and `param.<k>` for each masked param;
    - command: also `input`, `scope` and `ask_rule`;
    - absent options are omitted, never `""`.
  - `Refusal::{TouchFailed(String), TouchUnavailable(String), TouchMismatch(String)}`, with `rule()` = `touch_failed`, `touch_unavailable`, `touch_mismatch`, and `Display` = `touch failed: {d}`, `touch unavailable: {d}`, `touch mismatch: {d}`. Also `impl From<TouchError> for Refusal`, by `e.rule()` with `d = e.to_string()`.
  - `pub fn record_with_touch(mut rec: Record, ev: &TouchEvidence) -> Record`: `rec.extra.insert("touch".into(), ev.to_audit())`.

- [ ] **Step 1: failing tests:**
  - `old_request_file_loads` (Review Focus 5): a request JSON from before this task (no `touch_class`) deserialises with `touch_class == None`, and serialises back without the key;
  - `action_record_fields`: a connector request with env `prod`, two params and a body hash gives the exact `fields` map (assert the whole `BTreeMap`); a command request gives `type`, `project`, `input`, `scope`, `ask_rule`; `summary == reauth_detail(r)`;
  - `action_record_tracks_the_request`: changing `body_sha256`, `env`, a param, or `id` changes `challenge(action_record(..))`; changing `note` or `state` does not;
  - `touch_refusal_rules`: `Refusal::from(TouchError::UnknownCredential).rule() == "touch_mismatch"`; `Expired` gives `"touch_failed"`; `Unavailable` gives `"touch_unavailable"`; Display `touch mismatch: this device is not enrolled for you`;
  - `connector_create_sets_the_class` (`approval_ops` tests, the `ctx` builder already used there): a call to a `deploy`-marked operation stores `touch_class == Some("deploy")`; an unmarked one stores `None`;
  - `record_with_touch_adds_one_key`: the record's `extra["touch"]` equals `ev.to_audit()`, and every other key is unchanged.
- [ ] **Step 2:** run `cargo test -p saiife-daemon -j 4 -- --test-threads=4 approvals approvers approval_ops`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean; `bash scripts/check-windows.sh -p saiife-daemon` is clean.
- [ ] **Step 5:** commit `feat(daemon): touch classes on approval requests, the action record of a request, touch refusals`.

### Task 7: the daemon's touch state, op names and Ctx wiring (size M)

**Files:**
- Create `crates/daemon/src/touch.rs` and `crates/daemon/src/touch_ops.rs` (with `handle` dispatching to two stubs, `approve_ops` and `admin_ops`, which answer `unknown_op` until Tasks 8 and 9).
- Modify `crates/daemon/src/lib.rs` (`pub mod touch; pub mod touch_ops;`, in alphabetical order next to `tokens`).
- Modify `crates/daemon/src/ops.rs`:
  - add `pub touch: Arc<crate::touch::TouchState>` to `Ctx` (next to `reauth` at `:366`);
  - add `pub touch: Arc<crate::touch::TouchState>` to `CtxInit` (`:401-434`), opened in `minimal` (`:442`) under `state_dir`;
  - copy it in `Ctx::new` (`:666-716`);
  - add the dispatch arm in `dispatch_conn` (`:1172-1199`).
- Modify `crates/daemon/src/start.rs`: open it next to the grants (`:1006`), and add `("touch_unreadable", …)` to the notes (`:1104-1109`).
- Modify `crates/ipc/src/msg.rs`: the op constants, each with a doc comment of its args and answer, in the style of `:44-66`.
- Every other `CtxInit {` literal (`mcp_ops/tests.rs:244`, `ops.rs:1550`, `cli/tests/approvals_cmd.rs`, …) gets `touch` (most through `..CtxInit::minimal`).

**Interfaces:**
- Consumes `saiife_touch::{ActionRecord, Assertion, Credential, CredentialFile, TouchClass, TouchError, TouchEvidence, verify, challenge, LOCAL_RP_ID, CHALLENGE_TTL_SECS}`.
- Produces:
  - `msg.rs`:
    - `OP_TOUCH_BEGIN = "touch.begin"`: `{purpose: "approve", request} | {purpose: "enrol", label} | {purpose: "remove", credential} | {purpose: "test"}`, answered by `TouchRequest` + `{expires_at, class}`; for `enrol`, `EnrolRequest` + `{touch?: TouchRequest}`;
    - `OP_TOUCH_ENROL = "touch.enrol"`, `OP_TOUCH_REMOVE = "touch.remove"`, `OP_TOUCH_LIST = "touch.list"`, `OP_TOUCH_CHECK = "touch.check"` (Task 9 documents their args);
    - `approval.decide` gains the optional `touch` (an `Assertion` JSON); update its doc at `:49-57`.
  - `touch.rs`:
    - `#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)] pub enum IssueKey { Approve(u64), Enrol(u32), Remove(u32), Test(u32) }`. The uid in the last three is the peer's.
    - `pub struct Issued { pub uid: u32, pub class: TouchClass, pub nonce: [u8; 32], pub expires_at: u64, pub summary: String, pub fields: BTreeMap<String, String> }`.
    - `pub struct TouchState`. It holds the dir `<state>/state/touch` (0700), `instance_id: [u8; 16]`, `creds: Mutex<CredentialFile>`, and `issued: Mutex<BTreeMap<IssueKey, Issued>>`.
    - `pub fn open(state_dir: &Path) -> (TouchState, Option<String>)`:
      - it creates the dir;
      - it reads or makes `instance_id` (16 bytes from `ring::rand::SystemRandom`, written 0600 the first time);
      - it loads `credentials.json`;
      - an unreadable credentials file gives **no credentials** (every touch is `touch_unavailable`, so it fails closed) and `Some(why)`.
    - `pub fn instance_id(&self) -> [u8; 16]`, `pub fn credentials_of(&self, uid: u32) -> Vec<Credential>`, `pub fn all(&self) -> Vec<Credential>`.
    - `pub fn issue(&self, key: IssueKey, uid: u32, class: TouchClass, summary: String, fields: BTreeMap<String, String>, now: u64) -> Result<Issued, String>`:
      - it drops expired entries first;
      - it replaces an entry with the same key;
      - it refuses a 33rd live entry (`"too many touches in progress"`) or a 5th of one uid;
      - the nonce is 32 random bytes, and `expires_at = now + CHALLENGE_TTL_SECS`.
    - `pub fn consume(&self, key: &IssueKey, uid: u32, build: impl FnOnce(&Issued) -> ActionRecord, asr: &Assertion, rp_id: &str, now: u64) -> Result<(TouchEvidence, ActionRecord), TouchError>`, in this order:
      1. it **removes** the entry, which burns it whatever the outcome; a missing entry is `Expired`, and `entry.uid != uid` is `Mismatch` (the entry stays burned);
      2. it builds the record;
      3. it calls `verify(&self.credentials_of(uid), …)`;
      4. on success, it saves the new `sign_count` with `set_count` and `save`. A save failure is `Unavailable`, and the approval does not happen (fail closed).
    - `pub fn add(&self, c: Credential) -> Result<(), String>` and `pub fn remove(&self, id: &[u8]) -> Result<Option<Credential>, String>` save immediately.
  - `touch_ops.rs`: `pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value`. It runs every file-touching call through `tokio::task::spawn_blocking`, as `approval_ops::on_store` does.
  - `pub fn unix_now() -> u64` in `touch.rs`, from `crate::import_backup::now()`, so tests that fake the clock there also fake it here.

- [ ] **Step 1: failing tests** (unit tests in `touch.rs`, with a tempdir and a `SoftAuthenticator`):
  - `instance_id_is_stable`: two `open`s of the same dir give the same id; another dir gives another;
  - `unreadable_credentials_fail_closed`: `credentials.json` = `{` gives `Some(why)` and `credentials_of(any).is_empty()`;
  - `issue_caps`: the 5th live issue of uid 1000 is refused; after 300 s (`now + 301`) the old ones are dropped, and a new issue works; the 33rd over 9 uids is refused;
  - `consume_burns_even_on_failure`: a bad signature gives `BadSignature`, and the same key's second `consume` gives `Expired`;
  - `consume_checks_the_uid`: an entry issued to uid 1000 and consumed as 1001 is `Mismatch`;
  - `consume_saves_the_counter`: after a good consume, a fresh `open` of the dir shows `sign_count == 1`;
  - `ops_constants_documented`: (ipc) `OP_TOUCH_BEGIN == "touch.begin"`, and the other four.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo test -p saiife-daemon -j 4 -- --test-threads=4` is green (every `CtxInit` literal compiles); `cargo test -p saiife --no-run` builds; the Windows check is clean.
- [ ] **Step 5:** commit `feat(daemon): touch state (instance id, credentials, single-use challenges) and the touch ops' names`.

### Task 8: a touch for an approval (size L)

**Files:**
- Modify `crates/daemon/src/touch_ops.rs` (the `approve` purpose of `touch.begin`).
- Modify `crates/daemon/src/approval_ops.rs`:
  - `show` (`:484-499`): add `touch_class`;
  - `decide` (`:567-762`): the hook after `:688-690`, and the `touch` key in the approved record at `:732-735`.

**Interfaces:**
- Consumes `TouchState` (Task 7), and `action_record`, `record_with_touch`, the `Refusal` touch variants and `Request.touch_class` (Task 6).
- Produces:
  - `pub(crate) fn effective_class(ctx: &Ctx, r: &Request) -> Option<TouchClass>`: `TouchClass::stronger(stored, now)` (D8). `now` is `class_for` under the current policy, with `r.env` applied through `saiife_policy::environment::apply`; a missing policy or an apply error counts as no class *now*, so the stored class still counts.
  - `approval.show`'s `item` gets `"touch_class": <name>` whenever `effective_class` is `Some`, replacing the stored value.
  - `touch.begin {purpose: "approve", request}`:
    - the request must be visible to the peer (`visible`, an unknown id answers as `approval_ops::unknown`) and pending;
    - the peer must be an approver (`is_approver`), or the own user in personal mode, else `forbidden`;
    - it must have an `effective_class`, else `bad_request` `"request #<id> needs no touch"`;
    - the peer must have at least one credential, else `forbidden` with rule `touch_unavailable` (an `approval`/`refused` record, as `refuse` writes);
    - then it calls `issue(IssueKey::Approve(rid), …)` with `summary`/`fields` from `action_record`, and answers `TouchRequest { rp_id: LOCAL_RP_ID, challenge, allow: the peer's ids, uv: class.needs_uv(), summary, short_code }` + `{expires_at, class}`.
  - **The decide hook** (approve only; a reject or a withdrawal never needs a touch). After the refusal check, when `effective_class(r)` is `Some(class)`:
    - no `touch` arg: refuse with `TouchUnavailable("request #<id> needs a touch (<class>) from an enrolled device")`;
    - a `touch` arg that does not parse as `Assertion`: `bad_request`;
    - otherwise `ctx.touch.consume(&IssueKey::Approve(rid), peer.uid, |i| action_record(&r, class, ctx.touch.instance_id(), i.nonce, i.expires_at), &asr, LOCAL_RP_ID, unix_now())` on a blocking thread. The record is built from **the `r` that decide just loaded**, never from the client.
    - An error is `refuse(…, Refusal::from(e))`, and the request stays pending.
    - On success the evidence is kept, and the `approved` record (`:732-735`) is `record_with_touch(decided_record(…), &ev)`.
    - In personal mode the uid is `peer.uid`, which is the own uid there.

- [ ] **Step 1: failing tests** (`approval_ops` tests: a personal-mode `ctx`, as the existing tests build one, with a `deploy`-marked connector request, a `SoftAuthenticator` credential added for the own uid through `ctx.touch.add`, and `touch.begin`/`approval.decide` sent through `dispatch_conn`):
  - `marked_request_needs_a_touch`: `decide approve` without `touch` gives `forbidden` with rule `touch_unavailable`, and the request is still `pending`;
  - `touch_approves_and_is_recorded`: `begin`, then `soft.request(&answer)`, then `decide {touch}` gives `approved`. The last audit record's `extra["touch"]["cred_id"]` is the soft key's id, `["uv"] == true` and `["via"] == "local"`. `reverify(&rec.extra["touch"], &soft.public_key())` is `Ok`;
  - `same_assertion_twice_is_refused` (Review Focus 3):
    1. `begin` #1, then `decide` #1 with the assertion's signature flipped: refused with `touch_failed`, and the challenge is burned;
    2. `decide` #1 with the untampered assertion: refused with `touch_failed` (`Expired`);
    3. `begin` #1 again (a new nonce) and the old assertion: refused with `touch_mismatch`.

    The mock upstream saw no call, and #1 is still pending;
  - `restart_forgets_challenges` (Review Focus 3): `begin`, then a new `TouchState::open` on the same dir swapped into a new ctx, then `decide {touch}` is refused with `touch_failed`;
  - `touch_for_request_a_cannot_approve_b` (Review Focus 2): `begin` for #1 and an assertion over #1's challenge, sent as `decide` #2 (after `begin` #2), is refused with `touch_mismatch`;
  - `challenge_of_another_uid_is_refused` (Review Focus 2): a locked-mode ctx with two approvers (uid 4242 and 4343, the `FixedDirectory` of `approval_ops.rs:2074-2110`). `begin` as 4242 and `decide` as 4343 with 4242's assertion is refused with `touch_mismatch`;
  - `uv_missing_for_deploy`: `soft.uv = false` is refused with `touch_failed`, and the message names user verification;
  - `no_device_is_unavailable`: no credentials, then `begin` gives rule `touch_unavailable`;
  - `reject_needs_no_touch`: `decide reject` of a marked request is `rejected` with no `touch` key;
  - `reload_removing_a_mark_keeps_the_touch` (Review Focus 4): a request created under a `deploy` mark, then a policy swapped for one without it (`ctx.policy` replaced), then `decide` without `touch` is still refused with `touch_unavailable`;
  - `mark_added_after_ask_needs_touch`: a request created with no mark, then a policy with the mark: `show` gives `touch_class: "deploy"`, and `decide` without `touch` is refused;
  - `unmarked_request_unchanged`: an unmarked request approves exactly as before, with no `touch` key in the record (a regression guard).
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the whole daemon suite is green; `cargo test -p saiife -j 4 -- --test-threads=4 approvals` is green (the CLI tests use `approval.decide`).
- [ ] **Step 5:** commit `feat(daemon): touch-class approvals need an action-bound touch; the evidence goes in the audit record`.

### Task 9: enrol, remove, list and test devices, and audit compatibility (size M)

**Files:**
- Modify `crates/daemon/src/touch_ops.rs` (the purposes `enrol`, `remove`, `test`, and the ops `touch.enrol`, `touch.remove`, `touch.list`, `touch.check`).
- Create `crates/daemon/tests/touch_audit.rs`.

**Interfaces:**
- Consumes Tasks 4, 6 and 7.
- Produces (every op is **machine only**: the local socket, never the link of plan 29):
  - **Who may:**
    - `enrol`, `remove`, `list` and `test`: root, an `[admin] groups` member (`ctx.peer_is_admin`), or an approver (`approval_ops::is_approver`); in personal mode, the own user. Anyone else gets `forbidden`.
    - A peer acts on **its own uid's** devices. Root and admins may `list` all devices, and may `remove --host` any device (below).
  - `touch.begin {purpose: "enrol", label}`:
    - `check_label` first;
    - `issue(Enrol(uid), uid, TouchClass::Enrol, "enrol <label>", {label, uid}, now)`;
    - the answer is `EnrolRequest { rp_id: LOCAL_RP_ID, rp_name: RP_NAME, user_id: uid.to_be_bytes() (4 bytes), user_name: <daemon's name for the uid>, challenge, exclude: every enrolled id }`, plus `touch: TouchRequest` for the new key (`allow: []`, `uv: true`), plus `approve_with: TouchRequest` over the same challenge, allowing the uid's existing ids, **only when the uid already has a device** (D10).
  - `touch.enrol {label, auth_data, proof, approval?}` (bytes base64url; `proof` and `approval` are `Assertion` JSON):
    1. `take` the `Enrol(uid)` entry (burned in every case);
    2. `credential_from_attestation(auth_data, LOCAL_RP_ID, label, uid, peer.sid, ts(now))`;
    3. `verify(&[new], record, proof)`, which must be UV (`Enrol.needs_uv()`);
    4. with existing devices, `verify(&credentials_of(uid), record, approval)` (a missing `approval` is `touch_unavailable`);
    5. `add`.

    Use a `consume`-like helper that verifies two assertions against one taken entry. Add `TouchState::take(&self, key, uid) -> Result<Issued, TouchError>` for that. It removes the entry; missing is `Expired`, and another uid is `Mismatch`.

    The record is `kind = "touch"`, `action = "touch_enrolled"`, with `cred_id`, `label`, `alg`, `public_key` (base64url COSE), `aaguid`, `by_uid` (and `by_sid`), and `approved_by` (the approving credential's id, or `"host"` for the first device). An error writes `action = "touch_failed"` with `rule` and `reason`, and answers `forbidden` with the rule.
  - `touch.begin {purpose: "remove", credential}` and `touch.remove {credential, assertion?, host?: bool}`:
    - an assertion over a `Remove(uid)` challenge from **any** of the uid's devices (the one being removed included) removes it;
    - `host: true` needs a root peer (uid 0), skips the touch, and records `approved_by = "root"`. This is recovery when every device is lost (owner check 4);
    - an unknown id is `bad_request`;
    - the record has `action = "touch_removed"`, `cred_id`, `label` and `approved_by`.
  - `touch.list {all?: bool}` gives `{credentials: [{id, label, kind, alg, rp_id, created, sign_count, owner_uid}]}`. The public key is never listed, though it is no secret: keep the output small.
  - `touch.begin {purpose: "test"}` and `touch.check {assertion}` verify against a `Test(uid)` challenge and save the counter. The answer is `{ok: true, label, uv, sign_count}`; no audit record is written.
  - Records are built with `ctx.record("touch", …)`, the same base `approval_record` uses (`ops.rs:763-766`).

- [ ] **Step 1: failing tests:**
  - unit tests in `touch_ops.rs` (a personal-mode ctx and a `SoftAuthenticator`):
    - `first_enrol_needs_host_only`: `begin enrol "key"`, `soft.enrol`, `soft.request(touch)`, then `touch.enrol` gives ok. `touch.list` shows one device. The record is `touch_enrolled` with `approved_by == "host"` and `public_key` equal to `soft.public_key().to_cose()` in base64url;
    - `second_enrol_needs_an_existing_device`: with `key1` enrolled, enrolling `key2` without `approval` is refused with `touch_unavailable` and a `touch_failed` record. With `key1`'s assertion over `approve_with` it is ok, and `approved_by == key1's id`;
    - `enrol_without_uv_is_refused`: `soft.uv = false` is refused with `touch_failed` and names user verification;
    - `enrol_replay_is_refused`: the same `touch.enrol` body twice: the second gives `touch_failed` (entry burned);
    - `duplicate_device_is_refused`: enrolling the same soft key twice gives `forbidden` `"already enrolled"`;
    - `remove_with_touch` and `remove_by_host_root_only`: a non-root `host: true` is `forbidden`; with `touch_removed`, `list` is empty;
    - `test_touch`: `touch.check` gives `ok`, and the counter rises;
    - `non_approver_is_forbidden`: a locked ctx peer that is neither an approver nor an admin gets `forbidden` for each op;
  - `tests/touch_audit.rs` (an integration test with `saiife_audit::chain::append_chained` on a tempdir):
    - `old_chain_with_touch_records_verifies` (Review Focus 5): append three plain v2 approval records, then a `touch_enrolled` record and an `approved` record carrying `extra["touch"]` (built through `saiife_touch` + `record_with_touch`). `saiife_audit::verify::verify(dir).exit_code() == 0`, and the touch object reads back byte-identical;
    - `touch_record_size`: the serialised approved record with `touch` is under 4 KiB.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the whole daemon suite and `cargo test -p saiife-audit` are green.
- [ ] **Step 5:** commit `feat(daemon): enrol, remove, list and test touch devices; signed touch_enrolled and touch_removed records`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent`):
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -j 4 -- -D warnings`;
  - `cargo test -p saiife-touch --features soft`, plus `-p saiife-policy -p saiife-broker -p saiife-daemon -p saiife-audit -p saiife-ipc`, plus `cargo test -p saiife approvals`;
  - `cargo tree -e normal -p saiife-touch -p saiife-policy -p saiife-audit | grep -c tokio` prints `0`;
  - `cargo tree -e normal -p saiife-touch` lists no crate missing from the parent commit's `Cargo.lock` (diff `grep '^name' Cargo.lock` before and after: only `saiife-touch` is new);
  - `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-touch -p saiife-daemon`; `scripts/test-offline.sh`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR into v3-dev. The owner merges.

## Follow-ups (not in this plan)

- MCP servers and command rules as touch classes (`[mcp.<name>] real_system`).
- Persisting a burned-nonce list, if challenges ever outlive a daemon run.
- Verifying packed attestation statements (an AAGUID allow-list for fleets).
- Plan 31: `IssueKey::Web(..)` for browser approvals, and `origins` on WebAuthn credentials at pairing.
