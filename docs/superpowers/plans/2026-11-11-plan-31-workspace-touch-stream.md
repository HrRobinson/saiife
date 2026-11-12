# Plan 31: Workspace touch and terminal stream (W4): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Reconciled 2026-11-12** (outline turned into a full plan against `v3-dev` at `8086dee` with plans 26–29 and 32 merged, plan 30 on `v3-p30` at `c9eed15`, plan 34 on `v3-p34` at `ee5e264`). Changes from the outline:
> 1. Frame execution lives in `crates/daemon/src/workspace_link.rs` (`LATER` `:83`, `HANDLED` `:98`, `execute` `:435`, `act` `:554`, `touch_required` `:505`), not `workspace_ops.rs` (that file holds the machine-side pairing ops).
> 2. `TouchState` caps are plan 26's: 32 live entries in all (`MAX_LIVE`, `crates/daemon/src/touch.rs:27`) and per uid `MAX_PER_UID` (`touch.rs:28`), shared by every `IssueKey`; the outline's "64 open `Web` entries" is dropped. **Owner ruling 2026-11-12:** `MAX_PER_UID` goes from 4 to 8 (Task 2, Step 3a).
> 3. `TouchProof` (`crates/wire/src/frame.rs:38-44`) has no `origin`: the daemon reads it from `clientDataJSON` and checks it against `[workspace] origins` before `verify` (which checks it against the credential's `origins`, `crates/touch/src/verify.rs:182-185`).
> 4. UV: `saiife_touch::verify` already forces UV for every WebAuthn assertion (`verify.rs:296`); a clear UV flag is `TouchError::NotVerified`, rule `touch_failed` (`error.rs:21-27`). The outline's custom message is UI copy only.
> 5. Which record a proof names is decided by the frame's **action**, not by trying three stores in turn: request ids of `workspace.touch.begin`, of `BoxSource::pending_actions` and of v2 approvals are separate number spaces and can collide.
> 6. Pending box actions are verified with `TouchState::verify_counted` (`touch.rs:263`) against the `PendingAction.record`, plus a daemon-side spent-challenge set (passkeys may keep a zero counter, `verify.rs:262-265`).
> 7. Passkey enrolment uses `getAuthenticatorData()` (no CBOR parse; plan 26 keeps `cbor` `pub(crate)`) and `credential_from_attestation` (`store.rs:216`), and the device key signs the attestation so a relay cannot swap it.
> 8. New Task 1: `Ctx.boxes` is still `NoBoxes`/`FakeBoxSource` (`crates/daemon/src/start.rs:1029-1040`); plan 34's `ManagerSource` writes no audit and its spawn hides other boxes' admission changes (plan 34 R22 and final-review note). This plan wires it.
> 9. `TouchClass::Steer` is added here (plan 26's crate has no class for steer, revise or resume; `action.rs:14-23`). Owner-approved 2026-11-12.
> 10. `box.push` and `box.pr` stay in `LATER`: plan 39 gives push a CLI-only path (`box.push.*` control-socket ops) and builds no PR; the Workspace cannot run `git push` as the user.
> 11. Plan 30 R-1 answer shape (`{ok:false,error,rule,message}`, `crates/link/src/local.rs`) is the contract; `wire.js` `readAnswer` (`crates/link/assets/js/wire.js:101-121` on `v3-p30`) drops every other field, so it is widened for `touch` and `short_code` (Task 7).
> 12. Approver check: `approvers::is_approver(cfg, dir, user)` (`crates/daemon/src/approvers.rs:107`), not `:84`; the touch record helper is `approvals::record_with_touch` (`approvals.rs:476`).

> **Owner rulings 2026-11-12 (binding):**
> - The per-user live touch challenge limit is raised from 4 to 8: `const MAX_PER_UID: usize = 4;` at `crates/daemon/src/touch.rs:28` (on `v3-dev`) becomes `8`, in Task 2 (the task that already edits `TouchState`), with its test.
> - Confirmed and approved: Task 1 wires the real box manager into `Ctx.boxes`, with audit at the frame layer through `ManagerSource::with_changes`.
> - Owner-approved contract additions (no longer "flagged"): `TouchClass::Steer` (this plan), `IssueKey::Web` (this plan), `IssueKey::{Land, Push}` (plan 39), `Vmm::image_id` (plan 36, used by plans 35 and 38).

**Goal:** Make the Workspace's Touch-level actions real and add the read-only terminal:
- a WebAuthn passkey is enrolled **with** the browser at pairing (confirmed at the machine), so no remote action ever enrols a device;
- `workspace.touch.begin` issues a challenge bound to the action (§8.3); a Touch frame carries the WebAuthn assertion; the daemon verifies it and runs the action, recording the evidence (`touch.via: "web"`);
- Approve (`box.land`) through `BoxSource::complete`, Revise/Steer/Resume (one touch opens a 10-minute steer window), spawn from a template with secrets or egress, and v2 approvals from the inbox;
- the terminal pane: snapshot + delta frames polled with `box.term.read`, rendered as text, read-only, no OSC 52 or OSC 8;
- the Workspace runs over plan 34's box manager, with every state change audited.

**Architecture:**
- **One verifier, one challenge store.** All signature work goes through plan 26's daemon `TouchState` (`crates/daemon/src/touch.rs`): `issue(IssueKey::Web { device, request_id }, uid, class, summary, fields, now)` and `consume(&key, uid, build, &Assertion::WebAuthn { .. }, rp_id, now)` for actions this plan begins; `verify_counted(uid, &record, &asr, rp_id, now)` for records a box source or the approval store made. Every call runs in `spawn_blocking` (R14 of plan 26).
- **The daemon only accepts actions it created** (§15). A Touch frame's proof names a `request_id`; the record behind it is the daemon's (from `workspace.touch.begin`, from `BoxSource::pending_actions`, or from a v2 approval with a touch class). The frame's action and arguments must match that record; a mismatch is `touch_mismatch`.
- **Which store a proof names follows from the action:** `box.land` → `pending_actions()`; `approval.approve` → the v2 approval store; `box.steer`, `box.revise`, `box.resume`, `box.spawn` → `IssueKey::Web`.
- **Refusals** are the contract's: `touch_failed`, `touch_unavailable`, `touch_mismatch` (`TouchError::rule`, `crates/touch/src/error.rs:21`), plus `touch_required` (plan 29) when no proof and no open steer window.

**Tech Stack:** As plans 28–30; `saiife-touch` (plan 26) with feature `soft` (`SoftAuthenticator`) in tests. No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §8.1, §8.3–§8.6, §9.3, §9.4, §9.5, §9.6, §12, §15. Contract: `v3-step4-6-contract.md`. Ledgers read: plan 26 (R2–R19), 27 (R-J), 28 (R-P*, R-T*, R-F*), 29 (R-P3, R-P5, R-T4a, R-T9b), 30 (R-1, R-2, R-T2a), 34 (R1–R31).

## Contract changes (owner-approved 2026-11-12)

| Item | Change | Why |
|---|---|---|
| `saiife_touch::TouchClass` (`action.rs:14`) | `+ Steer`, name `"steer"`, `needs_uv() == true` | steer, revise and resume have no §8.2 class; owner-approved 2026-11-12 |
| daemon `touch::IssueKey` (`touch.rs:40`) | `+ Web { device: String, request_id: u64 }` | plan 26 reserved it for this plan; plan 39 adds `Land(u64)`, `Push(u64)` to the same enum; all three owner-approved 2026-11-12 |
| daemon `touch::MAX_PER_UID` (`touch.rs:28`) | `4` → `8` | owner ruling 2026-11-12: Workspace, CLI, land and push touches share it |
| `saiife_wire::pair::PairRequest` (`pair.rs:84`) | `+ #[serde(default)] passkey: Option<PasskeyAttestation>` (`deny_unknown_fields` stays) | enrol with the pairing |
| link `POST /api/pair` key list (`local.rs:298`) and hub `pair` message (`hub.rs:853`) | `passkey` allowed as an optional key | they whitelist keys |
| system config | `[workspace] origins = ["http://localhost:47810"]` (`crates/policy/src/system.rs:17-45`, a new `WorkspaceCfg`) | machine-only, like all config |
| `ManagerSource` (plan 34, `crates/boxes/src/source.rs:54`) | `+ fn with_changes(self, Arc<dyn Fn(&[Change]) + Send + Sync>) -> ManagerSource`; `spawn` uses `Manager::spawn_changes` (`manager.rs:318`) | §7.7 every state change audited (plan 34 R22, final-review note) |

**Deviation inherited from plan 26:** the contract's daemon-side `trait Touch` does not exist; `Touch` is a client trait (`crates/touch/src/client.rs:37`) and the daemon side is the concrete `TouchState`. The browser is a client in JavaScript, so this plan implements no Rust `Touch`.

## Global Constraints

- Everything in plans 28–30's Global Constraints (no network, loopback only, `ops::test_ctx` on a tempdir, tokio stays out of wire and touch).
- **Timeouts (§8.6):** browser prompt `timeout: 120000` ms (`saiife_touch::PROMPT_TIMEOUT_SECS` × 1000); challenge valid `CHALLENGE_TTL_SECS = 300` s; steer window `600` s per (device, box). Timeout, error or the wrong passkey all deny.
- **Never a password fallback** (§8.4) and **never a one-click approve link** (§9.6): no URL, notification or email carries anything that approves.
- **Tests never use a real authenticator.** Assertions come from `SoftAuthenticator::assert_webauthn(rp_id, origin, challenge)` (`crates/touch/src/soft.rs:167`) with origin `http://localhost:47810` and rp id `localhost`; credentials from `SoftAuthenticator::web_credential(rp_id, origin, owner_uid)` (`soft.rs:145`). Real phones and keys are the owner's smoke script.
- **Disk:** builds use `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` (plan 30 R-0).
- **Every task** (worktree `.worktrees/p31`, branch `v3-p31` off `v3-dev` after plans 30 and 34 merged):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p31-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$TMPDIR/no-bus"
  cargo test -p <crates touched> -j 4 -- --test-threads=4
  node --test crates/link/assets/tests/
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```
  Remove `$TMPDIR` at the end. Never commit `.superpowers/`. Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Fixed values

| Name | Value |
|---|---|
| passkey create challenge | SHA-256(`"saiife-pair-passkey-v1\n"` ‖ pair_id ASCII ‖ device_pub 65 bytes) |
| passkey device signature | device key, domain `PASSKEY_DOMAIN = b"saiife-pair-passkey-v1 sig\n"`, over pair_id ASCII ‖ credential_id ‖ SHA-256(authenticator_data) ‖ SHA-256(client_data_json) |
| `PasskeyAttestation` | `{credential_id, authenticator_data, client_data_json, device_sig}`, all b64u (`saiife_wire::b64`) |
| create options | `rp: {id: location.hostname, name: "saiife"}`, `user: {id: device id bytes, name: label, displayName: label}`, `pubKeyCredParams: [{type:"public-key", alg:-7}, {type:"public-key", alg:-8}]` (plan 26 verifies ES256 and Ed25519, `verify.rs:194-212`), `authenticatorSelection: {userVerification:"required", residentKey:"preferred"}`, `attestation: "none"`, `timeout: 120000` |
| get options | `{challenge, rpId: location.hostname, allowCredentials: [{type:"public-key", id}], userVerification:"required", timeout:120000}` |
| rp id | the host part of the origin (`localhost` for `http://localhost:<port>`), from config, never from the browser |
| default origins | `["http://localhost:47810"]` (plan 29 default port); with `serve --port N` the owner adds `http://localhost:N` |
| steer window | 600 s per (device id, box id); closed on revoke |
| term poll | at most once per second while the pane is visible |
| `begin` answer | plan 26's `TouchRequest` (`client.rs:11-19`: `rp_id`, `challenge` hex, `allow` b64u list, `uv`, `summary`, `short_code`) + `request_id` (decimal string), `expires_at`, `class` |
| spawn class | `SecretSensitive` when `has_secrets`, else `EgressExternal` (both forced UV by WebAuthn) |
| audit | Touch-level frames: the plan 29 `workspace` record plus `extra.touch = TouchEvidence::to_audit()` (`verify.rs:74`, its `via` is `"web"`); window-covered frames `extra.window = true`; approvals: `approvals::record_for` + `record_with_touch` |

## Review Focus

1. **An assertion for one action used for another**: a `land` touch replayed as `revise`, a touch for box A used on box B, a challenge used twice. Expected: `touch_mismatch`, then the nonce is burned once and a reuse is `touch_failed` (Task 5: `touch_for_other_box_is_mismatch`, `assertion_reuse_is_refused`, `land_proof_on_revise_is_mismatch`).
2. **A passkey without user verification** (UV clear, a security key without PIN). Expected: `touch_failed` (`NotVerified`) for every Workspace touch, the UI says "needs Face ID, fingerprint or PIN" (Task 5: `uv_clear_is_refused`).
3. **Wrong origin or RP ID**: an assertion made for `app.saiife.com` sent to the localhost UI, or an origin not in `[workspace] origins`. Expected: `touch_mismatch` (Task 5: `foreign_origin_is_refused`, `rp_id_of_other_host_is_refused`).
4. **A steer window outlives its purpose**: after revoke, after 600 s, used on another box. Expected: closed at once on revoke; per (device, box) only (Task 6: `steer_window_is_per_box_and_expires`, `revoke_closes_windows`).
5. **A passkey swapped on the way during pairing** (a relay replaces `passkey` with its own credential, keeping the HMAC proof). Expected: the device signature over the attestation fails, the pairing request is refused, no credential is stored (Task 3: `passkey_signed_by_another_key_is_refused`).
6. **Terminal output tries to act**: OSC 52, OSC 8, a drawn "Approve" button, 10 000 lines/s. Expected: inert text; the pane has no controls; at most one read per second (Task 7: node `term render is inert`, `term polls at most once per second`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (Workspace over the manager; daemon `start.rs`, `workspace_link.rs` spawn arm, boxes `source.rs`), Task 2 (contract additions; touch, daemon `touch.rs`, policy, wire `frame.rs` helper).
- **Wave 2:** Task 3 (passkey at pairing; needs 2).
- **Wave 3:** Task 4 (`workspace.touch.begin`; needs 2), then Task 5 (verify; needs 4: both edit `workspace_link.rs`).
- **Wave 4:** Task 6 (the Touch actions; needs 5).
- **Wave 5 (parallel):** Task 7 (browser; needs 4–6's answer shapes), Task 8 (notification, smoke, docs).
- Serial in one worktree (plan 30 R-5): one implementer at a time; waves only say what may be reordered.

---

### Task 1: the Workspace over plan 34's box manager (size M)

**Files:** Modify `crates/daemon/src/start.rs:1029-1040` (`Ctx.boxes`), `crates/boxes/src/source.rs` (`with_changes`, `spawn` via `spawn_changes`), `crates/daemon/src/box_ops.rs` (make `write_tick_records` `pub(crate)` and take `via`), `crates/daemon/src/workspace_link.rs` (records for source-reported changes); create `crates/daemon/tests/workspace_boxes.rs`.

**Interfaces:**
- Consumes: plan 34 `ManagerSource::new(mgr, owner: Option<u32>)` (`source.rs:54`), `Manager::spawn_changes(&SpawnArgs) -> Result<(BoxRecord, Vec<Change>), BoxError>` (`manager.rs:318`), `box_ops::Built` (`box_ops.rs:201`), `Ctx.box_manager: Option<Arc<Manager>>` (`ops.rs:396` on `v3-p34`).
- Produces:
```rust
// boxes source.rs
pub type ChangeSink = Arc<dyn Fn(&[Change]) + Send + Sync>;
impl ManagerSource { pub fn with_changes(self, sink: ChangeSink) -> ManagerSource; }
// daemon box_ops.rs
pub(crate) async fn write_change_records(ctx: &Ctx, changes: Vec<(Change, Option<String>)>, action: &str, via: &str);   // generalises write_tick_records (box_ops.rs:383)
```
- `start.rs`: when `box_manager` is `Some(m)`, `Ctx.boxes = ManagerSource::new(m, None).with_changes(sink)` (locked mode: `owner = None` is refused for `spawn` by plan 34, `source.rs:231-235`); personal mode `owner = Some(daemon uid)`. `fake-boxes` + `SAIIFE_WORKSPACE_FAKE_BOXES=1` keeps `FakeBoxSource::demo` and wins (test builds only).
- `sink` hands each batch to a tokio task that writes one `box` record per change with `action = "tick"`, `via = "workspace"`, `reason = why` (plan 34 R22's shape) through `write_change_records`. `ManagerSource::spawn` calls `spawn_changes` and passes every change except the new box's own to the sink (the frame's own `workspace` record covers the new box).
- **Locked-mode spawn:** `ManagerSource` with `owner = None` refuses spawn (`Unavailable("Workspace spawn in locked mode needs the device owner")`). The frame layer knows the owner: `act`'s `box.spawn` arm builds a per-call `ManagerSource::new(m, Some(owner_uid)).with_changes(sink)` from `ctx.box_manager` when it is `Some`, else uses `ctx.boxes`.

- [ ] **Step 1: Write the failing tests** (`tests/workspace_boxes.rs`, `--features fake-vmm`, `SAIIFE_BOX_FAKE_VMM=1`, `SAIIFE_BOX_FAKE_SLOTS=1`, a paired `TestDevice`): `overview_comes_from_the_manager` (spawn through the control socket, then `box.overview` over `link.sock` lists it), `remote_spawn_names_the_owner` (locked `test_ctx`: frame `box.spawn` of `claude-code` → the box's `owner_uid` is the device owner's uid), `admission_of_other_boxes_is_audited` (slots 1: box A running, B queued; frame `box.stop` on A → the tick admits B; a frame `box.spawn` that admits a queue head writes one `box` record with `action: "tick"`, `via: "workspace"` for B), `fake_boxes_env_still_wins` (`fake-boxes` build with `SAIIFE_WORKSPACE_FAKE_BOXES=1` → the demo's four boxes); boxes unit `with_changes_receives_spawn_admissions`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm,fake-boxes --test workspace_boxes` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; plan 29's `tests/workspace_link.rs` unchanged.
- [ ] **Step 5: Commit** `feat(daemon): the Workspace runs over the box manager, every admission audited`.

---

### Task 2: contract additions: `TouchClass::Steer`, `IssueKey::Web`, `[workspace] origins`, the web assertion (size S)

**Files:** Modify `crates/touch/src/action.rs` (`Steer`), `crates/daemon/src/touch.rs:28` (`MAX_PER_UID` 4 → 8), `crates/daemon/src/touch.rs:40` (`IssueKey::Web`), `crates/policy/src/system.rs` (`WorkspaceCfg`), `crates/wire/src/pair.rs` (`PasskeyAttestation`, `PASSKEY_DOMAIN`); create `crates/daemon/src/workspace_touch.rs` (`pub mod` in `lib.rs`).

**Interfaces (Produces):**
```rust
// touch action.rs: Steer => "steer", from_name("steer"), needs_uv() true
// daemon touch.rs
pub enum IssueKey { Approve(u64), Enrol(u32), Remove(u32), Test(u32), Web { device: String, request_id: u64 } }
// policy system.rs
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)] #[serde(deny_unknown_fields)]
pub struct WorkspaceCfg { #[serde(default = "default_origins")] pub origins: Vec<String> }   // SystemConfig gains #[serde(default)] pub workspace: WorkspaceCfg
// each origin: "http://localhost:<1..=65535>" or "https://<host>[:port]" with a lowercase DNS host; no path, query or trailing slash
// wire pair.rs
pub const PASSKEY_DOMAIN: &[u8] = b"saiife-pair-passkey-v1 sig\n";
pub const PASSKEY_CHALLENGE_DOMAIN: &[u8] = b"saiife-pair-passkey-v1\n";
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] #[serde(deny_unknown_fields)]
pub struct PasskeyAttestation { pub credential_id: String, pub authenticator_data: String, pub client_data_json: String, pub device_sig: String }
pub fn passkey_challenge(pair_id: &str, device_pub: &[u8; 65]) -> [u8; 32];
pub fn passkey_sig_msg(pair_id: &str, p: &PasskeyAttestation) -> Result<Vec<u8>, WireError>;   // pair_id ‖ cred_id ‖ sha256(ad) ‖ sha256(cdj), decoded
// daemon workspace_touch.rs
pub fn origins(ctx: &Ctx) -> Vec<String>;                         // ctx.policy().system.map(|s| s.workspace.origins), else the default
pub fn rp_id_of(origin: &str) -> Option<String>;                  // "http://localhost:47810" -> "localhost"
pub fn web_assertion(p: &saiife_wire::frame::TouchProof, origins: &[String]) -> Result<(saiife_touch::Assertion, String /* origin */), saiife_touch::TouchError>;
```
`web_assertion`: decode the four b64u fields (`Malformed` on failure); parse `client_data_json` as a JSON object and read `origin` (a string, else `Malformed`); `origin ∉ origins` → `Mismatch`; build `Assertion::WebAuthn { credential_id, auth_data, signature, client_data_json, origin }`. The rest (type, challenge, crossOrigin, rp id hash, UV, counter) is `verify`'s.

- [ ] **Step 1: Write the failing tests:** touch `steer_class_roundtrip` (`name`, `from_name`, serde, `needs_uv`), `stronger_with_steer`; daemon `web_key_is_distinct_per_device` (two `Web` keys with the same request id and different devices both issue), `web_entries_share_the_caps` (eight `Web` entries for one uid, the ninth `issue` errs "too many touches in progress"); policy `workspace_origins_default_and_parse` (no section → the default; `["http://localhost:9000"]` ok; `"http://evil.test"`, `"http://localhost:9000/"`, `"javascript:x"` refused at load), `workspace_unknown_key_is_refused`; wire `passkey_challenge_vector` (fixed pair id and key → pinned hex in `tests/vectors/pair-v1.json` as a new key `passkey_challenge_hex`), `passkey_sig_msg_layout`, `pair_request_without_passkey_still_parses` (plan 28's frozen pair vector unchanged); daemon unit `web_assertion_rules` (bad b64, non-object JSON, missing origin, origin outside the list → `Mismatch`, a good one keeps every byte).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3a: Raise the per-user limit (owner ruling 2026-11-12).** `crates/daemon/src/touch.rs:28`: `const MAX_PER_UID: usize = 8;` (doc line above unchanged: "Live challenges in all, and per uid"). Update plan 26's tests in the same file: `issue_caps` (`touch.rs:363`) issues `Approve(0..8)` for uid 1000 and asserts `Approve(8)` errs; its global part fills 32 as 4 uids × 8 and asserts the 33rd (a fifth uid) errs `"too many touches in progress"`; the cap-replace part of the test at `touch.rs:515-519` issues `Approve(20..28)` for uid 3000 before re-issuing `Approve(20)`, and fills 32 as 4 uids × 8. New test `per_uid_cap_is_eight` (8 live for one uid ok, the 9th refused, another uid still issues). `cargo test -p saiife-daemon touch::` → PASS.
- [ ] **Step 3b: Implement** the rest. Grep the tree for every `match` on `TouchClass` and add the `Steer` arm (strictest handling where a class decides an approval, as `approval_ops.rs:557`'s `strictest`). **Step 4: Run** → PASS; `bash scripts/check-windows.sh -p saiife-touch -p saiife-policy -p saiife-wire`.
- [ ] **Step 5: Commit** `feat(touch,wire,policy): steer class, web issue key, workspace origins, passkey attestation types`.

---

### Task 3: enrol a passkey with the pairing (size M)

**Files:** Modify `crates/daemon/src/workspace.rs` (`finish_pair` `:250`, `confirm_pair` `:283`), `crates/daemon/src/workspace_link.rs` (`pair_finish` `:249`), `crates/daemon/src/workspace_ops.rs` (`confirm` `:283`), `crates/link/src/local.rs:298`, `crates/link/src/hub.rs:853`, `crates/link/assets/js/pairing.js`; create `crates/link/assets/tests/passkey.test.mjs`.

**Interfaces:**
```rust
// daemon workspace.rs
impl Workspace {
  /// As finish_pair, plus a verified passkey held with the offer until confirm.
  pub fn finish_pair_with(&self, req: &PairRequest, passkey: Option<Credential>, now: u64) -> Result<(Device, String), WireError>;
  /// Accept: the device and its held passkey; the caller adds the credential, then saves.
  pub fn confirm_pair_with(&self, pair_id: &str, accept: bool, now: u64, add: &dyn Fn(&Credential) -> Result<(), String>) -> io::Result<Option<Device>>;
}
// daemon workspace_touch.rs
pub fn passkey_credential(p: &PasskeyAttestation, pair_id: &str, device_pub: &[u8; 65], origins: &[String], owner_uid: u32, label: &str, now_ts: &str) -> Result<Credential, String>;
```
`passkey_credential` checks, in order: `verify_p256_domain(device_pub, PASSKEY_DOMAIN, passkey_sig_msg(..), device_sig)` (`crates/wire/src/sig.rs:15`; else "the passkey is not signed by this browser's key"); `client_data_json` is an object with `type == "webauthn.create"`, `challenge == b64u(passkey_challenge(pair_id, device_pub))`, `origin ∈ origins`, `crossOrigin` not `true`; `rp_id = rp_id_of(origin)`; `saiife_touch::credential_from_attestation(auth_data, &rp_id, label, owner_uid, None, now_ts)` (`store.rs:216`: needs AT and UP and the rp id hash); the authData's UV flag set (`saiife_touch::authdata::{parse, UV}`, `authdata.rs:10,36`); its credential id equals `credential_id`; then `kind = "webauthn"`, `origins = vec![origin]`. `finish_pair_with` refuses the whole pairing request when a passkey is present and fails (the browser retries without one or re-pairs).

- `confirm_pair_with(accept = true)`: `add(&cred)` first (`ctx.touch.add`, `touch.rs:281`, in `spawn_blocking`), then the device with `touch_credentials = [b64u(cred.id)]` is saved; a failed device save removes the credential again (`ctx.touch.remove`, `touch.rs:292`). A failed `add` (16 credentials for that uid, `store.rs:63`; unwritable touch files) pairs the device without a passkey and the answer says so (`passkey: "not_saved"`, plus the reason). The `paired` record gains `extra.passkey = b64u(id)` or `null`.
- Browser (`pairing.js`): after the device key is made and before `POST /api/pair`, `navigator.credentials.create({publicKey: …})` with the Fixed values; `response.getAuthenticatorData()`, `response.clientDataJSON`, `rawId`; the device key signs the attestation (`PASSKEY_DOMAIN`, WebCrypto ECDSA P-256); a `NotAllowedError` or no `PublicKeyCredential` pairs without a passkey and the pair view says "Touches are not available on this browser: approvals stay on the machine".
- Link: `local.rs` `keys_ok(&obj, &["pair_id","device_pub","label","proof"], &["passkey"])`; `hub.rs` pair message optional key `passkey`; neither parses it.

- [ ] **Step 1: Write the failing tests:** daemon (`workspace_ops.rs` tests, `SoftAuthenticator::new_es256()` making the create-side `authData` with AT through its `enrol` path, `soft.rs:241`): `pair_with_passkey_enrols_credential` (after confirm: `ctx.touch.credentials_of(owner)` has one `webauthn` credential, `rp_id == "localhost"`, `origins == ["http://localhost:47810"]`; the device lists its id), `passkey_with_wrong_challenge_is_refused`, `passkey_signed_by_another_key_is_refused` (Review Focus 5), `passkey_without_uv_is_refused`, `passkey_for_other_origin_is_refused`, `pair_without_passkey_is_signed_only`, `reject_stores_no_credential`, `passkey_store_full_pairs_without_passkey` (16 credentials already: device Active, `passkey: "not_saved"`); link `pair_post_accepts_passkey_key` (`tests/local.rs`), `pair_post_refuses_other_extra_keys`; node `create options are as fixed`, `passkey is signed with the device key` (verified in the test with WebCrypto against `passkey_sig_msg`'s layout), `no PublicKeyCredential pairs without passkey`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(workspace): enrol a WebAuthn passkey with the pairing, signed by the device key`.

---

### Task 4: `workspace.touch.begin` and the open web touches (size M)

**Files:** Modify `crates/daemon/src/workspace_link.rs` (remove `workspace.touch.begin` from `LATER`, add it to `HANDLED`; a `begin` arm in `act`), `crates/daemon/src/workspace_touch.rs` (`WebTouches`); `crates/daemon/src/ops.rs` (`Ctx.web_touch: Arc<WebTouches>`).

**Interfaces (Produces):**
```rust
pub struct WebTouches { /* next request id: AtomicU64 from 1; spent: Mutex<BTreeMap<[u8;32] /* challenge */, u64 /* expires_at */>>; windows: Mutex<BTreeMap<(String, BoxId), u64>> */ }
impl WebTouches {
  pub fn new() -> WebTouches;
  pub fn next_id(&self) -> u64;
  pub fn spend(&self, challenge: &[u8; 32], expires_at: u64, now: u64) -> bool;   // false if already spent; prunes expired
  pub fn open_window(&self, device: &str, id: &BoxId, now: u64);
  pub fn window_open(&self, device: &str, id: &BoxId, now: u64) -> bool;
  pub fn close_device(&self, device: &str);
}
/// The class, summary and fields the daemon binds for a Touch action, from its own view.
pub fn bind(ctx: &Ctx, action: &str, args: &Map<String, Value>) -> Result<(TouchClass, String, BTreeMap<String, String>), Refused>;
```
- Frame `workspace.touch.begin {action, args}` (Signed): `action` must be one of `box.steer`, `box.revise`, `box.resume`, `box.spawn` (with a template whose `spawn_level` is Touch, `crates/wire/src/level.rs:144`) or `approval.approve` (`args = {id}`: a pending v2 request with a touch class; the record is `approvals::action_record(&r, class, ..)`, `approvals.rs:411`, so the browser signs what the machine prompt would show); `box.land` is refused `invalid` ("use the request id from the inbox": the box source made that record); anything else `invalid`. `bind` builds `fields` from the daemon's view, never trusting the args beyond ids: steer/revise/resume `{action, box}` (the box must exist: `ctx.boxes.list()`); spawn `{action, template, repo, task_sha256, start}`. Summary: `"<action> box <id>"`, spawn `"spawn <template> on <repo>"` (plain text, ≤ 200 chars).
- The device must have a passkey: `device.touch_credentials` non-empty, else `touch_unavailable` "this browser has no passkey: pair it again to add one".
- `ctx.touch.issue(IssueKey::Web { device, request_id }, owner_uid, class, summary, fields, now)` (`spawn_blocking`); an `Err` ("too many touches in progress") → `busy`. The answer: `TouchRequest { rp_id, challenge: saiife_touch::challenge(&record), allow: device.touch_credentials decoded, uv: true, summary, short_code }` + `request_id` (decimal), `expires_at`, `class` (name). The `ActionRecord` is built as plan 26 does (`instance_id = ctx.touch.instance_id()`, the issued nonce and expiry; `touch_ops.rs:120-135`).
- `begin` is recorded (`workspace` record, `extra.touch_begin = {request_id, class}`).

- [ ] **Step 1: Write the failing tests** (`tests/workspace_link.rs` additions, `FakeBoxSource::demo`, a paired `TestDevice` with a soft passkey from Task 3): `begin_for_steer_answers_a_touch_request` (`rp_id == "localhost"`, `allow == [the passkey id]`, `uv`, `short_code == saiife_touch::short_code(&challenge)`), `begin_binds_daemon_fields` (args with an extra `fields` key → `invalid`; the issued record's fields are `{action, box}` only), `begin_for_land_is_refused`, `begin_for_approval_binds_the_stored_request` (a pending v2 connector request with class `deploy`: the challenge equals `challenge(&approvals::action_record(..))` with the issued nonce; an `id` with no touch class → `invalid`), `begin_for_signed_action_is_refused` (`box.stop` → `invalid`), `begin_for_plain_spawn_is_refused` (template without secrets → `invalid`: it needs no touch), `begin_without_passkey_is_unavailable`, `ninth_open_touch_is_busy` (eight begins for one owner, the ninth `busy`), `begin_is_recorded`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-boxes --test workspace_link` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(workspace): workspace.touch.begin binds a challenge to the daemon's own view of the action`.

---

### Task 5: verify Touch frames (size M)

**Files:** Modify `crates/daemon/src/workspace_link.rs` (`act`: `Level::Touch` with `v.frame`'s proof; `run` records the evidence), `crates/daemon/src/workspace_touch.rs` (`verify_frame`).

**Interfaces (Produces):**
```rust
pub enum Proven { Web(TouchEvidence, ActionRecord), Pending(TouchEvidence, PendingAction), Approval(TouchEvidence, u64 /* approval id */) }
pub async fn verify_frame(ctx: &Arc<Ctx>, v: &Verified, owner_uid: u32, proof: &TouchProof) -> Result<Proven, Refused>;
```
`verify_frame`, in order:
1. `request_id` parses as a decimal u64 (else `invalid`).
2. `web_assertion(proof, &origins(ctx))` (Task 2).
3. The credential id is one of this device's `touch_credentials` (else `touch_mismatch`), and the owner's credential with that id exists (`ctx.touch.credentials_of(owner_uid)`, else `touch_mismatch`); `rp_id = cred.rp_id`.
4. By action:
   - `box.steer`/`box.revise`/`box.resume`/`box.spawn`: `ctx.touch.consume(&IssueKey::Web { device: v.device_id, request_id }, owner_uid, build, &asr, &rp_id, now)` (burns the entry whatever the outcome); then the consumed record's `fields` must equal `bind(ctx, action, args)`'s (else `touch_mismatch`).
   - `box.land`: the `PendingAction` with that `request_id` from `pending_actions()` (none → `touch_failed` "no pending action: it expired or was decided"); `record.fields.diff_sha256` equals the frame's `diff_sha256` arg and `pa.box_id` equals `id` (else `touch_mismatch`); `ctx.web_touch.spend(challenge(&pa.record), pa.record.expires_at, now)` (false → `touch_failed` "used before"); `ctx.touch.verify_counted(owner_uid, &pa.record, &asr, &rp_id, now)`.
   - `approval.approve`: the v2 request (the store `approval_ops::decide` reads, `approval_ops.rs:646`) is still pending with a touch class (`effective_class`, as `touch_ops.rs:100` uses), and its record was issued under `IssueKey::Web { device, request_id }` by Task 4's `begin {action: "approval.approve", args: {id}}`; consume as above, then the consumed record's `request_id` field equals the frame's `id` (else `touch_mismatch`).
5. `TouchError` → `Refused { code: Forbidden, rule: e.rule(), message: e.to_string() }`; `Unavailable` → code `Unavailable`.

- `run` records `extra.touch = ev.to_audit()` on success and on refusal (the deny record carries `rule`, never the assertion bytes when parsing failed).
- `box.land` with a `Proven::Pending` calls `BoxSource::complete(request_id, Decision::Approve, Some(ev))` (`FakeCall::Complete(.., Approve, true)` on the fake); the answer `{}`.

- [ ] **Step 1: Write the failing tests** (`SoftAuthenticator`, demo fake whose `b-done` has a pending `land`): `land_with_touch_completes` (`FakeCall::Complete(rid, Approve, true)`, record `extra.touch.kind == "webauthn"`, `extra.touch.via == "web"`), `touch_for_other_box_is_mismatch`, `land_proof_on_revise_is_mismatch` (a pending land's request id sent with `box.revise` → `touch_mismatch`: no `Web` entry), `assertion_reuse_is_refused` (same frame body re-signed with a new nonce and the same proof → `touch_failed`), `uv_clear_is_refused` (`soft.uv = false` → `touch_failed`, `NotVerified` text), `foreign_origin_is_refused` (assertion for `https://app.saiife.com` → `touch_mismatch`), `rp_id_of_other_host_is_refused` (`rp_override`, `soft.rs` → `touch_mismatch`), `other_devices_passkey_is_refused` (device B's passkey on device A's frame → `touch_mismatch`), `expired_challenge_is_refused` (clock + 301 s → `touch_failed`), `diff_hash_mismatch_is_refused` (frame `diff_sha256` other than the pending record's), `refusal_records_the_rule`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(workspace): verify WebAuthn touches on Touch frames; land through complete`.

---

### Task 6: the Touch actions: steer window, spawn, v2 approvals (size M)

**Files:** Modify `crates/daemon/src/workspace_link.rs` (remove `box.steer`, `box.revise`, `box.resume`, `approval.list`, `approval.approve`, `approval.reject` from `LATER`; `box.push`, `box.pr` stay), `crates/daemon/src/approval_ops.rs` (`decide_remote`), `crates/daemon/src/workspace_ops.rs` (`revoke` `:438` closes windows).

**Interfaces (Produces):**
```rust
// approval_ops.rs
pub(crate) async fn decide_remote(ctx: &Arc<Ctx>, owner_uid: u32, owner_user: &str, rid: u64, approve: bool, evidence: Option<TouchEvidence>, device: &Device) -> Result<Value, Refused>;
```
- `box.steer {id, msg}` / `box.revise {id, comment}` / `box.resume {id}`: with a verified `Proven::Web` → `ctx.web_touch.open_window(device, id, now)` and run; without a proof but `window_open(device, id, now)` → run, record `extra.window = true`; else `touch_required`. Text args through `check_text` (`MAX_STEER_BYTES`). Lockdown `all` refuses all three (plan 34 B-rule: they give a box power; `box_ops.rs:577-581`).
- `box.spawn` with a raising template: a verified `Proven::Web` whose fields equal `bind`'s → `spawn`.
- `approval.list {}` (Signed): the pending v2 requests the device owner may decide (`approvers::is_approver(&cfg.approval, ctx.directory.as_ref(), owner_user)`, `approvers.rs:107`; personal mode: the daemon's own user), each as `approval_ops::item` (`approval_ops.rs:412`, already masked) plus `touch_class` (`with_effective_class`, `:541`); a non-approver gets `{items: []}`.
- `approval.reject {id, note?}` (Signed) and `approval.approve {id, note?}` (Touch, `Proven::Approval`): `decide_remote` checks the owner is an approver and not the requester (as `decide` does), then the same store transition `decide` uses (`Store::transition_by`, `approvals.rs:956`) with `by = owner_uid`; the record is `approvals::record_for(..)` + `record_with_touch` + `extra.workspace = {device, label}`. Polkit re-authentication is not used (the UV touch replaces it: the §9.6 amendment).
- `workspace.revoke` (machine side): after `Workspace::revoke`, `ctx.web_touch.close_device(id)`.
- **Not in this plan:** `box.push`, `box.pr` (remain `LATER`, answer `unavailable`): plan 39 makes push a CLI-only, touch-bound path; PR has no plan yet.

- [ ] **Step 1: Write the failing tests:** `steer_window_is_per_box_and_expires` (touch on `b-run` → a plain `box.steer` on `b-run` runs, on another running box → `touch_required`; at +601 s → `touch_required`), `revoke_closes_windows`, `window_frames_are_marked`, `resume_and_revise_use_the_window`, `lockdown_refuses_steer_even_in_window`, `spawn_secret_template_with_touch_spawns` (`FakeCall::Spawn` for `claude-gh`), `approval_list_is_for_approvers`, `approval_approve_needs_touch_and_approver` (no proof → `touch_required`; non-approver owner → `forbidden`; with proof → `approved`, record has `touch` and `workspace.device`), `approval_reject_is_signed`, `requester_cannot_approve_own_request`, `push_and_pr_stay_unavailable`, `later_list_matches_remote` (plan 29's test: every Signed `REMOTE` entry is handled or in `LATER`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(workspace): steer window, touch-bound spawn and v2 approvals from the browser`.

---

### Task 7: the browser side of touch, and the terminal pane (size M)

**Files:** Create `crates/link/assets/js/touch.js`, `crates/link/assets/js/term.js`, `crates/link/assets/tests/touch.test.mjs`, `crates/link/assets/tests/term.test.mjs`; modify `crates/link/assets/js/wire.js` (`readAnswer`), `crates/link/assets/js/touchprompt.js` ("Touch now"), `crates/link/assets/js/views/steer.js` (terminal pane), `crates/link/assets/js/views/review.js` and `views/inbox.js` (plan 30; Approve calls `touch`), `crates/link/src/assets.rs` (the two new files).

**Interfaces (Produces):**
```js
// touch.js
export async function touch(client, { action, args, requestId, credentials = navigator.credentials })   // -> the answer of the Touch frame
export function proofOf(requestId, credential)   // PublicKeyCredential -> TouchProof {request_id, credential_id, authenticator_data, client_data_json, signature}, b64u
// term.js
export function apply(screen, frame)   // snapshot replaces; delta patches lines; returns {screen, gap: bool}
export function render(screen, h)      // one text node per line, visible() applied, inside a <pre>
export function poller({ client, id, schedule, now })   // at most one box.term.read per second; start/stop
```
- `touch`: without `requestId`, `client.send("workspace.touch.begin", {action, args})`; the prompt (`touchprompt.show`) shows the action, the box, the summary and the **short code before** `credentials.get` opens (§8.3); `credentials.get({publicKey: get options})` with `challenge` = the hex decoded, `allowCredentials` = `allow`; cancel, timeout or error → "Not approved" (deny, §8.6), nothing sent; then `client.send(action, args, {touch: proofOf(...)})`. On `stale_epoch` the retry resends the **same** proof once with a new body (plan 30 Task 2 minor; the challenge is bound to the action, not the frame nonce).
- `wire.js` `readAnswer`: an ok answer keeps `result` whole (already); a refusal keeps `error`, `rule`, `message` and, when present and valid, `short_code` (6 digits) and `touch` (an object with the `TouchRequest` keys); every other field is still dropped (plan 30 R-1).
- `term.js`: a `seq` gap (delta `seq` ≠ last + 1) sets `gap` and the poller asks `box.term.read {id}` with no `after` (a fresh snapshot); `ended` stops polling and shows "The terminal has ended". The pane is a `<pre>` with no buttons, links or inputs.
- Rust: `box.term.read {id, after}` pages on the fake (`FakeBoxSource::with_terminal`, `fake.rs:430`).

- [ ] **Step 1: Write the failing tests:** node `get options are as fixed`, `short code shows before the dialog` (the fake `credentials.get` records whether the prompt node with the code was mounted first), `cancel is not approved` (`NotAllowedError` → no frame sent), `stale epoch resends the same proof once`, `read answer keeps short code and touch`, `read answer drops other fields`, `term apply snapshot and delta`, `term seq gap asks for snapshot`, `term render is inert` (lines with `ESC]52;c;…`, `ESC]8;;https://x`, a bidi override: no `a`, `button` or `input` node, text through `visible`), `term polls at most once per second` (fake clock, 10 ticks in 1 s → one call); Rust `term_read_pages_on_fake` (`crates/link/tests/ui_flows.rs`), `assets_list_touch_and_term`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; plan 30's static scans (`no inline script`, `no http://`) still pass.
- [ ] **Step 5: Commit** `feat(link): WebAuthn touch in the browser, short code first; read-only terminal pane`.

---

### Task 8: notification, smoke script, docs (size S)

**Files:** Modify `crates/policy/src/system.rs` (notify event `box_waiting`), `crates/daemon/src/notifier.rs` (payload `:58`), `crates/daemon/src/workspace_touch.rs` (`notify_pending`); create `scripts/workspace-smoke.sh`; modify `docs/workspace.md`.

- `notify_pending(ctx, &PendingAction)` sends `NotifyEvent { event: box_waiting, summary: "A box is waiting for your approval in the Workspace inbox (code <short_code>)", .. }` with the box id and **no URL and no request id** (§9.6). It is called by whoever creates pending actions (plan 39's `Lands::refresh`); here a test calls it directly.
- `scripts/workspace-smoke.sh` (owner-run; agents only `bash -n` and shellcheck): pair a phone through `saiife workspace serve` on `localhost` (same machine) or over Tailscale with the phone's origin added to `[workspace] origins`, enrol the passkey at pairing, approve the fake `land` with Face ID, check the audit record's `touch` object (`jq` over the audit `*.jsonl`, as `scripts/touch-smoke.sh` does, plan 27 R-I) and `saiife audit verify`, replay the same request (refused), steer twice within 10 minutes with one touch, revoke the browser and see the next frame refused.
- `docs/workspace.md`: passkeys at pairing, the steer window, what needs a touch, why push stays on the machine, `[workspace] origins`.

- [ ] **Step 1: Write the failing tests:** `notification_has_no_approve_link` (payload JSON has no `http`, no `request_id`, no decimal request id; has the short code), `box_waiting_event_parses` (`[notify] on = ["box_waiting"]`), `cargo test -p saiife --test docs_wording` passes for the new docs.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; `bash -n scripts/workspace-smoke.sh`; shellcheck if installed. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(workspace): box_waiting notification without links; owner smoke for Workspace touches`.

---

## Gates

- [ ] `cargo test -p saiife-touch --features soft -p saiife-wire --features fake -p saiife-policy -p saiife-daemon --features fake-boxes,fake-vmm -p saiife-link -p saiife`, and the daemon suite without features; `node --test crates/link/assets/tests/`; `-j 4 -- --test-threads=4`.
- [ ] clippy; `check-unsafe.sh`; `check-windows.sh -p saiife-touch -p saiife-wire -p saiife-policy -p saiife-daemon -p saiife-link -p saiife`; tokio gate `0`; `git diff v3-dev -- Cargo.lock` empty.
- [ ] `every_ipc_op_is_classified` passes (no new IPC op: `workspace.touch.begin` is a frame action already in `REMOTE`).
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Owner handwork

- [x] `TouchClass::Steer` (one touch opens a 10-minute window per box): owner-approved 2026-11-12, with `IssueKey::Web` and the per-uid limit of 8.
- [ ] Decide the `[workspace] origins` default.
- [ ] Run `scripts/workspace-smoke.sh` with a phone (Face ID) and a security key with a PIN.
- [ ] After plan 39: the real `land` through `complete` (its `Lands::complete` burns the CLI entry, plan 39 Task 4) and a smoke spawn → review → land with touch → `saiife box apply`.

## Out of scope

- `../saiife.com` Workspace mode (its WebAuthn client reuses `touch.js` as reference, with RP ID `app.saiife.com`) and `../saiife-hub`: other repos. The seal client in the browser (plan 30 R-2) is theirs.
- `box.push` and `box.pr` from the browser.
- Windows Hello and macOS Secure Enclave touches (§8.1 "later").
