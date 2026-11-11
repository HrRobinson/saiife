# Plan 31: Workspace touch and terminal stream (W4, outline): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Outline plan.** Written before plan 26 (touch core) and step 3 (boxes) exist. Tasks marked **BLOCKED-ON-STEP-3** need real boxes (box manager, vsock PTY, `land` through the CLI) and must not start before the step 3 plans are merged; their steps are deliberately coarser. Every other task can start once plan 26's `saiife-touch` verifier and plan 30 are on `v3-dev`. Before building, the coordinator re-checks every `saiife_touch` name below against plan 26 as merged and refreshes this outline into a full plan where a step leaves a choice open.

**Goal:** Make the Workspace's Touch-level actions real and add the read-only terminal:
- a WebAuthn passkey is enrolled **with** the browser at pairing (confirmed at the machine), so no remote action ever enrols a device;
- `workspace.touch.begin` issues a challenge bound to the action (§8.3); a Touch frame carries the WebAuthn assertion; the daemon verifies it with `saiife_touch::verify` and runs the action, recording the evidence (`via: web`);
- Approve (`box.land`), Revise/Steer/Resume (one touch opens a 10-minute steer window), spawn with secrets, push/PR, and v2 approval asks from the inbox;
- v2 approval asks with a touch class (plan 26) in the same inbox, approved from the browser;
- the terminal pane: snapshot + delta frames polled with `box.term.read`, rendered as text, read-only, no OSC 52 or OSC 8.

**Architecture:**
- **One verifier, one challenge store.** All signature work goes through plan 26's daemon `TouchState`: `ctx.touch.issue(IssueKey::Web(..), uid, class, summary, fields, now)` makes the challenge and `ctx.touch.consume(&key, uid, build, &Assertion::WebAuthn { .. }, rp_id, now)` verifies (with the pure `saiife_touch::verify`), burns the nonce and saves the counter. Plan 26 leaves `IssueKey::Web(..)` to this plan. The `rp_id` is the credential's (enrolled per origin; plan 26 checks the origin against the credential's `origins`); `TouchEvidence.user_verified` must be `true` for every Workspace touch (UV is required for all of them, not only `land`/`deploy`/`secret:sensitive`: a remote touch must prove who, §15).
- **The daemon only accepts actions it created** (§15). A Touch frame names a `request_id`; the `ActionRecord` behind it is the daemon's (from `workspace.touch.begin`, from `BoxSource::pending_actions`, or from a v2 approval with a touch class). The frame's `action` and `args` must match that record; a mismatch is `touch_mismatch`.
- **Refusals** are the contract's: `touch_failed`, `touch_unavailable`, `touch_mismatch` (plus `touch_required` from plan 29 when no proof was sent).

**Tech Stack:** As plans 28–30; `saiife-touch` (plan 26) with feature `soft` (`SoftAuthenticator`) in tests. No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §8.1, §8.3–§8.6, §9.3, §9.4, §9.5, §9.6, §12, §15. Contract: `v3-step4-6-contract.md` (the `saiife-touch` names are binding).

## Contract changes

None to names. Uses: `saiife_touch::{ActionRecord, TouchClass, challenge, short_code, Assertion::WebAuthn, Credential, TouchEvidence, TouchError, EnrolRequest}`, `SoftAuthenticator::{web_credential, assert_webauthn}` (feature `soft`) and the daemon's `touch::TouchState::{issue, consume, add}` (plan 26 Task 7).

**Deviation inherited from plan 26:** the contract's daemon-side `trait Touch { fn request(&ActionRecord) -> Result<TouchEvidence, _> }` with a browser implementation does not exist; plan 26 made `Touch` a *client* trait (it produces assertions) and the daemon side the concrete `TouchState`. The browser is such a client (in JavaScript), so this plan implements no Rust `Touch`. Additions here:
- `saiife_wire::pair::PairRequest` gains `#[serde(default)] passkey: Option<PasskeyAttestation>` (plan 28's struct; `deny_unknown_fields` stays).
- System config `[workspace] origins = ["http://localhost:47810"]` (`crates/policy/src/system.rs:20-40`, beside `approval`). Machine-only, like all config.
- `IssueKey::Web { device_id: String, request_id: u64 }` in plan 26's `IssueKey` (plan 26 reserves it for this plan).

## Global Constraints

- Everything in plans 28–30's Global Constraints.
- **Timeouts (§8.6):** browser prompt `timeout: 120000` ms; challenge valid `300` s; steer window `600` s per (device, box). Timeout, error or the wrong passkey all deny.
- **Never a password fallback** (§8.4) and **never a one-click approve link** (§9.6): no URL, notification or email carries anything that approves.
- **Tests never use a real authenticator.** Assertions come from `SoftAuthenticator` producing the browser's `authenticatorData` / `clientDataJSON` form with origin `http://localhost:<port>`; real phones and keys are the owner's smoke script.
- Every task: worktree `.worktrees/p31`, branch `p31-workspace-touch` off `v3-dev`; the plan 29 command block, plus `node --test crates/link/assets/tests/`.

## Review Focus

1. **An assertion for one action used for another**: a `land` touch replayed as `push`, a touch for box A used on box B, or a challenge used twice. Expected: `touch_mismatch`, then the nonce is burned once and a reuse is `touch_failed` (Task 3: `touch_for_other_box_is_mismatch`, `assertion_reuse_is_refused`).
2. **A passkey without user verification** (UV flag clear, e.g. a security key without PIN). Expected: refused `touch_failed` with "needs Face ID, fingerprint or PIN" for every Workspace touch (Task 3: `uv_clear_is_refused`).
3. **Wrong origin or RP ID**: an assertion made for `app.saiife.com` sent to the localhost UI, or an origin not in `[workspace] origins`. Expected: `touch_mismatch` (Task 3: `foreign_origin_is_refused`).
4. **A steer window outlives its purpose**: after revoke, after 600 s, or used on another box. Expected: closed at once on revoke; per (device, box) only (Task 4: `steer_window_is_per_box_and_expires`, `revoke_closes_windows`).
5. **Terminal output tries to act**: OSC 52 clipboard writes, OSC 8 links, a fake "Approve" button drawn in the stream, 10 000 lines/s. Expected: shown as inert text; the pane has no controls; the UI reads at most one batch per second (Task 5: node `term render is inert`, `term polls at most once per second`).

---

### Task 1: enrol a passkey with the pairing (size M)

**Files:** `crates/wire/src/pair.rs` (`PasskeyAttestation { credential_id, attestation_object, client_data_json }`, all b64u), `crates/daemon/src/workspace.rs` (`confirm_pair` enrols the credential into plan 26's credential store with `rp_id` from the origin and the device id as its label), `crates/link/assets/js/pairing.js` (`navigator.credentials.create` after the key, before POST), `crates/policy/src/system.rs` (`[workspace] origins`).

- Create options: `rp: {id: location.hostname, name: "saiife"}`, `user.id` = the device id bytes, `challenge` = SHA-256(`"saiife-pair-passkey-v1\n"` ‖ pair_id ‖ device_pub), `pubKeyCredParams: [{type: "public-key", alg: -7}]` (ES256; add `-8` only if plan 26 supports EdDSA), `authenticatorSelection: {userVerification: "required", residentKey: "preferred"}`, `attestation: "none"`.
- The daemon checks `clientDataJSON.type == "webauthn.create"`, the challenge, the origin (allowed list), rpIdHash, UP and UV, parses the COSE key with plan 26's parser, and adds the `Credential` (kind `webauthn`, `rp_id = location.hostname`, `origins = [the origin]`, `owner_uid` = the device owner's uid) with `ctx.touch.add`. The device's `touch_credentials` (plan 28) lists its id, so a touch frame is checked against that device's passkeys only. A pairing without a passkey still pairs (Signed actions only), and the UI says touches are not available on this browser.
- Tests: `pair_with_passkey_enrols_credential`, `passkey_with_wrong_challenge_is_refused`, `pair_without_passkey_is_signed_only`; node `create options are as fixed`.

### Task 2: `workspace.touch.begin` and the pending-touch table (size M)

**Files:** `crates/daemon/src/workspace_ops.rs` (handler; remove `workspace.touch.begin` from `LATER`), plan 26's `crates/daemon/src/touch.rs` (`IssueKey::Web`; at most 64 open `Web` entries, 300 s each).

- Frame `workspace.touch.begin {action, args}` (Signed): `action` must have `Level::Touch` (or be `box.spawn` with a raising template); the daemon takes the class and `fields` from its own view of the target (for `box.land`: class `Land`, `fields = {repo, base_commit, diff_sha256}` from `BoxSource::diff`, never from the args), calls `ctx.touch.issue(IssueKey::Web { device_id, request_id }, owner_uid, class, summary, fields, now)`, and answers plan 26's `TouchRequest` plus `{request_id, expires_at, class}` (`request_id` as a decimal string). Steer, revise and resume have no §8.2 class: this plan asks plan 26's owner to add `TouchClass::Steer` (UV), and until then they are refused `touch_unavailable` (open point, flagged).
- For an existing `PendingAction` (inbox) the UI skips `begin` and uses its `request_id`.
- Tests: `begin_binds_the_daemon_diff_hash` (args claim another hash → the record still holds the fake's), `begin_for_signed_action_is_refused`, `sixty_fifth_open_touch_is_busy`.

### Task 3: verify Touch frames (size M)

**Files:** `crates/daemon/src/workspace_ops.rs` (`execute`: a `Level::Touch` action with `touch: Some(proof)`), `crates/daemon/src/workspace.rs`.

- Order: find what `proof.request_id` names (an `IssueKey::Web` entry, then `boxes.pending_actions()`, then a v2 approval with a touch class) → the frame's action and targets equal the record's (else `touch_mismatch`) → the credential is one of this device's `touch_credentials` (else `touch_mismatch`) → `ctx.touch.consume(&key, owner_uid, build, &asr, &cred.rp_id, now)` → `user_verified` (else `touch_failed`) → execute → audit `extra.touch` = the evidence plus `via: "web"`, device id and label (contract: via `approvals::record_for` for approvals; a `workspace` record otherwise). `TouchError::{Mismatch, UnknownCredential}` → `touch_mismatch`; `Unavailable` → `touch_unavailable`; the rest → `touch_failed`.
- Tests with `SoftAuthenticator`: `land_with_touch_completes` (`FakeCall::Complete(.., Approve, true)`, record has `touch.kind == "webauthn"`), `touch_for_other_box_is_mismatch`, `assertion_reuse_is_refused`, `uv_clear_is_refused`, `foreign_origin_is_refused`, `other_devices_passkey_is_refused`, `expired_challenge_is_refused`.

### Task 4: the Touch actions (size M; parts BLOCKED-ON-STEP-3)

**Files:** `crates/daemon/src/workspace_ops.rs` (remove the rest of `LATER`), `crates/daemon/src/approval_ops.rs` (a remote decision path after plan 26's touch hook).

- `box.steer`, `box.revise`, `box.resume`: a verified touch opens a steer window (device, box, 600 s); within it the Signed frame alone suffices; `workspace.revoke` closes the device's windows. Runs on the fake now.
- `box.spawn` with a raising template: runs on the fake now.
- `approval.list` (Signed: the pending v2 requests the device owner may see, masked as `approval.list` masks them), `approval.reject` (Signed), `approval.approve` (Touch): `approval_ops::decide_remote(ctx, device, request_id, action, evidence)` checks the owner is an approver (`approvers::is_approver`, `approvers.rs:84`) and that the touch evidence verified, then `transition_by`. The polkit re-authentication is not used (the UV touch replaces it); this is the §9.6 amendment. Runs now (v2 approvals exist).
- **BLOCKED-ON-STEP-3:** `box.land` performing the land (the CLI writes the worktree, §5.1: the daemon hands it the validated diff), `box.push` (`saiife box push` runs `git push` as the user after the touch, §8.2), `box.pr` (through the GitHub connector if configured). On the fake these complete via `BoxSource::complete`; the real paths come with the box manager.
- Tests: `steer_window_is_per_box_and_expires`, `revoke_closes_windows`, `approval_approve_needs_touch_and_approver`, `approval_reject_is_signed`; BLOCKED-ON-STEP-3: `land_writes_the_branch_via_cli`, `push_names_remote_ref_commit`.

### Task 5: the browser side of touch, and the terminal pane (size M; terminal source BLOCKED-ON-STEP-3)

**Files:** `crates/link/assets/js/touch.js`, `crates/link/assets/js/touchprompt.js` ("Touch now"), `crates/link/assets/js/term.js`, `crates/link/assets/js/views/steer.js` (terminal pane), node tests `touch.test.mjs`, `term.test.mjs`.

- `touch.js` `export async function touch(client, {action, args, requestId?})`: `begin` unless a `requestId` is given → `navigator.credentials.get({publicKey: {challenge, rpId: location.hostname, allowCredentials, userVerification: "required", timeout: 120000}})` → `TouchProof` (plan 28 names, b64u) → `client.send(action, args, {touch})`. Cancel or timeout shows "Not approved" (deny, §8.6). The prompt always shows the action, the box, the diff stats and the short code **before** the system dialog opens (§8.3).
- `term.js` `export function apply(screen, frame)` (snapshot replaces, delta patches lines; a gap in `seq` asks for a new snapshot) and `export function render(screen, h)` (one text node per line, `visible()` applied). The steer view polls `box.term.read {id, after}` at most once per second while visible; the pane is a `<pre>` with no buttons.
- Tests: node `get options are as fixed`, `cancel is not approved`, `term apply snapshot and delta`, `term seq gap asks for snapshot`, `term render is inert`, `term polls at most once per second`; Rust `term_read_pages_on_fake`.
- **BLOCKED-ON-STEP-3:** the real source (guest PTY over vsock → host headless terminal → `TermFrame`s, §9.4) and the asciicast v2 recording of each session; both belong to the box manager's `BoxSource::terminal`.

### Task 6: notifications, smoke script, conformance (size S; parts BLOCKED-ON-STEP-3)

**Files:** `crates/daemon/src/notifier.rs` (payload at `:58`), `scripts/workspace-smoke.sh`, `docs/workspace.md`.

- A pending touch-class action may notify "A box is waiting for your approval in the Workspace inbox" with the box id and short code, and **no URL with a request id** (§9.6). Test: `notification_has_no_approve_link` (payload text has no `http`, no request id).
- `scripts/workspace-smoke.sh` (owner-run; agents only `bash -n` and shellcheck): pair a phone through `--local` on the same machine or over Tailscale, approve a fake `land` with Face ID, check the audit record's `touch` object and `saiife audit verify`, try the same assertion again (refused), revoke the browser and see the next frame refused.
- **BLOCKED-ON-STEP-3:** step 3's real `BoxSource` runs plan 28's `conformance::check` in its own tests; the smoke script gains a real box spawn → review → land with touch → branch `saiife/box-<id>` has one commit.

## Out of scope

- `../saiife.com` Workspace mode (its WebAuthn client reuses `touch.js` as reference, with RP ID `app.saiife.com`) and `../saiife-hub`: other repos.
- Windows Hello and macOS Secure Enclave touches (§8.1 "later").
