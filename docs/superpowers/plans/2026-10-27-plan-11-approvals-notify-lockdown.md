# Plan 11 — Approvals, notifications, lockdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ask` rules stop being denies. A connector call or a guarded command that hits `ask` becomes a pending request (#N). An approver (a second uid, or the same uid after a polkit password prompt) decides it with `saiife approve|reject`. The daemon then sends the stored connector request, or issues a one-use grant for the exact command. The agent picks up the result. Notifications (webhook, SMTP, command) tell a human when something waits or goes wrong. `saiife lockdown` stops connector calls, or every hook, with one command.

**Architecture:**
- The daemon gains `approvals.rs`: a file-backed store under `<state>/approvals/` with sealed requests, results kept 24 h, expiry, and an id counter.
- `approvers.rs`: who may decide, plus the polkit re-authentication through an injectable `Reauth` seam.
- `grants.rs`: one-use command grants.
- `notifier.rs`: a bounded queue with webhook, SMTP and command targets.
- `lockdown.rs`: a persistent flag.
- The broker pipeline's step 8 creates a request instead of denying, and a new `pipeline::send_approved` sends a stored request.
- `check --managed` asks `grant.consume`/`approval.create` when a denying rule is listed in `[guard] ask`.
- The CLI gains `approvals`, `approve`, `reject`, `lockdown`, `api result` and `api --wait`.
- `system install` writes the polkit action file, and `doctor` reports whether re-authentication is available.

**Tech Stack:** Rust workspace, extending existing crates. Possible new dependencies: none required. SMTP is a small hand-written client over the existing `tokio-rustls`/`rustls` (ring) stack. Webhooks reuse `saiife_broker::upstream::Upstream`. Any new crate is pinned to the newest release older than 14 days, as in plan 10.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §6.10.1–6.10.4
- §6.18
- §6.16 (the re-authentication check only)
- §6.7.1 step 2 (lockdown) and step 8 (ask)
- §7 rows `approvals`, `approve`/`reject`, `lockdown`, `api result`, and `status` (pending approvals and lockdown)
- §8.1 `[approval]`, `[notify]` and `[guard] ask`
- §8.7 ops `approval.*`, `grant.consume`, `api.result` and `lockdown.set`
- §8.8 `GET /v1/requests/{id}`
- §8.10
- §9.2 A14 (lockdown) and A15
- §13 "Approvals" and "Re-authentication fallback"
- §14 point 7

Plan 10 (`2026-10-26-plan-10-vault-gateway-connectors.md`) sets the style.

## Global Constraints

- **No privileged or process-control tools on the dev machine.**
  - Nothing runs sudo, root, systemd, polkit (`pkcheck`, `pkttyagent`, `pkexec`) or kill/pkill/killall/pgrep. This applies to implementers and reviewers.
  - Tests use fake `pkcheck`/`pkttyagent` scripts in a tempdir through the `Reauth` seam.
  - Real polkit runs only in the CI `locked-linux` job (Task 9).
  - Tests may signal only their own spawned child, by the `Child` pid, via rustix.
- **Test isolation:** `TMPDIR` and `SAIIFE_TEST_TMP` point at a short dir made by `mktemp -d -p /home/jonas/projects/personal/saiife`. Never /tmp, never the real home, never `~/.claude`. No internet: webhook and SMTP tests use loopback mocks with `rcgen` certificates, as plan 10 does.
- **Hook path:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free (the CI gate). The extra `grant.consume`/`approval.create` round trip runs only when a deny rule is in `[guard] ask`. The `check --managed` p95 stays under 40 ms, and developer-mode medians within +1 ms of `main`.
- **Fail closed:** any error in the approval, grant or lockdown path means deny or not sent:
  - an unreadable store;
  - a seal failure (vault unavailable);
  - a reauth error or timeout;
  - an unknown id;
  - a notify failure. This one never blocks the request; it is recorded.
- **Secrets:**
  - Stored requests hold unmasked parameters and bodies, so they are sealed with the vault key (`request_sealed`).
  - The display copy and every record are masked.
  - Notifications never carry secrets, bodies or approve links.
  - Results are stored masked (they are already masked by `finish`) and sealed.
- **Commits:** the branch is `plan-11-approvals` from `main`. Each task is committed in its worktree and cherry-picked onto the plan branch. The trailer is `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never commit `.superpowers/`. `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`.
- **Spec values, verbatim:**
  - Approval record kind `approval`, with `action` ∈ `created|approved|refused|rejected|expired|sent|send_failed`, plus `id`, `by_uid`, `note`. Every step is linked by `approval` id.
  - `[approval] timeout` defaults to `30m`; `grant_ttl` defaults to `15m`. A grant is good for one use.
  - Results are kept 24 h.
  - Grant key = SHA-256 over `uid`, `agent`, `project`, `tool`, `input`, each length-prefixed (u32 BE) in that order.
  - The hook message on a pending command: `Needs approval: request #<id>. Run the same command again after it is approved.`
  - `saiife api` exit 3 = pending, and it prints the id and how to get the result. HTTP 202 `{"pending": <id>}`.
  - `same_user`: `"deny"` | `"reauth"`. The polkit action id is `com.saiife.approve`. The action file is `/usr/share/polkit-1/actions/com.saiife.approve.policy`, with `allow_any`, `allow_inactive` and `allow_active` = `auth_self` (never `auth_self_keep`).
  - The reauth-unavailable warning: `re-authentication unavailable: approvals need a second account`.
  - Lockdown scopes: `connectors` | `all`. Admin or approver only. Survives restarts. It is a record and a notification.
  - Notification events: `approval_created`, `limit_reached`, `error_denied_burst`, `chain_break`, `forward_failing`, `lockdown`. Targets: `webhook` | `smtp` | `command`. Records `kind = "notify"`.
- **Decisions this plan makes** (the spec is silent; each is restated in its task):
  1. **Limits on ask.** At creation the limiter is checked without reserving (`Limiter::would_allow`), so a request that could never be sent is denied at once with its `limit`. At send time `check_and_commit` runs for real. Over a limit then means `send_failed` with `limit`, and the result says so.
  2. **Policy at send.** The stored call is re-decided against the *current* policy snapshot. A now-`deny` gives `send_failed`, `rule = "policy_changed"`. `ask` or `allow` means it is sent. Scope is re-checked too.
  3. **`--wait`** is client-side polling of `api.result` every 2 s, up to the given duration (at most 1 h). HTTP `wait` is ignored; the gateway always answers 202 at once (documented).
  4. **Who sees what.** The requester sees its own requests (`approvals list/show`, `api result`). Approvers see all. Admins who are not approvers see none.
  5. **Ids** are a u64 counter in `<state>/approvals/next_id` (fsynced). Ids never repeat across restarts.
  6. **Expiry** is swept every 30 s and at start. An expired request gives an `expired` record and notification event `approval_created` is not repeated. A grant that is not used within `grant_ttl` lapses silently (its record is the approval itself).
  7. **Reauth** runs `pkcheck --action-id com.saiife.approve --process <pid>,<start>,<uid> --allow-user-interaction`. The pid and start come from the approving CLI's peer credentials and `/proc/<pid>/stat`. Timeout 120 s. Exit 0 means authorized; anything else is refused with `reauth_failed`. The CLI starts `pkttyagent --process <own pid> --fallback` when `SSH_TTY` is set or `DISPLAY`/`WAYLAND_DISPLAY` are unset, and stops it, its own child, afterwards.
  8. **Lockdown and hooks.** With `scope = all`, `audit.append` answers error `lockdown` (with the reason) instead of a seq. The guard record is still written (decision `deny`, rule `lockdown`), and the hook denies with `saiife lockdown is on: <reason>`. `connectors` affects only pipeline step 2 (`rule = "lockdown"`).
  9. **SMTP** is a minimal hand-written client: implicit TLS on 465, or STARTTLS on 587/25, then `EHLO`, `AUTH PLAIN` (secret `kind basic`), `MAIL`/`RCPT`/`DATA`, with a 10 s timeout per step. No other auth methods. Plain-text SMTP without TLS is refused.
  10. **Notify limits.** A bounded queue of 256 events; when full, the oldest is dropped and counted. Each target gets at most one send per event kind per 60 s, except `approval_created`, which is always sent. Each failure is a `notify` record with `result = "failed"`. No retries beyond one immediate retry.
  11. **`error_denied_burst`** = 10 or more `error_denied` guard records from one uid within 60 s, at most one notification per uid per 10 min.

## Review Focus

1. **The stored request cannot change between approval and send.** An agent that edits nothing on disk, but sends a second `api.call` with the same id or a changed body after approval, must not alter what is sent. Expected: the send uses only `request_sealed`, and the request file is daemon-owned 0600 (Task 1 `sealed_request_is_what_is_sent`; Task 3 `approve_sends_stored_body_not_new_one`).
2. **Self-approval in every disguise:**
   - the same uid with `same_user = "deny"`;
   - the same uid with `reauth` but a failed or timed-out `pkcheck`;
   - an approver approving a request whose requester uid it shares through a *group* match only;
   - an approver-listed uid approving its own request.

   Expected: refused and recorded (`approval` `action = "refused"`, `rule`) every time (Task 2 table test).
3. **A grant used twice, used by another uid, or used for a different command.** Expected:
   - the second use creates a new request;
   - another uid's key differs, so there is no grant;
   - `git push --force origin main` vs `… main ` (a trailing space) are different keys, both needing approval (Task 4).
4. **Lockdown while requests are pending, and across a restart.** Expected:
   - pending connector requests are not sent on approve while `connectors` or `all` is on (`send_failed`, `rule = "lockdown"`);
   - the flag is read at start, so a restart does not lift it;
   - a non-approver `lockdown off` is refused and recorded (Task 7).
5. **A notification target that hangs or is slow.** Expected:
   - approvals, hooks and connector calls never wait on it (bounded queue, own task, timeouts);
   - a webhook URL to another host after a redirect is refused;
   - a `command` target that is not root-owned is a config error (Tasks 6 and 8).

---

## Task order and parallelism

- Wave 1, in parallel: Tasks 1, 2, 6, 7.
- Wave 2: Task 3 (needs 1, 2), Task 4 (needs 1, 2), Task 8 (needs 2).
- Wave 3: Task 5 (needs 3, 4), Task 9 (needs 2, 8).
- Last: Task 10 (wiring of notify events into 3, 4 and 7, plus the docs), then the whole-branch review and one fix wave, the gates, push and the PR.

---

### Task 1: approval store

**Files:**
- Create: `crates/daemon/src/approvals.rs`
- Modify:
  - `crates/daemon/src/vault.rs`: `pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, VaultError>` and `pub fn open_sealed(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>`. These use the vault key with a fresh 24-byte nonce. The format is `nonce || ciphertext`, with AAD `b"SAIIFEAP1" || id (u64 BE)`.
  - `crates/daemon/src/ops.rs`: `Ctx.approvals`.
  - `crates/daemon/src/start.rs`: open at start, sweep timer.

**Interfaces:**
- Produces:
  - `pub enum ApprovalType { Connector, Command }`
  - `pub enum State { Pending, Approved, Rejected, Expired, Sent, SendFailed }`, serialized snake_case.
  - `pub struct Request { pub id: u64, pub created: String, pub expires: String, pub uid: u32, pub user: String, pub session: Option<String>, pub agent: String, pub project: String, pub kind: ApprovalType, pub service: Option<String>, pub operation: Option<String>, pub capability: Option<String>, pub params: BTreeMap<String,String> /*masked display*/, pub input: Option<String> /*masked command*/, pub grant_key: Option<String>, pub request_sealed: Option<String> /*base64*/, pub state: State, pub decided_by: Option<u32>, pub note: Option<String>, pub result_ref: Option<String> }`. These are the §8.10 fields. The JSON key for `kind` is `type`.
  - `pub struct Store` with:
    - `open(dir: &Path) -> io::Result<Store>`: the dir is 0700 and checked like the vault dir;
    - `create(&self, req: NewRequest, sealed: Option<Vec<u8>>, ttl: Duration, now) -> io::Result<Request>`: assigns the next id and writes `<id>.json` 0600 atomically;
    - `get(&self, id) -> Option<Request>`;
    - `list(&self, filter: Filter) -> Vec<Request>`;
    - `transition(&self, id, from: &[State], to: State, by: Option<u32>, note: Option<String>) -> Result<Request, StoreError::{Unknown, WrongState(State)}>`: atomic under one mutex, re-read from disk;
    - `put_result(&self, id, sealed: Vec<u8>, now)` writes `<id>.result` 0600;
    - `get_result(&self, id) -> Option<Vec<u8>>`;
    - `sweep(&self, now) -> Vec<Request /*newly expired*/>`: moves `Pending` past `expires` to `Expired`, deletes results older than 24 h, and deletes request files of terminal states older than 7 days.
  - Note size cap 1 KiB; control characters refused.

- [ ] **Step 1: failing tests:**
  - `ids_monotonic_across_reopen`
  - `files_0600_dir_0700`
  - `transition_rejects_wrong_state` (approve an expired → `WrongState(Expired)`)
  - `concurrent_transitions_one_wins` (2 threads approve/reject → exactly one Ok)
  - `sweep_expires_pending_only`
  - `results_dropped_after_24h`
  - `sealed_request_is_what_is_sent`: seal, then open, gives byte-identical output; a flipped byte gives an error; the AAD binds the id (opening `#1`'s seal as `#2` fails)
  - `vault_unavailable_seal_fails_closed`
  - `note_capped_and_control_chars_refused`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green, clippy clean.
- [ ] **Step 5:** commit `feat(daemon): approval request store with sealed requests and expiry`.

### Task 2: who may approve, and polkit re-authentication

**Files:**
- Create: `crates/daemon/src/approvers.rs`, `crates/daemon/src/reauth.rs`
- Modify: `crates/policy/src/system.rs`. Validate `approvers` entries (user names or `group:<name>`; an empty list is allowed and means nobody can approve, with a load warning).

**Interfaces:**
- Produces:
  - `pub trait Reauth: Send + Sync { fn available(&self) -> bool; fn check(&self, pid: u32, start: u64, uid: u32, timeout: Duration) -> ReauthResult; }`
  - `pub enum ReauthResult { Authorized, Denied, Unavailable, Error(String) }`
  - `pub struct PkCheck { pkcheck: PathBuf }` (production: `/usr/bin/pkcheck`). It runs the decision-7 argv with an empty environment except `PATH=/usr/bin:/bin`, with a timeout. `available()` means the binary exists and is root-owned, and `/usr/share/polkit-1/actions/com.saiife.approve.policy` exists.
  - `pub fn may_decide(cfg: &ApprovalCfg, dir: &dyn Directory, approver_uid: u32, approver_user: &str, req: &Request, reauth: &dyn Reauth, peer: &PeerCred, start_time: u64) -> Result<(), Refusal>`, with `pub enum Refusal { NotApprover, SameUserDenied, ReauthUnavailable, ReauthFailed, ReauthError(String) }`. Each has a `rule()`: `not_approver`, `same_user`, `reauth_unavailable`, `reauth_failed`, `reauth_error`.
  - Logic:
    - not in `approvers` (user, or `group:` via the current groups) → `NotApprover`;
    - `approver_uid == req.uid` and `same_user == deny` → `SameUserDenied`;
    - `== reauth` and not `available()` → `ReauthUnavailable`;
    - `== reauth` → `check(...)` must be `Authorized`;
    - a different uid → Ok.
- Consumes: `saiife_policy::{ApprovalCfg, SameUser, Directory}`, `sessions::Proc` for the start time.

- [ ] **Step 1: failing tests** (table test `may_decide_table`):
  - every Refusal path;
  - a second uid OK;
  - a group-listed approver OK;
  - the same uid via group membership is still `SameUserDenied`;
  - with a fake `Reauth`: Authorized → OK, Denied → `ReauthFailed`, Error → `ReauthError`, Unavailable → `ReauthUnavailable`.

  `pkcheck_argv_exact`: a fake `pkcheck` script in a tempdir records its argv and env. Assert the decision-7 argv, and that the env is only `PATH`. `pkcheck_timeout_is_error`: the fake sleeps longer than a 200 ms test timeout. Never run a real pkcheck.
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green, clippy clean.
- [ ] **Step 5:** commit `feat(daemon): approver checks and polkit re-authentication (pkcheck)`.

### Task 3: connector `ask` → pending → approve → send

**Files:**
- Modify:
  - `crates/broker/src/pipeline.rs`: step 8 calls `env.create_approval(&tr, &call_for_storage)` and returns `Outcome::Pending { id }`. Add `pub async fn send_approved(stored: StoredCall, cfg, cat, lim, env, up) -> Outcome`, which re-runs scope and decide (decision 2), lockdown, then `check_and_commit`, then send, mask and record, with `via = "approval"`.
  - `crates/broker/src/pipeline.rs` `Env`: `create_approval`, `would_allow` (decision 1).
  - `crates/broker/src/limits.rs`: `would_allow` (the same checks, no reservation).
  - `crates/daemon/src/api_ops.rs`: `api.call` answers `{pending: id}`; `api.result {id}` → `{state, result?}` (requester only, decision 4).
  - `crates/daemon/src/approval_ops.rs` (new): ops `approval.list`, `approval.show`, `approval.decide {id, action, note?}`. On approve of a Connector request: transition to Approved, write the record, spawn `send_approved`, store the sealed masked result, transition to Sent/SendFailed, write the record.
  - `crates/daemon/src/gateway.rs`: Pending → 202 `{"pending": id}`; `GET /v1/requests/{id}` → 200 with the result body and `X-Saiife-Upstream-Status`, 202 while pending, 404 for an unknown id or not the requester, 410 `{"state": "rejected"|"expired"|"send_failed"}`.
  - `crates/cli/src/api_cmd.rs`:
    - exit 3 prints `saiife: pending approval #<id> (saiife api result <id>)`;
    - `--wait` (decision 3);
    - `saiife api result <id>` maps exit codes as for a direct call; it exits 3 while pending, and 2 if rejected or expired.
- `StoredCall` = the resolved operation id, the validated params, the canonical body bytes, headers, service, uid/user/session/project. It is serialized to JSON, then sealed.

- [ ] **Step 1: failing tests:**
  - Pipeline: `ask_creates_pending_no_upstream_call` (mock 0 hits); `ask_over_limit_denied_at_creation`.
  - Daemon e2e via the CLI against a loopback mock:
    - `approve_by_second_uid_sends_once`: simulate the second uid with an `[approval] approvers` entry for the test user and a requester uid seam (a debug-only `SAIIFE_TEST_PEER_UID` override in the daemon, like the other test seams); or test at the ops level with fake `PeerCred`. Pick the ops level and document it.
    - `approve_sends_stored_body_not_new_one`
    - `reject_gives_410_and_exit_2`
    - `expired_after_timeout` (injected clock seam `SAIIFE_DAEMON_NOW`, already present)
    - `policy_changed_to_deny_send_failed`
    - `limit_reached_at_send_send_failed`
    - `result_visible_to_requester_only`
    - `records_linked_by_approval_id`: created, approved, sent each carry `approval = id`; the connector record has `via = "approval"`
    - `wait_returns_after_approval`
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green, `scripts/test-offline.sh` green, clippy clean.
- [ ] **Step 5:** commit `feat(approvals): connector ask becomes a pending request the daemon sends after approval`.

### Task 4: command grants (`[guard] ask`)

**Files:**
- Create: `crates/daemon/src/grants.rs`
- Modify:
  - `crates/ipc/src/msg.rs`: `grant.consume`, `approval.create`.
  - `crates/daemon/src/approval_ops.rs`: approve of a Command request creates a grant.
  - `crates/cli/src/check_managed.rs`: after the worker says Deny with `pack/rule` in `cfg.guard.ask`, call `grant.consume {key}` (`granted` → Allow, record decision `approved` with `approval`), else `approval.create {rec}` → Deny with the exact spec message and `approval = id`.
  - `crates/policy/src/load.rs`: validate every `[guard] ask` entry names an existing `pack/rule` in an active pack (error otherwise).
- Interfaces:
  - `pub struct Grants`: in-memory plus `<state>/grants.json` (0600, atomic) so a restart keeps them.
  - `insert(key: [u8;32], approval: u64, expires)`.
  - `consume(key, now) -> Option<u64>`: one use; it removes the grant.
  - `fn grant_key(uid, agent, project, tool, input) -> [u8;32]` per the spec. The **daemon** computes it from the peer uid plus the record fields. The client never supplies the key.
  - Deadlines: `grant.consume` and `approval.create` share the hook's existing 2 s ack budget. On timeout → `error_denied`.

- [ ] **Step 1: failing tests:**
  - `grant_used_once`
  - `grant_other_uid_no_match`
  - `grant_trailing_space_is_other_key`
  - `grant_expires_after_ttl`
  - `grants_survive_restart`
  - `hook_ask_rule_creates_request_and_denies_with_message` (an e2e `check --managed` against a test daemon with `[guard] ask = ["core.git/force-push"]`)
  - `hook_after_approval_allows_once_then_asks_again`
  - `self_approval_of_command_refused` (same uid, `same_user = "deny"`)
  - `unknown_guard_ask_rule_is_config_error`
  - `non_ask_deny_unchanged` (a deny rule not listed makes no extra round trip: assert no `grant.consume` record or op count)
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** green, bench note in the report, clippy clean.
- [ ] **Step 5:** commit `feat(approvals): one-use grants for guard rules under [guard] ask`.

### Task 5: approver CLI

**Files:** Create `crates/cli/src/approvals_cmd.rs` and `crates/cli/tests/approvals_cmd.rs`. Modify `crates/cli/src/main.rs`.

**Interfaces:**
- `saiife approvals [list] [--all|--pending] [--json]`: the default is pending. Columns: id, age, user, type, `service operation` or command (masked, cut to 60 chars), state.
- `saiife approvals show <id> [--json]`: the full masked request and its records.
- `saiife approve <id> [--note "…"]` and `saiife reject <id> [--note "…"]`. Before `approve`, the CLI starts `pkttyagent` per decision 7 when `same_user = reauth` would apply, i.e. the request's uid equals own uid. That uid is known from `approval.show`.
- Exit codes: 0 done; 2 refused (prints the rule); 5 daemon unavailable.

- [ ] **Step 1: failing tests** (e2e against a test daemon; a fake `pkttyagent` script via a debug-only `SAIIFE_TEST_PKTTYAGENT` path):
  - `list_shows_pending_masked`
  - `show_masks_params`
  - `approve_and_reject_round_trip`
  - `refusal_prints_rule_and_exit_2`
  - `pkttyagent_started_and_stopped_for_same_uid_reauth`: the fake writes its argv to a file, and the test asserts it is no longer running after exit by checking that its own pid file's process is gone via `/proc`. Never use pgrep.
  - `requester_sees_only_own`
- [ ] Steps 2–5 as usual. Commit `feat(cli): saiife approvals, approve and reject`.

### Task 6: notifier

**Files:**
- Create: `crates/daemon/src/notifier.rs`, `crates/daemon/src/smtp.rs`
- Modify:
  - `crates/policy/src/system.rs`: typed `NotifyCfg { on: Vec<Event>, targets: BTreeMap<String, TargetCfg> }`, where `TargetCfg = Webhook { url: Option<String>, url_secret: Option<String> } | Smtp { host, port, from, to: Vec<String>, secret, starttls: bool } | Command { path: PathBuf }`. Exactly one of `url`/`url_secret`. A `command` path must be absolute; root-owned is checked at use. Unknown keys and events are errors.
- Interfaces:
  - `pub struct Notifier` with `pub fn send(&self, ev: NotifyEvent)`. It never blocks: a bounded `mpsc(256)`, drop-oldest with a counter.
  - `pub struct NotifyEvent { pub event: Event, pub id: Option<u64>, pub service: Option<String>, pub operation: Option<String>, pub uid: Option<u32>, pub host: String, pub summary: String /*masked, ≤200 chars*/ }`
  - Delivery task:
    - webhook: POST `application/json` via `Upstream` to the URL host only, no redirects, 10 s;
    - SMTP: per decision 9;
    - command: exec `path` directly, env cleared, JSON on stdin, 10 s, output ignored. The path must be root-owned with root-owned parents (`system::fsops` check).
  - Rate limits per decision 10. A `notify` record per send: `event`, `target`, `result` (`sent`/`failed`/`dropped`), `reason`.

- [ ] **Step 1: failing tests:**
  - `webhook_posts_masked_payload_no_secret` (loopback TLS mock)
  - `webhook_redirect_not_followed`
  - `smtp_implicit_tls_and_starttls_send` (a loopback mock SMTP server in the test speaking just enough protocol)
  - `smtp_plaintext_refused`
  - `command_target_receives_json_stdin` (a root-owned program is impossible in tests, so use a test-only `trusted_owner` seam like plan 10's CA owner)
  - `user_owned_command_refused`
  - `slow_target_does_not_block_send` (a mock sleeps 5 s; `send()` returns in < 10 ms)
  - `queue_full_drops_oldest_and_records`
  - `rate_limit_per_kind_except_approval_created`
  - `config_unknown_event_is_error`
- [ ] Steps 2–5. Commit `feat(daemon): notifications by webhook, SMTP and command`.

### Task 7: lockdown

**Files:**
- Create: `crates/daemon/src/lockdown.rs`, `crates/cli/src/lockdown_cmd.rs`, `crates/cli/tests/lockdown_cmd.rs`
- Modify:
  - `crates/ipc/src/msg.rs`: `lockdown.set` and `ErrorCode::Lockdown`.
  - `crates/daemon/src/ops.rs`: `append` honours decision 8.
  - `crates/broker/src/pipeline.rs`: step 2 via `Env::lockdown() -> Option<Lockdown>`.
  - `crates/cli/src/check_managed.rs`: on `lockdown`, deny with the message.
  - `crates/cli/src/status_cmd.rs`: show the lockdown state, and the caller's pending approvals (count, plus the newest 3 ids) from `approval.list` (§7 `status` row).
- Interfaces:
  - `pub struct Lockdown { pub scope: Scope /*Connectors|All*/, pub reason: String, pub by_uid: u32, pub since: String }`, persisted at `<state>/state/lockdown.json` (0600, atomic). An unreadable file → treat it as `all` with reason `lockdown file unreadable` (fail closed), plus a record.
  - `lockdown.set {on: bool, scope?, reason?}`: admin or approver only. Others get Forbidden plus a `lockdown` record with decision deny. Records have `kind = "lockdown"`, `action = on|off`.
  - `saiife lockdown on [--scope all|connectors] [--reason "…"]` / `saiife lockdown off` / `saiife lockdown` (shows the state).

- [ ] **Step 1: failing tests:**
  - `connectors_lockdown_denies_api_call_rule_lockdown`
  - `all_lockdown_denies_hooks_with_message_and_record`
  - `lockdown_survives_restart`
  - `non_approver_off_refused_and_recorded`
  - `unreadable_flag_fails_closed_to_all`
  - `status_shows_lockdown_and_pending_approvals`
- [ ] Steps 2–5. Commit `feat(lockdown): saiife lockdown on|off for connectors or all hooks`.

### Task 8: install, uninstall and doctor (polkit)

**Files:** Modify:
- `crates/system/src/install.rs`: write the action file (root:root 0644) when `/usr/bin/pkcheck` exists, record it in `installed.toml`, and set `[approval] same_user` default to `"reauth"` if polkit exists, else `"deny"` (only for a new config).
- `crates/system/src/uninstall.rs`: remove exactly the listed file.
- `crates/system/src/doctor/system.rs`: re-authentication check with the exact warning.
- `crates/system/src/default_config.rs`.
- tests.

**Interfaces:** The action file content is fixed:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>saiife</vendor>
  <action id="com.saiife.approve">
    <description>Approve a saiife request</description>
    <message>Authentication is required to approve a saiife request</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
```

- [ ] **Step 1: failing tests** use the existing fake-host seam (`crates/system/src/testing.rs`), never the real `/usr/share`:
  - `install_writes_polkit_action_when_pkcheck_present`
  - `install_skips_and_sets_deny_without_pkcheck`
  - `uninstall_removes_action_file`
  - `doctor_warns_reauth_unavailable` (exact text)
  - `action_file_never_auth_self_keep`
- [ ] Steps 2–5. Commit `feat(system): polkit action for approvals; doctor re-authentication check`.

### Task 9: `locked-linux` CI checks for approvals

**Files:** Modify `scripts/locked-linux/lib.sh` and `scripts/locked-linux/run.sh`. These run only in GitHub Actions as root on the runner, never locally. Validate with `bash -n` and `shellcheck` only.

Add a phase `approvals` after the 9b phases. On the runner:
- check that the action file exists with the exact defaults;
- check that `doctor` does not warn about reauth when polkit is installed. Install `policykit-1` / `polkitd` in the job's apt step if absent;
- with an approver user `approver-ci` (created, then removed in cleanup) and `agent-ci` as requester:
  - an `ask` command rule creates a request;
  - `approver-ci` approves it via `sudo -u approver-ci saiife approve <id>`;
  - `agent-ci`'s retry is allowed once and asked again on the third run;
- `agent-ci` approving its own request with `same_user = "deny"` is refused;
- with `same_user = "reauth"` and no polkit agent, `pkcheck` fails, so the approval is refused with `reauth_failed`. A runner has no tty, so nobody can answer.

- [ ] Write it. `bash -n` and `shellcheck scripts/locked-linux/*.sh` pass. Commit `ci(locked-linux): approval, grant and reauth checks`.

### Task 10: wire notify events, docs, red-team case list

**Files:** Modify:
- the daemon producers: `approval_created` (Task 3/4 create), `limit_reached` (pipeline Limited, first per window per (uid, service, limit)), `error_denied_burst` (decision 11, in `append`), `chain_break` (start verification failure), `lockdown` (Task 7). `forward_failing` is defined but produced in plan 12.
- `docs/approvals.md` (new): flow, approvers, reauth, fallback, grants, exit codes, `--wait`, HTTP 202.
- `docs/notifications.md` (new).
- the `lockdown` section in `docs/threats.md`.
- `CHANGELOG.md`.
- an appendix `## Appendix: red-team cases for the 9c suite` in this plan file. Prose only, for the owner to script:
  - A15 self-approve;
  - grant reuse (used or expired);
  - lockdown off as a non-approver;
  - amount cap split across many approved refunds;
  - reading or editing the polkit action file.

- [ ] Failing tests for each producer:
  - `approval_created_notifies`
  - `limit_reached_notifies_once_per_window`
  - `error_denied_burst_after_10_in_60s`
  - `chain_break_notifies_at_start`
  - `lockdown_notifies`

  Then implement, then green, then commit `feat(notify): approval, limit, burst, chain and lockdown notifications; docs`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`;
  - clippy `-D warnings`;
  - the tokio gate prints 0;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with `TMPDIR` and `SAIIFE_TEST_TMP` set as above;
  - the developer-mode `scripts/bench-check.sh` vs `main` (never `--managed` locally).
- [ ] Whole-branch review (Opus), one fix wave, the scoped re-review, push, PR, CI. The owner merges.

## Appendix: red-team cases for the 9c suite

Prose only, for the owner to script. Each case gives the setup, the attack
(described, not scripted), the expected result and the record that must exist.
All run on the `locked-linux` job or a throwaway VM, with an agent user, an
approver user and a requester that can be the same as the agent.

### 1. A15: self-approval

**Setup.** Two configs. (a) `same_user = "deny"`, approvers `boss`. (b)
`same_user = "reauth"`, approvers include the agent's own user, with polkit and
the action file installed. A pending connector request made by the agent user.

**Attack.** (a) The agent runs `saiife approve <id>` itself, with and without
`--note`, and also tries to reach `approval.decide` on the control socket
directly. It also tries a request id belonging to another user. (b) The agent
runs `saiife approve <id>` from a process with no terminal and no desktop
session, so nobody can answer the polkit prompt, and again with a script that
tries to feed a password on a pty.

**Expected.** (a) Refused with exit 2 every time, request still pending, nothing
sent. The other user's id looks like an unknown id. (b) Refused with exit 2
(`reauth_failed`, or `reauth_unavailable` when polkit is gone); the request is
not approved and nothing is sent. The agent cannot answer the polkit
challenge: that needs the account password, which the agent does not have.

**Record.** An `approval` record with `action = "refused"`, `by_uid` = the
agent, `rule = "same_user"` (a) or `reauth_failed` (b), linked by `id`. No
`approved` or `sent` record exists for the request.

### 2. Grant reuse

**Setup.** `[guard] ask = ["core.git/force-push"]`. The agent runs a force
push, is denied with the needs-approval message, and the approver approves.

**Attack.** (a) The agent runs the exact command again: this uses the grant.
It then runs it a second time. (b) A second request is approved, the agent
waits out `grant_ttl` (15 minutes; the test can set it to a few seconds), then
runs the command. (c) The agent runs the same command from another project,
as another user, and under another agent name while a grant is waiting.

**Expected.** (a) The first rerun is allowed, the second is denied and asks
again (a new request, pending). (b) After expiry the command is denied and asks
again; the lapsed grant is gone. (c) None of these match; each asks for its own
approval.

**Record.** The first run: a guard record `allow` with `via = approval` linked
by the request id. The reuse and the late run: `ask`/deny records pointing at
new request ids. No second `sent` for the old request.

### 3. A masked-token variant of an approved command

**Setup.** As case 2, with a command that is approvable (`git push --force
origin main`).

**Attack.** The agent asks for a variant that carries a secret-looking token,
for example the same push to a URL with an embedded `ghp_` style token, or
with a long base64 argument, hoping the approver sees a masked line and
approves, while the grant covers a different exact string. It also tries a
command so long that its shown form would be cut.

**Expected.** No request is created. The hook denies as an ordinary deny with
"cannot be approved: the command contains masked or overlong content".
Nothing is left pending; no grant can exist for it.

**Record.** A guard record with decision `deny`, the rule's own reason, and no
`approval` records.

### 4. A compound command

**Setup.** As case 2.

**Attack.** The agent wraps the askable command with another denied one
(`rm -rf ~ ; git push --force origin main`), or chains it with `&&`, `||`, a
pipe or `$( )`, hoping the ask on one part approves the whole line.

**Expected.** A plain deny, no request: when another rule also denies the
line it is not approvable. A chain whose other parts are allowed is also
checked: the grant key is over the whole line, so approving the plain push
does not allow the chain, and approving the chain (if it were asked) does not
allow the plain push.

**Record.** A guard record `deny`; no `approval` record; no grant file entry.

### 5. Lockdown off as a non-approver

**Setup.** Lockdown on (`--scope all`) set by an approver. The agent user is
not root, not in `[admin]` and not an approver.

**Attack.** The agent runs `saiife lockdown off`, sends `lockdown.set` on the
control socket by hand, and tries to delete the flag file in the state
directory, to stop the daemon, or to edit `/etc/saiife/config.toml` to add
itself to `approvers`.

**Expected.** `lockdown off` is refused (exit 2, forbidden). The flag file and
config are not writable by the agent user (`core.lock` also blocks the hook
side). Lockdown stays on, including after a daemon restart. Hook calls are
still denied with "saiife lockdown is on: <reason>"; connector calls are
denied with rule `lockdown`.

**Record.** A `lockdown` record with decision `deny`, `rule = "forbidden"`,
the agent's uid. No `off` record. No `lockdown` notification for the refused
attempt.

### 6. An amount cap split across many approved refunds

**Setup.** A payment service with `amount_per_request` and `amount_per_day`
limits, `refunds:write` in `ask`. The agent can make many requests; the approver
approves each one that looks small.

**Attack.** The agent files many refunds each under the per-request cap, so
each is approved on its own, hoping the sum passes the day cap. It also files
more than 20 at once to fill the queue and bury a large one.

**Expected.** The limits are used at send time. Once the day total is full, the
next approved refund ends as `send_failed` with `limit = "amount_per_day"`, and
the requester's result says so. The 21st pending request from one user is
denied at once (`approvals_full`). The first `limit_reached` notification is
sent; the rest in the same window are not.

**Record.** `approval` records `approved` then `sent` for those that fit, then
`approved` and `send_failed` (with `limit`) for the one that did not; a
`connector` record with the limit; a `notify` record for `limit_reached`.

### 7. Reading or editing the polkit action file

**Setup.** `same_user = "reauth"` installed, so
`/usr/share/polkit-1/actions/com.saiife.approve.policy` exists, owned by root.

**Attack.** As the agent: read the file with a shell command and with the
agent's file tools (this must work: the file is public). Then try to change
`auth_self` to `yes` (no password), to add `auth_self_keep`, or to replace the
file, by direct write, by `sed -i`, by a move over it, by writing into the
`actions` directory, and by symlinking a path the installer writes. Then try
an approval that would pass if the file were weaker.

**Expected.** Reads succeed. Every write is denied by the hook (decision
`deny`, rule from `core.lock`), and a direct attempt that bypasses the hook is
refused by the OS (EACCES), as the file and directory are root-owned. The file
is unchanged and self-approvals keep failing closed (`reauth_failed`).

**Record.** Guard records with decision `deny` and the `core.lock` rule for
each write attempt; allow records for the reads. No `approved` record for any
self-request. If root ever changes the file's owner or mode, `saiife doctor`'s
`reauth` check warns (the polkit `action_problems` check).
