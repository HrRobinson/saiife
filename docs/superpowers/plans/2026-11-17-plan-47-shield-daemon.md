# Plan 47: Data Shield in the daemon: key store, datasets, audit, helpers and the model client (stage 1): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the pure Data Shield core into `saiifed` on Linux: per-dataset keys sealed with the vault key, dataset import/commit/refresh/remove ops with atomic swaps and approved-method re-validation, the Data Shield audit records with the outbox and the log scrub, the name-detector model fetch and helper client, the calculator process client, the daemon-side Anthropic model client (API keys only) behind the firewall, and `blind.status`.

**Architecture:** A new daemon module `crates/daemon/src/blind/` (Linux only; elsewhere every `blind.*` op answers `Data Shield runs on Linux in this release`). `Ctx` gains `blind: Arc<blind::Blind>` (Linux), built at start under `<state>/blind/` (0700). The daemon owns all I/O; `saiife-shield` does the logic. Every outgoing request is built from a `Pass`-ed envelope, re-scanned as bytes, written to the outbox and recorded before it is sent; nothing in this plan sends without that sequence. Plan 48 adds the ask flow, the touch flows and the CLI on top of these pieces.

**Tech Stack:** Rust, tokio `=1.53.3` (daemon only), hyper/`saiife_broker::upstream::Upstream` (existing, `crates/broker/src/upstream.rs:73`, `send` at `:397`), `chacha20poly1305` via `vault::Shared::seal`/`open_sealed` (`crates/daemon/src/vault.rs:603`, `:622`); new pinned crate `tokio-postgres = "=0.7.18"` (default features: the tokio runtime glue; no TLS crate) (2026-06-12, MIT OR Apache-2.0, pure Rust). `saiife-shield` (plans 43–45), `saiife-fido` (`check_helper`, `crates/fido/src/client.rs:58`).

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` §1.3 G1/G3, §2 (server first, per-uid scope), §2.1.1, §2.1.3, §2.1.5, §2.2.5, §2.3.3 (stage 1 calculator), §5.1 (cloud step [call], API keys only [call], models fetched on the host), §6.2, §6.3, §6.5, §9.

**Depends on:** plan 43 (all), plan 44 Tasks 2 and 5, plan 45 Tasks 1, 6 and 7, plan 46 Task 3 (protocol and fake helper). Map at the end.

## Plan rulings (refinements of spec [call]s)

- **R47-1 Key store** (spec §2.1.3 "inside saiife's existing vault"): each dataset's `KeySet` (plan 44 Task 2) is sealed with the vault key through `vault::Shared::seal(aad, bytes)` into `<blind>/datasets/<name>/keys.sealed` (0600), AAD `b"saiife-blind-keys-v1\0" ‖ name`. It is not a `vault.bin` entry: `secret list/rm/lease` never see it and no connector can lease it. An unavailable vault refuses every Data Shield op that needs keys (fail closed). Keys never leave the daemon: no op returns them, `Debug` prints versions only.
- **R47-2 Crypto-shredding** (`keys delete`): unlink `keys.sealed` (after overwriting it once with zeros and `fsync`), drop every live session of the dataset, remove `index.bin`/`index.bloom` (built with the old index key) and mark the dataset `needs_refresh`; the next refresh makes a new `KeySet`. Rotation (`keys rotate`): new stand-in key, the old one kept sealed as `retired` for 30 days (plan 44 `purge_retired` at start and daily), sessions of the dataset dropped.
- **R47-3 Who may do what** (spec §2 per-uid scope, §2.3.5 approver role [owner]): *users* of a dataset = its `users` list; *approvers* = its `approvers` list, or `[approval] approvers` when empty; in personal mode the daemon's own user is both (as `approval_ops::is_approver`, `crates/daemon/src/approval_ops.rs:78`). `ask`: users and approvers. `data stage` of a name not yet in policy, `data commit`, `data refresh`, `data rm`, `ner fetch`: root, the `[admin]` groups (`Ctx::is_admin`, `ops.rs:990`) or the dataset's approvers. Every op is local socket only (stage 1 has no remote surface; plan 48 refuses the ops on any other transport).
- **R47-4 Postgres** (spec §2.1.1): `tokio-postgres` without TLS, so only a Unix socket dir or a loopback host (policy load enforces it, plan 43 Task 2); a remote database is a later stage. The password is a vault secret (kind `basic` or `token`, field `password` or `token`) read at import time only; the session runs `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`, each table is read inside `BEGIN READ ONLY` with `SELECT <listed columns> FROM <table>` through `query_raw`, and the rows stream into a bounded `std::sync::mpsc::sync_channel(4096)` that the blocking build thread drains (no `COPY`, no temporary tables).
- **R47-5 File sources** are passed by the CLI as an open descriptor (the `box.fds` mechanism, `FD_OPS` at `crates/ipc/src/msg.rs:321`): in locked mode the daemon user cannot and must not read users' files; the CLI proves read access by opening it. `blind.data.stage` and `blind.data.refresh` join `FD_OPS`. SQLite sources are copied from the descriptor into `stage/source.sqlite` first (a path is needed to open them).
- **R47-6 Class baseline and loosening** (spec §2.1.2: only a person at the machine loosens, with `blind:loosen`): `data commit` writes `classes.json` (the classes in force). The effective class of a column is the policy's class, unless that is looser than the baseline's and no unspent loosen grant (`loosen.json`, written by plan 48 Task 3 after the touch) names `(table.column, new class)`; then the baseline's class stays and `status` warns `<col> was made <class> in policy without a blind:loosen touch; still <old>`. A loosening to `public` takes effect at the next refresh (the k-floor list is built then). A column with no class in policy is `sensitive`.
- **R47-7 The model client** (spec §5.1 [call]): `POST https://api.anthropic.com/v1/messages` with `x-api-key` (the `[blind.cloud] secret` vault token secret, which must allow the service `blind-model`, read per request as the box forwarder does, `box_gateway/model.rs:461`), `anthropic-version: 2026-10-21`, `anthropic-beta: server-side-fallback-2026-07-01`, `content-type: application/json`. Body: `{"model": <[blind.cloud] model or "claude-opus-5-5">, "max_tokens": 16000, "system": SYSTEM_PROMPT, "messages": [{"role":"user","content": <envelope canonical JSON as a string>}], "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": PLAN_SCHEMA}}, "fallbacks": "default"}`; no `thinking` field (adaptive is the model's default), no sampling parameters. Non-streaming; `Upstream::with_timeout(300 s)`, read limit 4 MiB. `stop_reason` `end_turn` → the first `text` block → `plan::parse_reply`; `refusal` → `PlanError::Refused` (shown, never retried); `max_tokens` → `PlanError::Truncated`; HTTP 429/5xx → one retry after `retry-after` (≤ 30 s); other status → `PlanError::Http(status)`. A subscription login is not accepted (`API keys only` until the owner's terms check, spec §5.1). Retries after a validation error are new single-message requests with `envelope.retry` set (plan 44), each one its own outbox entry and record.
- **R47-8 Order for every send** (G1, G3): envelope `Pass` (plan 44) → build the body → `Firewall::check_bytes(body)` `Pass` → outbox append + fsync → `blind_send` record → send. Any failure before the send stops it. The response: `blind_receive` record (status, bytes, reply sha256), then `Firewall::check_incoming`.
- **R47-9 Outbox** (spec §6.5 [call]): `<blind>/outbox/YYYY-MM.jsonl` (0600 in 0700), one line per request `{"ts","sha256","uid","dataset","ask","body"}` where `body` is the exact request body (UTF-8 JSON as a string); appended with `O_APPEND` and `fsync`. Retention `[blind] outbox_days` (default 365): whole month files older than that are removed at start and daily. Readable by root and the daemon only; `saiife blind audit --sent <sha256>` (plan 48) prints a body to root or an auditor.
- **R47-10 Records** (spec §2.1.5): kinds `blind_ask`, `blind_resolve`, `blind_preview`, `blind_send`, `blind_receive`, `blind_run`, `blind_check_refused`, `blind_approve`, `blind_reveal` (unused in stage 1), `blind_keys`, `blind_refresh`, `blind_loosen`, `blind_name`, `blind_log_scrubbed`, plus the existing `model` kind for each upstream call (with `credential: "daemon"`, `box` absent, `extra.blind_ask` = ask id). Fields are listed in Task 3. Before any `blind_*` record is written, every string field is scanned against the dataset's `KnownIndex`; a hit drops that field and writes a `blind_log_scrubbed` record naming the record kind and field (spec §6.5). `blind_*` kinds join `audit_query::USER_KINDS` (`crates/daemon/src/audit_query.rs:45`) so a user sees their own.
- **R47-11 Helpers.** NER helper path: locked mode `layout::NER_HELPER` after `check_helper(path, 0, "/")`; personal mode `NER_HELPER` if present, else `saiife-ner` beside `std::env::current_exe()` after `check_helper(path, own uid, its parent)`; debug builds honour `SAIIFE_TEST_NER_HELPER` (path) like `SAIIFE_TEST_FIDO_HELPER`. Calculator: `saiife __blind-calc` from `layout::BINARY` in locked mode, `current_exe()` in personal mode, `SAIIFE_TEST_BLIND_CALC` in debug builds. Both get an empty environment, cwd `/`, stdin/stdout pipes, stderr drained to 4 KiB (first line logged, never request text). The daemon kills only the children it spawned (`Child::kill`, `kill_on_drop`).

## Global Constraints

- **Tokio-free core.** All logic stays in `saiife-shield` (tokio-free); the daemon only wires I/O. `cargo tree -e normal -p saiife-shield -p saiife-system | grep -c tokio` = 0.
- **Dependencies** pinned with `=` and older than 14 days: `tokio-postgres =0.7.18` (Linux target dependency of `saiife-daemon` only). ONNX runtime: `tract-onnx =0.23.9` (MIT OR Apache-2.0, pure Rust) stays in `saiife-ner`; the daemon links only `saiife_shield::ner_proto` (`cargo tree -p saiife | grep -c tract` = 0); `ort` rejected (RC-only, C++ runtime, build-time download).
- **Tests fully offline with fakes:** `FakePlanner` (scripted replies), `saiife-fake-ner`, the real `__blind-calc` from the debug build, fixture datasets from plan 43's generator, vault opened with a test key, touch via the soft key seam. The live Anthropic test is `#[ignore]` and runs only from the owner's smoke. No sudo, docker, `/tmp` or real home; HOME/XDG/`SAIIFE_DATA_DIR`/`SAIIFE_AUDIT_DIR` point into `$TMPDIR`; `DBUS_SESSION_BUS_ADDRESS` set to a dead path in personal-mode tests.
- **No token-shaped literals:** fake API keys built with `concat!("test-", "key-", "blind")`.
- **Hook latency:** `saiife` now links rusqlite, sqlparser, calamine, csv and tokio-postgres through the daemon. Task 7 runs `bash scripts/bench-check.sh` (never `--managed`) and records the hook's p50/p95 before and after; a regression over 2 ms p95 is reported to the owner, not tuned around.
- **Every task** (worktree `.worktrees/p47`, branch `shield-p47` off `shield-dev`): plan 43's commands with `TMPDIR` named `p47-tN-…`; `cargo test -p saiife-daemon blind -p saiife-ipc -j 4 -- --test-threads=4`; `bash scripts/check-windows.sh -p saiife-daemon` (the `blind` module is `cfg(target_os = "linux")`; other targets keep compiling with the stub that answers the Linux-only message). Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit staging, no push, smoke `bash -n` only.

### Fixed values

| Name | Value |
|---|---|
| state | `<state>/blind/{datasets/<name>/{stage,live,keys.sealed,classes.json,loosen.json,methods.json},models/<sha256>,outbox/}` |
| vault service | `blind-model` (the model key's `allowed_services`) |
| system prompt id | `SYSTEM_PROMPT` const in `blind/model.rs`; its sha256 goes into every `blind_send` |
| ops (control socket, local) | `blind.status`, `blind.data.stage` (fd), `blind.data.commit`, `blind.data.refresh` (fd for file sources), `blind.data.rm`, `blind.ner.fetch`, `blind.methods.list`; plan 48 adds `blind.ask`, `blind.ask.answer`, `blind.touch.begin`, `blind.touch.commit` (names declared here) |
| refreshing answer | en `<dataset> is refreshing (<phase>, <done> of <total>); try again in a moment` · da `<dataset> opdateres (<phase>, <done> af <total>); prøv igen om lidt` |
| unavailable on other OS | `Data Shield runs on Linux in this release` |

## Review Focus

1. **A request leaving without its outbox entry or record** (disk full on the outbox, the audit writer refusing, a crash between the two). Expected: the send does not happen; the ask is refused with the reason (Task 6: `outbox_failure_blocks_send`, `record_failure_blocks_send`).
2. **Two refreshes, or a refresh racing an ask.** Expected: one build at a time per dataset (`busy`); an ask during a build gets the refreshing answer; an ask that started before the swap finishes on the old snapshot, whose file stays open (Task 2: `refresh_is_exclusive`, `ask_during_refresh_waits_out`).
3. **The vault locked or the key file damaged.** Expected: every keyed op refuses with `the vault is unavailable` or `the dataset keys cannot be opened: saiife blind keys delete --dataset <d> starts over`; nothing falls back to unkeyed stand-ins (Task 1: `vault_unavailable_refuses`, `damaged_keys_refuse`).
4. **A planner reply that is huge, not JSON, or holds a dataset value** (prompt injection in a column alias making the model echo a name it guessed). Expected: bounded read, `PlanError`, incoming firewall `Block` → the ask is refused as a leak and `blind_receive` has `leak: true` (Task 6: `incoming_leak_refuses`).
5. **A helper replaced by a writable file in personal mode** (`saiife-ner` beside a user-writable `saiife`). Expected: `check_helper` refuses group/world-writable files and dirs; status says why (Task 4: `unsafe_ner_helper_refused`).

---

### Task 1: the `blind` module, ops, state and the key store (size M)

**Files:**
- Create: `crates/daemon/src/blind/mod.rs`, `crates/daemon/src/blind/keys.rs`, `crates/daemon/src/blind/ops.rs`
- Modify: `crates/daemon/src/lib.rs:9-81` (`#[cfg(target_os = "linux")] pub mod blind;` and a stub module elsewhere), `crates/daemon/src/ops.rs:305-428` (`Ctx.blind`) and `:434` (`CtxInit.blind`), `crates/daemon/src/ops.rs:1350-1400` (dispatch arm `op if crate::blind::OPS.contains(&op) => crate::blind::ops::handle(ctx, conn, req).await`), `crates/daemon/src/start.rs` (build `Blind::open(&state_dir.join("blind"))` beside `TouchState::open`, `:1074`), `crates/ipc/src/msg.rs` (op constants; `FD_OPS` `:321` gains the two fd ops), `crates/daemon/Cargo.toml` (Linux target deps `saiife-shield`, `saiife-fido`, `tokio-postgres`)

**Interfaces:**
- Produces:
```rust
pub struct Blind { pub root: PathBuf, datasets: Mutex<BTreeMap<String, DatasetState>>, pub sessions: Mutex<saiife_shield::session::Sessions>, pub ner: ner::NerClient /* Task 4 */, pub asks: Mutex<ask::Asks> /* plan 48 */ }
pub enum DatasetState { Absent, Building { phase: Phase, done: u64, total: Option<u64>, started: Instant }, Live { manifest: Arc<Manifest>, open: Arc<LiveHandles> }, NeedsRefresh(String) }
pub struct LiveHandles { pub lexicon: Lexicon, pub index: Option<KnownIndex>, pub allow: AllowList }
impl Blind { pub fn open(root: &Path) -> Blind; pub fn dataset_dir(&self, name: &DatasetName) -> DatasetDir; pub fn live(&self, name: &DatasetName) -> Result<(Arc<Manifest>, Arc<LiveHandles>), Refusal>; }
pub struct Refusal { pub code: saiife_ipc::msg::ErrorCode /* BadRequest, Forbidden, Busy, Unavailable */, pub text: String }   // every blind op's error; `text` never holds a dataset value
impl Refusal { pub fn to_value(&self, id: u64) -> Value /* saiife_ipc::msg::err */ }
pub const OPS: &[&str];   // every blind.* name in the fixed-values table
// keys.rs
pub fn load(ctx: &Ctx, ds: &DatasetName) -> Result<KeySet, KeyError>;
pub fn create(ctx: &Ctx, ds: &DatasetName) -> Result<KeySet, KeyError>;           // refuses when keys.sealed exists
pub fn rotate(ctx: &Ctx, ds: &DatasetName) -> Result<u32 /* new version */, KeyError>;
pub fn shred(ctx: &Ctx, ds: &DatasetName) -> Result<(), KeyError>;                // R47-2
pub enum KeyError { VaultUnavailable, Damaged, Missing, Io(String) }
// ops.rs
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value;
pub(crate) async fn role(ctx: &Ctx, peer: &PeerCred, ds: Option<&BlindDataset>) -> Role;   // R47-3
pub enum Role { None, User, Approver, Admin }
```

- [ ] **Step 1: Write the failing tests** (`crates/daemon/tests/blind_keys.rs` and in-module): `keys_round_trip_sealed` (create → file 0600, bytes are not the `KeySet` JSON; load gives equal versions), `vault_unavailable_refuses`, `damaged_keys_refuse` (a flipped byte → `Damaged`), `rotate_keeps_retired`, `shred_removes_key_index_and_sessions` (sessions of the dataset gone; `NeedsRefresh`), `ops_registered` (every name in `OPS` dispatches to `blind::ops::handle`, and `blind.data.stage`/`blind.data.refresh` are in `FD_OPS`), `roles` (personal mode own user is Admin+Approver; locked: a user in `users` is User, in `approvers` Approver, in no list None; empty `approvers` falls back to `[approval] approvers`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `bash scripts/check-windows.sh -p saiife-daemon`.
- [ ] **Step 5: Commit** `feat(daemon): the blind module, its ops and the sealed dataset key store (plan 47 T1)`.

### Task 2: dataset import, commit, refresh and remove (size L)

**Files:** Create `crates/daemon/src/blind/data.rs`, `crates/daemon/src/blind/pg.rs`; Test: `crates/daemon/tests/blind_data.rs`

**Interfaces:**
- Consumes: Task 1; plan 43 `stage_snapshot`, `propose`, `finish`, `load_manifest`, `RowSource`, `CsvSource`, `XlsxSource`, `SqliteSource`; plan 45 `MethodStore::revalidate`.
- Produces (ops, JSON args → answers):
  - `blind.data.stage {dataset, kind: "csv"|"xlsx"|"sqlite"|"postgres", file_name?}` + 1 fd for file kinds → `{tables: [{name, rows_band, columns: [{name, type, guess, confidence, uncertain, public_refusal?, public_preview?: {passing: n, total: m}}]}]}`; records nothing yet (nothing left the machine and nothing is live).
  - `blind.data.commit {dataset}` (the dataset must now be in the reloaded policy) → builds lexicon, index (with `keys::create` or `load`), public values, allow list, swaps, writes `classes.json`, records `blind_refresh {dataset, snapshot_sha256, rows_band per table, index_entries, ms, first: true}` → `{manifest summary}`.
  - `blind.data.refresh {dataset}` (+ fd for file kinds) → `{started: true}` at once; the build runs on a blocking task; `status` shows the phase; at the end `blind_refresh {…, suspended: [method ids]}`.
  - `blind.data.rm {dataset}` → removes the dataset dir after `keys::shred`; `blind_keys {action: "delete", dataset, reason: "dataset removed"}`.
```rust
pub fn effective_schema(cfg: &BlindDataset, m: &Manifest, baseline: &Classes, grants: &[LoosenGrant]) -> (Schema, Vec<String> /* warnings */);   // R47-6
pub struct Classes(pub BTreeMap<String /* table.column */, ColumnClass>);
pub struct LoosenGrant { pub column: String, pub class: ColumnClass, pub touched_at: String, pub by: String }
pub struct PgSource { /* implements RowSource over the sync_channel bridge */ }
pub async fn pg_source(ctx: &Ctx, src: &BlindSource) -> Result<PgSource, String>;
```

- [ ] **Step 1: Write the failing tests** (personal-mode test daemon in `$TMPDIR`, fixture CSVs from plan 43's generator passed as fds): `stage_proposes` (uncertain list holds `status`, `segment`; `email` has `public_refusal`), `commit_needs_policy` (commit before the policy names the dataset → `bad_request: <d> is not in policy: write policy.d/blind-<d>.toml and reload`), `commit_builds_live` (manifest present, `classes.json` written, `blind_refresh` record without any cell value in it), `refresh_is_exclusive` (second refresh while one runs → `busy`), `ask_during_refresh_waits_out` (a fake ask probe gets the refreshing text with the phase), `refresh_suspends_broken_methods` (a stored method on a column the new CSV lacks → suspended and named), `loosen_without_grant_is_ignored` (policy changes `city` quasi → public without a grant: effective class stays quasi; warning text exact), `loosen_with_grant_applies_at_refresh`, `rm_shreds`, `pg_source_bridge` (a `PgSource` built over an in-memory channel fed by the test, no server: two-pass reads give the same rows; the live Postgres test is `#[ignore]` for the owner smoke).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): Data Shield dataset import, commit, refresh and removal (plan 47 T2)`.

### Task 3: records, the outbox and the log scrub (size M)

**Files:** Create `crates/daemon/src/blind/audit.rs`, `crates/daemon/src/blind/outbox.rs`; Modify `crates/daemon/src/audit_query.rs:45` (`USER_KINDS` gains the `blind_*` kinds; the array's type becomes a slice); Test: in-module and `crates/daemon/tests/blind_audit.rs`

**Interfaces:**
- Produces:
```rust
pub enum BlindRecord {
    Ask { ask: String, dataset: String, lang: Lang, question: String /* parameterized, symbols as stand-ins */, session: String, approved_method: Option<String> },
    Resolve { ask: String, params: Vec<(String /* tag */, u32 /* candidates */)>, did_you_mean: u32, kept_names: u32 },
    Preview { ask: String, sha256: String, outcome: &'static str /* shown|accepted|stopped|auto */, fragments: u32 },
    Send { ask: String, envelope_sha256: String, body_sha256: String, prompt_sha256: String, model: String, tables: u32, synthetic_rows: u32, params: u32, personal_values: u32, k: u32, attempt: u32 },
    Receive { ask: String, status: u16, bytes: u64, reply_sha256: String, leak: bool, stop_reason: String },
    Run { ask: String, method: String /* sha256 or approved id */, snapshot_sha256: String, ms: u64, rows_band: String, calculator: &'static str /* CALC_LABEL */, landlock_abi: u32, seccomp: bool, netns: bool },
    CheckRefused { ask: String, reason: String /* class or checker reason */ },
    Approve { method: String, version: u32, dataset: String, template_sha256: String, touch: String, action: &'static str /* add|remove */ },
    Keys { dataset: String, action: &'static str /* create|rotate|delete */, version: u32, touch: Option<String> },
    Refresh { dataset: String, snapshot_sha256: String, rows: Vec<(String, String)>, index_entries: u64, ms: u64, suspended: Vec<String>, first: bool },
    Loosen { dataset: String, column: String, from: ColumnClass, to: ColumnClass, touch: String },
    Name { ask: String, touch: String, name_sha256: String },
}
pub async fn write(ctx: &Ctx, uid: u32, r: BlindRecord, index: Option<&KnownIndex>) -> Result<(), String>;   // R47-10 scrub, then ctx.writer.append(ctx.record("blind_*", …) with extra fields)
pub struct Outbox { /* dir */ } impl Outbox { pub fn append(&self, e: &OutboxEntry) -> io::Result<()>; pub fn purge(&self, now: SystemTime, days: u32) -> io::Result<u32>; pub fn find(&self, sha256: &str) -> io::Result<Option<OutboxEntry>>; }
pub struct OutboxEntry { pub ts: String, pub sha256: String, pub uid: u32, pub dataset: String, pub ask: String, pub body: String }
```
  The record's `input` field is the kind and dataset (`blind_send crm`), never a question. `name_sha256` is a keyed hash with the dataset index key, so equal names can be linked locally but not read.

- [ ] **Step 1: Write the failing tests:** `records_have_no_values` (write each variant with fixture data; the audit file holds no fixture name, email or amount), `scrub_drops_and_marks` (an `Ask.question` that holds a rare fixture name → field dropped, `blind_log_scrubbed {kind: "blind_ask", field: "question"}`), `outbox_append_fsync_0600`, `outbox_purge_by_month`, `outbox_find`, `user_sees_own_blind_records` (an `audit.query` by the asker returns its `blind_*` records; another uid's are not returned).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): Data Shield audit records, the outbox and the log scrub (plan 47 T3)`.

### Task 4: the name-detector model fetch and helper client (size M)

**Files:** Create `crates/daemon/src/blind/ner.rs`; Test: `crates/daemon/tests/blind_ner.rs`

**Interfaces:**
- Consumes: plan 46 `ner_proto`, `saiife-fake-ner`; `saiife_fido::client::check_helper`; `ctx.upstream` (`Upstream::send`, `crates/broker/src/upstream.rs:397`).
- Produces:
```rust
pub struct NerFiles { pub model: PathBuf, pub vocab: PathBuf, pub labels: PathBuf }
pub async fn fetch(ctx: &Ctx, cfg: &NerCfg) -> Result<NerFiles, String>;   // op blind.ner.fetch: GET each https URL (Built, read limit cfg.max_bytes), sha256 must equal the pin, write <blind>/models/<sha256> (0400, temp+rename); an existing file whose hash matches is reused; a mismatch deletes the temp file
pub fn present(root: &Path, cfg: &NerCfg) -> Result<NerFiles, String>;    // re-hash on every helper start (spec §2.4 "checked on every start")
pub struct NerClient { /* Mutex<Option<Helper>>, restarts window */ }
impl NerClient { pub fn new() -> NerClient; pub fn configure(&self, files: Option<NerFiles>, mode: Mode, own_uid: u32); pub fn state(&self) -> NerState; }
impl saiife_shield::ner::NameDetector for NerClient { fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError> }   // blocking; called from spawn_blocking; hello ≤ 60 s, answer ≤ 5 s, at most 3 restarts per minute, then Unavailable
pub enum NerState { NotConfigured, Missing(String), Ready { pid: u32, labels: Vec<String> }, Failed(String) }
```
- [ ] **Step 1: Write the failing tests:** `fetch_checks_hash` (a loopback HTTPS upstream with an rcgen cert and `Upstream::with_ca_file`, as the existing broker tests do: right hash → file 0400; wrong → error, no file), `present_rehashes` (a changed byte → `Missing`), `client_detects_with_fake` (`SAIIFE_TEST_NER_HELPER` = the built `saiife-fake-ner` with a phrases file → spans with Danish offsets), `client_restarts_then_gives_up` (a helper that exits after hello: three restarts then `Unavailable`), `answer_timeout` (a helper that never answers → `Unavailable` after 5 s seam-shortened), `unsafe_ner_helper_refused` (personal mode, helper file mode 0666 → `Failed` naming the reason).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): pinned name-detector model fetch and the saiife-ner client (plan 47 T4)`.

### Task 5: the calculator client (size S)

**Files:** Create `crates/daemon/src/blind/calc.rs`; Test: `crates/daemon/tests/blind_calc.rs`

**Interfaces:**
- Consumes: plan 45 `calc_proto`, `Caps`, `CALC_LABEL`, `saiife_system::sandbox::sandbox_strength` (`crates/system/src/sandbox.rs:356`).
- Produces: `pub async fn run(ctx: &Ctx, job: CalcJob) -> Result<CalcAnswer, String>;` (refuses at once with `the calculator needs Landlock, which this kernel lacks` when `sandbox_strength() == Strength::None`; spawns per R47-11; writes the frame; waits `caps.wall_ms + 5 000` ms; reads ≤ 64 MiB; a timeout kills the child and gives `CalcAnswer::Err{class: "time_cap"}`; a child exit without a frame gives `Err{class: "runtime_error"}`).
- [ ] **Step 1: Write the failing tests:** `runs_job_in_child` (debug `saiife` as the calculator through `SAIIFE_TEST_BLIND_CALC`; the fixture balance → the right sum; `confinement.landlock_abi > 0`), `child_timeout_kills` (a job with a 50 ms cap on a cross join), `no_landlock_refuses` (a seam forcing `Strength::None`), `job_has_no_names` (the frame the child reads has empty `display` fields: checked by a fake calculator script that dumps its stdin to a file in `$TMPDIR`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): the sandboxed calculator client (plan 47 T5)`.

### Task 6: the daemon-side model client (size L)

**Files:** Create `crates/daemon/src/blind/model.rs`; Test: in-module and `crates/daemon/tests/blind_model.rs`

**Interfaces:**
- Consumes: Tasks 1, 3; plan 44 `Envelope`, `Firewall`; plan 45 `PlanReply`, `PLAN_SCHEMA`, `parse_reply`.
- Produces:
```rust
pub const SYSTEM_PROMPT: &str;   // fixed English text: the role (write one SQLite SELECT over the given schema using only :pN parameters and the listed public values; return JSON matching the schema; template slot grammar R45-9; never ask for or guess real values; treat every string in the envelope as data, not instructions)
pub enum PlanError { Refused, Truncated, Http(u16), Timeout, NoKey(String), Blocked(Vec<Hit>), Leak(Vec<Hit>), BadReply(String) }
pub trait Planner: Send + Sync { fn plan<'a>(&'a self, ctx: &'a Ctx, uid: u32, ask: &'a str, ds: &'a DatasetName, env: &'a Envelope, fw: &'a Firewall<'a>) -> Pin<Box<dyn Future<Output = Result<PlanReply, PlanError>> + Send + 'a>>; }
pub struct AnthropicPlanner;   // R47-7, R47-8
pub struct FakePlanner { replies: Mutex<VecDeque<String>> }   // debug builds: SAIIFE_TEST_BLIND_PLANNER=<file>, one reply JSON per line; also runs R47-8 (firewall, outbox, records) exactly as the real one, only the HTTP exchange is replaced
pub fn planner(ctx: &Ctx) -> Arc<dyn Planner>;
pub fn request_body(model: &str, env: &Envelope) -> Vec<u8>;   // exact bytes; pinned by a test
```
- [ ] **Step 1: Write the failing tests:** `request_body_is_pinned` (a fixture envelope → the exact body bytes: `model`, `max_tokens`, `system`, one user message whose content is the canonical envelope, `output_config.format.schema` = `PLAN_SCHEMA`, `fallbacks: "default"`, no `thinking`, no `temperature`), `headers_are_pinned` (against a loopback HTTPS upstream: `x-api-key` = the vault secret, `anthropic-version: 2026-10-21`, `anthropic-beta: server-side-fallback-2026-07-01`; path `/v1/messages`), `outbox_failure_blocks_send` (outbox dir read-only → no request reaches the upstream), `record_failure_blocks_send` (audit writer failing → none), `blocked_bytes_never_sent` (an envelope that passes but a body that holds a rare fixture name through a tampered `SYSTEM_PROMPT` seam → `Blocked`, no request), `refusal_stop_reason` (`{"stop_reason":"refusal"}` → `Refused`, not retried), `retry_on_429_once`, `incoming_leak_refuses` (a reply whose `method` quotes a fixture email → `Leak`, `blind_receive.leak == true`), `no_key_refuses` (secret missing, or not allowing `blind-model` → `NoKey` with `saiife secret add <name> --kind token --service blind-model`), `subscription_never_used` (a `Kind::OAuth2` or non-token secret → `NoKey`), `fake_planner_scripts_replies`; plus `#[ignore] live_planner_answers` (reads `SAIIFE_BLIND_LIVE_KEY_FILE`, sends one fixture envelope to the real API, asserts the reply parses and validates; owner smoke only).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): the daemon-side Anthropic model client behind the leak firewall (plan 47 T6)`.

### Task 7: `blind.status`, `blind.methods.list` and the daemon smoke (size S)

**Files:** Modify `crates/daemon/src/blind/ops.rs`; Create `scripts/blind-smoke.d/50-daemon.sh`; Test: `crates/daemon/tests/blind_status.rs`

**Interfaces:**
- Produces: `blind.status {}` → `{datasets: [{name, state, rows: [[table, band]], snapshot_sha256, built_at, keys_version, methods: {active, suspended: [{id, reason}]}, warnings: [..], role}], calculator: {label: CALC_LABEL, landlock: Strength::as_str, gap?}, ner: {state, labels?}, cloud: {secret_present: bool, model}, sessions: {yours: n}}` (only datasets the caller has a role on; admins see all); `blind.methods.list {dataset}` → `{methods: [{id, version, lang, template_key, param_tags, approved_by, approved_at, status}]}` (users and approvers of the dataset).
- [ ] **Step 1: Write the failing tests:** `status_shows_weaker_label` (the exact `calculator not in a box (weaker)` text), `status_scoped_by_role` (bob without a role sees no `crm`), `status_reports_ner_and_cloud`, `methods_list_scoped`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; `50-daemon.sh`: `smoke_daemon` starts a personal daemon (`saiife daemon --user`) with HOME/XDG in the smoke work dir, runs the `#[ignore]` live tests (`live_planner_answers` with `SAIIFE_BLIND_SMOKE_KEY_FILE`, the live Postgres one with `SAIIFE_BLIND_SMOKE_PG_SOCKET` when set), and records the hook bench (`bash scripts/bench-check.sh`, never `--managed`) before/after numbers the plan reported.
- [ ] **Step 4: Run** → PASS; `bash -n scripts/blind-smoke.d/50-daemon.sh`; `bash scripts/bench-check.sh` (record numbers in the report).
- [ ] **Step 5: Commit** `feat(daemon): blind.status and the daemon smoke (plan 47 T7)`.

---

## Owner smoke fragment (plan 47)

`scripts/blind-smoke.d/50-daemon.sh` (`bash scripts/blind-smoke.sh --only daemon`): personal daemon, the real Anthropic API with the owner's key file (one synthetic envelope, nothing personal), optional local Postgres, hook latency. Builders: `bash -n` only.

## Stage-1 dependency and parallel map (plans 43–48)

```
W1  43.T1 crate + shared types
W2  43.T2 policy/touch · 43.T3 snapshot · 44.T1 lang · 44.T2 stand-ins/sessions · 45.T1 validator · 46.T1 tokenizer · 46.T2 tract runtime
W3  43.T4 classify · 43.T5 lexicon · 43.T6 index · 44.T4 synthetic rows (needs 43.T4) · 45.T2 preview · 45.T4 templates · 45.T5 checker (need 44.T1) · 45.T3 executor (needs 43.T3) · 45.T6 approved methods
W4  43.T7 dataset build · 44.T3 parameterize (needs 43.T5) · 45.T7 calculator process + sandbox (needs 45.T3)
W5  44.T5 envelope + firewall (needs 43.T6, 44.T3, 44.T4) · 46.T3 helper binary (needs 45.T7 sandbox) · 46.T4 packaging
W6  47.T1 then 47.T2–T6 in parallel, then 47.T7   (needs all of 43, 44.T2, 44.T5, 45.T7, 46.T3)
W7  48.T1 → 48.T2 → 48.T3; 48.T4/T5 after 48.T3; 48.T6 after 48.T5; 48.T7 last
```
