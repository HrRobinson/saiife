# Plan 8 — Audit v2 + hash chain (developer mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every audit record becomes a v2 record chained to the one before it by SHA-256, and `saiife audit verify` reports any edit, deletion, insertion or reordering — in developer mode, on Linux and macOS.

**Architecture:** The `audit` crate gains the v2 record fields (`record.rs`), a chained
appender that serializes writers with an exclusive lock on `<audit dir>/.chain.lock`
(`chain.rs`), and a verifier that re-hashes the exact line bytes (`verify.rs`). The CLI
hook path writes through the chained appender with a `policy` hash and the agent's
`permission_mode`; a new `saiife audit verify` subcommand and three new report sections
read it. No daemon, no signing key (both are plan 9).

**Tech Stack:** Rust workspace (`audit`, `guard`, `cli` crates); new deps `sha2`,
`getrandom`, `rustix` (feature `process`); GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md` — §6.4.1 (chain),
§6.4.3 (verify), §6.4.4 (developer mode), §8.5 (record v2), §8.6 (genesis), §6.19
(report: chain status, policy per period, mode per host), §11, §12 step 1, §13 (chain tests).

## Global Constraints

- `prev` is the lowercase hex SHA-256 of the **exact bytes of the previous line**, without its newline. No canonical JSON.
- Record 0 of a chain is `kind = "genesis"`, `seq` 0, `prev` = 64 `0` characters, a random UUID v4 `chain`, and `host` = lowercase hex SHA-256 of `/etc/machine-id` (Linux; fallback `/var/lib/dbus/machine-id`) or of the macOS `IOPlatformUUID` — never the raw value. No `key` field in developer mode.
- New records are `v = 2`. v1 fields `agent`, `project`, `tool`, `input`, `decision`, `saiife` are **always present** (0.1.0 readers must show every record); for non-guard kinds `tool` is the kind and `input` is `""`.
- `saiife audit verify` exit codes: 0 intact, 1 a break was found, 2 the log could not be read. v1 files are listed as "not chained (v1)", never as failures.
- The audit log stays best-effort: an audit failure never changes a guard verdict (v1 spec §1.2). The hook stays inside its 50 ms budget: the appender reads at most the last 256 KiB of a month file on the hook path.
- `mode` is always `"developer"` in this plan. No signing, no checkpoints written, no daemon.
- Tests point HOME, PATH, SAIIFE_DATA_DIR, SAIIFE_AUDIT_DIR at tempdirs; never run `saiife init` against the real home or the repo. Stage explicit paths; scratch under `mktemp -d -p /home/jonas/projects/personal/saiife`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. Two hooks write at the same moment (an agent running tools in parallel, or two agents): the chain must stay intact — Task 2 `parallel_appends_keep_the_chain`, Task 4 `parallel_hooks_then_verify_is_intact`.
2. The clock jumps back across a month boundary: the record must go to the newest month file, not an older one, so name order still equals chain order — Task 2 `clock_going_back_writes_to_newest_file`.
3. A crash left a half-written last line: the next append still works, and `verify` reports exactly one problem, at that line — Task 2 `partial_last_line_is_terminated`, Task 3 `partial_line_is_one_break`.
4. Upgrade from 0.1.x with existing v1 files: the chain starts with a genesis after them, `verify` exits 0 and lists the v1 files — Task 2 `genesis_after_v1_files`, Task 4 `upgrade_from_v1_log`.
5. Downgrade to 0.1.x and back: v1 lines inside a chain, then a second genesis — `verify` exits 1 and says the chain restarted (that is also what an attacker restarting the chain looks like) — Task 3 `v1_line_inside_chain_and_restart`.

---

### Task 1: Record v2 format

**Files:**
- Modify: `crates/audit/src/record.rs`, `crates/audit/src/store.rs` (`Filter::matches`), `crates/audit/src/lib.rs`
- Modify: callers of `NewRecord` in `crates/cli/src/{check.rs,audit_cmd.rs,report.rs}` (tests too) — new fields set to `None` / `"developer"` for now
- Test: unit tests in `record.rs` and `store.rs`

**Interfaces:**
- Produces:
  - `pub const RECORD_VERSION: u32 = 2;`
  - `DecisionKind` gains `ErrorDenied`, `Ask`, `Approved`, `Rejected`, `Expired` (snake_case), `Unknown` stays `#[serde(other)]`.
  - `Record` gains, in this serialization order around the v1 fields: `v, seq, prev, ts, kind, host, uid, user, mode, policy, agent, project, session, tool, input, decision, pack, rule, reason, permission_mode, saiife`, then `extra`. New fields: `seq: Option<u64>`, `prev: Option<String>`, `kind: Option<String>`, `host: Option<String>`, `uid: Option<u32>`, `user: Option<String>`, `mode: Option<String>`, `policy: Option<String>`, `permission_mode: Option<String>`, each `#[serde(default, skip_serializing_if = "Option::is_none")]`; `extra: BTreeMap<String, serde_json::Value>` with `#[serde(flatten)]` (keeps `chain`, `key`, future fields). v1 optional fields (`session`, `pack`, `rule`, `reason`) keep serializing as `null` as today.
  - `NewRecord` gains `mode: &'a str`, `policy: Option<&'a str>`, `permission_mode: Option<&'a str>`. `Record::new`/`at` set `kind = Some("guard")`; `seq`, `prev`, `host`, `uid`, `user` stay `None` (the appender fills them). `permission_mode` is masked and cut to 64 chars.
  - `impl Record { pub fn kind(&self) -> &str }` (`"guard"` when `None`) and `pub fn is_bookkeeping(&self) -> bool` (kind is `genesis`, `checkpoint` or `key_rotate`).
  - `Filter::matches` returns false for bookkeeping records, so `saiife audit`, `status` and the report never show or count them.

- [ ] **Step 1: Failing tests** in `record.rs`: `v2_guard_record_field_order` (serialize a `Record::at` with fixed time; assert the JSON starts `{"v":2,"ts":` … and contains `"kind":"guard","mode":"developer"` and no `"seq"` key), `v1_line_still_parses` (the existing v1 line: `kind()` is `"guard"`, `seq` is `None`), `unknown_fields_round_trip` (parse `{"v":2,…,"chain":"abc","future":1}` and re-serialize: both keys kept), `new_decisions_parse` (each of `error_denied`, `ask`, `approved`, `rejected`, `expired`; `"later"` → `Unknown`), `genesis_is_bookkeeping`. In `store.rs`: `filter_hides_bookkeeping`.
- [ ] **Step 2:** `cargo test -p saiife-audit` — fails to compile / fails.
- [ ] **Step 3:** Implement; update every `NewRecord { … }` in the workspace (`mode: "developer"`, `policy: None`, `permission_mode: None`).
- [ ] **Step 4:** `cargo test --workspace` green; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 5:** Commit `feat(audit): record v2 fields`.

### Task 2: Chained appender

**Files:**
- Create: `crates/audit/src/chain.rs`
- Modify: `crates/audit/src/lib.rs`, `crates/audit/src/store.rs` (make `month_files`, `read_regular`, `create_private_dir`, `is_month_file` `pub(crate)`), `crates/audit/Cargo.toml` (`sha2 = "0.10"`, `getrandom = "0.3"`, unix-only `rustix = { version = "1", features = ["process"] }`)
- Test: unit tests in `chain.rs`

**Interfaces:**
- Consumes: Task 1 `Record`, `RECORD_VERSION`.
- Produces:
  - `pub const ZERO_PREV: &str` (64 × `0`), `pub const LOCK_FILE: &str = ".chain.lock"`.
  - `pub fn sha256_hex(bytes: &[u8]) -> String` (lowercase hex).
  - `pub fn host_id() -> Option<String>` (Global Constraints; macOS: parse `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice`; `None` if unavailable).
  - `pub fn append_chained(dir: &Path, rec: Record) -> io::Result<u64>` — returns the record's `seq`.

**Behaviour of `append_chained`** (all inside the lock):
1. Create the dir (0700, as `store::append`). Open/create `dir/.chain.lock` 0600 with `O_NOFOLLOW`; refuse a non-regular file. Lock with `File::try_lock()` retried every 5 ms for at most 1 000 ms.
2. Pick the target file: `max(rec.month(), newest existing month file name)` — never an older file than the newest.
3. Find the tail: read at most the last 256 KiB of the newest non-empty month file (read the whole file only if that window holds no complete line). If the file does not end with `\n`, write `\n` first (a crash left a half line; it stays, as a line). `prev` = `sha256_hex` of the last line's bytes. `seq` = 1 + the `seq` of the last line in the tail that parses as `v >= 2` with a `seq`, scanning backwards; the scan stops at a v1 line.
4. If no such line exists (empty dir, only v1 lines, or a v1 line is newer than any chained one): first append a genesis record (Global Constraints; `ts` now, `tool`/`kind` `"genesis"`, `decision` allow, `agent`/`project`/`input` `""`, `chain` in `extra`, `prev` = `ZERO_PREV`), then the record with `seq` 1 and `prev` = hash of the genesis line.
5. Fill `seq`, `prev`; `host` from the last chained record (from `host_id()` only at genesis); `uid` (rustix `getuid`) and `user` (`$USER`, else `$LOGNAME`, else none) only when `None`. Write `line + "\n"` with one `write_all` on an `O_APPEND | O_NOFOLLOW | O_NONBLOCK` handle (as `store::append`), refusing a non-regular file.
6. If the lock cannot be opened or taken in time: write the record **unchained** (`v` 2, no `seq`/`prev`) with `store::append` and return `Err(io::Error::other("audit chain lock unavailable; record written unchained"))`, so the caller warns and `verify` later reports it.

UUID v4: 16 bytes from `getrandom`, set version/variant bits, format `8-4-4-4-12` lowercase.

- [ ] **Step 1: Failing tests** in `chain.rs` (each with a tempdir): `first_append_writes_genesis_then_seq_1` (two lines; line 1 `kind` genesis, `seq` 0, `prev` == `ZERO_PREV`, `chain` is a UUID v4; line 2 `seq` 1, `prev` == `sha256_hex(line1)`), `seq_increments_across_month_files` (records dated 2026-10 then 2026-11 → second file's first line chains to the first file's last line), `genesis_after_v1_files` (a pre-existing raw v1 line in `2026-09.jsonl` → new chain starts with genesis, v1 file untouched byte-for-byte), `partial_last_line_is_terminated` (file ends in `{"v":2,"se` without newline → after append the file has that half line, a `\n`, then the new record whose `prev` is the hash of the half line and whose `seq` is last good seq + 1), `clock_going_back_writes_to_newest_file` (existing `2026-11.jsonl`, record dated 2026-10 → appended to `2026-11.jsonl`), `parallel_appends_keep_the_chain` (8 threads × 50 appends → 401 lines, seqs 0..=400 in file order, every `prev` matches), `symlinked_lock_file_falls_back_unchained` (lock path is a symlink → `Err`, record present without `seq`), `sha256_hex_known_vector` (`sha256_hex(b"abc")` == `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`).
- [ ] **Step 2:** `cargo test -p saiife-audit chain` — fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(audit): hash-chained appender with a lock file`.

### Task 3: Verifier + tamper tests + 0.1.0 reader compatibility

**Files:**
- Create: `crates/audit/src/verify.rs`, `crates/audit/tests/tamper.rs`, `crates/audit/tests/v010_reader.rs`, `crates/audit/tests/fixtures/v2/2026-11.jsonl`
- Modify: `crates/audit/src/lib.rs`

**Interfaces:**
- Consumes: Task 2 `sha256_hex`, `ZERO_PREV`, `append_chained`; `store::month_files`, `read_regular`.
- Produces:
  - `pub fn verify(dir: &Path) -> VerifyReport`
  - `pub struct VerifyReport { pub chained: u64, pub v1_records: u64, pub v1_files: Vec<String>, pub chain: Option<String>, pub head: Option<(u64, String)>, pub checkpoints: u64, pub breaks: Vec<Break>, pub read_errors: Vec<String> }` with `pub fn exit_code(&self) -> u8` (2 if `read_errors` non-empty, else 1 if `breaks` non-empty, else 0) and `pub fn first_break(&self) -> Option<&Break>`.
  - `pub struct Break { pub file: String /* file name only */, pub line: usize /* 1-based */, pub seq: Option<u64>, pub kind: BreakKind }`
  - `pub enum BreakKind { Unparseable, Unchained, SeqGap { expected: u64, found: u64 }, PrevMismatch, BadGenesis, MissingGenesis, ChainRestarted, V1InsideChain }` with `fn describe(&self) -> String` giving the plain-language text in the table below.

**Algorithm** (files in name order; a missing dir is an empty, intact log; an unlistable dir, a non-regular or unreadable month file → `read_errors`):
- Split each file on `\n`; a final segment without `\n` is still a line. Every line, even a bad one, becomes the "previous line" for the next.
- Parse as JSON. Fails → `Unparseable`. `v` is 1 or missing → before any genesis: count as v1; after a genesis: `V1InsideChain`. `v >= 2` without `seq` → `Unchained`.
- `kind == "genesis"`: `seq != 0` or `prev != ZERO_PREV` → `BadGenesis`; a genesis after an earlier one → `ChainRestarted`. Either way it starts the expectation over at seq 1 and sets `chain`.
- Other chained lines: no genesis seen yet → `MissingGenesis` (once), then adopt its seq; else `seq != expected` → `SeqGap`; `prev != sha256_hex(previous line)` → `PrevMismatch`. Then expected = seq + 1, `head` = (seq, hash of this line). Count `kind == "checkpoint"` in `checkpoints` (signatures are checked from plan 9).
- A file whose lines are all v1 goes into `v1_files`.

| BreakKind | `describe()` |
|---|---|
| Unparseable | `not a valid record (edited, or a write was cut off)` |
| Unchained | `record written without the chain (the chain lock was unavailable)` |
| SeqGap | `expected seq {expected}, found {found} (records were deleted, inserted or moved)` |
| PrevMismatch | `does not follow the line before (a line was edited, deleted, inserted or moved)` |
| BadGenesis | `chain start record is malformed` |
| MissingGenesis | `the start of the chain is missing (the oldest records were deleted)` |
| ChainRestarted | `a new chain starts here (older saiife version, or the log was rewritten)` |
| V1InsideChain | `v1 record inside the chain (written by saiife 0.1.x after an upgrade)` |

- [ ] **Step 1: Failing tests** in `crates/audit/tests/tamper.rs`; each builds a log with `append_chained` (genesis + 20 records over two month files), tampers, and asserts `exit_code()` and the first break's `file`, `line`, `kind`:
  - `intact_log_verifies` (0; `chained` 21; `head.0` 20), `edit_one_byte` (flip one char in record 10's `input` → `PrevMismatch` at the line after it), `delete_a_line` (`SeqGap`), `insert_a_copied_line` (`SeqGap`), `reorder_two_lines` (`SeqGap`), `swap_month_files` (swap the two files' contents → break reported, exit 1), `delete_oldest_file` (`MissingGenesis`), `partial_line_is_one_break` (cut the last line in half, append once more → exactly one break, `Unparseable`), `v1_line_inside_chain_and_restart` (write a raw v1 line at the end of the log, then `append_chained` twice — it starts a new genesis by itself → breaks `V1InsideChain` then `ChainRestarted`, exit 1), `v1_only_log_is_not_a_failure` (0; `v1_files` == `["2026-09.jsonl"]`), `unreadable_file_is_exit_2` (unix: chmod 000, skip as root), `truncated_tail_is_not_detected_without_checkpoints` (drop the last 3 lines → exit 0; the test comment says this needs a forwarded checkpoint, spec §6.4.2, plan 12).
- [ ] **Step 2:** Generate `tests/fixtures/v2/2026-11.jsonl` once (genesis + 4 guard records incl. one `deny` with pack/rule and one `error_denied`, plus one record of unknown kind `"connector"` with extra fields `service`/`status`), and commit it as a static file. Test `fixture_verifies` asserts exit 0 on it.
- [ ] **Step 3:** `crates/audit/tests/v010_reader.rs`: a frozen copy of 0.1.0's `Record` and `DecisionKind` (from tag `v0.1.0`, `git show v0.1.0:crates/audit/src/record.rs`), test `v010_reader_parses_every_v2_line` parses every fixture line with it — no line fails.
- [ ] **Step 4:** Implement `verify.rs`; `cargo test -p saiife-audit` green, clippy clean.
- [ ] **Step 5:** Commit `feat(audit): verify the hash chain`.

### Task 4: Hook writes the chain; `saiife audit verify`

**Files:**
- Modify: `crates/guard/src/payload.rs` (`HookContext.permission_mode: Option<String>` from the top-level `permission_mode` string), `crates/cli/src/check.rs`, `crates/cli/src/main.rs`, `crates/cli/src/audit_cmd.rs`
- Test: `crates/cli/tests/audit_verify.rs`, `crates/cli/tests/check_audit.rs` (extend), payload unit test

**Interfaces:**
- Consumes: Task 1 `NewRecord` fields; Task 2 `append_chained`, `sha256_hex`; Task 3 `verify`, `VerifyReport`.
- Produces: `fn policy_hash(version: &str, active_pack_ids: &[&str], project_config: Option<&[u8]>) -> String` in `check.rs`, returning `sha256:<hex>` of exactly:
  ```
  saiife-policy-v1\nsaiife <version>\npacks <sorted unique ids joined by ",">\nconfig <sha256_hex of the project's .saiife/config.toml bytes, or "none">\n
  ```
  `engine_for` also returns the active pack ids and the project root so `Audit` can compute it once per hook call.

- [ ] **Step 1: Failing tests:**
  - payload: `permission_mode_is_read` (Claude fixture `bash-deny.json` → `Some(..)`), absent → `None`.
  - `check_audit.rs`: `hook_record_is_v2_chained` (one `saiife check` call with a Claude payload → the audit dir holds a genesis line and a guard line with `"v":2`, `"seq":1`, `"mode":"developer"`, `"policy":"sha256:` + 64 hex, `"permission_mode"` as in the payload, `"uid"` present on unix).
  - `policy_hash_changes_with_config` (unit, `check.rs`): same inputs → same hash; different config bytes, or an added pack id → different hash; pack order does not matter.
  - `audit_verify.rs`: `verify_empty_log_exit_0`, `parallel_hooks_then_verify_is_intact` (spawn 6 `saiife check` processes at once, 5 calls each → `saiife audit verify` exit 0, stdout starts `audit chain: intact`), `edited_log_exit_1` (stdout contains `BROKEN` and `line`), `unreadable_log_exit_2`, `upgrade_from_v1_log` (pre-seeded v1 file + one hook call → exit 0, stdout contains `not chained (v1)`), `verify_prints_no_record_content` (a hook call whose command contains `\u001b[31m` → `saiife audit verify` stdout has no ESC byte and no command text).
- [ ] **Step 2:** Run — fail.
- [ ] **Step 3:** Implement. `Audit::write` calls `append_chained`; on `Err` it warns as today (`audit write failed (…); decision unaffected`). `main.rs`: `Audit` gets an optional subcommand `verify` (`args_conflicts_with_subcommands`); `saiife audit verify` reads `store::default_dir()`. Output (paths through `text::sanitize`, at most 20 breaks then `… and N more`):
  ```
  audit chain: intact
    records: 1043 chained (seq 0–1042), chain 6f1e2a…
    not chained (v1): 2026-09.jsonl, 2026-10.jsonl
    developer mode: no signing key, so this catches accidental edits, not deliberate rewrites.
  ```
  ```
  audit chain: BROKEN (2 problems)
    2026-11.jsonl line 17, seq 1040: does not follow the line before (a line was edited, deleted, inserted or moved)
  ```
  ```
  audit chain: could not read the log: <error>
  ```
  The last line of the intact form is printed while `checkpoints == 0`.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(cli): chained audit records and saiife audit verify`.

### Task 5: Report additions, docs, CI compatibility job

**Files:**
- Modify: `crates/cli/src/report.rs`, `crates/cli/src/report_html.rs`, `crates/cli/src/audit_cmd.rs`
- Modify: `.github/workflows/ci.yml` (new job `compat-0.1.0`), `README.md` (audit section), docs that show the v1 record format (find with `grep -rln '"v":1' docs/`), `docs/threats.md` (chain limits), `CHANGELOG.md` (`## Unreleased`)
- Test: `crates/cli/src/report.rs` unit tests, `crates/cli/tests/audit_report.rs`

**Interfaces:**
- Consumes: Task 3 `verify`, `VerifyReport`, `Break::describe`; Task 1 `Record.policy`, `host`, `mode`.
- Produces: `Report` gains `pub chain: String` (one line: `intact (N records)`, `broken: <file> line <n>: <describe>`, `could not be read`, or `no chained records yet`), `pub last_checkpoint: String` (`none` in developer mode), `pub policies: Vec<PolicyPeriod>` (`policy` shortened to `sha256:` + 12 hex, `from`, `to` as minute times, `records`), ordered by `from`; consecutive records with the same policy form one period), `pub modes: Vec<HostMode>` (`host` 12 hex or `unknown`, `mode` or `unknown` for v1 records, `records`).

- [ ] **Step 1: Failing tests:** `report_shows_chain_status` (intact log → `chain` starts `intact`; edited → starts `broken: `), `policy_periods_split_on_change` (records with policies A, A, B, A → 3 periods), `modes_per_host` (v1 + v2 records → `unknown`/`unknown` and `<host>`/`developer` rows), and in `audit_report.rs` `html_report_has_chain_policy_mode_sections` (headings `Audit chain`, `Policy in force`, `Mode per host` present; hostile `policy` string is escaped).
- [ ] **Step 2:** Run — fail. **Step 3:** Implement; HTML sections follow the existing section markup and stay free of network resources.
- [ ] **Step 4:** CI job `compat-0.1.0` (ubuntu-latest, actions pinned as in the other jobs, `persist-credentials: false`): download `saiife-0.1.0-x86_64-unknown-linux-musl.tar.gz` from the v0.1.0 release with `curl --proto '=https' --tlsv1.2 -fsSL`, check sha256 `3f5b0d344794d880f87a62c4c30d96166d885046d688e7d09e9312b09a6e1e93`, extract only `saiife`, run `SAIIFE_AUDIT_DIR=crates/audit/tests/fixtures/v2 HOME=$(mktemp -d) ./saiife audit`, and fail unless it exits 0, prints one row per fixture line, and stderr has no skipped-lines warning (match the wording in 0.1.0's `audit_cmd.rs`).
- [ ] **Step 5:** Docs: README gets `saiife audit verify` (one paragraph: what it catches, exit codes, the developer-mode limit); docs showing the record format show a v2 line; `docs/threats.md` "Limits" gains: in developer mode anyone with the user's rights can rewrite the whole chain consistently, and cutting off the newest records is not detectable without a forwarded checkpoint (locked mode, v2). CHANGELOG `## Unreleased`: record v2 with hash chain, `saiife audit verify`, report sections.
- [ ] **Step 6:** `cargo test --workspace`, clippy, `cargo test -p saiife-guard --test docs_pages` green. Commit `feat(report): chain status, policy periods, mode per host; docs; 0.1.0 compat CI`.
