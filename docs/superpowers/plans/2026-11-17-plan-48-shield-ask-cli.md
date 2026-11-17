# Plan 48: Data Shield ask flow, touches and the `saiife blind` CLI (stage 1): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The end-to-end stage-1 product on a Linux machine: `saiife blind init | ask | status | audit | keys | methods | data`, with local entity resolution and "did you mean", the `blind:name`, `blind:approve`, `blind:keys` and `blind:loosen` touches, the method preview with Run/Stop, approved-method reuse with no cloud call, template answers checked by the strict checker, 30-minute sessions, the 100-row list cap, the docs page and the full owner smoke.

**Architecture:** The daemon keeps each ask as a small state machine (`crates/daemon/src/blind/ask.rs`) keyed by a random ask id, owned by the asking uid, living at most 10 minutes; each step is one IPC call, so the CLI (and, in stage 2, the Workspace) only shows what the daemon asks and sends the user's answer back. Touches use the existing begin/assert/commit pattern (`box.land.begin` → `touch_cmd::pick` → `box.land`, `crates/cli/src/box_land_cmd.rs:225-245`, `crates/daemon/src/box_land.rs:726-830`) with a new `IssueKey::Blind(u64)`. The CLI writes Data Shield policy files itself (root in locked mode, the user in personal mode), then asks the daemon to reload and to commit the dataset.

**Tech Stack:** Rust; no new third-party crates. `clap` (existing), `saiife_touch` soft key seam `SAIIFE_TEST_TOUCH_SOFT` (`crates/cli/src/touch_cmd.rs:489-494`), `crates/cli/src/broker.rs` (`resolve_here` `:305`, `connect` `:225`), `crate::text::sanitize` for every daemon-supplied string printed.

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` §1.3, §1.4, §2.1.6, §2.1.7, §2.3.4–§2.3.6, §3.1, §5.1, §5.2, §6.5, §7 (Free: single machine incl. local uids), §9 anti-goals.

**Depends on:** plans 43–47 complete. Map at the end.

## Plan rulings (refinements of spec [call]s)

- **R48-1 Ask lifetime.** An ask id is 16 random bytes in hex; it belongs to the uid that made it (another uid's `blind.ask.answer` is `forbidden`); it expires 10 minutes after its last step; an answered ask is kept 10 more minutes so `methods approve <ask-id>` can use it. At most 4 open asks per uid, 64 per daemon (`busy`).
- **R48-2 Retries only before the preview.** Validation, template-slot and self-check-shape errors go back to the planner as an error class (the first try plus at most 3 retries, plan 45 R45-8). Once a preview was shown, any error ends the ask with a refusal; saiife never re-plans silently after the user said "run".
- **R48-3 Preview.** `ask` waits for Run/Stop unless `--yes`; `--yes` is refused for a dataset with `preview_required = true` (spec §2.3.6). Without a terminal and without `--yes`, `ask` refuses `the method preview needs an answer: run saiife blind ask in a terminal, or pass --yes`. Pick lists and "did you mean" need a terminal in stage 1 (no flags for them): without one, the ask refuses with the count only.
- **R48-4 Answer layout** (spec §5.2): the checked answer; then `── method: <preview text, past tense>`; then the footer `── exact · method <id> (approved) | new method · 0 personal values sent · <n>/<n> numbers checked` (da `── præcis · metode <id> (godkendt) | ny metode · 0 personlige værdier sendt · <n>/<n> tal tjekket`); the cap note `showing 100 of 2,314` above the method line when truncated; on a refusal: the refusal head, the reason, the method line. The answer text itself is never logged (its sha256 is, spec §6.5).
- **R48-5 Judgment** (spec §3.1, §3.2): `--judgment` and a plan reply with `needs_judgment: true` both answer `this question needs judgment, which needs the local composer (a later stage); exact mode cannot answer it` and end the ask. Never a silent switch.
- **R48-6 Approve** (spec §2.3.5 [owner]): `saiife blind methods approve <ask-id>` needs an ask that ended with a checked answer, the approver role (R47-3) **and** a `blind:approve` touch whose summary is the preview text and the template key. `methods rm <id>` needs the same role and touch. Only on the local socket.
- **R48-7 Init steps** (spec §5.1 flow is [call]): stage 1 has six steps (Data, Columns, Models, Cloud, Rules, Test); the Hardware step and tier detection come with the composer (stage 3). Every step has a flag for scripts. `init` writes `policy.d/blind.toml` (the `[blind]` globals, `[blind.ner]`, `[blind.cloud]`) once and `policy.d/blind-<dataset>.toml` per dataset; in locked mode it must run as root (the drop-in dir is root-owned) and refuses otherwise with `saiife blind init writes policy: run it as root (sudo saiife blind init)`.
- **R48-8 Loosening after init** (`saiife blind data class <dataset> <table.column> <class>`): a stricter class is written to policy at once; a looser one first takes a `blind:loosen` touch (approver or admin), the daemon writes the grant (`loosen.json`), then the CLI writes policy and reloads. A loosening to `public` runs `public_refusal` first and refuses names, IDs and amounts (spec §2.1.2 [owner]).
- **R48-9 Exact mode has no reveal.** A firewall hit is shown as `this would send <what> (<part>); nothing was sent. Rephrase the question, or ask without the name`; there is no stage-1 path that sends a real value, so `blind:reveal` and `blind:release` are never issued.

## Global Constraints

- **Tokio-free core.** No logic moves into the daemon or CLI that belongs in `saiife-shield`; the tokio gate (`ci.yml:208`) stays green.
- **Dependencies:** none new. ONNX runtime remains `tract-onnx =0.23.9` (pure Rust, MIT OR Apache-2.0) in `saiife-ner` only; `ort` rejected.
- **Tests fully offline with fakes:** CLI integration tests run a personal daemon in `$TMPDIR` with `SAIIFE_TEST_BLIND_PLANNER` (scripted replies), `SAIIFE_TEST_NER_HELPER` (`saiife-fake-ner`), `SAIIFE_TEST_BLIND_CALC` (the debug `saiife`), `SAIIFE_TEST_TOUCH_SOFT` (soft key) and, in debug builds only, `SAIIFE_TEST_BLIND_STDIN=1` (prompts read from stdin without a terminal). Synthetic Danish and English fixtures only. Never `saiife init` or `saiife blind init` on the real home or the repo; HOME, XDG_*, `SAIIFE_DATA_DIR`, `SAIIFE_AUDIT_DIR` in `$TMPDIR`; `DBUS_SESSION_BUS_ADDRESS` dead.
- **No token-shaped literals.** User-facing copy exactly as quoted here; `cargo test -p saiife --test docs_wording` stays green.
- **Every task** (worktree `.worktrees/p48`, branch `shield-p48` off `shield-dev`): plan 43's commands with `TMPDIR` named `p48-tN-…` (never the word "fix" in it); `cargo test -p saiife-daemon blind -p saiife --test blind_cli -j 4 -- --test-threads=4`; `bash scripts/check-windows.sh -p saiife -p saiife-daemon` (non-Linux: `saiife blind …` prints `saiife: Data Shield runs on Linux in this release` and exits 5). Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit staging, no push, smoke `bash -n` only.

### Fixed values

| Name | Value |
|---|---|
| pick prompt | en `Found <n> <word plural> named <written>:` … `Which one? ` · da `Fandt <n> <word_da> med navnet <written>:` … `Hvilken? ` |
| did you mean | en `No <word> named "<written>". Did you mean <display>? (y/N) ` · da `Ingen <word_da> ved navn "<written>". Mente du <display>? (j/N) ` |
| keep name | en `"<name>" is not in <dataset>. Send it as plain text to the planner? This needs a touch (blind:name). (y/N) ` |
| preview | `<preview text>` / optional `the planner says: <intent>` / `Run it? (Y/n) ` (da `Kør den? (J/n) `) |
| approve hint | `approve this method for reuse: saiife blind methods approve <ask-id>` (printed to approvers only) |
| exit codes | 0 answered; 2 refused (refusal, stop, firewall block, checker); 5 unavailable (daemon, vault, detector, Landlock, Linux-only) |

## Review Focus

1. **The answer of 0 for someone who isn't there, end to end:** a resolved customer without invoices, asked through the CLI with a scripted planner using `SUM`. Expected: `I could not produce a verified answer: the method found no rows for <display>`, exit 2, `blind_check_refused` (Task 2: `no_rows_for_key_refuses_end_to_end`).
2. **Reuse that should not happen:** a question with the same words but a different parameter type (an amount vs an integer), another language, or a dataset whose method was suspended by a refresh. Expected: goes to the planner; nothing reused (Task 1: `reuse_needs_same_template_and_types`, `suspended_method_not_reused`).
3. **A pick list or "did you mean" leaking into a log, the outbox or a record.** Expected: only counts in `blind_resolve`; candidate names never written anywhere (Task 1: `candidates_never_logged`).
4. **Another uid answering, or replaying, someone's ask or touch.** Expected: `forbidden`; touch challenges are bound to the uid and burned on use (Task 3: `other_uid_cannot_answer`, `touch_replay_refused`).
5. **Locked mode with a non-root `init`, or a policy file the daemon cannot reload** (a typo in the generated TOML is impossible by construction, but a pre-existing bad drop-in is not). Expected: refused before anything is written, or the written file removed again when the reload fails, with the loader's message (Task 6: `init_refuses_non_root_locked`, `init_rolls_back_on_bad_reload`).

---

### Task 1: the ask state machine up to the preview (size L)

**Files:** Create `crates/daemon/src/blind/ask.rs`; Modify `crates/daemon/src/blind/ops.rs`; Test: `crates/daemon/tests/blind_ask.rs`

**Interfaces:**
- Consumes: plan 44 `parameterize`, `answer`, `template_key`, `build_envelope`, `synthetic_rows`, `Firewall`; plan 45 `validate`, `parse_template`, `preview`, `MethodStore::find`; plan 47 `Blind`, `role`, `keys::load`, `model::planner`, `audit::write`, `NerClient`.
- Produces (ops):
  - `blind.ask {question, dataset?, lang?: "en"|"da", new_session?: bool, yes?: bool, limit?: u32 (≤ policy list cap), show_sent?: bool, judgment?: bool}` → `{ask: <id>, step: Step}`
  - `blind.ask.answer {ask, answer: {"pick": n} | {"did_you_mean": bool} | {"keep_name": false} | {"run": bool}}` → `{ask, step: Step}` (`keep_name: true` goes through the touch, Task 3)
  - `Step` (JSON, tag `kind`): `pick {word, written, candidates: [{n, label}], too_many}` · `did_you_mean {word, written, suggestion}` · `keep_name {name}` · `preview {text, planner_says?, approved?: id, sent: {tables, synthetic_rows, params, personal_values}, envelope?: <canonical JSON, only with show_sent>}` · `answer {text, method_line, cap_note?, footer, checked: {numbers, from_calc}}` · `refused {head, reason, method_line?}` · `refreshing {text}`.
```rust
pub struct AskArgs { pub question: String, pub dataset: Option<String>, pub lang: Option<Lang>, pub new_session: bool, pub yes: bool, pub limit: Option<u32>, pub show_sent: bool, pub judgment: bool }   // parsed from the op's args; question ≤ 2 000 chars
pub enum AskAnswer { Pick(usize), DidYouMean(bool), KeepNameNo, Run(bool), KeepNameTouched /* only from blind.touch.commit, Task 3 */ }
pub struct Asks { /* id -> AskState { uid, dataset, phase: AskPhase, last_step: Instant } */ }
pub enum AskPhase { Resolving(Draft), Previewing { draft: Draft, validated: Validated, reply: PlanReply, preview: Preview, approved: Option<String> }, Answered { draft: Draft, reply: PlanReply, preview: Preview }, Done }
pub async fn begin(ctx: &Arc<Ctx>, peer: &PeerCred, args: AskArgs) -> Result<(String, Step), Refusal>;
pub async fn step(ctx: &Arc<Ctx>, peer: &PeerCred, id: &str, a: AskAnswer) -> Result<Step, Refusal>;
```
  `candidates[].label` = display plus the `show` columns, built locally; the list goes only into this answer (spec §2.1.6). Records: `blind_ask` (parameterized text with stand-ins), `blind_resolve` (tags and counts), `blind_preview {outcome: "shown"}`; plan 47's send sequence for each planner call.

- [ ] **Step 1: Write the failing tests** (personal test daemon, fixture dataset committed through plan 47 ops, fake planner/NER/calc): `ready_question_reaches_preview` (Søren's balance → `preview` whose text equals plan 45's preview of the scripted method; one outbox entry; `blind_send.personal_values == 0`), `pick_then_preview` (Anna Berg → `pick` with 2 candidates incl. city; answer 2 → preview naming that customer's number), `did_you_mean_yes_and_no`, `keep_name_false_refuses`, `no_match_refuses_without_sending` (no outbox entry, no `blind_send`), `invalid_method_retried_then_refused` (4 bad replies, the first try plus 3 retries → refused `the planner's method was not valid after 4 tries (unknown_column)`; exactly 4 outbox entries, one per request), `reuse_needs_same_template_and_types` (an approved method in `methods.json` for the balance template: Anna's balance question → preview with `approved` and **no** outbox entry; `"…over 10 000 kroner"` vs `"…over 10 000"` with a different tag → planner), `suspended_method_not_reused`, `refreshing_answer`, `needs_judgment_says_so`, `candidates_never_logged` (after a pick flow, neither the audit files nor the outbox hold the candidate names or cities), `ask_belongs_to_uid` (another uid → `forbidden`), `asks_expire`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): the Data Shield ask flow up to the method preview (plan 48 T1)`.

### Task 2: run, fill, check and answer (size M)

**Files:** Modify `crates/daemon/src/blind/ask.rs`; Test: `crates/daemon/tests/blind_ask.rs`

**Interfaces:**
- Consumes: plan 45 `CalcJob`, `fill`, `check`; plan 47 `calc::run`, `audit::write`.
- Produces: the `run: true` branch: job from the validated method with param displays stripped, `calc::run`, then `fill` (lang from the draft), `check(filled, original question, lang)`, then the `answer` step per R48-4; `run: false` → `refused {head, reason: "stopped before the method ran"}` and `blind_preview {outcome: "stopped"}`. `--yes` runs straight after the preview step is built and returns `answer` with the preview text included as `method_line` (`blind_preview {outcome: "auto"}`). Records: `blind_run` (with `calculator: CALC_LABEL` and the confinement fields), `blind_check_refused` on any refusal after the run. The session gets the turn (parameterized question + symbols, plan 44 `push_turn`).
- [ ] **Step 1: Write the failing tests:** `answer_spec_example` (Anna #1 with the scripted template → exactly `Anna Berg (customer #4411) owes 18,420.00 NOK across 3 open invoices. That is above her limit of 15,000.00 NOK.` with fixture numbers chosen to match, the method line and the footer `3/3 numbers checked`), `danish_answer` (Danish question → Danish formatting and footer), `no_rows_for_key_refuses_end_to_end`, `checker_refusal_end_to_end` (a template with `in Q3` fixed text → refused, method line still shown), `list_cap_note` (a 250-row list with cap 100 → `showing 100 of 250`), `stop_refuses`, `yes_runs_but_shows_method`, `preview_required_blocks_yes`, `follow_up_uses_session_symbol` (second question "and her open invoices?" with a scripted planner that uses the first turn's `:p1` symbol → context holds the stand-in, the method binds the same key; after `--new-session` the symbol differs), `blind_run_has_weaker_label`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): run, fill, check and answer for Data Shield asks (plan 48 T2)`.

### Task 3: the touch flows (size M)

**Files:** Create `crates/daemon/src/blind/touch.rs`; Modify `crates/daemon/src/touch.rs:44-55` (`IssueKey::Blind(u64)`); Test: `crates/daemon/tests/blind_touch.rs`

**Interfaces:**
- Consumes: `TouchState::issue`/`consume` (`crates/daemon/src/touch.rs:202`, `:252`), `saiife_touch::{ActionRecord, challenge, short_code, TouchRequest, LOCAL_RP_ID}`, plan 43 Task 2 classes, plan 45 `MethodStore`, plan 47 `keys`, `data`.
- Produces (ops):
  - `blind.touch.begin {purpose, …}` → `{request_id: "<n>", touch: TouchRequest, expires_at, class}` where purpose and fields are: `name {ask, name}` (class `blind:name`, asker only, summary `keep "<name>" as plain text in a question about <dataset>`), `approve {ask}` (`blind:approve`, approver, summary `approve for reuse: <preview text> · template "<template key>"`, fields `dataset, template_key, method_sha256, preview_sha256`), `method_rm {dataset, id}` (`blind:approve`), `keys {dataset, action: "rotate"|"delete"}` (`blind:keys`, approver or admin), `loosen {dataset, column, to}` (`blind:loosen`, approver or admin, summary `make <column> <to> (now <from>)`).
  - `blind.touch.commit {request_id, assertion}` → runs the action once the touch verifies: `name` → the ask continues as if `keep_name: true` and returns its next `step`; `approve` → `MethodStore::add`, `blind_approve`; `method_rm` → remove, `blind_approve {action: "remove"}`; `keys` → `keys::rotate`/`shred`, `blind_keys`; `loosen` → grant into `loosen.json`, `blind_loosen`.
  The action record is the daemon's own (built at begin, nonce and expiry from the issued entry), as `box.land` does; no device enrolled → `refused: <purpose> needs a touch (<class>) and no touch device is enrolled for you: saiife touch enrol`.
- [ ] **Step 1: Write the failing tests** (soft key): `approve_needs_role_and_touch` (a dataset user who is not an approver → `forbidden` before any challenge; an approver with the soft key → method stored with `touch` filled), `approve_needs_answered_ask`, `name_touch_continues_ask` (keep a name → preview; the envelope's question holds the name as text and `released_names` let it pass), `keys_rotate_and_delete_by_touch`, `loosen_grant_then_refresh_applies`, `other_uid_cannot_answer` (another uid's commit → `touch_mismatch`), `touch_replay_refused` (a second commit with the same assertion → `touch_expired`), `no_device_refuses`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): blind:name, blind:approve, blind:keys and blind:loosen touches (plan 48 T3)`.

### Task 4: `saiife blind ask | status | audit` (size M)

**Files:** Create `crates/cli/src/blind_cmd.rs`, `crates/cli/src/blind_cmd/ask.rs`, `crates/cli/src/blind_cmd/prompt.rs`; Modify `crates/cli/src/main.rs:112-400` (`Blind { #[arg(long = "system-config", hide = true, global = true)] system_config, #[command(subcommand)] action: blind_cmd::BlindAction }`, dispatched like `Cmd::Box` at `:785`), `crates/daemon/src/audit_query.rs` (filter `kind_prefix`, only `blind_`), `crates/daemon/src/blind/ops.rs` (`blind.outbox.show {sha256}`: root or `saiife-audit` member, as `audit.query all`); Test: `crates/cli/tests/blind_cli.rs`

**Interfaces:**
- Produces:
```rust
#[derive(Subcommand)] pub enum BlindAction {
    Init(init::InitArgs), Ask { question: String, #[arg(long)] judgment: bool, #[arg(long)] show_sent: bool, #[arg(long)] dataset: Option<String>, #[arg(long)] new_session: bool, #[arg(long)] yes: bool, #[arg(long)] limit: Option<u32>, #[arg(long)] lang: Option<String> },
    Status { #[arg(long)] json: bool },
    Audit { #[arg(long, default_value = "7d")] since: String, #[arg(long)] user: Option<String>, #[arg(long)] sent: Option<String>, #[arg(long)] json: bool },
    Keys { #[command(subcommand)] action: KeysAction }, Methods { #[command(subcommand)] action: MethodsAction }, Data { #[command(subcommand)] action: DataAction },
}
pub fn run(config: Option<PathBuf>, a: BlindAction) -> ExitCode;
pub(crate) trait Prompter { fn line(&mut self, prompt: &str) -> Result<String, String>; fn is_interactive(&self) -> bool; }
```
  `ask` loops: `blind.ask` → for each step print (sanitized) and prompt → `blind.ask.answer`; a `keep_name` yes runs `touch.begin {purpose: name}` → `touch_cmd::pick()` → assertion → `touch.commit` on a new connection (a touch may take 120 s). `status` prints datasets, the weaker label, detector and cloud state, warnings. `audit` groups `blind_*` records by ask id: time, user, dataset, envelope hashes, `0 personal values`, refusals, touches; `--user` needs the auditor role (`all: true`); `--sent <sha256>` prints that outbox body.
- [ ] **Step 1: Write the failing tests** (CLI integration, personal daemon, fakes, `SAIIFE_TEST_BLIND_STDIN=1`): `ask_pick_preview_answer` (stdin `1\ny\n` → answer and footer on stdout, exit 0), `ask_without_terminal_refuses` (no stdin seam, no `--yes` → R48-3 text, exit 2), `ask_yes_answers`, `ask_judgment_says_later_stage`, `ask_show_sent_prints_envelope` (the printed JSON is the outbox body's user content), `status_prints_weaker_label`, `audit_groups_by_ask`, `audit_user_needs_auditor`, `daemon_text_is_sanitized` (a dataset alias with an ANSI escape prints escaped), `blind_is_linux_only` (`cfg(not(target_os = "linux"))` unit test of the message and exit 5).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): saiife blind ask, status and audit (plan 48 T4)`.

### Task 5: `saiife blind keys | methods | data` (size M)

**Files:** Create `crates/cli/src/blind_cmd/admin.rs`, `crates/cli/src/blind_cmd/policy_file.rs`; Test: `crates/cli/tests/blind_cli.rs`

**Interfaces:**
- Produces:
```rust
pub enum KeysAction { Rotate { #[arg(long)] dataset: Option<String> }, Delete { #[arg(long)] dataset: String } }   // delete asks to type the dataset name, then the touch
pub enum MethodsAction { Ls { #[arg(long)] dataset: Option<String> }, Approve { ask: String }, Rm { id: String, #[arg(long)] dataset: Option<String> } }
pub enum DataAction { Add(init::DataArgs), Refresh { #[arg(long)] dataset: Option<String>, #[arg(long)] file: Option<PathBuf> }, Rm { #[arg(long)] dataset: String }, Class { dataset: String, column: String, class: String } }
// policy_file.rs
pub fn dropin_dir(t: &Target) -> PathBuf;                                  // <config dir>/policy.d
pub fn write_dataset(t: &Target, d: &BlindDataset) -> Result<PathBuf, String>;   // policy.d/blind-<name>.toml via toml serialization, 0644 root-owned in locked mode, 0600 in personal; temp + rename; refuses to overwrite a file it did not write (first line marker `# written by saiife blind`)
pub fn write_globals(t: &Target, g: &BlindCfg) -> Result<PathBuf, String>;       // policy.d/blind.toml
pub fn reload(t: &Target) -> Result<(), String>;                                  // OP_POLICY_RELOAD; on Err the caller restores the previous file
```
  `data refresh` for file sources opens `--file` (or asks for it) and passes the fd (R47-5); then polls `blind.status` once a second, printing the phase, until live or failed. `data rm` asks to type the dataset name.
- [ ] **Step 1: Write the failing tests:** `keys_rotate_with_soft_key`, `keys_delete_confirms_name` (wrong name typed → nothing done), `methods_ls_approve_rm` (approve after an answered ask; `ls` shows it; `rm` removes it), `data_refresh_progress_then_live`, `data_class_tighten_writes_policy`, `data_class_loosen_needs_touch`, `data_class_public_refused_for_email`, `policy_file_marker_protects_hand_written` (an existing `blind-crm.toml` without the marker → refused).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): saiife blind keys, methods and data (plan 48 T5)`.

### Task 6: `saiife blind init` (size L)

**Files:** Create `crates/cli/src/blind_cmd/init.rs`; Test: `crates/cli/tests/blind_init.rs`

**Interfaces:**
- Produces:
```rust
pub struct DataArgs { #[arg(long)] dataset: Option<String>, #[arg(long)] file: Option<PathBuf>, #[arg(long)] postgres_host: Option<String>, #[arg(long)] postgres_db: Option<String>, #[arg(long)] postgres_user: Option<String>, #[arg(long)] postgres_password_secret: Option<String>, #[arg(long)] postgres_tables: Vec<String>, #[arg(long)] accept_guesses: bool, #[arg(long, value_delimiter = ',')] public: Vec<String>, #[arg(long = "class", value_parser = parse_kv)] classes: Vec<(String, String)>, #[arg(long = "alias", value_parser = parse_kv)] aliases: Vec<(String, String)>, #[arg(long = "entity")] entities: Vec<String> /* table:key:name_col[+name_col]:show_col[+…]:word:word_da */, #[arg(long)] users: Vec<String>, #[arg(long)] approvers: Vec<String>, #[arg(long)] k: Option<u32> }
pub struct InitArgs { #[command(flatten)] data: DataArgs, #[arg(long)] ner_model_url: Option<String>, #[arg(long)] ner_model_sha256: Option<String>, /* vocab, labels likewise */ #[arg(long)] cloud_secret: Option<String>, #[arg(long)] model: Option<String>, #[arg(long)] preview_required: bool, #[arg(long)] yes: bool, #[arg(long)] show_sent: bool, #[arg(long)] skip_test: bool }
```
  Steps (R48-7), each printed as `n/6 <Name>  …` like spec §5.1: **1 Data** (`blind.data.stage` with the fd or Postgres args → tables and rows); **2 Columns** (prints `<n> columns classified. <m> need you:` and the uncertain table with the guess in brackets; Enter keeps the guess; `public` marks show `(<p> of <t> values pass k = <k>)` and are refused with the classifier's reason for names/IDs/amounts; then `Mark more columns public? (y/N)`, `Alias column names for the cloud? (y/N)`; then entity tables: a guess (the table with identifier name columns and an INTEGER unique key) confirmed or edited); **3 Models** (name detector from flags or existing `[blind.ner]`: `name detector  <file name>  <size>  sha256 <first 4>…<last 2>  pinned. Fetch? (Y/n)` → `blind.ner.fetch`; without a pin: `no name detector is pinned yet: pass --ner-model-url and --ner-model-sha256 (and vocab, labels); see docs/data-shield.md` and init stops before writing policy); **4 Cloud** (`Claude, API key in vault: <secret> ✓` when `secret list` shows a token secret allowing `blind-model`, else the `saiife secret add <name> --kind token --service blind-model` line and stop); **5 Rules** (`exact mode by default · k = <k> · preview before every run · English, Danish`; writes `blind.toml` and `blind-<d>.toml`, reloads, `blind.data.commit`; a reload failure restores the previous files and prints the loader's error); **6 Test** (a question generated from the schema: en `How many <entity plural> are there?` / da `Hvor mange <word_da> er der?`, run as an ask with the preview shown; prints `method:`, `sent to cloud: schema + synthetic rows + 1 question, 0 personal values`, `answer:` with `(checked: n/n numbers from the calculator)`; `--show-sent` prints the envelope). Ends with `Done. Ask with: saiife blind ask "…"`.
- [ ] **Step 1: Write the failing tests** (personal daemon, fakes, stdin seam): `init_scripted_end_to_end` (all flags, `--yes`: policy files written with the marker, dataset live, the test answer printed with `0 personal values`), `init_interactive_columns` (stdin keeps guesses, marks `segment` public, refuses `email` public with the reason), `init_stops_without_ner_pin` (no policy written), `init_stops_without_cloud_secret`, `init_refuses_non_root_locked` (a locked-mode target as a normal user → refused before stage), `init_rolls_back_on_bad_reload` (a pre-existing broken drop-in → reload fails → `blind-<d>.toml` removed again, message shown).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): the saiife blind init wizard (plan 48 T6)`.

### Task 7: docs and the full owner smoke (size S)

**Files:** Create/complete `docs/data-shield.md`; Modify `README.md` (one line under the feature list), `crates/cli/tests/docs_wording.rs` (if it lists docs pages); Create `scripts/blind-smoke.d/60-ask.sh`

- [ ] **Step 1: Write the failing test:** `docs_wording` covers `docs/data-shield.md` (no banned words per the existing test; the page states G1–G3 with "exactly what the shown method computes", the honest limits of spec §1.4, "pseudonymized data is still personal data", "never claims anonymization", and the weaker calculator label verbatim).
- [ ] **Step 2: Run** `cargo test -p saiife --test docs_wording` → FAIL. **Step 3: Write** the page: what Data Shield is, what leaves in exact mode (spec §2.3.1, the envelope shown), the guarantees and their limits, each command with an example from spec §5.2, roles and touches, files and modes (`<state>/blind/…`, outbox), the name detector and its pin, API keys only, Linux only, and "what stage 1 does not do" (judgment, composer, Workspace Ask, boxes). Then `60-ask.sh`: `smoke_ask` (needs the API key file and the owner's NER pin from `40-ner.sh`) runs, in a personal daemon over the 3 M dataset from `10-data`: `saiife blind init` with flags; an English and a Danish customer question with a pick list (two synthetic "Anna Berg"); a typo with "did you mean"; a list over 100 rows (cap note); a question about a customer with no invoices (refusal); `methods approve` with the owner's touch key; the same question again (no new outbox entry: count the outbox lines); `data refresh` (method still active); `keys rotate`; `audit`; and greps the audit dir and the outbox for every synthetic name it asked about (must find none in the audit, and none in the outbox).
- [ ] **Step 4: Run** → PASS; `bash -n scripts/blind-smoke.d/60-ask.sh scripts/blind-smoke.sh`.
- [ ] **Step 5: Commit** `docs(shield): the Data Shield page and the full blind smoke (plan 48 T7)`.

---

## Owner smoke fragment (plan 48)

`scripts/blind-smoke.d/60-ask.sh` (`bash scripts/blind-smoke.sh --only ask`, after `data`, `ner`, `daemon`): the whole stage-1 flow on real hardware with the real model and API key, touch key in hand; checks that no asked name reaches the audit log or the outbox. Builders: `bash -n` only.

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
