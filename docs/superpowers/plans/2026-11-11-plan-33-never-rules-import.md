# Plan 33: never-rules import (`saiife rules import | sync | list`, extraction, confirm, status): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife rules import CLAUDE.md` (also `AGENTS.md`, `GEMINI.md`, any rules file) works like this:
1. It finds the "never / don't / must not / no" lines and proposes a concrete rule for each line that has a command or a path. It always lists the rest as **not enforced**.
2. The human confirms each rule in a table: enforce, ask, skip or edit, and host only or everywhere.
3. It writes a plan 32 user pack. Nothing unconfirmed is ever written as a rule.

After that:
- `saiife rules sync` follows edits to the source file: new lines are only proposed, and a removed line keeps its rule until the human says otherwise.
- `saiife rules` lists what is enforced on the host and in a box.
- `saiife status` warns when a source file changed.

**Architecture:**
- **All in the CLI crate**, as a `rules_cmd` module tree like `dev_cmd`. There are pure parts (`extract`, `propose`, `llm::parse`, `sync::plan`, the renderers) and thin IO parts (`confirm` on a `BufRead`/`Write` pair, file reading and writing, spawning `claude`). Most tests target the pure parts.
- **Deterministic first, offline.** Commands in backticks and in `:`-lists become command denies. Paths starting with `/`, `~/` or `$VAR` become `deny_path`. Every proposal is compiled into a one-rule user pack and **must pass its own examples**: blocks what it should, allows a near miss. A proposal that doesn't is listed as `unverified`, never offered (Codex execpolicy style, spec §10.2).
- **The LLM pass is opt-in (`--llm`), and the LLM never writes a regex.** saiife sends only the candidate lines the deterministic pass could not use to the user's own `claude -p`, with tools disabled. The answer must fit a strict schema with two kinds, `command` and `path`, and no allow. The same rule builder turns each answer into a rule, and the LLM's examples must pass as well. Tests use a fake `claude` script on a temp `PATH`.
- **Trust (§10.4).**
  - File text can only add deny, ask or `deny_path`. The only `[[allow]]` an import writes is the `--help` carve-out inside its own pack.
  - `where = "host"` is set only by the human's answer.
  - Broad proposals (they deny an everyday command or path, per plan 32's `broad_findings`) need a typed `yes`.
- **Edits keep the file.** `sync` changes an existing pack with `toml_edit` (already a CLI dependency, `crates/cli/Cargo.toml:37`), so hand edits, comments and keys saiife does not generate survive.

**Tech Stack:** Rust. `toml_edit 0.22.27`, `toml 0.8`, `serde`, `serde_json`, `sha2 0.10` (all already CLI dependencies). No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §10.1–§10.5, §11 step 5, §12, §15. **Builds on plan 32**: `saiifeguard::userpack::{load_user_packs, view, box_status, broad_findings, Broad, valid_user_pack_id, UserSrc, UserPackView, UserRuleView, SourceRef, ImportRef, RuleKind, BoxStatus}`, `saiifeguard::pack::{RuleWhere, UnenforcedWhy}`, `saiifeguard::profile::Profile`, `saiifeguard::wrappers::is_transparent`, `saiife_policy::userpacks::{read_user_packs, MAX_USER_PACK_BYTES}`, `saiife_policy::USER_PACKS_DIR`, `saiife_system::personal::user_packs_dir`.

## Facts checked (2026-11-11, branch `v3-dev` at `d464ce4`)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | Subcommands are variants of `enum Cmd` in `main.rs`, dispatched early with `if let Cmd::X {..} = cli.command { return x_cmd::run(..) }`. `windows_refusal` and the late `match` list every variant with no wildcard. | `crates/cli/src/main.rs:94-396, 418-450, 660-668, 696-718` | `Cmd::Rules` is added in all three places. |
| F2 | `broker::resolve_here(flag)` gives `Target::Locked { config, .. }` (flag given, or `/etc/saiife/config.toml` says `locked = true`) or `Target::Personal { config, .. }` (`~/.config/saiife/broker/config.toml`). Debug builds read `SAIIFE_TEST_SYSTEM_CONFIG`. | `crates/cli/src/broker.rs:25-55, 305-318` | The pack dir is `<target config's dir>/policy.d/packs`, the same dir plan 32's loaders read. |
| F3 | `saiife connect` checks that the target dir is writable before it acts, and writes root-owned 0644/0755 (locked) or user 0600/0700 (personal). Its tests run a locked target with `TestDaemon` and `--config`. | `crates/cli/src/connect_cmd.rs:129-160, 224-236, 409-424`; `crates/cli/tests/connect_cmd.rs:20-42` | `rules` follows the same pattern and test harness. |
| F4 | `import_cmd` reads answers one line at a time from stdin (`read_answer`), and reads files as root with `O_NOFOLLOW`, regular-file and one-link checks. | `crates/cli/src/import_cmd.rs:14-21, 485-494` | `confirm` reads lines from a `BufRead`; `read_source` uses the same checks. |
| F5 | CLI tests run the binary with PATH, HOME, `SAIIFE_DATA_DIR`, `SAIIFE_AUDIT_DIR` and `XDG_RUNTIME_DIR` set to tempdirs (`Env::command_in`). `fake_exe` writes an executable script. | `crates/cli/tests/common/mod.rs:34-46, 148-159` | The fake `claude` is `fake_exe(env.bin.path(), "claude", …)`. Every test also sets `SAIIFE_TEST_SYSTEM_CONFIG` to an absent file, so no test reads `/etc/saiife`. |
| F6 | `saiife status` collects `problems` (exit 1) and `notes`. | `crates/cli/src/status_cmd.rs:85-380` | A changed source is a **note**, not a problem. It is a reminder, and the rules stay in force. |
| F7 | The hard-rules file has about 13 lines enforceable now, about 7 needing new rule types, and the rest judgement. | spec §10.2 | The extraction test uses an inline fixture shaped like those lines. No test reads `.superpowers/` or any real `CLAUDE.md`. |

### Design decisions (flagged for the owner)

- **D1. Which lines are candidates.** Fenced code blocks (```` ``` ```` or `~~~`) and HTML comments are skipped. A candidate is a line that:
  - contains, case-insensitive, one of `never`, `don't`, `don’t`, `do not`, `must not`, `mustn't`, `shall not`, `may not`; or
  - after an optional list marker (`-`, `*`, `+`, `1.`) and optional `**`, starts with `no` followed by a space.

  From a candidate, the targets are:
  - every backtick span that is command-like (first word `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, and none of `| ; & < > ( ) $` or a backtick in the span) or path-like;
  - every single-word, lowercase, program-like segment of a list after the line's first `:` outside backticks. The list must have two or more segments, split on `,`, ` or ` and ` and `;
  - every bare token starting with `/`, `~/` or `$NAME/` (surrounding `,.;:()"'` stripped; not a URL).

  Access is `write` if the line has write, writes, edit, modify, change, delete, remove, overwrite or touch; `read` if it has read, reads, open, cat, print or show; and `any` if it has both or neither.
- **D2. How a target becomes a rule.**
  - A command of words `w1 … wn` becomes `pattern = '^w1\s+…\s+wn(?:\s|$)'` (each word escaped), with `triggers` holding `w1`.
  - If `w1` is a transparent wrapper (plan 32 `is_transparent`, e.g. `sudo`) and n = 1, it becomes two rules instead, as `core.lock` does (`core.lock.toml:48-58`):
    - `(?:^|\s)sudo(?:\s|$)` with `peeled_wrappers = true`;
    - `^sudo(?:\s|$)`.
  - If `w1` is a wrapper and n > 1, it becomes one rule with `whole_segment = true`.
  - A one-word, non-wrapper command also gets an `[[allow]]` carve-out in its own pack: `'^w1\s+(?:--help|-h|--version)$'`.
  - A path `p` (no wildcard) becomes two `deny_path` rules, `p` and `p/**`. A path with a wildcard becomes the glob as is. Both use the line's access.
  - Ids are `l<line>-<k>`, the first free `k` in the pack.
  - The reason is `<file name>:<line> "<line text without list marker and **, at most 160 chars>"`. That is the "source line quoted as the reason" of §10.1.
- **D3. Examples.**
  - A command rule blocks its own words joined by spaces, and allows `echo <words>`, plus `w1 --help` when there is a carve-out.
  - A path rule blocks the base path with `/saiife-example` added (for `p/**`), or `p` itself. It allows the sibling `<parent of p>/saiife-example-other`. Both are judged with `evaluate_path`, with `Access::Read` for `read` rules and `Access::Write` otherwise.
  - The engine for examples is the proposal alone, as a user pack (plan 32 `load_user_packs`), with `paths::path_vars(cwd, project)`.
- **D4. The LLM pass.**
  - Command: `claude -p --tools "" <INSTRUCTIONS>`, with the lines on stdin as `<line>: <text>`. The environment is inherited (the user's own login). The timeout is 120 s (`Child::kill` on our own child; debug builds read `SAIIFE_TEST_LLM_TIMEOUT_MS`). Stdout is capped at 256 KiB, and at most 64 rules are accepted.
  - Only candidate lines with no usable target are sent, never the whole file. The terminal says so before it runs: `sending N lines of <file> to claude -p (your Claude Code login)`.
  - **Owner check:** the flags (`--tools ""`) against your installed Claude Code's `claude --help`. Builders must not run `claude`.
- **D5. Confirm.**
  - Prompts go to stderr and answers come from stdin lines (F4), so a test can drive them. Piped answers can only add restrictions, or mark a rule host-only.
  - Each rule is answered `e`nforce, `a`sk, `s`kip or edit (`x`); an empty answer means skip. `ask` is offered only for command rules and only on a locked target (plan 32 D7).
  - After `e` or `a`: `everywhere or host only? [E/h]`, default everywhere. A hint `(often host only)` shows for `docker`, `systemctl`, `sudo`, `su`, `pkill`, `kill`, `killall`, `loginctl` and paths under `/etc`. It is a hint only, never a default.
  - A broad proposal shows `BROAD: blocks everyday <example>`, and `e` or `a` must then be followed by typing `yes`.
  - **End of input before the last question writes nothing and exits 1.** The same holds for `sync`.
- **D6. Packs and files.**
  - One pack per source file. The id is `user.<slug>-<8 hex of SHA-256 of the absolute source path>`, where the slug is the file name lowercased, with non-`[a-z0-9]` runs turned into `-` and cut to 30 characters (`user.claude-md-1a2b3c4d`). `--name <slug>` gives `user.<slug>`.
  - A source already imported (an `[import] file` equal to its absolute path) is refused with `already imported as <id>; use saiife rules sync`.
  - With no file given, `CLAUDE.md`, `AGENTS.md` and `GEMINI.md` are looked for in the project root (or cwd). `~/.claude/CLAUDE.md` is never read unless named.
  - The source is read with `O_NOFOLLOW`, as a regular file of at most 1 MiB in UTF-8; as root, it must also have exactly one link.
  - The pack is written to a temp file in the same dir and then renamed. A pack with zero confirmed rules is not written (plan 32 would reject it as `NoRules`), and the command says `no rule confirmed; nothing written`.
- **D7. Sync semantics (§10.3).**
  - A rule or `[[unenforced]]` entry whose `line_sha256` is still in the file gets its `line` updated (the nearest occurrence). This is silent, since it loosens nothing.
  - A source line that is gone: `line N is gone: "<text>" (k rules). keep? [K/r]`, default keep. `r` removes every rule from that line, carve-outs included. Gone `[[unenforced]]` entries are dropped.
  - New candidate lines go through propose and confirm.
  - `[import] sha256` is updated only when the whole run finished.
  - A missing source file is a warning (`source gone; rules kept`) and changes nothing.

## Global Constraints

- **Tokio-free:** `saiife-guard`, `saiife-audit`, `saiife-policy`, `saiife-ipc` and `saiife-system` never depend on tokio (CI gate `.github/workflows/ci.yml:151` prints `0`). This plan touches only the CLI crate.
- **No new dependencies.** If one is ever needed, pin it (`=x.y.z`) to a version released more than 14 days ago, and prefer crates already in `Cargo.lock`.
- **No network in tests.** No test runs a real `claude`; the LLM tests use a `fake_exe` script on a temp `PATH` and are `#[cfg(unix)]`. Builders never run `claude`, `sudo`, `docker` or any process-control tool.
- **Test isolation (hard rules):** `export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p33-tN-XXXXXX)" SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0`.
  - Every CLI test uses `common::Env` (HOME, PATH, XDG and data dirs in tempdirs) and sets `SAIIFE_TEST_SYSTEM_CONFIG` to an absent file, or uses a `TestDaemon` config with `--config`.
  - Rules files are written into the test's project tempdir.
  - Never read or write `~/.claude`, the owner's real `CLAUDE.md`, `/etc/saiife`, `.superpowers/` or the keyring.
  - No scratch name contains "fix". Remove `$TMPDIR` at the end.
- **Per task:** `cargo test -p saiife -j 4 -- --test-threads=4 <filters>`, then `cargo fmt --all` and `cargo clippy --workspace --all-targets -j 4 -- -D warnings`. Run `bash scripts/check-windows.sh -p saiife` (the `O_NOFOLLOW` code is `#[cfg(unix)]`, with a Windows twin that checks for a reparse point the way `load.rs:797-830` does).
- **Never run** `scripts/bench-check.sh --managed`, `scripts/locked-linux/*` or any CI-only smoke script.
- **Git:** stage explicit paths. Never commit `.superpowers/`. No token-shaped literals (fixtures are rule text, not secrets). Every commit ends with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A hostile rules file** (§10.4): "never run `ls`", "never write to `/`", "don't touch `~/`", "never run `rm -rf $(cat x)`", and 500 never-lines. Expected:
   - the first three are flagged BROAD and enforced only after a typed `yes`;
   - the span with `$(` is not command-like, so it becomes judgement;
   - the count is shown, and plan 32's 128-rule cap refuses the write with a clear message, not a pack the hook would reject.

   Tests: Task 2 `broad_proposals_are_flagged`; Task 4 `broad_needs_typed_yes`; Task 5 `over_the_rule_cap_writes_nothing`.
2. **Lines that only look like rules, and word order.** Expected:
   - code inside a fence, `never` inside a backtick span, and "`--force-with-lease` is fine" are not candidates (Task 1 `fenced_and_quoted_lines_are_not_candidates`);
   - "never use `git push --force`" gives a prefix rule. It blocks `git push --force origin` and allows `git push --force-with-lease`, but it also allows `git push origin --force`. That gap is pinned by a test and named in the docs' "What is not enforced", and the confirm table's examples show the rule's shape (Task 2 `prefix_rule_word_order_is_pinned`).
3. **Confirm cut short** (Ctrl-D, a closed pipe, a test with too few answers). Expected: nothing written, exit 1, and `stopped before the last rule; nothing written` (Task 4 `eof_is_an_error`; Task 5 `import_eof_writes_nothing`; Task 6 `sync_eof_writes_nothing`).
4. **The source file is edited.** Expected:
   - a moved line keeps its rule (line number updated);
   - a removed line keeps its rule unless `r` is answered;
   - a new line is proposed, never enforced unasked;
   - `status` notes the change until `sync` runs.

   Tests: Task 6 `moved_line_keeps_rule`, `gone_line_kept_by_default`, `gone_line_removed_on_r`, `new_line_is_only_proposed`; Task 7 `status_notes_a_changed_source`.
5. **A bad LLM answer:** an `allow` kind, an extra field, a regex field, a line that was not sent, examples that fail, no `claude` on PATH, a hang, or huge output. Expected: each such rule is refused and named; a missing, hung or oversized `claude` ends the LLM pass with one warning, and the deterministic proposals still go to confirm (Task 3 `llm_*` tests).

---

## Task order and parallelism

- **Wave 1:** Task 1 (module, clap, extraction).
- **Wave 2 (parallel):** Task 2 (propose and verify), Task 4 (confirm; uses Task 2's types, declared in Task 1).
- **Wave 3 (parallel):** Task 3 (LLM; needs 2), Task 5 (store and `import`; needs 2 and 4).
- **Wave 4 (parallel):** Task 6 (`sync`; needs 5), Task 7 (`list`, `status`, docs; needs 5).
- **Last:** gates, whole-branch review, PR to `v3-dev` (after plan 32 is merged there).

**Shared files:** `crates/cli/src/rules_cmd.rs` declares every submodule and every shared type in Task 1 (`SourceLine`, `Target`, `Candidate`, `Proposal`, `ProposalKind`, `CmdRule`, `Origin`, `Choice`, `Decided`, `Unverified`), so later tasks add no shared types.

---

### Task 1: the `rules` command, its types, and the extraction (size M)

**Files:**
- Create `crates/cli/src/rules_cmd.rs` and `crates/cli/src/rules_cmd/{extract.rs, propose.rs, llm.rs, confirm.rs, store.rs, sync.rs, list.rs}` (the last six with one `//!` line).
- Modify `crates/cli/src/main.rs` (`mod rules_cmd;`, `Cmd::Rules`, early dispatch, `windows_refusal`, the late match).
- Test: unit tests in `extract.rs`; `crates/cli/tests/rules_cmd.rs` (new; one `--help` test now).

**Interfaces (Produces):**
- clap:
  ```rust
  /// Never-rules from CLAUDE.md, AGENTS.md, GEMINI.md and rules files, as enforced packs.
  Rules { #[arg(long = "config", visible_alias = "system-config", value_name = "FILE", global = true)] config: Option<PathBuf>,
          #[command(subcommand)] action: Option<rules_cmd::RulesAction> }
  pub enum RulesAction {
      /// Propose rules from these files and confirm each one.
      Import { files: Vec<PathBuf>, #[arg(long)] llm: bool, #[arg(long, value_name = "SLUG")] name: Option<String> },
      /// Follow changes to the imported files.
      Sync { #[arg(long, value_name = "PACK_ID")] pack: Option<String>, #[arg(long)] llm: bool },
      /// List the rules, where they apply and what is not enforced (the default).
      List { #[arg(long)] json: bool },
  }
  pub fn run(config: Option<PathBuf>, action: Option<RulesAction>) -> ExitCode;   // None = List { json: false }
  ```
  `windows_refusal` gives `Cmd::Rules { .. } => None`. Exit codes: 0 ok, 1 stopped or refused, 2 bad input.
- Shared types in `rules_cmd.rs` (all `Debug, Clone, PartialEq, Eq`):
  ```rust
  pub struct SourceLine { pub line: u32, pub text: String, pub line_sha256: String }
  pub enum Target { Command(Vec<String>), Path { glob: String, access: RuleAccess } }
  pub struct Candidate { pub src: SourceLine, pub targets: Vec<Target> }        // no targets: judgement
  pub enum Origin { Rules, Llm }
  pub struct CmdRule { pub pattern: String, pub whole_segment: bool, pub peeled_wrappers: bool }
  pub enum ProposalKind { Command { words: Vec<String>, rules: Vec<CmdRule>, help_carve_out: bool }, Path { globs: Vec<String>, access: RuleAccess } }
  pub struct Proposal { pub src: SourceLine, pub kind: ProposalKind, pub reason: String, pub block: Vec<String>, pub allow: Vec<String>, pub broad: Option<String>, pub host_hint: bool, pub origin: Origin }
  pub struct Unverified { pub src: SourceLine, pub why: String }
  pub enum Choice { Enforce, Ask, Skip }
  pub struct Decided { pub p: Proposal, pub choice: Choice, pub where_: RuleWhere }
  ```
- `extract.rs`:
  - `pub fn line_sha256(text: &str) -> String`: hex SHA-256 of the line with trailing whitespace (including `\r`) removed;
  - `pub fn all_lines(text: &str) -> Vec<SourceLine>` (1-based);
  - `pub fn candidates(text: &str) -> Vec<Candidate>` (D1), with targets deduplicated in order of appearance.

- [ ] **Step 1: Write the failing tests** (`extract.rs`), on an inline fixture shaped like the hard rules (F7):
  - `colon_list_becomes_commands`: `"- Never execute process-control or privilege tools, even to probe them: kill, pkill, killall, pgrep, sudo, su, systemctl."` gives 7 `Command([w])` targets, in order;
  - `backticks_and_paths`: `"- No sudo, no root, no systemd units, systemctl or \`systemctl --user\`, no writes to /etc, /opt, /var or /run, no docker."` gives `Command(["systemctl","--user"])`, then `Path{"/etc",Write}`, `Path{"/opt",Write}`, `Path{"/var",Write}` and `Path{"/run",Write}`. There is no colon, so there are no list commands;
  - `home_path_any`: `"Never touch ~/.claude, and never touch the real desktop keyring."` gives `[Path{"~/.claude",Any}]`;
  - `judgement_has_no_targets`: `"Never put the word \"fix\" in a scratch name."` is a candidate with empty targets;
  - `fenced_and_quoted_lines_are_not_candidates` (Review Focus 2): a line `never run x` inside a ```` ``` ```` fence, `<!-- never run y -->`, `` "Use `git push --force-with-lease`; that is fine." `` and `"Run \`never-ending-test\`"` are not candidates;
  - `unsafe_span_is_not_a_command`: ``"Never run `rm -rf $(cat x)`"`` has no `Command` target;
  - `urls_are_not_paths`: `"Never fetch https://x/y"` has no targets;
  - `line_hash_ignores_trailing_space`: `line_sha256("a \r") == line_sha256("a")`, and `line_sha256(" a") != line_sha256("a")`.
  - `tests/rules_cmd.rs::rules_help_lists_the_actions`: `saiife rules --help` exits 0 and names `import`, `sync` and `list`.
- [ ] **Step 2: Run** `cargo test -p saiife -j 4 -- --test-threads=4 rules`. Expect FAIL.
- [ ] **Step 3: Implement.** `run` dispatches to `todo_unavailable` for the actions that later tasks fill. That stub prints `saiife: rules <action> is not built yet` and returns 1, and Tasks 5 to 7 replace it.
- [ ] **Step 4: Run** → PASS; clippy clean; `bash scripts/check-windows.sh -p saiife`.
- [ ] **Step 5: Commit** `feat(rules): saiife rules: command skeleton and the deterministic never-line extraction`.

### Task 2: proposals, examples and verification (size M)

**Files:** Modify `crates/cli/src/rules_cmd/propose.rs`. Test: unit tests there.

**Interfaces:**
- Consumes Task 1's types; plan 32's `load_user_packs`, `broad_findings`, `is_transparent`; `crate::paths::path_vars`.
- Produces:
  - `pub fn reason(file_name: &str, line: u32, text: &str) -> String` (D2);
  - `pub fn propose(c: &Candidate, file_name: &str, origin: Origin) -> Vec<Proposal>`: one proposal per target (D2, D3), with `broad: None` and `host_hint` set;
  - `pub fn one_rule_pack(p: &Proposal, id_line: u32) -> String`: the proposal alone as user-pack TOML (`user.proposal`, ids `l<line>-<k>`). It is used only to verify, and `store` renders the real pack;
  - `pub fn verify(p: &mut Proposal, vars: &PathVars) -> Result<(), String>`. It loads `one_rule_pack` with `load_user_packs(.., Profile::Host)` and judges every `block` (each must `Deny`) and every `allow` (each must not), naming the first that fails. It sets `p.broad = broad_findings(&pack).first().map(|b| format!("blocks everyday `{}`", b.example))`;
  - `pub fn proposals_for(cands: &[Candidate], file_name: &str, vars: &PathVars) -> (Vec<Proposal>, Vec<Unverified>, Vec<SourceLine> /* judgement */)`.

- [ ] **Step 1: Write the failing tests:**
  - `command_rule_shape`: `["docker","compose","down"]` gives the pattern `^docker\s+compose\s+down(?:\s|$)`, no carve-out, block `["docker compose down"]`, allow `["echo docker compose down"]`, and `verify` is `Ok`;
  - `one_word_gets_help_carve_out`: `["pkill"]` blocks `pkill`, allows `echo pkill` and `pkill --help`;
  - `wrapper_gets_two_rules`: `["sudo"]` gives two `CmdRule`s (one `peeled_wrappers`). `verify` blocks `sudo ls` and `timeout 5 sudo ls`, and allows `echo sudo`;
  - `path_rule_shape`: `Path{"/etc",Write}` gives globs `["/etc","/etc/**"]`, block `/etc/saiife-example` (write) and allow `/saiife-example-other`, and `verify` is `Ok`; `Path{"$PROJECT/.git/hooks",Write}` verifies with the test's project root;
  - `unknown_variable_is_unverified`: `Path{"$NOPE/x",Any}` gives `Unverified` with a reason naming `$NOPE`;
  - `broad_proposals_are_flagged` (Review Focus 1): `Command(["ls"])` gives `broad == Some("blocks everyday `ls`")`; `Path{"/",Write}` (globs `/` and `/**`) is broad; `pkill` is not;
  - `prefix_rule_word_order_is_pinned` (Review Focus 2): `["git","push","--force"]` blocks `git push --force origin` and allows `git push --force-with-lease`. It also allows `git push origin --force`: this pins a documented limit, not a wish;
  - `reason_quotes_the_line`: `reason("CLAUDE.md", 12, "- **Never** run `pkill`.")` is `CLAUDE.md:12 "Never run `pkill`."`; a 300-char line is cut to 160 chars plus `…`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(rules): proposals compiled and checked against their own block and allow examples`.

### Task 3: the opt-in LLM pass (size M)

**Files:** Modify `crates/cli/src/rules_cmd/llm.rs`. Test: unit tests there; `crates/cli/tests/rules_cmd.rs` (`#[cfg(unix)]`).

**Interfaces:**
- Consumes Task 2 (`propose`, `verify`).
- Produces:
  - `pub const INSTRUCTIONS: &str`, fixed copy:
    > `Turn each numbered rule line into guard rules. Reply with JSON only: {"rules":[...]}. Each item is {"kind":"command","line":N,"command":"<program and words>","block":["<command it must block>"],"allow":["<similar command it must allow>"]} or {"kind":"path","line":N,"path":"</abs, ~/ or $VAR path>","access":"read|write|any","block":["<path>"],"allow":["<path>"]}. Use only the lines given. Never propose an allow rule. Leave out lines with no concrete command or path.`
  - `#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct LlmOut { rules: Vec<LlmRule> }`, and `#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)] pub enum LlmRule { Command { line: u32, command: String, block: Vec<String>, allow: Vec<String> }, Path { line: u32, path: String, access: LlmAccess, block: Vec<String>, allow: Vec<String> } }` with `LlmAccess { Read, Write, Any }`;
  - `pub fn parse(out: &str, sent: &[u32]) -> Result<Vec<(LlmRule, Result<(), String>)>, String>`:
    - one ```` ```json ```` fence is stripped;
    - more than 64 rules is `Err`;
    - per rule, a `line` that was not sent, or empty `block` or `allow`, is `Err(why)`;
  - `pub fn to_proposal(r: &LlmRule, line: &SourceLine, file_name: &str, vars: &PathVars) -> Result<Proposal, String>`. The command goes through `extract`'s command-like check and `propose`, and the path through the path check. The LLM's `block` and `allow` are appended to the proposal's own, and `verify` must pass. `origin = Llm`;
  - `pub fn run_claude(lines: &[SourceLine], timeout: Duration) -> Result<String, String>`. It finds `claude` with `saiife_agents::detect::which("claude")`, else `Err("claude is not on PATH; the LLM pass needs Claude Code")`. It spawns `claude -p --tools "" <INSTRUCTIONS>`, writes the lines to stdin, and reads at most 256 KiB of stdout (more is `Err("claude answered more than 256 KiB")`). On timeout it kills the child (`Child::kill`, then `wait`) and returns `Err("claude did not answer in N s")`. A non-zero exit is `Err` with the first 400 bytes of stderr.

- [ ] **Step 1: Write the failing tests:**
  - unit `llm_parse_accepts_the_schema`: `{"rules":[{"kind":"command","line":4,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform plan"]}]}` with `sent = [4]` gives one `Ok` rule;
  - unit `llm_rejects_bad_shapes` (Review Focus 5): `"kind":"allow"`, an extra field `"regex":"x"`, a missing `block`, `line` 9 when `[4]` was sent, and 65 rules each give the expected `Err` or per-rule `Err`;
  - unit `llm_examples_must_pass`: a `command` rule `terraform destroy` with allow `["terraform destroy -auto-approve"]` fails `to_proposal` (the prefix rule blocks it), naming that example;
  - `tests/rules_cmd.rs` (fake `claude` via `fake_exe(env.bin.path(), "claude", "cat >/dev/null; printf '%s' '<json>'")`):
    - `llm_pass_adds_verified_rules`: `rules import --llm CLAUDE.md` with one judgement line (line 2: "Never destroy the staging infra") and stdin `e\n\n` writes a pack with a deny for `terraform destroy` and source line 2. Stderr shows `sending 1 lines of CLAUDE.md to claude -p`;
    - `llm_missing_claude_warns_and_goes_on`: no `claude` on PATH, so stderr has the warning, and the deterministic proposals are still asked;
    - `llm_timeout_kills_and_goes_on`: the script runs `sleep 30`, with `SAIIFE_TEST_LLM_TIMEOUT_MS=300`. It finishes in under 10 s with the timeout warning;
    - `llm_huge_output_is_refused`: the script prints 300 KiB.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(rules): opt-in LLM pass through the user's claude -p, schema-checked, examples verified`.

### Task 4: the confirm table (size M)

**Files:** Modify `crates/cli/src/rules_cmd/confirm.rs`. Test: unit tests there.

**Interfaces:**
- Consumes Task 1's types.
- Produces:
  - `pub struct Eof;`;
  - `pub fn table(props: &[Proposal], unverified: &[Unverified], judgement: &[SourceLine]) -> String`. It is the overview printed to stdout first:
    - one row per proposal: `#`, `file:line`, the rule (`deny command \`pkill\`` / `deny path /etc/** (write)`), blocks, allows, and the flags `BROAD` and `often host only`;
    - then `Not enforced:` with one row per unverified line (`unverified: <why>`) and judgement line (`judgement`);
    - then a count line `N proposed, U unverified, J judgement`;
  - `pub fn confirm(props: Vec<Proposal>, ask_ok: bool, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<Vec<Decided>, Eof>` (D5). It prompts `[i/N] <file:line>  <line text>` and asks `enforce, ask, skip, edit? [e/a/s/x] (s): ` (without `a/` when `ask` is not offered). Unknown answers ask again. `x` asks `new command or path (empty keeps): `. The answer is read as a path if it is path-like, else as command words. It is re-proposed and re-verified through a `&dyn Fn(&SourceLine, Target) -> Result<Proposal, String>` given by the caller, and a failure prints why and asks again.

- [ ] **Step 1: Write the failing tests** (input from `std::io::Cursor`):
  - `defaults_skip_and_everywhere`: two proposals, input `"\ne\n\n"`, give `[Skip, Enforce/Everywhere]`;
  - `host_only_answer`: `"e\nh\n"` gives `Enforce/Host`;
  - `ask_only_where_offered`: `ask_ok = false` with `"a\ne\n\n"` re-asks, then gives Enforce. A path proposal with `ask_ok = true` also re-asks on `a`;
  - `broad_needs_typed_yes` (Review Focus 1): a broad proposal with `"e\ny\n"` re-asks (`y` is not `yes`). `"e\nyes\n\n"` gives Enforce. `"e\n\n"` gives Skip;
  - `edit_reproposes`: `"x\ndocker system prune\ne\n\n"` gives a proposal for those words;
  - `eof_is_an_error` (Review Focus 3): `"e\n"` for two proposals gives `Err(Eof)`;
  - `table_shows_counts_and_unenforced`: the table has the rows, a `Not enforced:` block, and `2 proposed, 1 unverified, 1 judgement`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(rules): the confirm table: enforce, ask, skip or edit, host only or everywhere`.

### Task 5: store and `saiife rules import` (size L)

**Files:** Modify `crates/cli/src/rules_cmd/store.rs` and `crates/cli/src/rules_cmd.rs` (`import`). Test: unit tests in `store.rs`; `crates/cli/tests/rules_cmd.rs`.

**Interfaces:**
- Consumes Tasks 1, 2, 4 (and 3 behind `--llm`); `broker::resolve_here`; plan 32 `view`, `load_user_packs`, `MAX_USER_RULES`, `read_user_packs`.
- Produces:
  - `pub fn packs_dir(t: &Target) -> PathBuf`: `t.config()`'s dir + `policy.d` + `USER_PACKS_DIR`;
  - `pub fn pack_id(abs_source: &Path, name: Option<&str>) -> Result<String, String>` (D6; checked with `valid_user_pack_id`);
  - `pub fn read_source(path: &Path) -> Result<(String /*text*/, String /*sha256 hex*/), String>` (D6; `rustix::process::geteuid().is_root()` decides the one-link check on Unix);
  - `pub struct NewPack { pub id: String, pub file: String /*absolute*/, pub file_sha256: String, pub decided: Vec<Decided>, pub unverified: Vec<Unverified>, pub judgement: Vec<SourceLine> }`;
  - `pub fn render(p: &NewPack) -> String`. It builds a `toml_edit::DocumentMut`:
    - `[pack]` with `id`, `name = "Never-rules from <file name>"`, `description = "saiife rules import; change with saiife rules sync"`, `version = 1`, and `triggers` (the sorted unique first words of the command rules);
    - `[import] file, sha256`;
    - per `Decided` with `Enforce` or `Ask`: its rules, with `id`, `reason`, `source = {file, line, line_sha256}`, `where = "host"` only when chosen (absent otherwise), `ask = true` only on `Ask` denies, and `whole_segment`/`peeled_wrappers` only when true;
    - the carve-out `[[allow]]`, with `source` and `reason = "<w1> --help changes nothing"`;
    - `[[unenforced]]` for `Skip` (`skipped`), unverified (`unverified`) and judgement (`judgement`) lines, with the line text.
  - `pub fn write_pack(dir: &Path, id: &str, text: &str, locked: bool) -> Result<PathBuf, String>`. It makes the dir (0755 locked, 0700 personal), writes `<dir>/.<id>.toml.tmp` (0644 or 0600), fsyncs, and renames to `<dir>/<id>.toml`. An existing `<id>.toml` is an error (`exists; use saiife rules sync`).
  - `import` flow:
    1. resolve the target;
    2. pick the files (D6);
    3. refuse a source that is already imported (scan `view` of each existing pack's `[import] file`);
    4. read the source;
    5. extract;
    6. propose and verify (and the LLM pass);
    7. print the `table`, then `confirm` (`ask_ok = target.is_locked()`), where `Eof` gives `stopped before the last rule; nothing written` and exit 1;
    8. render;
    9. `load_user_packs` of the existing packs plus the new one, for `Host` and `Box`: any `Err` is printed and nothing is written (exit 1);
    10. `write_pack`;
    11. print `wrote <path>: R rules (A ask), N not enforced (J judgement, S skipped, U unverified)`; on a locked target, add `next: saiife policy reload` when `A > 0`.

- [ ] **Step 1: Write the failing tests:**
  - unit `render_round_trips_through_view`: a `NewPack` with one Enforce/Everywhere command, one Ask command, one Enforce/Host path, a skipped line and a judgement line. `view(render(..))` gives those rules with their `where_`, `ask` and `source`, and the three `unenforced` entries. `load_user_packs` accepts it;
  - unit `pack_id_shape`: `/p/CLAUDE.md` gives `user.claude-md-<8 hex>`, stable and different for `/q/CLAUDE.md`; `--name Bad_Name` gives `Err`;
  - `tests/rules_cmd.rs` (personal target, `SAIIFE_TEST_SYSTEM_CONFIG` absent):
    - `import_writes_a_pack_the_hook_enforces`: CLAUDE.md with "Never run `deploy-prod`." and stdin `e\n\n`. The pack is at `<home>/.config/saiife/broker/policy.d/packs/user.claude-md-*.toml`, mode 0600. A developer hook call with Bash `deploy-prod --now` (as in plan 32 Task 6) is denied with the reason `CLAUDE.md:1 "Never run \`deploy-prod\`."`;
    - `import_eof_writes_nothing` (Review Focus 3): stdin empty, so exit 1 with the message and no pack file;
    - `import_all_skipped_writes_nothing`: stdin `s\n`, so exit 0 with `no rule confirmed; nothing written`;
    - `second_import_is_refused`: importing the same file again exits 1 with `already imported as user.claude-md-…; use saiife rules sync`;
    - `default_files_are_found_in_the_project`: no file argument with `AGENTS.md` in the project root imports it; with none, exit 2 naming the three names;
    - `over_the_rule_cap_writes_nothing` (Review Focus 1): a colon list of 70 made-up programs gives 70 proposals, each a deny plus a carve-out, so 140 rules. With stdin answering `e` and then empty for each, the import exits 1 naming `128` and writes nothing;
    - `symlinked_source_is_refused` (`#[cfg(unix)]`);
  - locked target (the `admin()` `TestDaemon` of `tests/connect_cmd.rs:20-25`, with an approver added to its config, and `--config`): `import_on_locked_target_offers_ask`. Stdin `a\n\n` writes `<etc>/policy.d/packs/<id>.toml` with `ask = true`, prints `next: saiife policy reload`, and after `saiife policy reload --config …` the daemon's `[guard] ask` has the rule (`policy show` lists it).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean; `bash scripts/check-windows.sh -p saiife`.
- [ ] **Step 5: Commit** `feat(rules): saiife rules import writes a confirmed user pack`.

### Task 6: `saiife rules sync` (size M)

**Files:** Modify `crates/cli/src/rules_cmd/sync.rs` and `rules_cmd.rs` (`sync`). Test: unit tests in `sync.rs`; `crates/cli/tests/rules_cmd.rs`.

**Interfaces:**
- Consumes Tasks 1, 2, 4, 5 and plan 32's `view`.
- Produces:
  - `pub struct SyncPlan { pub moved: Vec<(String /*line_sha256*/, u32 /*from*/, u32 /*to*/)>, pub gone: Vec<(SourceRef, String /*text*/, usize /*rules*/)>, pub new: Vec<Candidate>, pub file_sha256: String }`;
  - `pub fn plan(view: &UserPackView, text: &str) -> SyncPlan` (D7: matches by `line_sha256`, takes the nearest line, and uses `extract::candidates` for `new`);
  - `pub fn apply(pack_text: &str, plan: &SyncPlan, removed: &[String /*line_sha256*/], added: &[Decided], unenforced: &[(SourceLine, UnenforcedWhy)]) -> Result<String, String>`. It edits with `toml_edit`:
    - sets `source.line` on moved rules and unenforced entries;
    - deletes the array elements whose `source.line_sha256` is in `removed`;
    - drops gone unenforced entries;
    - appends the new rules (the first free ids, D2) and unenforced entries;
    - sets `[import] sha256`;
    - keeps every other key and comment.
  - `sync` flow: for each user pack (or `--pack`) with `[import]`:
    1. read the source (missing → `warning: <file>: source gone; rules kept`);
    2. an equal SHA prints `unchanged`;
    3. otherwise print `~ line A → B`, `- line N gone: "<text>" (k rules)` and `+ line N: "<text>"`;
    4. ask `keep? [K/r]` for each gone line;
    5. propose and confirm the new lines (`--llm` as in import);
    6. `apply`, `load_user_packs` of all packs (both profiles), and write through temp + rename over the old file;
    7. `Eof` writes nothing and exits 1.

- [ ] **Step 1: Write the failing tests:**
  - unit `moved_line_keeps_rule` (Review Focus 4): a pack from "a\nNever run `x1`." and the new text "intro\na\nNever run `x1`." give `moved == [(h, 2, 3)]`; `apply` sets `line = 3` and keeps the rule id;
  - unit `apply_keeps_hand_edits`: a pack with a hand-added comment and an `operand_min_len = 2` key on a rule keeps both after `apply`;
  - `tests/rules_cmd.rs`:
    - `gone_line_kept_by_default`: after import, the line is deleted from CLAUDE.md, and `rules sync` with stdin `\n` keeps the rule, updates `[import] sha256`, and prints `- line 1 gone`;
    - `gone_line_removed_on_r`: the same with `r\n` removes the rule and its carve-out. When that leaves zero rules, the sync deletes the pack file and prints `user.… removed: no rules left` (an empty pack would fail plan 32's load);
    - `new_line_is_only_proposed`: an added "Never run `x2`." with stdin `s\n` adds an `[[unenforced]] why = "skipped"` entry and no rule. With `e\n\n` it adds a deny `l<line>-1`;
    - `sync_eof_writes_nothing` (Review Focus 3): empty stdin with a gone line exits 1, and the pack file is unchanged (byte for byte);
    - `unchanged_source_says_so`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(rules): saiife rules sync: moved lines follow, gone lines keep their rules, new lines are only proposed`.

### Task 7: `saiife rules list`, the `status` note, docs (size M)

**Files:**
- Modify `crates/cli/src/rules_cmd/list.rs`, `crates/cli/src/status_cmd.rs` (a note per changed source, after the packs line), `docs/never-rules.md` (adds "Import", "Sync", "What is not enforced").
- Test: `crates/cli/tests/rules_cmd.rs`, `crates/cli/tests/status_cmd.rs`, `crates/cli/tests/docs_wording.rs` (one assertion).

**Interfaces:**
- Consumes plan 32's `view`, `box_status`, `BoxStatus::label`, `load_user_packs`, `broad_findings`, and Task 5's `packs_dir` and `read_source`.
- Produces:
  - `pub fn render_list(packs: &[(PathBuf, UserPackView, Vec<Broad>)], locked: bool, source_state: &dyn Fn(&ImportRef) -> SourceState) -> String`, where `pub enum SourceState { Same, Changed, Gone }`.
    - Per pack: `<id>  <import file>  R rules (A ask), N not enforced` plus ` [source changed: run saiife rules sync]` or ` [source gone]`.
    - Per rule: `  <id>  <deny|deny path (access)|allow>  <text>  where=<host|everywhere>  host: <enforced|ask|ask (denied: approvals need locked mode)>  box: <BoxStatus::label>  <file:line>`, plus `  BROAD: blocks everyday <example>` when flagged.
    - Then `  not enforced: <file:line> <why>: "<text>"` lines.
  - `--json` gives `{"packs":[{"id","path","import":{"file","sha256","state"},"rules":[{"id","kind","text","where","mode","host","box","source":{"file","line"}}],"unenforced":[{"line","why","text"}]}]}`;
  - `status`: for each pack in the personal dir, and in the locked dir when it is readable, `Changed` adds the note `rules: <file> changed since it was imported (<id>); run saiife rules sync`, and `Gone` adds `rules: <file> is gone; its rules stay in force (<id>)`.

- [ ] **Step 1: Write the failing tests:**
  - `list_shows_host_and_box_status`: after importing a pack with an everywhere command, a host-only command and an everywhere `write` path, `saiife rules` shows `box: advisory in boxes`, `box: off in boxes (host only)` and `box: checked at diff review`, plus the `not enforced` lines;
  - `list_json_shape`: one pack to JSON, compared to a literal (with the hash replaced);
  - `list_flags_broad_rules`: a pack with an enforced broad rule shows `BROAD:`;
  - `status_notes_a_changed_source` (Review Focus 4): after import, editing CLAUDE.md makes `saiife status` print the note while its exit code is unchanged (0 in an otherwise clean `Env`). After `rules sync`, the note is gone;
  - `docs_wording.rs`: `never_rules_page_names_its_limits`. `docs/never-rules.md` exists, is linked from `README.md`, and contains `advisory in boxes`, `not enforced`, and the §15 limit sentence `Obfuscation and interpreters (python -c) can still slip past a command rule.`
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** The docs:
  - "Import": the flow, the table, the answers, the LLM pass (opt-in; what is sent; your own login);
  - "Sync": D7;
  - "What is not enforced": judgement lines, the ~half estimate (§10.2), the §15 limits, the word-order gap of prefix rules (Review Focus 2), and that piped answers can only add restrictions.
- [ ] **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(rules): saiife rules list (host and box status), status note on changed sources, docs`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP as in Global Constraints, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`):
  - `cargo fmt --all --check`;
  - `cargo clippy --workspace --all-targets -j 4 -- -D warnings`;
  - `cargo test -p saiife -p saiife-guard -p saiife-policy -j 4 -- --test-threads=4`;
  - the CI tokio gate prints `0`;
  - `bash scripts/check-unsafe.sh`;
  - `bash scripts/check-windows.sh -p saiife`;
  - `scripts/test-offline.sh`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR to `v3-dev`. The owner merges.

## Follow-ups (not in this plan)

- New rule types (§10.6: a tool-name deny, a cwd/env condition, a content scan). The lines they would cover stay `judgement` until then.
- A Workspace view of the rules (needs a plan 28 contract addition).
- Importing `.cursor/rules/*` and `.claude/rules/*` directories as one pack each (today: name each file).

## Owner handwork

- [ ] Check `claude -p --tools ""` against your installed Claude Code (`claude --help`). If the flag differs, tell the builder the right one (D4). Check that the current terms allow this use of your own login (it is your own headless call, the same as running `claude -p` yourself).
- [ ] On a scratch copy of your `hard-rules.md` (never the real `~/.claude/CLAUDE.md` in a test), run `saiife rules import <copy>` once. Count the proposals against §10.2's estimate (~13 enforceable), and report lines the extraction missed or got wrong.
