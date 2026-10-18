# Plan 4: HTML audit report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife audit --report [PATH]` writes one self-contained HTML file that a non-developer (a DPO, a manager) can read, and the plan-1 masking/escaping carry-over is closed.

**Architecture:** Three pure layers in the `saiife` cli crate, then the I/O. `report.rs` turns the filtered records plus the built-in packs into a `Report` value (summary, blocked list, fail-open list, active packs per project, full list). `report_html.rs` renders a `Report` to one HTML string: inline CSS, no JavaScript, no external resources, a CSP meta tag that forbids loading anything, and `<details>` for the collapsible full list. `audit_cmd.rs` reuses the existing filters, builds the report and writes it atomically through a temp file with a strict output-path check.

**Tech Stack:** Rust 2021, existing crates only (clap 4, time 0.3, serde_json, regex). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` §6.4 (report), §6.2–6.3 (record, masking), §5 (`saiife audit --report [path]`), §10 (audit tests), §1.2 principles 5 and 7.

## Global Constraints

- Report: "One file, no external resources (inline CSS, no JS dependencies, no fonts or images from the network)."
- Sections, in this order: "1. Summary: period, projects, agents, total decisions, blocked count, fail-open count. 2. Blocked actions: time, agent, project, input, pack, reason. 3. Fail-open events. 4. Active packs per project with their rules in plain language. 5. Full decision list (collapsible)."
- "Written for a non-developer reader: plain-language headings, rule descriptions instead of regexes." No regex or glob text appears in the report.
- Test (§10): "report contains no `http://`/`https://` resource references". Inputs may contain URLs as text, but they never become `href`/`src`.
- Plaintext secrets never reach disk (§6.3): the report prints only stored, already masked `input`, and adds no unmasked field.
- Offline (§1.2.7): no network use; the whole suite passes with networking disabled (`scripts/test-offline.sh`).
- Tests point `SAIIFE_AUDIT_DIR`, `SAIIFE_DATA_DIR`, `HOME` and the working directory at tempdirs. Never write a report into the repo or the real home.
- Main changes only through a PR from branch `plan-4-report`; CI checks `test (ubuntu-latest)`, `test (macos-latest)`, `offline` must pass.
- Times are shown in UTC and labelled "UTC" (the terminal table already uses UTC; there is no timezone crate).

## Review Focus

1. **Agent-controlled text in the report** (`<script>`, `</td>`, `"onload=`, bidi overrides, LRM/RLM/ALM, NUL, a 4096-char input): it must render as inert, visible text. Owned by Task 2 (`hostile_text_is_inert`) and Task 3 (`escape_*`).
2. **Choosing a dangerous output path** (an agent runs `saiife audit --report .claude/settings.json`, or a symlink named `r.html` that points at a hook config): it must be refused, and the target must stay byte-for-byte unchanged. Owned by Task 4 (`refuses_non_html_path`, `refuses_symlink_target`).
3. **Empty, filtered or huge logs** (no records; `--blocked` only; 20 000 records): you get a valid report that says "None in this period" where a section is empty, names the filters used, and shows the full list collapsed. Owned by Task 2 (`empty_report`) and Task 4 (`large_log_renders`).
4. **A project folder that no longer exists, or has no `.saiife/config.toml`**: the packs section says the default packs are shown and why, without crashing or using a parent folder's config. Owned by Task 2 (`missing_project_config_shows_defaults`).
5. **Unknown decision values from a newer saiife** (`error_denied`): counted as "Other" and listed in the full list, never dropped. Owned by Task 2 (`unknown_decision_is_listed`).

---

### Task 1: Masking and escaping carry-over

Closes the plan-1 carry-over: mask `mysql -pPASS`, stop the URL rule over-masking across quotes, escape LRM/RLM/ALM. It also moves the terminal sanitizer into a shared module, so the report (Task 3) uses the same character rules.

**Files:**
- Modify: `crates/audit/src/mask.rs` (rules list and tests)
- Create: `crates/cli/src/text.rs` (shared `sanitize`)
- Modify: `crates/cli/src/audit_cmd.rs` (use `text::sanitize`, delete the local copy)
- Modify: `crates/cli/src/main.rs` (`mod text;`)

**Interfaces:**
- Produces: `pub fn sanitize(s: &str) -> String` in `crates/cli/src/text.rs`. It keeps today's behavior: newline → `⏎`, control chars → `\xNN`, bidi `U+202A–202E`/`U+2066–2069` → `\u{NNNN}`. It adds `U+200E`, `U+200F` and `U+061C` to the `\u{NNNN}` set.

- [ ] **Step 1: Write the failing tests in `mask.rs`**

```rust
#[test]
fn mysql_attached_password() {
    assert_eq!(mask("mysql -uroot -phunter2 db"), "mysql -uroot -p[MASKED] db");
    assert_eq!(mask("mysqldump -p'a b' db"), "mysqldump -p[MASKED] db");
    assert_eq!(mask("mariadb -h h -p\"x\" db"), "mariadb -h h -p[MASKED] db");
    assert_eq!(mask("mysqladmin -psecret status"), "mysqladmin -p[MASKED] status");
    // `-p` alone prompts; `-P` is the port; other tools keep -p.
    assert_eq!(mask("mysql -u root -p db"), "mysql -u root -p db");
    assert_eq!(mask("mysql -P 3306 db"), "mysql -P 3306 db");
    assert_eq!(mask("mkdir -p dir"), "mkdir -p dir");
    assert_eq!(mask("ssh -p2222 host"), "ssh -p2222 host");
}

#[test]
fn url_userinfo_does_not_cross_quotes() {
    let s = r#"{"u":"https://h","email":"a@b.c"}"#;
    assert_eq!(mask(s), s);
    assert_eq!(mask("curl 'https://h' -d 'x@y'"), "curl 'https://h' -d 'x@y'");
    // A comma may be part of a password: still masked.
    assert_eq!(mask("curl https://u:p,w@host/x"), "curl https://[MASKED]@host/x");
}
```

- [ ] **Step 2: Run `cargo test -p saiife-audit mask`.** Expected: FAIL in both new tests.

- [ ] **Step 3: Change the mask rules.**
  - URL rule: the userinfo class becomes `[^/?#\s"'`<>]+`.
  - New rule after the `--password` flag rule: `(?i)(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^|;&\n]*?\s-p)(?:'[^']*'|"[^"]*"|[^\s'"]+)` → `${1}[MASKED]`. It applies only when a value is attached to `-p`, within one command segment.

- [ ] **Step 4: Run `cargo test -p saiife-audit`.** Expected: PASS, all old mask tests included.

- [ ] **Step 5: Write the failing test in `text.rs`, then move `sanitize` there**

```rust
#[test]
fn directional_marks_are_escaped() {
    assert_eq!(sanitize("a\u{200E}b\u{200F}c\u{061C}d"), "a\\u{200E}b\\u{200F}c\\u{061C}d");
    assert_eq!(sanitize("x\ny\u{1b}"), "x⏎y\\x1b");
}
```

  Move `sanitize` out of `audit_cmd.rs` and import it from there. The existing `audit_cmd` tests must pass unchanged.

- [ ] **Step 6: Run `cargo test -p saiife` and `cargo clippy --workspace -- -D warnings`.** Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/audit/src/mask.rs crates/cli/src/text.rs crates/cli/src/audit_cmd.rs crates/cli/src/main.rs
git commit -m "fix(audit): mask mysql -pPASS, keep URL masking inside quotes, escape LRM/RLM/ALM"
```

---

### Task 2: Report model

A pure function from records to a `Report`. Plain-language labels are decided here, so the HTML layer only lays them out.

**Files:**
- Create: `crates/cli/src/report.rs`
- Modify: `crates/cli/src/main.rs` (`mod report;`)

**Interfaces:**
- Consumes: `saiife_audit::{Record, DecisionKind}`, `saiifeguard::Pack` (`name`, `description`, `default_on`, `deny`, `allow`, `deny_path`, `allow_path`, each rule's `reason: String`), `crate::project::project_packs(start: &Path, known: &[Pack]) -> ProjectPacks`.
- Produces (all `pub`, all `#[derive(Debug, Clone, PartialEq, Eq)]`):

```rust
pub struct Report {
    pub generated: String,          // "2026-10-18 09:12 UTC"
    pub period: String,             // see Step 3
    pub filters: Vec<String>,       // e.g. ["only blocked actions", "agent: Codex"]
    pub projects: Vec<String>,      // distinct, sorted
    pub agents: Vec<String>,        // display names, distinct, sorted
    pub total: usize,
    pub blocked: usize,
    pub fail_open: usize,
    pub other: usize,               // DecisionKind::Unknown
    pub blocked_rows: Vec<Row>,     // newest first
    pub fail_open_rows: Vec<Row>,   // newest first
    pub all_rows: Vec<Row>,         // newest first
    pub packs: Vec<ProjectPacksView>,
}
pub struct Row {
    pub time: String,               // "2026-10-13 08:14:02" (UTC)
    pub agent: String,              // display name
    pub project: String,
    pub tool: String,
    pub decision: &'static str,     // label, see Step 3
    pub input: String,              // stored input; empty → "(no input recorded)"
    pub pack: String,               // pack *name* ("Core: secrets"); unknown id → id; none → ""
    pub reason: String,
}
pub struct ProjectPacksView {
    pub project: String,
    pub note: Option<String>,       // why defaults are shown, see Step 3
    pub packs: Vec<PackView>,
}
pub struct PackView {
    pub name: String,
    pub description: String,
    pub blocks: Vec<String>,        // unique non-empty deny + deny_path reasons, file order
    pub exceptions: Vec<String>,    // unique non-empty allow + allow_path reasons, file order
}

pub fn build(records: &[&Record], packs: &[Pack], filters: Vec<String>,
             since: Option<OffsetDateTime>, now: OffsetDateTime) -> Report;
pub fn agent_label(id: &str) -> String;
```

- [ ] **Step 1: Write the failing unit tests in `report.rs`**

Build records with `Record::at(NewRecord{..}, "0.1.0", datetime!(…))`, as in `audit_cmd.rs` tests, and packs with `builtin_packs()`.
  - `summary_counts_and_labels`: 1 allow, 2 deny (`core.secrets`), 1 error_allowed. Assert:
    - `total == 4`, `blocked == 2`, `fail_open == 1`, `blocked_rows.len() == 2`;
    - `blocked_rows[0].pack == "Core: secrets"`, `all_rows[0]` is the newest;
    - `agent_label("claude") == "Claude Code"`, `"codex" → "Codex"`, `"gemini" → "Gemini CLI"`, `"x" → "x"`.
  - `period_uses_since_or_record_span`. With `since`: `period == "2026-10-11 08:14 UTC to 2026-10-18 09:00 UTC"` (since to now). Without it: earliest to latest record. With no records: `"no records"`.
  - `empty_report`: zero records gives every count 0, empty row vecs and empty `packs`.
  - `unknown_decision_is_listed`: an `error_denied` record parsed from JSON gives `other == 1` and appears in `all_rows` with decision `"Other"`.
  - `active_packs_per_project`: a tempdir project whose `.saiife/config.toml` has `packs = ["db.postgres"]`. Its view lists every default-on pack name plus `db.postgres`'s name, `note == None`, and `core.secrets` `blocks` includes the `.env` reason text. Assert that no `blocks` or `exceptions` string equals any rule's `pattern` or `glob`.
  - `missing_project_config_shows_defaults`:
    - a project path that does not exist gives `note == Some("This folder no longer exists; the default packs are shown.")`;
    - an existing folder with no config, inside a parent that has one, gives `note == Some("No saiife config in this folder now; the default packs are shown.")`, and the parent's opt-in packs are not used;
    - in both cases `packs` are the default-on packs.
  - `hostile_text_is_inert`: an input of `<script>alert(1)</script>` is stored unchanged in `Row.input`. Escaping is Task 3's job, and this test pins that the model does not pre-escape, which would double-escape.

- [ ] **Step 2: Run `cargo test -p saiife report::`.** Expected: FAIL (module missing).

- [ ] **Step 3: Implement `build` and `agent_label`.** Decisions the tests do not fix:
  - Decision labels: Allow → `"Allowed"`, Deny → `"Blocked"`, ErrorAllowed → `"Allowed unchecked (fail-open)"`, Unknown → `"Other"`.
  - Time formats use `[year]-[month]-[day] [hour]:[minute]` plus `" UTC"` for `generated`/`period`, and `ts[..19]` with `T` → space for rows (the same as the terminal table). A record whose `ts` does not parse keeps its raw `ts` and sorts last.
  - Projects view: for each distinct project, `project_packs(Path::new(p), packs)`. Its config counts only if `root == Some(p)`; otherwise use the defaults with the note from Step 1. Active = `default_on` packs in built-in order, plus enabled opt-in packs in built-in order. Precede the packs section with one fixed sentence in Task 3: "Packs as configured today; they may have differed during the period."
  - Filters: `audit_cmd` passes the strings in (Task 4). `build` stores them as given.

- [ ] **Step 4: Run `cargo test -p saiife report::`.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/report.rs crates/cli/src/main.rs
git commit -m "feat(report): build a plain-language report model from audit records"
```

---

### Task 3: HTML rendering

**Files:**
- Create: `crates/cli/src/report_html.rs`
- Modify: `crates/cli/src/main.rs` (`mod report_html;`)

**Interfaces:**
- Consumes: `crate::report::{Report, Row, ProjectPacksView, PackView}` (Task 2) and `crate::text::sanitize` (Task 1).
- Produces: `pub fn render(r: &Report) -> String` and `pub fn escape(s: &str) -> String`. `escape` applies `sanitize`, then replaces `&` `<` `>` `"` `'` with `&amp;` `&lt;` `&gt;` `&quot;` `&#39;`.

- [ ] **Step 1: Write the failing unit tests**
  - `escape_html_and_controls`: `escape("<a href=\"x\">&'</a>\u{202e}\u{200f}\n")` is `"&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;\\u{202E}\\u{200F}⏎"`.
  - `page_is_self_contained`. Render a report whose inputs hold `curl https://evil.example/x` and `<img src=https://e/x>`. Then assert all of the following:
    - the output starts with `<!doctype html>`;
    - it contains `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`;
    - it contains `<meta charset="utf-8">`;
    - it contains no `<script`, `<link`, `<img`, `src=`, `href=`, `url(` or `@import`, case-insensitive;
    - every `http://`/`https://` occurrence is inside escaped row text: removing the two inputs' escaped forms leaves no `http`.
  - `sections_in_spec_order`. The headings appear in this order:
    - "Summary"
    - "Blocked actions"
    - "Allowed without a check (fail-open)"
    - "Protection rules in use"
    - "Every decision"

    "Every decision" sits inside a `<details>` whose `<summary>` reads `Show all N decisions`.
  - `empty_sections_say_none`: with zero records, the blocked and fail-open sections each contain "None in this period.", and the packs section contains "No projects in this period."
  - `summary_lists_filters_and_counts`: with a report that has filters `["only blocked actions"]`, the output contains the period, "Filters: only blocked actions", and the total, blocked and fail-open numbers as text.
  - `hostile_text_is_inert`: a row input `</td><script>alert(1)</script>` and a reason `"onload="x` appear only in escaped form.

- [ ] **Step 2: Run `cargo test -p saiife report_html::`.** Expected: FAIL.

- [ ] **Step 3: Implement `render`.** Decisions the tests leave open:
  - `<title>saiife audit report</title>`, `lang="en"`, and the viewport meta.
  - About 40 lines of inline CSS: a system font stack, readable tables with `word-break: break-word` on input cells, a print-friendly layout, and colors that work in light and dark (`prefers-color-scheme`).
  - Each section has one plain sentence under its heading:
    - Blocked actions: "Actions an AI agent tried that saiife stopped."
    - Fail-open: "Actions saiife let through without judging them, for example because it could not read the request. Each one is a gap in protection."
    - Protection rules: the sentence fixed in Task 2 Step 3.
  - Columns:
    - Blocked: Time (UTC), Agent, Project, Action, Rule pack, Why.
    - Fail-open: Time (UTC), Agent, Project, Action, Why.
    - Every decision: Time (UTC), Agent, Project, Tool, Decision, Action.
  - Packs: each project is a sub-heading (plus its note), and each pack shows its name, description, "Blocks:" bullet list and "Allowed exceptions:" bullet list (omitted when empty).
  - Footer: "Generated by saiife {CARGO_PKG_VERSION} on {generated}. Inputs are masked: secrets are shown as [MASKED]."

- [ ] **Step 4: Run `cargo test -p saiife report_html::`.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/report_html.rs crates/cli/src/main.rs
git commit -m "feat(report): render the audit report as one self-contained HTML page"
```

---

### Task 4: `saiife audit --report [PATH]`, safe write, docs

**Files:**
- Modify: `crates/cli/src/main.rs` (the `Audit` args)
- Modify: `crates/cli/src/audit_cmd.rs` (`run` gains `report: Option<String>`, plus the new `write_report`)
- Create: `crates/cli/tests/audit_report.rs`
- Modify: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md` (plan 4 row → `written: 2026-10-18-plan-4-html-report.md`; strike the plan-1 "Plan 4 (report)" carry-over line as done, in the existing `~~…~~ — done in plan 4: …` style)
- Modify: `README.md` (one line for `saiife audit --report`, if the README lists commands)

**Interfaces:**
- Consumes: `report::build` (Task 2), `report_html::render` (Task 3), `store::{read_all, Filter}`, `parse_since`.
- Produces: `pub fn write_report(path: &Path, html: &str) -> Result<(), String>` and `pub fn default_report_name(now: OffsetDateTime) -> String` (`"saiife-report-2026-10-18.html"`).

- [ ] **Step 1: Write the failing integration tests in `crates/cli/tests/audit_report.rs`**

Seed records with `append` into a tempdir `SAIIFE_AUDIT_DIR`, as in `tests/audit_cmd.rs`. Set `HOME` and `SAIIFE_DATA_DIR` to tempdirs, and `current_dir` to a temp working dir.
  - `writes_default_named_report`: `saiife audit --report` exits 0 and creates `saiife-report-<today UTC>.html` in the working dir. Stdout is `Report written: <absolute path> (N decisions)`. The file contains "Blocked actions" and a seeded blocked input.
  - `explicit_path_and_filters`: `saiife audit --since 7d --blocked --report out/r.html` (with `out/` created first) writes `out/r.html`. Its file has "Filters: last 7d, only blocked actions" and no allowed input. Filter strings: `last {since}`, `project: {p}`, `agent: {agent_label}`, `only blocked actions`, in that order, joined with ", ".
  - `refuses_non_html_path`: `--report settings.json` and `--report .claude/settings.json` exit 2 with stderr `the report file name must end in .html or .htm`. A pre-existing `.claude/settings.json` stays byte-identical.
  - `refuses_symlink_target`: with `r.html` → a symlink to `target.json`, `--report r.html` exits 2 with stderr containing `is not a regular file`, and `target.json` is unchanged. A directory named `d.html` is refused the same way.
  - `overwrites_existing_regular_report`: an existing regular `r.html` holding `old` gets replaced. No `.saiife-report-*.tmp` file is left in the folder.
  - `missing_parent_dir_is_an_error`: `--report nope/r.html` exits 2 with stderr containing `cannot write`.
  - `bad_since_still_exit_2`: `--since 7w --report` exits 2 and writes no file.
  - `large_log_renders`: 20 000 seeded records give exit 0 in under 10 s in a debug build. The file contains `Show all 20000 decisions`.

- [ ] **Step 2: Run `cargo test -p saiife --test audit_report`.** Expected: FAIL (unknown argument `--report`).

- [ ] **Step 3: Add the argument.** In `Cmd::Audit` add the following, with doc comment "Write a self-contained HTML report instead of the table (default name: saiife-report-YYYY-MM-DD.html here).":

```rust
#[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "")]
report: Option<String>,
```

  An empty value means the default name in the working directory. Pass it through to `audit_cmd::run`.

- [ ] **Step 4: Implement `write_report`.** The order of checks is fixed:
  1. The file name's extension, ASCII case-insensitive, must be `html` or `htm`. Otherwise fail with the exact message from Step 1.
  2. `symlink_metadata(path)`: if it exists and is not a regular file, return `"{path} is not a regular file; refusing to write the report"`.
  3. Write to `.<file name>.saiife-report-<pid>.tmp` in the same directory, using `OpenOptions::new().write(true).create_new(true)`. On Unix also set `custom_flags(libc::O_NOFOLLOW)`, or skip the flag if the cli crate has no libc: `create_new` already refuses an existing path. Then `rename` it over the target. On any I/O error, remove the temp file and return `"cannot write {path}: {e}"`.

  In `run`, when `report` is `Some`: validate `--since` first (exit 2 on error, as today), read and filter as today, build, render, write, and print the stdout line. A write error prints `saiife: {msg}` and exits 2. An empty record set still writes a report (the "None in this period." text). Otherwise (`report` is `None`) the table path is unchanged.

- [ ] **Step 5: Run `cargo test --workspace`, `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `scripts/test-offline.sh`.** Expected: all PASS.

- [ ] **Step 6: Generate a sample report from seeded tempdir records and open it once in a browser by hand.** Check that it reads cleanly at phone width and in print preview. The sample goes in a `mktemp -d -p /home/jonas/projects/personal/saiife` dir, never in the repo. Record what you checked in the commit body.

- [ ] **Step 7: Update the roadmap and README lines listed under Files, then commit**

```bash
git add crates/cli/src/main.rs crates/cli/src/audit_cmd.rs crates/cli/tests/audit_report.rs docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md README.md
git commit -m "feat(audit): saiife audit --report writes the HTML report safely"
```
