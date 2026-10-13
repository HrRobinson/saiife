# saiife Plan 1 — Foundation + Audit Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the Rust command guard out of `localflow` into this repo as a `saiife` binary that audits every decision (masked) and can show the audit log in the terminal, with CI proving it runs offline.

**Architecture:** Cargo workspace with three crates: `crates/guard` (the existing engine, unchanged API, lib name `saiifeguard`), `crates/audit` (record, masking, storage, filtering) and `crates/cli` (the `saiife` binary). `saiife check` evaluates a hook payload with the guard, appends one masked JSONL record per decision to a monthly file in the user data dir, and responds to the agent exactly as before.

**Tech Stack:** Rust stable (edition 2021), clap 4, serde/serde_json, regex, time 0.3, dirs 5; tests with assert_cmd, predicates, tempfile; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` (this plan covers §3, §4, §6.1–6.3, the offline CI part of §8, and §11). Roadmap of all five plans: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`.

## Global Constraints

- **Fail open.** Any internal error, parse failure or exceeded latency budget allows the command. The event is still audited.
- **Latency budget:** 50 ms per evaluation (existing `DEFAULT_BUDGET`, do not change).
- **No network.** The binary makes no network calls of any kind.
- Audit storage: `$XDG_DATA_HOME/saiife/audit/YYYY-MM.jsonl` (via `dirs::data_dir()`; macOS `~/Library/Application Support/saiife/audit/`). Never inside the project directory. Append-only, one file per calendar month. A failed write never blocks or alters the decision.
- Audit `decision` ∈ `allow` | `deny` | `error_allowed`.
- Plaintext secrets never reach disk: `input` is masked before writing.
- Binary name: `saiife`. Repo: `HrRobinson/saiife`. License: MIT.
- Platforms: Linux and macOS. No Windows.
- `#![forbid(unsafe_code)]` in every crate.

## Review Focus

1. **Audit dir unwritable** (read-only disk, path is a file, permissions): the guard verdict must be identical to a normal run. → Task 5 test `unwritable_audit_dir_keeps_verdict`.
2. **Parallel agents** firing hooks at the same moment into the same monthly file: every line must stay a complete, parseable record. → Task 5 test `concurrent_checks_write_whole_lines`.
3. **Very large command** (up to the 256 KiB payload cap): the record must stay bounded and never split a multi-byte character. → Task 3 tests `long_input_is_truncated_on_char_boundary` and `multibyte_input_truncates_without_panic`.
4. **Corrupt audit file** (half-written line after a crash, hand edits, an unrelated file in the dir): `saiife audit` must skip the bad lines and show the rest. → Task 4 test `read_all_skips_garbage_lines_and_foreign_files`.
5. **Audit log readable by other users** on a shared machine: commands may reveal what people work on. Files must be created `0600`. → Task 4 test `new_file_is_owner_only`.

---

### Task 0: Toolchain prerequisites

This machine has no Rust toolchain and no `git-filter-repo`. These commands need `sudo`, so the **human** runs them.

**Files:** none.

- [ ] **Step 1: Install rustup and git-filter-repo (Arch Linux)**

```bash
sudo pacman -S --needed rustup git-filter-repo
rustup default stable
```

- [ ] **Step 2: Verify**

Run: `cargo --version && rustc --version && git filter-repo --version`
Expected: three version lines, no errors.

---

### Task 1: Import the guard with its git history

**Files:**
- Create (via merge): `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `crates/saiifeguard/**`

**Interfaces:**
- Consumes: `localflow` repo at `/home/jonas/projects/personal/saiife/localflow`, branch `main`, directory `guard/`.
- Produces: the unchanged guard workspace at the repo root, with its history.

- [ ] **Step 1: Make a filtered copy of localflow containing only `guard/`**

```bash
IMPORT=$(mktemp -d)
git clone --no-local --branch main /home/jonas/projects/personal/saiife/localflow "$IMPORT/localflow"
git -C "$IMPORT/localflow" filter-repo --subdirectory-filter guard --force
git -C "$IMPORT/localflow" log --oneline | head
```

Expected: a short list of guard commits; `ls "$IMPORT/localflow"` shows `Cargo.toml Cargo.lock crates rust-toolchain.toml`.

- [ ] **Step 2: Merge it into this repo**

```bash
cd /home/jonas/projects/personal/saiife/saiife-cli
git remote add guard-import "$IMPORT/localflow"
git fetch guard-import
git merge --allow-unrelated-histories guard-import/main -m "chore: import saiifeguard from localflow with history"
git remote remove guard-import
rm -rf "$IMPORT"
```

- [ ] **Step 3: Verify the import builds and tests pass unchanged**

Run: `cargo test --quiet`
Expected: every `test result:` line says `ok`, 0 failed.

No commit needed: the merge is the commit.

---

### Task 2: Restructure into the workspace and rename the binary to `saiife`

**Files:**
- Move: `crates/saiifeguard/` → `crates/guard/`
- Move: `crates/guard/src/main.rs` → `crates/cli/src/main.rs`
- Move: `crates/guard/tests/cli.rs` → `crates/cli/tests/cli.rs`
- Move: `crates/guard/tests/hook_exit.rs` → `crates/cli/tests/hook_exit.rs`
- Modify: `Cargo.toml`, `crates/guard/Cargo.toml`, `crates/cli/src/main.rs`, `crates/cli/tests/cli.rs`, `crates/cli/tests/hook_exit.rs`, `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` (§4 layout)
- Create: `crates/cli/Cargo.toml`, `.gitignore`, `README.md`

**Interfaces:**
- Consumes: guard lib API `saiifeguard::{builtins::builtin_packs, engine::{Engine, Decision, AllowTrace}, payload::{command_from_hook_json, MAX_PAYLOAD_BYTES}, profile::select_active}`.
- Produces: binary `saiife` with subcommands `test`, `explain`, `check` (same behavior as `saiifeguard`); package `saiife-guard` whose lib is still named `saiifeguard`.

- [ ] **Step 1: Move files**

```bash
cd /home/jonas/projects/personal/saiife/saiife-cli
git mv crates/saiifeguard crates/guard
mkdir -p crates/cli/src crates/cli/tests
git mv crates/guard/src/main.rs crates/cli/src/main.rs
git mv crates/guard/tests/cli.rs crates/cli/tests/cli.rs
git mv crates/guard/tests/hook_exit.rs crates/cli/tests/hook_exit.rs
```

- [ ] **Step 2: Replace the root `Cargo.toml`**

```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.package]
edition = "2021"
version = "0.1.0"
license = "MIT"
repository = "https://github.com/HrRobinson/saiife"

[profile.release]
# saiife is spawned per command by agent hooks; a small, fast binary matters.
opt-level = 3
lto = true
strip = true
```

- [ ] **Step 3: Replace `crates/guard/Cargo.toml`**

```toml
[package]
name = "saiife-guard"
description = "Command guard engine for saiife — blocks destructive shell commands before agents run them."
edition.workspace = true
version.workspace = true
license.workspace = true
repository.workspace = true

[lib]
name = "saiifeguard"
path = "src/lib.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
regex = "1"
thiserror = "1"
```

- [ ] **Step 4: Create `crates/cli/Cargo.toml`**

```toml
[package]
name = "saiife"
description = "Guard and audit for AI coding agents."
edition.workspace = true
version.workspace = true
license.workspace = true
repository.workspace = true

[[bin]]
name = "saiife"
path = "src/main.rs"

[dependencies]
saiife-guard = { path = "../guard" }
clap = { version = "4", features = ["derive"] }
serde_json = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
```

- [ ] **Step 5: Rename the binary in code and tests**

```bash
sed -i 's/#\[command(name = "saiifeguard", version, about = "saiife command guard")\]/#[command(name = "saiife", version, about = "Guard and audit for AI coding agents")]/' crates/cli/src/main.rs
sed -i 's/"saiifeguard: {msg}"/"saiife: {msg}"/' crates/cli/src/main.rs
sed -i 's/cargo_bin("saiifeguard")/cargo_bin("saiife")/g' crates/cli/tests/cli.rs
sed -i 's/CARGO_BIN_EXE_saiifeguard/CARGO_BIN_EXE_saiife/g' crates/cli/tests/hook_exit.rs
grep -n 'saiifeguard' crates/cli/src/main.rs crates/cli/tests/*.rs
```

Expected: the only remaining matches are `use saiifeguard::…` lines (the lib name) and the doc comment at the top of `main.rs`. Change that doc comment's first line from `//! saiifeguard CLI.` to `//! saiife CLI.` and the three `saiifeguard test/explain/check` mentions in it to `saiife test/explain/check`.

- [ ] **Step 6: Create `.gitignore`**

```gitignore
/target
```

- [ ] **Step 7: Create `README.md`**

```markdown
# saiife

Guard and audit for AI coding agents (Claude Code, Codex, Gemini CLI) on your own machines.

Status: pre-release. Design: `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`.
```

- [ ] **Step 8: Update the spec's layout to match**

In `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` §4, replace the two lines

```
  guard/    engine, lexer, packs, payload parsing   (moved from saiifeguard)
```
and
```
packs/      *.toml rule packs (embedded in the binary at build time)
```
with

```
  guard/    engine, lexer, payload parsing, packs/*.toml (embedded at build time)
```

(The packs stay inside the guard crate so `include_str!` paths do not change.)

- [ ] **Step 9: Build, test, lint**

Run: `cargo test --quiet && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings`
Expected: all tests pass; fmt and clippy report nothing. If clippy reports warnings in moved code, fix exactly those warnings (no other changes) and commit them separately with message `style: clippy fixes after move`.

- [ ] **Step 10: Verify the binary**

Run: `cargo run -q -p saiife -- test "git reset --hard"; echo "exit=$?"`
Expected: stderr `saiife: BLOCKED by core.git: …`, then `exit=1`.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "refactor: workspace layout, rename binary to saiife"
```

---

### Task 3: Audit crate — record and masking

**Files:**
- Create: `crates/audit/Cargo.toml`, `crates/audit/src/lib.rs`, `crates/audit/src/mask.rs`, `crates/audit/src/record.rs`

**Interfaces:**
- Consumes: nothing from other crates.
- Produces:
  - `saiife_audit::mask::mask(input: &str) -> String`
  - `saiife_audit::record::{Record, NewRecord, DecisionKind, RECORD_VERSION, MAX_INPUT_CHARS}`
  - `Record::new(r: NewRecord<'_>, saiife_version: &str) -> Record`
  - `Record::at(r: NewRecord<'_>, saiife_version: &str, now: time::OffsetDateTime) -> Record`
  - `Record::month(&self) -> &str` (e.g. `"2026-10"`)
  - `Record::timestamp(&self) -> Option<time::OffsetDateTime>`
  - re-exports at crate root: `pub use record::{DecisionKind, NewRecord, Record};`

- [ ] **Step 1: Create `crates/audit/Cargo.toml`**

```toml
[package]
name = "saiife-audit"
description = "Audit log for saiife: one masked JSONL record per guard decision."
edition.workspace = true
version.workspace = true
license.workspace = true
repository.workspace = true

[lib]
name = "saiife_audit"
path = "src/lib.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
time = { version = "0.3", features = ["formatting", "parsing", "macros"] }
dirs = "5"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Create `crates/audit/src/lib.rs`**

```rust
//! saiife audit log: one masked JSONL record per guard decision.
//!
//! Records are written best-effort — the audit log is observability, never
//! enforcement, and a failed write must never change a guard verdict.

#![forbid(unsafe_code)]

pub mod mask;
pub mod record;

pub use record::{DecisionKind, NewRecord, Record};
```

- [ ] **Step 3: Write the failing masking tests — create `crates/audit/src/mask.rs`**

```rust
//! Secret masking applied to every record's `input` before it is written
//! (spec §6.3). Plaintext secrets never reach disk.

pub const MASK: &str = "[MASKED]";

/// Replace anything that looks like a secret with `[MASKED]`.
pub fn mask(input: &str) -> String {
    input.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_tokens() {
        let tok = format!("ghp_{}", "a".repeat(36));
        assert_eq!(mask(&format!("gh auth login --with-token {tok}")), "gh auth login --with-token [MASKED]");
        let pat = format!("github_pat_{}", "B".repeat(40));
        assert_eq!(mask(&format!("echo {pat}")), "echo [MASKED]");
        let gho = format!("gho_{}", "c".repeat(36));
        assert_eq!(mask(&gho), "[MASKED]");
    }

    #[test]
    fn aws_access_key_id_and_secret_assignment() {
        assert_eq!(mask("export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"), "export AWS_ACCESS_KEY_ID=[MASKED]");
        assert_eq!(mask("echo ASIAABCDEFGHIJKLMNOP"), "echo [MASKED]");
        assert_eq!(mask("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG"), "aws_secret_access_key=[MASKED]");
    }

    #[test]
    fn authorization_and_bearer() {
        assert_eq!(
            mask(r#"curl -H "Authorization: Bearer abc.def.ghi" https://x"#),
            r#"curl -H "Authorization: Bearer [MASKED]" https://x"#
        );
        assert_eq!(mask("curl -H 'authorization: token xyz123' u"), "curl -H 'authorization: token [MASKED]' u");
        assert_eq!(mask("bearer s3cr3t-value"), "bearer [MASKED]");
    }

    #[test]
    fn secret_flags_equals_and_space_forms() {
        assert_eq!(mask("mysql --password=hunter2 db"), "mysql --password=[MASKED] db");
        assert_eq!(mask("tool --token abc123 run"), "tool --token [MASKED] run");
        assert_eq!(mask("tool --api-key 'k e y' run"), "tool --api-key [MASKED] run");
        assert_eq!(mask(r#"tool --secret="x y""#), "tool --secret=[MASKED]");
    }

    #[test]
    fn secret_flag_lookalikes_are_not_masked() {
        assert_eq!(mask("tool --token-file ./path"), "tool --token-file ./path");
        assert_eq!(mask("git status"), "git status");
        assert_eq!(mask("rm -rf /"), "rm -rf /");
    }

    #[test]
    fn env_assignments_with_secret_names() {
        assert_eq!(mask("API_KEY=abc ./run"), "API_KEY=[MASKED] ./run");
        assert_eq!(mask("export DB_PASSWORD='p w'"), "export DB_PASSWORD=[MASKED]");
        assert_eq!(mask("MY_SECRET_TOKEN=x"), "MY_SECRET_TOKEN=[MASKED]");
        assert_eq!(mask("PATH=/usr/bin ls"), "PATH=/usr/bin ls");
    }

    #[test]
    fn url_credentials() {
        assert_eq!(
            mask("psql postgres://admin:pa55@db.local:5432/app"),
            "psql postgres://[MASKED]@db.local:5432/app"
        );
        assert_eq!(mask("git clone https://github.com/a/b"), "git clone https://github.com/a/b");
    }

    #[test]
    fn private_key_block() {
        let input = "echo '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----' > k";
        assert_eq!(mask(input), "echo '[MASKED]' > k");
        let unterminated = "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nAAAA";
        assert_eq!(mask(unterminated), "cat <<EOF\n[MASKED]");
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p saiife-audit mask`
Expected: FAIL — e.g. `github_tokens` asserts `left: "gh auth login --with-token ghp_aaaa…"`.

- [ ] **Step 5: Implement masking — replace the `mask` function in `crates/audit/src/mask.rs`** (keep `MASK` and the tests module)

```rust
use std::sync::LazyLock;

use regex::Regex;

/// `(pattern, replacement)`, applied in order. Order matters: whole private
/// key blocks first, then structured forms that keep a visible prefix
/// (URL scheme, header name, flag name, variable name), then bare tokens.
static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)", MASK),
        (r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", "${1}[MASKED]@"),
        (r#"(?i)(authorization:\s*(?:bearer\s+|basic\s+|token\s+)?)[^\s'"]+"#, "${1}[MASKED]"),
        (r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+", "${1}[MASKED]"),
        (r#"(?i)(--(?:password|passwd|token|secret|api-key|apikey)(?:=|\s+))(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY)[A-Z0-9_]*=)(?:'[^']*'|"[^"]*"|\S+)"#, "${1}[MASKED]"),
        (r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b", MASK),
        (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", MASK),
        (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", MASK),
    ]
    .into_iter()
    .map(|(p, r)| (Regex::new(p).expect("mask pattern compiles"), r))
    .collect()
});

/// Replace anything that looks like a secret with `[MASKED]`.
pub fn mask(input: &str) -> String {
    let mut out = input.to_string();
    for (re, replacement) in RULES.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *replacement).into_owned();
        }
    }
    out
}
```

Note on `AWS_ACCESS_KEY_ID=AKIA…`: the env-assignment rule matches `ACCESS_KEY` inside the variable name and masks the value, so the expected output is `export AWS_ACCESS_KEY_ID=[MASKED]`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p saiife-audit mask`
Expected: 8 passed.

- [ ] **Step 7: Write the failing record tests — create `crates/audit/src/record.rs`**

```rust
//! One audit record per guard decision (spec §6.2).

use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::mask::mask;

/// Schema version written into every record's `v` field.
pub const RECORD_VERSION: u32 = 1;

/// Longest `input` kept in a record, in characters. Longer inputs are cut on
/// a character boundary and marked, so one huge command cannot bloat the log.
pub const MAX_INPUT_CHARS: usize = 4096;

const TRUNCATED_MARK: &str = "…[truncated]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    /// The guard failed open (crash, unusable payload, budget exceeded): the
    /// action was allowed without being judged.
    ErrorAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub ts: String,
    pub agent: String,
    pub project: String,
    #[serde(default)]
    pub session: Option<String>,
    pub tool: String,
    /// The command (shell tools) or path (read tools), masked and truncated.
    pub input: String,
    pub decision: DecisionKind,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Version of the saiife binary that wrote the record.
    pub saiife: String,
}

/// The caller-supplied part of a record. `Record::new` adds the timestamp,
/// version, masking and truncation so no caller can forget them.
#[derive(Debug, Clone, Copy)]
pub struct NewRecord<'a> {
    pub agent: &'a str,
    pub project: &'a str,
    pub session: Option<&'a str>,
    pub tool: &'a str,
    pub input: &'a str,
    pub decision: DecisionKind,
    pub pack: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub reason: Option<&'a str>,
}

impl Record {
    pub fn new(r: NewRecord<'_>, saiife_version: &str) -> Self {
        Self::at(r, saiife_version, OffsetDateTime::now_utc())
    }

    pub fn at(r: NewRecord<'_>, saiife_version: &str, now: OffsetDateTime) -> Self {
        unimplemented!()
    }

    /// `YYYY-MM` of `ts`, used to pick the monthly file.
    pub fn month(&self) -> &str {
        unimplemented!()
    }

    /// `ts` parsed back to a UTC time; `None` if the record was hand-edited
    /// into something unparseable.
    pub fn timestamp(&self) -> Option<OffsetDateTime> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn base<'a>(input: &'a str) -> NewRecord<'a> {
        NewRecord {
            agent: "claude",
            project: "/home/u/app",
            session: Some("s1"),
            tool: "Bash",
            input,
            decision: DecisionKind::Deny,
            pack: Some("core.filesystem"),
            rule: Some("^rm"),
            reason: Some("deletes the filesystem root"),
        }
    }

    #[test]
    fn timestamp_format_and_month() {
        let r = Record::at(base("rm -rf /"), "0.1.0", datetime!(2026-10-13 08:14:02.381 UTC));
        assert_eq!(r.ts, "2026-10-13T08:14:02.381Z");
        assert_eq!(r.month(), "2026-10");
        assert_eq!(r.timestamp(), Some(datetime!(2026-10-13 08:14:02.381 UTC)));
        assert_eq!(r.v, RECORD_VERSION);
        assert_eq!(r.saiife, "0.1.0");
    }

    #[test]
    fn serializes_decision_snake_case() {
        let mut nr = base("x");
        nr.decision = DecisionKind::ErrorAllowed;
        let json = serde_json::to_string(&Record::new(nr, "0.1.0")).unwrap();
        assert!(json.contains(r#""decision":"error_allowed""#), "{json}");
    }

    #[test]
    fn input_is_masked() {
        let tok = format!("ghp_{}", "a".repeat(36));
        let r = Record::new(base(&format!("echo {tok}")), "0.1.0");
        assert_eq!(r.input, "echo [MASKED]");
    }

    #[test]
    fn long_input_is_truncated_on_char_boundary() {
        let input = "a".repeat(MAX_INPUT_CHARS + 10);
        let r = Record::new(base(&input), "0.1.0");
        assert_eq!(r.input.chars().count(), MAX_INPUT_CHARS + TRUNCATED_MARK.chars().count());
        assert!(r.input.ends_with(TRUNCATED_MARK));
    }

    #[test]
    fn multibyte_input_truncates_without_panic() {
        let input = "é".repeat(MAX_INPUT_CHARS * 2);
        let r = Record::new(base(&input), "0.1.0");
        assert!(r.input.starts_with("éé"));
        assert!(r.input.ends_with(TRUNCATED_MARK));
    }

    #[test]
    fn deserializes_record_without_optional_fields() {
        let line = r#"{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        assert_eq!(r.decision, DecisionKind::Allow);
        assert_eq!(r.session, None);
        assert_eq!(r.pack, None);
    }

    #[test]
    fn unparseable_ts_gives_none() {
        let mut r = Record::new(base("x"), "0.1.0");
        r.ts = "yesterday".into();
        assert_eq!(r.timestamp(), None);
    }
}
```

- [ ] **Step 8: Run tests to verify they fail**

Run: `cargo test -p saiife-audit record`
Expected: FAIL — tests panic with `not implemented`.

- [ ] **Step 9: Implement — replace the three `unimplemented!()` bodies and add helpers in `crates/audit/src/record.rs`**

```rust
const TS_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

impl Record {
    pub fn new(r: NewRecord<'_>, saiife_version: &str) -> Self {
        Self::at(r, saiife_version, OffsetDateTime::now_utc())
    }

    pub fn at(r: NewRecord<'_>, saiife_version: &str, now: OffsetDateTime) -> Self {
        let utc = now.to_offset(time::UtcOffset::UTC);
        Self {
            v: RECORD_VERSION,
            ts: utc.format(TS_FORMAT).expect("UTC timestamp formats"),
            agent: r.agent.to_string(),
            project: r.project.to_string(),
            session: r.session.map(str::to_string),
            tool: r.tool.to_string(),
            input: truncate(&mask(r.input)),
            decision: r.decision,
            pack: r.pack.map(str::to_string),
            rule: r.rule.map(str::to_string),
            reason: r.reason.map(str::to_string),
            saiife: saiife_version.to_string(),
        }
    }

    pub fn month(&self) -> &str {
        self.ts.get(..7).unwrap_or("unknown")
    }

    pub fn timestamp(&self) -> Option<OffsetDateTime> {
        PrimitiveDateTime::parse(&self.ts, TS_FORMAT)
            .ok()
            .map(PrimitiveDateTime::assume_utc)
    }
}

fn truncate(s: &str) -> String {
    match s.char_indices().nth(MAX_INPUT_CHARS) {
        None => s.to_string(),
        Some((cut, _)) => format!("{}{TRUNCATED_MARK}", &s[..cut]),
    }
}
```

(Delete the earlier stub `impl Record` block so only this one remains.)

- [ ] **Step 10: Run all audit tests**

Run: `cargo test -p saiife-audit`
Expected: 15 passed (8 mask + 7 record).

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt --all && cargo clippy -p saiife-audit --all-targets -- -D warnings
git add crates/audit Cargo.lock
git commit -m "feat(audit): masked, versioned audit record"
```

---

### Task 4: Audit crate — storage, reading and filtering

**Files:**
- Create: `crates/audit/src/store.rs`
- Modify: `crates/audit/src/lib.rs`

**Interfaces:**
- Consumes: `Record`, `Record::month`, `Record::timestamp`, `DecisionKind` (Task 3).
- Produces:
  - `saiife_audit::store::default_dir() -> Option<std::path::PathBuf>` — `$SAIIFE_AUDIT_DIR` if set and non-empty, else `dirs::data_dir()/saiife/audit`.
  - `saiife_audit::store::append(dir: &Path, rec: &Record) -> std::io::Result<()>`
  - `saiife_audit::store::read_all(dir: &Path) -> Vec<Record>`
  - `saiife_audit::store::Filter { since: Option<OffsetDateTime>, project: Option<String>, agent: Option<String>, blocked_only: bool }` with `Default` and `fn matches(&self, r: &Record) -> bool`

- [ ] **Step 1: Write the failing tests — create `crates/audit/src/store.rs`**

```rust
//! Monthly JSONL files under the user's data dir (spec §6.1).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::record::{DecisionKind, Record};

/// Environment variable that overrides the audit directory (tests, admins).
pub const DIR_ENV: &str = "SAIIFE_AUDIT_DIR";

pub fn default_dir() -> Option<PathBuf> {
    unimplemented!()
}

pub fn append(dir: &Path, rec: &Record) -> io::Result<()> {
    unimplemented!()
}

pub fn read_all(dir: &Path) -> Vec<Record> {
    unimplemented!()
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub since: Option<OffsetDateTime>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub blocked_only: bool,
}

impl Filter {
    pub fn matches(&self, r: &Record) -> bool {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::NewRecord;
    use time::macros::datetime;

    fn rec(project: &str, agent: &str, decision: DecisionKind, at: OffsetDateTime) -> Record {
        Record::at(
            NewRecord {
                agent,
                project,
                session: None,
                tool: "Bash",
                input: "ls",
                decision,
                pack: None,
                rule: None,
                reason: None,
            },
            "0.1.0",
            at,
        )
    }

    #[test]
    fn append_then_read_roundtrip_across_months() {
        let dir = tempfile::tempdir().unwrap();
        let a = rec("/p", "claude", DecisionKind::Allow, datetime!(2026-09-30 23:59:59 UTC));
        let b = rec("/p", "claude", DecisionKind::Deny, datetime!(2026-10-01 00:00:01 UTC));
        append(dir.path(), &a).unwrap();
        append(dir.path(), &b).unwrap();
        assert!(dir.path().join("2026-09.jsonl").exists());
        assert!(dir.path().join("2026-10.jsonl").exists());
        assert_eq!(read_all(dir.path()), vec![a, b]);
    }

    #[test]
    fn append_creates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        append(&nested, &rec("/p", "claude", DecisionKind::Allow, OffsetDateTime::now_utc())).unwrap();
        assert_eq!(read_all(&nested).len(), 1);
    }

    #[test]
    fn append_to_a_file_path_errors_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        fs::write(&file, "x").unwrap();
        assert!(append(&file, &rec("/p", "claude", DecisionKind::Allow, OffsetDateTime::now_utc())).is_err());
    }

    #[test]
    fn read_all_skips_garbage_lines_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let good = rec("/p", "claude", DecisionKind::Allow, datetime!(2026-10-13 08:00:00 UTC));
        append(dir.path(), &good).unwrap();
        let mut f = OpenOptions::new().append(true).open(dir.path().join("2026-10.jsonl")).unwrap();
        writeln!(f, "{{\"v\":1,\"ts\":\"2026-10-13T08:").unwrap(); // half-written line
        writeln!(f, "not json").unwrap();
        writeln!(f).unwrap();
        fs::write(dir.path().join("notes.txt"), "{\"v\":1}").unwrap();
        fs::write(dir.path().join("backup.jsonl"), "{}").unwrap();
        assert_eq!(read_all(dir.path()), vec![good]);
    }

    #[test]
    fn read_all_of_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_all(&dir.path().join("nope")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let r = rec("/p", "claude", DecisionKind::Allow, datetime!(2026-10-13 08:00:00 UTC));
        append(dir.path(), &r).unwrap();
        let mode = fs::metadata(dir.path().join("2026-10.jsonl")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn default_dir_honors_env_override() {
        // Only this test touches DIR_ENV in this test binary.
        std::env::set_var(DIR_ENV, "/tmp/saiife-audit-override");
        assert_eq!(default_dir(), Some(PathBuf::from("/tmp/saiife-audit-override")));
        std::env::set_var(DIR_ENV, "");
        assert!(default_dir().unwrap().ends_with("saiife/audit"));
        std::env::remove_var(DIR_ENV);
    }

    #[test]
    fn filter_since_project_agent_blocked() {
        let now = datetime!(2026-10-13 12:00:00 UTC);
        let old = rec("/p", "claude", DecisionKind::Deny, datetime!(2026-09-01 00:00:00 UTC));
        let deny = rec("/p/sub", "codex", DecisionKind::Deny, now);
        let allow = rec("/other", "claude", DecisionKind::Allow, now);

        let f = Filter { since: Some(datetime!(2026-10-01 00:00:00 UTC)), ..Default::default() };
        assert!(!f.matches(&old) && f.matches(&deny) && f.matches(&allow));

        let f = Filter { project: Some("/p".into()), ..Default::default() };
        assert!(f.matches(&old) && f.matches(&deny) && !f.matches(&allow));
        let f = Filter { project: Some("/p/".into()), ..Default::default() };
        assert!(f.matches(&deny), "trailing slash is ignored");
        let f = Filter { project: Some("/p/su".into()), ..Default::default() };
        assert!(!f.matches(&deny), "prefix must end on a path boundary");

        let f = Filter { agent: Some("codex".into()), ..Default::default() };
        assert!(!f.matches(&old) && f.matches(&deny));

        let f = Filter { blocked_only: true, ..Default::default() };
        assert!(f.matches(&deny) && !f.matches(&allow));

        let mut broken = deny.clone();
        broken.ts = "garbage".into();
        let f = Filter { since: Some(datetime!(2026-10-01 00:00:00 UTC)), ..Default::default() };
        assert!(!f.matches(&broken), "unparseable ts is excluded when --since is set");
    }
}
```

Also add to `crates/audit/src/lib.rs`, after `pub mod record;`:

```rust
pub mod store;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p saiife-audit store`
Expected: FAIL — tests panic with `not implemented`.

- [ ] **Step 3: Implement — replace the four `unimplemented!()` bodies in `crates/audit/src/store.rs`**

```rust
pub fn default_dir() -> Option<PathBuf> {
    match std::env::var_os(DIR_ENV) {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("saiife").join("audit")),
    }
}

/// Append one record as a single line to `<dir>/<YYYY-MM>.jsonl`, creating the
/// dir and file as needed. New files are owner-only (0600) on unix: commands
/// can reveal what people work on. The whole line goes out in one
/// `write_all` on an `O_APPEND` handle so parallel hooks do not interleave.
pub fn append(dir: &Path, rec: &Record) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(dir.join(format!("{}.jsonl", rec.month())))?;
    let mut line = serde_json::to_string(rec).map_err(io::Error::other)?;
    line.push('\n');
    file.write_all(line.as_bytes())
}

/// Every parseable record from every `YYYY-MM.jsonl` in `dir`, oldest file
/// first. Unparseable lines and other files are skipped silently.
pub fn read_all(dir: &Path) -> Vec<Record> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(is_month_file))
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .flat_map(|body| {
            body.lines()
                .filter_map(|l| serde_json::from_str::<Record>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `YYYY-MM.jsonl`
fn is_month_file(name: &str) -> bool {
    let b = name.as_bytes();
    name.len() == 13
        && name.ends_with(".jsonl")
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
}

impl Filter {
    pub fn matches(&self, r: &Record) -> bool {
        if let Some(since) = self.since {
            match r.timestamp() {
                Some(t) if t >= since => {}
                _ => return false,
            }
        }
        if let Some(p) = &self.project {
            let p = p.trim_end_matches('/');
            let under = r.project == p
                || r.project.strip_prefix(p).is_some_and(|rest| rest.starts_with('/'));
            if !under {
                return false;
            }
        }
        if let Some(a) = &self.agent {
            if &r.agent != a {
                return false;
            }
        }
        !(self.blocked_only && r.decision != DecisionKind::Deny)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p saiife-audit`
Expected: 23 passed.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy -p saiife-audit --all-targets -- -D warnings
git add crates/audit Cargo.lock
git commit -m "feat(audit): monthly owner-only storage, tolerant reader, filters"
```

---

### Task 5: `saiife check` audits every decision

**Files:**
- Modify: `crates/guard/src/payload.rs` (add `HookContext`, `context_from_hook_json`)
- Create: `crates/cli/src/check.rs`
- Modify: `crates/cli/src/main.rs`, `crates/cli/Cargo.toml`
- Modify: `crates/cli/tests/hook_exit.rs`, `crates/cli/tests/cli.rs`
- Create: `crates/cli/tests/check_audit.rs`

**Interfaces:**
- Consumes: `saiife_audit::{Record, NewRecord, DecisionKind}`, `saiife_audit::store::{default_dir, append, read_all, DIR_ENV}`; guard `Engine::evaluate(&str) -> Decision`, `command_from_hook_json`.
- Produces:
  - `saiifeguard::payload::HookContext { tool: Option<String>, session: Option<String>, cwd: Option<String> }` and `context_from_hook_json(input: &str) -> HookContext`
  - CLI: `saiife check [--hook-exit] [--agent <name>]` (default agent `unknown`). Flags `--audit-log`, `--audit-tag`, `--seen-dir` are **removed**; the audit log replaces the seen-marker (plan 2's `status` reads the last record per project).
  - `crates/cli/src/check.rs`: `pub fn run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode`

- [ ] **Step 1: Write the failing payload-context tests** — append inside `mod tests` in `crates/guard/src/payload.rs`

```rust
    #[test]
    fn context_reads_claude_fields() {
        let json = r#"{"session_id":"abc","cwd":"/home/u/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let ctx = context_from_hook_json(json);
        assert_eq!(ctx.tool.as_deref(), Some("Bash"));
        assert_eq!(ctx.session.as_deref(), Some("abc"));
        assert_eq!(ctx.cwd.as_deref(), Some("/home/u/app"));
    }

    #[test]
    fn context_reads_camel_case_and_tolerates_garbage() {
        let ctx = context_from_hook_json(r#"{"toolName":"shell","sessionId":"x"}"#);
        assert_eq!(ctx.tool.as_deref(), Some("shell"));
        assert_eq!(ctx.session.as_deref(), Some("x"));
        assert_eq!(context_from_hook_json("{not json"), HookContext::default());
        let huge = "a".repeat(MAX_PAYLOAD_BYTES + 1);
        assert_eq!(context_from_hook_json(&huge), HookContext::default());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p saiife-guard payload::tests::context`
Expected: compile error `cannot find function context_from_hook_json`.

- [ ] **Step 3: Implement** — add to `crates/guard/src/payload.rs`, directly after `command_from_hook_json`

```rust
/// Metadata about a hook call, for the audit log. Best-effort: any field the
/// payload does not carry (or an unparseable payload) is `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HookContext {
    pub tool: Option<String>,
    pub session: Option<String>,
    pub cwd: Option<String>,
}

pub fn context_from_hook_json(input: &str) -> HookContext {
    if input.len() > MAX_PAYLOAD_BYTES {
        return HookContext::default();
    }
    let Ok(v) = serde_json::from_str::<Value>(input) else {
        return HookContext::default();
    };
    let field = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| v.get(*n).and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    HookContext {
        tool: field(&["tool_name", "toolName"]),
        session: field(&["session_id", "sessionId"]),
        cwd: field(&["cwd"]),
    }
}
```

Run: `cargo test -p saiife-guard payload`
Expected: all payload tests pass.

- [ ] **Step 4: Add dependencies** — in `crates/cli/Cargo.toml`, `[dependencies]` gains:

```toml
saiife-audit = { path = "../audit" }
```

and `[dev-dependencies]` gains:

```toml
tempfile = "3"
```

- [ ] **Step 5: Write the failing integration tests — create `crates/cli/tests/check_audit.rs`**

```rust
//! `saiife check` writes one masked audit record per decision and never lets
//! the audit log change a verdict.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::{read_all, DIR_ENV};
use saiife_audit::DecisionKind;

fn check(audit_dir: &Path, args: &[&str], stdin: &str) -> i32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("check")
        .args(args)
        .env(DIR_ENV, audit_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait().unwrap().code().unwrap_or(-1)
}

fn payload(cmd: &str) -> String {
    serde_json::json!({
        "session_id": "sess-1",
        "cwd": "/home/u/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string()
}

#[test]
fn allow_is_audited_with_context() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(check(dir.path(), &["--hook-exit", "--agent", "claude"], &payload("ls -la")), 0);
    let recs = read_all(dir.path());
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.decision, DecisionKind::Allow);
    assert_eq!(r.agent, "claude");
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.session.as_deref(), Some("sess-1"));
    assert_eq!(r.project, "/home/u/app");
    assert_eq!(r.input, "ls -la");
    assert_eq!(r.saiife, env!("CARGO_PKG_VERSION"));
}

#[test]
fn deny_is_audited_with_pack_rule_reason() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(check(dir.path(), &["--hook-exit", "--agent", "codex"], &payload("rm -rf /")), 2);
    let r = &read_all(dir.path())[0];
    assert_eq!(r.decision, DecisionKind::Deny);
    assert_eq!(r.pack.as_deref(), Some("core.filesystem"));
    assert!(r.rule.is_some());
    assert!(r.reason.is_some());
}

#[test]
fn garbage_payload_is_audited_as_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(check(dir.path(), &["--hook-exit"], "{not json"), 0);
    let r = &read_all(dir.path())[0];
    assert_eq!(r.decision, DecisionKind::ErrorAllowed);
    assert_eq!(r.agent, "unknown");
    assert!(r.reason.as_deref().unwrap().contains("payload"));
}

#[test]
fn oversize_payload_is_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let big = payload(&format!("echo {}", "a".repeat(300 * 1024)));
    assert_eq!(check(dir.path(), &["--hook-exit"], &big), 0);
    assert_eq!(read_all(dir.path())[0].decision, DecisionKind::ErrorAllowed);
}

#[test]
fn secrets_never_reach_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let tok = format!("ghp_{}", "z".repeat(36));
    check(dir.path(), &["--hook-exit"], &payload(&format!("GH_TOKEN={tok} gh pr list")));
    let raw: String = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!raw.contains(&tok), "token leaked: {raw}");
    assert!(raw.contains("[MASKED]"));
}

#[test]
fn unwritable_audit_dir_keeps_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, "x").unwrap();
    assert_eq!(check(&file, &["--hook-exit"], &payload("rm -rf /")), 2);
    assert_eq!(check(&file, &["--hook-exit"], &payload("ls")), 0);
}

#[test]
fn concurrent_checks_write_whole_lines() {
    let dir = tempfile::tempdir().unwrap();
    let children: Vec<_> = (0..20)
        .map(|i| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"))
                .args(["check", "--hook-exit", "--agent", "claude"])
                .env(DIR_ENV, dir.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            c.stdin
                .take()
                .unwrap()
                .write_all(payload(&format!("echo {i} {}", "x".repeat(3000))).as_bytes())
                .unwrap();
            c
        })
        .collect();
    for mut c in children {
        c.wait().unwrap();
    }
    let lines: usize = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap().lines().count())
        .sum();
    assert_eq!(lines, 20);
    assert_eq!(read_all(dir.path()).len(), 20, "every line parses");
}
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p saiife --test check_audit`
Expected: FAIL — `unexpected argument '--agent'` makes every exit code 2 and no records exist.

- [ ] **Step 7: Create `crates/cli/src/check.rs`**

```rust
//! `saiife check`: hook mode. Read the agent's pre-tool JSON on stdin, decide,
//! audit, and answer in the agent's contract. FAIL OPEN on every error.

use std::io::Read;
use std::process::ExitCode;

use saiife_audit::{store, DecisionKind, NewRecord, Record};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{
    command_from_hook_json, context_from_hook_json, HookContext, MAX_PAYLOAD_BYTES,
};

use crate::warn;

pub fn run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        let audit = Audit::new(agent, HookContext::default());
        warn("could not read hook payload; failing open (allow)");
        audit.write("", DecisionKind::ErrorAllowed, None, Some("could not read hook payload"));
        return allow(hook_exit);
    }
    let audit = Audit::new(agent, context_from_hook_json(&buf));
    let command = match command_from_hook_json(&buf, MAX_PAYLOAD_BYTES) {
        Ok(c) => c,
        Err(e) => {
            warn(&format!("hook payload not usable ({e}); failing open (allow)"));
            audit.write(
                "",
                DecisionKind::ErrorAllowed,
                None,
                Some(&format!("hook payload not usable: {e}")),
            );
            return allow(hook_exit);
        }
    };

    let decision = engine.evaluate(&command);
    match &decision {
        Decision::Deny { pack, pattern, reason, .. } => {
            audit.write(&command, DecisionKind::Deny, Some((pack, pattern)), Some(reason))
        }
        Decision::Allow { trace: AllowTrace::AllowRule { pack, pattern, reason } } => {
            audit.write(&command, DecisionKind::Allow, Some((pack, pattern)), Some(reason))
        }
        Decision::Allow { trace: AllowTrace::NoMatch } => {
            audit.write(&command, DecisionKind::Allow, None, None)
        }
        Decision::Allow { trace: AllowTrace::FailedOpenTimeout } => audit.write(
            &command,
            DecisionKind::ErrorAllowed,
            None,
            Some("guard exceeded its latency budget"),
        ),
    }

    match decision {
        Decision::Deny { pack, reason, via_inline, .. } => {
            // Same "BLOCKED by <pack>: <reason> (inline: ...)" shape as
            // `test`/`explain`: the hook path is what a real user hits.
            let where_ = via_inline
                .as_deref()
                .map(|i| format!(" (inline: {i})"))
                .unwrap_or_default();
            let msg = format!("BLOCKED by {pack}: {reason}{where_}");
            if hook_exit {
                warn(&msg);
                ExitCode::from(2)
            } else {
                emit_deny(&msg)
            }
        }
        Decision::Allow { .. } => allow(hook_exit),
    }
}

/// Everything about this hook call except the decision, so each exit path
/// writes a complete record with one call.
struct Audit {
    agent: String,
    ctx: HookContext,
    project: String,
}

impl Audit {
    fn new(agent: &str, ctx: HookContext) -> Self {
        let project = ctx.cwd.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        });
        Self { agent: agent.to_string(), ctx, project }
    }

    /// Best-effort: a failed write is reported on stderr and otherwise ignored.
    fn write(
        &self,
        input: &str,
        decision: DecisionKind,
        rule: Option<(&String, &String)>,
        reason: Option<&str>,
    ) {
        let Some(dir) = store::default_dir() else { return };
        let rec = Record::new(
            NewRecord {
                agent: &self.agent,
                project: &self.project,
                session: self.ctx.session.as_deref(),
                tool: self.ctx.tool.as_deref().unwrap_or("unknown"),
                input,
                decision,
                pack: rule.map(|(p, _)| p.as_str()),
                rule: rule.map(|(_, r)| r.as_str()),
                reason,
            },
            env!("CARGO_PKG_VERSION"),
        );
        if let Err(e) = store::append(&dir, &rec) {
            warn(&format!("audit write failed ({e}); decision unaffected"));
        }
    }
}

fn allow(hook_exit: bool) -> ExitCode {
    if hook_exit {
        ExitCode::SUCCESS
    } else {
        emit_allow()
    }
}

/// Emit a PreToolUse "allow" response and exit 0.
fn emit_allow() -> ExitCode {
    println!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
    );
    ExitCode::SUCCESS
}

/// Emit a PreToolUse "deny" response with a reason and exit 0 (the JSON
/// carries the block decision).
fn emit_deny(reason: &str) -> ExitCode {
    let payload = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    println!("{payload}");
    ExitCode::SUCCESS
}
```

- [ ] **Step 8: Rewire `crates/cli/src/main.rs`**

1. Add `mod check;` below the `use` lines.
2. Replace the whole `Check { … }` variant in `enum Cmd` with:

```rust
    /// Hook mode: read a pre-tool JSON payload on stdin, decide, audit, respond.
    Check {
        /// Deny via exit code 2 + stderr reason (universal agent contract)
        /// instead of the JSON permissionDecision payload.
        #[arg(long = "hook-exit")]
        hook_exit: bool,
        /// Which agent is calling (claude, codex, gemini); recorded in the audit log.
        #[arg(long = "agent", default_value = "unknown")]
        agent: String,
    },
```

3. Replace the `Cmd::Check { … } => cmd_check(…)` match arm with:

```rust
        Cmd::Check { hook_exit, agent } => check::run(&engine, hook_exit, &agent),
```

4. Delete the functions `cmd_check`, `append_audit`, `write_seen_marker`, `emit_allow`, `emit_deny` from `main.rs`, and the now-unused imports `std::io::Read` and `saiifeguard::payload::{command_from_hook_json, MAX_PAYLOAD_BYTES}`.
5. Make `warn` visible to the module: change `fn warn(` to `pub(crate) fn warn(`.
6. In the doc comment at the top, replace the `check` line with: `//! - \`saiife check\` -> read agent pre-tool JSON on stdin, audit, emit the hook allow/block response; FAIL OPEN on error.`

- [ ] **Step 9: Point the old CLI tests at a throwaway audit dir and drop obsolete tests**

In `crates/cli/tests/hook_exit.rs`:
1. In `run_check`, after `.args(args)` add `.env("SAIIFE_AUDIT_DIR", std::env::temp_dir().join(format!("saiife-test-audit-{}", std::process::id())))`.
2. Delete the test `audit_log_records_deny_only` (replaced by `check_audit.rs`).
3. Delete everything from the line `/// A unique scratch dir for one test, cleaned up by the caller.` to the end of the file (the `scratch` helper and the seven `seen_dir_*` tests; the flag no longer exists).

In `crates/cli/tests/cli.rs`, in `check_denies_via_hook_json` and `check_fails_open_on_garbage`, add after `.arg("check")`:

```rust
        .env("SAIIFE_AUDIT_DIR", std::env::temp_dir().join("saiife-test-audit-cli"))
```

- [ ] **Step 10: Run all tests**

Run: `cargo test --quiet`
Expected: everything passes, including the 7 tests in `check_audit`.

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cli): audit every check decision; add --agent; drop seen-dir and audit-log flags"
```

---

### Task 6: `saiife audit` terminal view

**Files:**
- Create: `crates/cli/src/audit_cmd.rs`
- Modify: `crates/cli/src/main.rs`, `crates/cli/Cargo.toml`
- Create: `crates/cli/tests/audit_cmd.rs`

**Interfaces:**
- Consumes: `saiife_audit::store::{default_dir, read_all, Filter}`, `Record`, `DecisionKind`.
- Produces:
  - `audit_cmd::parse_since(s: &str) -> Result<time::Duration, String>` (`30m`, `24h`, `7d`)
  - `audit_cmd::render_table(records: &[&Record]) -> String`
  - `audit_cmd::run(since: Option<&str>, project: Option<&str>, agent: Option<&str>, blocked: bool) -> ExitCode`
  - CLI: `saiife audit [--since <30m|24h|7d>] [--project <path>] [--agent <name>] [--blocked]`. (`--report` comes in plan 4.)

- [ ] **Step 1: Add dependency** — `crates/cli/Cargo.toml` `[dependencies]` gains:

```toml
time = "0.3"
```

- [ ] **Step 2: Write the failing unit tests — create `crates/cli/src/audit_cmd.rs`**

```rust
//! `saiife audit`: the audit log as a terminal table.

use std::process::ExitCode;

use saiife_audit::store::{self, Filter};
use saiife_audit::{DecisionKind, Record};
use time::{Duration, OffsetDateTime};

const INPUT_WIDTH: usize = 60;

pub fn parse_since(s: &str) -> Result<Duration, String> {
    unimplemented!()
}

pub fn render_table(records: &[&Record]) -> String {
    unimplemented!()
}

pub fn run(since: Option<&str>, project: Option<&str>, agent: Option<&str>, blocked: bool) -> ExitCode {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_audit::NewRecord;
    use time::macros::datetime;

    fn rec(input: &str, decision: DecisionKind, pack: Option<&str>) -> Record {
        Record::at(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool: "Bash",
                input,
                decision,
                pack,
                rule: None,
                reason: Some("why"),
            },
            "0.1.0",
            datetime!(2026-10-13 08:14:02.381 UTC),
        )
    }

    #[test]
    fn parse_since_units() {
        assert_eq!(parse_since("30m"), Ok(Duration::minutes(30)));
        assert_eq!(parse_since("24h"), Ok(Duration::hours(24)));
        assert_eq!(parse_since("7d"), Ok(Duration::days(7)));
    }

    #[test]
    fn parse_since_rejects_bad_input() {
        for bad in ["", "7", "d", "7w", "-1d", "0d", "7дн", "1.5h"] {
            assert!(parse_since(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn table_rows_labels_and_summary() {
        let a = rec("ls", DecisionKind::Allow, None);
        let d = rec("rm -rf /", DecisionKind::Deny, Some("core.filesystem"));
        let e = rec("", DecisionKind::ErrorAllowed, None);
        let out = render_table(&[&a, &d, &e]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("TIME"));
        assert!(lines[1].starts_with("2026-10-13 08:14:02  claude   allowed"));
        assert!(lines[2].contains("BLOCKED") && lines[2].contains("core.filesystem") && lines[2].ends_with("rm -rf /"));
        assert!(lines[3].contains("FAIL-OPEN") && lines[3].ends_with("(why)"));
        assert_eq!(lines[4], "3 decisions · 1 blocked · 1 fail-open");
    }

    #[test]
    fn long_and_multiline_input_is_flattened_and_cut() {
        let long = format!("echo 'a\nb' {}", "x".repeat(200));
        let r = rec(&long, DecisionKind::Allow, None);
        let out = render_table(&[&r]);
        let row = out.lines().nth(1).unwrap();
        assert!(row.contains("echo 'a⏎b'"));
        assert!(row.ends_with('…'));
        let input_part = row.rsplit("  ").next().unwrap();
        assert_eq!(input_part.chars().count(), INPUT_WIDTH);
    }
}
```

Add `mod audit_cmd;` to `crates/cli/src/main.rs` next to `mod check;`.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p saiife audit_cmd`
Expected: FAIL — `not implemented`.

- [ ] **Step 4: Implement — replace the three `unimplemented!()` bodies in `crates/cli/src/audit_cmd.rs`**

```rust
pub fn parse_since(s: &str) -> Result<Duration, String> {
    let err = || format!("invalid --since {s:?}: use a whole number with m, h or d, e.g. 30m, 24h, 7d");
    if !s.is_ascii() || s.len() < 2 {
        return Err(err());
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.parse().map_err(|_| err())?;
    if n <= 0 {
        return Err(err());
    }
    match unit {
        "m" => Ok(Duration::minutes(n)),
        "h" => Ok(Duration::hours(n)),
        "d" => Ok(Duration::days(n)),
        _ => Err(err()),
    }
}

pub fn render_table(records: &[&Record]) -> String {
    let row = |time: &str, agent: &str, decision: &str, pack: &str, input: &str| {
        format!("{time:<19}  {agent:<7}  {decision:<9}  {pack:<16}  {input}\n")
    };
    let mut out = row("TIME", "AGENT", "DECISION", "PACK", "INPUT");
    let (mut blocked, mut fail_open) = (0, 0);
    for r in records {
        let label = match r.decision {
            DecisionKind::Allow => "allowed",
            DecisionKind::Deny => {
                blocked += 1;
                "BLOCKED"
            }
            DecisionKind::ErrorAllowed => {
                fail_open += 1;
                "FAIL-OPEN"
            }
        };
        let time = r.ts.get(..19).unwrap_or(&r.ts).replace('T', " ");
        let input = if r.input.is_empty() {
            format!("({})", r.reason.as_deref().unwrap_or("no input"))
        } else {
            one_line(&r.input)
        };
        out.push_str(&row(&time, &r.agent, label, r.pack.as_deref().unwrap_or("-"), &input));
    }
    out.push_str(&format!(
        "{} decisions · {blocked} blocked · {fail_open} fail-open\n",
        records.len()
    ));
    out
}

/// Newlines become `⏎`; anything longer than `INPUT_WIDTH` is cut with `…`.
fn one_line(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c == '\n' { '⏎' } else { c }).collect();
    if flat.chars().count() <= INPUT_WIDTH {
        flat
    } else {
        let mut cut: String = flat.chars().take(INPUT_WIDTH - 1).collect();
        cut.push('…');
        cut
    }
}

pub fn run(since: Option<&str>, project: Option<&str>, agent: Option<&str>, blocked: bool) -> ExitCode {
    let since = match since.map(parse_since).transpose() {
        Ok(d) => d.map(|d| OffsetDateTime::now_utc() - d),
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(dir) = store::default_dir() else {
        eprintln!("saiife: could not determine the audit directory");
        return ExitCode::from(2);
    };
    let filter = Filter {
        since,
        project: project.map(str::to_string),
        agent: agent.map(str::to_string),
        blocked_only: blocked,
    };
    let all = store::read_all(&dir);
    let shown: Vec<&Record> = all.iter().filter(|r| filter.matches(r)).collect();
    if shown.is_empty() {
        println!("No audit records found in {}.", dir.display());
    } else {
        print!("{}", render_table(&shown));
    }
    ExitCode::SUCCESS
}
```

- [ ] **Step 5: Wire the subcommand in `crates/cli/src/main.rs`**

Add to `enum Cmd`:

```rust
    /// Show the audit log: every allowed, blocked and fail-open decision.
    Audit {
        /// Only records newer than this, e.g. 30m, 24h, 7d.
        #[arg(long)]
        since: Option<String>,
        /// Only records from this project directory (or below it).
        #[arg(long)]
        project: Option<String>,
        /// Only records from this agent (claude, codex, gemini).
        #[arg(long)]
        agent: Option<String>,
        /// Only blocked actions.
        #[arg(long)]
        blocked: bool,
    },
```

Add the match arm:

```rust
        Cmd::Audit { since, project, agent, blocked } => {
            audit_cmd::run(since.as_deref(), project.as_deref(), agent.as_deref(), blocked)
        }
```

`main` builds the engine before the match; `audit` does not need it, which is fine (building it costs well under the latency budget).

- [ ] **Step 6: Write the integration test — create `crates/cli/tests/audit_cmd.rs`**

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use saiife_audit::store::{append, DIR_ENV};
use saiife_audit::{DecisionKind, NewRecord, Record};
use time::{Duration, OffsetDateTime};

fn seed(dir: &std::path::Path) {
    let now = OffsetDateTime::now_utc();
    let mk = |input: &str, decision, pack, at| {
        Record::at(
            NewRecord {
                agent: "claude",
                project: "/home/u/app",
                session: None,
                tool: "Bash",
                input,
                decision,
                pack,
                rule: None,
                reason: Some("r"),
            },
            "0.1.0",
            at,
        )
    };
    append(dir, &mk("ls", DecisionKind::Allow, None, now)).unwrap();
    append(dir, &mk("rm -rf /", DecisionKind::Deny, Some("core.filesystem"), now)).unwrap();
    append(dir, &mk("git status", DecisionKind::Allow, None, now - Duration::days(40))).unwrap();
    // A crashed half-line must not hide the rest.
    std::fs::write(dir.join("1999-01.jsonl"), "{\"v\":1,\"ts\":").unwrap();
}

#[test]
fn shows_all_records_and_summary() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("BLOCKED"))
        .stdout(predicate::str::contains("3 decisions · 1 blocked · 0 fail-open"));
}

#[test]
fn filters_blocked_and_since() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--blocked"])
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("1 decisions · 1 blocked"));
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--since", "7d"])
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("2 decisions"))
        .stdout(predicate::str::contains("git status").not());
}

#[test]
fn empty_log_says_so() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No audit records found"));
}

#[test]
fn bad_since_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--since", "7w"])
        .env(DIR_ENV, dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid --since"));
}
```

- [ ] **Step 7: Run all tests**

Run: `cargo test --quiet`
Expected: everything passes, including 4 unit tests in `audit_cmd` and 4 in `tests/audit_cmd.rs`.

- [ ] **Step 8: Try it by hand**

```bash
export SAIIFE_AUDIT_DIR=$(mktemp -d)
echo '{"tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"rm -rf /"}}' | cargo run -q -p saiife -- check --hook-exit --agent claude
cargo run -q -p saiife -- audit
unset SAIIFE_AUDIT_DIR
```

Expected: the first command prints `saiife: BLOCKED by core.filesystem: …`; the table shows one `BLOCKED` row and `1 decisions · 1 blocked · 0 fail-open`.

- [ ] **Step 9: Lint and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cli): saiife audit terminal view with since/project/agent/blocked filters"
```

---

### Task 7: CI — lint, test on Linux and macOS, and prove offline

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `scripts/test-offline.sh`

**Interfaces:**
- Consumes: the workspace from Tasks 2–6.
- Produces: a `ci` workflow with jobs `test` (ubuntu + macos) and `offline` (ubuntu, tests run with no network).

- [ ] **Step 1: Create `scripts/test-offline.sh`**

```bash
#!/usr/bin/env bash
# Run the full test suite with networking disabled (Linux only).
# Proves the spec's "no network calls" rule: any network use fails a test.
set -euo pipefail
cargo test --workspace --no-run --quiet
# Sanity check: inside the namespace there must be no network.
if unshare -rn curl -sS --max-time 3 https://example.com >/dev/null 2>&1; then
  echo "network is still reachable inside the namespace" >&2
  exit 1
fi
unshare -rn cargo test --workspace --offline --quiet
```

```bash
chmod +x scripts/test-offline.sh
```

- [ ] **Step 2: Run it locally**

Run: `./scripts/test-offline.sh`
Expected: all tests pass. (If `unshare -rn` fails with `Operation not permitted`, user namespaces are disabled on this machine; skip the local run — CI enables them below.)

- [ ] **Step 3: Create `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace

  offline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      # Ubuntu 24.04 blocks unprivileged user namespaces by default.
      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - run: ./scripts/test-offline.sh
```

- [ ] **Step 4: Commit and push**

```bash
git add .github scripts
git commit -m "ci: fmt, clippy, tests on linux+macos, offline test run"
git push origin main
```

- [ ] **Step 5: Verify CI**

Run: `gh run watch --exit-status $(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')`
Expected: all three jobs (`test (ubuntu-latest)`, `test (macos-latest)`, `offline`) succeed. If one fails, read its log with `gh run view --log-failed` and fix the cause in a new commit.

---

## Done when

- `cargo test --workspace` passes locally; CI is green on all three jobs.
- `saiife check` writes one masked record per decision (allow, deny, error_allowed) to `<data dir>/saiife/audit/YYYY-MM.jsonl`, files are `0600`, and an unwritable audit dir never changes a verdict.
- `saiife audit` shows the log with `--since`, `--project`, `--agent`, `--blocked`.
- Next: write plan 2 (agents + project config) against this code.
