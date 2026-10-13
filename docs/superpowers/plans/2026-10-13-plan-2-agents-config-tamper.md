# saiife Plan 2 — Agents, Project Config and Tamper Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife init` wires the guard into Claude Code, Codex and Gemini CLI for one project (and `init --off` takes exactly that out again), `saiife check` answers every agent's hook contract correctly for shell, read and write tools, and `saiife status` shows when the setup was removed, changed or bypassed.

**Architecture:** A new crate `crates/agents` (package `saiife-agents`, lib `saiife_agents`) owns everything saiife writes into a project: one module per agent (install / remove / fingerprint the hook entry), the project config `.saiife/config.toml`, and the integrity record kept outside the project. The guard gains a pure `payload::classify` that sorts a hook payload into shell, file or other tool calls; `saiife check` judges only shell calls (path rules are plan 3) and loads the project's opt-in packs by walking up from the payload's `cwd`. The `cli` crate adds `init`, `init --off`, `status` and `packs` as thin command layers over `agents`, `guard` and `audit`.

**Tech Stack:** Rust stable (edition 2021), clap 4, serde/serde_json (`preserve_order` in `agents`), toml_edit 0.22.27, sha2 0.10.9, tempfile 3, dirs 5, thiserror 1, time 0.3; tests with assert_cmd, predicates, tempfile.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` (this plan covers §5, §5.1, §5.2, §7.5, the reserved `locked` field of §9.1, and the agent / hook-payload / tamper parts of §10). Hook contracts: `docs/superpowers/research/2026-10-13-{claude-code,codex,gemini}-hooks.md` — authoritative for this plan where they refine the spec. Roadmap: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`.

## Global Constraints

- **Fail open.** Any internal error, parse failure or exceeded latency budget allows the command. The event is still audited (§6).
- **Latency budget:** 50 ms per evaluation (existing `DEFAULT_BUDGET`, do not change).
- **No network.** The binary makes no network calls of any kind (§8).
- **Fail open only where a human is present.** v1 developer mode fails open (a wedged guard gets uninstalled) — so no hook entry sets Claude's `onFailure: "block"` (§1.2 rule 4).
- **Protection must be observable.** Every fail-open, every disabled hook and every gap in the audit trail is recorded or reported; silence is never read as safety (§1.2 rule 5).
- Audit storage: `$XDG_DATA_HOME/saiife/audit/YYYY-MM.jsonl` (via `dirs::data_dir()`), overridable with `SAIIFE_AUDIT_DIR`. Never inside the project directory. A failed write never blocks or alters the decision.
- Audit `decision` ∈ `allow` | `deny` | `error_allowed`. `input` is the command for shell tools and the path for read tools (§6.2); plaintext secrets never reach disk.
- `saiife init`: "Detect installed agents; write the guard hook into this project's agent configs; create `.saiife/config.toml`. Idempotent." (§5)
- `saiife init --off`: "Remove exactly what `init` added. Leave all other user settings byte-for-byte unchanged where the format allows (JSON/TOML key order preserved)." (§5)
- `saiife status`: "exit code 1 if any check fails, so it can run in scripts and CI." Each failed check prints a plain-language warning and the fix (`saiife init` to restore). (§5, §7.5)
- `.saiife/config.toml`: `version = 1`, `packs = [...]`, `locked = false   # reserved for admin lock (§9.1); v1 reads and ignores it`. "Default-on packs are always active. `packs` adds opt-in ones. `saiife init` writes the default-on list explicitly so the file is self-describing." (§5.1)
- Files written by `init`: Claude Code `.claude/settings.json` (`PreToolUse`), Codex `.codex/config.toml` (`PreToolUse`), Gemini CLI `.gemini/settings.json` (`BeforeTool`) (§5.2).
- "The hook command is `saiife check --agent <name>`, resolved via `PATH`, so a reinstall/upgrade never leaves stale absolute paths in project files." (§5.2) — this plan writes `saiife check --hook-exit --agent <name>` (see Decisions).
- Integrity file: `<data dir>/saiife/projects/<sha256 of project path>.json` with SHA-256 fingerprints of each hook entry and of `.saiife/config.toml`; status checks "the `saiife` binary on `PATH` is the one that ran `init` (path + version)" (§7.5).
- Crate boundaries: "`guard`, `audit` and `agents` do not depend on each other except that `cli` passes a guard decision to `audit`." (§4)
- Hook output (research): allow = exit 0 with **nothing on stdout**, for every agent; deny = exit 2 + non-empty stderr reason. Never emit `permissionDecision: "allow"`.
- Tests never write to the real user's directories: `SAIIFE_AUDIT_DIR`, `SAIIFE_DATA_DIR`, `HOME` and `PATH` are set to temp dirs for every spawned `saiife`.
- Binary name: `saiife`. Platforms: Linux and macOS. No Windows. `#![forbid(unsafe_code)]` in every crate.
- Every commit message ends with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A `Write`/`Edit` of a large file** (content over the 256 KiB payload cap): it is an ordinary file-tool call, so it must be recorded as `allow` with its path — not as an `error_allowed` "guard failure" that floods the log and hides real ones. → Task 3 test `large_write_is_recorded_as_allow_with_its_path`.
2. **A settings file that is not plain JSON/TOML** (Gemini users often keep `//` comments; trailing commas; a hand-broken file; an unexpected layout): `init` must refuse that one agent with a clear message, leave the file byte-identical, still set up the other agents, and exit 1. → Task 6 test `unparseable_settings_are_left_byte_identical`, Task 7 test `other_layouts_and_bad_toml_are_left_untouched`, Task 9 test `broken_settings_file_fails_that_agent_only`.
3. **The same project reached another way** (through a symlink, or `init`/`status` run from a subdirectory): it must be one project with one integrity record, not "not set up". → Task 8 test `symlinked_project_path_maps_to_the_same_record`, Task 9 test `init_from_a_subdirectory_reuses_the_project`, Task 11 test `symlinked_path_and_subdirectory_find_the_same_project`.
4. **`saiife` not on `PATH`** (run as `./target/release/saiife init`, or `~/.local/bin` not on PATH): every hook then fails to start and the agent runs unguarded. `init` must say so plainly; `status` must fail. → Task 9 test `init_warns_when_saiife_is_not_on_path`, Task 11 test `saiife_missing_from_path_is_reported`.
5. **Re-running `init` after the user hand-edited `.saiife/config.toml`** (added a pack, a comment): the edits must survive and only missing pack ids are appended. → Task 5 test `existing_file_keeps_user_edits_and_only_gains_missing_ids`.

## Decisions (spec ambiguities resolved here)

- **All three agents get `--hook-exit`** (`saiife check --hook-exit --agent <name>`): exit 2 + stderr is the one block contract Claude Code, Codex and Gemini CLI all honor; Gemini does not read Claude's `hookSpecificOutput` JSON.
- **Allow is silent in both modes** (with and without `--hook-exit`): exit 0, empty stdout. JSON mode keeps its `permissionDecision: "deny"` payload for deny.
- **Unknown tool with a string `tool_input.command` is judged as a shell call**, so a shell tool renamed in a future agent version cannot slip past the guard. Other unknown tools: `allow`, reason `tool not guarded`.
- **Payload size:** payloads up to 1 MiB (`4 × MAX_PAYLOAD_BYTES`) are parsed. File tools of that size are handled normally; a shell payload over 256 KiB stays `error_allowed` with its command recorded (plan 1 behavior). Above 1 MiB: `error_allowed`, empty input.
- **JSON settings are rewritten with the indent the file already used** (two spaces when new) and its trailing newline, keys in their original order; a consistently indented file round-trips byte-for-byte through `init` + `init --off`. Files with comments are refused, not rewritten.
- **Codex:** hooks go into `.codex/config.toml` (not `.codex/hooks.json`), only in the `[[hooks.PreToolUse]]` / `[[hooks.PreToolUse.hooks]]` array-of-tables layout; any other layout of `hooks.PreToolUse` is reported and left alone.
- **Project root** for `init`, `init --off`, `status` and `packs`: the nearest directory at or above the current one that has `.saiife/config.toml`, else the current directory. `check` walks up from the payload's `cwd` (process cwd if absent). `test`/`explain` keep using only `--pack` (deterministic for scripts).
- **How saiife finds its own entries ("tagged", §5.2):** a hook handler whose `command` runs `saiife check` (any path to the binary), plus Gemini's `"name": "saiife"`. No extra marker field is added, because Claude Code and Codex validate their hook schema.
- **Tamper fingerprint** = SHA-256 of the canonical (sorted-key) JSON of `{matcher, handler}`, so narrowing the matcher counts as tampering. An agent passes if any saiife entry in its file matches the recorded fingerprint.
- **`init --off`** removes saiife's hook handlers from all three agent files; deletes a file only if saiife created it and nothing else is left; deletes `.saiife/config.toml` only if saiife created it and it is unchanged; removes empty directories saiife created; deletes the integrity record only when everything succeeded.
- **`status`** exits 1 when the project has no integrity record. Unreadable audit dir and non-regular audit files are failed checks; skipped half-written lines are a note. "Last hook call" is information, never a failure (it is "never" right after `init`). Claude `disableAllHooks` (project, local, user, managed), managed `allowManagedHooksOnly`, and Codex `[features] hooks = false` are failed checks. The binary version is read with `<path> --version` (2 s timeout).
- **`saiife audit`** exits 1 (instead of printing an empty table) when the audit directory cannot be read.

## File map

| File | Responsibility |
|---|---|
| `crates/guard/src/payload.rs` | + `ToolCall`, `classify`, `context_from_hook_json_bounded` |
| `crates/cli/src/check.rs` | tool-aware hook mode, silent allow, project packs |
| `crates/cli/src/project.rs` | which packs a project turns on |
| `crates/cli/src/init_cmd.rs` | `init`, `init --off`, `project_root` |
| `crates/cli/src/status_cmd.rs` | tamper checks |
| `crates/cli/src/packs_cmd.rs` | pack listing |
| `crates/cli/tests/fixtures/**` | recorded-shape payloads per agent and tool |
| `crates/agents/src/lib.rs` | `Agent`, `Change`, `AgentError`, `HookBlocker`, `is_saiife_command` |
| `crates/agents/src/{detect,fingerprint,fsutil}.rs` | PATH lookup, SHA-256 + canonical JSON, atomic file writes |
| `crates/agents/src/json_hooks.rs` | shared JSON hook editing (Claude, Gemini) |
| `crates/agents/src/{claude,codex,gemini}.rs` | per-agent entry, install/remove/entries, blockers, next step |
| `crates/agents/src/config.rs` | `.saiife/config.toml` |
| `crates/agents/src/integrity.rs` | integrity record outside the project |
| `crates/audit/src/store.rs` | + `ReadResult::dir_error` |

---

### Task 1: Silent allow — fix the hook contract

On allow, `saiife check` must print nothing and exit 0 for every agent (research: a Claude `permissionDecision: "allow"` skips the user's permission prompts; a Codex allow without `updatedInput` is a failed hook). Deny is unchanged. Also stops the check tests from leaving `/tmp/saiife-test-audit-*` dirs behind (plan 1 carry-over).

**Files:**
- Modify: `crates/cli/src/check.rs` (`allow`, `emit_allow`), `crates/cli/src/main.rs` (doc line)
- Test: `crates/cli/tests/hook_exit.rs`, `crates/cli/tests/cli.rs`

**Interfaces:**
- Consumes: plan 1's `check::run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode`.
- Produces: `fn allow() -> ExitCode` (private to `check.rs`, no parameters, prints nothing). `check::run`'s signature is unchanged.

- [ ] **Step 1: Write the failing tests**

In `crates/cli/tests/hook_exit.rs`, give every run its own temp audit dir (deleted on drop). Replace:

```rust
fn run_check(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(args)
        .env(
            "SAIIFE_AUDIT_DIR",
            std::env::temp_dir().join(format!("saiife-test-audit-{}", std::process::id())),
        )
```

with:

```rust
fn run_check(args: &[&str], stdin: &str) -> (i32, String, String) {
    let audit = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(args)
        .env("SAIIFE_AUDIT_DIR", audit.path())
```

Append to `crates/cli/tests/hook_exit.rs`:

```rust

/// Allow is exit 0 with NOTHING on stdout in both modes: Claude Code reads a
/// JSON `permissionDecision: "allow"` as "skip the user's permission
/// prompt", and Codex counts an allow without `updatedInput` as a failed hook.
#[test]
fn allow_prints_nothing_on_stdout_in_either_mode() {
    for args in [&["check", "--hook-exit"][..], &["check"][..]] {
        let (code, stdout, _) = run_check(args, ALLOW_JSON);
        assert_eq!(code, 0, "{args:?}");
        assert!(stdout.is_empty(), "{args:?} printed {stdout:?}");
    }
}

#[test]
fn fail_open_prints_nothing_on_stdout_in_either_mode() {
    for args in [&["check", "--hook-exit"][..], &["check"][..]] {
        let (code, stdout, _) = run_check(args, "not json");
        assert_eq!(code, 0, "{args:?}");
        assert!(stdout.is_empty(), "{args:?} printed {stdout:?}");
    }
}

#[test]
fn json_mode_deny_is_unchanged() {
    let (code, stdout, _) = run_check(&["check"], DENY_JSON);
    assert_eq!(code, 0, "JSON mode carries the deny in the payload");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("BLOCKED by core.filesystem"));
}
```

In `crates/cli/tests/cli.rs`, replace the last two tests (from `#[test]\nfn check_denies_via_hook_json()` to the end of the file):

```rust
#[test]
fn check_denies_via_hook_json() {
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("check")
        .env("SAIIFE_AUDIT_DIR", std::env::temp_dir().join("saiife-test-audit-cli"))
        .write_stdin(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn check_fails_open_on_garbage() {
    // Malformed JSON must NOT block — fail open (allow).
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("check")
        .env(
            "SAIIFE_AUDIT_DIR",
            std::env::temp_dir().join("saiife-test-audit-cli"),
        )
        .write_stdin("{not json at all")
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}
```

with:

```rust
#[test]
fn check_denies_via_hook_json() {
    let audit = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("check")
        .env("SAIIFE_AUDIT_DIR", audit.path())
        .write_stdin(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn check_fails_open_on_garbage() {
    // Malformed JSON must NOT block — fail open (allow).
    let audit = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("check")
        .env("SAIIFE_AUDIT_DIR", audit.path())
        .write_stdin("{not json at all")
        .assert()
        .success()
        // Allow is silence: an explicit "allow" would skip the agent's own
        // permission prompts (Claude) or count as a failed hook (Codex).
        .stdout(predicate::str::is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife --test hook_exit --test cli`
Expected: FAIL — `allow_prints_nothing_on_stdout_in_either_mode` (`["check"] printed "{\"hookSpecificOutput\"…allow…"`), `fail_open_prints_nothing_on_stdout_in_either_mode` and `check_fails_open_on_garbage` fail; the deny tests pass.

- [ ] **Step 3: Make allow silent**

In `crates/cli/src/check.rs`, replace `allow` and `emit_allow` (keep `emit_deny`):

```rust
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

```

with:

```rust
/// Allow = exit 0 with NOTHING on stdout, for every agent and both modes.
/// An explicit `permissionDecision: "allow"` would skip Claude Code's own
/// permission prompts, and Codex treats an allow without `updatedInput` as a
/// failed hook. Silence means "no objection": the agent's normal flow runs.
fn allow() -> ExitCode {
    ExitCode::SUCCESS
}

```

Then, in the same file, change every call `allow(hook_exit)` to `allow()` (three `return allow(hook_exit);` lines in `run`/`decide` and the arm `Decision::Allow { .. } => allow(hook_exit),`).

In `crates/cli/src/main.rs`, replace:

```rust
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, emit the hook allow/block response; FAIL OPEN on error.
```

with:

```rust
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, answer the hook (silent allow / block); FAIL OPEN on error.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p saiife`
Expected: PASS, 0 failed.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/cli/src/check.rs crates/cli/src/main.rs crates/cli/tests/hook_exit.rs crates/cli/tests/cli.rs
git commit -m "fix(check): allow is silent for every agent; never emit permissionDecision allow

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `payload::classify` — sort a hook payload by tool

A small pure function the CLI (and plan 3's `evaluate_path`) builds on. Tool names and input fields come from the research docs.

**Files:**
- Modify: `crates/guard/src/payload.rs`

**Interfaces:**
- Consumes: existing `command_from_hook_json(input: &str, max_bytes: usize) -> Result<String, PayloadError>`, `PayloadError`, `MAX_PAYLOAD_BYTES`, `HookContext`.
- Produces (all `pub` in `saiifeguard::payload`):
  - `enum ToolCall { Shell { command: String }, File { tool: String, paths: Vec<String>, write: bool }, Other { tool: String } }` (derives `Debug, Clone, PartialEq, Eq`)
  - `fn classify(input: &str, max_bytes: usize) -> Result<ToolCall, PayloadError>`
  - `fn context_from_hook_json_bounded(input: &str, max_bytes: usize) -> HookContext` (`context_from_hook_json(input)` now calls it with `MAX_PAYLOAD_BYTES`)

- [ ] **Step 1: Write the failing tests**

In `crates/guard/src/payload.rs`, inside `mod tests`, insert directly above `#[test] fn context_reads_claude_fields()`:

```rust
    fn call(json: serde_json::Value) -> ToolCall {
        classify(&json.to_string(), MAX_PAYLOAD_BYTES).unwrap()
    }

    #[test]
    fn classify_shell_tools() {
        for tool in ["Bash", "run_shell_command"] {
            let c =
                call(serde_json::json!({"tool_name": tool, "tool_input": {"command": "rm -rf /"}}));
            assert_eq!(
                c,
                ToolCall::Shell {
                    command: "rm -rf /".into()
                },
                "{tool}"
            );
        }
    }

    #[test]
    fn classify_claude_file_tools() {
        let read = call(
            serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": "/p/.env", "offset": 1}}),
        );
        assert_eq!(
            read,
            ToolCall::File {
                tool: "Read".into(),
                paths: vec!["/p/.env".into()],
                write: false
            }
        );
        let nb = call(
            serde_json::json!({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/p/a.ipynb", "new_source": "x"}}),
        );
        assert_eq!(
            nb,
            ToolCall::File {
                tool: "NotebookEdit".into(),
                paths: vec!["/p/a.ipynb".into()],
                write: true
            }
        );
        for tool in ["Write", "Edit", "MultiEdit"] {
            let c = call(
                serde_json::json!({"tool_name": tool, "tool_input": {"file_path": "/p/x.rs"}}),
            );
            assert_eq!(
                c,
                ToolCall::File {
                    tool: tool.into(),
                    paths: vec!["/p/x.rs".into()],
                    write: true
                }
            );
        }
    }

    #[test]
    fn classify_grep_without_path_uses_cwd() {
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Grep", "tool_input": {"pattern": "TODO"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Grep".into(),
                paths: vec!["/p".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/p/src"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Grep".into(),
                paths: vec!["/p/src".into()],
                write: false
            }
        );
    }

    #[test]
    fn classify_gemini_file_tools() {
        let c = call(
            serde_json::json!({"tool_name": "list_directory", "tool_input": {"dir_path": "/p/src"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "list_directory".into(),
                paths: vec!["/p/src".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "read_many_files", "tool_input": {"include": ["src/**/*.rs", ".env"], "exclude": ["target"]}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "read_many_files".into(),
                paths: vec!["src/**/*.rs".into(), ".env".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "replace", "tool_input": {"file_path": "/p/a", "old_string": "a", "new_string": "b"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "replace".into(),
                paths: vec!["/p/a".into()],
                write: true
            }
        );
    }

    #[test]
    fn classify_apply_patch_never_yields_a_shell_command() {
        let patch = "*** Begin Patch\n*** Add File: hello.txt\n+rm -rf /\n*** Update File: src/main.rs\n*** Move to: src/app.rs\n@@\n-a\n+b\n*** Delete File: old.txt\n*** End Patch\n";
        let c =
            call(serde_json::json!({"tool_name": "apply_patch", "tool_input": {"command": patch}}));
        assert_eq!(
            c,
            ToolCall::File {
                tool: "apply_patch".into(),
                paths: vec![
                    "hello.txt".into(),
                    "src/main.rs".into(),
                    "src/app.rs".into(),
                    "old.txt".into()
                ],
                write: true
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "apply_patch", "tool_input": {"command": "rm -rf /"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "apply_patch".into(),
                paths: vec![],
                write: true
            }
        );
    }

    #[test]
    fn classify_unknown_tools() {
        let c =
            call(serde_json::json!({"tool_name": "WebFetch", "tool_input": {"url": "https://x"}}));
        assert_eq!(
            c,
            ToolCall::Other {
                tool: "WebFetch".into()
            }
        );
        // A shell tool under a name this version does not know is still judged.
        let c =
            call(serde_json::json!({"tool_name": "shell", "tool_input": {"command": "rm -rf /"}}));
        assert_eq!(
            c,
            ToolCall::Shell {
                command: "rm -rf /".into()
            }
        );
    }

    #[test]
    fn classify_without_tool_name_keeps_old_shape() {
        let c = call(serde_json::json!({"command": "ls"}));
        assert_eq!(
            c,
            ToolCall::Shell {
                command: "ls".into()
            }
        );
        assert!(matches!(
            classify(r#"{"x":1}"#, MAX_PAYLOAD_BYTES),
            Err(PayloadError::NoCommand)
        ));
    }

    #[test]
    fn classify_errors() {
        assert!(matches!(
            classify("{not json", MAX_PAYLOAD_BYTES),
            Err(PayloadError::Json(_))
        ));
        assert!(matches!(
            classify(r#"{"tool_name":"Bash"}"#, 10),
            Err(PayloadError::TooLarge)
        ));
        assert!(matches!(
            classify(
                r#"{"tool_name":"Bash","tool_input":{"command":"  "}}"#,
                MAX_PAYLOAD_BYTES
            ),
            Err(PayloadError::NoCommand)
        ));
    }

    #[test]
    fn bounded_context_reads_past_the_default_cap() {
        let big = format!(
            r#"{{"tool_name":"Write","session_id":"s","cwd":"/p","tool_input":{{"file_path":"/p/a","content":"{}"}}}}"#,
            "a".repeat(MAX_PAYLOAD_BYTES)
        );
        assert_eq!(context_from_hook_json(&big), HookContext::default());
        let ctx = context_from_hook_json_bounded(&big, 2 * MAX_PAYLOAD_BYTES);
        assert_eq!(ctx.tool.as_deref(), Some("Write"));
        assert_eq!(ctx.cwd.as_deref(), Some("/p"));
    }

```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-guard --lib payload`
Expected: FAIL to compile — `cannot find function 'classify'`, `cannot find type 'ToolCall'`, `cannot find function 'context_from_hook_json_bounded'`.

- [ ] **Step 3: Implement**

In `crates/guard/src/payload.rs`, insert directly above the doc comment `/// Metadata about a hook call, for the audit log.`:

```rust
/// What a hook call asks to do, by kind of tool. Shell commands go to the
/// command guard; file tools carry the path(s) they touch (judged by path
/// rules from plan 3 on); anything else is recorded but not judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    Shell {
        command: String,
    },
    File {
        tool: String,
        paths: Vec<String>,
        write: bool,
    },
    Other {
        tool: String,
    },
}

/// Shell tools: Claude Code and Codex `Bash`, Gemini `run_shell_command`.
const SHELL_TOOLS: &[&str] = &["Bash", "run_shell_command"];

/// File tools that only read or list.
const READ_TOOLS: &[&str] = &[
    "Read",
    "Grep",
    "read_file",
    "read_many_files",
    "list_directory",
    "glob",
    "grep_search",
];

/// File tools that change files.
const WRITE_TOOLS: &[&str] = &[
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "write_file",
    "replace",
    "apply_patch",
];

/// Classify a hook payload by its `tool_name`.
///
/// - Shell tools yield their `tool_input.command`.
/// - File tools yield the path(s) they touch. Codex `apply_patch` carries the
///   patch text in `tool_input.command`; it is parsed for file headers and
///   never treated as a shell command.
/// - A payload with no `tool_name` keeps the old behavior: it is a shell
///   call if a command can be found.
/// - Any other tool that carries a string `tool_input.command` is treated as
///   a shell call, so a renamed shell tool is still judged.
/// - Everything else is `Other`.
///
/// Errors (oversize, not JSON, shell call without a command) make the caller
/// fail open.
pub fn classify(input: &str, max_bytes: usize) -> Result<ToolCall, PayloadError> {
    if input.len() > max_bytes {
        return Err(PayloadError::TooLarge);
    }
    let v: Value = serde_json::from_str(input).map_err(|e| PayloadError::Json(e.to_string()))?;
    let tool = ["tool_name", "toolName"]
        .iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str))
        .filter(|t| !t.is_empty());
    let Some(tool) = tool else {
        return command_from_hook_json(input, max_bytes).map(|command| ToolCall::Shell { command });
    };
    let tool_input = v.get("tool_input").unwrap_or(&Value::Null);
    if SHELL_TOOLS.contains(&tool) {
        return command_from_hook_json(input, max_bytes).map(|command| ToolCall::Shell { command });
    }
    let write = WRITE_TOOLS.contains(&tool);
    if write || READ_TOOLS.contains(&tool) {
        let mut paths = if tool == "apply_patch" {
            let patch = tool_input
                .get("command")
                .or_else(|| tool_input.get("input"))
                .and_then(Value::as_str)
                .unwrap_or("");
            patch_paths(patch)
        } else {
            tool_paths(tool_input)
        };
        if paths.is_empty() && tool != "apply_patch" {
            // Search and list tools default to the working directory.
            if let Some(cwd) = v.get("cwd").and_then(Value::as_str) {
                paths.push(cwd.to_string());
            }
        }
        return Ok(ToolCall::File {
            tool: tool.to_string(),
            paths,
            write,
        });
    }
    match tool_input.get("command").and_then(Value::as_str) {
        Some(cmd) if !cmd.trim().is_empty() => Ok(ToolCall::Shell {
            command: cmd.to_string(),
        }),
        _ => Ok(ToolCall::Other {
            tool: tool.to_string(),
        }),
    }
}

/// Path fields of the Claude Code and Gemini CLI file tools, in a fixed order.
fn tool_paths(tool_input: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["file_path", "notebook_path", "path", "dir_path"] {
        if let Some(p) = tool_input.get(key).and_then(Value::as_str) {
            if !p.is_empty() {
                out.push(p.to_string());
            }
        }
    }
    if let Some(list) = tool_input.get("include").and_then(Value::as_array) {
        out.extend(
            list.iter()
                .filter_map(Value::as_str)
                .filter(|p| !p.is_empty())
                .map(str::to_string),
        );
    }
    out
}

/// File paths named in a Codex `apply_patch` body, in patch order.
fn patch_paths(patch: &str) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    let mut out: Vec<String> = Vec::new();
    for line in patch.lines() {
        let line = line.trim_end_matches('\r');
        for h in HEADERS {
            if let Some(p) = line.strip_prefix(h) {
                let p = p.trim();
                if !p.is_empty() && !out.iter().any(|q| q == p) {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

```

Then replace the head of `context_from_hook_json`:

```rust
pub fn context_from_hook_json(input: &str) -> HookContext {
    if input.len() > MAX_PAYLOAD_BYTES {
```

with:

```rust
pub fn context_from_hook_json(input: &str) -> HookContext {
    context_from_hook_json_bounded(input, MAX_PAYLOAD_BYTES)
}

/// `context_from_hook_json` with a caller-chosen size cap, for callers that
/// still want the context of a payload above `MAX_PAYLOAD_BYTES` (a `Write`
/// of a large file).
pub fn context_from_hook_json_bounded(input: &str, max_bytes: usize) -> HookContext {
    if input.len() > max_bytes {
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p saiife-guard`
Expected: PASS (all corpus tests unchanged).

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/guard/src/payload.rs
git commit -m "feat(guard): classify hook payloads into shell, file and other tool calls

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Tool-aware `saiife check` with recorded-shape fixtures

`check` judges shell tools as before, records file tools with their paths (never judged in plan 2 — and Codex's `apply_patch` text must never reach the shell guard), and records unknown tools as `allow` / `tool not guarded`. Fixtures are built from the field lists in the research docs.

**Files:**
- Modify: `crates/cli/src/check.rs` (whole file)
- Create: `crates/cli/tests/fixtures/{claude,codex,gemini,malformed}/*` (24 files)
- Test: `crates/cli/tests/check_tools.rs`

**Interfaces:**
- Consumes: `saiifeguard::payload::{classify, context_from_hook_json_bounded, ToolCall, PayloadError, MAX_PAYLOAD_BYTES}` (Task 2); `allow()` (Task 1).
- Produces: `check::run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode` (unchanged signature); private `const PARSE_MAX_BYTES: usize = 4 * MAX_PAYLOAD_BYTES`, `fn fail_open(audit: &Audit, input: &str, e: &PayloadError) -> ExitCode`. Audit `input` for file tools = paths joined with `\n`. Removes `salvage_command` / `SALVAGE_MAX_BYTES`.

- [ ] **Step 1: Create the fixtures**

Each file is one line of JSON exactly as shown (the `bash`/`printf` forms below write them byte-exact):

```bash
mkdir -p crates/cli/tests/fixtures/{claude,codex,gemini,malformed}
cd crates/cli/tests/fixtures
cat > claude/bash-deny.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /","description":"Delete everything"},"tool_use_id":"toolu_01"}
EOF
cat > claude/bash-allow.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la","description":"List files"},"tool_use_id":"toolu_02"}
EOF
cat > claude/read.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/u/app/.env","offset":1,"limit":50},"tool_use_id":"toolu_03"}
EOF
cat > claude/grep-no-path.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"rm -rf /","output_mode":"content"},"tool_use_id":"toolu_04"}
EOF
cat > claude/write.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/home/u/app/notes.sh","content":"rm -rf /\n"},"tool_use_id":"toolu_05"}
EOF
cat > claude/edit.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/home/u/app/src/main.rs","old_string":"a","new_string":"git reset --hard","replace_all":false},"tool_use_id":"toolu_06"}
EOF
cat > claude/notebook-edit.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"NotebookEdit","tool_input":{"notebook_path":"/home/u/app/analysis.ipynb","new_source":"print(1)"},"tool_use_id":"toolu_07"}
EOF
cat > claude/webfetch.json <<'EOF'
{"session_id":"c-1","transcript_path":"/home/u/.claude/projects/app/c-1.jsonl","cwd":"/home/u/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com","prompt":"summarize"},"tool_use_id":"toolu_08"}
EOF
cat > codex/bash-deny.json <<'EOF'
{"session_id":"x-1","transcript_path":"/home/u/.codex/sessions/x-1.jsonl","cwd":"/home/u/app","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","turn_id":"t-1","tool_name":"Bash","tool_use_id":"call_1","tool_input":{"command":"git reset --hard"}}
EOF
cat > codex/bash-allow.json <<'EOF'
{"session_id":"x-1","transcript_path":"/home/u/.codex/sessions/x-1.jsonl","cwd":"/home/u/app","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","turn_id":"t-1","tool_name":"Bash","tool_use_id":"call_2","tool_input":{"command":"cargo test"}}
EOF
cat > codex/apply-patch.json <<'EOF'
{"session_id":"x-1","transcript_path":"/home/u/.codex/sessions/x-1.jsonl","cwd":"/home/u/app","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","turn_id":"t-1","tool_name":"apply_patch","tool_use_id":"call_3","tool_input":{"command":"*** Begin Patch\n*** Add File: docs/recovery.md\n+To start over, run: git reset --hard\n*** Update File: scripts/reset.sh\n@@\n git fetch origin\n git reset --hard\n-echo done\n+echo \"reset complete\"\n*** End Patch\n"}}
EOF
cat > codex/mcp-tool.json <<'EOF'
{"session_id":"x-1","transcript_path":"/home/u/.codex/sessions/x-1.jsonl","cwd":"/home/u/app","hook_event_name":"PreToolUse","model":"gpt-5-codex","permission_mode":"default","turn_id":"t-1","tool_name":"mcp__docs__search","tool_use_id":"call_4","tool_input":{"query":"hooks"}}
EOF
cat > gemini/shell-deny.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"run_shell_command","tool_input":{"command":"rm -rf /","description":"clean up"}}
EOF
cat > gemini/shell-allow.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"run_shell_command","tool_input":{"command":"git status"}}
EOF
cat > gemini/read-file.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"read_file","tool_input":{"file_path":"/home/u/app/.env"}}
EOF
cat > gemini/read-many-files.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"read_many_files","tool_input":{"include":["src/**/*.rs","README.md"],"exclude":["target/**"]}}
EOF
cat > gemini/list-directory.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"list_directory","tool_input":{"dir_path":"/home/u/app/src"}}
EOF
cat > gemini/write-file.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"write_file","tool_input":{"file_path":"/home/u/app/run.sh","content":"rm -rf /\n"}}
EOF
cat > gemini/replace.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"replace","tool_input":{"file_path":"/home/u/app/src/main.rs","old_string":"a","new_string":"b"}}
EOF
cat > gemini/web-fetch.json <<'EOF'
{"session_id":"g-1","transcript_path":"/home/u/.gemini/tmp/app/chats/g-1.json","cwd":"/home/u/app","hook_event_name":"BeforeTool","timestamp":"2026-10-13T08:14:02.381Z","tool_name":"web_fetch","tool_input":{"prompt":"summarize https://example.com"}}
EOF
cat > malformed/bash-no-command.json <<'EOF'
{"session_id":"c-1","cwd":"/home/u/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"description":"no command"}}
EOF
printf '%s' '{"session_id":"c-1","cwd":"/home/u/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf' > malformed/truncated.json
printf 'this is not json\n' > malformed/not-json.txt
cd -
```

Note: the `apply-patch.json` patch contains `git reset --hard` as file CONTENT (an added line and a context line of `scripts/reset.sh`) — that is the point of the fixture: judged as a shell command it would be blocked.

- [ ] **Step 2: Write the failing tests**

Create `crates/cli/tests/check_tools.rs`:

```rust
//! `saiife check` against recorded-shape payloads of every agent and tool
//! (fixtures built from docs/superpowers/research/2026-10-13-*-hooks.md).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::{read_all, DIR_ENV};
use saiife_audit::{DecisionKind, Record};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn check_bytes(audit_dir: &Path, agent: &str, stdin: &[u8]) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", agent])
        .env(DIR_ENV, audit_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Run one fixture in a fresh audit dir; return the output and the single
/// record it wrote.
fn run(name: &str, agent: &str) -> (Out, Record) {
    let dir = tempfile::tempdir().unwrap();
    let out = check_bytes(dir.path(), agent, &fixture(name));
    let mut recs = read_all(dir.path()).records;
    assert_eq!(recs.len(), 1, "{name}: exactly one record");
    (out, recs.remove(0))
}

#[test]
fn shell_fixtures_are_judged() {
    for (name, agent, code, decision, input) in [
        (
            "claude/bash-deny.json",
            "claude",
            2,
            DecisionKind::Deny,
            "rm -rf /",
        ),
        (
            "claude/bash-allow.json",
            "claude",
            0,
            DecisionKind::Allow,
            "ls -la",
        ),
        (
            "codex/bash-deny.json",
            "codex",
            2,
            DecisionKind::Deny,
            "git reset --hard",
        ),
        (
            "codex/bash-allow.json",
            "codex",
            0,
            DecisionKind::Allow,
            "cargo test",
        ),
        (
            "gemini/shell-deny.json",
            "gemini",
            2,
            DecisionKind::Deny,
            "rm -rf /",
        ),
        (
            "gemini/shell-allow.json",
            "gemini",
            0,
            DecisionKind::Allow,
            "git status",
        ),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, code, "{name}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{name}: stdout must stay empty");
        if code == 2 {
            assert!(out.stderr.contains("BLOCKED by"), "{name}: {}", out.stderr);
        }
        assert_eq!(rec.decision, decision, "{name}");
        assert_eq!(rec.input, input, "{name}");
        assert_eq!(rec.agent, agent, "{name}");
        assert_eq!(rec.project, "/home/u/app", "{name}");
    }
}

#[test]
fn file_tool_fixtures_are_recorded_with_their_paths_and_never_judged() {
    for (name, agent, tool, input) in [
        ("claude/read.json", "claude", "Read", "/home/u/app/.env"),
        ("claude/grep-no-path.json", "claude", "Grep", "/home/u/app"),
        (
            "claude/write.json",
            "claude",
            "Write",
            "/home/u/app/notes.sh",
        ),
        (
            "claude/edit.json",
            "claude",
            "Edit",
            "/home/u/app/src/main.rs",
        ),
        (
            "claude/notebook-edit.json",
            "claude",
            "NotebookEdit",
            "/home/u/app/analysis.ipynb",
        ),
        (
            "codex/apply-patch.json",
            "codex",
            "apply_patch",
            "docs/recovery.md\nscripts/reset.sh",
        ),
        (
            "gemini/read-file.json",
            "gemini",
            "read_file",
            "/home/u/app/.env",
        ),
        (
            "gemini/read-many-files.json",
            "gemini",
            "read_many_files",
            "src/**/*.rs\nREADME.md",
        ),
        (
            "gemini/list-directory.json",
            "gemini",
            "list_directory",
            "/home/u/app/src",
        ),
        (
            "gemini/write-file.json",
            "gemini",
            "write_file",
            "/home/u/app/run.sh",
        ),
        (
            "gemini/replace.json",
            "gemini",
            "replace",
            "/home/u/app/src/main.rs",
        ),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{name}: stdout must stay empty");
        assert_eq!(rec.decision, DecisionKind::Allow, "{name}");
        assert_eq!(rec.tool, tool, "{name}");
        assert_eq!(rec.input, input, "{name}");
        assert_eq!(
            rec.pack, None,
            "{name}: file tools are not judged by command packs"
        );
    }
}

/// The patch text of `apply_patch` contains `git reset --hard` as file
/// CONTENT (a context line of a script). Feeding it to the shell guard
/// would block a harmless edit.
#[test]
fn apply_patch_text_never_reaches_the_shell_guard() {
    let (out, rec) = run("codex/apply-patch.json", "codex");
    assert_eq!(out.code, 0);
    assert!(out.stderr.is_empty(), "no block message: {}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::Allow);
    assert!(!rec.input.contains("git reset"), "{}", rec.input);
}

#[test]
fn unknown_tools_are_allowed_and_recorded_as_not_guarded() {
    for (name, agent, tool) in [
        ("claude/webfetch.json", "claude", "WebFetch"),
        ("codex/mcp-tool.json", "codex", "mcp__docs__search"),
        ("gemini/web-fetch.json", "gemini", "web_fetch"),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, 0, "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        assert_eq!(rec.decision, DecisionKind::Allow, "{name}");
        assert_eq!(rec.tool, tool, "{name}");
        assert_eq!(rec.reason.as_deref(), Some("tool not guarded"), "{name}");
    }
}

#[test]
fn malformed_fixtures_fail_open_with_error_allowed() {
    for name in [
        "malformed/truncated.json",
        "malformed/not-json.txt",
        "malformed/bash-no-command.json",
    ] {
        let (out, rec) = run(name, "claude");
        assert_eq!(out.code, 0, "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        assert_eq!(rec.decision, DecisionKind::ErrorAllowed, "{name}");
        assert!(rec.reason.as_deref().unwrap().contains("payload"), "{name}");
    }
}

/// Review Focus 1: a `Write` of a file larger than the 256 KiB payload cap
/// is an ordinary file-tool call, not a guard failure.
#[test]
fn large_write_is_recorded_as_allow_with_its_path() {
    let payload = serde_json::json!({
        "session_id": "c-1",
        "cwd": "/home/u/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/home/u/app/big.txt", "content": "x".repeat(600 * 1024) }
    })
    .to_string();
    let dir = tempfile::tempdir().unwrap();
    let out = check_bytes(dir.path(), "claude", payload.as_bytes());
    assert_eq!(out.code, 0);
    let rec = &read_all(dir.path()).records[0];
    assert_eq!(rec.decision, DecisionKind::Allow);
    assert_eq!(rec.tool, "Write");
    assert_eq!(rec.input, "/home/u/app/big.txt");
    assert_eq!(rec.session.as_deref(), Some("c-1"));
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p saiife --test check_tools`
Expected: FAIL — `file_tool_fixtures_are_recorded_with_their_paths_and_never_judged` (decision `ErrorAllowed`, "no command found"), `apply_patch_text_never_reaches_the_shell_guard` (exit 2, `BLOCKED by core.git`), `unknown_tools_are_allowed_and_recorded_as_not_guarded`, `large_write_is_recorded_as_allow_with_its_path`. The shell and malformed tests already pass.

- [ ] **Step 4: Implement**

Replace the whole of `crates/cli/src/check.rs` with:

```rust
//! `saiife check`: hook mode. Read the agent's pre-tool JSON on stdin, decide,
//! audit, and answer in the agent's contract. FAIL OPEN on every error.

use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::ExitCode;

use saiife_audit::{store, DecisionKind, NewRecord, Record};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{
    classify, context_from_hook_json_bounded, HookContext, PayloadError, ToolCall,
    MAX_PAYLOAD_BYTES,
};

use crate::warn;

/// Payloads up to this size are still parsed. File tools (a `Write` of a big
/// file) are handled normally; a shell command above `MAX_PAYLOAD_BYTES` is
/// not judged but its command goes into the audit record. Bounded so parsing
/// stays cheap.
const PARSE_MAX_BYTES: usize = 4 * MAX_PAYLOAD_BYTES;

pub fn run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        let audit = Audit::new(agent, HookContext::default());
        warn("could not read hook payload; failing open (allow)");
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some("could not read hook payload"),
        );
        return allow();
    }
    let audit = Audit::new(agent, context_from_hook_json_bounded(&buf, PARSE_MAX_BYTES));
    match classify(&buf, PARSE_MAX_BYTES) {
        Ok(ToolCall::Shell { command }) if buf.len() > MAX_PAYLOAD_BYTES => {
            fail_open(&audit, &command, &PayloadError::TooLarge)
        }
        Ok(ToolCall::Shell { command }) => {
            decide(&audit, &command, hook_exit, |c| engine.evaluate(c))
        }
        Ok(ToolCall::File { paths, .. }) => {
            // Path rules arrive in plan 3; until then file tools are
            // recorded, never judged.
            audit.write(&paths.join("\n"), DecisionKind::Allow, None, None);
            allow()
        }
        Ok(ToolCall::Other { .. }) => {
            audit.write("", DecisionKind::Allow, None, Some("tool not guarded"));
            allow()
        }
        Err(e) => fail_open(&audit, "", &e),
    }
}

/// The payload could not be judged: allow, and record why.
fn fail_open(audit: &Audit, input: &str, e: &PayloadError) -> ExitCode {
    warn(&format!(
        "hook payload not usable ({e}); failing open (allow)"
    ));
    audit.write(
        input,
        DecisionKind::ErrorAllowed,
        None,
        Some(&format!("hook payload not usable: {e}")),
    );
    allow()
}

/// Judge `command` with `evaluate`, audit the decision and answer the hook.
/// Split out so the crash path can be tested with a panicking evaluator.
fn decide(
    audit: &Audit,
    command: &str,
    hook_exit: bool,
    evaluate: impl FnOnce(&str) -> Decision,
) -> ExitCode {
    // A panicking engine must not turn into a non-zero exit the agent may
    // read as "block" or as a hook error: fail open, and say so in the log.
    // (Release keeps the default panic=unwind, so this is reachable.)
    let decision = match std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(command))) {
        Ok(d) => d,
        Err(_) => {
            warn("guard crashed; failing open (allow)");
            audit.write(
                command,
                DecisionKind::ErrorAllowed,
                None,
                Some("guard crashed"),
            );
            return allow();
        }
    };
    match &decision {
        Decision::Deny {
            pack,
            pattern,
            reason,
            ..
        } => audit.write(
            command,
            DecisionKind::Deny,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace:
                AllowTrace::AllowRule {
                    pack,
                    pattern,
                    reason,
                },
        } => audit.write(
            command,
            DecisionKind::Allow,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace: AllowTrace::NoMatch,
        } => audit.write(command, DecisionKind::Allow, None, None),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        } => audit.write(
            command,
            DecisionKind::ErrorAllowed,
            None,
            Some("guard exceeded its latency budget"),
        ),
    }

    match decision {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
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
        Decision::Allow { .. } => allow(),
    }
}

/// Everything about this hook call except the decision, so each exit path
/// writes a complete record with one call.
struct Audit {
    dir: Option<PathBuf>,
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
        let dir = store::default_dir();
        if dir.is_none() {
            warn("could not determine the audit directory; this decision is not audited");
        }
        Self {
            dir,
            agent: agent.to_string(),
            ctx,
            project,
        }
    }

    /// Best-effort: a failed write is reported on stderr and otherwise ignored.
    fn write(
        &self,
        input: &str,
        decision: DecisionKind,
        rule: Option<(&String, &String)>,
        reason: Option<&str>,
    ) {
        let Some(dir) = &self.dir else {
            return;
        };
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
        if let Err(e) = store::append(dir, &rec) {
            warn(&format!("audit write failed ({e}); decision unaffected"));
        }
    }
}

/// Allow = exit 0 with NOTHING on stdout, for every agent and both modes.
/// An explicit `permissionDecision: "allow"` would skip Claude Code's own
/// permission prompts, and Codex treats an allow without `updatedInput` as a
/// failed hook. Silence means "no objection": the agent's normal flow runs.
fn allow() -> ExitCode {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_in(dir: &std::path::Path) -> Audit {
        Audit {
            dir: Some(dir.to_path_buf()),
            agent: "claude".into(),
            ctx: HookContext::default(),
            project: "/p".into(),
        }
    }

    #[test]
    fn engine_panic_fails_open_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "rm -rf /tmp/x", true, |_| {
            panic!("engine bug")
        });
        assert_eq!(code, ExitCode::SUCCESS);
        let recs = store::read_all(dir.path()).records;
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, DecisionKind::ErrorAllowed);
        assert_eq!(recs[0].input, "rm -rf /tmp/x");
        assert_eq!(recs[0].reason.as_deref(), Some("guard crashed"));
    }

    #[test]
    fn normal_decision_still_flows_through_decide() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "ls", true, |_| Decision::Allow {
            trace: AllowTrace::NoMatch,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            store::read_all(dir.path()).records[0].decision,
            DecisionKind::Allow
        );
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p saiife`
Expected: PASS — including plan 1's `oversize_payload_is_error_allowed` (a 300 KiB shell command is still `error_allowed` with its command recorded) and `garbage_payload_is_audited_as_error_allowed`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/cli/src/check.rs crates/cli/tests/check_tools.rs crates/cli/tests/fixtures
git commit -m "feat(check): judge shell tools, record file tools by path, never feed apply_patch to the guard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `saiife-agents` crate — agent names, PATH detection, fingerprints, safe writes

**Files:**
- Create: `crates/agents/Cargo.toml`, `crates/agents/src/lib.rs`, `crates/agents/src/detect.rs`, `crates/agents/src/fingerprint.rs`, `crates/agents/src/fsutil.rs`
- Modify: `Cargo.lock` (new deps `sha2`, `serde_json` feature `preserve_order`)

**Interfaces:**
- Consumes: nothing from other saiife crates (spec §4).
- Produces (`saiife_agents`):
  - `enum Agent { Claude, Codex, Gemini }` (derives `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash`) with `const ALL: [Agent; 3]`, `fn name(self) -> &'static str` (`"claude"|"codex"|"gemini"`), `fn from_name(s: &str) -> Option<Agent>`, `fn binary(self) -> &'static str`, `fn label(self) -> &'static str` (`"Claude Code"|"Codex"|"Gemini CLI"`), `fn hook_command(self) -> String` (`"saiife check --hook-exit --agent <name>"`)
  - `enum Change { Unchanged, Updated, Created { created_dirs: Vec<String> }, Deleted }` (derives `Debug, Clone, PartialEq, Eq`)
  - `enum AgentError { Io { path: PathBuf, source: std::io::Error }, Parse { path: PathBuf, format: &'static str, detail: String }, Layout { path: PathBuf, detail: String } }` (`thiserror`; `Parse`/`Layout` messages end in "saiife did not change it")
  - `fn is_saiife_command(command: &str) -> bool`
  - `detect::{find_in_path(name: &str, path: &OsStr) -> Option<PathBuf>, which(name: &str) -> Option<PathBuf>, detect_agents() -> Vec<Agent>}`
  - `fingerprint::{sha256_hex(bytes: &[u8]) -> String, canonical_json(v: &serde_json::Value) -> String, of_json(v: &serde_json::Value) -> String}`
  - `fsutil::{read_optional(path: &Path) -> Result<Option<String>, AgentError>, write(project: &Path, rel: &str, contents: &str) -> Result<Change, AgentError>, remove(project: &Path, rel: &str) -> Result<(), AgentError>}`, `pub(crate) fn io_err(path: &Path) -> impl FnOnce(io::Error) -> AgentError + '_`

- [ ] **Step 1: Create the crate manifest**

Create `crates/agents/Cargo.toml`:

```toml
[package]
name = "saiife-agents"
description = "Agent hook installers, project config and integrity records for saiife."
edition.workspace = true
version.workspace = true
license.workspace = true
repository.workspace = true

[lib]
name = "saiife_agents"
path = "src/lib.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
# preserve_order: settings files keep the user's key order when rewritten.
serde_json = { version = "1", features = ["preserve_order"] }
toml_edit = "0.22.27"
sha2 = "0.10.9"
dirs = "5"
thiserror = "1"
tempfile = "3"
```

`tempfile` is a normal dependency: `fsutil::write` uses it for atomic writes. The workspace picks the crate up through `members = ["crates/*"]`.

- [ ] **Step 2: Write the failing tests**

Create `crates/agents/src/lib.rs` with the module list and its tests only:

```rust
//! saiife-agents (tests first; the implementation is added in Step 4).

#![forbid(unsafe_code)]

pub mod detect;
pub mod fingerprint;
pub mod fsutil;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for a in Agent::ALL {
            assert_eq!(Agent::from_name(a.name()), Some(a));
        }
        assert_eq!(Agent::from_name("cursor"), None);
    }

    #[test]
    fn hook_commands_use_hook_exit() {
        assert_eq!(
            Agent::Claude.hook_command(),
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(
            Agent::Gemini.hook_command(),
            "saiife check --hook-exit --agent gemini"
        );
    }

    #[test]
    fn recognizes_saiife_commands_only() {
        assert!(is_saiife_command("saiife check --hook-exit --agent claude"));
        assert!(is_saiife_command(
            "/usr/local/bin/saiife check --agent codex"
        ));
        assert!(is_saiife_command("  saiife   check"));
        assert!(!is_saiife_command("saiife status"));
        assert!(!is_saiife_command("my-saiife check"));
        assert!(!is_saiife_command("echo saiife check"));
        assert!(!is_saiife_command(""));
    }
}
```

Create `crates/agents/src/detect.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn exe(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn finds_first_match_in_path_order() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        exe(b.path(), "claude");
        let want = exe(a.path(), "claude");
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        assert_eq!(find_in_path("claude", &path), Some(want));
    }

    #[cfg(unix)]
    #[test]
    fn skips_non_executable_files_and_directories() {
        let a = tempfile::tempdir().unwrap();
        fs::write(a.path().join("codex"), "not executable").unwrap();
        fs::create_dir(a.path().join("gemini")).unwrap();
        let path = std::env::join_paths([a.path()]).unwrap();
        assert_eq!(find_in_path("codex", &path), None);
        assert_eq!(find_in_path("gemini", &path), None);
    }

    #[test]
    fn empty_path_finds_nothing() {
        assert_eq!(find_in_path("claude", OsStr::new("")), None);
    }
}
```

Create `crates/agents/src/fingerprint.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_digest() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn key_order_does_not_change_the_fingerprint() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":[1,"x"],"x":null}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[1,"x"]},"b":1}"#).unwrap();
        assert_eq!(of_json(&a), of_json(&b));
        assert_eq!(canonical_json(&a), r#"{"a":{"x":null,"y":[1,"x"]},"b":1}"#);
    }

    #[test]
    fn any_value_change_does() {
        assert_ne!(
            of_json(&json!({"timeout": 10})),
            of_json(&json!({"timeout": 11}))
        );
        assert_ne!(
            of_json(&json!({"m": "Bash"})),
            of_json(&json!({"m": "Bash|Read"}))
        );
    }
}
```

Create `crates/agents/src/fsutil.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_file_and_reports_new_dirs() {
        let p = tempfile::tempdir().unwrap();
        let c = write(p.path(), ".claude/settings.json", "{}\n").unwrap();
        assert_eq!(
            c,
            Change::Created {
                created_dirs: vec![".claude".into()]
            }
        );
        assert_eq!(
            fs::read_to_string(p.path().join(".claude/settings.json")).unwrap(),
            "{}\n"
        );
        let c = write(p.path(), ".claude/settings.json", "{\"a\":1}\n").unwrap();
        assert_eq!(c, Change::Updated);
    }

    #[cfg(unix)]
    #[test]
    fn keeps_permissions_and_follows_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let p = tempfile::tempdir().unwrap();
        let real = p.path().join("real.json");
        fs::write(&real, "{}").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir(p.path().join(".gemini")).unwrap();
        std::os::unix::fs::symlink(&real, p.path().join(".gemini/settings.json")).unwrap();
        write(p.path(), ".gemini/settings.json", "{\"x\":1}").unwrap();
        assert!(fs::symlink_metadata(p.path().join(".gemini/settings.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&real).unwrap(), "{\"x\":1}");
        assert_eq!(
            fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn read_optional_and_remove_tolerate_missing_files() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(read_optional(&p.path().join("nope")).unwrap(), None);
        remove(p.path(), "nope").unwrap();
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p saiife-agents`
Expected: FAIL to compile — `cannot find type 'Agent'`, `cannot find function 'find_in_path'`, `cannot find function 'sha256_hex'`, `cannot find function 'write'`.

- [ ] **Step 4: Implement**

Replace the whole of `crates/agents/src/lib.rs` with:

```rust
//! saiife-agents: everything saiife writes into a project, and how it checks
//! that it is still there.
//!
//! - one module per agent (`claude`, `codex`, `gemini`): install the guard
//!   hook into the project's config file, remove only saiife's own entries,
//!   and fingerprint the entry for tamper detection (spec §5.2, §7.5);
//! - `config`: the project config `.saiife/config.toml` (spec §5.1);
//! - `integrity`: the per-project integrity record outside the project.
//!
//! This crate never depends on the guard or the audit crate (spec §4).

#![forbid(unsafe_code)]

pub mod detect;
pub mod fingerprint;
pub mod fsutil;

use std::path::PathBuf;

/// The agents saiife v1 supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Claude,
    Codex,
    Gemini,
}

impl Agent {
    pub const ALL: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::Gemini];

    /// Short name used on the command line, in hook commands and in the
    /// audit log.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Gemini => "gemini",
        }
    }

    pub fn from_name(s: &str) -> Option<Agent> {
        Agent::ALL.into_iter().find(|a| a.name() == s)
    }

    /// The executable looked up on `PATH` by `detect`.
    pub fn binary(self) -> &'static str {
        self.name()
    }

    /// Display name for messages.
    pub fn label(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
            Agent::Gemini => "Gemini CLI",
        }
    }

    /// The exact hook command written for this agent. Resolved via `PATH`
    /// so an upgrade never leaves a stale absolute path (spec §5.2).
    pub fn hook_command(self) -> String {
        format!("saiife check --hook-exit --agent {}", self.name())
    }

}

/// What an install or remove did to the config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The file already had exactly the wanted content; nothing was written.
    Unchanged,
    /// The file existed and was rewritten.
    Updated,
    /// The file did not exist and was created (`created_dirs`: directories
    /// created for it, relative to the project, outermost first).
    Created { created_dirs: Vec<String> },
    /// saiife's entries were removed and nothing else was left, so the file
    /// was deleted (only ever for a file the caller says saiife created).
    Deleted,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid {format} ({detail}); saiife did not change it — fix or remove it, then run `saiife init` again")]
    Parse {
        path: PathBuf,
        format: &'static str,
        detail: String,
    },
    #[error("{path}: {detail}; saiife did not change it")]
    Layout { path: PathBuf, detail: String },
}

/// True when `command` runs `saiife check` (any path to the binary). This is
/// how saiife recognizes its own hook entries.
pub fn is_saiife_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let (Some(bin), Some(sub)) = (words.next(), words.next()) else {
        return false;
    };
    let base = bin.rsplit('/').next().unwrap_or(bin);
    base == "saiife" && sub == "check"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for a in Agent::ALL {
            assert_eq!(Agent::from_name(a.name()), Some(a));
        }
        assert_eq!(Agent::from_name("cursor"), None);
    }

    #[test]
    fn hook_commands_use_hook_exit() {
        assert_eq!(
            Agent::Claude.hook_command(),
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(
            Agent::Gemini.hook_command(),
            "saiife check --hook-exit --agent gemini"
        );
    }

    #[test]
    fn recognizes_saiife_commands_only() {
        assert!(is_saiife_command("saiife check --hook-exit --agent claude"));
        assert!(is_saiife_command(
            "/usr/local/bin/saiife check --agent codex"
        ));
        assert!(is_saiife_command("  saiife   check"));
        assert!(!is_saiife_command("saiife status"));
        assert!(!is_saiife_command("my-saiife check"));
        assert!(!is_saiife_command("echo saiife check"));
        assert!(!is_saiife_command(""));
    }
}
```

Add the implementation to the top of `crates/agents/src/detect.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! Find executables on `PATH` (agents, and the `saiife` binary itself).

use std::ffi::OsStr;
use std::path::PathBuf;

use crate::Agent;

/// The first executable regular file called `name` in the directories of
/// `path` (a `PATH`-style list). Empty entries are skipped.
pub fn find_in_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(name))
        .find(|p| is_executable_file(p))
}

/// `find_in_path` over this process's `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    find_in_path(name, &std::env::var_os("PATH")?)
}

/// Agents whose binary is on this process's `PATH`, in `Agent::ALL` order.
pub fn detect_agents() -> Vec<Agent> {
    Agent::ALL
        .into_iter()
        .filter(|a| which(a.binary()).is_some())
        .collect()
}

fn is_executable_file(p: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

```

Add the implementation to the top of `crates/agents/src/fingerprint.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! SHA-256 fingerprints for tamper detection (spec §7.5).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// `v` as compact JSON with every object's keys sorted, so the same entry
/// always yields the same text whatever order its keys were written in.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

/// Fingerprint of a hook entry given as JSON.
pub fn of_json(v: &Value) -> String {
    sha256_hex(canonical_json(v).as_bytes())
}

```

Add the implementation to the top of `crates/agents/src/fsutil.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! File helpers for writing into a user's project: never leave a half-written
//! settings file behind, keep the file's permissions, and write through a
//! symlinked settings file instead of replacing the link.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::{AgentError, Change};

pub(crate) fn io_err(path: &Path) -> impl FnOnce(io::Error) -> AgentError + '_ {
    move |source| AgentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The file's text, or `None` if it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<String>, AgentError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// Write `contents` to `<project>/<rel>` atomically (temp file in the same
/// directory, then rename). An existing file keeps its permissions; a
/// symlink is followed and its target replaced. Missing directories are
/// created and reported in `Change::Created`.
pub fn write(project: &Path, rel: &str, contents: &str) -> Result<Change, AgentError> {
    let path = project.join(rel);
    let existed = fs::symlink_metadata(&path).is_ok();
    let target = if existed {
        fs::canonicalize(&path).map_err(io_err(&path))?
    } else {
        path.clone()
    };
    let parent = target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let created_dirs = if existed {
        Vec::new()
    } else {
        create_dirs(project, &parent)?
    };
    let mut tmp = tempfile::NamedTempFile::new_in(&parent).map_err(io_err(&parent))?;
    tmp.write_all(contents.as_bytes())
        .map_err(io_err(&target))?;
    let perms = match fs::metadata(&target) {
        Ok(m) => m.permissions(),
        Err(_) => default_permissions(),
    };
    fs::set_permissions(tmp.path(), perms).map_err(io_err(&target))?;
    tmp.persist(&target).map_err(|e| io_err(&target)(e.error))?;
    Ok(if existed {
        Change::Updated
    } else {
        Change::Created { created_dirs }
    })
}

/// Delete `<project>/<rel>`; a missing file is fine.
pub fn remove(project: &Path, rel: &str) -> Result<(), AgentError> {
    let path = project.join(rel);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(&path)(e)),
    }
}

/// Create `dir` and its missing ancestors; return the ones created, relative
/// to `project`, outermost first.
fn create_dirs(project: &Path, dir: &Path) -> Result<Vec<String>, AgentError> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.exists() {
            break;
        }
        missing.push(d.to_path_buf());
        cur = d.parent();
    }
    fs::create_dir_all(dir).map_err(io_err(dir))?;
    missing.reverse();
    Ok(missing
        .iter()
        .filter_map(|d| d.strip_prefix(project).ok())
        .map(|d| d.to_string_lossy().into_owned())
        .collect())
}

fn default_permissions() -> fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o644)
    }
    #[cfg(not(unix))]
    {
        fs::metadata(".").unwrap().permissions()
    }
}

```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p saiife-agents`
Expected: PASS. Check the lock file picked the planned versions: `grep -A1 -E '^name = "(sha2|toml_edit)"' Cargo.lock` shows `0.10.9` and `0.22.27`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/agents Cargo.lock
git commit -m "feat(agents): new crate with agent names, PATH detection, fingerprints and atomic writes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Project config `.saiife/config.toml`, and `check` loads the project's packs

**Files:**
- Create: `crates/agents/src/config.rs`, `crates/cli/src/project.rs`
- Modify: `crates/agents/src/lib.rs` (module), `crates/cli/Cargo.toml` (dep), `crates/cli/src/check.rs`, `crates/cli/src/main.rs`
- Test: `crates/cli/tests/check_project.rs`

**Interfaces:**
- Consumes: `fsutil::{read_optional, write, io_err}`, `Change`, `AgentError` (Task 4); `saiifeguard::{Pack, profile::select_active, engine::Engine}`.
- Produces:
  - `saiife_agents::config::{CONFIG_REL: &str = ".saiife/config.toml", ProjectConfig { version: i64, packs: Vec<String>, locked: bool }, find_project_root(start: &Path) -> Option<PathBuf>, load(project: &Path) -> Result<ProjectConfig, AgentError>, ensure(project: &Path, packs: &[String]) -> Result<Change, AgentError>}`
  - `crate::project::{ProjectPacks { root: Option<PathBuf>, enabled: Vec<String>, warnings: Vec<String> }, project_packs(start: &Path, known: &[Pack]) -> ProjectPacks}` (cli)
  - `check::run(packs: Vec<Pack>, cli_packs: &[String], hook_exit: bool, agent: &str) -> ExitCode` (new signature)

- [ ] **Step 1: Write the failing tests**

In `crates/agents/src/lib.rs`, declare the module — replace:

```rust
pub mod detect;
```

with:

```rust
pub mod config;
pub mod detect;
```

Create `crates/agents/src/config.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn new_file_lists_packs_and_reserves_locked() {
        let p = tempfile::tempdir().unwrap();
        let c = ensure(p.path(), &ids(&["core.filesystem", "core.git"])).unwrap();
        assert_eq!(
            c,
            Change::Created {
                created_dirs: vec![".saiife".into()]
            }
        );
        let text = fs::read_to_string(p.path().join(CONFIG_REL)).unwrap();
        assert!(text.contains("packs = [\"core.filesystem\", \"core.git\"]\n"));
        assert!(text.contains("locked = false\n"));
        assert_eq!(
            load(p.path()).unwrap(),
            ProjectConfig {
                version: 1,
                packs: ids(&["core.filesystem", "core.git"]),
                locked: false
            }
        );
    }

    /// Review Focus 5: re-running init after hand edits keeps them.
    #[test]
    fn existing_file_keeps_user_edits_and_only_gains_missing_ids() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        let mine = "# team config\nversion = 1\npacks = [\"core.git\", \"db.mysql\"] # mysql for CI\nlocked = false\n";
        fs::write(p.path().join(CONFIG_REL), mine).unwrap();
        assert_eq!(
            ensure(p.path(), &ids(&["db.mysql"])).unwrap(),
            Change::Unchanged
        );
        assert_eq!(fs::read_to_string(p.path().join(CONFIG_REL)).unwrap(), mine);
        assert_eq!(
            ensure(p.path(), &ids(&["db.postgres"])).unwrap(),
            Change::Updated
        );
        let text = fs::read_to_string(p.path().join(CONFIG_REL)).unwrap();
        assert!(text.starts_with("# team config\n"), "{text}");
        assert!(text.contains("# mysql for CI"), "{text}");
        assert_eq!(
            load(p.path()).unwrap().packs,
            ids(&["core.git", "db.mysql", "db.postgres"])
        );
    }

    #[test]
    fn locked_is_read_but_reserved() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::write(p.path().join(CONFIG_REL), "locked = true\n").unwrap();
        let c = load(p.path()).unwrap();
        assert!(c.locked);
        assert_eq!(c.version, 1);
        assert!(c.packs.is_empty());
    }

    #[test]
    fn bad_files_are_errors_not_rewrites() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        for bad in ["packs = \"db.mysql\"\n", "packs = [\n"] {
            fs::write(p.path().join(CONFIG_REL), bad).unwrap();
            assert!(load(p.path()).is_err(), "{bad:?}");
            assert!(ensure(p.path(), &ids(&["db.postgres"])).is_err(), "{bad:?}");
            assert_eq!(fs::read_to_string(p.path().join(CONFIG_REL)).unwrap(), bad);
        }
    }

    #[test]
    fn root_is_found_from_a_subdirectory() {
        let p = tempfile::tempdir().unwrap();
        ensure(p.path(), &ids(&["core.git"])).unwrap();
        let deep = p.path().join("src/nested/dir");
        assert_eq!(find_project_root(&deep), Some(p.path().to_path_buf()));
        assert_eq!(find_project_root(p.path()), Some(p.path().to_path_buf()));
        let other = tempfile::tempdir().unwrap();
        assert_eq!(find_project_root(other.path()), None);
    }
}
```

In `crates/cli/Cargo.toml`, add the dependency — replace:

```toml
saiife-audit = { path = "../audit" }
```

with:

```toml
saiife-audit = { path = "../audit" }
saiife-agents = { path = "../agents" }
```

Create `crates/cli/tests/check_project.rs`:

```rust
//! `saiife check` loads the opt-in packs of the project the agent works in:
//! the nearest `.saiife/config.toml` at or above the payload's `cwd`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::{read_all, DIR_ENV};
use saiife_audit::DecisionKind;

const DROP: &str = "psql -c 'DROP DATABASE prod'";

fn check(audit: &Path, cwd: &Path, cmd: &str) -> (i32, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .env(DIR_ENV, audit)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn project(packs: &str) -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(p.path().join(".saiife")).unwrap();
    std::fs::create_dir_all(p.path().join("src/deep")).unwrap();
    std::fs::write(
        p.path().join(".saiife/config.toml"),
        format!("version = 1\npacks = [{packs}]\n"),
    )
    .unwrap();
    p
}

#[test]
fn opt_in_pack_from_project_config_applies_in_subdirectories() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"core.filesystem\", \"core.git\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), &p.path().join("src/deep"), DROP);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("BLOCKED by db.postgres"), "{stderr}");
    let rec = &read_all(audit.path()).records[0];
    assert_eq!(rec.decision, DecisionKind::Deny);
    assert_eq!(rec.pack.as_deref(), Some("db.postgres"));
}

#[test]
fn outside_the_project_only_default_packs_apply() {
    let audit = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let (code, _) = check(audit.path(), elsewhere.path(), DROP);
    assert_eq!(code, 0);
}

#[test]
fn unknown_pack_ids_are_warned_about_and_ignored() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.oracle\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 2, "known packs still apply");
    assert!(stderr.contains("unknown pack \"db.oracle\""), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs always apply");
}

#[test]
fn broken_project_config_fails_open_to_default_packs() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.postgres\"");
    std::fs::write(p.path().join(".saiife/config.toml"), "packs = [\n").unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still apply");
    assert!(stderr.contains("default packs only"), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-agents config && cargo test -p saiife --test check_project`
Expected: the first command FAILS to compile (`cannot find function 'ensure'`, `cannot find function 'load'`…). After Step 3's `config.rs` exists, `check_project` still FAILS: `opt_in_pack_from_project_config_applies_in_subdirectories` and `unknown_pack_ids_are_warned_about_and_ignored` exit 0 instead of 2, `broken_project_config_fails_open_to_default_packs` finds no warning on stderr.

- [ ] **Step 3: Implement the config module**

Add the implementation to the top of `crates/agents/src/config.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

````rust
//! The project config `.saiife/config.toml` (spec §5.1).
//!
//! ```toml
//! version = 1
//! packs = ["core.filesystem", "core.git", "db.postgres"]
//! locked = false   # reserved for the v2 admin lock; v1 reads and ignores it
//! ```
//!
//! Default-on packs are always active; `packs` adds opt-in ones. Edited with
//! `toml_edit`, so a user's comments and edits survive `saiife init`.

use std::path::{Path, PathBuf};

use toml_edit::{Array, DocumentMut, Item};

use crate::{fsutil, AgentError, Change};

pub const CONFIG_REL: &str = ".saiife/config.toml";

/// What saiife reads from the project config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectConfig {
    /// `version`; 1 when absent.
    pub version: i64,
    /// `packs`, in file order. Ids are not checked here.
    pub packs: Vec<String>,
    /// `locked`: reserved (spec §9.1). Read so the field is known; v1
    /// ignores its value.
    pub locked: bool,
}

/// The nearest directory at or above `start` that contains
/// `.saiife/config.toml`.
pub fn find_project_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| d.join(CONFIG_REL).is_file())
        .map(Path::to_path_buf)
}

/// Read `<project>/.saiife/config.toml`.
pub fn load(project: &Path) -> Result<ProjectConfig, AgentError> {
    let path = project.join(CONFIG_REL);
    let text = std::fs::read_to_string(&path).map_err(fsutil::io_err(&path))?;
    let doc = parse(&path, &text)?;
    let packs = match doc.get("packs") {
        None => Vec::new(),
        Some(item) => item
            .as_array()
            .ok_or_else(|| layout(&path, "`packs` is not a list"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    };
    Ok(ProjectConfig {
        version: doc.get("version").and_then(Item::as_integer).unwrap_or(1),
        packs,
        locked: doc.get("locked").and_then(Item::as_bool).unwrap_or(false),
    })
}

/// Make sure the config exists and lists `packs`. A missing file is created
/// listing exactly `packs`; an existing file only gets the ids it lacks
/// appended, keeping everything else as the user wrote it.
pub fn ensure(project: &Path, packs: &[String]) -> Result<Change, AgentError> {
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return fsutil::write(project, CONFIG_REL, &new_file(packs));
    };
    let mut doc = parse(&path, &text)?;
    let list = doc
        .entry("packs")
        .or_insert_with(|| Item::Value(Array::new().into()))
        .as_array_mut()
        .ok_or_else(|| layout(&path, "`packs` is not a list"))?;
    let mut added = false;
    for id in packs {
        if !list.iter().any(|v| v.as_str() == Some(id)) {
            list.push(id.as_str());
            added = true;
        }
    }
    if !added {
        return Ok(Change::Unchanged);
    }
    fsutil::write(project, CONFIG_REL, &doc.to_string())
}

fn new_file(packs: &[String]) -> String {
    let list: Vec<String> = packs.iter().map(|p| format!("{p:?}")).collect();
    format!(
        "# saiife project config. Default-on packs are always active;\n\
         # list opt-in packs here to turn them on (`saiife packs` lists them).\n\
         version = 1\n\
         packs = [{}]\n\
         # Reserved for the admin lock (v2); saiife v1 reads and ignores it.\n\
         locked = false\n",
        list.join(", ")
    )
}

fn parse(path: &Path, text: &str) -> Result<DocumentMut, AgentError> {
    text.parse::<DocumentMut>().map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "TOML",
        detail: e.to_string().trim().replace('\n', " "),
    })
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

````

Run: `cargo test -p saiife-agents config`
Expected: PASS.

- [ ] **Step 4: Implement project packs and wire them into `check`**

Create `crates/cli/src/project.rs`:

```rust
//! Which packs a project turns on (spec §5.1, §9.1 precedence): default-on
//! packs always, plus the opt-in packs listed in the nearest
//! `.saiife/config.toml`, plus any `--pack` given on the command line.

use std::path::{Path, PathBuf};

use saiife_agents::config::{self, CONFIG_REL};
use saiifeguard::Pack;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProjectPacks {
    /// Directory holding `.saiife/config.toml`, if one was found.
    pub root: Option<PathBuf>,
    /// Known pack ids from the config, in file order.
    pub enabled: Vec<String>,
    /// Plain-language problems (unknown ids, unreadable config). Never fatal.
    pub warnings: Vec<String>,
}

/// Find the project config at or above `start` and read its packs. Unknown
/// pack ids are warned about and ignored.
pub fn project_packs(start: &Path, known: &[Pack]) -> ProjectPacks {
    let Some(root) = config::find_project_root(start) else {
        return ProjectPacks::default();
    };
    let mut out = ProjectPacks {
        root: Some(root.clone()),
        ..Default::default()
    };
    match config::load(&root) {
        Ok(cfg) => {
            for id in cfg.packs {
                if known.iter().any(|p| p.id == id) {
                    out.enabled.push(id);
                } else {
                    out.warnings.push(format!(
                        "unknown pack {id:?} in {}; ignored",
                        root.join(CONFIG_REL).display()
                    ));
                }
            }
        }
        Err(e) => out
            .warnings
            .push(format!("{e}; using the default packs only")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiifeguard::builtins::builtin_packs;

    #[test]
    fn reads_known_packs_and_warns_about_unknown_ones() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        std::fs::write(
            p.path().join(CONFIG_REL),
            "packs = [\"core.git\", \"db.postgres\", \"db.oracle\"]\n",
        )
        .unwrap();
        let got = project_packs(&p.path().join("src"), &known);
        assert_eq!(got.root.as_deref(), Some(p.path()));
        assert_eq!(got.enabled, ["core.git", "db.postgres"]);
        assert_eq!(got.warnings.len(), 1);
        assert!(got.warnings[0].contains("\"db.oracle\""));
    }

    #[test]
    fn no_config_means_defaults_only() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        assert_eq!(project_packs(p.path(), &known), ProjectPacks::default());
    }

    #[test]
    fn broken_config_is_a_warning() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        std::fs::write(p.path().join(CONFIG_REL), "packs = [\n").unwrap();
        let got = project_packs(p.path(), &known);
        assert!(got.enabled.is_empty());
        assert!(got.warnings[0].contains("default packs only"));
    }
}
```

In `crates/cli/src/check.rs`, extend the imports — replace:

```rust
use saiifeguard::engine::{AllowTrace, Decision, Engine};
```

with:

```rust
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::profile::select_active;
use saiifeguard::Pack;
```

and replace:

```rust
use crate::warn;
```

with:

```rust
use crate::project::project_packs;
use crate::warn;
```

Replace the signature of `run`:

```rust
pub fn run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode {
```

with:

```rust
/// `packs`: every built-in pack; `cli_packs`: `--pack` ids. The project's
/// own packs are added from the `.saiife/config.toml` at or above the
/// payload's `cwd`.
pub fn run(packs: Vec<Pack>, cli_packs: &[String], hook_exit: bool, agent: &str) -> ExitCode {
```

Build the engine only for shell calls — replace:

```rust
        Ok(ToolCall::Shell { command }) => {
            decide(
```

with:

```rust
        Ok(ToolCall::Shell { command }) => {
            let engine = engine_for(packs, cli_packs, audit.ctx.cwd.as_deref());
            decide(
```

Insert directly above `/// The payload could not be judged: allow, and record why.`:

```rust
/// The engine for this call: default-on packs, `--pack` ids, and the packs
/// of the project that `cwd` (or this process's directory) belongs to.
fn engine_for(packs: Vec<Pack>, cli_packs: &[String], cwd: Option<&str>) -> Engine {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    let project = project_packs(&start, &packs);
    for w in &project.warnings {
        warn(w);
    }
    let mut enabled = cli_packs.to_vec();
    enabled.extend(project.enabled);
    Engine::new(select_active(packs, &enabled))
}

```

In `crates/cli/src/main.rs`, replace:

```rust
mod audit_cmd;
mod check;
```

with:

```rust
mod audit_cmd;
mod check;
mod project;
```

and replace the engine construction and the first three match arms:

```rust
    let engine = Engine::new(select_active(packs, &cli.packs));

    match cli.command {
        Cmd::Test { command } => cmd_test(&engine, &command),
        Cmd::Explain { command } => cmd_explain(&engine, &command),
        Cmd::Check { hook_exit, agent } => check::run(&engine, hook_exit, &agent),
```

with:

```rust
    let engine = || Engine::new(select_active(packs.clone(), &cli.packs));

    match cli.command {
        Cmd::Test { command } => cmd_test(&engine(), &command),
        Cmd::Explain { command } => cmd_explain(&engine(), &command),
        Cmd::Check { hook_exit, agent } => check::run(packs, &cli.packs, hook_exit, &agent),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/agents/src/lib.rs crates/agents/src/config.rs crates/cli/Cargo.toml Cargo.lock crates/cli/src/project.rs crates/cli/src/check.rs crates/cli/src/main.rs crates/cli/tests/check_project.rs
git commit -m "feat: .saiife/config.toml; check loads the project's opt-in packs from the payload cwd

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Claude Code and Gemini CLI hook installers (JSON settings)

**Files:**
- Create: `crates/agents/src/json_hooks.rs`, `crates/agents/src/claude.rs`, `crates/agents/src/gemini.rs`
- Modify: `crates/agents/src/lib.rs` (modules, `HookBlocker`)

**Interfaces:**
- Consumes: `fingerprint::of_json`, `fsutil::{read_optional, write, remove}`, `is_saiife_command`, `Agent::hook_command`, `Change`, `AgentError` (Task 4).
- Produces:
  - `saiife_agents::HookBlocker { path: PathBuf, setting: &'static str }` (derives `Debug, Clone, PartialEq, Eq`)
  - `claude::{SETTINGS_REL = ".claude/settings.json", MATCHER = "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit", TIMEOUT_SECS: u64 = 10, NEXT_STEP, MANAGED_DIRS, install(project: &Path) -> Result<Change, AgentError>, remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError>, entries(project: &Path) -> Result<Vec<String>, AgentError>, expected_entry() -> String, blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker>, blockers_in(project: &Path, home: Option<&Path>, managed_dirs: &[PathBuf]) -> Vec<HookBlocker>}`
  - `gemini::{SETTINGS_REL = ".gemini/settings.json", MATCHER = "run_shell_command|read_file|read_many_files|list_directory|glob|grep_search|write_file|replace", TIMEOUT_MS: u64 = 10_000, NEXT_STEP, install, remove, entries, expected_entry}` (same signatures as claude)
  - private `json_hooks::JsonHooks { rel, event, group: fn() -> Value }` with `install`, `remove(project, delete_if_empty)`, `entries`, `expected`

- [ ] **Step 1: Write the failing tests**

In `crates/agents/src/lib.rs`, replace the module list:

```rust
pub mod config;
pub mod detect;
pub mod fingerprint;
pub mod fsutil;
```

with:

```rust
pub mod claude;
pub mod config;
pub mod detect;
pub mod fingerprint;
pub mod fsutil;
pub mod gemini;
mod json_hooks;
```

and insert directly above `/// What an install or remove did to the config file.`:

```rust
/// A setting that switches an agent's hooks off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBlocker {
    pub path: PathBuf,
    pub setting: &'static str,
}

```

Create `crates/agents/src/claude.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A user settings file with unrelated keys, a user hook in the same
    /// event, and another event — all must survive init and init --off.
    const USER_SETTINGS: &str = r#"{
  "model": "opus",
  "permissions": {
    "allow": [
      "Bash(npm run test:*)"
    ],
    "deny": []
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/lint-hook.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "notify-send done"
          }
        ]
      }
    ]
  },
  "env": {
    "FOO": "bar"
  }
}
"#;

    fn project_with(settings: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(p.path().join(SETTINGS_REL), settings).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(SETTINGS_REL)).unwrap()
    }

    #[test]
    fn install_adds_the_hook_and_keeps_user_settings() {
        let p = project_with(USER_SETTINGS);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let v: Value = serde_json::from_str(&read(p.path())).unwrap();
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "user group kept, saiife group added");
        assert_eq!(groups[0]["hooks"][0]["command"], "./scripts/lint-hook.sh");
        assert_eq!(groups[1]["matcher"], MATCHER);
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(groups[1]["hooks"][0]["timeout"], 10);
        assert!(groups[1]["hooks"][0].get("onFailure").is_none());
        assert_eq!(v["model"], "opus");
        assert_eq!(v["env"]["FOO"], "bar");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["model", "permissions", "hooks", "env"],
            "key order kept"
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    #[test]
    fn second_install_is_a_no_op() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
    }

    #[test]
    fn remove_restores_the_original_bytes() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_SETTINGS);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Unchanged);
    }

    #[test]
    fn four_space_indent_round_trips() {
        let four = "{\n    \"model\": \"opus\"\n}\n";
        let p = project_with(four);
        install(p.path()).unwrap();
        assert!(read(p.path()).contains("\n        \"PreToolUse\""));
        remove(p.path(), false).unwrap();
        assert_eq!(read(p.path()), four);
    }

    #[test]
    fn creates_the_file_and_deletes_it_again() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(
            install(p.path()).unwrap(),
            Change::Created {
                created_dirs: vec![".claude".into()]
            }
        );
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
        assert!(!p.path().join(SETTINGS_REL).exists());
    }

    #[test]
    fn a_changed_entry_is_replaced_not_duplicated() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let tampered = read(p.path()).replace(MATCHER, "NeverMatches");
        fs::write(p.path().join(SETTINGS_REL), tampered).unwrap();
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    /// Review Focus 2: a settings file that is not plain JSON is never
    /// rewritten.
    #[test]
    fn unparseable_settings_are_left_byte_identical() {
        for bad in [
            "{\n  // my comment\n  \"model\": \"opus\"\n}\n",
            "{\"model\": \"opus\",}\n",
            "[1, 2]\n",
            "{\"hooks\": {\"PreToolUse\": {\"matcher\": \"Bash\"}}}\n",
        ] {
            let p = project_with(bad);
            assert!(install(p.path()).is_err(), "{bad:?}");
            assert!(
                remove(p.path(), true).is_err() || read(p.path()) == bad,
                "{bad:?}"
            );
            assert_eq!(read(p.path()), bad, "{bad:?}");
        }
    }

    #[test]
    fn blockers_find_disable_all_hooks_and_managed_settings() {
        let p = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        assert!(
            blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]).is_empty()
        );

        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(
            p.path().join(".claude/settings.local.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        fs::create_dir(home.path().join(".claude")).unwrap();
        fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"disableAllHooks": false}"#,
        )
        .unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        fs::write(
            managed.path().join("managed-settings.d/10-lock.json"),
            r#"{"allowManagedHooksOnly": true}"#,
        )
        .unwrap();
        let found = blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]);
        let settings: Vec<&str> = found.iter().map(|b| b.setting).collect();
        assert_eq!(settings, ["disableAllHooks", "allowManagedHooksOnly"]);
        assert!(found[0].path.ends_with(".claude/settings.local.json"));
    }
}
```

Create `crates/agents/src/gemini.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const USER_SETTINGS: &str = r#"{
  "theme": "GitHub",
  "general": {
    "vimMode": true
  },
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "write_file",
        "hooks": [
          {
            "type": "command",
            "command": "./fmt-check.sh",
            "name": "fmt"
          }
        ]
      }
    ]
  }
}
"#;

    fn project_with(settings: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".gemini")).unwrap();
        fs::write(p.path().join(SETTINGS_REL), settings).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(SETTINGS_REL)).unwrap()
    }

    #[test]
    fn install_writes_named_handler_with_ms_timeout() {
        let p = project_with(USER_SETTINGS);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let v: Value = serde_json::from_str(&read(p.path())).unwrap();
        let groups = v["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0]["name"], "fmt");
        let h = &groups[1]["hooks"][0];
        assert_eq!(groups[1]["matcher"], MATCHER);
        assert_eq!(h["name"], "saiife");
        assert_eq!(h["command"], "saiife check --hook-exit --agent gemini");
        assert_eq!(h["timeout"], 10000);
        assert_eq!(v["general"]["vimMode"], true);
    }

    #[test]
    fn install_twice_then_remove_restores_bytes() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_SETTINGS);
    }

    /// A handler named "saiife" is ours even if its command was edited.
    #[test]
    fn handler_named_saiife_is_recognized_and_removed() {
        let edited = r#"{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "type": "command",
            "command": "true",
            "name": "saiife"
          }
        ]
      }
    ]
  }
}
"#;
        let p = project_with(edited);
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-agents`
Expected: FAIL to compile — `file not found for module 'json_hooks'`, then `cannot find function 'install'`, `cannot find value 'SETTINGS_REL'`.

- [ ] **Step 3: Implement the shared JSON editor**

Create `crates/agents/src/json_hooks.rs`:

```rust
//! Shared install/remove/fingerprint logic for agents whose hooks live in a
//! JSON settings file shaped like
//! `{"hooks": {"<Event>": [{"matcher": "…", "hooks": [{"type": "command", …}]}]}}`
//! (Claude Code `PreToolUse`, Gemini CLI `BeforeTool`).
//!
//! The file is parsed with `serde_json` (`preserve_order`), so every key the
//! user wrote stays where it was; it is written back with the indent the file
//! already used. Only handlers that run `saiife check` (or are named
//! `saiife`) are ever touched.

use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::{fingerprint, fsutil, is_saiife_command, AgentError, Change};

/// One agent's JSON hook layout and the entry saiife writes there.
pub(crate) struct JsonHooks {
    /// Settings file, relative to the project root.
    pub rel: &'static str,
    /// Hook event key under `hooks`.
    pub event: &'static str,
    /// The group `install` adds: `{"matcher": …, "hooks": [handler]}`.
    pub group: fn() -> Value,
}

impl JsonHooks {
    pub fn install(&self, project: &Path) -> Result<Change, AgentError> {
        let path = project.join(self.rel);
        let text = fsutil::read_optional(&path)?;
        let mut root = parse(&path, text.as_deref())?;
        let current = self.fingerprints(&path, &root)?;
        if current == [self.expected()] {
            return Ok(Change::Unchanged);
        }
        self.strip_ours(&path, &mut root)?;
        let groups = event_array(&path, &mut root, self.event)?;
        groups.push((self.group)());
        fsutil::write(project, self.rel, &render(&root, text.as_deref()))
    }

    /// Remove saiife's handlers. With `delete_if_empty`, a file left as `{}`
    /// is deleted (use only for a file saiife created).
    pub fn remove(&self, project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
        let path = project.join(self.rel);
        let Some(text) = fsutil::read_optional(&path)? else {
            return Ok(Change::Unchanged);
        };
        let mut root = parse(&path, Some(&text))?;
        if self.strip_ours(&path, &mut root)? == 0 {
            return Ok(Change::Unchanged);
        }
        prune(&mut root, self.event);
        if delete_if_empty && root.as_object().is_some_and(Map::is_empty) {
            fsutil::remove(project, self.rel)?;
            return Ok(Change::Deleted);
        }
        fsutil::write(project, self.rel, &render(&root, Some(&text)))
    }

    pub fn entries(&self, project: &Path) -> Result<Vec<String>, AgentError> {
        let path = project.join(self.rel);
        let Some(text) = fsutil::read_optional(&path)? else {
            return Ok(Vec::new());
        };
        let root = parse(&path, Some(&text))?;
        self.fingerprints(&path, &root)
    }

    pub fn expected(&self) -> String {
        let group = (self.group)();
        entry_fingerprint(group.get("matcher"), &group["hooks"][0])
    }

    /// Fingerprints of saiife's handlers, in file order.
    fn fingerprints(&self, path: &Path, root: &Value) -> Result<Vec<String>, AgentError> {
        let Some(groups) = root.get("hooks").and_then(|h| h.get(self.event)) else {
            return Ok(Vec::new());
        };
        let Some(groups) = groups.as_array() else {
            return Err(layout(
                path,
                &format!("\"hooks.{}\" is not a list", self.event),
            ));
        };
        let mut out = Vec::new();
        for g in groups {
            if let Some(handlers) = g.get("hooks").and_then(Value::as_array) {
                for h in handlers.iter().filter(|h| is_ours(h)) {
                    out.push(entry_fingerprint(g.get("matcher"), h));
                }
            }
        }
        Ok(out)
    }

    /// Remove every saiife handler; drop groups left with no handler. Returns
    /// how many handlers were removed.
    fn strip_ours(&self, path: &Path, root: &mut Value) -> Result<usize, AgentError> {
        let Some(groups) = root.get_mut("hooks").and_then(|h| h.get_mut(self.event)) else {
            return Ok(0);
        };
        let Some(groups) = groups.as_array_mut() else {
            return Err(layout(
                path,
                &format!("\"hooks.{}\" is not a list", self.event),
            ));
        };
        let mut removed = 0;
        groups.retain_mut(|g| {
            let Some(handlers) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = handlers.len();
            handlers.retain(|h| !is_ours(h));
            let gone = before - handlers.len();
            removed += gone;
            !(gone > 0 && handlers.is_empty())
        });
        Ok(removed)
    }
}

/// A saiife handler: runs `saiife check`, or is named `saiife` (Gemini).
fn is_ours(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(is_saiife_command)
        || handler.get("name").and_then(Value::as_str) == Some("saiife")
}

/// Matcher and handler together: changing either (e.g. narrowing the
/// matcher so the hook never fires) counts as tampering.
fn entry_fingerprint(matcher: Option<&Value>, handler: &Value) -> String {
    fingerprint::of_json(&serde_json::json!({
        "matcher": matcher.cloned().unwrap_or(Value::Null),
        "handler": handler,
    }))
}

fn parse(path: &Path, text: Option<&str>) -> Result<Value, AgentError> {
    let text = text.unwrap_or("");
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "JSON",
        detail: e.to_string(),
    })?;
    if !v.is_object() {
        return Err(layout(path, "the top level is not a JSON object"));
    }
    Ok(v)
}

/// `root.hooks.<event>`, created as needed.
fn event_array<'a>(
    path: &Path,
    root: &'a mut Value,
    event: &str,
) -> Result<&'a mut Vec<Value>, AgentError> {
    let obj = root.as_object_mut().expect("parse() checked the root");
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(hooks) = hooks.as_object_mut() else {
        return Err(layout(path, "\"hooks\" is not an object"));
    };
    let groups = hooks
        .entry(event)
        .or_insert_with(|| Value::Array(Vec::new()));
    groups
        .as_array_mut()
        .ok_or_else(|| layout(path, &format!("\"hooks.{event}\" is not a list")))
}

/// Drop `hooks.<event>` and then `hooks` if removing saiife left them empty.
fn prune(root: &mut Value, event: &str) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        if hooks
            .get(event)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            hooks.remove(event);
        }
        if hooks.is_empty() {
            obj.remove("hooks");
        }
    }
}

/// Pretty JSON with the indent the original file used (two spaces if it had
/// none) and its trailing newline (kept if there was one or no file).
fn render(root: &Value, original: Option<&str>) -> String {
    let indent = original.and_then(detect_indent).unwrap_or("  ");
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    root.serialize(&mut ser).expect("a JSON value serializes");
    let mut out = String::from_utf8(buf).expect("serde_json writes UTF-8");
    if original.is_none_or(|t| t.ends_with('\n') || t.trim().is_empty()) {
        out.push('\n');
    }
    out
}

/// Leading whitespace of the first indented line.
fn detect_indent(text: &str) -> Option<&str> {
    text.lines().skip(1).find_map(|l| {
        let n = l.len() - l.trim_start_matches([' ', '\t']).len();
        (n > 0).then(|| &l[..n])
    })
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}
```

- [ ] **Step 4: Implement the two agents**

Add the implementation to the top of `crates/agents/src/claude.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! Claude Code: `PreToolUse` hook in `.claude/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-claude-code-hooks.md).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change, HookBlocker};

pub const SETTINGS_REL: &str = ".claude/settings.json";

/// Shell, read and write tools (spec §5.2). Only `[A-Za-z0-9_|]`, so Claude
/// Code reads it as an exact list of tool names.
pub const MATCHER: &str = "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit";

/// Seconds. No `onFailure: "block"`: v1 developer mode fails open (spec §1.2
/// rule 4).
pub const TIMEOUT_SECS: u64 = 10;

pub const NEXT_STEP: &str = "Claude Code holds back project hooks until you accept the workspace trust prompt: start `claude` in this folder and accept it. `/hooks` shows the saiife hook.";

/// Managed-settings directories (Linux, macOS). Read-only checks.
pub const MANAGED_DIRS: &[&str] = &[
    "/etc/claude-code",
    "/Library/Application Support/ClaudeCode",
];

fn group() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": Agent::Claude.hook_command(),
            "timeout": TIMEOUT_SECS,
        }]
    })
}

const HOOKS: JsonHooks = JsonHooks {
    rel: SETTINGS_REL,
    event: "PreToolUse",
    group,
};

pub fn install(project: &Path) -> Result<Change, AgentError> {
    HOOKS.install(project)
}

pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    HOOKS.remove(project, delete_if_empty)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    HOOKS.entries(project)
}

pub fn expected_entry() -> String {
    HOOKS.expected()
}

/// Settings that stop the project hook from running: `disableAllHooks: true`
/// in project, local or user settings, and `allowManagedHooksOnly` /
/// `disableAllHooks` in managed settings.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    let managed: Vec<PathBuf> = MANAGED_DIRS.iter().map(PathBuf::from).collect();
    blockers_in(project, home, &managed)
}

/// `blockers` with the managed-settings directories given (tests).
pub fn blockers_in(
    project: &Path,
    home: Option<&Path>,
    managed_dirs: &[PathBuf],
) -> Vec<HookBlocker> {
    let mut files = vec![
        project.join(".claude/settings.json"),
        project.join(".claude/settings.local.json"),
    ];
    if let Some(home) = home {
        files.push(home.join(".claude/settings.json"));
    }
    let mut out = Vec::new();
    for f in &files {
        if flag_set(f, "disableAllHooks") {
            out.push(HookBlocker {
                path: f.clone(),
                setting: "disableAllHooks",
            });
        }
    }
    for dir in managed_dirs {
        let mut managed = vec![dir.join("managed-settings.json")];
        if let Ok(rd) = std::fs::read_dir(dir.join("managed-settings.d")) {
            let mut dropins: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            dropins.sort();
            managed.extend(dropins);
        }
        for f in managed {
            for setting in ["allowManagedHooksOnly", "disableAllHooks"] {
                if flag_set(&f, setting) {
                    out.push(HookBlocker {
                        path: f.clone(),
                        setting,
                    });
                }
            }
        }
    }
    out
}

/// True when `path` is a JSON object with `key: true`. Missing or unreadable
/// files are not blockers.
fn flag_set(path: &Path, key: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get(key).and_then(Value::as_bool))
        == Some(true)
}

```

Add the implementation to the top of `crates/agents/src/gemini.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! Gemini CLI: `BeforeTool` hook in `.gemini/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-gemini-hooks.md).

use std::path::Path;

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change};

pub const SETTINGS_REL: &str = ".gemini/settings.json";

/// Regex on the tool name: shell, read, list/search and write tools.
pub const MATCHER: &str =
    "run_shell_command|read_file|read_many_files|list_directory|glob|grep_search|write_file|replace";

/// Milliseconds (Gemini CLI's unit).
pub const TIMEOUT_MS: u64 = 10_000;

pub const NEXT_STEP: &str = "Gemini CLI only loads project hooks in a trusted folder: start `gemini` in this folder and trust it when asked.";

fn group() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": Agent::Gemini.hook_command(),
            "name": "saiife",
            "timeout": TIMEOUT_MS,
        }]
    })
}

const HOOKS: JsonHooks = JsonHooks {
    rel: SETTINGS_REL,
    event: "BeforeTool",
    group,
};

pub fn install(project: &Path) -> Result<Change, AgentError> {
    HOOKS.install(project)
}

pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    HOOKS.remove(project, delete_if_empty)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    HOOKS.entries(project)
}

pub fn expected_entry() -> String {
    HOOKS.expected()
}

```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p saiife-agents`
Expected: PASS — including `remove_restores_the_original_bytes`, `four_space_indent_round_trips` and `unparseable_settings_are_left_byte_identical`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/agents/src
git commit -m "feat(agents): Claude Code and Gemini CLI hook install/remove/fingerprint

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Codex hook installer (TOML) and the per-agent dispatch on `Agent`

**Files:**
- Create: `crates/agents/src/codex.rs`
- Modify: `crates/agents/src/lib.rs` (module, `Agent` methods)

**Interfaces:**
- Consumes: Task 4 helpers; `HookBlocker` (Task 6); `claude::*`, `gemini::*` (Task 6).
- Produces:
  - `codex::{CONFIG_REL = ".codex/config.toml", MATCHER = "^(Bash|apply_patch)$", TIMEOUT_SECS: i64 = 10, STATUS_MESSAGE = "saiife guard", NEXT_STEP, install, remove(project, delete_if_empty), entries, expected_entry, blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker>}`
  - On `Agent`: `config_rel(self) -> &'static str`, `next_step(self) -> &'static str`, `install(self, project: &Path) -> Result<Change, AgentError>`, `remove(self, project: &Path, delete_if_empty: bool) -> Result<Change, AgentError>`, `entries(self, project: &Path) -> Result<Vec<String>, AgentError>`, `blockers(self, project: &Path, home: Option<&Path>) -> Vec<HookBlocker>`, `expected_entry(self) -> String`

- [ ] **Step 1: Write the failing tests**

In `crates/agents/src/lib.rs`, replace:

```rust
pub mod claude;
pub mod config;
```

with:

```rust
pub mod claude;
pub mod codex;
pub mod config;
```

Create `crates/agents/src/codex.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const USER_CONFIG: &str = r#"# my codex setup
model = "gpt-5-codex"   # pinned
approval_policy = "on-request"

[features]
web_search = true

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "./audit-shell.sh"

[mcp_servers.docs]
command = "docs-mcp"
"#;

    fn project_with(config: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".codex")).unwrap();
        fs::write(p.path().join(CONFIG_REL), config).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(CONFIG_REL)).unwrap()
    }

    #[test]
    fn install_appends_our_group_and_keeps_comments() {
        let p = project_with(USER_CONFIG);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let text = read(p.path());
        assert!(text.starts_with("# my codex setup\nmodel = \"gpt-5-codex\"   # pinned\n"));
        let doc: DocumentMut = text.parse().unwrap();
        let groups = doc["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
        assert_eq!(groups.len(), 2);
        let ours = groups.get(1).unwrap();
        assert_eq!(ours["matcher"].as_str(), Some(MATCHER));
        let h = ours["hooks"].as_array_of_tables().unwrap().get(0).unwrap();
        assert_eq!(
            h["command"].as_str(),
            Some("saiife check --hook-exit --agent codex")
        );
        assert_eq!(h["timeout"].as_integer(), Some(10));
        assert_eq!(h["statusMessage"].as_str(), Some("saiife guard"));
        assert_eq!(
            doc["mcp_servers"]["docs"]["command"].as_str(),
            Some("docs-mcp")
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    #[test]
    fn install_twice_then_remove_restores_bytes() {
        let p = project_with(USER_CONFIG);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_CONFIG);
    }

    #[test]
    fn fresh_file_has_no_bare_hooks_header_and_is_deleted_again() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(
            install(p.path()).unwrap(),
            Change::Created {
                created_dirs: vec![".codex".into()]
            }
        );
        let text = read(p.path());
        assert!(text.starts_with("[[hooks.PreToolUse]]\n"), "{text}");
        assert!(!text.contains("[hooks]\n"), "{text}");
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
        assert!(!p.path().join(CONFIG_REL).exists());
    }

    #[test]
    fn tampered_timeout_changes_the_fingerprint() {
        let p = project_with(USER_CONFIG);
        install(p.path()).unwrap();
        let t = read(p.path()).replace("timeout = 10", "timeout = 0");
        fs::write(p.path().join(CONFIG_REL), t).unwrap();
        let got = entries(p.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert_ne!(got, vec![expected_entry()]);
    }

    #[test]
    fn other_layouts_and_bad_toml_are_left_untouched() {
        for bad in ["hooks = { PreToolUse = [] }\n", "model = \n", "hooks = 3\n"] {
            let p = project_with(bad);
            assert!(install(p.path()).is_err(), "{bad:?}");
            assert_eq!(read(p.path()), bad, "{bad:?}");
        }
    }

    #[test]
    fn features_hooks_false_is_a_blocker() {
        let p = project_with("[features]\nhooks = false\n");
        let home = tempfile::tempdir().unwrap();
        let found = blockers(p.path(), Some(home.path()));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].setting, "[features] hooks = false");
        let ok = project_with("[features]\nhooks = true\n");
        assert!(blockers(ok.path(), Some(home.path())).is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-agents codex`
Expected: FAIL to compile — `cannot find function 'install'`, `cannot find value 'CONFIG_REL'`.

- [ ] **Step 3: Implement Codex**

Add the implementation to the top of `crates/agents/src/codex.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! Codex: `[[hooks.PreToolUse]]` in `.codex/config.toml`
//! (contract: docs/superpowers/research/2026-10-13-codex-hooks.md).
//!
//! Edited with `toml_edit`, so the user's comments, key order and
//! formatting survive. saiife only reads and writes the array-of-tables
//! form (`[[hooks.PreToolUse]]` with `[[hooks.PreToolUse.hooks]]`); any
//! other layout of `hooks.PreToolUse` is reported, never rewritten.

use std::path::{Path, PathBuf};

use serde_json::Value;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

use crate::{fingerprint, fsutil, is_saiife_command, Agent, AgentError, Change, HookBlocker};

pub const CONFIG_REL: &str = ".codex/config.toml";

/// Regex on the tool name; `apply_patch` also covers Codex's `Edit`/`Write`
/// aliases.
pub const MATCHER: &str = "^(Bash|apply_patch)$";

/// Seconds.
pub const TIMEOUT_SECS: i64 = 10;

pub const STATUS_MESSAGE: &str = "saiife guard";

pub const NEXT_STEP: &str = "Codex asks you to trust every new or changed hook once: start `codex` in this folder (the project's .codex folder must be trusted), run `/hooks` and trust the saiife hook.";

pub fn install(project: &Path) -> Result<Change, AgentError> {
    let path = project.join(CONFIG_REL);
    let text = fsutil::read_optional(&path)?;
    let mut doc = parse(&path, text.as_deref().unwrap_or(""))?;
    if fingerprints(&path, &doc)? == [expected_entry()] {
        return Ok(Change::Unchanged);
    }
    strip_ours(&path, &mut doc)?;
    let hooks = doc
        .entry("hooks")
        .or_insert_with(|| {
            let mut t = Table::new();
            t.set_implicit(true);
            Item::Table(t)
        })
        .as_table_mut()
        .ok_or_else(|| layout(&path, "`hooks` is not a table"))?;
    let groups = hooks
        .entry("PreToolUse")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            layout(
                &path,
                "`hooks.PreToolUse` is not a list of [[hooks.PreToolUse]] tables",
            )
        })?;
    groups.push(group());
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    fsutil::write(project, CONFIG_REL, &out)
}

/// Remove saiife's handlers. With `delete_if_empty`, a file left with no
/// content is deleted (use only for a file saiife created).
pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return Ok(Change::Unchanged);
    };
    let mut doc = parse(&path, &text)?;
    if strip_ours(&path, &mut doc)? == 0 {
        return Ok(Change::Unchanged);
    }
    prune(&mut doc);
    let out = doc.to_string();
    if delete_if_empty && out.trim().is_empty() {
        fsutil::remove(project, CONFIG_REL)?;
        return Ok(Change::Deleted);
    }
    fsutil::write(project, CONFIG_REL, &out)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return Ok(Vec::new());
    };
    fingerprints(&path, &parse(&path, &text)?)
}

pub fn expected_entry() -> String {
    let g = group();
    let handler = g["hooks"]
        .as_array_of_tables()
        .and_then(|a| a.get(0))
        .expect("group() has one handler");
    entry_fingerprint(g.get("matcher"), handler)
}

/// `[features] hooks = false` in the project or user config turns every
/// Codex hook off.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    let mut files = vec![project.join(CONFIG_REL)];
    if let Some(home) = home {
        files.push(home.join(".codex/config.toml"));
    }
    files
        .into_iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .ok()
                .and_then(|t| t.parse::<DocumentMut>().ok())
                .and_then(|d| d.get("features")?.get("hooks")?.as_bool())
                == Some(false)
        })
        .map(|path: PathBuf| HookBlocker {
            path,
            setting: "[features] hooks = false",
        })
        .collect()
}

/// The `[[hooks.PreToolUse]]` table `install` appends.
fn group() -> Table {
    let mut handler = Table::new();
    handler["type"] = value("command");
    handler["command"] = value(Agent::Codex.hook_command());
    handler["timeout"] = value(TIMEOUT_SECS);
    handler["statusMessage"] = value(STATUS_MESSAGE);
    let mut handlers = ArrayOfTables::new();
    handlers.push(handler);
    let mut g = Table::new();
    g["matcher"] = value(MATCHER);
    g["hooks"] = Item::ArrayOfTables(handlers);
    g
}

fn parse(path: &Path, text: &str) -> Result<DocumentMut, AgentError> {
    text.parse::<DocumentMut>().map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "TOML",
        detail: e.to_string().trim().replace('\n', " "),
    })
}

/// `hooks.PreToolUse` as array-of-tables, `None` if absent.
fn groups<'a>(path: &Path, doc: &'a DocumentMut) -> Result<Option<&'a ArrayOfTables>, AgentError> {
    let Some(hooks) = doc.get("hooks") else {
        return Ok(None);
    };
    let Some(pre) = hooks.get("PreToolUse") else {
        return Ok(None);
    };
    pre.as_array_of_tables().map(Some).ok_or_else(|| {
        layout(
            path,
            "`hooks.PreToolUse` is not a list of [[hooks.PreToolUse]] tables",
        )
    })
}

fn fingerprints(path: &Path, doc: &DocumentMut) -> Result<Vec<String>, AgentError> {
    let mut out = Vec::new();
    for g in groups(path, doc)?.into_iter().flat_map(ArrayOfTables::iter) {
        if let Some(handlers) = g.get("hooks").and_then(Item::as_array_of_tables) {
            for h in handlers.iter().filter(|h| is_ours(h)) {
                out.push(entry_fingerprint(g.get("matcher"), h));
            }
        }
    }
    Ok(out)
}

/// Remove saiife handlers; drop groups left with none. Returns the count.
fn strip_ours(path: &Path, doc: &mut DocumentMut) -> Result<usize, AgentError> {
    groups(path, doc)?; // layout check
    let Some(groups) = doc
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(Item::as_array_of_tables_mut)
    else {
        return Ok(0);
    };
    let mut removed = 0;
    groups.retain(|g| {
        let Some(handlers) = g.get("hooks").and_then(Item::as_array_of_tables) else {
            return true;
        };
        let ours = handlers.iter().filter(|h| is_ours(h)).count();
        removed += ours;
        !(ours > 0 && ours == handlers.len())
    });
    for g in groups.iter_mut() {
        if let Some(handlers) = g.get_mut("hooks").and_then(Item::as_array_of_tables_mut) {
            handlers.retain(|h| !is_ours(h));
        }
    }
    Ok(removed)
}

/// Drop `hooks.PreToolUse` and then `hooks` if removing saiife left them
/// empty.
fn prune(doc: &mut DocumentMut) {
    let Some(hooks) = doc.get_mut("hooks").and_then(Item::as_table_mut) else {
        return;
    };
    if hooks
        .get("PreToolUse")
        .and_then(Item::as_array_of_tables)
        .is_some_and(ArrayOfTables::is_empty)
    {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        doc.remove("hooks");
    }
}

fn is_ours(handler: &Table) -> bool {
    handler
        .get("command")
        .and_then(Item::as_str)
        .is_some_and(is_saiife_command)
}

/// Same scheme as the JSON agents: matcher + handler, as canonical JSON.
fn entry_fingerprint(matcher: Option<&Item>, handler: &Table) -> String {
    fingerprint::of_json(&serde_json::json!({
        "matcher": matcher.map(item_to_json).unwrap_or(Value::Null),
        "handler": table_to_json(handler),
    }))
}

fn table_to_json(t: &Table) -> Value {
    Value::Object(
        t.iter()
            .map(|(k, v)| (k.to_string(), item_to_json(v)))
            .collect(),
    )
}

fn item_to_json(item: &Item) -> Value {
    match item {
        Item::Value(v) => value_to_json(v),
        Item::Table(t) => table_to_json(t),
        Item::ArrayOfTables(a) => Value::Array(a.iter().map(table_to_json).collect()),
        Item::None => Value::Null,
    }
}

fn value_to_json(v: &toml_edit::Value) -> Value {
    use toml_edit::Value as T;
    match v {
        T::String(s) => Value::String(s.value().clone()),
        T::Integer(i) => Value::from(*i.value()),
        T::Float(f) => serde_json::Number::from_f64(*f.value())
            .map(Value::Number)
            .unwrap_or(Value::Null),
        T::Boolean(b) => Value::Bool(*b.value()),
        T::Datetime(d) => Value::String(d.value().to_string()),
        T::Array(a) => Value::Array(a.iter().map(value_to_json).collect()),
        T::InlineTable(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_string(), value_to_json(v)))
                .collect(),
        ),
    }
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

```

- [ ] **Step 4: Add the per-agent dispatch to `Agent`**

In `crates/agents/src/lib.rs`, replace:

```rust
use std::path::PathBuf;
```

with:

```rust
use std::path::{Path, PathBuf};
```

Inside `impl Agent`, insert directly above `/// The exact hook command written for this agent.`:

```rust
    /// The project file `init` writes, relative to the project root.
    pub fn config_rel(self) -> &'static str {
        match self {
            Agent::Claude => claude::SETTINGS_REL,
            Agent::Codex => codex::CONFIG_REL,
            Agent::Gemini => gemini::SETTINGS_REL,
        }
    }

```

and replace the end of `impl Agent` (after `hook_command`):

```rust
        format!("saiife check --hook-exit --agent {}", self.name())
    }
}
```

with:

```rust
        format!("saiife check --hook-exit --agent {}", self.name())
    }

    /// What the user still has to do in the agent before the hook runs.
    pub fn next_step(self) -> &'static str {
        match self {
            Agent::Claude => claude::NEXT_STEP,
            Agent::Codex => codex::NEXT_STEP,
            Agent::Gemini => gemini::NEXT_STEP,
        }
    }

    /// Add saiife's hook entry to this agent's project config.
    pub fn install(self, project: &Path) -> Result<Change, AgentError> {
        match self {
            Agent::Claude => claude::install(project),
            Agent::Codex => codex::install(project),
            Agent::Gemini => gemini::install(project),
        }
    }

    /// Remove saiife's hook entries (and only those) from this agent's
    /// project config. With `delete_if_empty` (a file saiife created), a
    /// file left with nothing in it is deleted.
    pub fn remove(self, project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
        match self {
            Agent::Claude => claude::remove(project, delete_if_empty),
            Agent::Codex => codex::remove(project, delete_if_empty),
            Agent::Gemini => gemini::remove(project, delete_if_empty),
        }
    }

    /// Fingerprints of every saiife hook entry currently in the config, in
    /// file order. Empty when the file or the entry is missing.
    pub fn entries(self, project: &Path) -> Result<Vec<String>, AgentError> {
        match self {
            Agent::Claude => claude::entries(project),
            Agent::Codex => codex::entries(project),
            Agent::Gemini => gemini::entries(project),
        }
    }

    /// Settings in this agent's project or user config that stop the hook
    /// from running at all. Read-only.
    pub fn blockers(self, project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
        match self {
            Agent::Claude => claude::blockers(project, home),
            Agent::Codex => codex::blockers(project, home),
            Agent::Gemini => Vec::new(),
        }
    }

    /// Fingerprint of the entry `install` writes.
    pub fn expected_entry(self) -> String {
        match self {
            Agent::Claude => claude::expected_entry(),
            Agent::Codex => codex::expected_entry(),
            Agent::Gemini => gemini::expected_entry(),
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p saiife-agents`
Expected: PASS — including `install_twice_then_remove_restores_bytes` (comments and key order of the user's `config.toml` survive) and `fresh_file_has_no_bare_hooks_header_and_is_deleted_again`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/agents/src
git commit -m "feat(agents): Codex hook install/remove/fingerprint via toml_edit; Agent dispatch

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Integrity record outside the project

**Files:**
- Create: `crates/agents/src/integrity.rs`
- Modify: `crates/agents/src/lib.rs` (module)

**Interfaces:**
- Consumes: `fingerprint::sha256_hex`, `fsutil::io_err`, `AgentError` (Task 4).
- Produces: `saiife_agents::integrity::{DATA_DIR_ENV = "SAIIFE_DATA_DIR", INTEGRITY_VERSION: u32 = 1, Integrity { v: u32, project: String, saiife_path: String, saiife_version: String, config_sha256: String, hooks: BTreeMap<String, HookRecord>, created: Vec<String> }, HookRecord { file: String, sha256: String }, data_dir() -> Option<PathBuf>, canonical_project(project: &Path) -> Result<PathBuf, AgentError>, record_path(project: &Path) -> Result<Option<PathBuf>, AgentError>}`; `Integrity::{load(path: &Path) -> Result<Option<Integrity>, AgentError>, save(&self, path: &Path) -> Result<(), AgentError>, delete(path: &Path) -> Result<(), AgentError>}`. Both structs derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`.

- [ ] **Step 1: Write the failing tests**

In `crates/agents/src/lib.rs`, replace:

```rust
pub mod gemini;
mod json_hooks;
```

with:

```rust
pub mod gemini;
pub mod integrity;
mod json_hooks;
```

Create `crates/agents/src/integrity.rs` with its tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample(project: &str) -> Integrity {
        let mut hooks = BTreeMap::new();
        hooks.insert(
            "claude".to_string(),
            HookRecord {
                file: ".claude/settings.json".into(),
                sha256: "ab".repeat(32),
            },
        );
        Integrity {
            v: INTEGRITY_VERSION,
            project: project.into(),
            saiife_path: "/usr/local/bin/saiife".into(),
            saiife_version: "0.1.0".into(),
            config_sha256: "cd".repeat(32),
            hooks,
            created: vec![".saiife".into(), ".saiife/config.toml".into()],
        }
    }

    #[test]
    fn save_load_delete_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("projects/x.json");
        assert_eq!(Integrity::load(&path).unwrap(), None);
        let rec = sample("/p");
        rec.save(&path).unwrap();
        assert_eq!(Integrity::load(&path).unwrap(), Some(rec));
        Integrity::delete(&path).unwrap();
        Integrity::delete(&path).unwrap();
        assert_eq!(Integrity::load(&path).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn record_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("projects/x.json");
        sample("/p").save(&path).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn corrupt_record_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("x.json");
        fs::write(&path, "{").unwrap();
        assert!(Integrity::load(&path).is_err());
    }

    /// Review Focus 3: the same project through a symlink or `..` has one
    /// record. (Only this test in this binary touches DATA_DIR_ENV.)
    #[cfg(unix)]
    #[test]
    fn symlinked_project_path_maps_to_the_same_record() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::create_dir_all(real.join("sub")).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("link")).unwrap();
        std::env::set_var(DATA_DIR_ENV, d.path().join("data"));
        let a = record_path(&real).unwrap().unwrap();
        let b = record_path(&d.path().join("link")).unwrap().unwrap();
        let c = record_path(&real.join("sub/..")).unwrap().unwrap();
        std::env::remove_var(DATA_DIR_ENV);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert!(a.starts_with(d.path().join("data/projects")));
        assert_eq!(a.file_name().unwrap().len(), 64 + ".json".len());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-agents integrity`
Expected: FAIL to compile — `cannot find struct 'Integrity'`, `cannot find function 'record_path'`.

- [ ] **Step 3: Implement**

Add the implementation to the top of `crates/agents/src/integrity.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! The integrity record (spec §7.5): what `saiife init` wrote into a
//! project, kept OUTSIDE the project at
//! `<data dir>/saiife/projects/<sha256 of canonical project path>.json`, so
//! `saiife status` can tell when it was removed or changed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fingerprint::sha256_hex;
use crate::fsutil::io_err;
use crate::AgentError;

/// Overrides `<data dir>/saiife` (tests, admins); mirrors the audit crate's
/// `SAIIFE_AUDIT_DIR`.
pub const DATA_DIR_ENV: &str = "SAIIFE_DATA_DIR";

pub const INTEGRITY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub v: u32,
    /// Canonical project path.
    pub project: String,
    /// Canonical path of the `saiife` binary that ran `init`.
    pub saiife_path: String,
    /// Its version (`CARGO_PKG_VERSION`).
    pub saiife_version: String,
    /// SHA-256 of `.saiife/config.toml` as `init` left it.
    pub config_sha256: String,
    /// Agent name (`claude`, `codex`, `gemini`) -> the hook entry written.
    pub hooks: BTreeMap<String, HookRecord>,
    /// Files and directories `init` created, relative to the project, in
    /// creation order (a directory before what is inside it).
    #[serde(default)]
    pub created: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRecord {
    /// Config file, relative to the project.
    pub file: String,
    /// Fingerprint of the hook entry (`Agent::expected_entry`).
    pub sha256: String,
}

/// `$SAIIFE_DATA_DIR`, else `<data dir>/saiife`.
pub fn data_dir() -> Option<PathBuf> {
    match std::env::var_os(DATA_DIR_ENV) {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("saiife")),
    }
}

/// The project path that identifies a project: canonical, so a project
/// reached through a symlink or with `..` is still the same project.
pub fn canonical_project(project: &Path) -> Result<PathBuf, AgentError> {
    fs::canonicalize(project).map_err(io_err(project))
}

/// Where the integrity record of `project` lives. `None` if there is no data
/// directory.
pub fn record_path(project: &Path) -> Result<Option<PathBuf>, AgentError> {
    let canonical = canonical_project(project)?;
    let key = sha256_hex(canonical.as_os_str().as_encoded_bytes());
    Ok(data_dir().map(|d| d.join("projects").join(format!("{key}.json"))))
}

impl Integrity {
    /// `None` if there is no record (never initialized here, or removed).
    pub fn load(path: &Path) -> Result<Option<Integrity>, AgentError> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(path)(e)),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| AgentError::Parse {
                path: path.to_path_buf(),
                format: "JSON",
                detail: e.to_string(),
            })
    }

    /// Write atomically; the directory is created owner-only (0700) and the
    /// file is owner-only (0600) on unix.
    pub fn save(&self, path: &Path) -> Result<(), AgentError> {
        let dir = path.parent().expect("record path has a parent");
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(io_err(dir))?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(io_err(dir))?;
        let mut body = serde_json::to_string_pretty(self).expect("integrity serializes");
        body.push('\n');
        tmp.write_all(body.as_bytes()).map_err(io_err(path))?;
        tmp.persist(path).map_err(|e| io_err(path)(e.error))?;
        Ok(())
    }

    /// Delete the record; a missing one is fine.
    pub fn delete(path: &Path) -> Result<(), AgentError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(path)(e)),
        }
    }
}

```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p saiife-agents`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/agents/src
git commit -m "feat(agents): per-project integrity record outside the project (0700 dir, 0600 file)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: `saiife init` and `saiife init --off`

**Files:**
- Create: `crates/cli/src/init_cmd.rs`
- Modify: `crates/cli/src/main.rs`
- Test: `crates/cli/tests/common/mod.rs`, `crates/cli/tests/init_cmd.rs`

**Interfaces:**
- Consumes: `Agent` + dispatch (Tasks 4, 7), `detect::{detect_agents, which}`, `config::{find_project_root, ensure, load, CONFIG_REL}` (Task 5), `integrity::*` (Task 8), `fingerprint::sha256_hex`.
- Produces:
  - `init_cmd::project_root(cwd: &Path) -> PathBuf` (used by `status` in Task 11)
  - `init_cmd::run(builtin: &[Pack], agent_names: &[String], pack_ids: &[String]) -> ExitCode` — exit 0 ok, 1 if any agent/config/record failed, 2 for bad arguments or no agent found
  - `init_cmd::off() -> ExitCode` — exit 0 ok, 1 on any failure
  - CLI: `saiife init [--agent <AGENT>]... [--pack <PACK_ID>]...`, `saiife init --off` (`--off` conflicts with `--agent`)
  - test helper `common::{Env, fake_exe, code, stdout, stderr}`; `Env::{new(agents: &[&str]) -> Env, bare(agents: &[&str]) -> Env, root(&self) -> &Path, saiife(&self, args: &[&str]) -> Output, saiife_in(&self, dir: &Path, args: &[&str]) -> Output, read(&self, rel: &str) -> String, write(&self, rel: &str, contents: &str)}`; fields `project, bin, home, data, audit: TempDir`

- [ ] **Step 1: Write the test helper and the failing tests**

Create `crates/cli/tests/common/mod.rs`:

```rust
//! Shared setup for tests that run `saiife init` / `status` / `packs`:
//! a temp project, a temp HOME, temp data and audit dirs, and a PATH that
//! holds only fake agent binaries and (optionally) a link to the saiife
//! under test. Nothing touches the real user's directories.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

pub struct Env {
    pub project: TempDir,
    pub bin: TempDir,
    pub home: TempDir,
    pub data: TempDir,
    pub audit: TempDir,
}

/// An executable shell script `dir/name` with `body` after the shebang.
pub fn fake_exe(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

impl Env {
    /// Fake `agents` on PATH plus a symlink `saiife` -> the binary under test.
    pub fn new(agents: &[&str]) -> Env {
        let env = Env::bare(agents);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_saiife"), env.bin.path().join("saiife"))
            .unwrap();
        env
    }

    /// Fake `agents` on PATH and no `saiife` on PATH.
    pub fn bare(agents: &[&str]) -> Env {
        let env = Env {
            project: tempfile::tempdir().unwrap(),
            bin: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            data: tempfile::tempdir().unwrap(),
            audit: tempfile::tempdir().unwrap(),
        };
        for a in agents {
            fake_exe(env.bin.path(), a, "exit 0");
        }
        env
    }

    pub fn root(&self) -> &Path {
        self.project.path()
    }

    /// Run the saiife under test in the project root.
    pub fn saiife(&self, args: &[&str]) -> Output {
        self.saiife_in(self.root(), args)
    }

    pub fn saiife_in(&self, dir: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(args)
            .current_dir(dir)
            .env("PATH", self.bin.path())
            .env("HOME", self.home.path())
            .env("SAIIFE_DATA_DIR", self.data.path())
            .env("SAIIFE_AUDIT_DIR", self.audit.path())
            .output()
            .unwrap()
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root().join(rel)).unwrap()
    }

    pub fn write(&self, rel: &str, contents: &str) {
        let p = self.root().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
```

Create `crates/cli/tests/init_cmd.rs`:

```rust
//! `saiife init` / `saiife init --off` end to end (spec §5, §10 "Agents").

mod common;

use common::{code, stderr, stdout, Env};

const CLAUDE_USER: &str = "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"FOO\": \"bar\"\n  }\n}\n";
const CODEX_USER: &str = "# mine\nmodel = \"gpt-5-codex\"\n\n[features]\nweb_search = true\n";
const GEMINI_USER: &str = "{\n  \"theme\": \"GitHub\"\n}\n";

#[test]
fn init_hooks_detected_agents_and_writes_the_config() {
    let env = Env::new(&["claude", "gemini"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("saiife is on for"), "{text}");
    assert!(text.contains("workspace trust"), "Claude next step: {text}");
    assert!(text.contains("trusted folder"), "Gemini next step: {text}");
    assert!(!text.contains("WARNING"), "{text}");
    assert!(env
        .read(".claude/settings.json")
        .contains("saiife check --hook-exit --agent claude"));
    assert!(env
        .read(".gemini/settings.json")
        .contains("\"name\": \"saiife\""));
    assert!(!env.root().join(".codex").exists(), "codex not on PATH");
    let cfg = env.read(".saiife/config.toml");
    assert!(
        cfg.contains("packs = [\"core.filesystem\", \"core.git\"]"),
        "{cfg}"
    );
    assert!(cfg.contains("locked = false"), "{cfg}");
}

#[test]
fn explicit_agents_and_packs() {
    let env = Env::new(&[]);
    let out = env.saiife(&[
        "init",
        "--agent",
        "codex",
        "--pack",
        "db.postgres",
        "--pack",
        "db.nope",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("unknown pack \"db.nope\""));
    assert!(stdout(&out).contains("/hooks"), "Codex next step");
    assert!(env
        .read(".codex/config.toml")
        .contains("[[hooks.PreToolUse]]"));
    let cfg = env.read(".saiife/config.toml");
    assert!(cfg.contains("\"db.postgres\""), "{cfg}");
    assert!(!cfg.contains("db.nope"), "{cfg}");
}

#[test]
fn no_agent_on_path_exits_2() {
    let env = Env::new(&[]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("no supported agent found"));
    assert!(!env.root().join(".saiife").exists());
}

#[test]
fn unknown_agent_exits_2() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init", "--agent", "cursor"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("unknown agent"));
}

#[test]
fn second_init_changes_nothing() {
    let env = Env::new(&["claude", "codex", "gemini"]);
    env.write(".claude/settings.json", CLAUDE_USER);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let files = [
        ".claude/settings.json",
        ".codex/config.toml",
        ".gemini/settings.json",
        ".saiife/config.toml",
    ];
    let before: Vec<String> = files.iter().map(|f| env.read(f)).collect();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("already set up"));
    let after: Vec<String> = files.iter().map(|f| env.read(f)).collect();
    assert_eq!(before, after);
}

#[test]
fn off_restores_user_files_and_deletes_what_init_created() {
    let env = Env::new(&["claude", "codex", "gemini"]);
    env.write(".claude/settings.json", CLAUDE_USER);
    env.write(".codex/config.toml", CODEX_USER);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    assert_eq!(env.read(".claude/settings.json"), CLAUDE_USER);
    assert_eq!(env.read(".codex/config.toml"), CODEX_USER);
    assert!(
        !env.root().join(".gemini").exists(),
        "created by init, now empty"
    );
    assert!(!env.root().join(".saiife").exists());
    // The integrity record is gone too.
    let records = std::fs::read_dir(env.data.path().join("projects"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(records, 0);
}

#[test]
fn off_keeps_files_with_user_content_added_after_init() {
    let env = Env::new(&["gemini"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    // The user adds their own setting to the file saiife created.
    let with_theme =
        env.read(".gemini/settings.json")
            .replacen('{', "{\n  \"theme\": \"GitHub\",", 1);
    env.write(".gemini/settings.json", &with_theme);
    env.write(
        ".saiife/config.toml",
        "version = 1\npacks = [\"db.mysql\"]\n",
    );
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0);
    assert_eq!(env.read(".gemini/settings.json"), GEMINI_USER);
    assert!(
        stdout(&out).contains("config.toml kept"),
        "edited config is kept: {}",
        stdout(&out)
    );
    assert!(env.root().join(".saiife/config.toml").exists());
}

/// Review Focus 2: one broken settings file does not stop the others, and
/// is left exactly as it was.
#[test]
fn broken_settings_file_fails_that_agent_only() {
    let env = Env::new(&["claude", "gemini"]);
    let broken = "{\n  // comment\n  \"theme\": \"x\"\n}\n";
    env.write(".gemini/settings.json", broken);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("gemini  FAILED"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("did not change it"),
        "{}",
        stdout(&out)
    );
    assert_eq!(env.read(".gemini/settings.json"), broken);
    assert!(env.read(".claude/settings.json").contains("saiife check"));
}

/// Review Focus 3: init from a subdirectory of an initialized project uses
/// that project.
#[test]
fn init_from_a_subdirectory_reuses_the_project() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let sub = env.root().join("src/deep");
    std::fs::create_dir_all(&sub).unwrap();
    let out = env.saiife_in(&sub, &["init"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("Using the saiife project at"));
    assert!(!sub.join(".claude").exists());
}

/// Review Focus 4: without saiife on PATH the hooks cannot fire; say so.
#[test]
fn init_warns_when_saiife_is_not_on_path() {
    let env = Env::bare(&["claude"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("WARNING: `saiife` is not on your PATH"),
        "{}",
        stdout(&out)
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife --test init_cmd`
Expected: FAIL — every test; clap answers `error: unrecognized subcommand 'init'` (exit 2), so the `code == 0` assertions fail.

- [ ] **Step 3: Implement**

Create `crates/cli/src/init_cmd.rs`:

```rust
//! `saiife init` and `saiife init --off` (spec §5, §5.1, §5.2, §7.5).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use saiife_agents::config::{self, CONFIG_REL};
use saiife_agents::detect::{detect_agents, which};
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, HookRecord, Integrity, INTEGRITY_VERSION};
use saiife_agents::{Agent, Change};
use saiifeguard::Pack;

/// The project `init`, `--off` and `status` work on: the nearest directory
/// at or above `cwd` with `.saiife/config.toml`, else `cwd` itself.
pub fn project_root(cwd: &Path) -> PathBuf {
    config::find_project_root(cwd).unwrap_or_else(|| cwd.to_path_buf())
}

pub fn run(builtin: &[Pack], agent_names: &[String], pack_ids: &[String]) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    if root != cwd {
        println!("Using the saiife project at {}", root.display());
    }

    // Which agents.
    let agents = if agent_names.is_empty() {
        let found = detect_agents();
        if found.is_empty() {
            eprintln!(
                "saiife: no supported agent found on PATH (looked for claude, codex, gemini).\n\
                 Install one, or name it: saiife init --agent claude"
            );
            return ExitCode::from(2);
        }
        found
    } else {
        let mut out = Vec::new();
        for name in agent_names {
            match Agent::from_name(name) {
                Some(a) if !out.contains(&a) => out.push(a),
                Some(_) => {}
                None => {
                    eprintln!("saiife: unknown agent {name:?} (choose claude, codex or gemini)");
                    return ExitCode::from(2);
                }
            }
        }
        out
    };

    // Which packs.
    let mut requested = Vec::new();
    for id in pack_ids {
        if builtin.iter().any(|p| &p.id == id) {
            if !requested.contains(id) {
                requested.push(id.clone());
            }
        } else {
            eprintln!("saiife: unknown pack {id:?} ignored (`saiife packs` lists them)");
        }
    }
    let config_existed = root.join(CONFIG_REL).exists();
    let mut packs: Vec<String> = if config_existed {
        Vec::new()
    } else {
        builtin
            .iter()
            .filter(|p| p.default_on)
            .map(|p| p.id.clone())
            .collect()
    };
    for id in requested {
        if !packs.contains(&id) {
            packs.push(id);
        }
    }

    let record_path = match integrity::record_path(&root) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("saiife: could not determine the data directory; set SAIIFE_DATA_DIR");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(1);
        }
    };
    let previous = match Integrity::load(&record_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("saiife: {e}; starting a new integrity record");
            None
        }
    };
    let mut created = previous
        .as_ref()
        .map(|p| p.created.clone())
        .unwrap_or_default();
    let mut hooks = previous.map(|p| p.hooks).unwrap_or_default();

    // Project config first: if it cannot be written, touch nothing else.
    let config_change = match config::ensure(&root, &packs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(1);
        }
    };
    note_created(&mut created, &config_change, CONFIG_REL);
    let mut failed = false;
    let mut lines = vec![format!(
        "  config  {CONFIG_REL} ({})",
        describe(&config_change, "packs added", "already set up")
    )];

    for agent in &agents {
        match agent.install(&root) {
            Ok(change) => {
                note_created(&mut created, &change, agent.config_rel());
                hooks.insert(
                    agent.name().to_string(),
                    HookRecord {
                        file: agent.config_rel().to_string(),
                        sha256: agent.expected_entry(),
                    },
                );
                lines.push(format!(
                    "  {:<7} {} ({})",
                    agent.name(),
                    agent.config_rel(),
                    describe(&change, "hook added", "already set up")
                ));
            }
            Err(e) => {
                failed = true;
                lines.push(format!("  {:<7} FAILED: {e}", agent.name()));
            }
        }
    }

    let config_sha256 = match std::fs::read(root.join(CONFIG_REL)) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(e) => {
            eprintln!("saiife: {CONFIG_REL}: {e}");
            return ExitCode::from(1);
        }
    };
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .unwrap_or_default();
    let record = Integrity {
        v: INTEGRITY_VERSION,
        project: integrity::canonical_project(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.display().to_string()),
        saiife_path: exe.display().to_string(),
        saiife_version: env!("CARGO_PKG_VERSION").to_string(),
        config_sha256,
        hooks,
        created,
    };
    if let Err(e) = record.save(&record_path) {
        failed = true;
        lines.push(format!("  integrity record FAILED: {e}"));
    }

    println!("saiife is on for {}", root.display());
    for l in &lines {
        println!("{l}");
    }
    if let Ok(cfg) = config::load(&root) {
        let active: Vec<&str> = builtin
            .iter()
            .filter(|p| p.default_on || cfg.packs.contains(&p.id))
            .map(|p| p.id.as_str())
            .collect();
        println!("  packs   {}", active.join(", "));
    }
    path_warning(&exe);
    println!("\nNext steps:");
    for agent in &agents {
        println!("  - {}: {}", agent.label(), agent.next_step());
    }
    println!("Check the setup any time with `saiife status`.");
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// The hooks run whatever `saiife` is on PATH. Say so plainly when that is
/// nothing, or a different binary.
fn path_warning(exe: &Path) {
    match which("saiife").map(|p| std::fs::canonicalize(&p).unwrap_or(p)) {
        None => println!(
            "\nWARNING: `saiife` is not on your PATH, so the agents cannot run the hook and \
             their actions are NOT guarded. Put saiife in a PATH directory (e.g. ~/.local/bin), \
             then run `saiife init` again."
        ),
        Some(p) if p != exe => println!(
            "\nWARNING: the hooks will run {} (the saiife on your PATH), not this binary ({}). \
             Run `saiife init` with the saiife on your PATH.",
            p.display(),
            exe.display()
        ),
        Some(_) => {}
    }
}

pub fn off() -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    let record_path = integrity::record_path(&root).ok().flatten();
    let record = record_path
        .as_deref()
        .and_then(|p| Integrity::load(p).ok().flatten());
    let created: Vec<String> = record
        .as_ref()
        .map(|r| r.created.clone())
        .unwrap_or_default();
    let mut failed = false;
    let mut lines = Vec::new();

    for agent in Agent::ALL {
        let ours = created.iter().any(|c| c == agent.config_rel());
        match agent.remove(&root, ours) {
            Ok(Change::Unchanged) => {}
            Ok(Change::Deleted) => lines.push(format!(
                "  {:<7} hook removed; {} deleted (saiife created it)",
                agent.name(),
                agent.config_rel()
            )),
            Ok(_) => lines.push(format!(
                "  {:<7} hook removed from {}",
                agent.name(),
                agent.config_rel()
            )),
            Err(e) => {
                failed = true;
                lines.push(format!("  {:<7} FAILED: {e}", agent.name()));
            }
        }
    }

    let config_path = root.join(CONFIG_REL);
    if config_path.exists() {
        let unchanged = record.as_ref().is_some_and(|r| {
            std::fs::read(&config_path).is_ok_and(|b| sha256_hex(&b) == r.config_sha256)
        });
        if created.iter().any(|c| c == CONFIG_REL) && unchanged {
            match std::fs::remove_file(&config_path) {
                Ok(()) => lines.push(format!("  config  {CONFIG_REL} deleted")),
                Err(e) => {
                    failed = true;
                    lines.push(format!("  config  FAILED to delete {CONFIG_REL}: {e}"));
                }
            }
        } else {
            lines.push(format!(
                "  config  {CONFIG_REL} kept (saiife did not create it, or it was edited); \
                 delete it yourself if you no longer need it"
            ));
        }
    }
    // Directories saiife created, innermost first; only empty ones go.
    for rel in created.iter().rev() {
        let p = root.join(rel);
        if p.is_dir() {
            let _ = std::fs::remove_dir(&p);
        }
    }
    if !failed {
        if let Some(p) = &record_path {
            if let Err(e) = Integrity::delete(p) {
                failed = true;
                lines.push(format!("  integrity record FAILED: {e}"));
            }
        }
    }

    println!("saiife is off for {}", root.display());
    if lines.is_empty() {
        println!("  nothing to remove");
    }
    for l in &lines {
        println!("{l}");
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Remember what a write created: its new directories, then the file.
fn note_created(created: &mut Vec<String>, change: &Change, file: &str) {
    if let Change::Created { created_dirs } = change {
        for rel in created_dirs.iter().map(String::as_str).chain([file]) {
            if !created.iter().any(|c| c == rel) {
                created.push(rel.to_string());
            }
        }
    }
}

fn describe(change: &Change, updated: &str, unchanged: &str) -> String {
    match change {
        Change::Created { .. } => "created".into(),
        Change::Updated => updated.into(),
        Change::Unchanged => unchanged.into(),
        Change::Deleted => "deleted".into(),
    }
}
```

In `crates/cli/src/main.rs`, replace:

```rust
mod check;
mod project;
```

with:

```rust
mod check;
mod init_cmd;
mod project;
```

Add the subcommand — insert directly above `/// Show the audit log: every allowed, blocked and fail-open decision.` in `enum Cmd`:

```rust
    /// Turn saiife on for this project: write the guard hook into each
    /// agent's project config and create .saiife/config.toml.
    Init {
        /// Agent to set up (claude, codex, gemini; repeatable). Default: every
        /// supported agent found on PATH.
        #[arg(long = "agent", value_name = "AGENT")]
        agents: Vec<String>,
        /// Remove exactly what `saiife init` added.
        #[arg(long, conflicts_with = "agents")]
        off: bool,
    },
```

and the match arms — replace:

```rust
        Cmd::Check { hook_exit, agent } => check::run(packs, &cli.packs, hook_exit, &agent),
```

with:

```rust
        Cmd::Check { hook_exit, agent } => check::run(packs, &cli.packs, hook_exit, &agent),
        Cmd::Init { off: true, .. } => init_cmd::off(),
        Cmd::Init { agents, off: false } => init_cmd::run(&packs, &agents, &cli.packs),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p saiife`
Expected: PASS.

- [ ] **Step 5: Try it by hand**

```bash
cargo build
P=$(mktemp -d) && cd "$P"
SAIIFE_DATA_DIR=$P/.data SAIIFE_AUDIT_DIR=$P/.audit PATH="$OLDPWD/target/debug:$PATH" saiife init --agent claude --agent codex --pack db.postgres
cat .claude/settings.json .codex/config.toml .saiife/config.toml
SAIIFE_DATA_DIR=$P/.data PATH="$OLDPWD/target/debug:$PATH" saiife init --off && ls -A
cd - && rm -rf "$P"
```

Expected: `saiife is on for …` with one line per file and the Claude/Codex next steps; the three files contain the entries; `--off` prints `hook removed; … deleted (saiife created it)` for both agents and `ls -A` shows only `.data`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/cli/src/init_cmd.rs crates/cli/src/main.rs crates/cli/tests/common crates/cli/tests/init_cmd.rs
git commit -m "feat(cli): saiife init / init --off for Claude Code, Codex and Gemini CLI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: `saiife packs`

**Files:**
- Create: `crates/cli/src/packs_cmd.rs`
- Modify: `crates/cli/src/main.rs`
- Test: `crates/cli/tests/packs_cmd.rs`

**Interfaces:**
- Consumes: `project::project_packs` (Task 5); `saiifeguard::Pack` fields `id`, `default_on`, `description`, `allow`, `deny`.
- Produces: `packs_cmd::run(builtin: &[Pack], cli_packs: &[String]) -> ExitCode` (always 0); `packs_cmd::render(builtin: &[Pack], project: &[String], cli_packs: &[String]) -> String` — header `ID DEFAULT HERE RULES SUMMARY`, one row per pack, `RULES` = allow + deny rule count.

- [ ] **Step 1: Write the failing tests**

Create `crates/cli/src/packs_cmd.rs` with its unit test only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use saiifeguard::builtins::builtin_packs;

    #[test]
    fn lists_every_pack_with_default_and_here() {
        let (packs, _) = builtin_packs();
        let out = render(&packs, &["db.postgres".to_string()], &[]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("ID"));
        assert_eq!(lines.len(), packs.len() + 1);
        let git = lines.iter().find(|l| l.starts_with("core.git ")).unwrap();
        assert!(git.contains(" on      on "), "{git}");
        let pg = lines
            .iter()
            .find(|l| l.starts_with("db.postgres "))
            .unwrap();
        assert!(pg.contains(" off     on "), "{pg}");
        let my = lines.iter().find(|l| l.starts_with("db.mysql ")).unwrap();
        assert!(my.contains(" off     off "), "{my}");
        assert!(my.contains("MySQL"), "{my}");
    }
}
```

Create `crates/cli/tests/packs_cmd.rs`:

```rust
mod common;

use common::{code, stdout, Env};

#[test]
fn packs_shows_what_is_on_here() {
    let env = Env::new(&[]);
    let out = env.saiife(&["packs"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("showing the defaults"));
    env.write(
        ".saiife/config.toml",
        "version = 1\npacks = [\"db.postgres\"]\n",
    );
    let out = env.saiife(&["packs"]);
    let text = stdout(&out);
    let pg = text
        .lines()
        .find(|l| l.starts_with("db.postgres "))
        .unwrap();
    assert!(pg.contains(" off     on "), "{pg}");
    assert!(text.lines().count() >= 12, "{text}");
}
```

In `crates/cli/src/main.rs`, replace:

```rust
mod init_cmd;
mod project;
```

with:

```rust
mod init_cmd;
mod packs_cmd;
mod project;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife packs`
Expected: FAIL to compile — `cannot find function 'render'`.

- [ ] **Step 3: Implement**

Add the implementation to the top of `crates/cli/src/packs_cmd.rs`, above the `#[cfg(test)]` module (the file then reads: implementation, then tests):

```rust
//! `saiife packs`: every pack, whether it is on by default and here, its
//! rule count and what it guards.

use std::process::ExitCode;

use saiifeguard::Pack;

use crate::project::project_packs;
use crate::warn;

pub fn run(builtin: &[Pack], cli_packs: &[String]) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_default();
    let project = project_packs(&cwd, builtin);
    for w in &project.warnings {
        warn(w);
    }
    match &project.root {
        Some(r) => println!("Project: {}", r.display()),
        None => println!("No .saiife/config.toml here or above; showing the defaults."),
    }
    print!("{}", render(builtin, &project.enabled, cli_packs));
    ExitCode::SUCCESS
}

pub fn render(builtin: &[Pack], project: &[String], cli_packs: &[String]) -> String {
    let row = |id: &str, def: &str, here: &str, rules: &str, summary: &str| {
        format!("{id:<18} {def:<7} {here:<4} {rules:>5}  {summary}\n")
    };
    let mut out = row("ID", "DEFAULT", "HERE", "RULES", "SUMMARY");
    for p in builtin {
        let here = p.default_on || project.contains(&p.id) || cli_packs.contains(&p.id);
        out.push_str(&row(
            &p.id,
            if p.default_on { "on" } else { "off" },
            if here { "on" } else { "off" },
            &(p.allow.len() + p.deny.len()).to_string(),
            &p.description,
        ));
    }
    out
}

```

In `crates/cli/src/main.rs`, insert directly above `/// Show the audit log: every allowed, blocked and fail-open decision.`:

```rust
    /// List packs: id, on by default, on here, rule count, summary.
    Packs,
```

and replace:

```rust
        Cmd::Init { agents, off: false } => init_cmd::run(&packs, &agents, &cli.packs),
```

with:

```rust
        Cmd::Init { agents, off: false } => init_cmd::run(&packs, &agents, &cli.packs),
        Cmd::Packs => packs_cmd::run(&packs, &cli.packs),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p saiife packs`
Expected: PASS (unit test `lists_every_pack_with_default_and_here`, integration test `packs_shows_what_is_on_here`).

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/cli/src/packs_cmd.rs crates/cli/src/main.rs crates/cli/tests/packs_cmd.rs
git commit -m "feat(cli): saiife packs lists packs, default and project state, rule counts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: `saiife status` — tamper detection

Implements the four checks of spec §7.5 plus the carry-over (an unreadable audit dir is reported, not shown as an empty log) and the research findings (settings that switch hooks off).

**Files:**
- Modify: `crates/audit/src/store.rs` (`ReadResult::dir_error`), `crates/cli/src/audit_cmd.rs`, `crates/cli/src/main.rs`, `crates/cli/Cargo.toml` (`dirs`)
- Create: `crates/cli/src/status_cmd.rs`
- Test: `crates/audit/src/store.rs` (unit), `crates/cli/tests/audit_cmd.rs`, `crates/cli/tests/status_cmd.rs`

**Interfaces:**
- Consumes: `init_cmd::project_root` (Task 9), `project::project_packs` (Task 5), `Agent::{entries, blockers, config_rel, label, name}` (Task 7), `integrity::{record_path, canonical_project, Integrity}` (Task 8), `detect::which`, `fingerprint::sha256_hex`, `store::{default_dir, read_all, Filter, DIR_ENV}`, `Record::timestamp`.
- Produces: `saiife_audit::store::ReadResult` gains `pub dir_error: Option<String>` (`None` for a missing dir); `status_cmd::run(builtin: &[Pack]) -> ExitCode` (0 clean, 1 any failed check); `saiife audit` exits 1 when the audit dir cannot be read.

- [ ] **Step 1: Write the failing tests**

In `crates/audit/src/store.rs` `mod tests`, insert directly above `#[cfg(unix)] #[test] fn new_file_is_owner_only()`:

```rust
    #[test]
    fn read_all_of_an_unlistable_dir_says_so() {
        // A file where the directory should be: unreadable even as root
        // (the offline CI job runs tests as root in a user namespace).
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("audit");
        fs::write(&file, "x").unwrap();
        let got = read_all(&file);
        assert!(got.records.is_empty());
        assert!(got.dir_error.is_some());
    }

```

Append to `crates/cli/tests/audit_cmd.rs`:

```rust

#[test]
fn unreadable_audit_dir_is_an_error_not_an_empty_log() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit");
    std::fs::write(&file, "x").unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, &file)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot be read"));
}
```

Create `crates/cli/tests/status_cmd.rs`:

```rust
//! `saiife status` tamper checks (spec §7.5, §10 "Tamper detection"): each
//! check tampers with one thing and expects a warning, a fix and exit 1; an
//! untouched project exits 0.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{code, fake_exe, stdout, Env};

fn initialized(agents: &[&str]) -> Env {
    let env = Env::new(agents);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    env
}

fn status(env: &Env) -> (i32, String) {
    let out = env.saiife(&["status"]);
    (code(&out), stdout(&out))
}

#[test]
fn untouched_project_passes() {
    let env = initialized(&["claude", "codex", "gemini"]);
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(text.contains("All checks passed."), "{text}");
    for a in ["claude", "codex", "gemini"] {
        assert!(
            text.lines()
                .any(|l| l.contains(a) && l.contains("hooked") && l.contains("never")),
            "{a}: {text}"
        );
    }
    assert!(text.contains("packs   core.filesystem, core.git"), "{text}");
    assert!(text.contains("cannot stop a determined agent"), "{text}");
}

#[test]
fn not_initialized_fails() {
    let env = Env::new(&["claude"]);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("not set up for this project"), "{text}");
}

#[test]
fn hook_removed_by_hand_is_reported_with_the_fix() {
    let env = initialized(&["claude"]);
    env.write(".claude/settings.json", "{}\n");
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("The saiife hook for Claude Code was removed from .claude/settings.json."),
        "{text}"
    );
    assert!(
        text.contains("Fix: run `saiife init` to restore it"),
        "{text}"
    );
    // ...and init does restore it.
    assert_eq!(code(&env.saiife(&["init"])), 0);
    assert_eq!(status(&env).0, 0);
}

#[test]
fn hook_changed_is_reported() {
    let env = initialized(&["codex"]);
    let t = env
        .read(".codex/config.toml")
        .replace("^(Bash|apply_patch)$", "^Nothing$");
    env.write(".codex/config.toml", &t);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("The saiife hook for Codex in .codex/config.toml was changed."),
        "{text}"
    );
}

#[test]
fn settings_file_deleted_is_reported() {
    let env = initialized(&["gemini"]);
    std::fs::remove_file(env.root().join(".gemini/settings.json")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("was removed from .gemini/settings.json"),
        "{text}"
    );
}

#[test]
fn config_edited_is_reported() {
    let env = initialized(&["claude"]);
    let t = env
        .read(".saiife/config.toml")
        .replace("\"core.git\"", "\"db.mysql\"");
    env.write(".saiife/config.toml", &t);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains(".saiife/config.toml was changed since `saiife init`."),
        "{text}"
    );
}

#[test]
fn config_deleted_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.root().join(".saiife/config.toml")).unwrap();
    // Without the config the project root is the cwd itself, which is still
    // the project: the record is found by path.
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains(".saiife/config.toml was removed."), "{text}");
}

#[test]
fn swapped_binary_on_path_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.bin.path().join("saiife")).unwrap();
    fake_exe(env.bin.path(), "saiife", "echo 'saiife 0.1.0'");
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("is not the one that ran `saiife init`"),
        "{text}"
    );
}

#[test]
fn saiife_missing_from_path_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.bin.path().join("saiife")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("`saiife` is not on PATH"), "{text}");
}

#[test]
fn disable_all_hooks_is_reported() {
    let env = initialized(&["claude"]);
    env.write(
        ".claude/settings.local.json",
        "{\"disableAllHooks\": true}\n",
    );
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("sets disableAllHooks"), "{text}");
    // User-level settings count too.
    std::fs::remove_file(env.root().join(".claude/settings.local.json")).unwrap();
    std::fs::create_dir_all(env.home.path().join(".claude")).unwrap();
    std::fs::write(
        env.home.path().join(".claude/settings.json"),
        "{\"disableAllHooks\": true}",
    )
    .unwrap();
    assert_eq!(status(&env).0, 1);
}

#[test]
fn last_hook_call_is_shown_per_agent() {
    let env = initialized(&["claude", "codex"]);
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": env.root().join("src"),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("s ago"), "{claude}");
    let codex = text
        .lines()
        .find(|l| l.trim_start().starts_with("codex"))
        .unwrap();
    assert!(codex.contains("never"), "{codex}");
}

#[test]
fn unreadable_audit_dir_is_a_failed_check() {
    let env = initialized(&["claude"]);
    let file = env.audit.path().join("not-a-dir");
    std::fs::write(&file, "x").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("status")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", &file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("cannot be read"), "{}", stdout(&out));
}

#[cfg(unix)]
#[test]
fn fifo_in_the_audit_dir_is_a_failed_check() {
    let env = initialized(&["claude"]);
    let fifo = env.audit.path().join("2026-01.jsonl");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("are not regular files"), "{text}");
}

/// Review Focus 3: the same project reached through a symlink, or status
/// run from a subdirectory, finds the same record.
#[cfg(unix)]
#[test]
fn symlinked_path_and_subdirectory_find_the_same_project() {
    let env = initialized(&["claude"]);
    let link_parent = tempfile::tempdir().unwrap();
    let link = link_parent.path().join("app");
    std::os::unix::fs::symlink(env.root(), &link).unwrap();
    let out = env.saiife_in(&link, &["status"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    let sub = env.root().join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let out = env.saiife_in(&sub, &["status"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p saiife-audit && cargo test -p saiife --test audit_cmd --test status_cmd`
Expected: FAIL — `no field 'dir_error' on type 'ReadResult'`; after that, `unreadable_audit_dir_is_an_error_not_an_empty_log` (exit 0) and every `status_cmd` test (`unrecognized subcommand 'status'`).

- [ ] **Step 3: Report an unreadable audit directory**

In `crates/audit/src/store.rs`, replace the end of `ReadResult`:

```rust
    /// Month files that could not be read or are not regular files
    /// (symlinks, FIFOs, directories).
    pub unreadable_files: usize,
}

```

with:

```rust
    /// Month files that could not be read or are not regular files
    /// (symlinks, FIFOs, directories).
    pub unreadable_files: usize,
    /// Set when the audit directory itself exists but cannot be listed
    /// (permissions, not a directory). A missing directory is not an error:
    /// it only means nothing was recorded yet.
    pub dir_error: Option<String>,
}

```

and the start of `read_all`:

```rust
    let mut out = ReadResult::default();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
```

with:

```rust
    let mut out = ReadResult::default();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return out,
        Err(e) => {
            out.dir_error = Some(e.to_string());
            return out;
        }
    };
```

In `crates/cli/src/audit_cmd.rs` `run`, replace:

```rust
    let all = store::read_all(&dir);
```

with:

```rust
    let all = store::read_all(&dir);
    if let Some(e) = &all.dir_error {
        eprintln!(
            "saiife: the audit directory {} cannot be read: {e}",
            dir.display()
        );
        return ExitCode::from(1);
    }
```

Run: `cargo test -p saiife-audit && cargo test -p saiife --test audit_cmd`
Expected: PASS.

- [ ] **Step 4: Implement `status`**

In `crates/cli/Cargo.toml` `[dependencies]`, replace:

```toml
time = "0.3"
```

with:

```toml
time = "0.3"
dirs = "5"
```

Create `crates/cli/src/status_cmd.rs`:

```rust
//! `saiife status`: is this project still guarded? Runs the tamper checks
//! of spec §7.5 and exits 1 if any fails, so it can run in scripts and CI.

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use saiife_agents::config::CONFIG_REL;
use saiife_agents::detect::which;
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, Integrity};
use saiife_agents::Agent;
use saiife_audit::store::{self, Filter};
use saiife_audit::Record;
use saiifeguard::Pack;
use time::OffsetDateTime;

use crate::init_cmd::project_root;
use crate::project::project_packs;

const RESTORE: &str = "run `saiife init` to restore it";

/// One failed check: what is wrong, and what to do.
struct Problem {
    what: String,
    fix: String,
}

pub fn run(builtin: &[Pack]) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    println!("saiife status for {}", root.display());

    let record = match integrity::record_path(&root) {
        Ok(Some(p)) => Integrity::load(&p).map_err(|e| e.to_string()),
        Ok(None) => Err("could not determine the data directory".to_string()),
        Err(e) => Err(e.to_string()),
    };
    let record = match record {
        Ok(Some(r)) => r,
        Ok(None) => {
            println!(
                "\nWARNING: saiife is not set up for this project on this machine \
                 (no integrity record).\n  Fix: run `saiife init` in {}",
                root.display()
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            println!("\nWARNING: the integrity record cannot be read: {e}\n  Fix: run `saiife init` to write a new one");
            return ExitCode::from(1);
        }
    };

    let mut problems = Vec::new();
    let mut notes = Vec::new();
    let last_calls = last_calls(&root, &mut problems, &mut notes);
    let home = dirs::home_dir();

    for agent in Agent::ALL {
        let rel = agent.config_rel();
        let found = agent.entries(&root);
        let Some(rec) = record.hooks.get(agent.name()) else {
            if found.is_ok_and(|f| !f.is_empty()) {
                problems.push(Problem {
                    what: format!(
                        "{rel} has a saiife hook for {} that `saiife init` did not record.",
                        agent.label()
                    ),
                    fix: "run `saiife init` to record it".into(),
                });
            } else {
                println!("  {:<7} not set up", agent.name());
            }
            continue;
        };
        match found {
            Err(e) => problems.push(Problem {
                what: format!("{} cannot be checked: {e}", agent.label()),
                fix: format!("repair {rel}, then {RESTORE}"),
            }),
            Ok(f) if f.contains(&rec.sha256) => {
                let last = last_calls
                    .iter()
                    .filter(|r| r.agent == agent.name())
                    .filter_map(Record::timestamp)
                    .max();
                println!(
                    "  {:<7} hooked   {rel:<22} last hook call: {}",
                    agent.name(),
                    last.map(ago).unwrap_or_else(|| "never".into())
                );
            }
            Ok(f) if f.is_empty() => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} was removed from {rel}.",
                    agent.label()
                ),
                fix: RESTORE.into(),
            }),
            Ok(_) => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} in {rel} was changed.",
                    agent.label()
                ),
                fix: RESTORE.into(),
            }),
        }
        for b in agent.blockers(&root, home.as_deref()) {
            let fix = if b.setting == "allowManagedHooksOnly" {
                "ask your administrator: managed settings only allow their own hooks on this machine".to_string()
            } else {
                format!("remove `{}` from {}", b.setting, b.path.display())
            };
            problems.push(Problem {
                what: format!(
                    "{} sets {}, which stops {}'s hooks: saiife does not run there.",
                    b.path.display(),
                    b.setting,
                    agent.label()
                ),
                fix,
            });
        }
    }

    check_config(&root, &record, builtin, &mut problems);
    check_binary(&record, &mut problems);

    if !notes.is_empty() {
        println!();
        for n in &notes {
            println!("Note: {n}");
        }
    }
    for p in &problems {
        println!("\nWARNING: {}\n  Fix: {}", p.what, p.fix);
    }
    println!(
        "\nsaiife v1 catches mistakes and makes a switched-off guard visible; it cannot stop a \
         determined agent running as your user."
    );
    if problems.is_empty() {
        println!("All checks passed.");
        ExitCode::SUCCESS
    } else {
        println!("{} check(s) failed.", problems.len());
        ExitCode::from(1)
    }
}

/// Audit records of this project (by its literal and canonical path).
/// An unreadable audit trail is a failed check (spec §1.2 rule 5).
fn last_calls(root: &Path, problems: &mut Vec<Problem>, notes: &mut Vec<String>) -> Vec<Record> {
    let Some(dir) = store::default_dir() else {
        problems.push(Problem {
            what: "the audit directory cannot be determined, so no decision is recorded".into(),
            fix: format!("set {}", store::DIR_ENV),
        });
        return Vec::new();
    };
    let all = store::read_all(&dir);
    if let Some(e) = &all.dir_error {
        problems.push(Problem {
            what: format!("the audit log at {} cannot be read: {e}", dir.display()),
            fix: "make the directory readable by your user again".into(),
        });
    }
    if all.unreadable_files > 0 {
        problems.push(Problem {
            what: format!(
                "{} file(s) in the audit log at {} are not regular files or cannot be read",
                all.unreadable_files,
                dir.display()
            ),
            fix: "check the audit directory for files you did not create".into(),
        });
    }
    if all.skipped_lines > 0 {
        notes.push(format!(
            "{} unreadable audit line(s) skipped (a crash mid-write, or a hand edit)",
            all.skipped_lines
        ));
    }
    let mut roots = vec![root.display().to_string()];
    if let Ok(c) = integrity::canonical_project(root) {
        roots.push(c.display().to_string());
    }
    let filters: Vec<Filter> = roots
        .into_iter()
        .map(|p| Filter {
            project: Some(p),
            ..Default::default()
        })
        .collect();
    all.records
        .into_iter()
        .filter(|r| filters.iter().any(|f| f.matches(r)))
        .collect()
}

fn check_config(root: &Path, record: &Integrity, builtin: &[Pack], problems: &mut Vec<Problem>) {
    match std::fs::read(root.join(CONFIG_REL)) {
        Err(_) => problems.push(Problem {
            what: format!("{CONFIG_REL} was removed."),
            fix: RESTORE.into(),
        }),
        Ok(bytes) if sha256_hex(&bytes) != record.config_sha256 => problems.push(Problem {
            what: format!("{CONFIG_REL} was changed since `saiife init`."),
            fix: "if you made this change, run `saiife init` to record it; otherwise restore the file and run `saiife init`".into(),
        }),
        Ok(_) => {}
    }
    let project = project_packs(root, builtin);
    for w in project.warnings {
        problems.push(Problem {
            what: w,
            fix: format!("fix {CONFIG_REL} (`saiife packs` lists the pack ids)"),
        });
    }
    let active: Vec<&str> = builtin
        .iter()
        .filter(|p| p.default_on || project.enabled.contains(&p.id))
        .map(|p| p.id.as_str())
        .collect();
    println!("  packs   {}", active.join(", "));
}

/// The `saiife` on PATH must be the binary that ran `init` (path + version).
fn check_binary(record: &Integrity, problems: &mut Vec<Problem>) {
    let fix =
        "if you moved, upgraded or reinstalled saiife yourself, run `saiife init` to record it";
    let Some(on_path) = which("saiife") else {
        problems.push(Problem {
            what: "`saiife` is not on PATH, so the agents cannot run the hook.".into(),
            fix: "put saiife back in a PATH directory, then run `saiife init`".into(),
        });
        return;
    };
    let on_path = std::fs::canonicalize(&on_path).unwrap_or(on_path);
    if on_path.as_path() != Path::new(&record.saiife_path) {
        problems.push(Problem {
            what: format!(
                "the saiife on PATH ({}) is not the one that ran `saiife init` ({}).",
                on_path.display(),
                record.saiife_path
            ),
            fix: fix.into(),
        });
        return;
    }
    match binary_version(&on_path) {
        Some(v) if v == record.saiife_version => {
            println!("  binary  {} ({v})", on_path.display());
        }
        Some(v) => problems.push(Problem {
            what: format!(
                "the saiife on PATH is version {v}; `saiife init` ran with {}.",
                record.saiife_version
            ),
            fix: fix.into(),
        }),
        None => problems.push(Problem {
            what: format!("{} --version did not answer.", on_path.display()),
            fix: fix.into(),
        }),
    }
}

/// `<path> --version` -> the version after "saiife ". Gives up after 2 s.
fn binary_version(path: &Path) -> Option<String> {
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while child.try_wait().ok()?.is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    out.trim().strip_prefix("saiife ").map(str::to_string)
}

fn ago(t: OffsetDateTime) -> String {
    let secs = (OffsetDateTime::now_utc() - t).whole_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}
```

In `crates/cli/src/main.rs`, replace:

```rust
mod project;
```

with:

```rust
mod project;
mod status_cmd;
```

insert directly above `/// List packs: id, on by default, on here, rule count, summary.`:

```rust
    /// Check that this project is still guarded; exit 1 if any check fails.
    Status,
```

replace:

```rust
        Cmd::Packs => packs_cmd::run(&packs, &cli.packs),
```

with:

```rust
        Cmd::Status => status_cmd::run(&packs),
        Cmd::Packs => packs_cmd::run(&packs, &cli.packs),
```

and complete the module doc — replace:

```rust
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, answer the hook (silent allow / block); FAIL OPEN on error.
```

with:

```rust
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, answer the hook (silent allow / block); FAIL OPEN on error.
//! - `saiife init [--off]` -> hook the agents into this project (or remove exactly that)
//! - `saiife status` -> tamper checks; exit 1 if any fails
//! - `saiife packs` -> list packs and which are on here
//! - `saiife audit` -> the audit log as a table
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --workspace`
Expected: PASS. The status tests set `HOME` to a temp dir; the managed-settings check reads `/etc/claude-code` read-only — on a machine that really has a managed `disableAllHooks`/`allowManagedHooksOnly`, `untouched_project_passes` correctly fails.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/audit/src/store.rs crates/cli/src/audit_cmd.rs crates/cli/src/status_cmd.rs crates/cli/src/main.rs crates/cli/Cargo.toml Cargo.lock crates/cli/tests/audit_cmd.rs crates/cli/tests/status_cmd.rs
git commit -m "feat(cli): saiife status tamper checks; report an unreadable audit dir

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Roadmap, live check, CI

**Files:**
- Modify: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`

**Interfaces:**
- Consumes: everything above.
- Produces: roadmap row 2 points at this plan; carry-over items handled by this plan struck through; live-check gaps recorded for plan 3.

- [ ] **Step 1: Full local verification**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./scripts/test-offline.sh`
Expected: all pass (the offline script needs unprivileged user namespaces; if `unshare -rn` is not permitted locally, CI runs it).

- [ ] **Step 2: Live check with Claude Code (installed on this machine)**

```bash
cargo build --release
mkdir -p ~/.local/bin && cp target/release/saiife ~/.local/bin/saiife
P=$(mktemp -d) && cd "$P" && git init -q && echo hi > a.txt && git add a.txt && git commit -qm init
saiife init --agent claude
claude -p "Run the shell command: ls"
claude -p "Run exactly this shell command and nothing else: git reset --hard"
claude -p "Read the file a.txt and tell me what it says"
saiife audit --project "$P"
saiife status
# Record real payloads to compare with the fixtures (this edit makes status fail; that is expected):
sed -i 's#"command": "saiife check --hook-exit --agent claude"#"command": "tee -a /tmp/saiife-claude-payloads.jsonl | saiife check --hook-exit --agent claude"#' .claude/settings.json
claude -p "Run the shell command: ls"
claude -p "Read the file a.txt and tell me what it says"
cat /tmp/saiife-claude-payloads.jsonl
cd - && rm -rf "$P" /tmp/saiife-claude-payloads.jsonl
```

Expected: the first `claude -p` lists `a.txt`; the second reports the command was blocked with `BLOCKED by core.git` (if the model refuses to try it on its own, the `ls` row below still proves the hook fires); the third answers "hi"; `saiife audit` shows an `allowed` `Bash` row for `ls`, a `BLOCKED` `Bash` row for `git reset --hard` and an `allowed` `Read` row with path `…/a.txt`; `saiife status` shows `claude  hooked … last hook call: …s ago` and exits 0. The recorded payloads must carry the fields the fixtures in `crates/cli/tests/fixtures/claude/` use (`session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input.command` / `tool_input.file_path`); if a field differs, update the fixtures and `payload::classify` in a separate commit. Remove `~/.local/bin/saiife` afterwards if you do not want it installed yet. If any of this differs, record the actual behavior in `docs/superpowers/research/2026-10-13-claude-code-hooks.md` and fix before continuing. Codex and Gemini CLI are not installed here — their UNVERIFIED points are listed in the roadmap step below.

- [ ] **Step 3: Update the roadmap**

In `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md`:

- In the table row for plan 2, replace the Status cell `to write after plan 1` with the same style as row 1: written: `2026-10-13-plan-2-agents-config-tamper.md`.
- Under "Carry-over from plan 1", replace the two **Plan 2** bullets with:

```markdown
- ~~**Plan 2:** `saiife check` answers Claude Code with `permissionDecision: "allow"`~~ — done in plan 2: allow is silent for every agent.
- ~~**Plan 2 (`status`):** `read_all` returns an empty result with no signal when the audit dir itself is unreadable~~ — done in plan 2: `ReadResult::dir_error`; `status` and `audit` report it.
- **Plan 3 (verify live):** Codex and Gemini CLI hook entries are built from the research docs but not yet run against a live install: Codex `/hooks` trust flow, `apply_patch` patch text in `tool_input.command`, project `config.toml` hooks loading; Gemini `name`/ms timeout, folder trust, and whether a missing `saiife` (exit 127) blocks every tool.
```

- [ ] **Step 4: Commit and push**

```bash
git add docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md
git commit -m "docs: plan 2 done; record live-check status per agent

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin HEAD
```

- [ ] **Step 5: Verify CI**

Run: `gh run watch --exit-status $(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')`
Expected: `test (ubuntu-latest)`, `test (macos-latest)` and `offline` succeed. On failure read `gh run view --log-failed` and fix in a new commit.

---

## Done when

- `cargo test --workspace` passes locally and CI is green on all three jobs.
- `saiife init` adds exactly one saiife hook entry per agent; a second run changes no byte; `saiife init --off` restores user files byte-for-byte and deletes only what `init` created.
- `saiife check` prints nothing on allow, blocks with exit 2 + reason, records file tools by path, never judges `apply_patch` text, and loads the project's opt-in packs.
- `saiife status` exits 0 on an untouched project and 1 with a plain warning + fix for each tamper case in spec §10.
- Next: write plan 3 (`core.secrets`, `core.self`, `evaluate_path`) on top of `ToolCall::File`.
