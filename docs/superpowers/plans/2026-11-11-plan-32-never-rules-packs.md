# Plan 32: never-rules packs (user-pack schema, loading, `where`/profiles, hook wiring): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** User packs (`user.*`) written into `policy.d/packs/` (locked) or the personal config are loaded by every hook, judged after the built-in packs, enforced fail-closed in locked mode, hashed into the policy, and filtered by `where` for a box profile. A rule marked `ask` goes through the v2 `[guard] ask` approval path. Plan 33 (import, confirm, sync) writes these packs; this plan makes them real.

**Architecture:**
- **The pack format grows five keys, all inert for built-ins.** `where`, `source`, `ask` on rules; `[import]` and `[[unenforced]]` on the file. `build.rs` refuses them in `packs/*.toml`, so "host only" can never touch a built-in pack (spec §10.4).
- **Two readers, one file.** `saiife-policy` reads the files (regular, no symlink, size caps), hashes them and pulls out the header and the `ask` rule ids with a light TOML parse. It needs no guard dependency. `saiife-guard` compiles them strictly: any broken rule is an error, never a dropped rule.
- **The files ride on `SystemConfig`** (`#[serde(skip)] user_packs`), filled by `load_system_with`. So the managed hook, the daemon (approval checks, policy hash), `policy check` and the Windows re-judge service all see the same bytes from one read. The hook ships the texts to the worker in `EvalRequest`, so the hash and the engine always describe the same packs.
- **Profiles are a guard concept** (`Profile::{Host, Box}`). A box profile leaves out `where = "host"` rules at load. Only the developer hook (`saiife check --profile box`, the in-box hook step 3 installs) and `explain --profile box` select it. The managed hook is always `Host`.
- **Box boundary seam:** `userpack::box_status` (what `rules list` prints) and `userpack::diff_hits` (what step 3's diff review calls) live in the guard. This plan does not change plan 28's `BoxSource` DTOs.

**Tech Stack:** Rust. `serde`, `toml 0.8`, `regex`, `sha2 0.10`, `serde_json` (all already in `Cargo.lock` and in these crates). No new crates. `tempfile` for tests.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §10 (all), §11 step 5, §12, §15 ("about half of a typical file is enforceable"), §7.7–§7.9 for boxes. Plan 33 builds on Tasks 1–3 and 6 of this plan.

## Facts checked (2026-11-11, branch `v3-dev` at `d464ce4`)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | `load_packs_dir` exists and is fail-open (skips a broken pack with a warning). Nothing outside its own tests calls it. | `crates/guard/src/pack.rs:1591-1644`; grep | Not reused: user packs come through `saiife-policy` (one read, hashed), and a broken one must fail closed (D3). |
| F2 | `RawRule` and `RawPathRule` are `deny_unknown_fields`. `RawPackFile` and `RawMeta` are not. | `crates/guard/src/pack_raw.rs:53-63, 66-86, 88-130, 132-143` | Each new key is a schema change (spec §10.6). Unknown top-level keys are already ignored, so `[import]` and `[[unenforced]]` are declared explicitly. |
| F3 | `build.rs` destructures every `Raw*` struct exhaustively and writes literals. | `crates/guard/build.rs:58-177` | Adding a field breaks the build until `build.rs` emits it. That is also where built-ins are refused the user-pack keys. |
| F4 | `platform` is filtered at load by `HostFilter::notes`, and a rule left out still counts, so a pack is not `NoRules`. | `pack.rs:1008-1036, 1564-1572` | `where` uses the same filter (D5). |
| F5 | `policy.d/*.toml` drop-ins are parsed as `DropIn` with `deny_unknown_fields`. `dropin_paths` only takes `*.toml` entries of the dir itself. | `crates/policy/src/load.rs:76-101, 749-781` | A pack file in `policy.d/` would break the policy load. User packs go in the subdirectory `policy.d/packs/` (D1). `dropin_paths` skips it, because a directory named `packs` does not end in `.toml`. |
| F6 | `read_policy_file`/`read_regular`: regular file only, `O_NOFOLLOW`, ≤ 1 MiB, UTF-8, `(path, sha256)` recorded. | `load.rs:783-830` | Reused for pack files (made `pub(crate)`). |
| F7 | `SystemConfig` is `deny_unknown_fields` and is serialized into the effective policy. No code builds it with a struct literal. | `crates/policy/src/system.rs:14-54`; `effective.rs:67-90`; grep `SystemConfig {` | A `#[serde(skip)]` field can't be set from `config.toml`, stays out of the `system` hash part, and breaks no constructor. |
| F8 | `active_packs` builds the active set from a `PackInfo` catalog. `check_guard_ask` uses it. `effective_policy` writes `{"id","version"}` per pack. | `effective.rs:9-60, 67-90`; `load.rs:291-317` | User packs join `active_packs` from `cfg.user_packs`. A pack hash `sha256` is written only when present, so every existing hash stays the same (Review Focus 3). |
| F9 | The daemon refuses an `approval.create` unless the rule is in its own `sys.guard.ask`. | `crates/daemon/src/approval_ops.rs:1077` | User `ask` ids are merged into `cfg.guard.ask` at load. The daemon then needs no code change, only a reload (`saiife policy reload`) after an import. |
| F10 | The managed hook loads the config on every call (`load_locked`), resolves packs and the hash in `policy_with`, and sends `EvalRequest { packs, ask, … }` to the worker, or judges Claude Code calls in-process. | `crates/cli/src/check_managed.rs:413, 673-760, 1008-1016, 1050-1105` | User packs reach the worker as text in `EvalRequest.user_packs` (D4). |
| F11 | `Verdict::Unjudged` from the worker becomes `error_denied` in the managed hook. | `check_managed.rs:369-399` | A broken user pack is an `Unjudged` answer, so the managed hook fails closed. |
| F12 | The developer hook builds its engine from `Catalog::builtin()` and hashes `saiife-policy-v1\nsaiife <v>\npacks <ids>\nconfig <c>\n`. | `crates/cli/src/check.rs:229-292, 476-486` | It also loads the personal user packs. Its hash adds lines only when there are user packs or a box profile, so `policy_hash_text_is_exact` keeps passing. |
| F13 | `MAX_EVAL_BYTES = 2 * PARSE_MAX_BYTES + 64 KiB`. | `crates/cli/src/eval.rs:32-37` | User pack text is capped at 256 KiB in total and added to the frame limit. |
| F14 | `saiife connect` writes `policy.d/<svc>.toml`: as root (0644, dir 0755) when locked, as the user (0600, dir 0700) for the broker at `$XDG_CONFIG_HOME/saiife/broker/`. | `crates/cli/src/connect_cmd.rs:129-133, 224-236`; `crates/system/src/personal.rs:86-91` | User packs follow the same owners and modes. The personal dir is `<broker config dir>/policy.d/packs`. |
| F15 | `profile` is reserved for v3 at the top level, in `[[scope]]`, and under services and secrets. | `load.rs:659-695` | **Unchanged** (D6). |
| F16 | Transparent wrappers (`sudo`, `env`, `timeout`, …) are peeled before rules match. The list is private. | `crates/guard/src/wrappers.rs:53-56, 306-330`; `core.lock.toml:48-58` | Task 1 adds `pub fn is_transparent(name) -> bool` for plan 33's rule builder. |

### Design decisions (flagged for the owner)

- **D1. Where user packs live.**
  - Locked: `<config dir>/policy.d/packs/*.toml`, which is `/etc/saiife/policy.d/packs/` by default. Root owns it, files are 0644 and the dir is 0755, and `doctor` checks it like `policy.d`.
  - Personal broker and developer hook: `<broker config dir>/policy.d/packs/`, which is `~/.config/saiife/broker/policy.d/packs/`.
  - Never in a project.
  - At most 32 files and 256 KiB of pack text in total. A dot-file is skipped. A symlinked dir or file is refused.
- **D2. One pack per source file, id `user.<slug>`.** The slug is `[a-z0-9-]{1,48}` and must not start with `-`. Every `[[deny]]` in a user pack needs an `id`, so the audit's `rule_id` and `ask` work. `default_on = false` and `lazy = true` are load errors in a user pack (a user pack is always on). There are at most 128 rules in total across user packs (`MAX_USER_RULES`); this keeps the hook's compile cost bounded.
- **D3. Fail closed for user packs, unlike built-ins.**
  - **Managed hook:** a read error, a header error, a duplicate id, a rule that does not compile, or a bad glob makes every call `error_denied` ("user pack <file>: <why>"). This is the same as a broken `config.toml` today.
  - **Developer hook:** fail-open with a warning, as v2 developer mode does, unless `/etc/saiife` asks for fail closed.
  - A rule left out for another `platform`, or for the box profile, is not an error.
- **D4. Texts in the request, compile cache in the guard.** The hook sends `(path, text)` pairs to the worker. `userpack::load_user_packs_cached` keeps the last compiled set per process, keyed by SHA-256 of (style, profile, each path and text). That is the spec's "cache the compiled packs" (§10.6) for the warm re-judge worker (`__eval --serve`). A one-shot hook compiles at most 128 rules once. The owner's bench run (Owner handwork) measures it.
- **D5. `where` default and filtering.** `where = "host" | "everywhere"`, default `everywhere`. An unknown value fails the pack's load, like `platform`. The box profile leaves out `host` rules at load, with no warning. Built-in packs carry no `where` (F3), so a box profile keeps every built-in rule.
- **D6. `profile` stays reserved in `config.toml`.** The box profile is chosen by what runs the hook (`saiife check --profile box`, written by step 3's in-box hook setup and by the template's rules profile, §7.8), not by a config key. The managed hook always uses `Host`, so its hash has no profile part. The developer hash gets `profile box` when it is used (§10.5 "part of the policy hash"). **Owner check:** keep `[[scope]] profile` reserved until a template needs it.
- **D7. `ask` lives on the rule.** `ask = true` on a `[[deny]]` with an `id` makes the policy loader add `user.<x>/<id>` to `[guard] ask`. From there the v2 path runs unchanged: `askable`, `grant.consume`, `approval.create`, approvers, and the `NO_APPROVERS_WARNING`. The developer hook has no approvals, so it denies an `ask` rule with the reason plus " (needs approval; approvals need locked mode)".
- **D8. Box status of a rule (spec §10.5, "advisory in boxes"):**
  - `where = "host"`: **off in boxes**;
  - a path rule whose access covers writes (`write`, `any`, `replace`, `content`): **checked at diff review** (`diff_hits`). Step 3 marks those files in the `land` review, which always needs a touch (plan 26 `TouchClass::Land`; nothing removes `land`);
  - everything else: **advisory in boxes**. That covers every command rule and read-only path rules.

  Push and secrets are enforced by the box design itself (no network, gateway, `push_protected`), not by a user rule, so no user rule claims them.

## Global Constraints

- **Tokio-free:** `saiife-guard`, `saiife-audit`, `saiife-policy`, `saiife-ipc` and `saiife-system` never depend on tokio. The CI gate `cargo tree -e normal -p saiife-guard -p saiife-audit -p saiife-policy -p saiife-ipc -p saiife-system … | grep -c tokio` must stay `0`.
- **No new dependencies.** If one is ever needed, pin it (`=x.y.z`) to a version released more than 14 days ago, and prefer crates already in `Cargo.lock`.
- **No network in tests.** No test runs a real `claude`, `docker`, `sudo` or any process-control tool.
- **Test isolation (hard rules):** `export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p32-tN-XXXXXX)" SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0`. In tests, point HOME, PATH, SAIIFE_DATA_DIR, SAIIFE_AUDIT_DIR and XDG_* at tempdirs (CLI tests: `common::Env`, `common::hermetic`). Locked tests use `--system-config`/`SAIIFE_TEST_SYSTEM_CONFIG` under a tempdir. Never read or write `/etc/saiife`, `~/.claude`, the owner's real `CLAUDE.md`, or the desktop keyring. No scratch name contains "fix". Remove `$TMPDIR` at the end.
- **Per task:** `cargo test -p <each crate touched> -j 4 -- --test-threads=4`, then `cargo fmt --all` and `cargo clippy --workspace --all-targets -j 4 -- -D warnings`. Keep non-Linux stubs compiling (`bash scripts/check-windows.sh -p <crate>` for guard, policy and system).
- **Never run** `scripts/bench-check.sh --managed`, `scripts/locked-linux/*` or any CI-only smoke script.
- **Git:** stage explicit paths. Never commit `.superpowers/`. No token-shaped literals. Every commit ends with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A user pack that is broken on a locked host:** a bad regex, an unknown `where`, an unknown key, a file over the cap, a symlink. Expected: every hook call is `error_denied` with the file named; nothing is silently dropped (Task 5: `managed_broken_user_pack_denies_every_call`; Task 4: `symlinked_pack_file_is_refused`, `pack_text_cap`).
2. **A user pack trying to loosen a built-in:** an `[[allow]]` matching `git reset --hard`, or `id = "core.git"`. Expected: the built-in still denies, and a non-`user.` id is a load error (Task 2: `user_allow_cannot_exempt_builtin`, `user_pack_id_must_be_user_prefixed`).
3. **Hosts with no user packs.** Expected: every policy hash, managed and developer, is byte-identical to today's (Task 4: `hash_unchanged_without_user_packs`; Task 6: the existing `policy_hash_text_is_exact` unchanged plus `dev_hash_unchanged_without_user_packs`).
4. **The box profile.** Expected: `where = "host"` rules are left out, `everywhere` and every built-in rule stay, and the dev hash differs from host (Task 1: `box_profile_drops_host_rules_only`, `builtins_keep_every_rule_in_box_profile`; Task 6: `dev_hash_names_the_box_profile`).
5. **An `ask` rule in a user pack.** Expected: on a locked host with approvers, the call becomes a pending request that the daemon accepts (not `not_ask`). In developer mode it is a plain deny that says why (Task 5: `managed_user_ask_rule_creates_a_request`; Task 6: `dev_ask_rule_denies_with_note`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (schema, profile filter).
- **Wave 2 (parallel):** Task 2 (strict user-pack loading and cache), Task 4 (policy reading, hashing, `ask` merge, layout, doctor).
- **Wave 3 (parallel):** Task 3 (box status, `diff_hits`, broad findings; needs 2), Task 5 (managed wiring; needs 2 and 4), Task 6 (developer hook, `test`/`explain`/`packs`, `policy check`, docs; needs 2 and 4).
- **Last:** gates, whole-branch review, PR to `v3-dev`. Plan 33 starts from this branch.

**Shared files:** `crates/guard/src/lib.rs` (Task 1 declares `pub mod userpack;` with an empty file), `crates/cli/src/eval.rs` (Tasks 5 and 6: Task 5 owns `EvalRequest` and `engine_for`; Task 6 only calls them).

---

### Task 1: the pack schema keys and the profile filter (size M)

**Files:**
- Modify `crates/guard/src/pack_raw.rs`, `crates/guard/build.rs`, `crates/guard/src/pack.rs` (`HostFilter`, `load_raw`, `Pack`, `PackWarning`, `PackError`, new `load_pack_in`), `crates/guard/src/profile.rs`, `crates/guard/src/wrappers.rs`, `crates/guard/src/lib.rs`.
- Create `crates/guard/src/userpack.rs` (one `//!` line; Task 2 fills it).
- Test: unit tests in `pack.rs` and `profile.rs`; `crates/guard/tests/prebuilt_packs.rs`.

**Interfaces (Produces):**
- `pack_raw.rs`:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)] #[serde(rename_all = "lowercase")] pub enum RuleWhere { Host, Everywhere }`.
  - `#[derive(Debug, Clone, PartialEq, Deserialize)] #[serde(deny_unknown_fields)] pub struct RawSource { pub file: Str, pub line: u32, pub line_sha256: Str }`.
  - `#[serde(deny_unknown_fields)] pub struct RawImport { pub file: Str, pub sha256: Str }`.
  - `#[derive(…, Copy, Eq)] #[serde(rename_all = "snake_case")] pub enum UnenforcedWhy { Judgement, Skipped, Unverified }`.
  - `#[serde(deny_unknown_fields)] pub struct RawUnenforced { pub source: RawSource, pub text: Str, pub why: UnenforcedWhy }`.
  - `RawRule` gains `#[serde(default, rename = "where")] pub where_: Option<RuleWhere>`, `#[serde(default)] pub source: Option<RawSource>` and `#[serde(default)] pub ask: bool`.
  - `RawPathRule` gains `where_` and `source` (the same attributes).
  - `RawPackFile` gains `#[serde(default)] pub import: Option<RawImport>` and `#[serde(default)] pub unenforced: List<RawUnenforced>`.
- `profile.rs`: `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum Profile { #[default] Host, Box }`, with `pub fn from_name(s: &str) -> Option<Profile>` (`"host"`, `"box"`) and `pub fn name(self) -> &'static str`. Also `impl RuleWhere { pub fn applies_in(self, p: Profile) -> bool }`, which is false only for `(Host, Box)`. Re-export `RuleWhere`, `RawSource`, `UnenforcedWhy` from `pack`.
- `pack.rs`:
  - `pub fn load_pack_in(source: &str, toml_str: &str, style: PathStyle, profile: Profile, warnings: &mut Vec<PackWarning>) -> Result<Pack, PackError>`. `load_pack_for` calls it with `Profile::Host`.
  - `HostFilter` gets `profile`, and `notes(platform, where_)` keeps a rule only if both apply. A rule left out by profile is counted in `left_out`, with no warning.
  - `Pack` gains `pub ask_ids: Vec<String>`: the ids of kept `[[deny]]` rules with `ask = true`.
  - `PackError::AskWithoutId(String)` (the pattern): "`ask = true` needs an `id`". It is also an error on `[[allow]]`, because only a deny can be asked.
  - `PackWarning` gains `pub dropped: bool`. It is `true` where a rule or a pack was dropped (an uncompilable regex, a bad glob, a skipped pack in `load_packs_dir` and `builtins.rs:255`), and `false` for "not in force on this host". Every `PackWarning {` literal (15) sets it.
- `wrappers.rs`: `pub fn is_transparent(name: &str) -> bool` (lowercased name in `TRANSPARENT_PREFIXES`).
- `build.rs`: `rule()` and `path_rule()` panic with `"<source>: <key> is a user-pack key; built-in packs may not use it"` if `where_`, `source` or `ask` is set, and so does `pack()` for a non-empty `import` or `unenforced`. The emitted literals add `where_: None, source: None, ask: false` and `import: None, unenforced: Cow::Borrowed(&[])`.

- [ ] **Step 1: Write the failing tests:**
  - `where_and_source_parse`: a pack with `[[deny]] id = "a", pattern = '^x\b', reason = "r", where = "host", source = { file = "/p/CLAUDE.md", line = 3, line_sha256 = "ab" }` loads with `Profile::Host` and has 1 deny;
  - `unknown_where_fails_the_load`: `where = "vm"` gives `Err(PackError::Toml(_))`;
  - `box_profile_drops_host_rules_only` (Review Focus 4): a pack with one `host` and one `everywhere` deny, plus one `host` deny_path, loaded with `Profile::Box`, has 1 deny and 0 deny_path. A pack whose only rule is `host` loads in `Box` with 0 rules and is not `NoRules`;
  - `ask_ids_listed`: `ask = true` on deny `a` gives `ask_ids == ["a"]`; `ask = true` with no id gives `AskWithoutId`, and so does `ask` on an `[[allow]]`;
  - `left_out_warning_is_not_dropped`: a `platform = "windows"` rule loaded for `PathStyle::Posix` gives a warning with `dropped == false`, and a bad regex gives one with `dropped == true`;
  - `import_and_unenforced_parse`: `[import] file = "/p/CLAUDE.md", sha256 = "cd"` and `[[unenforced]] source = {…}, text = "be nice", why = "judgement"` load; `why = "maybe"` fails;
  - `builtins_keep_every_rule_in_box_profile` (in `prebuilt_packs.rs`, Review Focus 4): for every built-in pack, `load_pack_in(.., Profile::Box, ..)` of its TOML gives the same `rule_count()` as `Profile::Host`;
  - `is_transparent_names_the_wrappers`: `sudo`, `ENV`, `timeout` give true; `pkill` and `git` give false.
- [ ] **Step 2: Run** `cargo test -p saiife-guard -j 4 -- --test-threads=4`. Expect FAIL to compile (the new items do not exist).
- [ ] **Step 3: Implement** the items above. The build-time refusal is checked by hand once (temporarily add `where = "host"` to a copy of a pack under `$TMPDIR`; do not commit it). The panic message is pinned by a unit test of a helper `fn user_key_in_builtin(r: &RawRule) -> Option<&'static str>`, which `build.rs` includes via `#[path]` like `pack_raw.rs`.
- [ ] **Step 4: Run** the tests → PASS; `bash scripts/check-windows.sh -p saiife-guard` is clean.
- [ ] **Step 5: Commit** `feat(guard): user-pack keys (where, source, ask, import, unenforced) and the box profile filter`.

### Task 2: strict user-pack loading and the compile cache (size M)

**Files:** Modify `crates/guard/src/userpack.rs`. Test: unit tests there, and `crates/guard/tests/user_packs.rs` (new).

**Interfaces:**
- Consumes `load_pack_in`, `Profile`, `PackWarning.dropped`, `Pack.ask_ids` (Task 1).
- Produces:
  - `pub const USER_PREFIX: &str = "user.";`, `pub const MAX_USER_RULES: usize = 128;`;
  - `pub fn valid_user_pack_id(id: &str) -> bool`: `user.` plus 1 to 48 of `[a-z0-9-]`, not starting with `-`;
  - `#[derive(Debug, Clone, Copy)] pub struct UserSrc<'a> { pub source: &'a str, pub text: &'a str }`;
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct UserPackError { pub source: String, pub message: String }`, with `Display` `"user pack {source}: {message}"` and `std::error::Error`;
  - `pub fn load_user_packs(srcs: &[UserSrc], style: PathStyle, profile: Profile) -> Result<Vec<Pack>, UserPackError>`. In input order, it fails on the first of:
    - a `PackError`;
    - any warning with `dropped`;
    - an invalid id;
    - a duplicate id;
    - `default_on = false` (message `a user pack is always on; remove default_on`);
    - `lazy = true`;
    - a `[[deny]]` without `id` (message `every [[deny]] in a user pack needs an id`);
    - more than `MAX_USER_RULES` rules (`rule_count()` summed; message names the total and the cap).

    Warnings that are not `dropped` are ignored;
  - `pub fn load_user_packs_cached(srcs: &[UserSrc], style: PathStyle, profile: Profile) -> Result<Vec<Pack>, UserPackError>`: the same result, kept in a process-wide `static LAST: Mutex<Option<([u8; 32], Result<Vec<Pack>, UserPackError>)>>`. The key is SHA-256 over `style`, `profile.name()`, and for each src `source`, `\0`, `text`, `\0`. A poisoned lock falls back to `load_user_packs`.

- [ ] **Step 1: Write the failing tests** (`tests/user_packs.rs` builds the engine as `Engine::new(builtins ++ user)`, with builtins from `Catalog::builtin().load_active(&[])`):
  - `user_deny_blocks_with_its_reason`: pack `user.t`, deny `id = "l3-1"`, `pattern = '^deploy-prod(?:\s|$)'`, `reason = "CLAUDE.md:3 \"Never run deploy-prod\""`, `triggers = ["deploy-prod"]` (a made-up command, so no built-in claims it). `evaluate("deploy-prod --now")` is `Deny { pack: "user.t", reason: <that>, .. }`; `evaluate("echo deploy-prod")` is `Allow`;
  - `user_allow_cannot_exempt_builtin` (Review Focus 2): user pack with `[[allow]] pattern = '^git\s+reset'`. `evaluate("git reset --hard")` is still `Deny { pack: "core.git", .. }`;
  - `user_pack_id_must_be_user_prefixed` (Review Focus 2): `id = "core.git"` and `id = "user."` give `Err` naming the id; `user.ok-1` is fine;
  - `broken_regex_is_an_error_not_a_drop`: `pattern = '('` gives `Err` whose message contains `uncompilable`;
  - `duplicate_ids_and_caps`: two packs with the same id give `Err`; 129 rules give `Err` naming `128`; `default_on = false` and a deny without `id` give the messages above;
  - `cache_hits_on_same_input` (unit test): two calls with equal srcs give equal `Vec<Pack>` ids. A changed text gives the new result. `crate::pack::compiled_packs()` (thread-local counter) rises by 1 on a hit-free call and by 0 on a hit.
- [ ] **Step 2: Run** `cargo test -p saiife-guard -j 4 -- --test-threads=4`. Expect FAIL.
- [ ] **Step 3: Implement** `userpack.rs`.
  - Parse once with `parse_pack` and check the header fields on the `RawPackFile`. Then compile with `load_raw` (made `pub(crate)`, `shipped = false`, `Compile::Now`), and bump the test-only `COMPILED` counter there, as `load_pack_for` does.
  - If `Pack` turns out not to be `Send` (it holds `Cell`s in `RuleRegex`), make the cache a `thread_local!`: `__eval --serve` judges on one thread.
- [ ] **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(guard): strict user-pack loading (fail closed on any broken rule) with a compile cache`.

### Task 3: box status, diff-review hits and broad-rule findings (size M)

**Files:** Modify `crates/guard/src/userpack.rs`. Test: unit tests there.

**Interfaces:**
- Consumes Task 2.
- Produces (plan 33 uses all of them, and step 3's diff review uses `diff_hits`):
  - read-only view, parsed without compiling: `pub fn view(text: &str) -> Result<UserPackView, UserPackError>` with
    ```rust
    pub struct UserPackView { pub id: String, pub name: String, pub import: Option<ImportRef>, pub rules: Vec<UserRuleView>, pub unenforced: Vec<UnenforcedView> }
    pub struct ImportRef { pub file: String, pub sha256: String }
    pub struct SourceRef { pub file: String, pub line: u32, pub line_sha256: String }
    pub enum RuleKind { Allow, Deny, AllowPath(RuleAccess), DenyPath(RuleAccess) }
    pub struct UserRuleView { pub id: Option<String>, pub kind: RuleKind, pub text: String /* pattern or glob */, pub reason: String, pub where_: RuleWhere /* default Everywhere */, pub ask: bool, pub source: Option<SourceRef> }
    pub struct UnenforcedView { pub source: SourceRef, pub text: String, pub why: UnenforcedWhy }
    ```
    (all `Debug, Clone, PartialEq, Eq`);
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum BoxStatus { OffInBoxes, DiffReview, Advisory }`, with `pub fn label(self) -> &'static str`: `"off in boxes (host only)"`, `"checked at diff review"`, `"advisory in boxes"`;
  - `pub fn box_status(r: &UserRuleView) -> BoxStatus` (D8). An `Allow*` is reported as its pack's carve-out: `Advisory`;
  - `pub struct DiffHit { pub path: String, pub pack: String, pub reason: String }`;
  - `pub fn diff_hits(packs: &[Pack], repo_root: &Path, home: &Path, rel_paths: &[&str]) -> Vec<DiffHit>`. The packs are expected to be loaded with `Profile::Box`. It builds one `Engine` with `PathVars::new().with_cwd(repo_root).with_var("PROJECT", repo_root).with_var("HOME", home)`. Each `rel_path` is joined to `repo_root` and judged with `evaluate_path(Access::Write, ..)`, and each `Deny` is a hit. An `rel_path` that is absolute or holds a `..` component is a hit with `pack = "saiife"` and reason `path leaves the repo`: never trust a diff path;
  - `pub struct Broad { pub rule: String, pub example: String }`;
  - `pub fn broad_findings(pack: &Pack) -> Vec<Broad>`. It judges these probes with an engine of `pack` alone, with `HOME=/saiife-probe/home`, `PROJECT=/saiife-probe/project` and cwd `PROJECT`, and reports every probe the pack denies, with the deny's pattern or glob:
    ```rust
    pub const EVERYDAY_COMMANDS: &[&str] = &["ls", "ls -la", "cat README.md", "cd src", "pwd", "echo hi", "git status", "git diff", "git log", "grep -r todo .", "cargo build", "cargo test", "npm test", "make", "python3 main.py"];
    pub const EVERYDAY_PATHS: &[(&str, Access)] = &[("$PROJECT/src/main.rs", Access::Write), ("$PROJECT/README.md", Access::Read), ("~/notes.txt", Access::Read), ("/tmp/x", Access::Write)];
    ```
    `$PROJECT` and `~` are expanded to the probe roots before judging.

- [ ] **Step 1: Write the failing tests:**
  - `view_reads_every_key`: one pack with an `[import]`, a `host` ask deny, an everywhere `deny_path` `access = "write"` and an `[[unenforced]]` gives the matching view. `where` absent reads as `Everywhere`;
  - `box_status_per_kind`: `host` deny → `OffInBoxes`; everywhere deny → `Advisory`; everywhere deny_path with `write`, `any`, `replace` or `content` → `DiffReview`; with `read` → `Advisory`;
  - `diff_hits_flags_protected_paths`: a user pack with `deny_path glob = "**/.git/hooks/**"` and `glob = "$PROJECT/CLAUDE.md"` (`access = "write"`), loaded with `Profile::Box`. `rel_paths = ["src/a.rs", ".git/hooks/pre-commit", "CLAUDE.md"]` gives hits for the last two only, each naming `user.t` and the reason;
  - `diff_hits_refuses_escaping_paths`: `"../x"` and `"/etc/passwd"` are hits with reason `path leaves the repo`;
  - `diff_hits_skips_host_rules`: the same glob marked `where = "host"`, loaded with `Box`, gives no hit;
  - `broad_findings_flag_the_hostile`: deny `^\S+` gives `Broad { example: "ls", .. }` first; `deny_path glob = "/**"` gives a finding with example `/saiife-probe/project/src/main.rs`; deny `^pkill(?:\s|$)` gives none.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(guard): user-pack view, box status, diff-review hits and broad-rule findings`.

### Task 4: reading, hashing and `ask` in the policy; layout and doctor (size M)

**Files:**
- Create `crates/policy/src/userpacks.rs`.
- Modify:
  - `crates/policy/src/lib.rs` (`pub mod userpacks; pub use userpacks::{UserPackFile, USER_PACKS_DIR};`);
  - `crates/policy/src/load.rs` (`read_regular`, `dropin_paths` → `pub(crate)`; `load_system_with` reads the packs);
  - `crates/policy/src/system.rs` (`SystemConfig.user_packs`);
  - `crates/policy/src/effective.rs` (`PackInfo.sha256`, `active_packs`, `effective_policy`);
  - every `PackInfo {` literal: `crates/cli/src/{policy_cmd.rs, status_cmd.rs, check_managed.rs, main.rs}`, `crates/policy/tests/{environments.rs, load.rs}`, `crates/daemon/tests/windows_daemon.rs`, `effective.rs` tests;
  - `crates/system/src/layout.rs`, `crates/system/src/doctor/system.rs:380-404`, `crates/system/src/personal.rs`.
- Test: unit tests in `userpacks.rs`; `crates/policy/tests/load.rs`; doctor unit tests in `doctor/system.rs`.

**Interfaces:**
- Produces:
  - `pub const USER_PACKS_DIR: &str = "packs";` (below the drop-in dir), `pub const MAX_USER_PACKS: usize = 32;`, `pub const MAX_USER_PACK_BYTES: usize = 256 * 1024;` (all files together);
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct UserPackFile { pub path: String, pub sha256: String, pub text: String, pub id: String, pub version: u32, pub rules: Vec<String> /* [[deny]] ids */, pub ask: Vec<String> /* ids with ask = true */ }`;
  - `pub fn read_user_packs(dir: &Path, files: &mut Vec<(String, String)>) -> Result<Vec<UserPackFile>, PolicyError>`. It lists with `dropin_paths(dir)` (missing dir → empty; symlinked dir refused; dot-files skipped) and reads each with `read_policy_file` (records `(path, sha256)`). It then does a light `toml::Table` parse:
    - `[pack] id` must be a string with `user.` + `[a-z0-9-]{1,48}`, not starting with `-` (the same rule as `saiifeguard::userpack::valid_user_pack_id`, re-stated here with a test for each, since policy does not depend on guard);
    - `version` is an integer ≥ 1, default 1;
    - `[[deny]] id`, plus `ask = true` with no `id`, is `Invalid`.

    It is also `Invalid` (naming the file) on a duplicate id, more than 32 files, or more than 256 KiB in total;
  - `pub fn pack_infos(cfg: &SystemConfig) -> Vec<PackInfo>`: `default_on: true`, `rules` = deny ids, `sha256: Some(file sha256)`;
  - `SystemConfig`: `#[serde(skip)] pub user_packs: Vec<UserPackFile>`;
  - `load_system_with`, after the drop-in loop:
    1. `cfg.user_packs = read_user_packs(&dropin_dir.join(USER_PACKS_DIR), &mut files)?`;
    2. for each pack and each `ask` id, push `"<pack id>/<rule id>"` to `cfg.guard.ask` if it is not there.

    This runs before the `[guard] ask` shape check (`load.rs:254`), so the `NO_APPROVERS_WARNING` covers user asks;
  - `PackInfo` gains `pub sha256: Option<String>`. `active_packs` adds `pack_infos(cfg)` to the active set: every user pack is active, in id order, and a user id that is also in `catalog` is impossible (prefix). `effective_policy` writes `{"id","version","sha256"}` for a pack with `sha256`, and `{"id","version"}` otherwise;
  - `saiife_system::layout::POLICY_PACKS_D: &str = "/etc/saiife/policy.d/packs"`. `doctor` checks the dir and every `*.toml` in it for root ownership and no symlink, exactly as for `POLICY_D`;
  - `saiife_system::personal::user_packs_dir(p: &PersonalPaths) -> PathBuf`: `<p.config's dir>/policy.d/packs`.

- [ ] **Step 1: Write the failing tests:**
  - `reads_user_packs_below_policy_d` (`tests/load.rs`): `config.toml` + `policy.d/packs/user.a.toml` (deny `l1-1`, `ask = true`). `load_system` gives `user_packs.len() == 1`, `files` holding the pack's path and SHA-256, and `guard.ask` containing `"user.a/l1-1"`;
  - `a_pack_in_policy_d_itself_is_still_a_drop_in_error`: `policy.d/user.a.toml` (pack format) gives `PolicyError::Parse`, unchanged from today (pins D1);
  - `symlinked_pack_file_is_refused` (Review Focus 1), `symlinked_packs_dir_is_refused` (`#[cfg(unix)]`), and `pack_text_cap`: 33 files, or 257 KiB in total, give `Invalid` naming `packs`;
  - `user_pack_header_rules`: id `core.git`, `user.`, `user.-x` and a duplicate id are `Invalid`; `ask` with no id is `Invalid`;
  - `user_packs_key_in_config_is_unknown`: a `config.toml` with `user_packs = []` is a `Parse` error (F7);
  - `hash_unchanged_without_user_packs` (Review Focus 3, in `effective.rs` tests): `hash_of(CFG_A …)` equals the literal it had on the parent commit (run once on the parent and paste the value, with a comment saying so);
  - `hash_changes_with_user_pack_bytes`: the same config with one user pack, then the same pack with one byte changed, gives three different hashes;
  - `user_packs_are_active_and_askable`: `check_guard_ask(&cfg, &builtin catalog)` is `Ok` when the only ask is the merged user one;
  - doctor: `group_writable_user_pack_fails`, mirroring `group_writable_policy_drop_in_fails` (`doctor/system.rs:1801`) for `policy.d/packs/user.a.toml`.
- [ ] **Step 2: Run** `cargo test -p saiife-policy -p saiife-system -j 4 -- --test-threads=4`. Expect FAIL.
- [ ] **Step 3: Implement.** Update the 10 `PackInfo` literals with `sha256: None`. The daemon needs no code change (F9): its `load_policy` and `check_ask` go through `load_and_check` and `active_packs`.
- [ ] **Step 4: Run** the two crates, plus `cargo test -p saiife-daemon -j 4 -- --test-threads=4` (the literal in `windows_daemon.rs` and the reload path) → PASS. Run `bash scripts/check-windows.sh -p saiife-policy -p saiife-system`.
- [ ] **Step 5: Commit** `feat(policy): user packs from policy.d/packs: read, hashed, always active, ask ids merged`.

### Task 5: the managed hook and the worker (size M)

**Files:**
- Modify `crates/cli/src/eval.rs` (`EvalRequest`, `MAX_EVAL_BYTES`, `judge_in`, `engine_for`), `crates/cli/src/check_managed.rs:735-750` (the request), `crates/cli/src/rejudge.rs:533` (the request).
- Test: `crates/cli/tests/check_managed.rs`, unit tests in `eval.rs`, `crates/cli/tests/rejudge_pool.rs` (one case).

**Interfaces:**
- Consumes `SystemConfig.user_packs` (Task 4), `load_user_packs_cached`, `UserSrc` (Task 2).
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct UserPackSrc { pub source: String, pub text: String }`;
  - `EvalRequest.user_packs: Vec<UserPackSrc>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`);
  - `pub const MAX_EVAL_BYTES: usize = 2 * PARSE_MAX_BYTES + 2 * saiife_policy::userpacks::MAX_USER_PACK_BYTES + 64 * 1024;`;
  - `engine_for` takes `user: &[UserPackSrc]` and `profile: Profile`, and returns `Result<(Engine, PathVars), String>`. The packs are the built-ins from `load_active(packs)`, then `load_user_packs_cached(.., PathStyle::host(), profile)`, appended. On `Err(e)`, `judge_in` answers `Verdict::Unjudged` with `reason = e.to_string()`;
  - `judge_call` sets `user_packs` from `cfg.user_packs` (`source = path`, `text`), and sets it empty for a `config-change` event, exactly like `packs`. `rejudge.rs` does the same from its `cfg`. The managed and re-judge paths pass `Profile::Host`.

- [ ] **Step 1: Write the failing tests** (`tests/check_managed.rs`, with the existing `managed(config, stdin)` and `TestDaemon` helpers; the pack goes in `<fixture etc>/policy.d/packs/user.t.toml`):
  - `managed_user_pack_denies_with_source_reason`: a Bash `deploy-prod --now` gives exit 2, stderr `BLOCKED by user.t: CLAUDE.md:3 "Never run deploy-prod"`, and a guard record with `pack == "user.t"` and `rule_id == "l3-1"`;
  - `managed_broken_user_pack_denies_every_call` (Review Focus 1): the pack with `pattern = '('`. A harmless `ls` gives exit 2, and the record is `error_denied` with a reason containing `user pack` and the file name;
  - `managed_user_ask_rule_creates_a_request` (Review Focus 5): the pack's deny with `ask = true`, and a config with an approver. The call is denied with `Needs approval: request #`, and `approval.list` on the daemon shows one pending request naming `user.t`;
  - `managed_hash_names_the_user_pack`: a record's `policy` differs with and without the pack, and is equal for two calls with the same pack;
  - `eval.rs` unit test `request_without_user_packs_serializes_as_before`: `serde_json::to_string` of an `EvalRequest` with no user packs has no `user_packs` key;
  - `rejudge_pool.rs`: `serve_judges_user_packs`. Two frames to `__eval --serve` carry the same `user_packs` and payload `deploy-prod --now`. Both answers are `deny` by `user.t`. The second frame hits the compile cache, which the result cannot show; the cache itself is pinned by Task 2's `cache_hits_on_same_input`.
- [ ] **Step 2: Run** `cargo test -p saiife -j 4 -- --test-threads=4 check_managed rejudge eval`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; clippy clean; `bash scripts/check-windows.sh -p saiife`.
- [ ] **Step 5: Commit** `feat(hook): the managed hook and the worker enforce user packs, fail closed`.

### Task 6: developer hook, `--profile`, `test`/`explain`/`packs`, `policy check`, docs (size M)

**Files:**
- Modify:
  - `crates/cli/src/check.rs` (`engine_for`, `policy_hash`, `active_engine`, args);
  - `crates/cli/src/main.rs` (`Cmd::Check` and `Cmd::Explain` get `--profile`; lines 680-691 add user packs to `packs` for `test`/`explain`/`packs`);
  - `crates/cli/src/packs_cmd.rs` (user packs listed with a `user` marker);
  - `crates/cli/src/policy_cmd.rs:294-333` (`check` compiles `cfg.user_packs` for both profiles).
- Create `docs/never-rules.md` (sections "User packs", "Boxes"; plan 33 adds "Import" and "Sync") and a README link.
- Test: `crates/cli/tests/check_project.rs` (developer hook), `crates/cli/tests/explain_paths.rs`, `crates/cli/tests/packs_cmd.rs`, `crates/cli/tests/policy_cmd.rs`, unit tests in `check.rs`.

**Interfaces:**
- Consumes Tasks 2, 4 and 5 (`engine_for` in `eval.rs` is not used here; the developer hook has its own `check.rs::engine_for`).
- Produces:
  - `saiife check [--profile host|box]` (hidden, `value_parser = ["host", "box"]`, default `host`) and `saiife explain [--profile host|box]` (visible);
  - `pub(crate) fn dev_user_packs() -> Result<Vec<saiife_policy::UserPackFile>, String>` in `check.rs`, which reads `saiife_system::personal::user_packs_dir(&personal_paths(&|k| std::env::var_os(k), home)?)` with `read_user_packs`. No home means no packs;
  - The developer hook's packs are the built-ins, then the user packs loaded with `load_user_packs(.., profile)`. A user-pack error goes through `Fail::unjudged` with the reason `user pack …` and the open warning `user pack … not loaded; failing open (allow)` (D3).
  - A deny by a rule whose `<pack>/<id>` is in that pack's `ask_ids` gets its reason suffixed with ` (needs approval; approvals need locked mode)`;
  - `fn policy_hash(version: &str, active_pack_ids: &[&str], config: &str, user: &[(&str, &str)] /* (id, sha256) */, profile: Profile) -> String`. The text appends `user <id> <sha256>\n` per user pack, sorted by id, then `profile box\n` when `Box`. With no user packs and `Host`, the text is exactly today's;
  - `policy check` adds `errors` for each `load_user_packs` failure (with `Host` and with `Box`). On success with N > 0 user packs, the `ok:` line ends `, N user packs)` instead of `)`. With N = 0 the line is unchanged.

- [ ] **Step 1: Write the failing tests:**
  - `dev_hook_enforces_personal_user_pack` (`check_project.rs`, `Env::new(&["claude"])`): the pack at `<env.home>/.config/saiife/broker/policy.d/packs/user.t.toml`. A Claude Bash payload `deploy-prod --now` is denied with the source reason;
  - `dev_broken_user_pack_fails_open_with_warning`: `pattern = '('` lets the call through, with stderr containing `user pack` and `failing open`, and an `error_allowed` record;
  - `dev_ask_rule_denies_with_note` (Review Focus 5): a deny with `ask = true` gives a reason ending `(needs approval; approvals need locked mode)`;
  - `check.rs` unit tests: `dev_hash_unchanged_without_user_packs`: `policy_hash("1", &["b","a"], CONFIG_NONE, &[], Profile::Host)` equals the existing `policy_hash_text_is_exact` value; `dev_hash_names_the_box_profile` (Review Focus 4): the same with `Profile::Box` hashes the text plus `profile box\n`; `dev_hash_lists_user_packs`;
  - `explain_box_profile_skips_host_rules` (`explain_paths.rs`): a `where = "host"` deny. `explain "deploy-prod --now"` shows `user.t`, and with `--profile box` shows no match;
  - `packs_lists_user_packs` (`packs_cmd.rs`): `saiife packs` lists `user.t` with its rule count; `saiife packs user.t` lists its rules;
  - `policy_check_reports_a_broken_user_pack` (`policy_cmd.rs`): exit 1 and stderr `saiife: error: user pack …uncompilable…`; a good one gives `ok: … 1 user packs)`.
- [ ] **Step 2: Run** `cargo test -p saiife -j 4 -- --test-threads=4 check_project explain_paths packs_cmd policy_cmd check::`. Expect FAIL.
- [ ] **Step 3: Implement.** `docs/never-rules.md`:
  - "User packs": the file format with every key and one full example; where the files live (D1); fail closed in locked mode and open in developer mode (D3); `ask` (D7); the caps;
  - "Boxes": `where`, the three box statuses (D8), and that a rule shown as "advisory in boxes" is not enforced there.

  Link it from `README.md`.
- [ ] **Step 4: Run** → PASS; the docs tests (`cargo test -p saiife docs_wording`) and `bash scripts/check-windows.sh -p saiife` pass.
- [ ] **Step 5: Commit** `feat(cli): user packs in the developer hook, explain/test/packs, policy check; --profile box`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP as in Global Constraints, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`):
  - `cargo fmt --all --check`;
  - `cargo clippy --workspace --all-targets -j 4 -- -D warnings`;
  - `cargo test -p saiife-guard -p saiife-policy -p saiife-system -p saiife-daemon -p saiife -j 4 -- --test-threads=4`;
  - the CI tokio gate (`.github/workflows/ci.yml:151`) prints `0`;
  - `bash scripts/check-unsafe.sh`;
  - `bash scripts/check-windows.sh -p saiife-guard -p saiife-policy -p saiife-system -p saiife`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR to `v3-dev`. The owner merges.

## Follow-ups (not in this plan)

- Spec §10.6 later rule types: a tool-name deny, a cwd/env condition, and a content scan on Write/Edit. Each is a schema change to `RawRule`.
- Step 3 (boxes):
  - call `diff_hits` in the `land` review and show the hits in the touch summary;
  - write the in-box hook with `--profile box`.
- Workspace (plan 30): showing "advisory in boxes" there needs a field the plan 28 DTOs do not have. That is a contract change through the coordinator.

## Owner handwork

- [ ] Decide D6 (keep `profile` reserved in `config.toml`).
- [ ] With 128 user rules installed (`scripts/` has no generator; copy one rule 128 times with distinct ids), run `scripts/bench-check.sh --managed` yourself. The managed p95 must stay under 40 ms (#44). If it does not, cut `MAX_USER_RULES`, or make user packs lazy by trigger (`lazy = true` with `Compile::OnFirstUse`).
