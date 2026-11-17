# Plan 39: diff out, review, land with a touch, push (v3 step 3, VM half 5 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Reconciled 2026-11-12** against `v3-dev` (plans 26–29, 32 merged), plan 34 on `v3-p34` (`ee5e264`; rulings R8, R18, R20, R25), plan 27's rulings and the reconciled plan 31. Changes:
> 1. Names checked: `TouchState::issue(key, uid, class, summary, fields, now) -> Result<Issued, String>`, `consume(&key, uid, build, &asr, rp_id, now) -> Result<(TouchEvidence, ActionRecord), TouchError>`, `take(&key, uid)`, `verify_counted(..)` (`crates/daemon/src/touch.rs:191-278`); `IssueKey` today is `{Approve(u64), Enrol(u32), Remove(u32), Test(u32)}` (`touch.rs:40`) and plan 31 adds `Web { device, request_id }` to the same enum; `approvals::record_with_touch(rec, &ev)` (`approvals.rs:476`); `TouchRequest` (`crates/touch/src/client.rs:11`); `LOCAL_RP_ID` (`lib.rs`).
> 2. Plan 32 names as merged: `saiifeguard::userpack::load_user_packs(srcs, style, Profile::Box)` (`crates/guard/src/userpack.rs:63`), `diff_hits(packs, repo_root, home, rel_paths) -> Vec<DiffHit { path, pack, reason }>` (`:402`, `:392`), `saiifeguard::profile::Profile::Box` (`profile.rs:14`), `BoxStatus::DiffReview` (`userpack.rs:363`). `diff_hits` needs the repo root and home: the daemon passes the box's `repo_dir` (or `/work` when it has none) and the owner's home.
> 3. Control-socket ops take the box id under `box` (plan 34 R25: the envelope's `id` overwrites an `id` argument, `crates/ipc/src/msg.rs:318-322`) and nest any answer that carries an `id` (R20: `msg::ok` drops a top-level `id`, `msg.rs:384-393`): `LandInfo` is answered as `{land: LandInfo}`; `box.diff` keeps plan 34's `{diff: DiffSummary}` (`box_ops.rs:960-965`) and adds `review`.
> 4. `land_ops_are_machine_only` was wrong for three names: `box.diff` (Signed), `box.land` and `box.push` (Touch) are remote frame actions in `saiife_wire::level::REMOTE` (`crates/wire/src/level.rs`); only the new `box.land.*`/`box.push.*` sub-ops are MachineOnly. Test rewritten.
> 5. **Already in plan 34 (not rebuilt):** `BoxRecord.image`, `Change.image` (unused here); `Event::Land` in the state machine (`state.rs:14`). **Not in plan 34 (still this plan's):** `Manager::land`, `ManagerSource::with_lands` (R8 "not taken").
> 6. `ManagerSource` is built per call in `box_ops` (`info_of`, `Diff`, `TermRead`: `ManagerSource::new(m, None)`, `box_ops.rs:629-636`, `:960-973`) and owner-scoped for the Workspace (R18); `with_lands` must be applied at every construction, so the daemon keeps the book in `Ctx` (`box_lands: Option<Arc<Lands>>`), and an owner-scoped source's `pending` lists only that owner's records.
> 7. Workspace path (plan 31 Task 5): plan 31 verifies the WebAuthn assertion with `verify_counted` against `PendingAction.record` and then calls `complete`; `Lands::complete` must also burn the CLI-path entry (`ctx.touch.take(&IssueKey::Land(rid), owner)`) so one request cannot be approved twice through two paths.
> 8. L8 interaction: plan 26's per-uid live-entry limit (`MAX_PER_UID`, `crates/daemon/src/touch.rs:28`) is shared with CLI approvals and plan 31's Workspace touches. **Owner ruling 2026-11-12:** plan 31 Task 2 raises it from 4 to 8, so `pending` issues land records for at most **4** `Done` boxes per owner again (the earlier reconciliation's 2 is withdrawn), leaving 4 slots for other touches.
> 9. Plan 27's CLI touch client is `touch_cmd::pick() -> Result<Box<dyn Touch>, String>`, `run_touch`, `exit_for` (`crates/cli/src/touch_cmd.rs:358`, `:386`, `:406`). **Owner ruling 2026-11-12 (resolves the conflict):** `fido-hid` is off in Linux release builds (plan 27 D1/R-A, `release.yml:97` enables it for `apple-darwin` only), and boxes are Linux-only. Plan 41 (`2026-11-12-plan-41-linux-fido-helper.md`) builds the packaged FIDO helper that gives a static Linux `saiife` key support. Until plan 41 lands, and afterwards on a Linux install without the helper (tarball, `install.sh`), `saiife box land` refuses with plan 27's D1 line plus a pointer to the Workspace (Face ID) and `saiife box apply` (Task 6, fixed text below). Tests use the soft authenticator and are unaffected. Boxes do not ship in a release before plan 41 is done (plan 35 header).
> 10. Global Constraints: branch `v3-p39`; builds with `CARGO_PROFILE_DEV_DEBUG=0`.

> **Hand-off to plan 31 (and plan 35), from the final review of this plan, 2026-11-13:**
> 1. Production `ctx.boxes` is built before `Ctx` exists (today `NoBoxes`, `start.rs`), while the land book is attached afterwards (`box_ops::attach_lands` sets `ctx.box_lands`, a `OnceLock`). Whoever replaces `ctx.boxes` with a real `ManagerSource` must look the book up at call time (`box_ops::source()` or `ctx.box_lands.get()` on each call), not once at build time. Otherwise the Workspace's `discard` bypasses the L4 guard (and its box lock, `LandBook::discard_with`), and `pending` and `complete` stay empty.
> 2. Plan 31's Workspace `complete` (its Task 5) must verify the WebAuthn touch only against a `PendingAction.record` that `pending()` listed, never against a record of a request it did not get from `pending()`. `Lands::complete(Approve, ..)` itself refuses any request that changes git config (`git_config` set): "land {id} changes git config; land it from the CLI: saiife box land {id} --allow-git-config".

> **Depends on:** plan 34 merged (`Manager`, `ManagerSource`, plan 28's kit); **plan 26** merged (`saiife_touch::{ActionRecord, TouchClass::{Land, PushProtected}, TouchEvidence}`, daemon `TouchState::{issue, consume}`, `approvals::record_with_touch`); **plan 27** (the CLI's touch client, for Task 6); **plan 32 Task 3** (`userpack::diff_hits`, `Profile::Box`); plan 37 Tasks 2–4 (`fdpass`, `BaseManifest`, `check_path`, the base ref); plan 38 Tasks 1, 3, 4 (`Request::{Export, Advance}`, the guest crate, `VsockGuest::request_stream`). Plan 31's Workspace land (its Task 5, `complete` after a WebAuthn touch) builds on Task 4; Workspace push is not built (plan 31 keeps `box.push` in `LATER`).
> **Soft dependency (owner ruling 2026-11-12):** plan 41 (`2026-11-12-plan-41-linux-fido-helper.md`, the packaged Linux FIDO helper). This plan builds and tests without it; without it a Linux release `saiife box land` refuses and points to the Workspace plus `saiife box apply` (Task 6). The CLI land path with a real key on a Linux release needs plan 41.

**Goal:** What the agent did comes out as untrusted data, is reviewed on the host, and lands only with a touch:
- the guest exports a tree diff against the last landed tree over vsock (binary-safe, untracked files included);
- the host validates it as hostile input (paths, `.git`, symlinks, sizes, and every old file checked against the spawn-time manifest), stores it, renders the unified diff itself, flags protected paths (`.claude/`, `CLAUDE.md`, workflow files, rule files) and plan 32's `diff_hits`, and computes `diff_sha256`;
- `saiife box diff | land [--files …] | apply | push` and plan 28's `BoxSource::{diff, pending_actions, complete}` work on real boxes; every land is bound to a `land` touch (`TouchClass::Land`, UV) over `{repo, base_commit, target_ref, diff_sha256}`; each land adds one commit to `saiife/box-<id>` (§7.7), written by the CLI as the user (§5.1), with no git hook or filter of the user's running on box content.

**Architecture:**
- **A tree delta, not a git patch** (decision L1). The guest sends, per changed path: the new content, and for a modified file the old content too. The host keeps the spawn manifest (plan 37) as the trusted base and refuses any delta whose old side does not match it, so the guest cannot misstate what it changed. The host renders the review from trusted old content and validated new content; `diff_sha256` = SHA-256 of that full rendering, in which binary files appear by size and SHA-256, so the hash binds every byte that lands.
- **The CLI builds the land commit with git plumbing** (`hash-object --no-filters`, a temporary index, `update-index --index-info`, `write-tree`, `commit-tree`) on top of `refs/saiife/box-<id>/base` or the previous land. No file is written by saiife code; checking the branch out into the worktree is git's own work, with `core.hooksPath=/dev/null` on every call. That is the spec's "own applier": git never parses the box's output, and no box-written `.git` exists.
- **One record type for local and Workspace lands.** A land request is issued in plan 26's `TouchState` under a new key `IssueKey::Land(request_id)`; the CLI path consumes it with a FIDO2 assertion, plan 31's Workspace path with WebAuthn, and both end in the same `Lands::approve`. A Workspace approval cannot write the user's repo, so it leaves the land "approved, not applied" until the CLI runs `saiife box apply` (decision L4).
- **`LandBook`** is a new trait in `saiife-boxes` that `ManagerSource` consults for `diff`, `pending_actions` and `complete` (plan 34 returned `Unavailable` / `vec![]` / `NotFound` there); the daemon implements it.

**Tech Stack:** Rust. **One new crate:** `similar = "=2.7.0"` (pure Rust, no deps) for line diffs (flagged). `ring` SHA-256, `serde_json`; git via plan 35's `Tools` (`Git`).

**Spec:** §5.1, §7.5, §7.7 (multi-land, revise), §8.2–§8.3 (land, push classes), §10.5 (protected paths at diff review), §12 (the adversarial importer suite), §15. Plan 28 Task 7 (`DiffSummary`, `FileChange`, `MAX_DIFF_BYTES`, `PendingAction`, the contract: "`diff_sha256` is SHA-256 of the full unified diff before truncation, the value the `land` `ActionRecord` binds") and its rulings R-F1 (revise and discard valid from `Landed`), R-T8b (the kit's land binding). Plan 26 D4 (UV for `land`), reserved field names. Plan 32 Task 3 (`diff_hits`, `BoxStatus::DiffReview`).

## Decisions

- **L1. Delta format** (`boxproto::delta`, frames of plan 38's codec): `{"t":"delta","n":<export n>,"entries":<count>}`; per entry `{"t":"entry","path","op":"add"|"modify"|"delete","kind":"file"|"symlink","mode":420|493|0,"size","sha256","old_kind","old_size","old_sha256"}` (the `old_*` fields `null` for `add`), then `Bytes` frames: `old_size` bytes of old content (`modify` only), then `size` bytes of new content (`add`, `modify`); a symlink's content is its target; then `{"t":"end","entries":<count>}`. Entries sorted by path bytes, each path once.
- **L2. Caps.** `MAX_ENTRIES = 20_000`, `MAX_FILE_BYTES = 64 MiB` (each side), `MAX_TOTAL_BYTES = 512 MiB` (new content), export time 120 s. Over a cap the whole delta is refused, naming the cap and the path.
- **L3. Validation of the resulting tree** (base manifest + delta): every path passes `manifest::check_path`; `add` only for paths not in the base, `modify`/`delete` only for paths in it with `old_kind`, `old_size`, `old_sha256` equal to the manifest; no path is both a file and a directory prefix of another; no path has a symlink as a proper prefix (no writing through a link); a symlink target is relative, has no NUL, ≤ 4096 bytes, and, resolved lexically from the link's directory, stays inside the repo; file modes 0o644/0o755 only. A `.git` component anywhere (any letter case) is refused, never "flagged".
- **L4. Workspace approvals are applied later.** `complete(Approve)` (plan 31 verifies the touch first) marks the land approved, moves the box to `Landed` (lands + 1) and advances the guest's base, exactly as a CLI land does; the commit is written when the user runs `saiife box apply <id>` (or the next `saiife box land`). `box ls` shows `approved, not applied: saiife box apply <id>`. A box with an approved, unapplied land cannot be discarded without `--force`. **Owner check.**
- **L5. `base_commit` in the record and the summary is the snapshot commit** (plan 37 D9), the exact tree the box started from; the user's `HEAD` at spawn is shown beside it.
- **L6. Protected paths** (built-in, always flagged and named in the touch summary; land still needs the same `land` touch, §10.5): `.claude/**`, `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.saiife/**`, `.github/workflows/**`, `.gitlab-ci.yml`, `.gitattributes`, `.gitmodules`, `.envrc`, `**/.git*` other than `.gitignore`, and any path plan 32's `diff_hits` names (user `deny_path` rules with write access, loaded with `Profile::Box`). Also flagged, not refused: a file becoming executable, a new symlink, a binary file, two paths that differ only in letter case.
- **L7. Push** (`saiife box push <id> [--remote origin]`): class `PushProtected`, fields `{repo, target_ref, remote}`, the summary names the commit; after the touch the CLI runs `git -c core.hooksPath=/dev/null push <remote> <commit>:refs/heads/saiife/box-<id>` as the user (§7.4: pushing happens on the host). `box pr` is not in this plan.
- **L8. Touch limits.** Land and push entries count against plan 26's live-entry limits (32 total, `MAX_LIVE` `touch.rs:27`; per uid `MAX_PER_UID` `touch.rs:28`, 8 after plan 31 Task 2, owner ruling 2026-11-12), shared with CLI approvals and plan 31's `IssueKey::Web` touches. `pending_actions` issues records for at most the **4** oldest `Done` boxes per owner (so 4 slots stay free for other touches); the rest appear as those are decided. **Contract addition to plan 26, owner-approved 2026-11-12:** `IssueKey::{Land(u64), Push(u64)}` (beside plan 31's `Web`).

## Contract changes (owner-approved 2026-11-12)

Owner-approved 2026-11-12 across plans 31, 35, 38 and 39: `TouchClass::Steer` (plan 31), `IssueKey::{Web, Land, Push}` (plans 31 and 39), `Vmm::image_id` (plan 36). Of those, this plan adds `IssueKey::{Land, Push}`.

| Item | Change | Why |
|---|---|---|
| plan 26 `IssueKey` | `+ Land(u64)`, `+ Push(u64)` (request ids) | one key space for CLI and Workspace touches (L8) |
| plan 34 `Manager` | `+ fn land(&self, id) -> Result<Change, BoxError>` (`Done`/`Landed` → `Landed`, `lands += 1`, via `Event::Land`) | the state machine had `Land` but no method |
| plan 34 `ManagerSource` | `+ fn with_lands(self, Arc<dyn LandBook>) -> ManagerSource`; with it, `diff`/`pending_actions`/`complete` go to the book and `discard` refuses an unapplied approved land | L4 |
| plan 34 `BoxError` use | `Invalid("box <id> has an approved land that is not applied …")` for that refusal | no new variant |

## Global Constraints

Plan 35's Global Constraints apply (including `CARGO_PROFILE_DEV_DEBUG=0`), with worktree `.worktrees/p39`, branch `v3-p39`, scratch prefix `p39-tN-`. Real `git` in tempdir repos is allowed in tests (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `HOME` at a tempdir). **No real touch device:** tests use plan 26's `SoftAuthenticator` (feature `soft`). `similar = "=2.7.0"` is the only new dependency.

### Fixed values

| Name | Value |
|---|---|
| caps | `MAX_ENTRIES = 20_000`, `MAX_FILE_BYTES = 64 << 20`, `MAX_TOTAL_BYTES = 512 << 20`, export timeout 120 s |
| text rule | both sides valid UTF-8, no NUL, each ≤ 1 MiB; else binary |
| unified header | `diff --saiife a/<p> b/<p>`; `new file mode 100644`, `deleted file mode 100755`, `old mode …`/`new mode …`; `--- a/<p>` or `--- /dev/null`; `+++ b/<p>` or `+++ /dev/null`; hunks with 3 context lines; `\ No newline at end of file` |
| binary line | `Binary file b/<p>: <size> bytes, sha256 <hex>` (deleted: `Binary file a/<p> deleted`) |
| symlink | rendered as a one-line text file whose content is the target, with mode `120000` in the header |
| land dir | `<record dir>/lands/<n>/` (0700; the box's record dir, `RecordPaths::of(<store root>, id)`, never the VMM runtime dir, R37): `blobs/<sha256>`, `delta.bin` (canonical, new content only, for the CLI), `review.json`, `request.json`, `approved.json`, `applied.json` |
| `target_ref` | `saiife/box-<id>` |
| land commit message | `saiife box <id>: land <n>\n\n<first line of the task, ≤ 72 chars>\n\nSaiife-Box: <id>\nSaiife-Land: <n>\nSaiife-Diff-Sha256: <sha>\n` |
| worktree | `$XDG_DATA_HOME/saiife/worktrees/<repo>-<id>` |
| git flags on every call | `-c core.hooksPath=/dev/null -c core.fsmonitor=false`, env `GIT_TERMINAL_PROMPT=0` |
| guest base | `/var/lib/saiife-guest/base.git` (bare-ish: `GIT_DIR` there, work tree `/work`), exports `refs/exports/<n>`, base `refs/base` |
| audit | `kind = "box"`; `diff_rejected` `{box, reason}`, `land` `{box, land, diff_sha256, files, via}` + `touch`, `land_rejected`, `land_applied` `{box, land, commit}`, `push` `{box, remote, commit, ok}` + `touch` |

## Review Focus

1. **A forged or hostile diff** (§12): `../x`, `/etc/passwd`, `.git/hooks/pre-commit`, `sub/.GIT/config`, a symlink `l -> ../../..` and then `l/x`, a symlink created in the base and written through, a file `a` added while `a/b` stays in the base, a duplicate path, unsorted entries, an `old_sha256` that differs from the manifest, a 65 MiB file, 20 001 entries, a stream cut in the middle, a `size` that disagrees with the bytes sent. Expected: each refused with its reason, nothing stored, one `diff_rejected` record (Task 1: one test per case; Task 3: `hostile_delta_stores_nothing`).
2. **A touch that does not match what lands:** the box writes more after `land.begin`; `--files a` approved then used for `--files a,b`; the request used twice; another user's assertion; an expired request; a Workspace `complete` for a stale review. Expected: refused (`touch_mismatch`, `touch_failed`, or `WrongState`), the diff never applied, and the next `land.begin` shows the new diff (Task 5: `later_writes_need_a_new_touch`, `subset_hash_is_bound`, `request_is_single_use`, `other_uid_is_refused`, `stale_complete_is_wrong_state`).
3. **The user's own git config acting on box content:** a `pre-commit`, `post-checkout`, `post-merge` and `pre-push` hook in the user's repo; a `.gitattributes` from the box naming a filter driver. Expected: no hook runs (marker files never appear); blobs are stored with `--no-filters`; the worktree checkout runs only what the user's own config defines, never a box-supplied driver (Task 6: `no_user_hook_runs`, `box_attributes_add_no_filter`).
4. **Base drift and multi-land:** two lands in a row; a revise in between; a per-file land leaving other files for later; a guest that "advances" its base to something else. Expected: the second review shows only changes since the first land; partial land leaves the rest in the next diff; a lying guest's next export fails the manifest check with "the box's base no longer matches" (Task 3: `second_land_diffs_against_the_first`, `partial_land_keeps_the_rest`, `lying_advance_is_caught`).
5. **Approved but not applied:** the phone approves, then the user discards, or approves twice, or runs `apply` with the branch moved by hand. Expected: discard refused without `--force`; one approval only; `apply` refuses a moved branch (compare-and-swap) and says how to recover (Task 4: `discard_refuses_unapplied_land`; Task 6: `apply_refuses_moved_branch`, `apply_twice_is_ok_once`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (delta format and validator), Task 2 (guest export and advance).
- **Wave 2:** Task 3 (host review: receive, store, render; needs 1, plan 38 Task 4).
- **Wave 3:** Task 4 (`LandBook`, manager, Workspace path; needs 3, plan 26).
- **Wave 4 (parallel):** Task 5 (daemon land/push ops; needs 4), Task 6 (CLI diff/land/apply/push; needs 5's op shapes, plan 27).
- **Wave 5:** Task 7 (smoke fragment).

---

### Task 1: the delta format and the hostile-input validator (size L)

**Files:** Modify `crates/boxproto/src/delta.rs`; create `crates/boxproto/tests/delta_adversarial.rs`.

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")] pub enum Op { Add, Modify, Delete }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)]
pub struct EntryHead { pub path: String, pub op: Op, pub kind: EntryKind, pub mode: u32, pub size: u64, pub sha256: String, pub old_kind: Option<EntryKind>, pub old_size: Option<u64>, pub old_sha256: Option<String> }
pub struct Limits { pub entries: usize, pub file_bytes: u64, pub total_bytes: u64 }   // L2 defaults via Default
pub trait BlobSink { fn begin(&mut self) -> io::Result<()>; fn write(&mut self, b: &[u8]) -> io::Result<()>; fn finish(&mut self, sha256: &str) -> io::Result<()>; }   // the host spills content to blobs/<sha256>
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Valid { pub n: u32, pub entries: Vec<EntryHead> }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct DeltaError { pub path: Option<String>, pub reason: String }
pub struct Reader<'a> { /* state machine */ }
impl<'a> Reader<'a> {
  pub fn new(base: &'a BaseManifest, limits: Limits, sink: &'a mut dyn BlobSink) -> Reader<'a>;
  pub fn paths_only(limits: Limits, sink: &'a mut dyn BlobSink) -> Reader<'a>;   // the CLI's re-check of delta.bin: path, symlink, size and hash rules, no manifest (old_* ignored)
  pub fn push(&mut self, f: Frame) -> Result<bool /* done */, DeltaError>;     // per-frame checks; sha256 streamed
  pub fn finish(self) -> Result<Valid, DeltaError>;                            // the resulting-tree checks of L3
}
pub fn write_delta(w: &mut impl Write, n: u32, entries: &[(EntryHead, Option<&[u8]> /* old */, Option<&[u8]> /* new */)]) -> io::Result<()>;   // used by the guest, the host's delta.bin and tests
pub fn apply_manifest(base: &BaseManifest, v: &Valid, only: Option<&BTreeSet<String>>) -> BaseManifest;   // the base after a (partial) land
```
- [ ] **Step 1: Write the failing tests** (`tests/delta_adversarial.rs`, a base manifest fixture of ten paths with a symlink `ln -> docs`): one test per Review Focus 1 case (`traversal_is_refused`, `absolute_is_refused`, `dot_git_any_case_any_depth`, `symlink_escape_is_refused`, `write_through_symlink_in_delta`, `write_through_symlink_in_base`, `file_dir_conflict`, `duplicate_path`, `unsorted_entries`, `old_hash_must_match_manifest`, `add_of_existing_is_refused`, `delete_of_missing_is_refused`, `file_too_large`, `too_many_entries`, `total_too_large`, `truncated_stream`, `size_mismatch`, `sha_mismatch`, `bad_mode`, `end_count_mismatch`); and `good_delta_roundtrip` (`write_delta` → `Reader` → `Valid`, blobs in the sink), `apply_manifest_full_and_partial`, `symlink_inside_is_ok` (`ln2 -> docs/a`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `check-windows.sh -p saiife-boxproto`.
- [ ] **Step 5: Commit** `feat(boxes): tree delta format and a validator that treats the guest as hostile (spec §7.5, §12)`.

---

### Task 2: the guest's export and advance (size M)

**Files:** Modify `crates/guest/src/export.rs` (replace plan 38's no-op `init_base`), `crates/guest/src/control.rs` (route `Export`, `Advance`); create `crates/guest/tests/export.rs`.

**Interfaces (Produces):**
```rust
pub fn init_base(env: &GuestEnv) -> Result<(), String>;    // git init the base dir; commit /work as refs/base (first setup only)
pub fn export(env: &GuestEnv, n: u32, out: &mut dyn Write) -> Result<(), String>;   // snapshot /work as refs/exports/<n>, then write_delta of base..exports/<n>
pub fn advance(env: &GuestEnv, n: u32, paths: Option<&[String]>) -> Result<(), String>;   // refs/base := exports/<n> (all), or base + the listed paths taken from exports/<n>
```
Every git call: `GIT_DIR=<root>/var/lib/saiife-guest/base.git GIT_WORK_TREE=<root>/work`, `-c core.hooksPath=/dev/null -c core.autocrlf=false -c core.symlinks=true`, a per-call `GIT_INDEX_FILE` under the base dir. Snapshot: `git add -A` (respects `/work/.gitignore`; a `.git` dir anywhere in `/work` is excluded through `info/exclude` containing `.git`), `write-tree`, `commit-tree`. Changes: `git diff-tree -r -z --no-renames --raw refs/base <export>`; contents through one `git cat-file --batch` process; SHA-256 computed while streaming. The control reply for `Export` is the delta frames on the same connection, then the connection closes.

- [ ] **Step 1: Write the failing tests** (real git, `GuestEnv { root: $TMPDIR/g }`, `/work` filled by the test): `init_base_commits_work`, `export_lists_add_modify_delete`, `export_includes_untracked_and_skips_ignored`, `export_skips_nested_dot_git` (an agent `git init` inside `/work/sub`), `export_symlink_and_mode_change`, `export_is_binary_safe` (random bytes with NULs roundtrip through `Reader`), `advance_all_then_empty_export`, `advance_some_paths_keeps_the_rest`, `no_hook_runs` (a hook in the base dir writes a marker; it never appears).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(guest): export a tree delta against the last landed base; advance the base`.

---

### Task 3: the host review: receive, validate, store, render (size L)

**Files:** Modify `crates/boxhost/src/review.rs`, `crates/boxhost/Cargo.toml` (`similar = "=2.7.0"`); create `crates/boxhost/tests/review.rs`.

**Interfaces:**
- Consumes: Task 1; plan 38 `VsockGuest::request_stream`; plan 37 `BaseManifest`; plan 28 `DiffSummary`, `FileChange`, `FileStatus`, `MAX_DIFF_BYTES`.
- Produces:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct Flag { pub path: String, pub why: String }   // L6 texts: "protected path", "rule <pack>: <reason>", "becomes executable", "new symlink", "binary", "differs only in case from <other>"
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)] pub struct Review { pub n: u32, pub summary: saiife_wire::DiffSummary, pub flags: Vec<Flag>, pub entries: Vec<EntryHead>, pub base_head: Option<String> }
pub type Hits<'a> = &'a dyn Fn(&[&str]) -> Vec<Flag>;   // the daemon passes plan 32's diff_hits mapped to Flag
pub fn receive(guest: &VsockGuest, id: &BoxId, paths: &RecordPaths, base: &BaseManifest, n: u32) -> Result<Valid, DeltaError>;   // request_stream(Export{n}) into lands/<n>/blobs; on error removes lands/<n>
pub fn render(base: &BaseManifest, v: &Valid, blobs: &Path, only: Option<&BTreeSet<String>>) -> (String /* full unified */, Vec<FileChange>);
pub fn review(id: &BoxId, base: &BaseManifest, v: &Valid, blobs: &Path, only: Option<&BTreeSet<String>>, hits: Hits) -> Review;   // diff_sha256 = sha256(full); unified cut at a line end ≤ MAX_DIFF_BYTES
pub fn write_land_files(paths: &RecordPaths, r: &Review, only: Option<&BTreeSet<String>>) -> Result<(), String>;   // delta.bin (new content of the selected entries) + review.json, 0600
pub fn protected(path: &str) -> bool;   // L6 built-in list
```
Old content of a `modify` comes from the delta's old side, already proven equal to the manifest hash, so the renderer never trusts the guest for it. `render` output is deterministic (entries in path order; `similar` `TextDiff::from_lines(..).unified_diff().context_radius(3)`), pinned by golden files.

- [ ] **Step 1: Write the failing tests** (`tests/review.rs`; the guest side is plan 38's test multiplexer with a canned export from Task 1's `write_delta`): `render_golden_text_add_modify_delete`, `render_golden_binary_and_symlink`, `render_mode_change`, `diff_sha256_is_of_the_full_text` (a 3 MB diff: `truncated`, hash over all 3 MB), `binary_change_changes_the_hash` (one byte differs → another hash), `flags_protected_and_hits`, `case_collision_is_flagged`, `subset_review_hashes_only_the_subset`, `hostile_delta_stores_nothing`, `second_land_diffs_against_the_first` (manifest advanced with `apply_manifest`), `partial_land_keeps_the_rest`, `lying_advance_is_caught` (export's `old_sha256` from a base the host never landed → `DeltaError` "the box's base no longer matches").
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; tokio gate `0`.
- [ ] **Step 5: Commit** `feat(boxes): host-side review: validated delta, own unified rendering, protected-path flags`.

---

### Task 4: `LandBook`, `Manager::land`, and the Workspace path (size L)

**Files:** Modify `crates/boxes/src/{source.rs,manager.rs,guest.rs}` (trait `LandBook` in `source.rs`); create `crates/daemon/src/box_land.rs`, `crates/daemon/tests/box_land.rs`; modify `crates/daemon/src/touch.rs` (plan 26: `IssueKey::{Land, Push}`), `crates/daemon/src/ops.rs` (`Ctx.box_lands: Option<Arc<Lands>>`), `crates/daemon/src/box_ops.rs` (build `Lands`; `with_lands` at every `ManagerSource::new`, `box_ops.rs:629-636`, `:834`, `:919`, `:960-973`; refresh on `→ Done`), `crates/daemon/src/start.rs` (`Ctx.boxes` gets `with_lands` too, after plan 31 Task 1).

**Interfaces:**
- Consumes: Task 3; plan 26 `TouchState::{issue, consume, take}` (`touch.rs:191`, `:241`, `:223`), `ActionRecord`, `TouchClass::Land`, `approvals::record_with_touch` (`approvals.rs:476`); plan 32 `saiifeguard::userpack::{load_user_packs, diff_hits}` (`userpack.rs:63`, `:402`) with `saiifeguard::profile::Profile::Box`.
- Produces:
```rust
// boxes source.rs
pub trait LandBook: Send + Sync {
  fn diff(&self, id: &BoxId) -> Result<saiife_wire::DiffSummary, BoxError>;
  fn pending(&self) -> Vec<saiife_wire::PendingAction>;
  fn complete(&self, request_id: u64, d: saiife_wire::Decision, ev: Option<saiife_touch::TouchEvidence>) -> Result<(), BoxError>;
  fn unapplied(&self, id: &BoxId) -> u32;
}
impl ManagerSource { pub fn with_lands(self, lands: Arc<dyn LandBook>) -> ManagerSource; }
// boxes manager.rs
impl Manager { pub fn land(&self, id: &BoxId) -> Result<Change, BoxError>; }
// daemon box_land.rs
pub struct Lands { /* Arc<Ctx>, Arc<Manager>, Arc<VsockGuest>, Layout, Mutex<state: next request id, per-box latest review> */ }
impl Lands {
  pub fn new(ctx: Arc<Ctx>, mgr: Arc<Manager>, guest: Arc<VsockGuest>, layout: Layout) -> Arc<Lands>;
  pub fn refresh(&self, id: &BoxId) -> Result<Review, BoxError>;                       // export n = lands + exports so far + 1; review with hits; cached
  pub fn begin(&self, id: &BoxId, owner: u32, only: Option<BTreeSet<String>>, now: u64) -> Result<(u64 /* request id */, ActionRecord, Review), BoxError>;   // issue(IssueKey::Land(rid), owner, Land, summary, fields)
  pub fn approve(&self, rid: u64, ev: &TouchEvidence, via: &'static str) -> Result<LandInfo, BoxError>;   // approved.json, mgr.land, guest Advance, audit `land` + touch
  pub fn reject(&self, rid: u64, via: &'static str) -> Result<(), BoxError>;
  pub fn applied(&self, id: &BoxId, n: u32, commit: &str) -> Result<(), BoxError>;      // applied.json, audit land_applied
  pub fn approved_unapplied(&self, id: &BoxId) -> Vec<LandInfo>;
}
#[derive(Debug, Clone, Serialize)] pub struct LandInfo { pub id: BoxId, pub n: u32, pub target_ref: String, pub base_commit: String, pub diff_sha256: String, pub task: String, pub repo_dir: Option<String> }   // always answered nested as {land: LandInfo} (R20)
impl saiife_boxes::source::LandBook for Lands { … }
```
- Record fields: `repo` (manifest display name), `base_commit` (L5), `target_ref`, `diff_sha256`; summary `land <id>: <k> files (+a −r)[; flagged: <path> (<why>), …]` cut at 512 chars.
- `refresh` needs the VM on; a `Done` box with the VM off returns the cached review, or `Unavailable("the box's VM is off and it has no review; saiife box revise <id> restarts it")`. The daemon calls `refresh` whenever a tick or guest change moves a box to `Done` (before plan 34's idle stop can turn the VM off).
- `pending()` (L8): per owner, the 4 oldest `Done` boxes with a non-empty review; a record past `expires_at` is re-issued with a new request id. An owner-scoped `ManagerSource` (plan 34 R18) shows only its owner's records.
- `complete(Approve, Some(ev))`: the request must still name the box's latest review (`diff_sha256` equal), else `WrongState { state }`; then `ctx.touch.take(&IssueKey::Land(rid), owner)` (burns the CLI-path entry; plan 31 has verified `ev` against the record with `verify_counted`) and `approve(rid, ev, "web")`. `complete(Reject, None)`: `reject` (and the same `take`); the box stays `Done` (plan 28 kit: `complete_reject_keeps_done`).
- `ManagerSource::discard` with a book: `unapplied(id) > 0` → `Invalid("box <id> has an approved land that is not applied: saiife box apply <id>, or discard --force")`; the CLI's `--force` is a separate op argument checked in `box_ops`.

- [ ] **Step 1: Write the failing tests** (`tests/box_land.rs`: `test_ctx` with FakeVmm, a VsockGuest over plan 38's test multiplexer serving canned exports, `SoftAuthenticator` credentials): `manager_source_with_lands_passes_conformance` (plan 28's `conformance::check` with the real book: the kit's land binding — `diff_sha256` and `base_commit` of the pending record equal `diff()` — holds), `pending_issues_four_per_owner` (five `Done` boxes of one owner → four records; the fifth appears after one is decided), `owner_scoped_pending_hides_others`, `expired_pending_is_reissued`, `complete_approve_lands_and_advances` (state `Landed`, `lands == 1`, guest received `Advance { n, paths: None }`, one `land` record with a `touch` object and `via: "web"`), `complete_burns_the_cli_entry` (after `complete(Approve)`, `box.land` with a CLI assertion for the same request id → `touch_failed` `Expired`), `complete_reject_keeps_done`, `stale_complete_is_wrong_state`, `revise_then_second_land` (R-F1: `Landed → Running → Done → Landed`, `lands == 2`), `discard_refuses_unapplied_land`, `refresh_runs_on_done`, `vm_off_uses_cached_review`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm --test box_land -j 4 -- --test-threads=4` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo test -p saiife-boxes --features fake` (plan 34 suite unchanged, plus `land_moves_done_to_landed`).
- [ ] **Step 5: Commit** `feat(boxes): land book: reviews, land touch records, Workspace approve, multi-land`.

---

### Task 5: daemon land and push ops (size M)

**Files:** Modify `crates/daemon/src/box_land.rs` (ops), `crates/daemon/src/box_ops.rs` (routes), `crates/ipc/src/msg.rs`, `crates/wire/src/level.rs` (`IPC_OPS`), `crates/ipc/src/client.rs` (`recv_fds` after an answer).

**Interfaces (Produces):** ops on the control socket (owner check as plan 34 B8; lockdown `all` refuses `land` and `push`). The box id is always the `box` argument and an answer never carries a top-level `id` (plan 34 R25, R20). `box.diff`, `box.land` and `box.push` keep their `REMOTE` levels as frame actions (Signed, Touch, Touch); the new sub-ops are MachineOnly:

| op | args | answer |
|---|---|---|
| `box.diff` | `{box, refresh?: bool}` | `{diff: DiffSummary, review: {n, flags, entries, base_head}}` (plan 34's `{diff}` kept, `box_ops.rs:960-965`; `unified` up to `MAX_DIFF_BYTES`) |
| `box.land.begin` | `{box, files?: [path]}` | `{request_id: "<decimal>", touch: TouchRequest, expires_at, review}` (`TouchRequest` of plan 26 with `rp_id = LOCAL_RP_ID`, the peer's credentials, `uv = true`) |
| `box.land` | `{request_id, assertion}` | `{land: LandInfo}`, then the `delta.bin` fd via `send_fds` |
| `box.land.reject` | `{request_id}` | `{}` |
| `box.land.fetch` | `{box, n}` (an approved, unapplied land) | `{land: LandInfo}` + fd |
| `box.land.applied` | `{box, n, commit}` | `{}` |
| `box.discard` | plan 34's `{box}` + `force?: bool` | as plan 34 |
| `box.push.begin` | `{box, remote, commit}` | `{request_id, touch, expires_at}` (`PushProtected`, fields of L7) |
| `box.push` | `{request_id, assertion}` | `{}` (touch verified; the CLI pushes) |
| `box.push.done` | `{request_id, ok, detail}` | `{}` (audit `push`) |

`box.land` order: `ctx.touch.consume(&IssueKey::Land(rid), peer.uid, build, &asr, LOCAL_RP_ID, now)` (the record is rebuilt from the daemon's stored request, never from the client) → the box's latest review still has this `diff_sha256` (else `touch_mismatch`, the review is refreshed for the next `begin`) → `Lands::approve(rid, ev, "cli")`. Error mapping as plan 26 (`touch_failed`, `touch_mismatch`, `touch_unavailable` with "enrol a key: saiife touch enrol").

- [ ] **Step 1: Write the failing tests** (daemon `tests/box_land.rs` additions, `SoftAuthenticator`): `cli_land_roundtrip` (begin → assert → land → fd holds the delta; record `via: "cli"`), `later_writes_need_a_new_touch` (the canned export changes between begin and land → `touch_mismatch`), `subset_hash_is_bound` (begin with `files = [a]`, a record for `[a, b]` never verifies), `request_is_single_use`, `other_uid_is_refused`, `expired_request_is_refused`, `no_credential_names_enrol`, `fetch_for_web_approved_land`, `applied_is_recorded_once`, `push_needs_touch_and_records`, `lockdown_refuses_land_and_push`, `land_sub_ops_are_machine_only` (wire `level.rs` unit test, as plan 34 R19: `box.land.begin`, `.reject`, `.fetch`, `.applied`, `box.push.begin`, `box.push.done` → `MachineOnly`; `box.diff` stays `Signed`, `box.land` and `box.push` stay `Touch`), `per_box_ops_take_box_not_id` (over the real socket with `Client::call`: `{box: "b1"}` works; an answer of `box.land` has `land.id == "b1"`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): box.diff, box.land and box.push ops, each bound to a touch`.

---

### Task 6: CLI `saiife box diff | land | apply | push` and the commit builder (size L)

**Files:** Create `crates/cli/src/box_land_cmd.rs`, `crates/cli/tests/box_land_cmd.rs`; modify `crates/cli/src/box_cmd.rs` (`Diff { id, #[arg(long)] json: bool, #[arg(long)] stat: bool }`, `Land { id, #[arg(long, value_delimiter = ',')] files: Vec<String> }`, `Apply { id }`, `Push { id, #[arg(long, default_value = "origin")] remote: String }`, `Discard` gains `--force`).

**Interfaces (Produces):**
```rust
pub fn build_commit(tools: &Tools, repo: &Path, info: &LandInfo, delta: File, parent: &str) -> Result<String, String>;   // plumbing only; returns the commit id
pub fn apply(tools: &Tools, repo: &Path, info: &LandInfo, delta: File) -> Result<Applied, String>;
pub struct Applied { pub commit: String, pub worktree: PathBuf, pub moved_branch: bool }
```
`apply`: `repo` = the box's `repo_dir` (the spawn's `repo_dir`, kept on the record by plan 34, `store.rs:37`; `box.list` entries are `BoxInfo` and carry no `repo_dir`, so Task 5's `{land: LandInfo}` answer adds it), must be the same repo (its `refs/saiife/box-<id>/base` exists, or is recreated from the review's `base_commit` when `git cat-file -e` finds the object, else refuse); parent = `refs/heads/saiife/box-<id>` if it exists, else the base ref; read `delta.bin` with Task 1's `Reader` against no manifest (path rules and sizes only: `Reader::paths_only`), `hash-object -w --no-filters`, temp index `read-tree <parent>`, `update-index --index-info` (deletes as `0 0000…\t<path>`), `write-tree`, `commit-tree -p <parent> -F -` (Fixed values message); then, without a worktree, `update-ref refs/heads/saiife/box-<id> <new> <old-or-empty>` and `worktree add <wt> saiife/box-<id>`; with a worktree, `git -C <wt> merge --ff-only <new>` (a dirty worktree: the commit is kept, the branch is not moved, and the message prints the command to finish). Then `box.land.applied`.

`land`: `box.land.begin` → print the review stats, the flags (each `! <path>: <why>`), the short code and `touch your key to land box <id> (code 123456)` → plan 27's touch client (`touch_cmd::pick()` then `run_touch`, exit codes from `exit_for`; `touch_cmd.rs:358-418`; with no key support (`pick()` gives `NO_KEY_SUPPORT`: a Linux release before plan 41, or a Linux install without plan 41's helper) it prints plan 27's D1 line, then `saiife: land box <id> from the Workspace instead (Face ID or your passkey), then run: saiife box apply <id>`, and exits 5 without calling `box.land.begin`, so no challenge is spent) → `box.land` → `apply` → print `landed <id> #<n>: <commit> on saiife/box-<id> (worktree <wt>)`. Any approved-unapplied land of the box is applied first (`box.land.fetch`). `apply <id>`: every approved-unapplied land, in order. `diff`: the review through `crate::text::sanitize` per line (`--stat` files only; `--json` raw). `push`: the branch tip, `box.push.begin`, touch, `box.push`, `git push` (L7), `box.push.done`.

- [ ] **Step 1: Write the failing tests** (`tests/box_land_cmd.rs`, real git tempdir repo with a base ref from plan 37's `snapshot_commit`; a canned `delta.bin`; the daemon side through `TestDaemon` with `fake-vmm` and a soft authenticator where a full roundtrip is needed): `build_commit_tree_is_exact` (`git ls-tree -r` equals base + delta), `deletes_and_symlinks_and_modes`, `first_land_creates_branch_and_worktree`, `second_land_fast_forwards_the_worktree`, `dirty_worktree_keeps_commit_and_explains`, `apply_refuses_moved_branch`, `apply_twice_is_ok_once`, `missing_base_ref_is_recreated`, `no_user_hook_runs` (`pre-commit`, `post-checkout`, `post-merge`, `pre-push` markers absent after land and push to a local bare remote), `box_attributes_add_no_filter` (a box-written `.gitattributes` with `filter=evil` and the user's config has no such driver: blobs equal the raw bytes), `diff_output_is_sanitized` (a path with `\u{202e}`), `push_to_local_remote` (bare repo remote: ref `saiife/box-b1` equals the commit), `discard_force_flag_is_sent`, `land_without_key_support_points_to_workspace` (a debug build without `fido-hid` and without `SAIIFE_TEST_TOUCH_SOFT` / plan 41's `SAIIFE_TEST_FIDO_HELPER`: exit 5, stderr has the D1 line and `saiife box apply <id>`, the daemon saw no `box.land.begin`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo test -p saiife --test docs_wording`.
- [ ] **Step 5: Commit** `feat(cli): saiife box diff, land, apply and push; the land commit is built with git plumbing`.

---

### Task 7: the smoke fragment (size S)

**Files:** Create `scripts/box-smoke.d/40-land.sh`.

Owner-run checks (result keys): a box with the `bash` smoke template edits two files, adds one, deletes one, makes a symlink and a binary file; `saiife box diff` shows them, with the binary line and the symlink (`diff_ok`); `saiife box land <id>` asks for the touch with a short code and lands (`land_ok`); `git log saiife/box-<id>` has one commit with the `Saiife-Diff-Sha256` trailer equal to the audit's `land` record (`land_hash_matches`); `revise`, more edits, a second land adds a second commit (`multi_land_ok`); `--files` lands one of two changes and the next diff shows only the other (`partial_land_ok`); a change to `CLAUDE.md` is flagged in the review and the touch summary (`protected_flagged`); the box writes `.git/hooks/x` and a `../escape` path through its own tools: the review refuses with `diff_rejected` (`hostile_refused`); `saiife box push <id> --remote <a local bare repo>` after a touch (`push_ok`); with a paired phone (plan 31): approve a land in the Workspace, then `saiife box apply <id>` writes the commit (`web_land_applied`).

- [ ] **Step 1:** write the fragment; `bash -n`; shellcheck if installed.
- [ ] **Step 2: Commit** `test(boxes): owner smoke for diff, land, multi-land, partial land and push`.

---

## Gates

- [ ] `cargo test -p saiife-boxproto -p saiife-guest -p saiife-boxhost --features fake -p saiife-boxes --features fake -p saiife-daemon --features fake-vmm -p saiife --features fake-vmm -p saiife-touch --features soft`, and the daemon and CLI suites without features; `-j 4 -- --test-threads=4`.
- [ ] clippy; `check-unsafe.sh`; `check-windows.sh -p saiife-boxproto -p saiife-boxes -p saiife-daemon -p saiife`; tokio gate `0`.
- [ ] `git diff v3-dev -- Cargo.lock` adds `similar` only.
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`. Tell the plan 31 owner that `box.land` via `complete` now works on real boxes; `box.push` stays CLI-only (`box.push.*`), so the Workspace keeps it in `LATER`.

## Owner handwork

- [ ] Decide L4 (Workspace approvals applied by the CLI later).
- [x] L8: `IssueKey::{Land, Push}` approved, per-uid limit 8 (plan 31 Task 2), 4 land records per owner (owner ruling 2026-11-12).
- [x] Linux release key access for `saiife box land`: plan 41's packaged helper; until it lands, Workspace plus `saiife box apply` (owner ruling 2026-11-12).
- [ ] Run `scripts/box-smoke.sh --only land` with an enrolled key (plan 27; a build with `--features fido-hid`, or after plan 41 the release static binary with the packaged helper).
