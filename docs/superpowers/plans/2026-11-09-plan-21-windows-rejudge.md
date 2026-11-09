# Plan 21: the service judges each co-signed call itself (Windows locked mode leaves preview for Claude Code): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A forged verdict never turns into an allow for Claude Code:
- **The co-signer re-judges.** For each `POST /v1/cosign/claude` the service judges the request body itself, the exact input Claude Code sent, with the system policy of the user who asks. It answers "no opinion" (empty `200`) only when the hook recorded an allow **and** its own judgment allows. A same-user process that begins, binds and appends an allow, then ends the real hook (D4 of plan 20), gets a deny.
- **The co-signer knows who asks**, on macOS (`net.inet.tcp.pcblist_n`) and Windows (`GetExtendedTcpTable` plus the process tree), as it already does on Linux (`/proc/net/tcp`).
- **Windows hook speed:** one task, with options the owner picks from (the managed hook is about 150 ms p95 against a 130 ms budget).
- **Done:** `locked-windows` measures the forged append and the hook kill and asserts a deny for both. `doctor` stops calling Windows locked mode a preview for Claude Code (Codex and Gemini CLI stay preview). The docs, the spec and the A25 row say so.

**Architecture:**
- **Both must agree.** The hook keeps judging with the agent user's view: the filesystem, the project config, the MCP pin check. The service adds its own judgment of the same call, with no filesystem access (a *lexical* judgment). An allow needs both. Neither can allow alone, so a missing or forged hook verdict cannot allow, and a service judgment cannot widen what the hook denied.
- **Why the lexical judgment is enough.** It is the cut in §16.2, answered head on (D1). Every fact the service cannot see is a fact that code of the agent's user can change after any judgment anyway: it can swap a junction, a symlink or a directory's contents between the judgment and the tool run, and edit the project config it owns. So the parts only the hook can see were never a boundary against that code (A21). The parts that are a boundary are the system policy, the pack rules, and the lexical path rules against the user's fixed account paths. The service judges all of them, on the input it got from Claude Code, not from the hook.
- **The service runs the same guard.** It runs in a warm `saiife __eval --serve` worker child of the service, with `FsView::Lexical`. The guard then makes no file system call at all. The path variables (`HOME`, `XDG_CONFIG_HOME`, the agent config dirs) come from the asking user's account record, exactly as the locked hook's worker already builds them (it clears its environment). The packs are the system policy's packs for that user's scope. The project config only adds packs in locked mode (A18), so the service judges a policy no stricter than the hook's.
- **Approvals.** A call that only `[guard] ask` rules deny may still be allowed. The service accepts that only when the same hook connection consumed a grant (`grant.consume`), and the grant's `raw_sha256` equals the SHA-256 of the command in the request body.

**Tech Stack:** Rust workspace, no new crates. Two new FFI calls: `GetExtendedTcpTable` in `crates/win/src/ffi/net.rs` (`windows-sys` feature `Win32_NetworkManagement_IpHelper`, from `Cargo.lock`) and `sysctlbyname` in `crates/darwin`. The co-signer stays in `saiife-daemon` (tokio). The guard change stays in tokio-free `saiife-guard`.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`: §5.3a (the "Built" note and the plan 20 bullet), §5.3a.2 (W13, the TCP peer), §6.1.1, §6.1.2, §6.16, §8.5, §9.2 A18, A21 and A25, §9.3, §9.4, §15 row 20, §16.2 ("Daemon-side guard evaluation"). Read plan 20 (`docs/superpowers/plans/2026-11-09-plan-20-hook-kill.md`) first: its design notes D1 to D7 and its Owner rulings apply here. Plan 19b's Global Constraints and W1 to W28 apply unchanged.

## Facts checked (2026-11-09)

**D** marks a fact that changes the design. The changes are listed after the table.

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | The HTTP hook's POST body is the same JSON input a command hook reads on stdin, sent with `Content-Type: application/json`. | code.claude.com/docs/en/hooks, "HTTP hook fields", "Hook input" | Confirmed. The service judges the body Claude Code sent, and the hook's claim is only one of two votes. |
| F2 | The common input fields include `session_id`, `transcript_path`, `cwd`, `permission_mode` and `hook_event_name`. `PreToolUse` adds `tool_name`, `tool_input` and `tool_use_id`. | hooks, "Common input fields", PreToolUse example | Confirmed. `cwd` is in the body, so relative paths are judged against Claude Code's own cwd, not against a value the hook sends. |
| F3 | The docs name no request header that identifies Claude Code or its process. The only headers are `Content-Type` and the user's own `headers`. | hooks, "HTTP hook fields" | **D2.** The request does not say who sends it. The asker must come from the socket (Tasks 4 and 5). |
| F4 | Command hooks: in shell form, "Git Bash on Windows, or PowerShell when Git Bash isn't installed". With `args` (exec form), "`command` is resolved as an executable and spawned directly ... with no shell involved". "On Windows, exec form requires `command` to resolve to a real executable such as a `.exe`." | hooks, "Command hook fields", "Exec form and shell form" | **D3.** The drop-in uses shell form today, so every Windows hook call also starts Git Bash or PowerShell. The CI bench starts `saiife.exe` directly and does not measure that. Exec form is speed option E (Task 8). The hook's parent is a shell, so the process-tree check in Task 4 allows a depth of 3. |
| F5 | Which Claude Code version added `args` | hooks; code.claude.com/docs/en/changelog (searched, too long to read in full) | **Not found.** Owner handwork step 4 checks it before option E is used. |
| F6 | Matching hooks run in parallel. For `PreToolUse`, "precedence is `deny` > `defer` > `ask` > `allow`". | hooks, "Hook lifecycle", "PreToolUse decision control" | Confirmed, as in plan 20 (F4). The co-signer may take longer than the hook; the user waits for the slower one. |
| F7 | `GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)`. With `AF_INET` and `TCP_TABLE_OWNER_PID_ALL` it fills a `MIB_TCPTABLE_OWNER_PID` (local and remote address and port, state, owning pid). A buffer that is too small gives `ERROR_INSUFFICIENT_BUFFER` and the size needed. No privilege is named. Iphlpapi.dll, Vista and Server 2008 or later. | learn.microsoft.com, `GetExtendedTcpTable` | Confirmed. The service can find the pid that owns the client end of a co-sign connection. |
| F8 | `OpenProcess` checks the requested rights against the process DACL. "To open a handle to another process and obtain full access rights, you must enable the SeDebugPrivilege privilege." `OpenProcessToken` needs `PROCESS_QUERY_INFORMATION`. | learn.microsoft.com, "Process Security and Access Rights" | **D2.** A hook's DACL, measured in CI 11, is `(A;;0x1fffff;;;<user>)(A;;0x1fffff;;;SY)(A;;0x121411;;;<logon SID>)`. That has no entry for `NT SERVICE\saiifed`, so the service cannot open the token of a process the agent's user started. Granting the service `SeDebugPrivilege` would give it full access to every process. Rejected. |
| F9 | `WTSEnumerateProcessesExW` level 1 returns `WTS_PROCESS_INFO_EX` with the user SID, but "the caller must be a member of the Administrators group to enumerate processes that are running under another user session". | learn.microsoft.com, `WTSEnumerateProcessesExW` | Unusable: the service runs in session 0 and is not an admin. Rejected. |
| F10 | `PROCESSENTRY32W.th32ParentProcessID` is "the identifier of the process that created this process". The page says nothing about reuse. | learn.microsoft.com, `PROCESSENTRY32W` | Confirmed. The snapshot (`saiife_win::ffi::proc::snapshot`, already used) needs no handle to the process. A parent pid can be stale after its process exits, which is the residual risk in Task 4. |
| F11 | XNU: `struct xsocket_n` holds `so_uid`, `so_last_pid` and `so_e_pid`. `sotoxsocket_n` sets `so_uid = kauth_cred_getuid(so->so_cred)`. The struct is inside `#ifdef PRIVATE`, so it is not in the public SDK. | apple-oss-distributions/xnu `bsd/sys/socketvar.h`, `bsd/netinet/in_pcblist.c` (main, read 2026-11-09) | **D4.** The uid is there without a pid lookup, but the layout is no stable ABI. The parser walks records by their `xgn_len` and `xso_kind` and refuses a size it does not know (Task 5). |
| F12 | `net.inet.tcp.pcblist_n` is `CTLTYPE_STRUCT \| CTLFLAG_RD \| CTLFLAG_LOCKED`. `get_pcblist_n` refuses writes only; it does not check the caller. | xnu `bsd/netinet/tcp_subr.c`, `in_pcblist.c` | Readable by `_saiife`, as `netstat` reads it unprivileged. Not measured yet: Task 5's CI step does. |
| F13 | `proc_pidfdinfo` and `PROC_PIDLISTFDS` use `proc_security_policy(..., CHECK_SAME_USER)`. Another uid gets `EPERM` without `PRIV_GLOBAL_PROC_INFO` (root). | xnu `bsd/kern/proc_info.c` | Unusable from `_saiife`. Rejected. |
| F14 | In locked mode the hook's worker builds its path variables from the account record, not from the agent's environment. On Unix that is `HOME` and `USER` from the uid's passwd entry; on Windows it is `ProfileImagePath` under `ProfileList\<SID>` and `SystemRoot`. | `crates/cli/src/check_managed.rs` `worker_account`, `crates/cli/src/win_locked.rs` `worker_environment`, `crates/cli/src/paths.rs` `path_vars_locked` | Confirmed in code. The service can build the same variables from the principal (Task 2). |
| F15 | The project config is add-only in locked mode. It adds packs and service `ask` and `deny` rules; `allow` is dropped. A pack's `[[allow]]` exempts a command from that pack's own `[[deny]]` rules only. | `crates/policy/src/project.rs` `merge_project`; `crates/guard/src/pack.rs` header | Confirmed in code. More packs can only deny more, so the service's judgment without the project config allows a superset of the hook's. |
| F16 | Every file system access in the guard goes through `canon::fs_entry`, `fs_read_dir`, `fs_next_entry` and `fs_is_dir`, which are metered (`fs_call`). `PathVars::with_cwd` and `with_var` resolve values with `resolve` (Unix). | `crates/guard/src/canon.rs`, `crates/guard/src/engine.rs` | Confirmed in code. One switch turns the guard lexical (Task 1). |

### Design changes and notes (flagged for the owner)

- **D1. The §16.2 cut, answered.** The cut said daemon-side evaluation "needs the agent user's view of the filesystem, and gains nothing against an agent that skips the hook (§9.4)". Both halves change for the Claude Code co-signer:
  - **The view:** the service does not need it. The facts only that view gives are the ones a process of the agent's user can change after the judgment. The hook's view stays a second vote, and it denies on its own.
  - **Skipping the hook:** the co-sign request comes from Claude Code because of the managed drop-in, not from the hook. A forger can silence or fake the hook, but not this request.
  - **What it gains:** the forged allow of A25. The §16.2 row moves to "built in plan 21, for Claude Code's co-signed calls, lexical". For Codex and Gemini CLI the cut stands: they have no HTTP hook.
- **D2. Who asks, on Windows.** The service cannot read a token of the agent's user (F8, F9). It finds the pid that owns the client socket (F7). It then requires that this pid is an ancestor, at most 3 levels up (Claude Code, then the shell, then the hook), of the pid of the hook connection that bound the key. The pid comes from `GetNamedPipeClientProcessId`, which the kernel gives. The judged principal is that hook connection's SID, with its token groups. The `PeerCred.pid` comment "for attribution only" changes: on Windows the pid now ties the bind to the asker, and still never grants access on its own.
  - **Residual:** a stale parent pid (F10). A forger's process whose parent has exited could carry the pid of a later Claude Code as its parent. It would need the system to reuse the pid of its parent for the victim's Claude Code. That is a cross-user attack, and the service still judges the call itself.
- **D3. Speed and exec form.** See Task 8. Exec form takes Git Bash or PowerShell out of every Windows hook call. It changes the drop-in, so it waits for F5.
- **D4. macOS reads a private struct.** It is versioned by record length and covered by a live CI test on `macos` runners. If the parser meets a size it does not know, the asker is `Unknown`, and the co-signer denies. That is fail closed, and doctor fails `cosign.asker`.
- **D5. Re-judging runs on all three systems.** It is one code path, testable on Linux with no Windows machine. On Linux and macOS a forged allow already gains nothing (plan 20, wave B note), so there it is defence in depth. The cost is a possible false deny where the lexical judgment is stricter than the hook's. The corpus test in Task 1 pins this to zero cases on the existing corpora (owner question 1).
- **D6. Not closed by this plan:**
  - **The port squat** while the service restarts (plan 20 D6). A squatter answers an empty `200`, and then a forged hook exit 0 allows. It needs the service to crash first (A5).
  - **Injection into Claude Code itself** (a patched agent, A21).
  - **Codex and Gemini CLI on Windows:** they have no co-signer, so they stay preview.

### Owner questions

1. **D5:** re-judge on Linux and macOS too (default yes), or on Windows only?
2. **D6:** is the restart-window port squat acceptable for dropping "preview" for Claude Code? Default yes, documented in A25.
3. **Task 8:** which speed option: A, B, C, D or E (default B, then E once F5 is known)? Or should the 130 ms budget move instead?
4. **D2:** is a depth of 3 right? A shell form hook is Claude Code, then `bash.exe` or `powershell.exe`, then `saiife.exe`. With exec form it is 1.
5. **Disagreement records:** one `rejudge_denied` record per call (default), or folded per principal and reason every 10 s, as `cosign_denied` records are?

## Consumes (verify at build time)

- **Plan 20 at `14d17f2`** (plus whatever lands before this plan starts, such as the wintime cuts in `39f3b5a`):
  - `crates/daemon/src/cosign.rs`: `Asker`, `handle`, `judge_body`, `judge`, `CosignDeny`, `deny_body`, `record`, `Opts`, `start_cosign_with`;
  - `crates/daemon/src/hooks.rs`: `HookTable::{begin, bind, verdict, ended, wait}`, `Principal`, `Slot`, `Waited`;
  - `crates/daemon/src/ops.rs`: `HookSteps { granted, created }`;
  - `crates/cli/src/check_managed.rs`: `Worker`, `worker_account`, `policy_for`, `own_env`, `WORKER_TIMEOUT`;
  - `crates/cli/src/eval.rs`: `EvalRequest`, `EvalAnswer`, `judge_with`, `worker_main`, `mcp_check`, `mcp_identity`;
  - `crates/cli/src/paths.rs` `path_vars_locked`; `crates/cli/src/win_locked.rs` `worker_environment`, `worker_env`, `profile_key`, `profile_home`;
  - `saiife_win::ffi::proc::snapshot`, `crates/win/src/ffi/net.rs`; `saiife_darwin::proc_info`;
  - `crates/daemon/src/mcp_gateway/mod.rs` `tcp_peer_socket`;
  - `scripts/locked-windows/lib.ps1` `phase_cosign`, `bench_managed`, `Invoke-Cosign`, `Invoke-PwshAs`, `measure.c`.
- Where these landed with other names, the code wins, and the task is adjusted before it starts.

## Global Constraints

- **Plans 19a, 19b and 20 apply in full:** no Windows machine, nothing privileged locally, `Child::kill` only on a test's own children, admin tests only in CI's `locked-*` jobs, test isolation, commit rules, CI job ids without dots, no secrets off tags.
- **Tokio-free:** `saiife-guard`, `saiife-audit`, `saiife-policy`, `saiife-ipc` and `saiife-system` stay tokio-free. The re-judge pool is a blocking type in `saiife` (cli). The daemon calls it on `spawn_blocking`.
- **Unsafe only in FFI:** `crates/win/src/ffi/` gains `GetExtendedTcpTable` (W1 count 42 → 43). `crates/darwin` gains `sysctlbyname` (its doc changes from "exactly one FFI call" to two). Each `unsafe` block has a `SAFETY:` comment, and `bash scripts/check-unsafe.sh` exits 0.
- **The service never reads the agent user's files.** In lexical mode the guard makes zero file system calls; a test meters it (Task 1). The service worker runs as the service account and never impersonates. The pipe keeps `SECURITY_IDENTIFICATION`.
- **Hook budget:** Linux +1 ms against `main` (`bench-check.sh --managed`, CI and owner only). The Windows managed hook p95 is ≤ 130 ms, unless the owner moves it (question 3). Re-judging is on the co-sign path, not the command hook. The co-sign answer for an allow fixture has a p95 ≤ 300 ms after the hook's own exit, measured in `locked-windows` (report-only in Task 7, asserted once the owner accepts the number).
- **Fixed values (copied into the spec in Task 9):**
  - `REJUDGE_POOL = 2` warm workers. Each serves at most `REJUDGE_MAX_USES = 500` requests, then is replaced. A worker that fails, times out or answers badly is killed and replaced, and its request gets the `RejudgeFailed` deny;
  - `REJUDGE_TIMEOUT = 3 s` per request (as `WORKER_TIMEOUT`), always inside `COSIGN_WAIT` (8 s) from arrival;
  - `ASKER_MAX_DEPTH = 3` (Windows);
  - new `CosignDeny` texts:
    - `Rejudged`: `the saiife service's own judgment denies this call: <reason>`, where `<reason>` is the guard reason, cut to 200 characters;
    - `RejudgeFailed`: `the saiife service could not judge this call`;
    - `AskerUnknown`: `the saiife service could not tell who sent this call`;
  - new `hook` record events `rejudge_denied` (decision `deny`) and `rejudge_failed` (decision `error_denied`);
  - new `status` fields: `cosign.rejudge: {"workers": <n>, "error": <s|null>}`, `cosign.asker: "proc_net" | "pcblist" | "tcp_table" | null`, and `hooks_rejudge_denied: {since_start, last_ts}`.

## Review Focus

1. **A command the hook allows and the lexical judgment denies** (a false deny). Examples: a glob that the host expands to harmless files, a relative path under a symlinked cwd, a `cd` into a directory whose junction the host resolves. Expected: none on the existing corpora. Each case found is fixed in the lexical view or listed by name and approved by the owner (Task 1: `lexical_never_stricter_on_the_corpora`).
2. **The service judges with the wrong user's paths:** a `~\.ssh\id_rsa` read judged against another profile. Expected: the principal is the binding connection's SID, tied to the asker (Task 4: `foreign_tree_is_denied`); the variables come from that SID's profile (Task 2: `vars_come_from_the_principal_record`).
3. **An approved `ask` call.** Expected: allowed once, when the same connection consumed a grant whose `raw_sha256` matches the body's command. Expected: a grant for another command, or none, gives `Rejudged` (Task 3: `approved_call_passes_only_with_its_grant`).
4. **The warm worker dies, hangs or is killed by the agent's user** (it runs as the service account, so the agent cannot open it, but a crash in the guard can kill it). Expected: that one request gets `RejudgeFailed`, a `rejudge_failed` record is written, the pool restarts, and the next call is judged (Task 2: `crashed_worker_is_replaced`; Task 3: `rejudge_failure_denies_and_records`).
5. **A co-sign request whose hook connection is gone** (killed after bind, plan 20) while the re-judge is still running. Expected: the deny from plan 20 (`NoVerdict`), at once. The re-judge result is dropped, and no `rejudge_denied` record is written (Task 3: `no_verdict_wins_over_a_running_rejudge`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (lexical guard), Task 4 (Windows asker), Task 5 (macOS asker), Task 8 (speed; once the owner has chosen).
- **Wave 2:** Task 2 (re-judge pool; needs 1).
- **Wave 3:** Task 3 (the co-signer re-judges; needs 2, 4, 5).
- **Wave 4 (parallel):** Task 6 (doctor; needs 3), Task 7 (CI; needs 3, 6).
- **Last:** Task 9 (docs and spec; needs Task 7's CI results), the gates, a whole-branch review, one fix wave, push, PR, CI. The owner merges.

**Shared files:** `crates/daemon/src/cosign.rs` (Tasks 3, 4 and 5; Tasks 4 and 5 add only `Asker` sources behind `fn asker`, and Task 3 rebases on them), `crates/daemon/src/hooks.rs` (Tasks 3 and 4), `crates/cli/src/check_managed.rs` (Tasks 2 and 8), `.github/workflows/ci.yml` (Tasks 5 and 7, different jobs).

---

### Task 1: the guard judges lexically on request (size M)

**Files:**
- Modify `crates/guard/src/canon.rs` (`FsView`, the four primitives, `resolve` in `with_cwd` and `with_var`), `crates/guard/src/lib.rs`.
- Create `crates/guard/tests/lexical.rs` and `crates/cli/tests/lexical_corpus.rs`.

**Interfaces (Produces):**
- `pub enum FsView { Host, Lexical }` and `pub fn with_fs_view<R>(view: FsView, f: impl FnOnce() -> R) -> R`, thread-scoped like `FS_METER`. `Host` is the default and is unchanged.
- Under `Lexical`:
  - `fs_entry` answers `FsEntry::Missing`, `fs_read_dir` answers `None`, `fs_next_entry` answers `false`, and `fs_is_dir` answers `false`, all with no system call;
  - `resolve` in `with_cwd` and `with_var` is the lexical form (`push_lexical`).
- `pub fn fs_calls_made() -> u64` (test-visible counter of real calls; `#[doc(hidden)]`).
- [ ] **Step 1: failing tests:**
  - `lexical_makes_no_fs_call`: each `crates/cli/tests/fixtures/claude/*.json` payload and each command of the guard corpora, judged under `Lexical`, leaves `fs_calls_made()` unchanged;
  - `lexical_symlink_is_literal`: under `Host`, `cat notes.txt` (a link to `secrets/.env`) is denied; under `Lexical` it is judged as `notes.txt`;
  - `lexical_home_rules_still_deny`: `cat ~/.ssh/id_rsa`, `type %USERPROFILE%\.ssh\id_rsa` (Windows style), and `Read` of `$HOME/.aws/credentials` are denied under `Lexical`;
  - `lexical_never_stricter_on_the_corpora` (`crates/cli/tests/lexical_corpus.rs`): every case of `crates/guard/tests/corpus_*.rs` (exported as data through a `corpus_cases()` helper) and every Claude fixture is judged under `Host` in a tempdir project and under `Lexical`. Assert there is no case where `Host` allows and `Lexical` denies, apart from a `KNOWN_STRICTER: &[&str]` list that starts empty and needs the owner's approval to grow.
- [ ] **Step 2:** `cargo test -p saiife-guard lexical -p saiife --test lexical_corpus`; expect FAIL.
- [ ] **Step 3:** implement. Pick each lexical answer so that it is never stricter. If `Missing` makes a rule deny where `Host` would allow (Review Focus 1), change that answer, not the corpus.
- [ ] **Step 4:** the tests pass; `cargo tree -e normal -p saiife-guard` shows no tokio; the Windows check is clean.
- [ ] **Step 5:** commit `feat(guard): a lexical file system view, never stricter than the host's`.

### Task 2: the re-judge pool (size L)

**Files:**
- Create `crates/daemon/src/rejudge.rs` (the trait and its types) and `crates/cli/src/rejudge.rs` (the pool).
- Modify `crates/cli/src/eval.rs` (`EvalRequest` gains `view` and `vars`; `worker_main` gains `--serve`), `crates/cli/src/main.rs` (`__eval --serve`; `DaemonOptions.rejudge`), `crates/daemon/src/lib.rs` (`DaemonOptions`), `crates/cli/src/win_locked.rs` (`environment_of(sid)`).

**Interfaces:**
- Produces, in `saiife_daemon::rejudge`:
  - `pub trait Rejudge: Send + Sync { fn judge(&self, req: RejudgeRequest) -> RejudgeAnswer; }` (blocking);
  - `pub struct RejudgeRequest { pub payload: Bytes, pub principal: Principal, pub groups: Vec<String>, pub deadline: std::time::Instant }`;
  - `pub enum RejudgeAnswer { Allow, Deny { reason: String, pack: Option<String>, rule: Option<String>, input: String, askable: bool }, Failed(String) }`;
  - `DaemonOptions.rejudge: Option<Arc<dyn Rejudge>>`. The cli passes `Some` in system mode. `None` in a system daemon means the co-signer denies every call with `RejudgeFailed`, and `status.cosign.rejudge.error` says why.
- Produces, in `saiife::rejudge` (cli): `pub struct Pool`, built with `Pool::start(exe: PathBuf, cfg_path: PathBuf) -> io::Result<Pool>`, and `impl Rejudge for Pool`. Per request it:
  1. loads the system config (cached by file mtime);
  2. finds the principal's scope and packs, with no project: `policy_for(cfg, None)`, made to take the principal instead of the running process (`own_env` gains a `principal_groups: &[String]` source for Windows and the uid's passwd groups on Unix);
  3. builds the path variables from the principal's account record (F14: Unix `HOME` and `USER` from passwd; Windows `environment_of(sid)`, the parameterized `worker_environment`);
  4. sends `EvalRequest { payload, packs, budget_ms, locked, ask, agent: Some("claude"), view: Lexical, vars }` to a warm worker and reads its `EvalAnswer`;
  5. for an MCP tool, applies `mcp_check` with the system `[guard.mcp] allow` and `mcp_identity(payload)`, but not the pin check (hook-only).
- `saiife __eval --serve`: reads length-prefixed `EvalRequest` frames (u32 big-endian, ≤ `MAX_EVAL_BYTES`) and writes one `EvalAnswer` frame for each, until EOF. A frame it cannot parse ends the worker with exit 1. Under `view: Lexical` it judges inside `with_fs_view(Lexical, ..)` and uses `vars` instead of the process environment. Plain `__eval` (the hook's) is unchanged.
- Workers run with a cleared environment. On Windows they run in a kill-on-close job object (the existing `job.rs` calls), so none outlives the service.

- [ ] **Step 1: failing tests** (`crates/cli/src/rejudge.rs` unit tests, plus `crates/cli/tests/rejudge_pool.rs` with the real binary in a tempdir system config):
  - `allow_fixture_allows`, `deny_fixture_denies_with_the_rule` (`claude/bash-deny.json`: same pack and rule as the hook's own answer);
  - `vars_come_from_the_principal_record` (Unix: a fake passwd source gives `HOME=/home/other`, and `cat /home/other/.ssh/id_rsa` is denied while `cat ~/.ssh/id_rsa` is judged against `/home/other`; Windows twin in `windows_tests` with a fake registry host);
  - `scope_packs_follow_the_principal` (two `[[scope]]` blocks: the principal in the stricter one is denied);
  - `project_config_is_not_read` (a project with a `.saiife/config.toml` naming an extra pack: the pool's answer ignores it, and no file under the project is opened; checked with `fs_calls_made`);
  - `serve_answers_many_frames`; `serve_exits_on_a_bad_frame`;
  - `crashed_worker_is_replaced` (`SAIIFE_EVAL_FAULT=abort` on the first request: `Failed`, then the next request is `Allow`);
  - `hung_worker_times_out` (`SAIIFE_EVAL_FAULT=hang`: `Failed` at the deadline, and the worker is killed);
  - `worker_is_replaced_after_max_uses` (lowered to 3 through a test parameter);
  - `mcp_tool_uses_the_system_allow_list` (`claude/mcp-tool.json`).
- [ ] **Step 2:** `cargo test -p saiife rejudge`; expect FAIL.
- [ ] **Step 3:** implement. The pool is a `Mutex<Vec<WorkerHandle>>` with a condvar, and a request takes a free worker or waits until its deadline. Reuse `Worker`'s bounded stdout reader and its job handling from `check_managed.rs` (move the shared parts into `crates/cli/src/worker.rs`, not copy them).
- [ ] **Step 4:** the tests pass; `scripts/test-offline.sh` passes; the Windows check is clean.
- [ ] **Step 5:** commit `feat(daemon,cli): a warm lexical guard pool for the service, judged as the asking user`.

### Task 3: the co-signer allows only when both agree (size M)

**Files:**
- Modify `crates/daemon/src/cosign.rs`, `crates/daemon/src/hooks.rs` (`Slot` keeps the binder's pid and groups, and the connection's consumed grant hash), `crates/daemon/src/ops.rs` (`grant.consume` stores the grant's `raw_sha256` on the connection's slot; `status` fields), `crates/audit/src/record.rs` if a new decision text is needed (none expected: `deny` and `error_denied` exist).
- Test: `crates/daemon/tests/cosign.rs`.

**Interfaces:**
- Consumes `Rejudge`, `RejudgeRequest` and `RejudgeAnswer` (Task 2), and the `Asker` variants of Tasks 4 and 5.
- `Waited::Allow` becomes `Waited::Allow(Bound)`, with `pub struct Bound { pub principal: Principal, pub pid: u32, pub groups: Vec<String>, pub grant_sha256: Option<String> }`.
- `judge` runs `ctx.hooks.wait(..)` and the re-judge (`spawn_blocking`, deadline `min(arrival + COSIGN_WAIT, now + REJUDGE_TIMEOUT)`) at the same time, with the principal known from the asker (Linux and macOS: the uid; Windows: once `wait` has given the binder, see Task 4). On Windows the re-judge starts when `wait` returns `Allow`, because only then is the SID known. Decision:

| `wait` | re-judge | answer | record |
|---|---|---|---|
| `Allow(b)` | `Allow` | empty `200` | none |
| `Allow(b)` | `Deny { askable: true }`, `b.grant_sha256 == sha256(command in body)` | empty `200` | none (the guard record says `approved`) |
| `Allow(b)` | other `Deny` | `Rejudged` | `rejudge_denied` |
| `Allow(b)` | `Failed` or past its deadline | `RejudgeFailed` | `rejudge_failed` |
| `Deny`, `NoVerdict`, `Timeout`, `Foreign` | dropped | as plan 20 | as plan 20 |

- The `rejudge_denied` record has `kind: "hook"`, `decision: "deny"`, `agent: "claude"`, the principal's `uid` and `sid`, `tool`, `input` (masked by `Record::new`), `session` (capped as now), `pack`, `rule` and `reason` from the re-judge, and extra fields `event: "rejudge_denied"`, `hook_pid`, `tool_use_id` (masked and capped).
- `status.hooks_rejudge_denied` counts them.

- [ ] **Step 1: failing tests** (the fake `Rejudge` is a closure in the tests; one integration test uses the real pool):
  - `forged_allow_of_a_denied_call_is_denied`: a test connection begins, binds the key of `claude/bash-deny.json`, and appends an allow; the POST of that body gets the `Rejudged` body (byte for byte) and one `rejudge_denied` record;
  - `honest_allow_still_gets_empty_200`;
  - `forged_allow_of_an_allowed_call_is_allowed` (the residual, pinned: no record);
  - `approved_call_passes_only_with_its_grant` (a grant for the same command passes; a grant for another command, or no grant, gives `Rejudged`);
  - `rejudge_failure_denies_and_records`;
  - `no_verdict_wins_over_a_running_rejudge` (the fake re-judge sleeps 2 s, and the hook connection drops: `NoVerdict` within `RECONNECT_GRACE` + 1 s, with no re-judge record);
  - `no_rejudge_configured_denies_everything` (`DaemonOptions.rejudge = None` in system mode);
  - `rejudge_sees_the_body_not_the_record` (the forged append's record says `ls`; the body says `type secrets.env`: the re-judge receives the body bytes exactly);
  - the plan 20 co-signer tests stay green.
- [ ] **Step 2:** `cargo test -p saiife-daemon --test cosign`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(daemon): the co-signer allows only when its own judgment agrees with the hook`.

### Task 4: who asks, on Windows (size M)

**Files:**
- Modify `crates/win/src/ffi/net.rs` (`tcp_owner_pid`), `crates/win/Cargo.toml` (`Win32_NetworkManagement_IpHelper`), `crates/win/src/proc.rs` (`is_descendant`), `crates/daemon/src/cosign.rs` (`Asker::Process(u32)`), `crates/daemon/src/hooks.rs` (`wait` checks the tree), `crates/ipc/src/peer.rs` (the `pid` doc comment), `scripts/check-unsafe.sh` (count 43), and plan 19b's W1 list.

**Interfaces:**
- `saiife_win::ffi::net::tcp_owner_pid(local: SocketAddrV4, remote: SocketAddrV4) -> io::Result<Option<u32>>`: `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS)`. Size it first, then retry up to 3 times on `ERROR_INSUFFICIENT_BUFFER`. Match the row whose local end is the client (`peer` of the accepted socket) and whose remote end is the co-signer. Ports are compared in network byte order (the low 16 bits of `dwLocalPort` and `dwRemotePort`).
- `saiife_win::proc::is_descendant(snap: &[ProcEntry], ancestor: u32, pid: u32, max_depth: usize) -> bool`: walks `ppid` from `pid`, at most `max_depth` steps. It stops at pid 0 or 4, and at a loop.
- `cosign::asker` on Windows: `Asker::Process(pid)` from `tcp_owner_pid`, looked up before the body is read; `Unknown` when there is no row.
- `HookTable::wait(key, principal: Option<&Principal>, asker_pid: Option<u32>, until)`: with `asker_pid`, a slot whose binder is not a descendant (`ASKER_MAX_DEPTH = 3`) of it gives `Waited::Foreign`. The snapshot is taken once per wait, on a blocking thread.
- `status.cosign.asker = "tcp_table"` when `tcp_owner_pid` worked at startup on a self-connection.
- [ ] **Step 1: failing tests:**
  - pure, on every OS: `descendant_within_depth`, `not_descendant_beyond_depth`, `loop_in_ppids_stops`, `pid_zero_and_four_stop`;
  - `foreign_tree_is_denied` (daemon, with an injected asker and tree: the binder is not under the asker, so `Foreign` and the `NoReport` deny);
  - Windows CI (`test (windows-latest)`, no admin): `owner_pid_of_own_connection` (a test listener and a client in the test: `tcp_owner_pid` gives `std::process::id()`); `unknown_connection_is_none`.
- [ ] **Step 2:** `cargo test -p saiife-win proc -p saiife-daemon cosign`; expect FAIL.
- [ ] **Step 3:** implement, with one `SAFETY:` comment per `unsafe` block.
- [ ] **Step 4:** the tests pass; `bash scripts/check-unsafe.sh` exits 0 with 43; the Windows check is clean.
- [ ] **Step 5:** commit `feat(win): the co-signer finds who asks (TCP owner pid, tied to the binding hook's process tree)`.

### Task 5: who asks, on macOS (size M)

**Files:**
- Modify `crates/darwin/src/lib.rs` (`tcp_peer_uid`, the parser), `crates/daemon/src/cosign.rs` (`asker` on macOS), `scripts/check-unsafe.sh` if it counts darwin calls, `.github/workflows/ci.yml` (the macOS test job runs the live test).

**Interfaces:**
- `saiife_darwin::tcp_peer_uid(local: SocketAddr, peer: SocketAddr) -> Option<u32>`: `sysctlbyname("net.inet.tcp.pcblist_n")` (size first, then fetch with 25% headroom, retrying twice). It then calls the parser.
- `pub fn parse_pcblist_n(buf: &[u8], local: SocketAddr, peer: SocketAddr) -> Result<Option<u32>, ParseError>`: pure and compiled on every target, so Linux CI tests it. It walks `xinpgen` and then records by `xgn_len`, and groups each connection's `XSO_INPCB` and `XSO_SOCKET` records. It matches the inpcb whose local end is `peer` and whose foreign end is `local`, and returns that socket's `so_uid`. A record length other than the known sizes for the running OS's `xinpcb_n` and `xsocket_n` is `ParseError::Layout`.
- On `Layout`, the asker is `Unknown` (deny) and `status.cosign.asker` is null (doctor fails `cosign.asker`, Task 6).
- [ ] **Step 1: failing tests:**
  - parser, on every OS, with byte buffers built in the test from the XNU layout: `finds_the_client_uid`, `ignores_the_listening_socket`, `unknown_record_size_is_layout_error`, `truncated_buffer_is_error`;
  - macOS CI: `own_connection_has_own_uid` (a test listener and a client: `tcp_peer_uid` gives `getuid()`).
- [ ] **Step 2:** `cargo test -p saiife-darwin`; expect FAIL.
- [ ] **Step 3:** implement. Take the record sizes from the XNU headers of the macOS versions CI runs. A new macOS that changes them fails the live test, not a user's call: the call is denied.
- [ ] **Step 4:** the tests pass; the macOS-target check and `check-unsafe.sh` are clean.
- [ ] **Step 5:** commit `feat(darwin): the co-signer finds who asks (pcblist_n so_uid)`.

### Task 6: doctor, and the preview label (size S)

**Files:**
- Modify `crates/system/src/doctor/windows.rs` (`locked.preview`, `PREVIEW_LIMITS`), `crates/system/src/doctor/system.rs` (Unix), the tests, and `windows_tests.rs`.

**Interfaces:**
- Consumes `status.cosign.rejudge`, `status.cosign.asker` and `status.hooks_rejudge_denied` (Tasks 3 to 5).
- New checks, on every system install with Claude Code:
  - **`cosign.rejudge`:** Pass `the service judges each Claude Code call itself (<n> workers)`; Fail `the service cannot judge Claude Code calls (<error>), so every call is blocked`.
  - **`cosign.asker`:** Pass with the source; Fail `the co-signer cannot tell who asks (<platform reason>), so every Claude Code call is blocked`.
  - **`hooks.rejudge-denied`:** Warn when `since_start > 0`: `<n> call(s) the hook allowed were denied by the service's own judgment (last <ts>): a forged verdict, or a guard difference; see saiife audit --kind hook`.
- **`locked.preview` on Windows:**
  - It names only the installed agents without a co-signer: `Windows locked mode is a preview for Codex and Gemini CLI: a process of the agent's user can end their hook with exit 0`.
  - With only Claude Code installed, and `cosign.listen`, `cosign.rejudge` and `cosign.asker` all passing, it is Pass: `Windows locked mode for Claude Code: each call is judged by the hook and by the service`.
  - If any of the three fails, it stays Info with the old text.
- [ ] **Step 1: failing tests:** `preview_absent_for_claude_only_when_cosign_is_whole`, `preview_names_codex_and_gemini`, `preview_kept_when_rejudge_fails`, `rejudge_fail_check`, `asker_fail_check`, `rejudge_denied_warns_with_count`, and their Unix twins where they apply (no `locked.preview` there).
- [ ] **Step 2:** `cargo test -p saiife-system doctor`; expect FAIL.
- [ ] **Step 3:** implement; all values come from the one `status` call.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(doctor): the service's own judgment and asker; Windows locked mode is no preview for Claude Code`.

### Task 7: CI measures the forged append and the kill, and asserts a deny (size M)

**Files:**
- Create `scripts/locked-windows/forge-allow.ps1`, `scripts/locked-linux/forge-allow.py`.
- Modify `scripts/locked-windows/lib.ps1` (`phase_forge`, after `phase_cosign`), `scripts/locked-windows/run.ps1`, `scripts/locked-linux/lib.sh` and `run.sh`, `scripts/locked-macos/lib.sh` and `run.sh` (the same phase; macOS uses the Python probe on the control socket named in `/etc/saiife/config.toml`).

**Interfaces:**
- `forge-allow.ps1 -Payload <file>`, run as the agent: it opens `\\.\pipe\saiife` with `NamedPipeClientStream`, checks nothing (an attacker would not), and sends §8.7 frames:
  1. `hello`;
  2. `hook.begin {agent: "claude"}`;
  3. `hook.bind` with the payload's key (it computes `input_sha256` with the canonical form; the script carries a short canonical JSON writer, checked in the `test (windows-latest)` parse step against plan 20's `key_of_the_claude_fixture` hash for `claude/bash-allow.json`);
  4. `audit.append` of a guard record with `decision: "allow"`.

  It then holds the connection open for 10 s. `forge-allow.py` does the same over the Unix socket (stdlib only, run with `python3 -I`).
- `phase_forge`, asserted (each step fails the job):
  1. **The forged append:** run the real hook on `claude/bash-deny.json` with `SAIIFE_EVAL_FAULT=hang`, then `forge-allow` on the same payload, then `measure terminate <hook pid> 0`, then `Invoke-Cosign` with the payload. Assert the deny body with `the saiife service's own judgment denies this call`, one `hook` record with `event == "rejudge_denied"` and the agent's SID, and `doctor` `hooks.rejudge-denied` = warn. `Measure-Result 'forged-append'` prints the answer and the time.
  2. **The hook kill** (plan 20's step, kept): `TerminateProcess(hook, 0)` with no forger gives the `NoVerdict` deny.
  3. **The residual control:** a forged append for `claude/bash-allow.json` gives an empty `200` (the call is allowed by policy anyway), printed as a measurement.
  4. **The foreign asker:** `Invoke-Cosign` started as the approver account for the agent's bound key gives the `NoReport` deny (`Foreign`).
  5. **The honest path:** allow and deny fixtures through the hook plus `Invoke-Cosign`, as in plan 20; and the co-sign latency for the allow fixture after the hook's exit (50 runs, p95 printed; report-only, see Global Constraints).
  6. `saiife doctor --json`: `cosign.rejudge` = pass, `cosign.asker` = pass, and no `locked.preview` Info when only Claude Code is installed.
- Linux and macOS: steps 1 (with `kill -KILL` replaced by letting the real hook exit 2 after the forger appended: the co-signer must still deny) and 3 to 6, without the Windows-only parts.
- [ ] **Step 1:** write the scripts and phases.
- [ ] **Step 2:** locally only: `bash -n` and `shellcheck` on the shell files, `python3 -I -m py_compile scripts/locked-linux/forge-allow.py` (then delete `__pycache__`). The `.ps1` parse runs in `test (windows-latest)`. Never run the scripts.
- [ ] **Step 3:** commit `ci: locked-* forge a hook verdict and assert the co-signer's own deny`.

### Task 8: Windows hook speed: an option for the owner (size M, choice first)

The profiling round (`39f3b5a`, `SAIIFE_HOOK_TIMING`) came first. Its options A to D, plus E from F4:
- **A. The service judges, and the hook does not.** With this plan the service judges lexically anyway. For Claude Code, the hook would keep only the file-system part (symlinks, globs, project packs, pin check) in-process. It is the largest change, and it moves the guard's file-system work into a second code path. Not recommended now.
- **B. In-process judging in the hook for Claude Code** (no `__eval` child). A guard crash then kills the hook, which `onFailure: "block"` turns into a block, and plan 20's `no_verdict` record covers. This saves one `CreateProcess` plus image load (tens of ms on Windows). Codex and Gemini CLI keep the worker, because for them a crash would run the call (§9.3). **Default.**
- **C. Packs compiled at build time:** saves the regex compile per hook. It fits with B.
- **D. A pre-warmed worker:** the hook starts the worker before it reads stdin (`39f3b5a` already starts it early). Little is left to gain.
- **E. Exec form in the drop-in:** `"command": "C:/ProgramData/saiife/bin/saiife.exe", "args": ["check", "--managed", "--hook-exit", "--agent", "claude"]`. This takes Git Bash or PowerShell out of every real call. The bench does not see it, because it starts `saiife.exe` directly. It needs F5 resolved, and the Unix drop-in can keep shell form.

**Files (for B, the default):** modify `crates/cli/src/check_managed.rs` (`judge_call`: `agent == "claude"` judges with `eval::judge_with` on a thread with an 8 MiB stack, in the same `WORKER_TIMEOUT`), and its tests.
- [ ] **Step 0:** the owner picks. The coordinator records the choice here before dispatch.
- [ ] **Step 1: failing tests (B):** `claude_judges_in_process` (no child is spawned: the worker-spawn fault seam is never reached); `codex_still_uses_the_worker`; `claude_in_process_timeout_denies` (`SAIIFE_EVAL_FAULT=hang` in-process: deny at `WORKER_TIMEOUT`); `claude_in_process_panic_denies` (a panic is caught and denies with `error_denied`).
- [ ] **Step 2:** `cargo test -p saiife check_managed`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass. CI's `bench_managed` on both Windows runners is ≤ 130 ms p95 (read from the CI run; never run locally).
- [ ] **Step 5:** commit `perf(check): Claude Code's managed hook judges in-process (onFailure covers a crash)`.

### Task 9: docs and spec (size S)

**Files:**
- Modify the spec: §5.3a "Built" note and its plan 20 bullet, §5.3a.2 (W13: the co-signer's asker per platform), §6.1.1 (the co-signer re-judges), §6.16 (the new checks, `locked.preview`), §8.5 (the two events), §9.2 A21, A25 and a note under A18, §9.3 (a new row), §9.4 (a co-sign `rejudge_denied` record is the daemon's own judgment), §13 (`phase_forge`), §15 (row 21), §16.2 (the cut row, D1).
- Modify `docs/windows.md`, `docs/threats.md`, `docs/agents/claude-code.md`, `docs/agents/codex.md`, `docs/agents/gemini.md`, `CHANGELOG.md`, and `crates/cli/tests/docs_wording.rs`.

**Interfaces:**
- **A25, new text** (the numbers come from Task 7's CI run):
  - A process of the agent's user can still end the hook with exit 0, or begin, bind and append an allow itself.
  - **Claude Code:** the service judges every call itself, on the input Claude Code sent, and allows only what both the hook and the service allow. A forged allow of a call the policy denies is denied (measured on `windows-2022` and `windows-2025`).
  - **Left:** what only the user's own file system view decides (a junction, a symlink, a glob's matches, the project's extra packs). Code of the user can change these after any judgment (A21).
  - **Codex and Gemini CLI:** recorded only, and still preview.
  - **Not prevented:** a squat of `127.0.0.1:7433` while the service restarts.
- **§9.3, new row:** "a forged allow by a process of the agent's user (A25)": Claude Code **blocked (service judgment)**, Codex **runs; recorded**, Gemini CLI **runs; recorded**.
- **`docs/windows.md`:** "Locked mode" says Claude Code is no longer a preview and why, in two sentences. "Limits" keeps "preview" for Codex and Gemini CLI.
- [ ] **Step 1: failing tests** (`docs_wording`):
  - `windows_locked_mode_is_documented_as_preview` becomes `windows_preview_names_codex_and_gemini_only`;
  - `windows_limits_keep_preview_and_name_the_cosigner` gains `own judgment` and drops `with no code injection`;
  - `threats_a25_names_the_service_judgment` (A25 in `docs/threats.md` names `rejudge_denied`, `127.0.0.1:7433` and the file-system residual).
- [ ] **Step 2:** `cargo test -p saiife --test docs_wording`; expect FAIL.
- [ ] **Step 3:** write the docs and the spec changes.
- [ ] **Step 4:** the tests pass.
- [ ] **Step 5:** commit `docs: the service's own judgment closes the forged allow for Claude Code (A25); Windows preview for Codex and Gemini CLI only`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `-j 4`, `--test-threads=4`):
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`;
  - the tokio gate; `bash scripts/check-unsafe.sh`;
  - `cargo test --workspace`; `scripts/test-offline.sh`;
  - `bash scripts/check-windows.sh`; the macOS-target check;
  - `bash -n` and `shellcheck` on changed shell files.
- [ ] **CI and the owner:** the hook budgets (Linux +1 ms; Windows `bench_managed` ≤ 130 ms p95, or the owner's new number), the co-sign latency measurement, and `phase_forge` green on both `locked-windows` cells, both `locked-linux` cells and `locked-macos`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. The owner merges. No tag.

## Follow-ups (not in this plan)

- Close the restart-window port squat (D6). One option is a port the service holds through a restart (a socket handed to a successor). Another is to have Claude Code check the server, if it ever offers that.
- A co-signer for Codex and Gemini CLI, if either gains an HTTP hook type.
- The lexical view as a `saiife explain --lexical` switch for admins.

## Owner handwork

Nothing here runs on Claude's machine.

- [ ] Answer owner questions 1 to 5, and confirm D1 to D6.
- [ ] **In the plan 19b Windows VM, with a real Claude Code ≥ 2.1.295, from this branch's `ci-locked` build:**
  1. Ask for `ls` and for a denied read (`type %USERPROFILE%\.ssh\id_rsa`). The first runs, and the second is blocked by the hook. The daemon log shows one re-judge each.
  2. As the agent user, run `forge-allow.ps1` against a denied call while Claude runs it, and end the hook. The call is blocked with `the saiife service's own judgment denies this call`.
  3. Check the process tree: Claude Code, then `bash.exe` (or `powershell.exe`), then `saiife.exe`. Confirm that the depth is ≤ 3 (D2, question 4).
  4. Read Claude Code's `CHANGELOG.md` for the release that added `args` (F5). Then try the exec-form drop-in (option E) by hand, and time a dozen calls against shell form.
- [ ] **On a Mac with a real install:** `saiife doctor` shows `cosign.asker` pass (`pcblist`).

## Owner rulings (2026-11-09)
1. Re-judge on all three OSes: one code path, tested on Linux.
2. The port squat during a service restart is accepted and documented in A25. Doctor flags a failed bind.
3. Windows hook speed: option B, judge in the hook process for Claude Code only (a crash gets a co-signer deny). Then option E (hook in exec form, no shell) once the Claude Code version that supports `args` is confirmed. The 130 ms budget stays.
4. One `rejudge_denied` record per call, not folded.
5. Coordinator default, owner may overrule: Windows process-tree depth 3 (1 with exec form).
