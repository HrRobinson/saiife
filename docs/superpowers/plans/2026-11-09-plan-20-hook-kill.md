# Plan 20 — a killed or crashed hook never counts as an allow: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A hook that is killed, crashed or ended by another process never turns into an allow without a trace:
- **Claude Code** gets a second managed `PreToolUse` hook, of type `http`, with `onFailure: "block"`, that posts to the saiife daemon on loopback. The daemon answers deny unless the command hook has already recorded an allow for the same session, tool call id and input hash. A `TerminateProcess(hook, 0)` (A25) is then denied.
- **Every agent:** the hook registers with the daemon before it reads its input. The daemon notices a hook that ends without a verdict and writes a `hook` record plus a `doctor` warning. Record only, no automatic lockdown (owner ruling 2026-11-06).
- **Linux:** `/opt/saiife/bin/saiife` is installed at mode `0711`, so no other process of the same user can trace or read the hook. A check and a CI test prove it.
- **Docs:** the A25 row and §9.3 say what this changed. Windows locked mode stays a **preview** (see design change D4).

**Architecture:**
- **One key per call.** `HookKey { agent, session, tool_use_id, input_sha256 }`, where `input_sha256` is the SHA-256 of `tool_input` in a canonical JSON form (keys sorted at every level, compact). The command hook and the daemon compute it with the same function in `saiife-ipc`, so stdin and the HTTP body give the same key even if Claude Code formats them differently.
- **Hello-first.** `check --managed` loads the system config, connects, says `hook.begin`, and only then reads stdin. After stdin it sends `hook.bind` with the key, while the worker runs. The `audit.append` on that connection is the verdict.
- **The daemon's hook table** (`crates/daemon/src/hooks.rs`) follows each begun connection. A connection that ends without a verdict, or overruns, becomes a `hook` record with decision `no_verdict`, unless a second connection for the same key delivers the verdict within a grace period (the approval step's reconnect).
- **The co-signer** (`crates/daemon/src/cosign.rs`) is a small hyper HTTP/1 listener on `127.0.0.1:7433`. `POST /v1/cosign/claude` computes the key from the body and waits on the hook table: a recorded `allow` gets `200` with an **empty body** (no opinion, so the command hook's verdict and Claude Code's permission prompts stand); anything else gets `200` with a `permissionDecision: "deny"` body. Claude Code runs both hooks in parallel and takes the strictest answer (`deny` > `defer` > `ask` > `allow`), so either hook alone can deny.
- **Linux 0711.** An exec needs only execute permission; the kernel marks a process whose binary it cannot read as not dumpable, and `ptrace`, `/proc/<pid>/mem` and `process_vm_writev` then refuse the same uid.

**Tech Stack:** Rust workspace, no new crates. `sha2 = "0.10"` (already in `Cargo.lock`) is added to `saiife-ipc`. The co-signer uses the daemon's existing `hyper =1.12.0`, `hyper-util`, `http` and `tokio`. One new Windows FFI call (`setsockopt`, `SO_EXCLUSIVEADDRUSE`) in `crates/win/src/ffi/net.rs`; `windows-sys` gains the `Win32_Networking_WinSock` feature.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`: §5.2 (the binary row), §5.3a (the "Built" note), §6.1.1, §6.1.2, §6.1.3, §6.16, §8.3, §8.5, §9.2 A21 and A25, §9.3, §13. Read plan 19b (`docs/superpowers/plans/2026-10-30-plan-19b-windows-locked-mode.md`) first: its Global Constraints and W1–W28 apply here unchanged.

## Facts checked (2026-11-09)

Each fact the design summary (`hook-kill-design.md`, 2026-11-06) left unverified, with its source. **D** marks a fact that changed the design; the changes are listed after the table.

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | Claude Code HTTP hooks: `"type": "http"`, `url`, `headers`, `allowedEnvVars`, `timeout`, `onFailure`. The hook's JSON input is the POST body (`Content-Type: application/json`); the response body uses the command hooks' JSON output. | code.claude.com/docs/en/hooks, "HTTP hook fields" | Confirmed. HTTP hooks were added in 2.1.63 (code.claude.com/docs/en/changelog). |
| F2 | HTTP response handling: 2xx + empty body = success, like exit 0; 2xx + JSON object = parsed as hook output; 2xx + other body, non-2xx, connection failure = non-blocking error; timeout = canceled. "To block a tool call ... return a 2xx response with a JSON body containing the appropriate decision fields." | hooks, "HTTP response handling" | Confirmed. |
| F3 | `onFailure: "block"` on `command` and `http` hooks, **requires Claude Code v2.1.295 or later**. Failures: can't start, exit code other than 0 or 2, "an HTTP hook's connection fails, or the response status isn't 2xx", timeout, invalid output. On `PreToolUse` a failure blocks the call. An exit 0 is **not** a failure, even when forged. | hooks, "Block the action when a hook fails"; changelog 2.1.295 | Confirmed. No new version floor: doctor already fails below 2.1.295 (`crates/system/src/doctor/host.rs:1253`). |
| F4 | Parallel execution: "When an event fires, its matching hooks run in parallel." Precedence: "When multiple PreToolUse hooks return different decisions, precedence is `deny` > `defer` > `ask` > `allow`." A hook that exits 2 "routes the same way as `deny`". | hooks, "Hook lifecycle"; "PreToolUse decision control" | Confirmed. **D3**: no ordering between the two hooks, so the co-signer must wait for the command hook's verdict. |
| F5 | `permissionDecision: "allow"` "skips the permission prompt". | hooks, "PreToolUse decision control" | **D3**: the co-signer never answers `allow`; it answers an empty 2xx body. |
| F6 | `allowedHttpHookUrls`: scope "Any file", "Arrays merge across settings files", `*` wildcard, default unset (any URL). "When you define this key, Claude Code runs an HTTP hook only if its URL matches one of the patterns and blocks the rest without running them; an empty array blocks every HTTP hook." It "applies to hooks from every source, including managed settings." Since 2.1.267 an unreadable managed list admits nothing. `httpHookAllowedEnvVars` limits header interpolation the same way. | code.claude.com/docs/en/settings-reference, `allowedHttpHookUrls`, `httpHookAllowedEnvVars`; changelog 2.1.267 | **D1**: a user or project file can define the list and so silence an HTTP hook not on it. The managed drop-in therefore lists saiife's own URL; the lists merge, so it is always on the merged list. Whether a hook skipped by the list counts as a failure is **not documented**. saiife sends no headers, so `httpHookAllowedEnvVars` does not affect it. |
| F7 | Loopback and plain `http`: no rule restricts loopback or requires `https`; every example uses `http://localhost:8080/...`. | hooks, "HTTP hook fields"; hooks-guide, "HTTP hooks" | Allowed by example, **not stated**. The URL uses the literal `127.0.0.1`, not `localhost`, which may resolve to `::1` first. Owner handwork step 2 checks it on a real Claude Code. |
| F8 | Proxies: "Claude Code respects standard proxy environment variables" (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, lowercase too). The only stated loopback bypass is for WebSockets: "Claude Code never sends its WebSocket connections to `localhost`, `::1`, or `127.0.0.0/8` through the proxy". Nothing says whether HTTP hook requests use the proxy. A settings `env` value "overwrites the same variable exported in your shell". | code.claude.com/docs/en/network-config; settings-reference, `env` | **Not documented.** **D2**: on a machine with a proxy and no `127.0.0.1` in `NO_PROXY`, the co-sign request may go to the proxy, fail, and block every Claude Code call. The docs say to add `127.0.0.1` to `NO_PROXY`; owner handwork step 3 measures it; owner question 2. |
| F9 | Same-handler dedup: "If you define the same handler in more than one settings file, it runs once." | hooks, "Hook lifecycle" | Confirmed; the two saiife handlers differ, so both run. |
| F10 | `PreToolUse` input has `session_id`, `tool_name`, `tool_input` and `tool_use_id`. | hooks, "Common input fields", PreToolUse input example | Confirmed. `tool_use_id` is not read by saiife yet (no use in `crates/`). |
| F11 | Linux exec without read: `do_open_execat` opens with `acc_mode = MAY_EXEC`; `would_dump()` checks `MAY_READ` and on failure sets `BINPRM_FLAGS_ENFORCE_NONDUMP` ("If the binary is not readable then enforce mm->dumpable=0"); `begin_new_exec` then sets dumpable to `suid_dumpable`, not owner. | torvalds/linux `fs/exec.c` (master, read 2026-11-09) | Confirmed: a `0711` static binary runs for every user and is not dumpable. |
| F12 | `__ptrace_may_access` returns `-EPERM` when `!task_still_dumpable(task, mode)` (formerly `get_dumpable() != SUID_DUMP_USER`) and the caller lacks `CAP_SYS_PTRACE`; the same thread group is always allowed. `/proc/<pid>/mem` and `process_vm_writev` go through the same check. | torvalds/linux `kernel/ptrace.c` | Confirmed, for every `suid_dumpable` value (0 and 2 are both "not owner"). The process can still read its own `/proc/self`. |
| F13 | Windows: the hook's default process DACL grants its own user `0x1fffff` (`PROCESS_ALL_ACCESS`). | ci11 measurement `TerminateProcess-other-process`, `hook_sddl=...(A;;0x1fffff;;;<agent SID>)...` (`ci11-measurements.txt`) | Measured. **D4**: the same right allows `WriteProcessMemory` and `CreateRemoteThread`, so code of the agent's user can make the hook record an allow and then exit 0. The co-signer cannot catch that. |

### Design changes and notes (flagged for the owner)

- **D1. The managed drop-in declares `allowedHttpHookUrls`.** `"allowedHttpHookUrls": ["http://127.0.0.1:7433/*"]` goes in `50-saiife.json`. Without it, a user's `allowedHttpHookUrls` in `~/.claude/settings.json` would skip saiife's HTTP hook. With it, the merged list always admits it.
- **D2. Proxies.** Claude Code may route the co-sign request through `HTTPS_PROXY`/`HTTP_PROXY`. That fails closed (every call is blocked), and it does not fail open, unless the proxy is hostile and answers `2xx` with an empty body. A hostile proxy is code of the agent's user (A21) and needs a new Claude Code process started with that environment: `ConfigChange` already denies an `env` change in a running session (§6.1.1). This plan documents `NO_PROXY=127.0.0.1` and adds no managed `env` (owner question 2).
- **D3. The co-signer never says `allow`.** It answers an empty `200` for a recorded allow, so Claude Code's own permission prompts still apply, and the deny JSON otherwise. It waits for the command hook's verdict because the two hooks run in parallel.
- **D4. Windows: the co-signer closes the kill, not code injection.** The owner's own user has full access to the hook process (F13). Code of that user can inject into the hook and make it record an allow for a denied input. The co-signer then sees a recorded allow. This is A21-class, like the kill, and it is not measured. **Windows locked mode stays a preview.** The A25 row says the kill is denied for Claude Code and that injection is not prevented. A fix would have the daemon judge the co-signed input itself (owner question 3).
- **D5. Detection cannot always name the call.** The hook binds its key only after it has read stdin. A kill while it waits for stdin gives a `no_verdict` record without a key (`bound: false`). The co-signer then cannot match it, and denies at its 8 s cap instead of at once.
- **D6. Squatting the co-signer port on Windows.** While the service is down (a crash, before its 1 s restart), a process of the agent's user can bind `127.0.0.1:7433` and answer empty `200`s. It must also kill the command hook, which denies while the daemon is down. The daemon binds with `SO_EXCLUSIVEADDRUSE`. A failed bind is recorded and fails `doctor`, but a squat during the restart window is not prevented. On Linux, a squat gains nothing: a kill cannot forge exit 0 there, and `0711` blocks tracing.
- **D7. Codex and Gemini CLI get detection only** (no HTTP hook type is used for them). Their row in §9.3 stays "runs", now "runs; recorded". The `ConfigChange` hook is not co-signed: managed settings outrank whatever it lets through (owner question 4).

### Owner questions

1. **The port.** Is a fixed `127.0.0.1:7433`, not configurable, acceptable? A configurable port would have to be rendered into the managed drop-in at install time.
2. **Proxies (D2).** Should the drop-in set a managed `env` `NO_PROXY` that includes `127.0.0.1`? A managed value replaces the user's and the admin's own `NO_PROXY` entries, because env values do not merge. The plan's default is docs only, until handwork step 3 shows whether hook requests use the proxy at all.
3. **Injection on Windows (D4).** Should a later plan move the judgement into the daemon (the co-signer re-runs the guard), and does Windows stay a preview until then? The plan's default is yes to both. Should Claude Code on Windows lose its "preview" label once Task 9 is green? The plan's default is no, because of D4.
4. **`ConfigChange` (D7):** leave it without a co-signer?
5. **macOS:** keep the binary at `0755` and rely on the hardened runtime?
6. **Still open from the design (its Q3):** re-run the cross-user `TerminateProcess` with a real interactive logon (not `CreateProcessWithLogonW` from one session), in the plan 19b VM, to confirm it is a CI artifact.
7. **Folding:** is one `cosign_denied` record per reason per 10 s, with a `suppressed` count, enough for the audit?

## Consumes (verify at build time)

- **Plan 19b merged (main `0286c52`):** `saiife_ipc::client::Client::{connect, connect_pipe, call, hello_answer, is_poisoned}`, `saiife_ipc::msg::{OP_HELLO, OP_AUDIT_APPEND, ErrorCode}`, `PeerCred { uid, pid, sid, group_sids, .. }`, the daemon's `server::serve_peer`, `ops::Ctx`, `WriterHandle::append(Record)`, `saiife_audit::{Record, NewRecord, DecisionKind}`, `check_managed::{run, judge_call, connect_locked, append, start_watchdog}`, `eval::{fault, PARSE_MAX_BYTES}`, `claude::{managed_settings, managed_settings_for, HklmPolicy}`, `install.rs` `binary()`, `doctor/system.rs` `daemon_health` and the `files.binary` check, `scripts/locked-{linux,macos,windows}/`, `scripts/locked-windows/measure.c` (`spawn-hold`, `spawn-kill`, `terminate`).
- Where those landed with different names, the code wins and this plan is adjusted before the task starts.

## Global Constraints

- **Plan 19b's and 19a's Global Constraints apply in full.** Standing rules: no Windows machine, nothing privileged locally, `Child::kill` only on a test's own children, admin tests only in CI's `locked-*` jobs, test isolation (TMPDIR, SAIIFE_TEST_TMP, HOME, XDG_* in tempdirs), commit rules.
- **Tokio-free crates:** `saiife-guard`, `saiife-audit`, `saiife-policy`, `saiife-ipc` and `saiife-system` stay tokio-free (`cargo tree -e normal -p <crate>` shows no tokio). The co-signer and the hook table live in `saiife-daemon`, which uses tokio.
- **Unsafe only in FFI:** every `unsafe` block lives in `crates/win/src/ffi/` (or `crates/darwin`), with a `SAFETY:` comment. This plan adds one call, `setsockopt` (`SO_EXCLUSIVEADDRUSE`), in `crates/win/src/ffi/net.rs`; plan 19b's W1 list goes from 41 to 42 functions in Task 4. `bash scripts/check-unsafe.sh` exits 0.
- **Hook budget:** the managed hook on Linux stays within **+1 ms** of `main` (`scripts/bench-check.sh --managed`, run by CI or the owner, never by an agent). On Windows the hook stays at **p95 ≤ 130 ms** (the `test (windows-latest)` bench, and the new managed bench in `locked-windows`, Task 9).
- **CI job ids have no dots.** New steps go in existing jobs; any new job id is `[a-z0-9-]` only.
- **Secrets only on tags:** no new secret; no step that runs on `pull_request` or `push` to a branch reads one.
- **New dependencies:** none. `sha2 = "0.10"` and the `windows-sys` feature come from `Cargo.lock`.
- **Fixed values (copied into the spec in Task 10):**
  - co-signer address `127.0.0.1:7433`, path `/v1/cosign/claude`, URL `http://127.0.0.1:7433/v1/cosign/claude`, allow-list pattern `http://127.0.0.1:7433/*`;
  - HTTP hook `"timeout": 10`, `"onFailure": "block"`, no `headers`;
  - `COSIGN_WAIT = 8 s` (cap from the request's arrival), `RECONNECT_GRACE = 5 s`, `HOOK_OVERRUN = 10 s` (from `hook.begin`), `VERDICT_TTL = 60 s`, `MAX_KEYS = 4096`, `MAX_INFLIGHT = 16`, body cap `PARSE_MAX_BYTES` (64 MiB);
  - Linux binary mode `0711` (`root:root`); macOS and Windows unchanged;
  - the deny body, byte for byte: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): <reason>"}}`, with `<reason>` one of the `CosignDeny` texts in Task 4;
  - the new record kind `hook`, with `event` `no_verdict` or `cosign_denied` and decision `no_verdict` or `error_denied`.

## Review Focus

1. **Two connections for one call.** The approval step times out, the hook reconnects and appends on a new connection (`check_managed.rs`, `client.is_poisoned()`). Expected: no `no_verdict` record, and the co-signer answers per the second connection's verdict (Task 2: `a_reconnect_append_is_not_no_verdict`; Task 3: `poisoned_client_rebinds_on_the_new_connection`).
2. **The co-sign request arrives first.** On Windows the hook process starts tens of ms after Claude Code sends the POST. Expected: the co-signer waits and answers per the verdict, with no deny for an honest allow (Task 4: `cosign_waits_for_a_late_verdict`).
3. **stdin and the HTTP body differ only in formatting** (key order, whitespace, `\u` escapes). Expected: the same key, so an honest allow is not denied (Task 1: `key_ignores_order_whitespace_and_escapes`). A changed value gives another key (Task 1: `key_changes_with_any_value`).
4. **The port is taken at daemon start** (another program, or a squat). Expected: the daemon keeps running for the other agents, writes one `daemon` record with `event: "cosign_bind_failed"`, `status` shows `cosign.addr: null`, and doctor fails `cosign.listen`. Claude Code then blocks every call through `onFailure` (Task 4: `port_in_use_is_recorded_and_the_daemon_runs`; Task 6: `cosign_not_listening_fails`).
5. **A local web page or flood hits the port.** A browser POST carries `Origin`, so it gets `403`. Above 16 requests in flight the answer is `503`, and a body over 64 MiB gets the deny body. Each of these blocks only the request it answers. Co-sign deny records are folded to one per reason per 10 s, so a flood cannot grow the audit (A9) (Task 4: `origin_header_refused`, `inflight_cap_answers_503`, `oversize_body_denied`, `cosign_denied_records_are_folded`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (key and ops), Task 5 (managed drop-in), Task 7 (Linux 0711).
- **Wave 2 (parallel):** Task 2 (daemon hook table; needs 1), Task 3 (hello-first hook; needs 1).
- **Wave 3:** Task 4 (co-signer; needs 1, 2).
- **Wave 4 (parallel):** Task 6 (doctor; needs 2, 4, 7), Task 8 (locked-linux and locked-macos; needs 3–5, 7), Task 9 (locked-windows; needs 3–5).
- **Last:** Task 10 (docs and spec; needs the CI results of 8 and 9), the gates, a whole-branch review, one fix wave, push, PR, CI. The owner merges.

**Shared files:** `crates/daemon/src/ops.rs` (Task 2 adds the ops and the `status` fields; Task 4 adds `status.cosign`, so Task 4 rebases on Task 2), `crates/daemon/src/start.rs` (Task 4 only), `crates/cli/src/check_managed.rs` (Task 3 only), `crates/system/src/install.rs` (Task 7; Task 5 changes only `claude.rs`), `.github/workflows/ci.yml` (Tasks 8 and 9, different jobs).

---

### Task 1: the hook key and the hook ops (size S)

**Files:**
- Create `crates/ipc/src/hookkey.rs`; modify `crates/ipc/src/lib.rs`, `crates/ipc/src/msg.rs`, `crates/ipc/Cargo.toml` (`sha2 = "0.10"`).
- Modify `crates/guard/src/payload.rs` (`Envelope` and `HookContext` gain `tool_use_id`, with the `toolUseId` spelling too, as `session_id` has).

**Interfaces (Produces):**
- `pub struct HookKey { pub agent: String, pub session: Option<String>, pub tool_use_id: Option<String>, pub input_sha256: String }` (`Serialize`, `Deserialize`, `Clone`, `Eq`, `Hash`).
- `pub fn hook_key(agent: &str, payload: &str) -> Result<HookKey, KeyError>`: parses the payload, takes `session_id`/`sessionId`, `tool_use_id`/`toolUseId`, and hashes `tool_input` (or `toolInput`; `null` when absent). `KeyError::{Json(String), TooLarge}` over `PARSE_MAX_BYTES`; the cap is passed in as `max_bytes: usize` in `hook_key_bounded`, which `hook_key` calls with 64 MiB.
- `pub fn canonical_sha256(v: &serde_json::Value) -> String` (lowercase hex): objects with keys sorted by byte order at every level, arrays in order, compact, serde_json's own number and string formatting. It must not rely on map order: the workspace builds serde_json with `preserve_order` (`crates/agents/Cargo.toml`).
- `HookKey::cosignable(&self) -> bool`: `agent == "claude"`, and `session` and `tool_use_id` are both non-empty.
- `msg::OP_HOOK_BEGIN = "hook.begin"` (args `{agent, event}`; answer `{}`), `msg::OP_HOOK_BIND = "hook.bind"` (args: the `HookKey` fields; answer `{}`).
- `HookContext.tool_use_id: Option<String>`.

- [ ] **Step 1: failing tests** (`crates/ipc/src/hookkey.rs`, `crates/guard/src/payload.rs`):
  - `key_of_the_claude_fixture`: `hook_key("claude", <crates/cli/tests/fixtures/claude/bash-allow.json>)` has `session == Some("c-1")`, `tool_use_id == Some("toolu_02")`, and `input_sha256 == sha256_hex(br#"{"command":"ls -la","description":"List files"}"#)`;
  - `key_ignores_order_whitespace_and_escapes`: `{"tool_input":{"b":1,"a":"é"}}` and `{ "tool_input" : { "a" : "é", "b" : 1 } }` give the same `input_sha256`;
  - `key_changes_with_any_value` (one changed character in `command`, in `description`, and in a nested array);
  - `missing_tool_input_hashes_null`; `camel_case_fields_read`; `not_cosignable_without_tool_use_id`; `not_cosignable_for_codex`;
  - `oversize_payload_is_too_large` (with `hook_key_bounded`, cap 16);
  - `context_reads_tool_use_id` (guard).
- [ ] **Step 2:** `cargo test -p saiife-ipc hookkey -p saiife-guard payload`; expect FAIL (no `hookkey` module).
- [ ] **Step 3:** implement. The canonical form is a short recursive writer into a `Sha256` hasher. Do not round-trip through a `BTreeMap` of `Value`, which would still print in insertion order under `preserve_order`.
- [ ] **Step 4:** the tests pass; `cargo tree -e normal -p saiife-ipc` shows no tokio; the Windows check (`bash scripts/check-windows.sh`) is clean.
- [ ] **Step 5:** commit `feat(ipc): hook key (canonical input hash) and the hook.begin / hook.bind ops`.

### Task 2: the daemon's hook table and the `no_verdict` record (size M)

**Files:**
- Create `crates/daemon/src/hooks.rs`.
- Modify `crates/daemon/src/server.rs` (each connection gets a `ConnId`; on its end, call `HookTable::ended`), `crates/daemon/src/ops.rs` (route the two ops; `audit.append` on a bound connection calls `verdict`; `status` gains `hooks_no_verdict`), `crates/daemon/src/lib.rs`, and `crates/audit/src/record.rs` (`DecisionKind::NoVerdict`, serialized `no_verdict`).

**Interfaces:**
- Consumes `HookKey`, `OP_HOOK_BEGIN`, `OP_HOOK_BIND` (Task 1).
- Produces, in `saiife_daemon::hooks`:
  - `pub struct ConnId(u64)`, handed out by `server.rs`;
  - `pub struct HookTable` in `Ctx` as `ctx.hooks: Arc<HookTable>`, with:
    - `fn begin(&self, conn: ConnId, peer: &PeerCred, agent: &str, event: Option<&str>)`;
    - `fn bind(&self, conn: ConnId, key: HookKey)`;
    - `fn verdict(&self, conn: ConnId, decision: DecisionKind)` (called after the append is written; `allow` and every other decision);
    - `fn ended(&self, conn: ConnId)`;
    - `async fn wait(&self, key: &HookKey, until: Instant) -> Waited`, where `pub enum Waited { Allow, Deny, NoVerdict, Timeout }`. Task 4 uses this.
  - `pub fn no_verdict_count(&self) -> (u64, Option<String /*ts*/>)` for `status`.
  - The constants `RECONNECT_GRACE = 5 s`, `HOOK_OVERRUN = 10 s`, `VERDICT_TTL = 60 s`, `MAX_KEYS = 4096` (oldest dropped first).
- Behaviour:
  - A connection that began and ends (EOF, error, or the daemon's own `HOOK_OVERRUN` close) without a verdict starts the grace period: bound, `RECONNECT_GRACE` for a verdict on the same key from another connection; unbound, none.
  - After that, one record: `kind: "hook"`, `decision: "no_verdict"`, `agent`, `uid`/`sid`/`user` from the peer, `session`, `tool` (when bound and known, else `""`), `input: ""`, `reason: "the hook ended without a verdict (killed, crashed or timed out)"`, and extra fields `event: "no_verdict"`, `bound`, `tool_use_id`, `input_sha256`, `elapsed_ms`, `pid`. Waiters on that key get `NoVerdict`.
  - A connection that never sent `hook.begin` (a CLI command) is never tracked. A second `hook.begin` on one connection is refused with `bad_request`.
- `status` gains `"hooks_no_verdict": {"since_start": <n>, "last_ts": <ts|null>}`.

- [ ] **Step 1: failing tests** (`crates/daemon/src/hooks.rs` unit tests with tokio's paused clock; an integration test in `crates/daemon/tests/hooks.rs` over the real socket, unix only):
  - `verdict_then_end_writes_nothing`;
  - `end_without_verdict_writes_one_record` (every field above; `decision == NoVerdict`, `extra["event"] == "no_verdict"`, `bound == true`);
  - `unbound_end_writes_bound_false`;
  - `a_reconnect_append_is_not_no_verdict` (conn A binds K and ends; conn B binds K and appends an allow within 5 s: no record, `wait(K)` gives `Allow`);
  - `grace_expires_into_no_verdict` (B never comes: the record lands at 5 s);
  - `overrun_is_closed_and_recorded` (no verdict 10 s after `begin`: the daemon closes the connection and records);
  - `cli_connections_are_not_tracked`; `second_begin_refused`;
  - `table_is_bounded` (4097 keys: the first is gone, and `wait` on it gives `Timeout` at its deadline);
  - `status_counts_no_verdict`;
  - `record_round_trips_no_verdict` (audit crate: `no_verdict` serializes and parses; an older reader gets `Unknown`).
- [ ] **Step 2:** `cargo test -p saiife-daemon hooks -p saiife-audit record`; expect FAIL.
- [ ] **Step 3:** implement. The table is one `Mutex<State>` with a `tokio::sync::Notify` per key, never held across an `.await`. The grace and overrun timers are `tokio::time::sleep_until` tasks keyed by `ConnId`.
- [ ] **Step 4:** the tests pass; the Windows check is clean (the named-pipe `connection` in `server.rs` gets its `ConnId` the same way).
- [ ] **Step 5:** commit `feat(daemon): track hook connections; record a hook that ends without a verdict`.

### Task 3: the hook registers before it reads its input (size M)

**Files:**
- Modify `crates/cli/src/check_managed.rs`; `crates/cli/tests/` (the managed-hook tests that use a fake daemon).

**Interfaces:**
- Consumes `hook_key_bounded`, `OP_HOOK_BEGIN`, `OP_HOOK_BIND` (Task 1).
- The new order of `run` (the §6.1.2 pseudo-code is updated to match in Task 10):
  1. load the system config (on Windows the pipe is fixed, as now);
  2. `connect_locked` and `hook.begin {agent, event}`;
  3. read stdin;
  4. lockdown check, project, policy, and spawn the worker, as now;
  5. while the worker runs, `hook.bind` with `hook_key_bounded(agent, &input, PARSE_MAX_BYTES)`. A key error means no bind, and nothing else changes;
  6. as now: the approval step, `audit.append`, the answer.
  - After a poisoned client, the new connection sends `hook.begin` and `hook.bind` (same key) before its `audit.append`.
- A config that fails to load still denies as now. On Linux there is then no socket to register with, so no `no_verdict` record can follow: that is a deny, not a forged allow.
- `connect_locked` moves out of `judge_call`; `judge_call` takes the connected `Client` instead of `&mut Option<Client>`.
- **Budget fallback,** only if the bench in Step 4 is over +1 ms: start step 2 on a helper thread before step 3, and join it before step 5. Note it in the commit message.

- [ ] **Step 1: failing tests** (`crates/cli/src/check_managed.rs` tests with the existing fake-daemon harness):
  - `begin_comes_before_stdin_is_read`: the fake daemon sees `hook.begin` while the test still holds the hook's stdin open, with no byte written;
  - `bind_carries_the_key`: for `claude/bash-allow.json`, the bound key equals `hook_key("claude", payload)`;
  - `bind_precedes_append_on_one_connection`;
  - `poisoned_client_rebinds_on_the_new_connection` (the fake daemon times out `approval.create`: the second connection sends `hook.begin`, then `hook.bind` with the same key, then `audit.append`);
  - `unparseable_payload_still_appends_error_denied_without_bind`;
  - `daemon_down_still_denies` (the existing fail-closed tests stay green unchanged).
- [ ] **Step 2:** `cargo test -p saiife check_managed`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `scripts/test-offline.sh` passes; the Windows check is clean. The managed bench is left to CI and the owner (Global Constraints).
- [ ] **Step 5:** commit `feat(check): register with the daemon before reading the payload; bind the hook key`.

### Task 4: the co-signer (size L)

**Files:**
- Create `crates/daemon/src/cosign.rs` and `crates/win/src/ffi/net.rs`; modify `crates/win/src/ffi/mod.rs`, `crates/win/Cargo.toml` (`Win32_Networking_WinSock`), `crates/daemon/src/start.rs` (bind and spawn after the control endpoint is open, on Linux, macOS and Windows, system mode only), `crates/daemon/src/ops.rs` (`status.cosign`), `crates/system/src/layout.rs` (`COSIGN_ADDR = "127.0.0.1:7433"`), `scripts/check-unsafe.sh` (the FFI count), and plan 19b's W1 list in `docs/superpowers/plans/2026-10-30-plan-19b-windows-locked-mode.md` (+`net.rs: setsockopt`).

**Interfaces:**
- Consumes `HookTable::wait` and `Waited` (Task 2), and `hook_key_bounded` (Task 1).
- Produces:
  - `pub fn bind_cosign(addr: SocketAddr) -> io::Result<tokio::net::TcpListener>`: a `TcpSocket` with `SO_EXCLUSIVEADDRUSE` on Windows (`saiife_win::ffi::net::exclusive_addr_use(sock: RawSocket) -> io::Result<()>`) and `SO_REUSEADDR` off everywhere;
  - `pub async fn serve_cosign(listener: TcpListener, ctx: Arc<Ctx>)`;
  - `pub enum CosignDeny { NoReport, NoVerdict, Denied, NotCosignable, TooLarge, BadJson }`, with the texts `no saiife hook reported a verdict for this call`, `the saiife hook ended without a verdict`, `saiife denied this call`, `the call has no session or tool use id`, `the payload is too large`, `the payload is not JSON`.
- Request handling (HTTP/1.1 only):
  - only `POST /v1/cosign/claude`, else `404`;
  - an `Origin` header present gives `403`; a `Content-Type` other than `application/json` (parameters allowed) gives `415`;
  - more than `MAX_INFLIGHT = 16` requests in flight gives `503`;
  - the body is read up to `PARSE_MAX_BYTES`; over that, the deny body with `TooLarge`;
  - else `hook_key_bounded("claude", body)`; not cosignable gives `NotCosignable`; then `ctx.hooks.wait(&key, arrival + COSIGN_WAIT)`:
    - `Allow` gives `200`, `Content-Length: 0`;
    - `Deny` gives the deny body with `Denied`; no record (the guard record says why);
    - `NoVerdict` gives `NoVerdict`, `Timeout` gives `NoReport`; both write a record.
  - Every non-allow answer is `200` with the Global Constraints deny body, so Claude Code reads it as a deny (F2) and not as a failure. (`onFailure` would block a failure too.)
- The record for `NoVerdict`, `NoReport`, `NotCosignable`, `TooLarge` and `BadJson`: `kind: "hook"`, `decision: "error_denied"`, `agent: "claude"`, `tool` from `tool_name`, `input` = the command or path the guard would show (masked by `Record::new`), `session`, `reason` = the `CosignDeny` text, extra `event: "cosign_denied"`, `tool_use_id`, `input_sha256`. No `uid`: a TCP peer is not identified on Windows (W13). Folding: at most one such record per `CosignDeny` value per 10 s, and the next one carries `suppressed: <n>`.
- Startup: a bind failure does not stop the daemon. It writes a `daemon` record with `event: "cosign_bind_failed"` and `reason: <the io error>`, logs the line `co-signer 127.0.0.1:7433 is not available: <error>; Claude Code calls are blocked until it is`, and `status` shows `"cosign": {"addr": null, "error": "<error>"}`. On success it shows `{"addr": "127.0.0.1:7433", "error": null}`.
- Personal mode and developer mode never bind it.

- [ ] **Step 1: failing tests** (`crates/daemon/tests/cosign.rs`, a hyper client on loopback against a daemon started on a test port; `COSIGN_ADDR` is a parameter of `start` in tests):
  - `recorded_allow_gets_empty_200` (a hook connection binds K and appends an allow; then the POST of the same payload gets `200`, empty body);
  - `cosign_waits_for_a_late_verdict` (the POST first, the allow 300 ms later: `200` empty);
  - `recorded_deny_gets_deny_body` (byte-for-byte body, reason `saiife denied this call`; no new record);
  - `killed_hook_gets_deny_at_once` (bound, then the connection drops: deny `NoVerdict` within `RECONNECT_GRACE` plus 1 s, not at 8 s; a `cosign_denied` and a `no_verdict` record);
  - `no_hook_at_all_denies_at_the_cap` (tokio paused clock: deny `NoReport` at 8 s);
  - `other_payload_does_not_match` (allow recorded for `ls -la`; the POST says `rm -rf /` with the same `tool_use_id`: deny);
  - `not_cosignable_without_tool_use_id`;
  - `origin_header_refused` (403), `wrong_content_type_refused` (415), `wrong_path_404`, `get_404`;
  - `inflight_cap_answers_503` (17 held requests);
  - `oversize_body_denied` (cap lowered to 1 KiB through the test parameter);
  - `cosign_denied_records_are_folded` (20 `NoReport` answers in 10 s: one record, then one with `suppressed: 19`);
  - `port_in_use_is_recorded_and_the_daemon_runs` (the test binds the port first: the daemon starts, `status.cosign.addr` is null, a `daemon` record has `event == "cosign_bind_failed"`, and `audit.append` still works);
  - `personal_mode_does_not_bind`;
  - Windows CI (`test (windows-latest)`, no admin): `exclusive_addr_blocks_a_second_bind` (a second `TcpListener::bind` on the same address fails).
- [ ] **Step 2:** `cargo test -p saiife-daemon --test cosign`; expect FAIL.
- [ ] **Step 3:** implement. Reuse the gateway's hyper `serve_connection` setup (`crates/daemon/src/gateway.rs`, `serve_tcp`), with its header and read timeouts. Do not use the gateway's bearer-token path: the co-signer has no token, because its answer only ever takes away.
- [ ] **Step 4:** the tests pass; `bash scripts/check-unsafe.sh` exits 0 with the new count; the Windows check is clean; the tokio gate is clean for the tokio-free crates.
- [ ] **Step 5:** commit `feat(daemon): Claude Code co-signer on 127.0.0.1:7433 (deny unless the hook recorded an allow)`.

### Task 5: the managed drop-in carries the HTTP hook (size S)

**Files:**
- Modify `crates/agents/src/claude.rs` (`MANAGED_SETTINGS`, `managed_settings_for`, and `COSIGN_URL`, `COSIGN_URL_PATTERN`); `crates/agents/tests/fixtures/managed/` (expected files); `crates/system/src/doctor/` where `agents.claude.policy` reads the drop-in back; `crates/system/src/layout.rs` test `cosign_addr_matches_the_claude_url`.

**Interfaces:**
- Produces: `claude::COSIGN_URL = "http://127.0.0.1:7433/v1/cosign/claude"`, `claude::COSIGN_URL_PATTERN = "http://127.0.0.1:7433/*"`.
- The drop-in, byte for byte (Windows differs in the command path only, as now):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude",
                     "timeout": 10, "onFailure": "block" },
                   { "type": "http",
                     "url": "http://127.0.0.1:7433/v1/cosign/claude",
                     "timeout": 10, "onFailure": "block" } ] }
    ],
    "ConfigChange": [
      { "hooks": [ { "type": "command",
                     "command": "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude --event config-change",
                     "timeout": 10, "onFailure": "block" } ] }
    ]
  },
  "allowedHttpHookUrls": ["http://127.0.0.1:7433/*"],
  "disableAllHooks": false
}
```

- `agents.claude.policy` fails when the installed drop-in lacks the `http` entry or the allow-list line: `the Claude Code drop-in has no saiife co-signer hook; run saiife system install`. Install rewrites it like any other changed managed file.
- The HKLM check (W24): a merged HKLM `Settings` that sets `allowedHttpHookUrls` is fine (the lists merge), so `WeakensHooks` does not change.

- [ ] **Step 1: failing tests:**
  - `managed_settings_bytes` (the block above, exactly);
  - `windows_differs_in_the_command_only`;
  - `http_hook_has_no_headers` (no `headers`, no `allowedEnvVars`);
  - `allow_list_admits_the_url` (`COSIGN_URL` matches `COSIGN_URL_PATTERN` with `*` as any run of characters);
  - `cosign_addr_matches_the_claude_url` (system);
  - `drop_in_without_cosign_fails_policy` (doctor, with `FakeHost` holding the old file).
- [ ] **Step 2:** `cargo test -p saiife-agents claude -p saiife-system`; expect FAIL.
- [ ] **Step 3:** implement; update the lock-check fixtures that embed the drop-in (`scripts/lock-check/lib.sh` writes it from the same text, so check that it reads it from `saiife` and does not keep a copy).
- [ ] **Step 4:** the tests pass; `bash scripts/lock-check/test-lib.sh` passes.
- [ ] **Step 5:** commit `feat(agents): Claude Code managed drop-in gains the co-signer HTTP hook and its URL allow-list`.

### Task 6: doctor (size S)

**Files:**
- Modify `crates/system/src/doctor/system.rs` (Unix), `crates/system/src/doctor/windows.rs`, and their tests.

**Interfaces:**
- Consumes `status.cosign` and `status.hooks_no_verdict` (Tasks 2 and 4), and the 0711 mode (Task 7).
- New checks:
  - **`cosign.listen`:** Fail when Claude Code is in `installed.toml` and `status.cosign.addr` is null: `the co-signer is not listening on 127.0.0.1:7433 (<error>), so Claude Code blocks every call`. Pass with the address. Info when Claude Code is not installed.
  - **`hooks.no-verdict`:** Warn when `since_start > 0`: `<n> hook call(s) ended without a verdict since the daemon started (last <ts>): a hook was killed, crashed or timed out; see saiife audit --kind hook`. Pass at 0.
  - **`files.binary` on Linux:** an `EACCES` read as a non-root caller is Info, `not readable by this user (mode 0711, so no process of the user can trace a hook)`. A mode other than `0711` is Warn: `/opt/saiife/bin/saiife is <mode>, expected 0711; run saiife system install`.
- [ ] **Step 1: failing tests:** `cosign_not_listening_fails`, `cosign_listening_passes`, `cosign_info_without_claude`, `no_verdict_warns_with_count`, `no_verdict_zero_passes`, `binary_unreadable_is_info_for_non_root`, `binary_0755_warns_on_linux`, `binary_mode_not_checked_on_macos`, and the Windows twins of the first five in `windows_tests.rs`.
- [ ] **Step 2:** `cargo test -p saiife-system doctor`; expect FAIL.
- [ ] **Step 3:** implement; both new values come from the one `status` call `daemon_health` already makes.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(doctor): co-signer listening, hooks without a verdict, the 0711 binary`.

### Task 7: the Linux binary at 0711 (size S)

**Files:**
- Modify `crates/system/src/install.rs` (`binary()`), `crates/system/src/layout.rs` (`BINARY_MODE`), and the install tests.

**Interfaces:**
- Produces `layout::binary_mode(platform: Platform) -> u32`: `0o711` on Linux, `0o755` on macOS (the hardened runtime already refuses `task_for_pid`; owner question 5), unused on Windows.
- `binary()` writes with `binary_mode`, and an existing `0755` binary with the same bytes is re-moded (the existing `set_file_mode` path) and shown as changed. `installed.toml` records the new mode, so doctor's `files.installed` compares against it.
- The `/usr/local/bin/saiife` symlink is unchanged (exec through it works at `0711`).
- [ ] **Step 1: failing tests:** `binary_is_0711_on_linux`, `binary_is_0755_on_macos`, `reinstall_moves_0755_to_0711` (`FakeHost`: a recorded `0755` binary, same bytes: one change line, mode now `0711`), `installed_toml_records_0711`.
- [ ] **Step 2:** `cargo test -p saiife-system install`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass.
- [ ] **Step 5:** commit `feat(install): Linux binary at 0711 so the hook cannot be traced by its own user`.

### Task 8: `locked-linux` and `locked-macos` prove it (size M)

**Files:**
- Modify `scripts/locked-linux/lib.sh` and `run.sh`, `scripts/locked-macos/lib.sh` and `run.sh`. Create `scripts/locked-linux/ptrace-probe.py`. The CI jobs `locked-linux` and `locked-macos` keep their ids.

**Interfaces:**
- Consumes the `saiife` CLI with Tasks 2–7.
- `phase_modes` (Linux): `expect_stat "$OPT_BIN" "root:root 711"`, and `cat "$OPT_BIN"` as the agent is denied.
- New `phase_cosign` (both OSes, after `phase_hooks`), with `cosign_post <payload>` = `curl -sS -o body -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:7433/v1/cosign/claude` (curl is on both runners):
  - the allow fixture, run through the hook and POSTed at the same time: `200`, empty body;
  - the deny fixture: `200`, the deny body, reason `saiife denied this call`;
  - **the kill:** the allow fixture through the hook as the agent with `SAIIFE_EVAL_FAULT=hang` (the worker hangs, so the hook is bound and waiting); POST it; the runner then ends the hook with `kill -KILL` (CI only, on its own child). Expect: the POST gets the deny body with `the saiife hook ended without a verdict` in under 7 s; one `hook` record with `event == "no_verdict"` and `bound == true`; `saiife doctor --json` has `hooks.no-verdict` = warn;
  - no hook at all: a POST of a fresh `tool_use_id` gets the deny body with `no saiife hook reported a verdict for this call` after about 8 s;
  - `curl -H 'Origin: http://example.com'` gets `403`.
- New `phase_ptrace` (Linux only, after `phase_modes`): `ptrace-probe.py` (stdlib `ctypes`, run with `python3 -I`), as the agent:
  - it starts `$OPT_BIN check --managed --hook-exit --agent claude` with stdin held open (so the hook is its own child, which Yama `ptrace_scope=1` allows);
  - it tries `PTRACE_ATTACH` and an open of `/proc/<pid>/mem`. Expect `EPERM` for both, and the hook's `/proc/<pid>/status` shows its uid;
  - **the control:** a `0755` copy in the agent's home, started the same way, attaches (exit 0), which shows the probe works.
- [ ] **Step 1:** write the phases and the probe.
- [ ] **Step 2:** locally only: `bash -n scripts/locked-linux/*.sh scripts/locked-macos/*.sh`, `shellcheck` on them if installed, and `python3 -I -m py_compile scripts/locked-linux/ptrace-probe.py` (writes into `__pycache__`; delete it). Never run the scripts.
- [ ] **Step 3:** commit `ci: locked-linux and locked-macos prove the co-signer, the no-verdict record and the 0711 binary`.

### Task 9: `locked-windows` re-runs the hook-kill measurement with the co-signer on (size M)

**Files:**
- Modify `scripts/locked-windows/lib.ps1` (`measure_terminate`, a new `phase_cosign`), `scripts/locked-windows/measure.c` (a `spawn-fed-hold` mode), `scripts/locked-windows/run.ps1` (phase order).

**Interfaces:**
- `measure spawn-fed-hold <hook> <agent> <payload file> <pid file> <wait seconds>`: starts the hook with the payload on stdin, closes stdin, writes the pid, and waits up to `<wait>` s for the hook's exit, printing `child_exit=<n>` as `spawn-hold` does. It inherits the caller's environment, so `SAIIFE_EVAL_FAULT=hang` reaches the hook (`ci-locked` has debug assertions).
- `Invoke-Cosign -PayloadJson <s>`: `Invoke-WebRequest -Method Post -Uri http://127.0.0.1:7433/v1/cosign/claude -ContentType application/json -Body $s -SkipHttpErrorCheck -TimeoutSec 12`; it returns status, body and elapsed time.
- `measure_terminate` keeps its three measurements unchanged, so the CI 11 results stay comparable, and gains **asserted** steps (these fail the job, unlike the report-only measurements):
  1. **own child, co-signer on:** `spawn-fed-hold` with `SAIIFE_EVAL_FAULT=hang` as the agent; `Invoke-Cosign` with the same payload, started at the same time as a job; then `measure terminate <pid> 0` as the agent. Assert: `child_exit=0` (the forged exit still happens); the co-sign answer is `200` with the deny body and reason `the saiife hook ended without a verdict`, within 7 s; a new `hook` record with `event == "no_verdict"`, `bound == true` and the agent's SID; the audit grew. `Measure-Result 'TerminateProcess-cosign'` prints the three facts.
  2. **killed while waiting on stdin** (the CI 11 `spawn-hold` case): assert the co-sign answer is the deny body with `no saiife hook reported a verdict for this call` (about 8 s, D5), and a `no_verdict` record with `bound == false`.
  3. **controls:** the allow fixture through the hook plus `Invoke-Cosign` gives `200` with an empty body; the deny fixture gives the deny body with `saiife denied this call`.
  4. `saiife doctor --json` as the elevated runner: `hooks.no-verdict` = warn, `cosign.listen` = pass.
- `phase_cosign` also asserts that `Get-NetTCPConnection -LocalPort 7433 -State Listen` has `OwningProcess` equal to the service's pid, and that a bind of `127.0.0.1:7433` as the agent fails while the service runs.
- A managed hook bench: 50 runs of the allow fixture as the agent, with p95 ≤ 130 ms asserted (`Measure-Result 'managed-hook-p95'` prints it).
- [ ] **Step 1:** write the changes.
- [ ] **Step 2:** locally nothing runs. The `test (windows-latest)` cell parses every `.ps1` (the existing step), and `measure.c` is built by `Build-Native` in the job.
- [ ] **Step 3:** commit `ci: locked-windows re-runs TerminateProcess with the co-signer on and asserts the deny`.

### Task 10: docs and spec (size S)

**Files:**
- Modify the spec: §5.2 table (`/opt/saiife/bin/saiife | root:root | 0711`), §6.1.1 (the co-signer bullet and hello-first), §6.1.2 (the new order), §6.1.3 (Claude Code's row names the co-signer), §6.16 (the three doctor checks), §8.3 (the drop-in of Task 5, byte for byte), §8.5 (kind `hook`, decision `no_verdict`, the extra fields), §9.2 A21 and A25, §9.3, §13 (the CI phases), §15 row 20, §5.3a "Built (plan 19b)" (one line pointing to A25).
- Modify `docs/threats.md`, `docs/agents/claude-code.md`, `docs/agents/codex.md`, `docs/agents/gemini.md`, `docs/windows.md` (`#limits`), `docs/install.md` (a `NO_PROXY` note), `CHANGELOG.md`, and `crates/cli/tests/docs_wording.rs`.

**Interfaces:**
- **A25, new text** (the measured numbers come from Task 9's CI run): Forge the hook's verdict on Windows. A process of the agent's user can still end the hook with `TerminateProcess(hook, 0)`, but:
  - **Claude Code:** the co-signer then finds no recorded allow and denies the call (measured on `windows-2022` and `windows-2025`, with Claude Code's request simulated);
  - **Codex and Gemini CLI:** the call runs, and the daemon records `no_verdict`, and `doctor` warns;
  - **not prevented:** code injected into the hook (the user has full access to its own processes), and a squat of `127.0.0.1:7433` while the service restarts. Windows locked mode stays a preview.
  - On Linux the binary is `0711`, so the hook cannot be traced, and a kill cannot choose an exit code.
- **§9.3:** the A25 row reads Claude Code **blocked (co-signer)**, Codex **runs; recorded**, Gemini CLI **runs; recorded**. The "`check` parent killed or crashes" row for Codex and Gemini gains "; recorded". A new row, "co-signer not listening", reads Claude Code **blocked (`onFailure`)**, others n/a.
- **A21:** one sentence: a hook it kills is recorded (`no_verdict`).
- **`docs/install.md`:** with `HTTPS_PROXY` or `HTTP_PROXY` set for Claude Code, add `127.0.0.1` to `NO_PROXY`, or every Claude Code call is blocked.
- [ ] **Step 1: failing tests** (`docs_wording`): `docs/threats.md` names `co-signer`, `127.0.0.1:7433` and `no_verdict`; `docs/install.md` contains `NO_PROXY` and `127.0.0.1`; `docs/windows.md` still says `preview`; the spec's §8.3 Claude block equals `claude::managed_settings()` (extend the existing spec-sync test if there is one, otherwise add `spec_83_matches_the_drop_in`).
- [ ] **Step 2:** `cargo test -p saiife --test docs_wording`; expect FAIL.
- [ ] **Step 3:** write the docs and the spec changes.
- [ ] **Step 4:** the tests pass.
- [ ] **Step 5:** commit `docs: co-signer, no-verdict records, Linux 0711; A25 and the fail-closed matrix`.

## Finish

- [ ] **Gates** (with TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `-j 4`, `--test-threads=4`):
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`;
  - the tokio gate for `saiife-guard`, `saiife-audit`, `saiife-policy`, `saiife-ipc` and `saiife-system`; `bash scripts/check-unsafe.sh`;
  - `cargo test --workspace` and `scripts/test-offline.sh`;
  - `bash scripts/check-windows.sh` and the macOS-target check;
  - `bash -n` and `shellcheck` on the changed shell scripts; `scripts/lock-check/test-lib.sh`.
- [ ] **The hook budget**, by CI and the owner: `scripts/bench-check.sh --managed` against `main` on Linux (+1 ms at most), the `test (windows-latest)` bench (p95 ≤ 130 ms), and Task 9's managed bench.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. CI must be green, including both `locked-linux` cells, `locked-macos`, both `locked-windows` cells and `test (windows-latest)`. The owner merges. No tag.

## Follow-ups (not in this plan)

- The daemon judges the co-signed input itself, with the system policy and the project config the record names. That would close D4, injection on Windows, for Claude Code.
- A hardened hook process DACL on Windows, using an `OWNER RIGHTS` ACE so the owner loses its implicit `WRITE_DAC`. It raises the bar but does not close it: the agent can duplicate Claude Code's own full-access handle to the hook.
- A co-signer for `ConfigChange`.
- `no_verdict` counts that survive a daemon restart (today: since start; the records stay in the audit).

## Owner handwork

Nothing here runs on Claude's machine.

- [ ] **Confirm the design changes D1–D7** and the fixed port `127.0.0.1:7433`.
- [ ] **In a throwaway VM with a real Claude Code ≥ 2.1.295** (the plan 19b handwork VM for Windows, any Linux VM for Linux):
  1. Install from this branch's `ci-locked` build. `/hooks` in Claude Code lists both saiife `PreToolUse` handlers.
  2. Ask Claude to run `ls`: it runs, and the daemon log shows one co-sign request answered empty. This confirms F7: the literal `127.0.0.1` URL and plain `http` are accepted.
  3. **Proxy (F8):** start `claude` with `HTTPS_PROXY=http://127.0.0.1:9` (nothing listens) and no `NO_PROXY`, and ask for `ls`. Note whether the call is blocked (the hook request went to the proxy) or runs (hook requests skip the proxy). Repeat with `NO_PROXY=127.0.0.1`. Report both.
  4. **Allow-list (F6):** add `"allowedHttpHookUrls": ["https://example.com/*"]` to `~/.claude/settings.json` of the agent user, restart Claude, and ask for `ls`. The call must still go through the co-signer: the managed list merges in.
  5. **The kill (Windows):** as the agent user, run a script that waits for a `saiife.exe check` process and ends it with exit 0 (the `measure terminate` probe from the CI build), then ask Claude for a command the guard allows. Expect the call to be blocked with `saiife: BLOCKED (fail closed): the saiife hook ended without a verdict`, and `saiife doctor` to warn `hooks.no-verdict`.
  6. **Port squat (D6, Windows):** with the service running, try binding `127.0.0.1:7433` as the agent user. It must fail.

## Owner rulings (2026-11-09)
1. Port: fixed 7433, not configurable.
2. NO_PROXY: docs only. The managed settings don't set it; doctor warns when a proxy is set and 127.0.0.1 is not in NO_PROXY.
3. Windows locked mode stays preview until a later plan has the service re-judge each input (closes D4). Claude Code's lock label may be raised once Task 9's CI run passes.
4. macOS keeps 0755 and relies on the hardened runtime.
5. Coordinator defaults, owner may overrule: ConfigChange has no co-signer; the cross-user kill is re-run with a real interactive logon later; one co-signer deny record per reason per 10 s.
