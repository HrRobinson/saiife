# Plan 41: the Linux FIDO helper (v3, touch for static Linux releases): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Owner ruling 2026-11-12 (binding):** plan 27 R-A's route is built here. The Linux release binary stays static musl; a small, dynamically linked helper in the Linux packages talks to the key. Boxes do not ship in a release before this plan is done (plan 35 header, errata file). Plan 39's `saiife box land` names this plan as a soft dependency.

**Goal:** A Linux release `saiife` (static musl, no libudev) can enrol and use a FIDO2 key by running `/usr/libexec/saiife/saiife-fido`, a dynamically linked helper shipped in the deb and rpm, that only talks to the key and returns the CTAP response.

**Architecture:**
- **The helper is a transport, nothing more.** It never sees policy, never prompts, never verifies. One process per key operation: it writes a `hello` line, reads one request line on stdin, does one CTAP call through `ctap-hid-fido2`, writes one answer line and exits. The static `saiife` keeps everything else: D2 (one key), the PIN prompt on its own terminal (D3), the touch prompt, the timeout (D4), error classification, plan 27's credential-id fallback (R-F) and C1's allow list; the daemon keeps verification (`saiife-touch`).
- **One key layer in the CLI, two transports.** The CTAP calls and the error classifier move out of `crates/cli/src/touch_cmd/hid.rs` into a new tokio-free crate `saiife-fido` (`crates/fido`). The CLI's `KeyTouch<T: Transport>` implements `saiife_touch::Touch` once; `InProcess` (feature `fido-hid`: macOS releases, source builds) and `Helper` (Linux builds without `fido-hid`) are the two transports. Behaviour on macOS does not change.
- **Integrity before exec.** The helper path is a compile-time constant. Before every run the CLI checks the file and every directory up to `/`: root-owned, no group or world write, no setuid or setgid, a regular file (no symlink). Only root can then change what runs, and root can do anything anyway. The child gets an empty environment, cwd `/`, no arguments, and pipes for stdin, stdout and stderr (never the terminal).

**Tech Stack:** Rust; `ctap-hid-fido2 = "=3.6.0"` (moves from `saiife` to `saiife-fido`, already in `Cargo.lock`), `serde`, `serde_json`, `zeroize = "=1.9.1"`, `base64 = "=0.23.1"`, `sha2`, `rustix` (fs `stat`). No new third-party crate. Release: nfpm (pinned, plan 18), a pinned `debian:bullseye` build container.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §8.1 (what counts), §8.4, §8.6 (120 s per prompt, timeout or error is deny). Plan 27 (`2026-11-11-plan-27-touch-cli.md`) D1–D6 and its ledger rulings R-A, R-F, R-N, R-O, R-P (`.worktrees/p27/.superpowers/sdd/2026-11-11-plan-27-touch-cli/progress.md`). Plan 18 (packaging) decisions 1, 3, 10.

## Decisions

- **F1. Protocol `saiife-fido/1`** (newline-delimited JSON, UTF-8, one object per line, at most `MAX_LINE = 65_536` bytes per line):
  1. helper → `{"t":"hello","proto":1,"version":"<CARGO_PKG_VERSION>","devices":<n>}` at start, before reading stdin (`devices` = `get_fidokey_devices().len()`);
  2. `saiife` checks `proto == 1` **and** `version == env!("CARGO_PKG_VERSION")` (the helper and `saiife` ship in the same package; a mismatch is a mixed install); on a mismatch, or with `devices != 1` (D2), it closes stdin and the helper exits 0 without touching the key. The PIN is asked only after a good hello;
  3. `saiife` → one request: `{"op":"assert","rp_id","challenge":"<hex32>","allow":["<b64u>",…],"pin":"…"|null}` or `{"op":"enrol","rp_id","challenge":"<hex32>","user_id":"<b64u>","user_name","exclude":["<b64u>",…],"pin":"…"}` (`deny_unknown_fields`);
  4. helper → one answer: `{"t":"assertion","credential_id","auth_data","signature"}` (b64u; `credential_id` may be empty, R-F applies on the `saiife` side), `{"t":"attestation","auth_data"}`, or `{"t":"error","error":"<ctap-hid-fido2 text, {:#}, at most 512 chars>"}`; then exit 0. A bad request line is an `error` answer and exit 2.
  The helper sends the raw library text; `saiife` classifies it with the same `classify` as the in-process path, so there is one table of hints.
- **F2. Discovery and integrity.** `FIDO_HELPER = "/usr/libexec/saiife/saiife-fido"` (`crates/system/src/layout.rs`, beside `PACKAGE_BINARY` `:55`). `check_helper(path, owner_uid, trusted_root)`: `lstat` of the file: regular, `uid == owner_uid`, `mode & 0o022 == 0`, `mode & 0o6000 == 0`, `mode & 0o111 != 0`; each ancestor directory up to and including `trusted_root`: `lstat` is a directory (not a symlink), `uid == owner_uid`, `mode & 0o022 == 0`. Release: `owner_uid = 0`, `trusted_root = "/"`. Debug builds only: `SAIIFE_TEST_FIDO_HELPER=<path>` replaces the path, with `owner_uid` = the caller's uid and `trusted_root` = the path's parent (tests cannot make root-owned files). The helper is run by path after the check; a swap between check and exec needs root (every component is root-owned and not writable by others).
- **F3. PIN on the user's terminal.** `saiife` reads the PIN with `tty::read_hidden("PIN for your security key: ")` (`crates/cli/src/tty.rs:35`) exactly as today, and sends it only inside the request line on the helper's stdin pipe: never in argv, the environment, a file or a log. Both sides hold it in `Zeroizing` (`String` and the line buffer); the helper drops it after the CTAP call.
- **F4. Timeouts.** Hello within `HELLO_TIMEOUT = 5 s` of spawn; the answer within `prompt_limit()` (`touch_cmd.rs:420`: 120 s, or `SAIIFE_TEST_TOUCH_TIMEOUT_MS` in debug builds) of writing the request; after the answer the child gets `EXIT_GRACE = 2 s` to exit. Past any of these, `saiife` kills its own child (`Child::kill`, then `wait`; the only signal, sent to a process it spawned), prints `no touch within <s> s` for the answer limit or `the FIDO helper did not answer` otherwise, and gives `TouchError::Unavailable` (exit 5, D5). stderr is drained by a thread into a 4 KiB buffer and shown (first line, through `crate::text::sanitize`) only when the helper exits without an answer.
- **F5. Packaging.** The helper is built per architecture (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`) in `debian:bullseye` pinned by multi-arch index digest (glibc 2.31: Ubuntu 20.04+, Debian 11+, RHEL/Rocky 9; plan 18 decision 10's pinning), checked for `GLIBC_` symbol versions ≤ 2.31 and `NEEDED` ⊆ {`libudev.so.1`, `libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, `libpthread.so.0`, `libdl.so.2`, `librt.so.1`, `ld-linux-x86-64.so.2`, `ld-linux-aarch64.so.1`}. It goes in the same deb and rpm as `saiife` (mode 0755, root:root), which gain `Depends: libc6 (>= 2.31), libudev1` and `Requires: glibc >= 2.31, libudev.so.1()(64bit)`. The tarballs and `install.sh` do not carry it (a user-local copy fails F2); docs say so.
- **F6. Windows (plan 27 R-O).** The helper pattern does not help there: Windows refuses raw HID access to FIDO devices to any non-elevated process, a helper included, and an elevated helper puts every elevated admin on the shared uid 0. The Windows route is the platform WebAuthn API (`webauthn.dll`, which also gives Windows Hello, §8.1 "later"), a separate plan. Windows stays as built: no key support, `(a Windows build)` refusal, docs unchanged.

## Global Constraints

- No real FIDO key, no `/dev/hidraw*` access, no USB, no `sudo`, no docker in any test or agent command. Tests use the fake helper (`saiife-fake-fido`, Task 2) built on `saiife_touch::soft::SoftAuthenticator`, in a per-test tempdir copy. Real keys only in the owner's smoke (Task 6).
- `#![forbid(unsafe_code)]` via `[lints] workspace = true` in `crates/fido/Cargo.toml` (`scripts/check-unsafe.sh` checks it); `saiife-fido` is tokio-free (add it to the CI `no tokio in hook crates` list).
- The static musl `saiife` must not link `ctap-hid-fido2`, `hidapi` or libudev: `cargo tree -p saiife --target x86_64-unknown-linux-musl -e normal` lists no `ctap-hid-fido2` (Task 1 gate).
- User-facing copy is exact where this plan quotes it; `cargo test -p saiife --test docs_wording` stays green.
- **Every task** (worktree `.worktrees/p41`, branch `v3-p41` off `v3-dev`):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p41-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
  cargo test -p <crates touched> -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```
  Remove `$TMPDIR` by its literal path at the end. Never commit `.superpowers/`. Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Fixed values

| Name | Value |
|---|---|
| helper path | `/usr/libexec/saiife/saiife-fido` (`saiife_system::layout::FIDO_HELPER`) |
| protocol | `saiife_fido::proto::PROTO = 1`, `MAX_LINE = 65_536`, `MAX_ERROR_CHARS = 512` |
| timeouts | `HELLO_TIMEOUT = 5 s`, answer `prompt_limit()`, `EXIT_GRACE = 2 s`, stderr kept `4096` bytes |
| answer field caps | `credential_id` ≤ 1023 bytes, `auth_data` 37..=4096 bytes, `signature` ≤ 512 bytes (else `Protocol`) |
| no-support line (Linux, no helper) | `this saiife build has no FIDO2 key support (a static Linux build without the FIDO helper); install the saiife deb or rpm, see docs/touch.md` |
| unsafe helper | `the FIDO helper /usr/libexec/saiife/saiife-fido is not safe to run (<why>); reinstall the saiife package` |
| version skew | `the FIDO helper is version <h> (protocol <p>), this saiife is <v> (protocol 1); reinstall the saiife package` |
| cannot start | `the FIDO helper cannot start: <first stderr line>` (exit 127 adds `; is libudev installed?`) |
| doctor check id | `touch-helper`, title `touch helper` |

## Review Focus

1. **A helper that never answers** (a key stuck mid-CTAP, a helper that hangs after hello). Expected: killed at the limit, `no touch within 120 s`, exit 5, no child left, the request stays pending (Task 3: `hung_helper_is_killed_at_the_limit`, `silent_helper_fails_the_hello`).
2. **A helper that is not the package's**: group-writable file or directory, a symlink at the path, owned by another uid, setuid, not executable. Expected: refused before exec, exit 5, the message names the path and why, nothing runs (Task 3: `check_helper_rules`, `unsafe_helper_never_runs`).
3. **Version skew** (`saiife` updated by `install.sh`, the package's helper older). Expected: refused after hello and before the PIN prompt, `reinstall the saiife package`, the helper exits without touching the key (Task 3: `version_skew_is_refused_before_the_pin`).
4. **Hostile or broken output**: a 1 MiB line, non-JSON, an unknown field, an answer of the wrong type, a 2 KiB error with ANSI escapes. Expected: bounded read, `Unavailable`, printed text sanitized and cut (Task 3: `garbage_answers_are_unavailable`, `error_text_is_sanitized`).
5. **The PIN leaving the terminal-to-pipe path** (argv, environment, a crash dump of stderr). Expected: the fake helper sees an empty environment and no arguments, and the PIN only in the request line (Task 3: `pin_goes_only_over_stdin`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (crate, moves; everything else builds on it).
- **Wave 2 (parallel):** Task 2 (helper `serve` and bins), Task 5 (packaging; needs only the helper's bin name and Task 2's `serve` contract to write the scripts; its CI runs after Task 2 lands).
- **Wave 3:** Task 3 (client and `pick`; needs 2's fake), then Task 4 (doctor; needs 3's `support()`).
- **Wave 4:** Task 6 (docs, smoke; needs 3–5).

---

### Task 1: the `saiife-fido` crate: protocol types, the classifier and the CTAP calls move out of the CLI (size M)

**Files:**
- Create: `crates/fido/Cargo.toml`, `crates/fido/src/lib.rs`, `crates/fido/src/proto.rs`, `crates/fido/src/errors.rs`, `crates/fido/src/hid.rs` (feature `hid`)
- Modify: `crates/cli/Cargo.toml:77-82` (drop `ctap-hid-fido2`; `saiife-fido = { path = "../fido" }`; `fido-hid = ["saiife-fido/hid"]`), `crates/cli/src/touch_cmd/hid.rs` (becomes the `InProcess` transport), `crates/cli/src/touch_cmd.rs:341-376` (`KeyTouch`, `Transport`), `.github/workflows/ci.yml:29-33` (the fido-hid clippy and unit-test lines), `.github/workflows/ci.yml` tokio gate list

**Interfaces:**
- Produces:
```rust
// saiife_fido::proto (always built; serde only)
pub const PROTO: u32 = 1; pub const MAX_LINE: usize = 65_536; pub const MAX_ERROR_CHARS: usize = 512;
pub struct Hello { pub proto: u32, pub version: String, pub devices: usize }          // "t":"hello"
pub enum Request { Assert(AssertReq), Enrol(EnrolReq) }                               // tag "op"
pub struct AssertReq { pub rp_id: String, pub challenge: [u8; 32], pub allow: Vec<Vec<u8>>, pub pin: Option<Zeroizing<String>> }
pub struct EnrolReq { pub rp_id: String, pub challenge: [u8; 32], pub user_id: Vec<u8>, pub user_name: String, pub exclude: Vec<Vec<u8>>, pub pin: Zeroizing<String> }
pub enum Answer { Hello(Hello), Assertion { credential_id: Vec<u8>, auth_data: Vec<u8>, signature: Vec<u8> }, Attestation { auth_data: Vec<u8> }, Error { error: String } }   // tag "t"
pub fn encode<T: Serialize>(v: &T) -> Zeroizing<Vec<u8>>;                             // one line, '\n'-terminated
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, String>;                 // refuses > MAX_LINE, unknown fields
// saiife_fido::errors (always built; moved from cli hid.rs:24-118 with its tests)
pub fn classify(msg: &str) -> (TouchError, &'static str);
pub fn one_of(n: usize) -> Result<(), (TouchError, &'static str)>;
pub fn credential_of(given: Vec<u8>, allow: &[Vec<u8>]) -> Vec<u8>;
pub const DID_NOT_ANSWER: &str;   // and BLOCKED, SET_PIN, CANCELLED, PLUG_IN, ONLY_ONE, as today
// saiife_fido::hid (feature "hid"): no printing, no prompts
pub fn device_count() -> usize;
pub fn assert(r: &AssertReq) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String>;         // (credential_id, auth_data, signature); Err = format!("{e:#}")
pub fn enrol(r: &EnrolReq) -> Result<Vec<u8>, String>;                                // auth_data
// cli touch_cmd.rs
pub(crate) trait Transport: Send + Sync {
    fn devices(&self) -> Result<usize, TouchError>;
    fn assert(&self, r: AssertReq, limit: Duration) -> Result<Result<(Vec<u8>, Vec<u8>, Vec<u8>), String>, TouchError>;
    fn enrol(&self, r: EnrolReq, limit: Duration) -> Result<Result<Vec<u8>, String>, TouchError>;
}
pub(crate) struct KeyTouch<T: Transport> { transport: T, pin: PinPrompt }   // impl saiife_touch::Touch
```
`KeyTouch::request`/`enrol` keep today's order and copy exactly (`hid.rs:137-202`): D2 via `one_of(transport.devices()?)`, the PIN only when `r.uv` (always for enrol), `saiife: touch your key now`, the transport call with `prompt_limit()`, then `classify` on an inner `Err` (printing the hint, or `DID_NOT_ANSWER: <first line>` sanitized), R-F `credential_of`, `client_data_hash = sha256(challenge)`. `InProcess` wraps `saiife_fido::hid` in `run_touch` (`touch_cmd.rs:386`). `hex32` and b64u (de)serialisers are the `saiife-touch` ones re-used through `serde(with)`, or copies in `proto.rs` if `saiife_touch::codec` is private.

- [ ] **Step 1: Write the failing tests:** fido `proto_round_trip` (each `Request` and `Answer` variant encodes to one line ending `\n` and decodes to itself; `challenge` is 64 hex chars, ids b64u), `proto_refuses_unknown_fields`, `proto_refuses_long_lines` (`MAX_LINE + 1` bytes → `Err`), `error_text_is_cut` (`Answer::Error` built by `Answer::error(&str)` keeps at most `MAX_ERROR_CHARS` chars, on a char boundary); `errors.rs` gets plan 27's `classify_ctap_errors`, `omitted_id_is_the_one_allowed`, `pick_one_device_rules` unchanged; cli unit `key_touch_checks_devices_before_the_pin` (a `Transport` double with `devices() == Ok(2)`: the PIN closure is never called, the result is `Unavailable`), `key_touch_classifies_inner_errors` (inner `Err("0x31 CTAP2_ERR_PIN_INVALID …")` → `NotVerified`).
- [ ] **Step 2: Run** `cargo test -p saiife-fido -p saiife --bin saiife touch_cmd` → FAIL (crate missing).
- [ ] **Step 3: Implement** the crate and the move; `lib.rs` declares `pub mod proto; pub mod errors; #[cfg(feature = "hid")] pub mod hid; #[cfg(feature = "fake")] pub mod fake; pub mod helper;` (`fake` and `helper` are filled by Task 2; declare them now as empty modules so Task 2 adds none). ci.yml: `cargo clippy -p saiife --features fido-hid` stays; the unit-test line becomes `cargo test -p saiife-fido --features hid`.
- [ ] **Step 4: Run** `cargo test -p saiife-fido -p saiife --bin saiife touch_cmd`, `cargo clippy -p saiife --features fido-hid --all-targets -- -D warnings` (libudev headers are on this host, plan 27 ledger), and `cargo tree -p saiife --target x86_64-unknown-linux-musl -e normal | grep -c ctap-hid-fido2` → `0`. `bash scripts/check-windows.sh -p saiife-fido -p saiife`.
- [ ] **Step 5: Commit** `refactor(touch): saiife-fido crate: protocol types, the CTAP calls and the error table move out of the CLI`.

---

### Task 2: the helper: `serve`, the `saiife-fido` binary and the fake (size M)

**Files:**
- Create: `crates/fido/src/helper.rs` (fill), `crates/fido/src/fake.rs` (fill), `crates/fido/src/bin/saiife-fido.rs` (`required-features = ["hid"]`), `crates/cli/src/bin/saiife-fake-fido.rs` (`required-features = ["fake-fido"]`)
- Modify: `crates/fido/Cargo.toml` (`[[bin]]`, feature `fake = ["dep:saiife-touch", "saiife-touch/soft"]`), `crates/cli/Cargo.toml` (`[[bin]] saiife-fake-fido`, feature `fake-fido = ["saiife-fido/fake"]`)

**Interfaces:**
- Consumes: Task 1's `proto`, `hid`.
- Produces:
```rust
// saiife_fido::helper
pub trait Backend { fn devices(&self) -> usize; fn assert(&self, r: &AssertReq) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String>; fn enrol(&self, r: &EnrolReq) -> Result<Vec<u8>, String>; }
pub fn serve(input: impl BufRead, output: impl Write, b: &dyn Backend) -> u8;   // the exit code: 0, or 2 for a bad request
// saiife_fido::fake (feature "fake")
pub fn main() -> std::process::ExitCode;   // the fake helper: SoftBackend, knobs from "<argv0>.json"
```
- `serve`: write `Hello { PROTO, CARGO_PKG_VERSION, b.devices() }` and flush; read one line (bounded at `MAX_LINE`, into `Zeroizing<Vec<u8>>`); EOF before any byte → return 0 without calling the backend; a line that does not decode → `Answer::Error { "bad request: <why>" }`, return 2; else call the backend once, write the answer, return 0. Never reads a second line.
- `saiife-fido` main: refuses any argument (`saiife-fido takes no arguments`, exit 2, nothing on stdout), `LibCfg` with `enable_keep_alive_msg: false` (the library's keep-alive text would corrupt stdout), then `serve(stdin.lock(), stdout.lock(), &HidBackend)`.
- The fake's knobs file `<argv0>.json` (`deny_unknown_fields`): `{"key": "<path of a soft key file>", "devices": 1, "mode": "ok"|"hang_after_hello"|"no_hello"|"exit_at_start:<code>"|"garbage"|"long_line"|"wrong_type"|"ctap_error:<text>"|"proto:<n>"|"version:<v>", "log": "<path>"}`. The key file is `{pkcs8, credential_id, counter}` (b64u), created on the first `enrol` and written back after each `assert` (`SoftAuthenticator::from_parts`/`parts`, `crates/touch/src/soft.rs:61`, `:92`). The fake asserts **without** a matching allow entry as `CTAP2_ERR_NO_CREDENTIALS` text (a non-discoverable key, C1). The log gets one JSON line per run: `{"argv": [...], "env": [<names>], "op", "pin_len"}` (never the PIN).

- [ ] **Step 1: Write the failing tests** (`helper.rs` unit tests with a `Backend` double and in-memory IO): `hello_comes_first` (with an input that yields nothing until the test has read the output's first line, that line is already the hello: use a `BufRead` double whose `fill_buf` asserts the output buffer already holds one line), `eof_after_hello_touches_nothing` (backend call count 0, exit 0), `one_request_one_answer` (an assert request with a second line after it: the second is never read, the answer is `Assertion`), `bad_request_is_an_error_answer` (`{"op":"assert"}` → `Error` starting `bad request:`, exit 2), `oversized_request_is_refused`, `backend_error_text_is_cut` (a 2000-char error → ≤ 512 chars); bin test `crates/fido/tests/helper_args.rs` is not possible without `hid` hardware, so the argument check is a unit test of `fn args_ok(args: &[OsString]) -> bool`.
- [ ] **Step 2: Run** `cargo test -p saiife-fido --features fake` → FAIL.
- [ ] **Step 3: Implement** `serve`, the two mains, the fake. `cargo build -p saiife-fido --features hid --bin saiife-fido` builds on this host (libudev present).
- [ ] **Step 4: Run** `cargo test -p saiife-fido --features fake`, `cargo build -p saiife --features fake-fido --bin saiife-fake-fido` → PASS / builds.
- [ ] **Step 5: Commit** `feat(touch): saiife-fido helper speaks saiife-fido/1; a soft fake for tests`.

---

### Task 3: the static `saiife` runs the helper: integrity, handshake, timeouts, `pick` (size L)

**Files:**
- Create: `crates/fido/src/client.rs` (`#[cfg(target_os = "linux")]`), `crates/cli/src/touch_cmd/helper.rs` (the `Helper` transport), `crates/cli/tests/touch_helper.rs`
- Modify: `crates/system/src/layout.rs` (`FIDO_HELPER` beside `:55`, plus its test row near `:992`), `crates/cli/src/touch_cmd.rs:343-376` (`NO_KEY_SUPPORT` on Linux, `pick`, `device`, `support`), `crates/cli/src/touch_cmd.rs:713-728` (`pick_without_hid_names_the_build`)

**Interfaces:**
- Consumes: Task 1's `proto`, `errors`, `KeyTouch`, `Transport`; Task 2's fake (`CARGO_BIN_EXE_saiife-fake-fido`).
- Produces:
```rust
// saiife_fido::client (linux)
pub enum HelperError { Missing, Unsafe(String), Spawn(String), NoHello { exit: Option<i32>, stderr: String }, Skew { proto: u32, version: String }, Timeout, Protocol(String), Exited { exit: Option<i32>, stderr: String } }
pub fn check_helper(path: &Path, owner_uid: u32, trusted_root: &Path) -> Result<(), HelperError>;   // F2
pub struct Running { /* child, stdin, line reader thread, stderr thread */ }
impl Running {
    pub fn start(path: &Path) -> Result<(Running, Hello), HelperError>;    // env_clear, cwd "/", no args, piped; hello within HELLO_TIMEOUT; checks PROTO and version (F1.2)
    pub fn call(self, req: &Request, limit: Duration) -> Result<Answer, HelperError>;   // Timeout kills and reaps; then EXIT_GRACE
    pub fn close(self);                                                    // closes stdin, waits EXIT_GRACE, kills if needed
}
// cli touch_cmd.rs
pub(crate) enum KeySupport { Soft, InProcess, Helper { version: String, devices: usize }, HelperBroken(String), None }
pub(crate) fn support() -> KeySupport;                                     // for doctor (Task 4): runs start + close, never a request
```
- `pick()` order (`touch_cmd.rs:358`): the soft seam (debug) → `InProcess` (feature `fido-hid`) → on Linux without `fido-hid`: `check_helper` at `FIDO_HELPER` (or the debug seam, F2): `Missing` → `NO_KEY_SUPPORT`, `Unsafe(why)` → the fixed "unsafe helper" line, else `KeyTouch<Helper>` → elsewhere `NO_KEY_SUPPORT` as today. Every `HelperError` maps to `TouchError::Unavailable` (exit 5) with its fixed line; an `Answer::Error` becomes the inner `Err(text)` that `KeyTouch` classifies (so a wrong PIN still exits 2).
- `Helper::devices` starts the helper and keeps the `Running` (in a `Mutex<Option<Running>>`) for the following `assert`/`enrol` (one process per operation, F1); `KeyTouch` asks the PIN between the two (F3). A `Running` not used (D2 refusal, PIN refused) is `close`d.
- **PIN seam (debug builds only):** `SAIIFE_TEST_TOUCH_PIN=<text>` replaces `tty::read_hidden` in `KeyTouch`'s PIN closure (tests have no terminal); an empty value is "no PIN typed". Ignored in release builds, like `SAIIFE_TEST_TOUCH_SOFT` and `SAIIFE_TEST_FIDO_HELPER`.
- `NO_KEY_SUPPORT` on Linux becomes the fixed no-support line; on Windows and other systems it is unchanged.

- [ ] **Step 1: Write the failing tests.** fido unit (`client.rs`, tempdirs, files made by the test, current uid): `check_helper_rules` — ok: 0755 file in a 0700 dir; refused, each naming why: missing → `Missing`, `chmod g+w` file, `chmod o+w` parent, a symlink at the path, a directory at the path, mode 0644 (not executable), mode 04755, `owner_uid = uid + 1`, an ancestor above the parent group-writable when `trusted_root` is the grandparent. CLI integration `tests/touch_helper.rs` (Linux only; each test copies `CARGO_BIN_EXE_saiife-fake-fido` into its own tempdir with its knobs file and sets `SAIIFE_TEST_FIDO_HELPER`; the daemon side is `tests/common/approvals_world.rs`, as `tests/touch_cmd.rs`):
  - `enrol_test_and_approve_through_the_helper` (enrol, `touch test` → `ok: … answered`, a `deploy`-class approve → approved; the audit `touch` object as plan 27's tests check it);
  - `pin_goes_only_over_stdin` (the fake's log: `argv == [path]`, `env == []`, `pin_len` equals the length of `SAIIFE_TEST_TOUCH_PIN`);
  - `version_skew_is_refused_before_the_pin` (`mode: "version:0.0.1"` → exit 5, the skew line, no PIN asked (no `PIN for your security key` on stderr), log has no `op`), same for `proto:2`;
  - `two_keys_refused_before_the_pin` (`devices: 2` → exit 5, D2's text);
  - `hung_helper_is_killed_at_the_limit` (`hang_after_hello`, `SAIIFE_TEST_TOUCH_TIMEOUT_MS=300` → exit 5 within 3 s, stderr has `no touch within`, and the fake's pid, logged at start, is gone: `/proc/<pid>` missing after the CLI exits);
  - `silent_helper_fails_the_hello` (`no_hello` → `the FIDO helper did not answer` within 6 s);
  - `garbage_answers_are_unavailable` (`garbage`, `long_line`, `wrong_type` → exit 5 each);
  - `ctap_errors_are_classified` (`ctap_error:0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid.` → exit 2, `wrong PIN`; the request stays pending);
  - `error_text_is_sanitized` (`ctap_error:` with `\u{1b}[31m` and 2000 chars → the printed line has no ESC and is cut);
  - `cannot_start_names_stderr` (`exit_at_start:127` with a stderr line → `the FIDO helper cannot start: …; is libudev installed?`);
  - `unsafe_helper_never_runs` (the copy made `chmod g+w` → the unsafe-helper line, exit 5, the log file never created);
  - `missing_helper_names_the_package` (seam path missing → the no-support line; `touch ls` still lists and prints it as a note, plan 27 D1).
  Update `pick_without_hid_names_the_build` for the new Linux text.
- [ ] **Step 2: Run** `cargo test -p saiife-fido -p saiife --features fake-fido --test touch_helper -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement.** Reads: a reader thread per pipe; the stdout thread sends whole lines (bounded at `MAX_LINE`; a longer line is `Protocol("line too long")`) over an `mpsc` channel the caller waits on with `recv_timeout`.
- [ ] **Step 4: Run** the same → PASS; plan 27's `tests/touch_cmd.rs` and `tests/approvals_cmd.rs` unchanged and green; release-mode `cargo test -p saiife --release --bin saiife touch_cmd` (the debug seams are gone in release: `SAIIFE_TEST_FIDO_HELPER` and `SAIIFE_TEST_TOUCH_PIN` ignored, test `helper_seam_is_debug_only` beside plan 27's `soft_seam_is_debug_only`).
- [ ] **Step 5: Commit** `feat(touch): a static Linux saiife touches a key through the packaged FIDO helper`.

---

### Task 4: `saiife doctor`: the `touch-helper` check (size S)

**Files:**
- Modify: `crates/system/src/doctor/mod.rs:39-42` (`touch_supported: bool` → `touch: TouchSupport`), `crates/system/src/doctor/touch.rs` (the new check; `touch-key` reads `TouchSupport::usable()`), `crates/system/src/doctor/system.rs:2916` (id list), `crates/cli/src/doctor_cmd.rs:62`, `crates/cli/src/system_cmd.rs:140`

**Interfaces:**
- Consumes: Task 3's `touch_cmd::support()`.
- Produces:
```rust
// saiife_system::doctor
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TouchSupport { #[default] None, InProcess, Helper { version: String }, HelperMissing, HelperBroken(String) }
impl TouchSupport { pub fn usable(&self) -> bool; }   // InProcess | Helper
```
- `touch-helper` (Linux only; not emitted elsewhere): `InProcess` → Info `this build talks to keys itself`; `Helper { version }` → Pass `/usr/libexec/saiife/saiife-fido <version>, protocol 1`; `HelperMissing` → Info `no FIDO helper: install the saiife deb or rpm for key support (docs/touch.md)`; `HelperBroken(why)` → Warn `<why>` (the unsafe, skew or cannot-start line). Never Fail (touch is optional, plan 27 Task 4).
- `system_cmd.rs:140` (after install) passes `TouchSupport::None` unchanged in meaning (plan 27 final-review note: install's doctor does not probe keys); `doctor_cmd.rs` passes `support()` mapped. As root, `doctor` runs the helper only through `start` + `close` (hello only, no key operation).

- [ ] **Step 1: Write the failing tests** (`doctor/touch.rs` tests): `helper_check_rows` (each `TouchSupport` value → the status and text above), `touch_key_uses_helper_support` (a FIDO hidraw node in the fake `/sys` and `Helper{..}` → `touch-key` is Pass, not plan 27's "this build has no FIDO2 key support" Info); `not_installed_is_info_only` id list gains `touch-helper`.
- [ ] **Step 2: Run** `cargo test -p saiife-system doctor::touch` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo test -p saiife --test doctor` (or the CLI's doctor tests) green.
- [ ] **Step 5: Commit** `feat(doctor): touch-helper check; touch-key counts the helper as key support`.

---

### Task 5: build and ship the helper in the deb and rpm (size M)

**Files:**
- Create: `scripts/release/build-fido-helper.sh`
- Modify: `packaging/linux/nfpm.yaml` (contents, `depends`, `overrides`), `packaging/linux/build.sh` (new argument), `packaging/linux/lintian-overrides` (only if lintian flags the helper, each line with its reason), `.github/workflows/release.yml:94-97` (comment), `:322-450` (`fido-helper` job, `linux-packages` wiring), `.github/workflows/ci.yml:440-530` (`package-linux` builds the helper), `scripts/package-linux/deb.sh` (`:250` area, `:386`), `scripts/package-linux/rpm-container.sh` (`:54-106`)

**Interfaces:**
- `build-fido-helper.sh <amd64|arm64> <out dir>`: refuses root and a non-matching host arch (`uname -m`); runs `docker run --rm` of `debian:bullseye@sha256:<index digest>` (pinned at build time from the registry, recorded beside the line as `ROCKY_IMAGE` is in `scripts/package-linux/run.sh:68-70`) with the repo mounted read-only and a writable target dir; inside: `apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev libudev-dev pkg-config binutils`, `rustup-init` fetched by URL with its SHA-256 pinned in the script, the toolchain of `rust-toolchain.toml`, `cargo build --release --locked -p saiife-fido --features hid --bin saiife-fido`; then checks F5's glibc ceiling (`objdump -T | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1` ≤ `GLIBC_2.31`) and `NEEDED` allowlist (`readelf -d`), `file -b` says `dynamically linked` and the right arch; writes `<out>/saiife-fido`. CI-only by its header (it runs docker); agents only `bash -n`.
- `build.sh <static saiife> <saiife-fido> <version> <amd64|arm64> <out dir>`: the helper must be `dynamically linked` for the same arch (the static check of `saiife` stays); staged as `$SAIIFE_STAGE/saiife-fido`.
- `nfpm.yaml`: `- src: ${SAIIFE_STAGE}/saiife-fido`, `dst: /usr/libexec/saiife/saiife-fido`, `mode: 0755`, root:root; `overrides.deb.depends: [libc6 (>= 2.31), libudev1]`, `overrides.rpm.depends: [glibc >= 2.31, "libudev.so.1()(64bit)"]`. The header comment's "the package owns only the staging binary, its symlink and the docs" gains "and the FIDO helper".
- `release.yml`: new job `fido-helper` (`needs: check-version`; matrix `{arch: amd64, os: ubuntu-latest}`, `{arch: arm64, os: ubuntu-24.04-arm}`; runs the script; uploads `fido-helper-<arch>`); `linux-packages` `needs: [check-version, build, fido-helper]`, downloads it, passes it to `build.sh`. The `FEATURES` comment says Linux key support comes from the packaged helper (plan 41); the expression is unchanged.
- `ci.yml` `package-linux`: builds the helper with the script for amd64 and passes it to both `build.sh` calls (`:513-514`).
- Package tests: deb (Ubuntu 22.04 and 24.04) and rpm (Rocky 9 container) each check `/usr/libexec/saiife/saiife-fido` is root:root 0755, a regular file, and that `/usr/libexec/saiife/saiife-fido </dev/null` prints one line matching `^\{"t":"hello","proto":1,` and exits 0 (proves the loader, glibc and libudev resolve; it touches no key: EOF after hello). After remove or purge the helper is gone (deb `:386` list, rpm `:105`).

- [ ] **Step 1:** Write the script and the YAML and package-script changes.
- [ ] **Step 2: Check** `bash -n` on every changed script; `shellcheck` and `actionlint` if installed (else as plan 27 R-D: eye review, CI checks on push). The new script is covered by the `scripts/release/*.sh` glob of the `ci.yml:221` shellcheck line; no edit there.
- [ ] **Step 3: Commit** `build(release): ship the FIDO helper in the deb and rpm, built against glibc 2.31`. CI proves it on push (package-linux job); a failure there is fixed in this task.

---

### Task 6: docs and the owner smoke (size S)

**Files:**
- Modify: `docs/touch.md` (§2 doctor paragraph `:73-77`, §7 Builds `:168-195`), `docs/install.md` and `docs/fleet.md` (package contents: `/usr/libexec/saiife/saiife-fido`, the new dependencies), `CHANGELOG.md` (Unreleased), `scripts/touch-smoke.sh` (header `:32` and a helper step)

**Content:**
- `docs/touch.md` §7: the Linux bullet becomes: the Linux deb and rpm carry key support through `/usr/libexec/saiife/saiife-fido`, a small helper linked against libudev that only talks to the key; the main `saiife` stays static and checks the helper before running it (root-owned, not writable by others), and refuses one of another version; the PIN is typed into `saiife` and passed to the helper over a pipe; the tarball and `install.sh` install have no helper, and refuse with the no-support line; a source build with `--features fido-hid` needs no helper. Quote the no-support line exactly. Windows bullet unchanged (F6), plus one sentence: the Windows route is the platform WebAuthn API, planned.
- §2: the doctor paragraph names `touch-helper` (Pass with the helper, Info without it, Warn when it is not safe to run or of another version).
- `touch-smoke.sh`: header: either a `--features fido-hid` build, or an installed deb/rpm with the release binary; a step 0 that, when `/usr/libexec/saiife/saiife-fido` exists, checks `saiife doctor` shows `touch-helper` PASS.

- [ ] **Step 1:** Write the docs and the script change. **Step 2: Run** `cargo test -p saiife --test docs_wording`; `bash -n scripts/touch-smoke.sh`. **Step 3: Commit** `docs(touch): the Linux packages carry key support through the FIDO helper`.

---

## Gates

- [ ] `cargo test -p saiife-fido --features fake -p saiife-system -p saiife --features fake-fido`, and `-p saiife` without features; `cargo test -p saiife --release --bin saiife touch_cmd`; `-j 4 -- --test-threads=4`.
- [ ] clippy (also `-p saiife --features fido-hid` and `-p saiife-fido --features hid`); `scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-fido -p saiife -p saiife-system`; tokio gate `0`; `git diff v3-dev -- Cargo.lock` moves `ctap-hid-fido2` under `saiife-fido` and adds no package.
- [ ] `cargo tree -p saiife --target x86_64-unknown-linux-musl -e normal | grep -c ctap-hid-fido2` → `0`.
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`. Tell the plan 39 owner that `pick()` now succeeds on a Linux release with the package installed.

## Owner handwork

- [ ] Pin the `debian:bullseye` index digest and the `rustup-init` SHA-256 in `build-fido-helper.sh` (Task 5 writes placeholders that refuse to run until set, as plan 18 decision 10).
- [ ] **Smoke with a real key** (YubiKey with a PIN), on a Linux machine with the CI-built deb (or rpm) of this branch installed, using the package's static binary: `saiife doctor` shows `touch-helper` PASS and `touch-key` PASS; then `bash scripts/touch-smoke.sh` (enrol two devices, `touch test`, an approve that needs a touch with the PIN, a wrong PIN → exit 2, pull the key mid-prompt → exit 5, remove); and check once that `saiife --version` and the helper's hello `version` agree (`/usr/libexec/saiife/saiife-fido </dev/null`).
- [ ] After plan 39: `scripts/box-smoke.sh --only land` with the release static binary and the key (the land touch goes through the helper).

## Out of scope

- A helper in the tarballs or for `install.sh` installs (F2 needs a root-owned path).
- Windows key support (F6: the WebAuthn API route, a later plan) and macOS (in-process, unchanged).
- A pure-Rust hidraw transport that would let the static binary talk to keys itself (owner chose the helper route).
