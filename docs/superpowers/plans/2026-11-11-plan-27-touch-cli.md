# Plan 27: touch CLI and the local FIDO2 key (enrol, ls, rm, test, approve with a touch, doctor, owner smoke): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- `saiife touch enrol | ls | rm | test` manages the approver's FIDO2 keys.
- `saiife approve <id>` does the touch by itself when the request needs one.
- `saiife doctor` says whether a key is reachable from this session.
- An owner-run `scripts/touch-smoke.sh` checks all of it with a real key.

No test uses hardware: the CLI's key is `saiife_touch::Touch`, and debug test builds swap in a `SoftAuthenticator` from a file.

**Architecture:**
- **The CLI does the touch; the daemon verifies it** (plan 26). The CLI calls `touch.begin`, hands the `TouchRequest` to a `Touch` (the HID key, or the soft key in tests), and sends the `Assertion` back. It never computes a challenge and never judges an assertion.
- **`HidAuthenticator`** wraps ctap-hid-fido2 `=3.6.0`, behind the CLI feature `fido-hid`. One key at a time, a 120 s limit per prompt, a PIN asked on the terminal when UV is needed. It is never built or run in tests.
- **The test seam:** `SAIIFE_TEST_TOUCH_SOFT=<file>`, honoured only in debug builds, like `SAIIFE_TEST_PKTTYAGENT` (`crates/cli/tests/approvals_cmd.rs:6`, `:17`).

**Tech Stack:** Rust. `saiife-touch` (plan 26, feature `soft`), `ctap-hid-fido2 = "=3.6.0"` (optional, its default `ring` backend; `ring` 0.17.14 is already in `Cargo.lock`), and the CLI's existing `serde_json`, `base64 = "=0.23.1"`, `zeroize = "=1.9.1"` and `rustix`.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §8 (§8.1 what counts, §8.4 enrolment, §8.6 timeouts), §11 (step 4), §12 (owner-run `scripts/touch-smoke.sh`), §15. Binding contract: `v3-step4-6-contract.md` (coordinator scratchpad). This plan **starts after plan 26 has merged to v3-dev**. Its Tasks 1 to 4 give `saiife-touch`, and its Tasks 7 to 9 give the daemon ops `touch.begin`, `touch.enrol`, `touch.remove`, `touch.list`, `touch.check`, and `approval.decide {touch}`.

## Contract changes

| Contract | This plan | Why |
|---|---|---|
| `approve --touch` (and `saiife approvals approve --touch` in the research) | **No flag.** The command is `saiife approve <id>` (`crates/cli/src/main.rs:333-345`). It does the touch whenever `approval.show` gives the item a `touch_class`, and never otherwise. | A flag the user can forget only buys a refusal. The daemon decides whether a touch is needed, and the CLI follows. |
| "HidAuthenticator implements `Touch::request(&ActionRecord) -> TouchEvidence`" | `HidAuthenticator: saiife_touch::Touch` (plan 26 Task 3): `request(&TouchRequest) -> Assertion` and `enrol(&EnrolRequest) -> Vec<u8>`. | Plan 26's contract change: only the daemon makes evidence. |
| "ctap-hid-fido2 behind a CLI feature; the ring feature off" (research) | `fido-hid` is **off by default**. The release workflow turns it on for macOS and Windows only. ctap-hid-fido2's default feature *is* `ring`, and one crypto backend must be on, so `ring` (already locked) stays on and `aws-lc-rs` stays off. | F2 and F3 below. |

## Facts checked (2026-11-11)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | 3.6.0 API: `FidoKeyHidFactory::create(cfg: &LibCfg) -> Result<FidoKeyHid>`, `LibCfg::init()`, `get_fidokey_devices() -> Vec<HidInfo>`. `FidoKeyHid::get_assertion_with_args(&self, &GetAssertionArgs) -> Result<Vec<Assertion>>` and `make_credential_with_args`. `GetAssertionArgsBuilder::new(rpid: &str, challenge: &[u8])` with `.pin(&str)`, `.without_pin_and_uv()`, `.add_credential_id(&[u8])` and `.build()`. `MakeCredentialArgsBuilder::new(rpid, challenge)` with `.pin`, `.key_type`, `.exclude_authenticator`, `.user_entity` and `.build()`. `Assertion { auth_data, signature, credential_id, .. }`, `Attestation { auth_data, .. }`. `Result` is `anyhow::Result`. | docs.rs `ctap-hid-fido2/3.6.0/source` (`lib.rs`, `fidokey/get_assertion/{mod.rs, get_assertion_params.rs}`, `fidokey/make_credential/make_credential_params.rs`) | Used as is. The builder names are verified again by `cargo check --features fido-hid` in Task 1. |
| F2 | The challenge is hashed inside the crate: `client_data_hash: util::create_clientdata_hash(challenge)`, which is SHA-256. | `util.rs`, both `*_command.rs` | The CLI passes the daemon's 32-byte challenge **as is** and reports `client_data_hash = SHA-256(challenge)` (plan 26 D1). |
| F3 | `[features] default = ["ring"]`. `hidapi = { version = "2.6.7", default-features = false, features = ["linux-static-hidraw"] }`. hidapi's `build.rs` for that backend compiles `etc/hidapi/linux/hid.c` and calls `pkg_config::probe_library("libudev").expect("Unable to find libudev")`. | `ctap-hid-fido2/3.6.0/source/Cargo.toml.orig`; `hidapi/2.6.7/source/build.rs` | **D1.** A Linux build needs libudev headers and `pkg-config`, and it links libudev, so it **cannot be in the static musl release** (`.github/workflows/release.yml:63-70`). |
| F4 | Release targets: `x86_64`/`aarch64-unknown-linux-musl`, `x86_64`/`aarch64-apple-darwin`, `x86_64`/`aarch64-pc-windows-msvc`, built at `release.yml:164-166`. | code | D1. |
| F5 | On Arch, `60-fido-id.rules` tags FIDO hidraw nodes `ID_SECURITY_TOKEN`, and `70-uaccess.rules` gives the seat user an ACL on them (systemd ≥ 248). SSH sessions have no seat and get no ACL. | research §2 (checked on the owner's host) | The doctor check and `docs/touch.md` say "log in at the machine", never "run as root". |
| F6 | The CLI already reads a line without echo on Unix (`secret_cmd.rs:690-735`: `Restore`, `prompt`, `read_line` at `:759`), and with `rpassword` on Windows (`:671-687`). | code | Task 1 moves the Unix pieces to `crates/cli/src/tty.rs` for the PIN, and `secret_cmd` calls them. |

### Design decisions (flagged for the owner)

- **D1. The Linux release has no key support in this plan.** `fido-hid` is a CLI feature, off by default. Release builds turn it on for macOS and Windows (`--features fido-hid`). The musl Linux builds stay without it. There, `saiife touch …` and a touch-class `approve` exit 5 with: `this saiife build has no FIDO2 key support (a static Linux build); see docs/touch.md`. On a glibc host (the owner's Arch box) `cargo build --features fido-hid` works. Owner check 1 picks the shipped Linux route:
  - (a) a small dynamically linked helper binary in the Linux packages;
  - (b) glibc Linux release artifacts;
  - (c) a hand-written CTAPHID-over-hidraw transport, which also needs the PIN protocol (ECDH P-256 + AES-CBC + HMAC).
- **D2. One key at a time.** With no FIDO device the error is `Unavailable` ("plug in your key"). With more than one it is also `Unavailable` ("more than one FIDO key is plugged in; leave only the one to use"). Picking among keys by trial would touch the wrong key first.
- **D3. PIN.** When `TouchRequest.uv` is set (and always at enrol), the CLI asks `PIN for your security key: ` with no echo, before it tells the user to touch. The PIN is a `Zeroizing<String>`. It is never logged, never sent to the daemon, and never kept after the call. No PIN at the prompt is `NotVerified`, and nothing is sent.
- **D4. 120 s per prompt** (§8.6). The HID call runs on a worker thread, and the CLI waits with `recv_timeout(120 s)`. On timeout it prints `no touch within 120 s` and exits 5. The worker ends when the key gives up (CTAP's own timeout); the process exits anyway.
- **D5. Exit codes:** `Unavailable` gives 5; every other touch error, and a daemon refusal, gives 2. This is the same split as `approvals_cmd::finish` (`approvals_cmd.rs:189-203`).
- **D6. Approve with a touch prints first, then prompts:** `saiife: approving request #<id>: …` (as today), then `saiife: touch needed (<class>); code <short_code>; check that the same code shows wherever you started this`. Then it asks for the PIN, then `touch your key now`. `approval.decide` goes over a **new** connection after the touch, so a 120 s wait never meets an idle connection timeout. Same-user re-authentication (polkit) still runs after the touch, as in v2.

## Global Constraints

- **Hardware never runs in tests or agent steps.** `HidAuthenticator` code is checked with `cargo check`/`clippy --features fido-hid` only. `scripts/touch-smoke.sh` is owner-run. Agents run `bash -n` and `shellcheck` on it, and nothing else.
- **No network in tests, no D-Bus:** `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent` in every test command. polkit, `pkcheck` and `pkttyagent` never run (tests use the existing fake agent of `approvals_cmd.rs:692`).
- **New dependency:** `ctap-hid-fido2 = { version = "=3.6.0", optional = true }` in `crates/cli/Cargo.toml`, under `[features] fido-hid = ["dep:ctap-hid-fido2"]`. 3.6.0 is from 2026-09-05; 3.6.1 (2026-11-02) is too new. Every crate it adds to `Cargo.lock` must be older than 14 days. Check each new `[[package]]` in the lock diff on crates.io (public reference data). If one is younger, run `cargo update -p <crate> --precise <older version>` within its semver range. If none fits, stop and report. Other new lock entries are expected: hidapi, ciborium, x509-parser, aes, cbc, strum and their trees. `openssl`, `aws-lc-rs` and `tokio` must not appear.
- **The CLI's `saiife-touch` dependency:** `saiife-touch = { path = "../touch", features = ["soft"] }`. The soft key is compiled in; the seam that picks it is `#[cfg(debug_assertions)]`.
- **Fixed copy:** the messages in D1 to D6, and the prompt strings in Tasks 1 to 3.
- **Commands for every task** (hard rules), in the worktree `.worktrees/p27`:
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p27-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent
  cargo test -p saiife -j 4 -- --test-threads=4 <filter>
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  cargo clippy -p saiife --features fido-hid --all-targets -j 4 -- -D warnings
  ```
  The last line needs libudev headers and `pkg-config` on the build host. If they are missing, report it and do not install anything (no sudo). Remove `$TMPDIR` at the end. Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A key that never answers, or is pulled mid-prompt.** Expected: exit 5 after at most about 120 s with `no touch within 120 s` (or `plug in your key`), and the request still pending. No password prompt is offered instead (Task 1: `slow_key_times_out`, with a soft key that sleeps; Task 3: `unavailable_key_leaves_the_request_pending`).
2. **Several keys plugged in, or a key that is not enrolled.** Expected: a clear message, exit 2 or 5, nothing sent to `approval.decide` (Task 1: `pick_one_device_rules`, `classify_ctap_errors`; Task 3: `unenrolled_key_is_refused_before_decide`).
3. **The CLI's terminal echo after a PIN prompt interrupted by Ctrl-C** (ISIG is off, so it arrives as a byte). Expected: the terminal is restored. The prompt is the moved `secret_cmd` code, so the existing `secret_cmd` tests still pass (Task 1).
4. **A daemon that predates plan 26** (no `touch.*` ops). Expected: `saiife touch ls` exits 5 with `this saiife daemon has no touch support; update it`, not a raw `unknown_op` (Task 2: `old_daemon_is_named`).
5. **A release build with `SAIIFE_TEST_TOUCH_SOFT` set.** Expected: ignored. Only debug builds honour it (Task 1: `soft_seam_is_debug_only`, a `#[cfg(not(debug_assertions))]` test, run in the Finish gates with `--release`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (the key layer, the tty move, and the feature).
- **Wave 2 (parallel):** Task 2 (`saiife touch`) and Task 3 (`approve`). Both use Task 1's `touch_cmd::pick` and `touch_cmd::run_touch`. Task 2 owns `touch_cmd.rs`'s subcommands; Task 3 changes only `approvals_cmd.rs`.
- **Wave 3 (parallel):** Task 4 (doctor and docs) and Task 5 (CI, release and the smoke script).
- **Last:** the gates, a whole-branch review, one fix wave, push, PR into v3-dev.

**Shared files:** `crates/cli/src/main.rs`. Task 2 adds `Cmd::Touch` and its arms at `:416-450` (`windows_refusal`, value `None`) and `:715-735` (the `unreachable!` list), and Task 3 does not touch `main.rs`.

---

### Task 1: the key layer: `pick`, `HidAuthenticator`, the soft seam, and the PIN prompt (size M)

**Files:**
- Modify `crates/cli/Cargo.toml`: deps and `[features]` per Global Constraints; `Cargo.lock` (by cargo).
- Create `crates/cli/src/tty.rs`, moving `Restore`, the Unix `prompt` and `read_line` from `secret_cmd.rs:690-735` and `:759-…`.
- Create `crates/cli/src/touch_cmd.rs` (only the key layer in this task), and `crates/cli/src/touch_cmd/hid.rs` (`#[cfg(feature = "fido-hid")]`).
- Modify `crates/cli/src/main.rs` (`mod touch_cmd; mod tty;`) and `crates/cli/src/secret_cmd.rs` (call `tty`).

**Interfaces:**
- Consumes `saiife_touch::{Touch, TouchRequest, EnrolRequest, Assertion, TouchError, soft::SoftAuthenticator, CoseAlg}`.
- Produces:
  - `tty.rs`:
    - `#[cfg(unix)] pub(crate) fn read_hidden(label: &str) -> Result<Zeroizing<String>, String>`: the moved code. `Err` texts: `cannot read the terminal: …`, and `no value read` for an empty line;
    - `#[cfg(windows)] pub(crate) fn read_hidden(label: &str) -> Result<Zeroizing<String>, String>`, through `rpassword::prompt_password`.

    `secret_cmd` maps the `Err(String)` onto its `Stop::Refused`, and keeps its own `MAX_VALUE_BYTES` and UTF-8 checks.
  - `touch_cmd.rs`:
    - `pub(crate) fn pick() -> Result<Box<dyn Touch>, String>`, in this order:
      1. debug builds only: a non-empty `SAIIFE_TEST_TOUCH_SOFT` gives `SoftFile::open(path)`;
      2. `#[cfg(feature = "fido-hid")]`: `HidAuthenticator::new(Box::new(|| tty::read_hidden("PIN for your security key: ")))`;
      3. otherwise `Err` with D1's message.
    - `pub(crate) fn run_touch<T: Send + 'static>(f: impl FnOnce() -> Result<T, TouchError> + Send + 'static, limit: Duration) -> Result<T, TouchError>`: a worker thread and an mpsc channel. `recv_timeout(limit)` elapsing gives `Unavailable`, after printing `saiife: no touch within <limit.as_secs()> s`.
    - `pub(crate) fn exit_for(e: TouchError) -> u8`: 5 for `Unavailable`, else 2 (D5).
    - `struct SoftFile { path: PathBuf, key: SoftAuthenticator }` (`#[cfg(debug_assertions)]`), with `impl Touch` delegating to the key. After each `request` or `enrol` it writes the file back with the new counter.
      - The file is JSON `{alg, pkcs8, credential_id, counter, up?, uv?, delay_ms?}`: `pkcs8` and `credential_id` are base64url, and `up`/`uv` default to true.
      - `delay_ms` sleeps before answering, for the timeout test.
      - A file `{"chain": ["<path A>", "<path B>"]}` instead answers each `request` or `enrol` with the next key file in order, staying on the last one. This stands in for "unplug one key, plug in another".
      - `SoftFile::create(path, alg)` makes a new key file. It is used by tests only (`pub(crate)`, `#[cfg(debug_assertions)]`).
      - A seam file that is missing or does not parse makes `pick()` give `Err`. Every caller turns a `pick()` `Err` into exit 5 with the message.
    - `pub(crate) fn prompt_limit() -> Duration`: `PROMPT_TIMEOUT_SECS`. In debug builds, a set `SAIIFE_TEST_TOUCH_TIMEOUT_MS` replaces it. `HidAuthenticator` and `SoftFile` both wait through `run_touch(.., prompt_limit())`.
  - `hid.rs`: `pub(crate) struct HidAuthenticator { pin: Box<dyn Fn() -> Result<Zeroizing<String>, String> + Send + Sync> }`, with `impl Touch`:
    - **`request(r)`**:
      1. `one_device()`: `get_fidokey_devices()`, then D2's rules;
      2. the PIN, when `r.uv` (D3); a prompt `Err` is `NotVerified`;
      3. `eprintln!("saiife: touch your key now")`;
      4. `run_touch(move || …, PROMPT_TIMEOUT_SECS)`, which calls `FidoKeyHidFactory::create(&LibCfg::init())` and `GetAssertionArgsBuilder::new(&rp_id, &challenge)`, plus `.add_credential_id(id)` for each of `r.allow`, plus `.pin(&pin)`, or `.without_pin_and_uv()` when there is no PIN; then `.build()`, then `get_assertion_with_args`. It takes the first assertion, and maps it to `Assertion::Ctap2 { credential_id, auth_data, signature, client_data_hash: sha256(&r.challenge) }` (F2).
    - **`enrol(r)`**: the same device and PIN steps (the PIN is always asked), then `MakeCredentialArgsBuilder::new(&r.rp_id, &r.challenge)`, plus `.pin(&pin)`, `.key_type(CredentialSupportedKeyType::Ecdsa256)`, `.exclude_authenticator(id)` for each of `r.exclude`, and `.user_entity(…)` from `user_id` and `user_name`; then `make_credential_with_args`. It returns `attestation.auth_data`.
    - **Errors:** `pub(crate) fn classify(msg: &str) -> (TouchError, &'static str)` maps the crate's error text (from `format!("{e:#}")`):

      | Contains | Error | Hint printed |
      |---|---|---|
      | `PIN_INVALID` | `NotVerified` | `wrong PIN` |
      | `PIN_BLOCKED`, `PIN_AUTH_BLOCKED` | `NotVerified` | `the key's PIN is blocked; reset it with your key's tool` |
      | `PIN_NOT_SET`, `PIN_REQUIRED` | `NotVerified` | `set a PIN on the key first (for a YubiKey: ykman fido access change-pin)` |
      | `NO_CREDENTIALS` | `UnknownCredential` | `this key is not enrolled for you (saiife touch ls)` |
      | `CREDENTIAL_EXCLUDED` | `Mismatch` | `this key is already enrolled` |
      | `OPERATION_DENIED`, `USER_ACTION_TIMEOUT`, `KEEPALIVE_CANCEL` | `NotPresent` | `the touch was cancelled or not given` |
      | anything else | `Unavailable` | `the key did not answer: <first line>` |

      `request` and `enrol` print `saiife: <hint>` and return the error. **Before writing `classify`, read how 3.6.0 renders CTAP status codes** (`src/ctapdef.rs`, or wherever `get_ctap_status_message` lives), and use its exact substrings. The table is the mapping; the substrings follow the crate.

- [ ] **Step 1: failing tests** (unit tests in `touch_cmd.rs`, `hid.rs` and `tty.rs`):
  - `soft_file_round_trip` (debug): `SoftFile::create(p, Es256)`, then `request`, then reopen: the counter is 1, and the assertion verifies with `saiife_touch::verify` against `key.credential(LOCAL_RP_ID, 0, "k")` and an action record whose challenge is the one requested;
  - `soft_seam_is_debug_only` (`#[cfg(not(debug_assertions))]`, Review Focus 5): with the env var set to a valid soft file, `pick()` is not the soft key (it is `Err(D1)` without `fido-hid`);
  - `slow_key_times_out` (Review Focus 1): `run_touch` of a closure that sleeps 2 s, with a 100 ms limit, gives `Err(Unavailable)` within 1 s;
  - `exit_codes`: `exit_for(Unavailable) == 5`, `exit_for(Mismatch) == 2`;
  - `pick_without_hid_names_the_build` (`#[cfg(not(feature = "fido-hid"))]`): with no env var, `pick()` gives `Err` containing `no FIDO2 key support`;
  - `classify_ctap_errors` (`#[cfg(feature = "fido-hid")]`, Review Focus 2): one string per row gives that row's error and hint;
  - `pick_one_device_rules` (`#[cfg(feature = "fido-hid")]`): the pure `fn one_of(n: usize) -> Result<(), (TouchError, &'static str)>` gives `Ok` for 1, and `Unavailable` with D2's two hints for 0 and for 2;
  - `secret_cmd` tests still pass unchanged (Review Focus 3).
- [ ] **Step 2:** run `cargo test -p saiife touch_cmd tty secret_cmd`; expect FAIL.
- [ ] **Step 3:** implement. Run the lock-age check from Global Constraints after adding `ctap-hid-fido2`.
- [ ] **Step 4:** the tests pass. `cargo clippy -p saiife --features fido-hid --all-targets -- -D warnings` is clean. `cargo tree -p saiife --features fido-hid -i openssl` and `-i aws-lc-rs` each find nothing. The Windows check (`bash scripts/check-windows.sh -p saiife`) is clean without the feature.
- [ ] **Step 5:** commit `feat(cli): the touch key layer: ctap-hid-fido2 behind fido-hid, a debug-only soft key seam, the PIN prompt in tty.rs`.

### Task 2: `saiife touch enrol | ls | rm | test` (size M)

**Files:**
- Modify `crates/cli/src/touch_cmd.rs` (add `TouchAction`, `run`), and `crates/cli/src/main.rs` (`Cmd::Touch`, its dispatch next to `Cmd::Approvals` at `:614-621`, and its arms at `:416-450` and `:715-735`).
- Create `crates/cli/tests/touch_cmd.rs`.

**Interfaces:**
- Consumes Task 1, and plan 26's ops (`touch.begin`, `touch.enrol`, `touch.remove`, `touch.list`, `touch.check`, with the arguments of its Task 9).
- Produces:
  - `#[derive(Subcommand)] pub enum TouchAction`:
    - `Enrol { #[arg(long)] label: String }`;
    - `Ls { #[arg(long)] json: bool, #[arg(long)] all: bool }`;
    - `Rm { id: String, #[arg(long)] host: bool }`;
    - `Test`.
  - `Cmd::Touch { #[arg(long = "system-config", hide = true, global = true)] system_config: Option<PathBuf>, #[command(subcommand)] action: TouchAction }`. Doc line: `Locked mode and the personal broker: enrol, list, remove and test the FIDO2 keys your touch approvals use.`
  - `pub fn run(config: Option<PathBuf>, action: TouchAction) -> ExitCode`. It uses the daemon target and calls of `approvals_cmd`: make `approvals_cmd::linux::{target, connect, call, Stop, finish}` `pub(crate)` and re-export them as `approvals_cmd::client` (no copy). Then:
    - **`enrol`:**
      1. `touch.begin {purpose: "enrol", label}`;
      2. print `saiife: enrolling "<label>": touch the new key twice`, plus, when `approve_with` is present, `then one of your enrolled keys`;
      3. `pick()?.enrol(&enrol_request)` gives `auth_data`;
      4. `request(&touch)` gives the proof, then `request(&approve_with)` gives the approval (if present). On a host with only one key plugged in, print `unplug the new key and plug in an enrolled one, then press Enter` between the two, and wait for one line on stdin;
      5. `touch.enrol {label, auth_data, proof, approval?}`;
      6. print `enrolled "<label>" (<first 8 chars of the id>)`, then, when this is the user's only device, `saiife: add a second device (spec §8.4): a lost key leaves only root to remove it`.
    - **`ls`:** `touch.list {all}`. The text table has the columns `ID` (12 chars), `LABEL`, `KIND`, `ALG`, `ADDED` (date) and `COUNT`, plus `OWNER` with `--all`. `--json` prints the array. No device prints `no touch devices enrolled; saiife touch enrol --label <name>`. In a build without `fido-hid`, ls still works (no key is needed), and prints D1's message as a last line to stderr.
    - **`rm <id>`:** a unique id prefix of at least 8 chars, resolved through `touch.list` (an ambiguous or unknown prefix is exit 2). Then:
      - without `--host`: `touch.begin {purpose: "remove", credential}`, then `request`, then `touch.remove {credential, assertion}`;
      - with `--host`: `touch.remove {credential, host: true}`; the daemon refuses non-root.

      It prints `removed "<label>"`.
    - **`test`:** `touch.begin {purpose: "test"}`, then `request`, then `touch.check {assertion}`. It prints `ok: "<label>" answered (user verified: yes, counter <n>)`.
    - Every daemon `unknown_op` answer for a `touch.*` op becomes exit 5 with `this saiife daemon has no touch support; update it` (Review Focus 4).
    - Touch errors are printed as `saiife: touch: <TouchError Display>` and exit `exit_for(e)`.
- **Test harness:** `tests/touch_cmd.rs` reuses the in-process daemon world of `tests/approvals_cmd.rs` (`mod common;` and the `World` builder at `:288-298`). Move what both need (`World`, `world_with`, `cmd`) into `tests/common/approvals_world.rs`, rather than copy it. The test sets `SAIIFE_TEST_TOUCH_SOFT=<world>/soft.json` (from `SoftFile::create`) on the CLI command. It runs only `#![cfg(all(unix, debug_assertions))]`, as `approvals_cmd.rs:18` does.

- [ ] **Step 1: failing tests** (`tests/touch_cmd.rs`):
  - `enrol_ls_test_rm`: `touch enrol --label key1` exits 0 and prints `enrolled "key1"` and the second-device hint. `touch ls --json` has one entry with `label == "key1"` and `kind == "fido2"`. `touch test` prints `ok: "key1" answered (user verified: yes, counter`. `touch rm <8-char prefix>` prints `removed "key1"`, and `ls` then prints `no touch devices enrolled`;
  - `second_device_needs_the_first`: with `key1` enrolled from soft file A, `touch enrol --label key2` with soft file B alone exits 2 with `refused (touch_mismatch)`. B's approval assertion names an unenrolled credential. With the chain file `{"chain": [B, B, A]}` (enrol, proof, approval), the enrol succeeds;
  - `enrol_without_uv_is_refused`: a soft file with `"uv": false` exits 2 with `user verification`;
  - `rm_unknown_prefix`: exit 2 `no enrolled device starts with`;
  - `rm_host_needs_root`: `touch rm <id> --host` as the test user exits 2 with `forbidden`;
  - `old_daemon_is_named` (Review Focus 4): a world whose ctx answers `unknown_op` to `touch.list` (a dispatch wrapper in the test) gives exit 5 with `no touch support`;
  - `audit_has_the_enrol_record`: after an enrol, the world's audit dir has a record with `action == "touch_enrolled"` and `label == "key1"`, and `saiife audit verify` (the existing CLI on that dir) exits 0.
- [ ] **Step 2:** run `cargo test -p saiife --test touch_cmd`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo test -p saiife --test approvals_cmd` still passes (the harness move); the Windows check is clean.
- [ ] **Step 5:** commit `feat(cli): saiife touch enrol, ls, rm and test`.

### Task 3: `saiife approve` with a touch (size M)

**Files:**
- Modify `crates/cli/src/approvals_cmd.rs`: `decide_inner` at `:480-521`; `show_cmd` at `:360-470` (one line); the `Approve` doc in `main.rs:333-334` (one sentence).
- Test: `crates/cli/tests/touch_cmd.rs` (more cases).

**Interfaces:**
- Consumes `touch_cmd::{pick, exit_for}` (Task 1), plan 26's `touch.begin {purpose: "approve", request}` answer (`TouchRequest` + `{expires_at, class}`), and `approval.decide {touch}`.
- Produces:
  - In `decide_inner`, approve only, after the existing `approval.show` and the `approving …` line:
    - if `shown["item"]["touch_class"]` is a string:
      1. `touch.begin {purpose: "approve", request: id}`;
      2. print D6's line, with `short_code` and `class`;
      3. `pick()`, then `request(&touch_request)`;
      4. on `Err(e)`, return the exit `exit_for(e)` with `touch: <e>`, without calling `approval.decide`;
      5. on `Ok(asr)`, `a.insert("touch", serde_json::to_value(asr))`, and **reconnect** (D6) before `approval.decide`.
    - The same-user `prepare_reauth` block (`:505-517`) runs after the touch, unchanged.
  - `Stop` gains the exit code of a touch error: add `Stop::Touch(TouchError)` with `finish` printing `saiife: touch: {e}` and exiting `exit_for(e)`. Do not overload `Refused`.
  - `show_cmd` text output: a line `  touch:     <class> (your enrolled key<, and its PIN>)` under the existing header lines. `<, and its PIN>` is printed when the class is `land`, `deploy` or `secret:sensitive` (plan 26 D4). Exact copy, with the column alignment of the neighbouring lines.
  - The `Approve` doc gains: `A touch-class request asks you to touch your enrolled key (saiife touch).`

- [ ] **Step 1: failing tests** (`tests/touch_cmd.rs`; the world config gives the erp service `deploy = ["<the capability the existing approve_and_reject_round_trip request uses>"]`, and the CLI user has a soft key enrolled):
  - `approve_with_touch_round_trip`: an agent request is pending (as `approvals_cmd.rs` makes one). `saiife approve <id>` exits 0 and prints `touch needed (deploy); code ` followed by 6 digits. The audit has an `approved` record whose `touch.cred_id` is the soft key's id, and the mock upstream got the call;
  - `show_prints_the_touch_line`: `saiife approvals show <id>` has `touch:     deploy (your enrolled key, and its PIN)`;
  - `unenrolled_key_is_refused_before_decide` (Review Focus 2): a second soft file (not enrolled) gives exit 2 with `touch_mismatch` from the daemon, the request still pending, and an `approval`/`refused` record with `rule == "touch_mismatch"`;
  - `unavailable_key_leaves_the_request_pending` (Review Focus 1): `SAIIFE_TEST_TOUCH_SOFT` pointing at a missing file gives exit 5. No `approval.decide` is sent (the audit has no `refused` record for it), and the request is still pending;
  - `slow_soft_key_times_out`: a soft file with `delay_ms: 3000` and `SAIIFE_TEST_TOUCH_TIMEOUT_MS=200` (Task 1's `prompt_limit`) gives exit 5 with `no touch within`;
  - `reject_needs_no_touch`: `saiife reject <id>` of a marked request exits 0 with no key file set at all;
  - `unmarked_approve_unchanged`: the existing `approve_and_reject_round_trip` still passes with no seam set (a regression guard: the touch path is never entered).
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo test -p saiife --test approvals_cmd --test approvals` is green; clippy (with and without `fido-hid`) is clean.
- [ ] **Step 5:** commit `feat(cli): approve asks for a touch when the request's class needs one`.

### Task 4: doctor's key check and the docs (size S)

**Files:**
- Create `crates/system/src/doctor/touch.rs` (`#[cfg(target_os = "linux")]`). Modify `crates/system/src/doctor/mod.rs` (`mod touch;`, and `checks.extend(touch::checks(ctx))` in `unix_checks` at `:119-123`, under a Linux cfg).
- Create `docs/touch.md`. Modify `docs/approvals.md` (a link to it from plan 26's "Touch marks" section) and `README.md` (the docs index line, if the README lists docs).

**Interfaces:**
- Consumes `Ctx`, `Check` and `Status` (`doctor/report.rs:8-52`), `Layout::at` (`layout.rs:412`), and `rustix::fs::access` (already a `saiife-system` dep with `fs`).
- Produces: `pub(super) fn checks(ctx: &Ctx) -> Vec<Check>`, which yields one check with id `touch-key`:
  - For each `ctx.layout.at("/sys/class/hidraw")/<n>/device/report_descriptor` whose bytes start with the FIDO usage page item `06 D0 F1`, it tests `ctx.layout.at("/dev")/<n>` with `rustix::fs::access(.., Access::READ_OK | Access::WRITE_OK)`. This is only an access test; the node is never opened.
  - Results (title `touch key`):
    - **Info:** `no FIDO key plugged in`, when there are no FIDO nodes;
    - **Pass:** `<n> is usable by you`, when one is accessible;
    - **Warn:** `<n> is plugged in but not usable by you: log in at the machine (an SSH session gets no access), or see docs/touch.md for other distros`.
  - It is Info, never a failure: touch is optional until a policy marks something.
- `docs/touch.md` sections:
  1. what counts as a touch (§8.1), and that a PIN-only or fingerprint answer is not one;
  2. setup: set a PIN, then `saiife touch enrol --label …` twice for two devices (§8.4); Arch and systemd ≥ 248 need nothing (uaccess); other distros get the libfido2 `70-u2f.rules` (an owner step; never automated);
  3. `saiife approve` with a touch: the short code, the PIN, 120 s, and that the challenge lives 5 min;
  4. touch marks (a link to `docs/approvals.md`);
  5. recovery: `touch rm --host` as root, recorded;
  6. limits (§15): attestation is not checked (any FIDO2 device can enrol, by someone with host access), and a synced passkey means "any of your synced devices";
  7. builds: D1's text, and which release builds carry key support.

  `docs/touch.md` must pass `crates/cli/tests/docs_wording.rs`.

- [ ] **Step 1: failing tests** (unit tests in `doctor/touch.rs`, with a fake tree under a tempdir `Layout::under(root)`):
  - `no_key_is_info`: an empty `sys/class/hidraw` gives Info `no FIDO key plugged in`;
  - `fido_node_usable`: `hidraw3/device/report_descriptor` = `06 D0 F1 09 01 …` and `dev/hidraw3` (mode 0600, owned by the test user) give Pass `hidraw3 is usable by you`;
  - `fido_node_not_usable` (`#[cfg(unix)]`, skipped when running as root): `dev/hidraw3` with mode 0000 gives Warn, and the text contains `log in at the machine`;
  - `other_hid_devices_ignored`: a descriptor starting `05 01` (generic desktop) gives Info `no FIDO key plugged in`;
  - `cargo test -p saiife --test docs_wording` passes with `docs/touch.md` added.
- [ ] **Step 2:** run `cargo test -p saiife-system doctor::touch`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo tree -e normal -p saiife-system | grep -c tokio` prints `0`.
- [ ] **Step 5:** commit `feat(doctor): say whether a FIDO key is usable from this session; docs/touch.md`.

### Task 5: CI, release features, and the owner smoke script (size S)

**Files:**
- Modify `.github/workflows/ci.yml`. In the `test` job (`:11-45`), add a step after `cargo clippy` (`:23`): `cargo clippy -p saiife --features fido-hid --all-targets -- -D warnings`. On `ubuntu-latest` it is preceded by `sudo apt-get update && sudo apt-get install -y libudev-dev pkg-config`, with `if: runner.os == 'Linux'`. CI may use sudo; agents never run it.
- Modify `.github/workflows/release.yml:164-166`: `cargo build --release --locked --target "$TARGET" -p saiife $FEATURES`, with `FEATURES: ${{ contains(matrix.target, 'linux') && '' || '--features fido-hid' }}` in the job `env` (`:91-96`).
- Create `scripts/touch-smoke.sh` (owner-run). Add it to nothing that runs automatically. The `shellcheck` job already globs `scripts/*.sh` (`ci.yml:188`).

**Interfaces:**
- Consumes the whole CLI surface of Tasks 2 and 3, and the `audit` commands.
- Produces `scripts/touch-smoke.sh`:
  - **Header:**
    - `# OWNER-RUN ONLY. Never run this from CI or from a build agent.` (the same first line as `scripts/dev-smoke.sh:2`);
    - what it needs: a FIDO2 key with a PIN, plugged in at a logged-in seat; a second key for steps 6 and 7 (optional; skipped without it); a running personal broker or locked daemon whose config has a test service with `deploy = ["…"]` on an operation `SAIIFE_SMOKE_OP` of `SAIIFE_SMOKE_SERVICE` (the snippet is printed in the header); `SAIIFE=${SAIIFE:-target/debug/saiife}` built with `cargo build -p saiife --features fido-hid`;
    - `Expect N "ok:" lines and exit 0.`
  - `set -euo pipefail`, an `ok`/`bad` counter as in `dev-smoke.sh`, and no `sudo` except where step 8 says so.
  - **Steps**, each an `ok:` or `bad:` line:
    1. `saiife doctor` has `touch key` with PASS;
    2. `saiife touch enrol --label smoke-1` (touch twice, PIN);
    3. `saiife touch ls --json | jq` shows `smoke-1`;
    4. `saiife touch test` ok;
    5. a call of `SAIIFE_SMOKE_OP` through `saiife api` gives pending (exit 3). Write the exact invocation from `saiife api --help` and `docs/approvals.md`, and keep `SAIIFE_SMOKE_ARGS` for its parameters. Then `saiife approve <id>` shows a 6-digit code and approves after the touch. The audit query command (its form from `saiife audit --help`, JSON output) has the `approved` record with `touch.via == "local"` and `touch.uv == true`. `saiife audit verify` exits 0;
    6. with the second key plugged in alone and not enrolled, a new pending request's `approve` exits 2 with `touch_mismatch` (or the client-side `not enrolled` hint);
    7. a pulled key: start `approve`, pull the key when asked, and expect exit 5 within 125 s;
    8. `saiife touch rm <id>` with a touch removes `smoke-1`. Optionally `sudo saiife touch rm <id> --host` on a second enrolment, recorded `approved_by = root`; this is the only sudo, and the owner runs it by hand;
    9. `saiife audit query` shows `touch_enrolled` and `touch_removed`.
  - It leaves no enrolled smoke device behind: an EXIT trap removes `smoke-*` labels it enrolled, with a touch if needed, and says so.

- [ ] **Step 1:** write the CI and release changes. Check them with `actionlint` if it is installed; otherwise review by eye against the neighbouring steps.
- [ ] **Step 2:** write `scripts/touch-smoke.sh`.
- [ ] **Step 3:** `bash -n scripts/touch-smoke.sh` and `shellcheck scripts/touch-smoke.sh` (if installed; never through docker). Both are clean.
- [ ] **Step 4:** commit `ci(touch): clippy with fido-hid on every OS; release builds carry it on macOS and Windows; owner smoke script`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent`):
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `cargo clippy -p saiife --features fido-hid --all-targets -j 4 -- -D warnings`;
  - `cargo test -p saiife -p saiife-system -j 4 -- --test-threads=4`;
  - `cargo test -p saiife --release --lib touch_cmd -j 4` (Review Focus 5's release-only test);
  - `cargo tree -e normal -p saiife-system | grep -c tokio` prints `0`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife`; `scripts/test-offline.sh`;
  - the lock-age check of Global Constraints is recorded in the task report (each new crate, its version and its publish date).
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR into v3-dev. The owner merges, then runs `scripts/touch-smoke.sh`.

## Follow-ups (not in this plan)

- Key support in the Linux release (D1, owner check 1).
- Choosing among several plugged-in keys (D2).
- `touch_class` for MCP servers and commands (plan 26 follow-up).
- The step 3 hooks: `saiife box land` and `box push` create requests with `touch_class = land` / `push_protected` and the fields `repo`, `base_commit`, `target_ref`, `diff_sha256` and `remote`. They then use the same `approve` path, with no new CLI code.

## Owner handwork

- [ ] Answer owner check 1 (the Linux release route).
- [ ] Set a PIN on the key, then run `scripts/touch-smoke.sh` on the Arch box (logged in at the seat, not over SSH).
