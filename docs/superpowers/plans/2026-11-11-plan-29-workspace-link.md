# Plan 29: Workspace link (W2): daemon ops, `link.sock`, `saiife-link`, localhost server, outbound WSS: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pair a browser with the machine and serve it, with no box and no hub:
- the daemon side: a machine key, the device list, `workspace.*` ops for the CLI on the control socket, and a **separate `link.sock`** that takes only signed frames, so no bug in link can reach a MachineOnly op;
- `saiife workspace pair | devices | revoke | serve` in the CLI;
- a new tokio crate `saiife-link` (`crates/link`): the localhost HTTP server for the UI (plan 30), a small RFC 6455 WebSocket client, and the outbound hub client that relays sealed frames by machine id.
Signed-level actions run end to end against `FakeBoxSource`; Touch-level actions are refused with `touch_required` until plan 31.

**Architecture:**
```
browser ──HTTP 127.0.0.1──┐                       ┌─ control socket (saiife.sock): workspace.pair.* / devices / revoke (CLI, machine side)
                          ├─ saiife-link ──link.sock──▶ daemon: workspace.hello / pair.finish / frame / sign only
phone ──hub (sealed)──WSS─┘   (user process)          └─ saiife_wire::Verifier → level → BoxSource (Ctx.boxes)
```
- **Two sockets, two dispatchers.** `ops::dispatch_conn` (control socket) gains the machine-side `workspace.*` ops. `link.sock` is served by `workspace_ops::dispatch_link`, which knows four ops and refuses every other op name with `unknown_op` before it reads the args. A paired device can therefore only reach what `saiife_wire::level_for` allows, and MachineOnly ops have no route from link at all.
- **The daemon decides; link relays.** Link never parses a frame's action. It forwards `{body, sig, touch?}` and `via` (`local` or `hub`) and returns the daemon's answer.
- **Link is the user's process.** `saiife workspace serve` runs it (the crate is a library). It finds the daemon the way every CLI command does (`crates/cli/src/broker.rs:25` `Target`). The daemon only answers frames from a `link.sock` peer whose uid is the device owner's uid.
- **No WebSocket crate.** `tungstenite 0.30.0` (2026-07-11) is old enough, but it and `tokio-tungstenite 0.30.0` pull `rand 0.10`, `sha1 0.11` (the lock has `0.10.7`), `log`, `url` and `futures-util`. The client side we need (handshake, masked client frames, ping/pong/close, no extensions) is ≈300 lines over `tokio-rustls` with `sha1 0.10.7` and `base64` already in the lock. The localhost server needs no WebSocket: the UI polls signed frames over HTTP.

**Tech Stack:** Rust; `tokio =1.53.2`, `hyper =1.12.0`, `hyper-util =0.1.21`, `http =1.5.0`, `http-body-util =0.1.5`, `bytes =1.12.1`, `rustls =0.23.45` (ring), `tokio-rustls =0.26.6`, `rustls-native-certs =0.8.4`, `sha1 =0.10.7`, `base64 =0.23.1`, `getrandom 0.3` (all in `Cargo.lock`, versions as in `crates/broker/Cargo.toml` and `crates/daemon/Cargo.toml`); `saiife-wire` (plan 28); dev: `rcgen =0.14.10`. One new crate: `qrcode =0.14.1`, CLI only (Task 5).

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5, §8.4, §9.1, §9.2, §9.5, §9.6, §12. Contract: `v3-step4-6-contract.md`. Plan 28 (`2026-11-11-plan-28-workspace-wire.md`) defines every `saiife_wire` name used here.

## Contract changes

None to names. Additions (flagged for the owner):
- **`link.sock`** (`saiife_ipc::msg::LINK_SOCKET_NAME`), a third daemon socket beside `saiife.sock` and `gateway.sock` (`crates/daemon/src/start.rs:1668-1677`). The contract says "MachineOnly actions are unreachable from link"; a separate listener is how.
- **`box.*` IPC op constants** are defined now (as frame action names; the research's "mirror as IPC ops"). They are dispatched only inside `workspace.frame` in this plan. Step 3 may route them on the control socket for `saiife box` with the same names.
- **`saiife workspace serve`** runs link; there is no separate `saiife-link` binary (the crate is `saiife-link`, as the contract names it).
- `lockdown::may_turn_off` and `lockdown::off_refusal` (`crates/daemon/src/lockdown.rs:267`, `:316`) become `pub(crate)` so pairing reuses the machine-side re-authentication.

## Facts checked (2026-11-11)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | `tungstenite` newest 0.30.0 (2026-07-11), 0.29.0 (2026-03-17); `tokio-tungstenite` 0.30.0 (2026-07-11). 0.30.0 normal deps: `bytes`, `log`, `rand ^0.10.2`, `thiserror ^2`, optional `sha1 ^0.11`, `http`, `httparse`, `data-encoding`, `url`, rustls family; tokio-tungstenite adds `futures-util`. | crates.io API `/crates/{tungstenite,tokio-tungstenite}/versions` and `/0.30.0/dependencies` | Age ok; rejected for the new tree (rand, log, url, sha1 0.11). Hand-written client (Task 7). |
| F2 | `qrcode` 0.14.1 is from 2024-07-05; features `default = [image, svg, pic]`; with `default-features = false` its only optional dep (`image`) is off. | crates.io API `/crates/qrcode/versions` | Pin `=0.14.1`, `default-features = false`; the text renderer `qrcode::render::unicode::Dense1x2` needs no feature (check `cargo tree -p saiife` adds only `qrcode`). |
| F3 | The daemon's gateway tests run hyper servers in process: `TcpListener::bind("127.0.0.1:0")` (`crates/daemon/src/gateway.rs:1348`) and a loopback rcgen TLS upstream (`crates/daemon/tests/gateway.rs:122-160`, `CertifiedIssuer::self_signed` + `tokio_rustls::TlsAcceptor`). | tree | Link's tests do the same: a localhost server on port 0, a fake hub over rcgen TLS on 127.0.0.1. |
| F4 | `serve_peer` (`crates/daemon/src/server.rs:113`) runs hello then `ops::dispatch_conn` (`server.rs:206`); `dispatch_conn` is `crates/daemon/src/ops.rs:1172`. | tree | Task 4 passes a `Listener` kind into `serve_peer` and picks the dispatcher at line 206. |
| F5 | `Client::connect(socket_dir, daemon_uid, deadline)` joins `SOCKET_NAME` (`crates/ipc/src/client.rs:402-418`) and checks the socket owner and the peer uid. | tree | Task 1 adds `Client::connect_named(socket_dir, name, daemon_uid, deadline)`; `connect` calls it. |
| F6 | `Ctx::record(kind, input)` (`ops.rs:752`) makes an audit record; `lockdown::set` writes them with `ctx.writer.append` (`lockdown.rs:384-456`); `lockdown::free_change` (`:253`) says whether a change only widens lockdown. | tree | Records `kind = "workspace"`; remote `lockdown.on` applies only when `free_change(cur, Some(LockScope::All))`. |
| F7 | WebAuthn's RP ID must be a domain; `localhost` is allowed and `http://localhost` is a secure context; an IP literal is not a valid RP ID. | W3C WebAuthn L3 §5.1.3, Secure Contexts | The UI origin is `http://localhost:<port>` (bound on 127.0.0.1); other `Host` values are refused. |

## Global Constraints

- **Tokio stays out of** guard, audit, policy, ipc, system, wire (CI gate `.github/workflows/ci.yml:131`; Task 6 checks `saiife-wire` is still listed). `saiife-link` uses tokio.
- **No unsafe:** `[lints] workspace = true` and `#![forbid(unsafe_code)]` in `crates/link/src/lib.rs`.
- **Unix only for link and `link.sock`** in v3.0 (boxes are Linux; macOS is unix). On Windows `crates/link` compiles to a stub whose `run` returns an error "the Workspace link is not available on Windows yet"; `saiife workspace` prints that and exits 5. `bash scripts/check-windows.sh -p saiife-link -p saiife-daemon -p saiife` stays clean.
- **No network in tests.** Loopback only (`127.0.0.1:0`), rcgen certs, in-process servers, as F3. No test resolves a name or reads the real `HOME`, `PATH` or keyring; daemon tests use `ops::test_ctx` (`ops.rs:1528`) on a tempdir.
- **Fixed values:**

| Name | Value |
|---|---|
| `LINK_SOCKET_NAME` | `"link.sock"` |
| default UI port | `47810` (`--port`), bound on `127.0.0.1` only |
| allowed `Host` | exactly `localhost:<port>`; `Origin` on POST exactly `http://localhost:<port>` |
| `MAX_REQUEST_BYTES` (UI POST body) | `96 * 1024` |
| state files | `<state_dir>/state/workspace/machine.p256` (PKCS#8, mode 0600), `<state_dir>/state/workspace/devices.json` (0600) |
| hub URL | `--hub wss://…` (no default in v3.0: the hub repo does not exist yet); hub path `/v1/link` |
| hub reconnect | backoff 1 s doubling to 60 s, ±20 % jitter, reset after 60 s connected |
| WS limits | frame payload ≤ `2 MiB`, message ≤ `2 MiB`, ping every 25 s, close after 60 s without a pong |
| audit | `kind = "workspace"`; actions `pair_offer`, `pair_request`, `paired`, `pair_rejected`, `revoked`, and each state-changing frame action (`box.stop`, `lockdown.on`, `box.spawn`, …) with `extra = {device, label, via, level}`; refused frames after a valid signature with `decision = deny` and `rule` |

- **Every task** (worktree `.worktrees/p29`, branch `p29-workspace-link` off `v3-dev` after plan 28 merged):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p29-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR"
  export CARGO_INCREMENTAL=0
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$TMPDIR/no-bus"
  cargo test -p <crates touched> -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```
  Remove `$TMPDIR` at the end. Never commit `.superpowers/`. Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Another local user, or a web page, talks to link or `link.sock`.** Expected: a frame whose device owner is not the `link.sock` peer's uid is `forbidden` (`wrong_owner`); a browser request with `Host: evil.test:47810` (DNS rebinding) or `Origin: https://evil.test` is 403 before any IPC (Task 4: `frame_from_other_uid_is_refused`; Task 7: `rebinding_host_is_refused`, `cross_origin_post_is_refused`).
2. **A MachineOnly op name sent on `link.sock`** (`policy.reload`, `lockdown.set`, `workspace.pair.confirm`, `workspace.revoke`). Expected: `unknown_op` from `dispatch_link`, no handler runs, nothing is recorded as done (Task 4: `link_socket_refuses_every_other_op`, which iterates every `OP_*` the ipc crate defines).
3. **A pairing confirmed by the wrong person or for the wrong browser.** Expected: `pair.begin` and `pair.confirm` need an admin, or an approver who passes re-authentication like `lockdown off`; `confirm` shows the label and code the browser posted; a second browser posting to the same offer gets `pair_expired` (Task 3: `approver_needs_reauth_to_pair`, `non_approver_cannot_pair`, `second_request_for_one_offer_is_refused`).
4. **Junk from the internet through the hub** (unsigned frames, bad seals, 3 MB messages, a slowloris WebSocket). Expected: dropped by link or refused by the daemon without an audit record per frame (the audit cannot be flooded), the WS frame limit closes the connection, and link reconnects with backoff (Task 4: `unsigned_junk_is_not_recorded`; Task 8: `oversize_frame_closes`; Task 9: `bad_seal_drops_the_session_not_the_link`, `reconnect_backs_off`).
5. **The daemon restarts, or a device is revoked, while a browser is open.** Expected: the next frame is `stale_epoch` (the UI reloads hello) or `unknown_device`; a revoked device's frames are refused at once, with no cache in link (Task 4: `revoked_device_is_refused_next_frame`, `restart_changes_epoch`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (ipc).
- **Wave 2 (parallel):** Task 2 (daemon workspace state), Task 8 (WebSocket codec; touches only `crates/link/src/ws.rs`, so Task 6's skeleton files are created by whichever lands first, with the same contents).
- **Wave 3:** Task 3 (machine-side ops; needs 2).
- **Wave 4:** Task 4 (`link.sock` and frames; needs 3: both edit `workspace_ops.rs`).
- **Wave 5:** Task 6 (link crate and daemon client; its test uses Task 4's `link.sock`).
- **Wave 6 (parallel):** Task 5 (CLI; needs 3, 4, 6), Task 7 (localhost server; needs 6), Task 9 (hub client; needs 6, 8).
- **Last:** gates, whole-branch review, PR. Plan 30 starts after Task 7 is merged (its server skeleton).

**Shared files:** `crates/ipc/src/msg.rs` (Task 1 only), `crates/daemon/src/ops.rs` (Task 2 adds the Ctx fields; Task 3 adds dispatch arms), `crates/daemon/src/lib.rs` (Task 2 declares `workspace` and `workspace_ops`).

---

### Task 1: IPC names and `Client::connect_named` (size S)

**Files:** Modify `crates/ipc/src/msg.rs` (after `OP_HOOK_BIND`, `:95`), `crates/ipc/src/client.rs:402-418`, `crates/wire/Cargo.toml` (`[dev-dependencies] saiife-ipc = { path = "../ipc" }`). Create `crates/wire/tests/ipc_names.rs`.

**Interfaces (Produces):** doc comment on each with its args and answer, in the style of `msg.rs:42-66`.
```rust
pub const LINK_SOCKET_NAME: &str = "link.sock";
// Control socket, machine side (CLI):
pub const OP_WORKSPACE_PAIR_BEGIN: &str = "workspace.pair.begin";     // {label?} -> {pair_id, fragment, machine_id, expires_at}
pub const OP_WORKSPACE_PAIR_STATUS: &str = "workspace.pair.status";   // {pair_id} -> PairStatus JSON (plan 28)
pub const OP_WORKSPACE_PAIR_CONFIRM: &str = "workspace.pair.confirm"; // {pair_id, accept: bool, auth?} -> {device_id, state}
pub const OP_WORKSPACE_DEVICES: &str = "workspace.devices";           // {} -> {devices: [Device without public_key]}
pub const OP_WORKSPACE_REVOKE: &str = "workspace.revoke";             // {device_id, auth?} -> {device_id, state: "revoked"}
// link.sock only:
pub const OP_WORKSPACE_HELLO: &str = "workspace.hello";               // {} -> {machine_id, machine_pub, epoch, frame_version: 1}
pub const OP_WORKSPACE_PAIR_FINISH: &str = "workspace.pair.finish";   // PairRequest -> {device_id, short_code}
pub const OP_WORKSPACE_FRAME: &str = "workspace.frame";               // {body, sig, touch?, via: "local"|"hub"} -> {result}
pub const OP_WORKSPACE_SIGN: &str = "workspace.sign";                 // {purpose: "seal"|"hub_hello", data: b64u} -> {sig: b64u}
// Frame actions (dispatched inside workspace.frame; level from saiife_wire::level_for):
pub const OP_BOX_OVERVIEW: &str = "box.overview"; pub const OP_BOX_LIST: &str = "box.list";
pub const OP_BOX_DIFF: &str = "box.diff"; pub const OP_BOX_TERM_READ: &str = "box.term.read";
pub const OP_BOX_STOP: &str = "box.stop"; pub const OP_BOX_PAUSE: &str = "box.pause";
pub const OP_BOX_RESUME: &str = "box.resume"; pub const OP_BOX_DISCARD: &str = "box.discard";
pub const OP_BOX_REORDER: &str = "box.reorder"; pub const OP_BOX_STEER: &str = "box.steer";
pub const OP_BOX_REVISE: &str = "box.revise"; pub const OP_BOX_LAND: &str = "box.land";
pub const OP_BOX_PUSH: &str = "box.push"; pub const OP_BOX_PR: &str = "box.pr";
pub const OP_BOX_SPAWN: &str = "box.spawn"; pub const OP_BOX_TEMPLATES: &str = "box.templates";
pub const OP_BOX_INBOX: &str = "box.inbox";
pub const LINK_OPS: &[&str] = &[OP_HELLO, OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_FRAME, OP_WORKSPACE_SIGN];
// client.rs
impl Client { pub fn connect_named(socket_dir: &Path, name: &str, daemon_uid: u32, deadline: Instant) -> Result<Client, ClientError>; }
```
- Add every new `workspace.*` value to plan 28's hand-kept `saiife_wire::level::IPC_OPS` (the `box.*` ones are already in `REMOTE`); `every_ipc_op_is_classified` fails until this is done.
- `workspace.pair.*`, `workspace.devices`, `workspace.revoke` must come out `MachineOnly` from `saiife_wire::level_for` (plan 28's ipc scan does this: they are ipc ops not in `REMOTE`); the `box.*` names must match plan 28's `level::actions` exactly.

- [ ] **Step 1: Write the failing tests:** in `msg.rs` tests `link_ops_are_few` (`LINK_OPS.len() == 5`, none starts with `workspace.pair.` except `workspace.pair.finish`); in `crates/wire/tests/ipc_names.rs` (wire dev-dep on `saiife-ipc` is fine: both are tokio-free) `box_ops_match_the_table` (each `OP_BOX_*` value has `level_for(..) == Some(Signed|Touch)` and equals a `saiife_wire::level::actions` const) and `machine_side_workspace_ops_are_machine_only`; in `client.rs` (unix) `connect_named_checks_the_owner` (a socket owned by this uid with `daemon_uid = uid + 1` is `ClientError::Owner`, as the existing `connect` test does).
- [ ] **Step 2: Run** `cargo test -p saiife-ipc -p saiife-wire` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(ipc): workspace and box op names, link.sock, Client::connect_named`.

---

### Task 2: the daemon's workspace state (size M)

**Files:**
- Create: `crates/daemon/src/workspace.rs`
- Modify: `crates/daemon/src/lib.rs` (`pub mod workspace; pub mod workspace_ops;`, empty `workspace_ops.rs`), `crates/daemon/src/ops.rs` (`Ctx` at `:305`: fields `workspace`, `boxes`; `CtxInit` at `:401` and `CtxInit::minimal` at `:446`; `Ctx::new` copies them), `crates/daemon/Cargo.toml` (`saiife-wire = { path = "../wire" }`; dev-dep `saiife-wire` with `features = ["fake"]`; `[features] fake-boxes = ["saiife-wire/fake"]`).

**Interfaces (Produces):**
```rust
// workspace.rs
pub fn dir_in(state_dir: &Path) -> PathBuf;   // <state_dir>/state/workspace
pub struct Workspace { /* machine: MachineKey, inner: Mutex<Inner { devices: DeviceList, offers: Offers, verifier: Verifier }>, dir: Option<PathBuf> */ }
impl Workspace {
    /// Loads or creates the machine key (0600, created with O_EXCL, never
    /// overwritten), loads devices.json (a bad file: the error, and no device
    /// is trusted), draws a new epoch.
    pub fn open(dir: PathBuf) -> (Workspace, Option<String> /* warning */);
    pub fn memory() -> Workspace;                       // tests
    pub fn machine_id(&self) -> String;
    pub fn hello(&self) -> serde_json::Value;           // {machine_id, machine_pub, epoch, frame_version}
    pub fn device(&self, id: &str) -> Option<saiife_wire::device::Device>;
    pub fn devices(&self) -> Vec<saiife_wire::device::Device>;
    pub fn begin_pair(&self, owner_user: &str, label: Option<String>, now: u64) -> Result<saiife_wire::pair::PairOffer, WireError>;
    pub fn finish_pair(&self, req: &PairRequest, now: u64) -> Result<(Device, String /* short code */), WireError>;
    pub fn pair_status(&self, pair_id: &str, now: u64) -> PairStatus;
    pub fn confirm_pair(&self, pair_id: &str, accept: bool, now: u64) -> io::Result<Option<Device>>;   // saves devices.json atomically
    pub fn revoke(&self, id: &str) -> io::Result<bool>;
    pub fn check(&self, sf: &SignedFrame, now: u64) -> Result<Verified, WireError>;
    pub fn sign(&self, purpose: SignPurpose, data: &[u8]) -> [u8; 64];
}
pub enum SignPurpose { Seal, HubHello }   // domains: saiife_wire::seal::HANDSHAKE_DOMAIN, b"saiife-hub-hello-v1\n"
// ops.rs
pub workspace: Arc<crate::workspace::Workspace>,
pub boxes: Arc<dyn saiife_wire::BoxSource>,   // default Arc::new(saiife_wire::source::NoBoxes)
```
- The owner of a pairing is the user who ran `pair.begin` (the peer's name); `Offers::open` stores it in the offer, and `finish_pair` takes it from there. Link never supplies an owner.
- `fake-boxes` (cargo feature, off by default, never in release CI): `start.rs` sets `boxes = Arc::new(FakeBoxSource::demo(now))` when `SAIIFE_WORKSPACE_FAKE_BOXES=1`, and logs `saiifed: Workspace uses fake boxes (test build)`. For the owner to try plan 30's UI before step 3.

- [ ] **Step 1: Write the failing tests** (`workspace.rs`, tempdir): `creates_key_once` (open twice → same `machine_id`; file mode `0o600`), `does_not_overwrite_a_key` (a non-PKCS#8 file at the path → warning, `open` keeps the file and trusts no device), `epoch_changes_on_open`, `pair_flow_persists` (begin → finish → confirm(accept) → reopen → device `Active`), `reject_leaves_no_device`, `revoke_persists`, `bad_devices_file_trusts_nobody`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): workspace state: machine key, devices, offers, verifier`.

---

### Task 3: machine-side ops on the control socket (size M)

**Files:** Modify `crates/daemon/src/workspace_ops.rs`, `crates/daemon/src/ops.rs:1174` (dispatch arm), `crates/daemon/src/lockdown.rs:267,316` (`pub(crate)`).

**Interfaces (Produces):**
```rust
pub const PAIR_DETAIL: &str = "workspace pair";      // polkit --detail, as lockdown's OFF_DETAIL
pub const REVOKE_DETAIL: &str = "workspace revoke";
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value;   // pair.begin | pair.status | pair.confirm | devices | revoke
```
- Who: `pair.begin`, `pair.confirm`, `revoke`: `ctx.peer_is_admin(peer)`, or an approver (`approval_ops::is_approver`, `approval_ops.rs:75`) who passes `lockdown::may_turn_off(ctx, conn, PAIR_DETAIL | REVOKE_DETAIL, auth)`. A refusal answers like `lockdown off` (`off_refusal`'s rule and text). Personal mode: the broker's own user only (as `may_turn_off` already does). `pair.status` and `devices`: the same people, no re-authentication. Re-authentication runs at `confirm` (the moment power is granted), not at `begin`.
- `pair.status` is only for the user who began the offer (else `forbidden`).
- Records (`ctx.record("workspace", <action>)`): `pair_offer` (label, pair_id, expires_at; never the secret or the fragment), `paired` (device id, label, owner, short code), `pair_rejected`, `revoked`. A refused attempt: `decision = deny`, `rule`.
- The answer to `pair.begin` carries `fragment` (it holds the secret). The CLI shows it once; it is never logged.

- [ ] **Step 1: Write the failing tests** (`workspace_ops.rs`, `ops::test_ctx` with a fake `Reauth` as in `approvers.rs` tests): `admin_pairs_without_reauth`, `approver_needs_reauth_to_pair` (fake reauth denies → `refused (reauth_required)`; allows → `paired`), `non_approver_cannot_pair`, `second_request_for_one_offer_is_refused`, `status_is_for_the_begin_user`, `records_never_hold_the_secret` (scan every record written: no `fragment` text, no b64u of the secret), `revoke_records_and_persists`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon workspace_ops` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): workspace pairing, devices and revoke, at the machine only`.

---

### Task 4: `link.sock` and frame execution (size L)

**Files:** Modify `crates/daemon/src/workspace_ops.rs`, `crates/daemon/src/server.rs:113,206`, `crates/daemon/src/start.rs:1655-1700` (`Endpoints`: bind `LINK_SOCKET_NAME` with the same `perms`, accept loop beside the control socket; removed on stop), `crates/daemon/src/lockdown.rs` (new `pub(crate) async fn set_remote_on(ctx, device: &Device, reason: String) -> Result<(), String>`).
**Test:** `crates/daemon/tests/workspace_link.rs` (new; in-process daemon context and `link.sock` on a tempdir, as `crates/daemon/tests/gateway.rs` does for `gateway.sock`).

**Interfaces:**
- Consumes: Task 2 `Workspace::{hello, check, finish_pair, sign}`, `Ctx.boxes`, plan 28 `Verified`, `level_for`, `spawn_level`, `WireError::rule`, `BoxError::rule`, `PendingAction::view`.
- Produces:
```rust
pub enum Listener { Control, Link }                       // server.rs; serve_peer(s, peer, ctx, Listener)
pub async fn dispatch_link(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value;   // workspace_ops.rs
/// One verified frame -> the answer's `result`. Exposed for plan 30's tests.
pub async fn execute(ctx: &Arc<Ctx>, v: &Verified, via: Via) -> Result<Value, Refused>;
pub enum Via { Local, Hub }
pub struct Refused { pub code: ErrorCode, pub rule: &'static str, pub message: String }
pub const LATER: &[&str] = &["box.land", "box.push", "box.pr", "box.steer", "box.revise", "box.resume", "approval.list", "approval.approve", "approval.reject", "workspace.touch.begin"];   // plan 31 fills these
```
- `dispatch_link`: `req.op` not in `LINK_OPS` → `unknown_op` (no args read, nothing recorded). `workspace.frame`: parse `{body, sig, touch?, via}` (`bad_request` otherwise) → `ctx.workspace.check(sf, now)` → peer uid must equal `ctx.directory.user(device.owner_user).uid` (else `forbidden`, rule `wrong_owner`) → `execute`.
- `execute` mapping (args are validated: ids with `BoxId::parse`, text with `check_text`; all `BoxSource` calls in `spawn_blocking`):

| Action | Call | Result |
|---|---|---|
| `workspace.whoami` | — | `{device_id, label, owner_user}` |
| `box.overview` / `box.list` / `box.templates` | `overview()` / `list()` / `templates()` | the DTO |
| `box.diff {id}` | `diff` | `DiffSummary` |
| `box.term.read {id, after?}` | `terminal` | `TermBatch` |
| `box.inbox` | `pending_actions()` | `{items: [PendingView]}` |
| `box.stop` / `box.pause` / `box.discard {id}` | same name | `{}` |
| `box.reorder {ids}` | `reorder` | `{}` |
| `box.spawn {template, repo, task, start}` | template from `templates()`; `spawn_level(t)`; `Signed` → `spawn` | `{id}`; `Touch` → refused `touch_required` |
| `lockdown.on {reason?}` | `lockdown::set_remote_on` (scope `all`, `by_uid` = owner's uid, applied only if `free_change`) | `{lockdown: status_json}` |
| any `Level::Touch` action, and every name in `LATER` | — | refused: `forbidden`, rule `touch_required` (Touch) or `unavailable` (`LATER` Signed ones) |

- A test asserts **every `Signed` entry of `saiife_wire::level::REMOTE` has a row above or is in `LATER`**, so a table entry cannot be silently unhandled.
- Records: one per state-changing action (rows from `box.stop` down) and per refusal after a valid signature; none for reads or for frames that fail before the signature verifies (they bump a counter shown in `status` as `workspace.refused_unsigned`).
- `workspace.sign`: only for a peer uid that owns at least one `Active` device; `purpose` picks the domain (Task 2).
- `workspace.pair.finish`: no peer check (the proof is the authority), records `pair_request` with label and device id.

- [ ] **Step 1: Write the failing tests** (`tests/workspace_link.rs`, with `FakeBoxSource::demo` in `Ctx.boxes` and a `TestDevice` paired through Task 3's ops): `overview_over_link_sock`, `link_socket_refuses_every_other_op` (every `OP_*` const not in `LINK_OPS`, from a hand list kept beside plan 28's scan; each answers `unknown_op`), `frame_from_other_uid_is_refused` (device owner set to a user whose uid ≠ test uid via the test `Directory`), `stop_is_recorded_with_device`, `reads_are_not_recorded`, `unsigned_junk_is_not_recorded` (100 bad-sig frames → 0 new records, counter = 100), `touch_action_is_refused_touch_required` (`box.land`), `spawn_with_secret_template_needs_touch` (`claude-gh`), `spawn_plain_template_runs` (`claude` → `FakeCall::Spawn`), `lockdown_on_from_remote` (on; and when already `all`, a no-op that still answers ok), `machine_only_action_is_refused_after_signature` (`lockdown.off` → `machine_only`, recorded deny), `revoked_device_is_refused_next_frame`, `restart_changes_epoch` (new `Workspace::open` on the same dir → old frame `stale_epoch`), `every_signed_action_is_handled_or_later`, `hostile_diff_passes_through_as_data` (the `b-done` diff JSON round-trips byte for byte).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): link.sock: verified Workspace frames against the box source`.

---

### Task 5: `saiife workspace pair | devices | revoke | serve` (size M)

**Files:** Create `crates/cli/src/workspace_cmd.rs`; modify `crates/cli/src/main.rs` (`mod workspace_cmd;`, a `Workspace { action }` arm in `Cmd` at `:95`, dispatch next to `lockdown_cmd::run` at `:612`), `crates/cli/Cargo.toml` (`saiife-link = { path = "../link" }`; `qrcode = { version = "=0.14.1", default-features = false }` with a comment "0.14.1 is from 2024-07-05; no default features: no image crate").
**Test:** unit tests in `workspace_cmd.rs`; `crates/cli/tests/workspace_cli.rs` (the ops-level pattern of the existing approvals CLI tests: an in-process daemon context on a tempdir, `HOME`/`PATH`/`XDG_*` pointed at tempdirs).

**Interfaces (Produces):**
```rust
#[derive(clap::Subcommand)]
pub enum WorkspaceAction {
    /// Pair a browser with this machine (shows a QR code and a link).
    Pair { #[arg(long)] label: Option<String>, /// The localhost UI instead of app.saiife.com.
           #[arg(long)] local: bool, #[arg(long, default_value_t = 47810)] port: u16 },
    /// List paired browsers.
    Devices,
    /// Remove a paired browser.
    Revoke { device: String },
    /// Run the Workspace link: the localhost UI, and the hub if --hub is given.
    Serve { #[arg(long, default_value_t = 47810)] port: u16, #[arg(long)] hub: Option<String> },
}
pub fn run(config: Option<PathBuf>, action: WorkspaceAction) -> ExitCode;
pub fn pair_url(local: bool, port: u16, fragment: &str) -> String;   // local: http://localhost:<port>/#pair=<f>; else https://app.saiife.com/workspace#pair=<f>
pub fn qr_text(url: &str) -> String;                                  // qrcode Dense1x2, quiet zone on
```
- `pair` flow: `pair.begin` → print the QR (only when stdout is a terminal), the URL, and "Waiting for the browser (5 min)…" → poll `pair.status` every 1 s → on `requested`, print `Browser "<label>" shows: 123 456. Same code? [y/N]` (label through `crate::text::sanitize`) → `pair.confirm {accept}` (re-authentication prompt as `lockdown off` starts `pkttyagent`; reuse `approvals_cmd::prepare_reauth`) → print `Paired d-…`. Exit 0 ok, 2 refused or rejected, 5 unreachable (codes as `lockdown_cmd.rs:10`). Ctrl-C or expiry: exit 2, nothing paired.
- `serve`: resolves the target with `broker::resolve_here` (`crates/cli/src/broker.rs:305`), builds a tokio runtime, calls `saiife_link::run(LinkConfig { socket_dir, daemon_uid, port, hub })` (Task 6) and prints `Workspace on http://localhost:<port>/`.

- [ ] **Step 1: Write the failing tests:** `pair_url_shapes` (local and hub; the fragment is after `#`, never in the path or query), `qr_text_is_nonempty_unicode`, `confirm_prompt_sanitizes_label` (`"\x1b[2J"` label shows escaped), `workspace_pair_end_to_end` (in-process: begin, a `TestDevice` posts `pair.finish` through `link.sock`, the test answers `y` on stdin, device listed by `devices`), `revoke_unknown_device_exits_2`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo tree -p saiife -e normal -i qrcode` shows only `saiife` depends on it, with no `image`.
- [ ] **Step 5: Commit** `feat(cli): saiife workspace pair, devices, revoke and serve`.

---

### Task 6: the `saiife-link` crate and its daemon client (size S)

**Files:** Create `crates/link/Cargo.toml`, `crates/link/src/lib.rs`, `crates/link/src/daemon.rs`, empty `local.rs`, `ws.rs`, `hub.rs`, `assets.rs` (one `//!` line each); modify `.github/workflows/ci.yml:131` only to confirm `-p saiife-wire` is there (Task 1 of plan 28 added it; link is **not** added: it uses tokio).

**Interfaces (Produces):**
```rust
// lib.rs
pub struct LinkConfig { pub socket_dir: PathBuf, pub daemon_uid: u32, pub port: u16, pub hub: Option<String>, pub hub_roots: Option<rustls::RootCertStore> /* tests; None = rustls-native-certs */ }
pub async fn run(cfg: LinkConfig) -> Result<(), String>;    // local server + optional hub client, until both end
// daemon.rs: one blocking saiife_ipc::client::Client per call, inside spawn_blocking
#[derive(Clone)] pub struct Daemon { socket_dir: PathBuf, uid: u32 }
impl Daemon {
    pub fn new(socket_dir: PathBuf, uid: u32) -> Daemon;
    pub async fn call(&self, op: &'static str, args: serde_json::Map<String, serde_json::Value>) -> Result<serde_json::Map<String, serde_json::Value>, LinkError>;
}
pub enum LinkError { Unreachable(String), Refused { error: String, rule: Option<String>, message: String } }
```
- `Cargo.toml`: deps from the Tech Stack line, `saiife-ipc`, `saiife-wire`; `[dev-dependencies]` `saiife-wire` with `fake`, `saiife-daemon` with `fake-boxes` (to run a real dispatcher in process), `rcgen`, `tempfile`. Windows: `#[cfg(not(unix))] pub async fn run(_: LinkConfig) -> Result<(), String>` returns the Global Constraints message.
- Calls time out at 10 s (connect 2 s), `Unreachable` otherwise. A `Refused` keeps the daemon's `error`, `rule` and `message` for the HTTP answer.

- [ ] **Step 1: Write the failing test** `daemon_call_roundtrip` (`tests/daemon_client.rs`: an in-process daemon context with `link.sock` on a tempdir from Task 4; `call(OP_WORKSPACE_HELLO)` returns a `machine_id`; `call("policy.reload")` is `Refused { error: "unknown_op" }`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): saiife-link crate and its link.sock client`.

---

### Task 7: the localhost server (size M)

**Files:** Modify `crates/link/src/local.rs`, `crates/link/src/assets.rs` (placeholder: one `index.html` "saiife Workspace" with `app.css`; plan 30 replaces the table). **Test:** `crates/link/tests/local.rs`.

**Interfaces (Produces):**
```rust
pub const MAX_REQUEST_BYTES: usize = 96 * 1024;
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
pub async fn serve(listener: tokio::net::TcpListener, daemon: crate::daemon::Daemon, port: u16);
// assets.rs (plan 30 fills ASSETS)
pub struct Asset { pub path: &'static str, pub mime: &'static str, pub bytes: &'static [u8] }
pub static ASSETS: &[Asset];
pub fn etag(a: &Asset) -> String;   // "\"" + first 16 hex of SHA-256(bytes) + "\""
```
Routes (HTTP/1.1 via `hyper::server::conn::http1`, one task per connection, like `gateway.rs:332`):

| Method, path | Does | Answer |
|---|---|---|
| `GET /` and each `ASSETS` path | static file | 200 with `Content-Type`, `ETag`, `Cache-Control: no-cache`; `If-None-Match` → 304 |
| `GET /api/hello` | `workspace.hello` | JSON |
| `POST /api/frame` | body `{body, sig, touch?}` → `workspace.frame` with `via: "local"` | `{"ok":true,"result":…}` or `{"ok":false,"error","rule","message"}` with 200 (the UI reads `rule`); daemon unreachable → 503 |
| `POST /api/pair` | `PairRequest` → `workspace.pair.finish` | `{device_id, short_code}` |
| anything else | — | 404 |

- Every answer carries `Content-Security-Policy: CSP`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- Before routing: `Host` must be exactly `localhost:<port>` (403 otherwise; `127.0.0.1:<port>` too, so the WebAuthn RP ID is always `localhost`, F7). POST also needs `Origin: http://localhost:<port>` and `Content-Type: application/json`, and a body ≤ `MAX_REQUEST_BYTES` (413). A peer that is not loopback is closed unanswered (as `gateway.rs:255`).
- `link` never looks inside `body`.

- [ ] **Step 1: Write the failing tests** (server on `127.0.0.1:0`, a hyper client, daemon in process): `index_has_csp_and_nosniff`, `etag_304`, `rebinding_host_is_refused` (`Host: evil.test:<port>` → 403; `Host: 127.0.0.1:<port>` → 403), `cross_origin_post_is_refused` (`Origin: https://evil.test` → 403; missing `Origin` → 403), `wrong_content_type_is_415`, `oversize_post_is_413`, `frame_passes_through` (a `TestDevice` frame for `box.overview` → `ok: true` with 4 boxes), `refusal_keeps_rule` (`box.land` → `ok: false`, `rule: "touch_required"`), `daemon_down_is_503`, `unknown_path_is_404`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): localhost Workspace server: strict host, origin and CSP`.

---

### Task 8: an RFC 6455 WebSocket client (size M)

**Files:** Modify `crates/link/src/ws.rs`; `crates/link/Cargo.toml` (`sha1 = "=0.10.7"` "already in Cargo.lock through saiife-win"). **Test:** unit tests in `ws.rs` over `tokio::io::duplex`.

**Interfaces (Produces):**
```rust
pub const MAX_PAYLOAD: usize = 2 * 1024 * 1024;
pub fn accept_key(sec_websocket_key: &str) -> String;   // base64(SHA-1(key ‖ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
pub enum Message { Text(String), Binary(Vec<u8>), Close(Option<u16>) }   // ping/pong are handled inside
pub struct WsClient<S> { /* stream, read buffer, last_pong */ }
impl<S: AsyncRead + AsyncWrite + Unpin> WsClient<S> {
    /// GET <path> with Host, Upgrade, Connection, Sec-WebSocket-Key (16 random bytes),
    /// Sec-WebSocket-Version: 13 and the extra headers; checks 101 and the accept key.
    pub async fn handshake(stream: S, host: &str, path: &str, headers: &[(&str, String)]) -> Result<WsClient<S>, WsError>;
    pub async fn send(&mut self, m: Message) -> Result<(), WsError>;   // client frames always masked (fresh 4-byte key)
    pub async fn recv(&mut self) -> Result<Message, WsError>;          // reassembles fragments; answers ping; utf-8 checked
}
#[cfg(test)] pub mod server_side { /* the unmasked server half, for tests and Task 9's fake hub */ }
pub enum WsError { Handshake(String), Protocol(String), TooLarge, Closed, Io(std::io::Error) }
```
- Refused as `Protocol`: a masked server frame, RSV bits set, an unknown opcode, a control frame > 125 bytes or fragmented, a continuation without a start, a 64-bit length with the top bit set, invalid UTF-8 in text. Any `Sec-WebSocket-Extensions` in the 101 answer is a handshake error (we offer none).

- [ ] **Step 1: Write the failing tests:** `accept_key_rfc_example` (RFC 6455 §1.3: `dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`), `roundtrip_text_and_binary`, `client_frames_are_masked`, `fragments_reassemble`, `ping_is_answered`, `oversize_frame_closes` (a 2 MiB + 1 length header → `TooLarge` before reading the payload), `masked_server_frame_is_refused`, `bad_utf8_is_refused`, `extension_in_answer_is_refused`, `wrong_accept_is_refused`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): a small RFC 6455 WebSocket client`.

---

### Task 9: the outbound hub client (size L)

**Files:** Modify `crates/link/src/hub.rs`. **Test:** `crates/link/tests/hub.rs` (a fake hub: rcgen CA + leaf for `hub.test`, `tokio_rustls::TlsAcceptor` on `127.0.0.1:0`, Task 8's `server_side`, a resolver override so `hub.test` connects to that port; no DNS).

**Hub protocol v1** (this section is what `../saiife-hub` implements; out of scope here). All messages are WebSocket text, JSON:
- link → hub after connect: `{"t":"hello","v":1,"machine_id","machine_pub","challenge_sig"}` where the hub first sent `{"t":"challenge","nonce":b64u}` and `challenge_sig` = daemon `workspace.sign {purpose: "hub_hello", data: nonce ‖ machine_id}`. The hub learns nothing it could use to forge frames.
- hub → link: `{"t":"open","session":S}` when a browser connects for this machine id; `{"t":"msg","session":S,"data":b64u}`; `{"t":"close","session":S}`.
- link → hub: `{"t":"msg","session":S,"data":b64u}`, `{"t":"close","session":S}`.
- Inside `data`, per session: first browser → machine `{"t":"seal_hello","browser_eph","device_id"?,"sig"?}`; machine → browser `{"t":"seal_hello","machine_eph","session_id","machine_sig"}` (`machine_sig` from `workspace.sign {purpose: "seal"}`); then only sealed messages (plan 28 `Channel`) whose plaintext is `{"t":"frame", body, sig, touch?}` / `{"t":"pair", …PairRequest}` / `{"t":"hello"}` and the answers.

**Interfaces (Produces):**
```rust
pub struct HubConfig { pub url: String /* wss://host[:port]/v1/link */, pub roots: rustls::RootCertStore, pub connect: Option<std::net::SocketAddr> /* tests only: skip DNS */ }
pub async fn run(cfg: HubConfig, daemon: crate::daemon::Daemon);   // forever: connect, serve sessions, back off
pub struct Backoff { /* 1 s doubling to 60 s, ±20 % jitter, reset after 60 s up */ }
impl Backoff { pub fn next(&mut self, rng: &mut dyn FnMut() -> f64) -> std::time::Duration; pub fn connected_for(&mut self, d: std::time::Duration); }
```
- At most 8 sessions at once (a 9th `open` is answered `close`). A session whose seal fails is closed; the link connection stays. A pairing-only channel (`device_id` absent) accepts only `{"t":"pair"}` and `{"t":"hello"}`. Frames go to the daemon with `via: "hub"`.
- Only `wss://` is accepted (`ws://` is a config error). TLS: `rustls` with the ring provider, `cfg.roots` (production: `rustls-native-certs`), ALPN `http/1.1`.

- [ ] **Step 1: Write the failing tests:** `hello_is_signed_by_the_machine_key` (fake hub verifies `challenge_sig` with `machine_pub`), `sealed_frame_roundtrip` (fake hub plays a `TestBrowserEnd` from plan 28: seal_hello, sealed `box.overview` frame, opens the sealed answer: 4 boxes), `hub_sees_no_plaintext` (every `data` the fake hub relays, decoded, contains neither `"box.overview"` nor `"b-run"`), `pairing_channel_is_pair_only` (a frame on it → session closed), `bad_seal_drops_the_session_not_the_link`, `ninth_session_is_refused`, `ws_url_is_refused`, `reconnect_backs_off` (`Backoff` with a fixed jitter fn: 1, 2, 4 … 60, 60; reset after `connected_for(60 s)`), `hub_cert_must_chain` (fake hub with a cert from another CA → no connection, backoff).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): outbound hub client: signed hello, sealed sessions, backoff`.

---

## Gates (after Task 9)

- [ ] `cargo test -p saiife-ipc -p saiife-wire -p saiife-daemon -p saiife-link -p saiife -j 4 -- --test-threads=4`.
- [ ] `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `cargo clippy -p saiife-daemon --features fake-boxes --all-targets -j 4 -- -D warnings`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-link -p saiife-daemon -p saiife`.
- [ ] `cargo tree -e normal -p saiife-wire -p saiife-ipc | grep -c tokio` → `0`. `git diff v3-dev -- Cargo.lock` adds only `saiife-link` and `qrcode`.
- [ ] Release builds never enable `fake-boxes`: `grep -n fake-boxes .github/workflows/*.yml` shows no release job.
- [ ] Whole-branch review; one fix wave; PR to `v3-dev`.

## Out of scope

- **`../saiife-hub`** (the sealed-frame relay, its machine registry, browser-side WSS endpoint) and **`../saiife.com`** (Workspace mode in Next.js, the phone pairing page at `/workspace`): other repos, same hard rules. They build against "Hub protocol v1" above and plan 28's vectors.
- The UI itself: plan 30. Touch-level actions, WebAuthn and the terminal view: plan 31.
- A systemd user unit or autostart for `saiife workspace serve`: the owner's choice, documented in plan 30's `docs/workspace.md`.
