# Plan 38: the `saiife-guest/1` channel, terminal, gateway CONNECT proxy and the in-box hook (v3 step 3, VM half 4 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Depends on:** plan 34 merged (`GuestLink`, `GuestEvent`, `Manager::guest_event`, template `egress`); plan 35 Task 1 (scaffold) and Task 5 (`VmHooks`) and Task 7 (`real_vmm(…, hooks)`). The in-box hook needs **plan 32 Task 6** (`saiife check --profile box`) at smoke time only; the code here only writes the hook config. Plan 39 uses Task 4's `request_stream`; plan 40 fills Task 6's model listener.

**Goal:** The box talks to the host, and only through channels the daemon owns:
- `saiife-guest` (the `saiife __guest init` service in the image) says hello over vsock with a versioned protocol, receives its setup, runs the agent in a PTY as the `agent` user, streams the PTY, and reports ready, activity, turn finished and exit;
- the host side (`VsockGuest`) implements plan 34's `GuestLink` (prompt, terminal) and feeds `GuestEvent`s to the manager; the terminal is rendered by a headless VT on the host into plan 28's `TermFrame`s and recorded as asciicast v2; `saiife box attach` shows it read-only;
- a per-box gateway listener on vsock carries all egress: an allow-listed `CONNECT` proxy (§7.4) that never opens TLS, refuses private addresses, honours lockdown, and audits per host and byte count;
- the in-box Claude Code hook runs `saiife check --profile box` (advisory, §7.9, §10.5) and the Stop hook reports "turn finished" (§7.7).

**Architecture:**
- **vsock without unsafe code, the spike's way.** The guest has no Rust vsock code: baked `socat` units bridge vsock ports to Unix sockets under `/run/saiife-guest/` (the spike ran `socat VSOCK-LISTEN` and `VSOCK-CONNECT` the same way). The host uses Cloud Hypervisor's multiplexer: host→guest connects to `vsock.sock` and sends `CONNECT <port>\n`; guest→host arrives on `vsock.sock_<port>`, which the host binds before boot (`VmHooks`).
- **Ports** (fixed, `boxproto::ports`): guest→host `5000` events, `5001` egress, `5002` model (plan 40), `5003` PTY; host→guest `1024` control. In the guest, egress is `0.0.0.0:3128` (reachable from containers on the guest's docker bridge, there is no NIC) and the model endpoint `127.0.0.1:3129`.
- **Framing** is one codec for every channel: a tag byte (`0x01` JSON, `0x02` bytes), a 4-byte big-endian length, the payload; at most 1 MiB per frame. The first frame on events is `hello` with `proto: "saiife-guest/1"`; anything else is refused (§7.7: versioned from day one).
- **The gateway is daemon code (tokio)** in `crates/daemon/src/box_gateway/`, because it needs the audit writer, lockdown and (plan 40) the vault. It learns the box id from the listener a connection arrives on, never from the connection.
- **`saiife-guest` is the main `saiife` binary** (hidden subcommand `__guest`), so the image carries one static binary that is also the in-box hook (`saiife check`). Its logic is the `saiife-guest` crate.

**Tech Stack:** Rust. `rustix` (`pty`, `termios` features, already in `Cargo.lock`) in the guest; **one new crate**, `vt100 = "=0.15.2"` (2023, pure Rust, deps `vte`, `unicode-width`, `itoa`, `log`) for the host's headless terminal (spec §9.4 names xterm headless; this is its Rust equivalent; flagged). The daemon's gateway uses tokio as the v2 gateway does.

**Spec:** §5, §7.4, §7.7 (task model, `saiife-guest/1`), §7.9 (hooks advisory), §9.4 (streams), §10.5, §12, §15. Plan 28 Task 7 (`TermFrame`, `TermBatch`), plan 31 Task 5 (the terminal source it waits for), plan 32 D5/D6 and Follow-ups ("write the in-box hook with `--profile box`"). Spike: `guest/spike-exec.sh`, `spike-ready.sh`, `vm.sh` `guest_run`/`guest_recv` (the multiplexer handshake and the ready marker).

## Decisions

- **G1. Ready means "the agent's TUI is up":** the guest sends `started` after the agent has written output and then been quiet for 1 s (at most 30 s after spawn). The manager sends the task as the first prompt on `Ready` (plan 34), so it lands in a drawn TUI.
- **G2. Activity** is sent at most once per 5 s while the PTY produces output. The Stop hook sends `turn_finished`. Plan 34's 30 s idle rule does the rest.
- **G3. Re-hello.** A guest reconnecting (after a restore, or a restarted `saiife-guest.service`) sends `hello` with `set_up: true`; the host does not send setup again and maps a later `started` to nothing (the box is already `Running`).
- **G4. Terminal model.** 40 rows × 120 cols by default; frames are cut at most every 200 ms; the ring keeps 2000 frames with a `Snapshot` every 200 deltas; a reader whose `after` is older than the ring gets the newest snapshot first. Lines carry no control characters (C0, DEL, C1 stripped after the VT has applied them). OSC sequences never produce output (OSC 52 and OSC 8 are dropped by the VT).
- **G5. Recording** `<box>/term.cast`, asciicast v2, capped at 64 MiB; at the cap a final `[t, "m", "recording stopped: 64 MiB cap"]` line and nothing more. The file holds raw escapes: it is evidence, never `cat` it to a terminal (honest limit).
- **G6. CONNECT only.** Plain-HTTP proxying is refused (`403`, "only CONNECT to allowed hosts: plain http is not available in boxes"). So `apt` from `http://` mirrors does not work inside a box in v3.0; HTTPS registries (npm, crates.io, PyPI, Docker Hub) do. **Owner check.**
- **G7. Address rule.** The gateway resolves on the host and refuses when **any** answer is non-public (loopback, RFC 1918, CGNAT, link-local, ULA, multicast, documentation, unspecified, IPv4-mapped forms of those), so an allow-listed name cannot point a box at the host or the LAN. IP literals in `CONNECT` are refused outright.
- **G8. Lockdown.** Any lockdown level that blocks connectors (v2 `lockdown` semantics; `all` always) refuses new egress connections, and open tunnels are closed within 5 s of it turning on.
- **G9. Limits.** 64 open tunnels per box (`429` above); request head ≤ 8 KiB within 10 s; connect timeout 10 s; tunnel idle timeout 300 s.
- **G10. Audit.** One `egress` record per closed tunnel: `extra = {box, session, host, port, addr, bytes_up, bytes_down, ms, outcome}`; refusals `egress_denied` `{box, host, port, reason}`, at most one per (box, host, reason) per 60 s with a `suppressed` count on the next. Per host and byte count, not per request (§7.4).
- **G11. The in-box hook is advisory** (§7.9): `/home/agent/.claude/settings.json` gets `PreToolUse` → `/usr/local/bin/saiife check --hook-exit --agent claude --profile box` (the developer hook; the matcher is the one v2 writes for project hooks in `saiife_agents::claude`) and `Stop` → `/usr/local/bin/saiife __guest event turn-finished`. The host sends the user packs' texts with the setup and the guest writes them to `/home/agent/.config/saiife/packs/`, where plan 32's developer hook reads personal user packs.

## Global Constraints

Plan 35's Global Constraints apply, with worktree `.worktrees/p38`, branch `p38-box-guest`, scratch prefix `p38-tN-`. In addition:
- **Guest code is tested on the host against a tempdir root** (`GuestEnv.root`), with fake `setsid`, `runuser`, `systemctl`, `chown` scripts. A test may open a real PTY and run `/bin/cat` or `/bin/sh -c` as the "agent" through the fake wrappers; never run `systemctl`, never run anything as another user.
- **Gateway tests never use the network:** the resolver is injected (`Resolve` trait) and upstreams are loopback listeners started by the test; the public-address rule is bypassed only through a debug-only `allow_loopback_for_tests` flag on the gateway config.
- `vt100 = "=0.15.2"` is the only new dependency; record it in the report.

### Fixed values

| Name | Value |
|---|---|
| `PROTO` | `"saiife-guest/1"` |
| ports | `EVENTS = 5000`, `EGRESS = 5001`, `MODEL = 5002`, `PTY = 5003`, `CONTROL = 1024`; guest TCP `PROXY_TCP = 3128` (bind `0.0.0.0`), `MODEL_TCP = 3129` (bind `127.0.0.1`) |
| guest sockets | `/run/saiife-guest/{events,pty,control,local}.sock` (dir 0755; `local.sock` 0666) |
| frame | tag `0x01` JSON / `0x02` bytes, `u32` BE length, `MAX_FRAME = 1 << 20` |
| multiplexer handshake | host writes `CONNECT <port>\n`, reads `OK <n>\n` within 2 s |
| hello retry | 30 tries, 1 s apart (spike `spike-ready.sh`) |
| ready | output then 1 s quiet, ≤ 30 s (G1) |
| activity throttle | 5 s (G2) |
| terminal | 40 × 120; frame cut ≤ every 200 ms; ring 2000; snapshot every 200 deltas (G4) |
| cast cap | 64 MiB (G5) |
| gateway limits | 64 tunnels; head 8 KiB / 10 s; connect 10 s; idle 300 s; lockdown check every 5 s (G8, G9) |
| guest env for the agent | `HOME=/home/agent`, `USER=agent`, `PATH=/usr/local/bin:/usr/bin:/bin`, `TERM=xterm-256color`, `LANG=C.UTF-8`, `HTTPS_PROXY=http://127.0.0.1:3128`, `HTTP_PROXY=http://127.0.0.1:3128`, `NO_PROXY=localhost,127.0.0.1`, plus the setup's `env` |
| agent spawn | `/usr/bin/setsid --ctty --wait /usr/sbin/runuser -u agent -- <command…>`, cwd `/work`, stdio = PTY slave |

Guest units (`assets/box/guest/units/`, all `WantedBy=multi-user.target`, listed in `assets/box/guest/enable.list`):

| Unit | `ExecStart` |
|---|---|
| `saiife-guest.service` (`After=local-fs.target saiife-events.service saiife-control.service`, `Restart=always`, `RestartSec=1`) | `/usr/local/bin/saiife __guest init` |
| `saiife-events.service` | `/usr/bin/socat UNIX-LISTEN:/run/saiife-guest/events.sock,fork,mode=0600 VSOCK-CONNECT:2:5000` |
| `saiife-pty.service` | `/usr/bin/socat UNIX-LISTEN:/run/saiife-guest/pty.sock,fork,mode=0600 VSOCK-CONNECT:2:5003` |
| `saiife-control.service` | `/usr/bin/socat VSOCK-LISTEN:1024,reuseaddr,fork UNIX-CONNECT:/run/saiife-guest/control.sock` |
| `saiife-egress.service` | `/usr/bin/socat TCP-LISTEN:3128,bind=0.0.0.0,reuseaddr,fork VSOCK-CONNECT:2:5001` |
| `saiife-model.service` | `/usr/bin/socat TCP-LISTEN:3129,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:5002` |

Each socat unit has `RuntimeDirectory=saiife-guest` and `RuntimeDirectoryPreserve=yes`, `Restart=always`, `RestartSec=1`.

## Review Focus

1. **The box draws a fake UI or tries to act through the terminal:** OSC 52 clipboard writes, OSC 8 links, a drawn "Approve" button, bidi overrides, a 10 MB burst of output. Expected: the host's frames hold plain text only, no escape reaches `box attach` or the Workspace, and frame cutting stays at ≤ 5 per second (Task 5: `osc_sequences_never_reach_frames`, `frames_have_no_control_chars`, `burst_is_rate_limited`; Task 7: `attach_prints_sanitized_lines`).
2. **Egress to where it must not go:** an allow-listed name that resolves to `127.0.0.1` or `10.0.0.5`, mixed public and private answers, an IP literal, `*.crates.io` asked for `crates.io`, port 80 on a 443 rule, a CONNECT with a huge header, a plain `GET http://…`. Expected: each refused with its reason and one rate-limited `egress_denied` record (Task 6: `private_answers_are_refused`, `mixed_answers_are_refused`, `ip_literal_is_refused`, `wildcard_rules`, `port_must_match`, `oversized_head_is_refused`, `plain_http_is_refused`).
3. **A guest that lies about the protocol:** a first frame that is not `hello`, `proto: "saiife-guest/2"`, a 2 MiB frame, events before `welcome`, a flood of `turn_finished`. Expected: refused and the connection closed; nothing reaches the manager before a valid hello; repeated events change nothing beyond plan 34's rules (Task 1: `oversized_frame_is_refused`; Task 4: `wrong_proto_is_refused`, `events_before_hello_are_ignored`, `rehello_does_not_resetup`).
4. **Lockdown and limits during a long download:** lockdown turns on mid-tunnel; the 65th tunnel; a tunnel idle for 300 s. Expected: the tunnel closes within 5 s with outcome `lockdown`; `429`; closed with `idle`; every close audited with byte counts (Task 6: `lockdown_closes_open_tunnels`, `tunnel_cap`, `idle_tunnel_closes`).
5. **The box is stopped or discarded with connections open** (a reader blocked on PTY, an open tunnel, a pending control request). Expected: `after_off` closes every listener and connection, the recorder is flushed, threads end, and no socket file is left (Task 4: `after_off_cleans_up`; Task 6: `gateway_after_off_closes_tunnels`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (protocol), Task 5 (terminal model; needs only plan 28's types).
- **Wave 2 (parallel):** Task 2 (host vsock helpers; needs 1), Task 3 (guest init; needs 1), Task 6 (gateway CONNECT; needs plan 35 Task 5's `VmHooks`).
- **Wave 3:** Task 4 (`VsockGuest`; needs 1, 2, 5).
- **Wave 4 (parallel):** Task 7 (attach, in-box hook config; needs 4), Task 8 (daemon wiring, smoke; needs 4, 6).

---

### Task 1: the `saiife-guest/1` protocol (size S)

**Files:** Modify `crates/boxproto/src/{frame.rs,msg.rs,ports.rs}`.

**Interfaces (Produces):**
```rust
// frame.rs
pub const MAX_FRAME: usize = 1 << 20;
#[derive(Debug, Clone, PartialEq)] pub enum Frame { Json(serde_json::Value), Bytes(Vec<u8>) }
#[derive(Debug)] pub enum FrameError { Io(io::Error), TooLarge(usize), BadTag(u8), BadJson(String) }
pub fn write_frame(w: &mut impl Write, f: &Frame) -> io::Result<()>;
pub fn read_frame(r: &mut impl Read) -> Result<Option<Frame>, FrameError>;   // None = clean EOF before a tag
pub fn write_msg<T: Serialize>(w: &mut impl Write, m: &T) -> io::Result<()>;
pub fn read_msg<T: DeserializeOwned>(r: &mut impl Read) -> Result<Option<T>, FrameError>;   // a Bytes frame here is BadJson
// msg.rs  (every enum: #[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)])
pub enum Event { Hello { proto: String, guest: String, uptime_ms: u64, set_up: bool }, Started, Activity, TurnFinished, Exited { code: Option<i32> } }
pub enum HostReply { Welcome { proto: String }, Refuse { why: String } }
pub enum Request { Setup(Setup), Type { text: String, enter: bool }, Resize { rows: u16, cols: u16 }, Poweroff, Export { n: u32 }, Advance { n: u32, paths: Option<Vec<String>> } }
pub enum Reply { Ok, Err { why: String } }
#[derive(…, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct Setup { pub agent: AgentSpec, pub env: Vec<(String, String)>, pub files: Vec<SetupFile>, pub rows: u16, pub cols: u16 }
#[serde(deny_unknown_fields)] pub struct AgentSpec { pub command: Vec<String>, pub user: String, pub cwd: String }
#[serde(deny_unknown_fields)] pub struct SetupFile { pub path: String, pub mode: u32, pub text: String }
impl Setup { pub fn check(&self) -> Result<(), String>; }
// ports.rs: the Fixed values
```
`Setup::check`: `command` non-empty, no NUL; `user == "agent"`; `cwd == "/work"`; env names `[A-Z_][A-Z0-9_]{0,63}`, values without NUL or newline, at most 64 pairs; files at most 64, each `path` absolute, under `/home/agent/` or `/etc/saiife-guest/`, no `..`, `mode` ≤ `0o755`, text ≤ 256 KiB. (`Export`/`Advance` are plan 39's; declared here so the enum is complete.)

- [ ] **Step 1: Write the failing tests:** `frame_roundtrip_json_and_bytes`, `oversized_frame_is_refused` (header says 1 MiB + 1: `TooLarge` without reading the body), `bad_tag_is_refused`, `clean_eof_is_none`, `truncated_frame_is_io_error`, `msg_json_shapes_are_pinned` (one literal per enum variant: these are the wire contract), `unknown_field_is_refused`, `setup_check_rules`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `bash scripts/check-windows.sh -p saiife-boxproto`.
- [ ] **Step 5: Commit** `feat(boxes): the saiife-guest/1 protocol: frames, messages, ports`.

---

### Task 2: host-side vsock over the Cloud Hypervisor multiplexer (size S)

**Files:** Modify `crates/boxhost/src/vsock.rs`.

**Interfaces (Produces):**
```rust
pub fn connect(paths: &BoxPaths, port: u32, timeout: Duration) -> io::Result<UnixStream>;   // CONNECT <port>\n, expects "OK <n>\n"; read/write timeouts set
pub fn listen(paths: &BoxPaths, port: u32, group_rw: bool) -> io::Result<UnixListener>;      // unlink a stale socket first (only a socket, never another file type); mode 0660 if group_rw else 0600
pub fn unlink_all(paths: &BoxPaths);                                                          // vsock_port() of every port in ports.rs
```
- [ ] **Step 1: Write the failing tests** (a fake multiplexer thread on `$TMPDIR/b1/vsock.sock` that answers `OK 1073741824\n` or `garbage\n` or nothing): `connect_handshake_ok`, `connect_bad_answer_is_error`, `connect_times_out`, `listen_replaces_stale_socket`, `listen_refuses_to_unlink_a_regular_file`, `listen_mode_0660`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): host vsock through the Cloud Hypervisor multiplexer`.

---

### Task 3: the guest init (`saiife __guest`) and the guest units (size L)

**Files:** Modify `crates/guest/src/{lib.rs,env.rs,control.rs,events.rs,pty.rs,setup.rs,export.rs}`; create `assets/box/guest/units/*` (the six units), `assets/box/guest/enable.list`, `crates/guest/tests/init.rs`; modify `crates/cli/src/main.rs` (hidden `Cmd::Guest { #[command(subcommand)] cmd: GuestCmd }` as `__guest`).

**Interfaces (Produces):**
```rust
// env.rs
#[derive(Debug, Clone)] pub struct GuestTools { pub setsid: PathBuf, pub runuser: PathBuf, pub systemctl: PathBuf, pub chown: PathBuf, pub git: PathBuf }
#[derive(Debug, Clone)] pub struct GuestEnv { pub root: PathBuf, pub tools: GuestTools, pub version: String }
impl GuestEnv { pub fn system() -> GuestEnv;   // root "/", /usr/bin/setsid, /usr/sbin/runuser, /usr/bin/systemctl, /usr/bin/chown, /usr/bin/git
                pub fn path(&self, abs: &str) -> PathBuf; }   // root.join(abs without the leading '/')
// lib.rs
pub fn run_init(env: &GuestEnv) -> Result<(), String>;        // the service main; returns only on a fatal error (systemd restarts it)
pub fn send_local_event(env: &GuestEnv, ev: &Event) -> Result<(), String>;   // `saiife __guest event turn-finished` -> local.sock
// export.rs (plan 39 fills; a no-op here)
pub fn init_base(env: &GuestEnv) -> Result<(), String> { Ok(()) }
// CLI
#[derive(Subcommand)] pub enum GuestCmd { Init, Event { name: String /* "turn-finished" */ } }
```
`run_init`: (1) connect `events.sock` (hello retry), send `Hello { set_up: <marker /var/lib/saiife-guest/setup-done exists>, uptime_ms from /proc/uptime, guest: version }`; expect `Welcome` (a `Refuse` logs to stderr and returns `Err`). (2) Bind `control.sock` and `local.sock`. (3) Serve control requests one connection at a time, one request each, answering `Reply`:
- `Setup`: `check()`; write each file (parents created, owner `agent` via `chown`, mode as given); write `/etc/saiife-guest/agent.env`; on first setup `chown -R agent:agent /work` and `init_base(env)`, then touch the marker; spawn the agent (Fixed values row) on a new PTY (`rustix::pty::openpt` + `grantpt` + `unlockpt` + `ptsname`, window size via `rustix::termios::tcsetwinsize`), env = the fixed agent env + setup env, nothing inherited; start the PTY pump thread; reply `Ok`. A second `Setup` while the agent runs is `Err("already set up")`.
- `Type`: write `text` (+ `\r` when `enter`) to the PTY master; no agent → `Err("the agent is not running")`.
- `Resize`: `tcsetwinsize`.
- `Poweroff`: `systemctl poweroff --no-block`, reply `Ok` first.
- `Export`/`Advance`: `Err("not in this version")` until plan 39.

PTY pump: read the master in 16 KiB reads, write each read as a `Bytes` frame to `pty.sock` (reconnecting on error, dropping output while disconnected), drive G1 (`Started`) and G2 (`Activity`) on the events connection. On child exit: `Exited { code }`. `local.sock` accepts one JSON `Event` per connection (only `TurnFinished` is forwarded; anything else is dropped).

- [ ] **Step 1: Write the failing tests** (`tests/init.rs`: `GuestEnv { root: $TMPDIR/g }`, fake `setsid` script that `exec "$4"…` past `--ctty --wait` and fake `runuser` that strips `-u agent --`, fake `chown`/`systemctl` that record argv; the test plays the host on `events.sock`, `pty.sock` and `control.sock`): `hello_then_welcome`, `refuse_ends_init`, `setup_writes_files_and_env`, `setup_check_refuses_bad_paths` (`/etc/shadow`, `/home/agent/../x`), `agent_runs_on_a_pty` (command `/bin/sh -c 'tty; echo hi; sleep 2'`: output arrives as `Bytes` frames and contains `/dev/pts/`), `started_after_quiet`, `activity_is_throttled`, `type_writes_to_the_pty` (agent `/bin/cat`: typed `abc` comes back), `exited_reports_code`, `second_setup_is_refused`, `turn_finished_via_local_socket`, `poweroff_replies_then_calls_systemctl`, `rehello_reports_set_up`.
- [ ] **Step 2: Run** `cargo test -p saiife-guest -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement**; write the units and `enable.list` (`systemd-analyze verify` is **not** run; check by test `units_are_as_fixed` that each file's `ExecStart` equals the table).
- [ ] **Step 4: Run** → PASS; tokio gate `0` for `saiife-guest`.
- [ ] **Step 5: Commit** `feat(guest): saiife-guest init: hello, setup, the agent on a PTY, events; guest units`.

---

### Task 4: `VsockGuest`, the host end of the channel (size L)

**Files:** Modify `crates/boxhost/src/guest.rs`; create `crates/boxhost/tests/vsock_guest.rs` (a fake guest built from `saiife-guest`'s pieces is **not** used; the test plays the guest with the protocol codec).

**Interfaces:**
- Consumes: Tasks 1, 2, 5; plan 34 `GuestLink`, `GuestEvent`, `GuestError`; plan 35 `VmHooks`, `BoxPaths`.
- Produces:
```rust
pub trait SetupSource: Send + Sync { fn setup_for(&self, id: &BoxId) -> Result<Setup, String>; }
pub struct VsockGuest { /* Mutex<BTreeMap<BoxId, Link>>, event queue (Mutex<VecDeque> + Condvar) */ }
impl VsockGuest {
  pub fn new(setups: Arc<dyn SetupSource>, group_rw: bool) -> Arc<VsockGuest>;
  pub fn recv_events(&self, timeout: Duration) -> Vec<(BoxId, GuestEvent)>;      // blocks up to timeout
  pub fn request(&self, id: &BoxId, req: &Request, timeout: Duration) -> Result<Reply, GuestError>;
  pub fn request_stream(&self, id: &BoxId, req: &Request, timeout: Duration, on_frame: &mut dyn FnMut(Frame) -> Result<bool, String>) -> Result<(), GuestError>;   // frames until on_frame returns Ok(false) or the guest closes; plan 39
  pub fn resize(&self, id: &BoxId, rows: u16, cols: u16) -> Result<(), GuestError>;
  pub fn last_error(&self, id: &BoxId) -> Option<String>;   // the last refused hello or failed setup; the daemon copies it into the record's `error` on BootFailed
}
impl VmHooks for VsockGuest { /* before_boot: listen(EVENTS), listen(PTY), Recorder::create, spawn the two acceptor threads; after_off: shut both listeners and streams, flush the recorder, unlink sockets */ }
impl saiife_boxes::guest::GuestLink for VsockGuest {
  /* prompt -> request(Type { text, enter: true }, 5 s); terminal -> the box's Screen::batch(after); diff -> Unavailable("the diff is read through the land book") */
}
```
Event acceptor: first frame must be `Hello` with `proto == PROTO` within 10 s (else `Refuse` and close); reply `Welcome`; if `!set_up`, `setup_for(id)` then `request(Setup, 10 s)` on a fresh control connection (`vsock::connect(CONTROL)`); then map `Started` → `GuestEvent::Ready` (only once per box run, G3), `Activity`, `TurnFinished`, `Exited` → the same `GuestEvent`s on the queue. A new events connection replaces the old one. PTY acceptor: every `Bytes` frame → `Screen::feed` and `Recorder::output`.

- [ ] **Step 1: Write the failing tests** (box dir `$TMPDIR/b1`; the test runs a fake multiplexer on `vsock.sock` that forwards `CONNECT 1024` to a test-side control server): `hello_setup_started_is_ready`, `wrong_proto_is_refused`, `events_before_hello_are_ignored`, `rehello_does_not_resetup`, `setup_failure_is_kept` (control answers `Err`: no `Ready` is queued and `last_error(b1)` returns the text; the boot timeout then discards the box with that text), `prompt_types_text_and_enter`, `prompt_without_link_is_not_connected`, `terminal_serves_screen_frames`, `request_stream_stops_on_false`, `after_off_cleans_up` (threads joined, sockets gone, cast flushed), `recv_events_times_out_empty`.
- [ ] **Step 2: Run** `cargo test -p saiife-boxhost --features fake --test vsock_guest` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): VsockGuest: hello, setup, events and the PTY stream on the host (GuestLink)`.

---

### Task 5: the headless terminal and the recorder (size M)

**Files:** Modify `crates/boxhost/src/term.rs`, `crates/boxhost/Cargo.toml` (`vt100 = "=0.15.2"`).

**Interfaces (Produces):**
```rust
pub struct Screen { /* vt100::Parser, ring: VecDeque<TermFrame>, seq, last rows, last cut ms */ }
impl Screen {
  pub fn new(rows: u16, cols: u16) -> Screen;
  pub fn feed(&mut self, bytes: &[u8], now_ms: u64);    // parses all bytes; cuts a frame only if ≥ 200 ms since the last cut
  pub fn flush(&mut self, now_ms: u64);                  // cut a pending change now (called on a 200 ms timer and at exit)
  pub fn resize(&mut self, rows: u16, cols: u16, now_ms: u64);   // always a Snapshot
  pub fn batch(&self, after: Option<u64>, ended: bool) -> saiife_wire::TermBatch;   // plan 28 semantics: seq > after; next = highest returned or after.unwrap_or(0)
}
pub fn clean_line(s: &str) -> String;   // strip C0, DEL, C1; keep printable and wide chars
pub struct Recorder { /* BufWriter<File>, bytes, capped */ }
impl Recorder { pub fn create(path: &Path, rows: u16, cols: u16, unix_now: u64) -> io::Result<Recorder>; pub fn output(&mut self, t_secs: f64, bytes: &[u8]); pub fn flush(&mut self); }
```
A delta lists only the rows whose cleaned text changed; the first frame is always a `Snapshot`.

- [ ] **Step 1: Write the failing tests:** `first_frame_is_snapshot`, `delta_lists_changed_rows_only`, `cursor_is_reported`, `osc_sequences_never_reach_frames` (`ESC ]52;c;aGk= BEL`, `ESC ]8;;https://x BEL link ESC ]8;; BEL`: lines contain `link` and never `]52`, `]8`, `https://x` from the OSC, or `\x1b`), `frames_have_no_control_chars` (random bytes fuzzed 1000 times with a fixed seed: every line passes `clean_line == itself`), `burst_is_rate_limited` (10 MB fed in 1 s of simulated time → ≤ 6 frames), `old_after_gets_a_snapshot`, `batch_pages_by_seq`, `resize_is_snapshot`, `cast_header_and_events` (asciicast v2 header keys, `[t, "o", data]` lines), `cast_stops_at_cap` (cap lowered through a test-only constructor).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo tree -e normal -p saiife-boxhost | grep -c tokio` → `0`.
- [ ] **Step 5: Commit** `feat(boxes): headless terminal frames and asciicast v2 recording (spec §9.4)`.

---

### Task 6: the per-box gateway listener and the CONNECT proxy (size L)

**Files:** Create `crates/daemon/src/box_gateway/{mod.rs,egress.rs,model.rs}`, `crates/daemon/tests/box_gateway.rs`; modify `crates/daemon/src/lib.rs`.

**Interfaces:**
- Consumes: plan 34 `Manager::get`, `Manager::templates`, `template::EgressRule`; plan 35 `VmHooks`, `BoxPaths`; v2 `ctx.lockdown`, `ctx.record`, `ctx.writer`.
- Produces:
```rust
// mod.rs
pub trait Resolve: Send + Sync { fn lookup(&self, host: &str, port: u16) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>>; }   // tokio::net::lookup_host in production; no async-trait crate
pub struct GatewayConfig { pub limits: Limits, pub allow_loopback_for_tests: bool /* debug builds only */ }
pub struct Limits { pub tunnels: usize, pub head_bytes: usize, pub head_secs: u64, pub connect_secs: u64, pub idle_secs: u64 }   // G9
pub struct GatewayHooks { /* Arc<Ctx>, tokio Handle, Arc<dyn Resolve>, config, Mutex<BTreeMap<BoxId, BoxListeners>> */ }
impl GatewayHooks { pub fn new(ctx: Arc<Ctx>, rt: Handle, resolve: Arc<dyn Resolve>, cfg: GatewayConfig) -> Arc<GatewayHooks>; }
impl saiife_boxhost::vmm::VmHooks for GatewayHooks { /* before_boot: bind vsock_port(EGRESS) and vsock_port(MODEL) (0660, group per layout), spawn accept loops; after_off: abort them and every open tunnel, unlink */ }
// egress.rs
pub fn parse_connect(head: &[u8]) -> Result<(String, u16), &'static str>;   // "CONNECT host:port HTTP/1.x" + headers to CRLFCRLF
pub fn allowed(rules: &[EgressRule], host: &str, port: u16) -> bool;        // exact name, or "*.<suffix>" for names with ≥ 1 more label; port equal
pub fn public(ip: &IpAddr) -> bool;                                          // G7 list
pub async fn serve(stream: UnixStream, id: BoxId, gw: Arc<GatewayShared>);
// model.rs: plan 40 fills; here every model connection gets "HTTP/1.1 503 Service Unavailable" with body "model access is not set up yet" and closes
```
`serve`: read the head (G9) → `parse_connect` (error → `400`); non-CONNECT → G6 `403`; lockdown (G8) → `503`; the box's template egress via `spawn_blocking(mgr.get(id))` (unknown box → `403`); `allowed` (no → `403 "<host>:<port> is not in this box's allow-list"`); `lookup` → every answer `public` (else `403 "<host> resolves to a private address"`); connect the first answer (timeout → `504`, error → `502`); `HTTP/1.1 200 Connection established\r\n\r\n`; `copy_bidirectional` with byte counters, idle timeout and a 5 s lockdown check; on close the `egress` record (G10). The template's rule list is read once per connection (a template change applies to new tunnels).

- [ ] **Step 1: Write the failing tests** (`tests/box_gateway.rs`: `test_ctx` with a FakeVmm manager and a template whose egress is `["example.test:443", "*.crates.test:443"]`; a fake `Resolve` map; a loopback TCP echo server as upstream with `allow_loopback_for_tests`): `connect_tunnels_bytes_both_ways` (and one `egress` record with `bytes_up`/`bytes_down` equal to what was sent), `not_allowed_is_403_and_audited`, `wildcard_rules` (`a.crates.test` ok, `crates.test` refused, `a.b.crates.test` ok), `port_must_match`, `private_answers_are_refused` (allow-loopback off: `127.0.0.1`, `10.0.0.5`, `::1`, `::ffff:192.168.1.1`, `100.64.0.1`, `fe80::1`), `mixed_answers_are_refused`, `ip_literal_is_refused`, `plain_http_is_refused`, `oversized_head_is_refused`, `slow_head_times_out`, `denied_records_are_rate_limited` (5 refusals in a second → 1 record; the next after 60 s of the injected clock carries `suppressed: 4`), `lockdown_refuses_new_tunnels`, `lockdown_closes_open_tunnels` (outcome `lockdown` within 6 s), `tunnel_cap` (the 65th gets `429`), `idle_tunnel_closes` (idle lowered to 1 s), `gateway_after_off_closes_tunnels`, `model_port_is_503_until_plan_40`; unit `public_rules` (each range of G7, plus `8.8.8.8` and `2606:4700::1111` public).
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm --test box_gateway -j 4 -- --test-threads=4` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): per-box gateway listener and allow-listed CONNECT proxy (spec §7.4)`.

---

### Task 7: `saiife box attach` and the in-box hook config (size M)

**Files:** Create `crates/cli/src/box_attach.rs`; modify `crates/cli/src/box_cmd.rs` (`BoxAction::Attach { id: String }`), `crates/boxhost/src/guest.rs` (`claude_settings`, `pack_files`).

**Interfaces (Produces):**
```rust
// boxhost guest.rs
pub fn claude_settings() -> String;    // G11 JSON, pinned by test
pub fn pack_files(packs: &[(String, String)] /* (id, toml text) */) -> Vec<SetupFile>;   // /home/agent/.config/saiife/packs/<id>.toml, 0644; ids must be valid user-pack ids (plan 32 valid_user_pack_id)
// cli box_attach.rs
pub fn run(client: &mut Client, id: &BoxId, tty: bool) -> ExitCode;
pub fn apply(screen: &mut Vec<String>, f: &TermFrame);     // snapshot replaces, delta patches
```
`attach`: polls `box.term.read {id, after}` every 250 ms; on change redraws the whole screen (clear, then each line through `crate::text::sanitize`), with a header `box <id> (<state>): read-only, q quits; type into it with saiife box say <id> "…"`; raw mode through `rustix::termios` only to read `q` / Ctrl-C, restored on exit and on panic; without a TTY prints the current screen once and exits 0; `ended` prints `the box's terminal has ended` and exits 0.

- [ ] **Step 1: Write the failing tests:** `claude_settings_are_pinned` (exact JSON: the `PreToolUse` command with `--profile box`, the `Stop` command), `pack_files_paths_and_bad_ids`, `apply_snapshot_and_delta`, `attach_prints_sanitized_lines` (CLI test with `--features fake-vmm`: a `FakeGuest` terminal with a line holding `\u{202e}` and an ESC; output shows the escaped forms only), `attach_without_tty_prints_once`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): saiife box attach (read-only); in-box hook config with --profile box`.

---

### Task 8: daemon wiring and the smoke fragment (size M)

**Files:** Modify `crates/daemon/src/box_ops.rs` (build `VsockGuest` + `GatewayHooks`, pass both to `real_vmm`, start the event forwarder), `crates/daemon/src/box_vmm.rs`; create `crates/daemon/src/box_setup.rs`, `scripts/box-smoke.d/30-guest.sh`.

**Interfaces:**
- Consumes: Tasks 4, 6, 7; plan 35 `real_vmm(layout, mode, hooks)`; plan 32 Task 4's user-pack reader (`crates/policy/src/userpacks.rs`).
- Produces:
```rust
pub struct TemplateSetup { /* Arc<Manager>, packs reader */ }
impl saiife_boxhost::guest::SetupSource for TemplateSetup { /* command from the template, env = [] (plan 40 adds the model env), files = [claude_settings at /home/agent/.claude/settings.json (0644)] + pack_files(user packs), rows 40, cols 120 */ }
pub fn start_event_forwarder(ctx: Arc<Ctx>, guest: Arc<VsockGuest>);   // spawn_blocking loop: recv_events(1 s) -> mgr.guest_event -> one tick-style record per Change (via "guest")
```
`Manager` is built with `guest = VsockGuest` when the real VMM is used (FakeGuest stays for the `fake-vmm` path). `box.term.read` (plan 29 / plan 34 name) reaches `GuestLink::terminal` through `ManagerSource`, unchanged.

`30-guest.sh` (owner-run; result keys): time from spawn to `Ready` (`ready_ms`); `saiife box say` types into the TUI (`say_ok`); `saiife box attach` shows the screen (by eye; the script pauses for the owner); inside the box (`say` a shell command when the template command is `bash`, the smoke uses a `bash` template from `scripts/box-smoke.d/templates/bash.toml`): `printf '\e]52;c;aGVsbG8=\a'` leaves the host clipboard unchanged and `box.term.read` has no `\x1b` (`osc52_inert`); `curl -sS https://registry.npmjs.org/ -o /dev/null -w '%{http_code}'` with npm allow-listed → `200`, a host not on the list → proxy `403` (`egress_allow`, `egress_deny`); `localtest.me` (a public name that resolves to `127.0.0.1`), allow-listed in the smoke template → `403` (`egress_private`); `docker pull busybox@sha256:<pin>` through the proxy with Docker Hub's three hosts allow-listed (`docker_pull_ok`); the audit has `egress` records with byte counts; a Claude Code `Stop` hook moves the box to `done` within ~30 s of the turn (needs plan 40; skipped with a note if the template is `bash`).

- [ ] **Step 1: Write the failing tests:** daemon `setup_for_has_settings_and_packs` (a user pack in the personal packs dir → a `SetupFile` at the expected path), `forwarder_moves_ready_box_to_running` (VsockGuest replaced by a test `SetupSource` + test guest on a fake multiplexer, or: `start_event_forwarder` over a stub that yields `(b1, Ready)` → `mgr.get(b1).state == Running` and one record with `via: "guest"`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; write the fragment and `templates/bash.toml` (`command = ["bash"]`, egress for the checks above); `bash -n`; shellcheck if installed. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): wire the guest channel and the gateway into real boxes; guest smoke`.

---

## Gates

- [ ] `cargo test -p saiife-boxproto -p saiife-guest -p saiife-boxhost --features fake -p saiife-daemon --features fake-vmm -p saiife --features fake-vmm`, and the daemon and CLI suites without features; `-j 4 -- --test-threads=4`.
- [ ] clippy; `check-unsafe.sh`; `check-windows.sh -p saiife-boxproto -p saiife-daemon -p saiife`; tokio gate `0` for `saiife-boxproto`, `saiife-boxhost`, `saiife-guest`.
- [ ] `git diff v3-dev -- Cargo.lock` adds `vt100` and its deps only (list them in the PR).
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Owner handwork

- [ ] Decide G6 (CONNECT only, no plain-HTTP proxying in v3.0) and the `vt100` dependency.
- [ ] Rebuild the image (plan 36) with this plan's guest units, then run `scripts/box-smoke.sh --only guest`.
