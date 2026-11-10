# saiife v3 design: agents in boxes

Date: 2026-11-10
Status: **draft for owner review** (builder check done; owner answers folded in). Comes from the owner brainstorm of 2026-11-10 and four read-only research passes (boxes, touch approvals, Workspace, never-rules). It builds on the v3 vision (`docs/superpowers/specs/2026-10-26-saiife-v3-harness-os-vision.md`, branch `pr15`), v1 §9.4 and v2 §18. Nothing here changes v2.0, except one amendment, which the owner signed off (§9.6).

Each decision is marked **[owner]** (said by the owner in the brainstorm) or **[call]** (my call, open to change). Unmarked text describes the design that follows from them.

## 1. Intent

Today an AI coding agent runs on the user's machine as the user. saiife v1/v2 put a guard and an audit around it, but the agent still shares the user's files, network, secrets and processes. Because of that, agents are kept away from Docker, `sudo`, process control and real test stacks. The 2026-10-22 `pkill` crash is why the owner's hard rules exist.

v3 runs every agent **inside a full VM (a "box")** that saiife controls from outside. Inside its box the agent may do anything: Docker, databases, whole app stacks, root. Nothing leaves the box unless saiife allows it:

- network only through saiife's gateway;
- secrets added by the gateway, never inside the box;
- code changes land on the real repo only after the human reviews the diff;
- risky steps need a physical touch (fingerprint, hardware key, phone Face ID).

The user watches and steers boxes from the CLI or from a web **Workspace** on their phone.

Why now: v2 is code-complete (2026-11-10). The owner wants agents that can really work (run app stacks, privileged tests, integration tests), safely and on the record. That is the "safe runs" brand direction.

## 2. Goals, non-goals, anti-goals

**Goals**
1. One command or one tap starts an agent in a box with a full app-capable Linux VM. **[owner]**
2. Nothing from a box reaches the real repo, the network or a secret without saiife's say and a record.
3. Risky actions need a physical touch, and the audit holds a signature that proves it.
4. The user's never-rules (`CLAUDE.md`, rules files) become rules the guard enforces, not requests.
5. Phone Workspace: overview, review and revise, steer, approve, spawn. **[owner]**
6. Works for many workflows, not only the owner's. **[owner]**

**Non-goals (v3.0)**
- macOS and Windows boxes (Linux/KVM first; adapters later, §7.10). **[call]**
- Agents other than Claude Code at launch. Codex and Gemini follow as "beta" templates. **[owner]** for the focus, **[call]** for the beta label.
- Desktop or GUI inside a box. **[owner]** (terminal plus diff plus app link is enough)
- Trading-style multi-pane "advanced terminal" for power users and vibecoders. **[owner]**: out of scope, listed in §14.
- Multi-machine fleet, team approvers, cloud-hosted boxes.

**Anti-goals: failures even if it technically works**
- A hub compromise that can start boxes, approve actions or loosen rules.
- Approval fatigue: so many touch prompts that users approve without reading.
- Boxes that eat the disk (as 25 worktrees did on 2026-11-05) or bring the laptop to a crawl.
- A "container-only" tier sold as isolation. **[owner]**: full VM only.
- Hiding what is not enforced: never-rules saiife cannot check must be shown as "not enforced".
- A design that only works for the owner's own workflow. **[owner]**

## 3. Constraints

- **Rust**, in the saiife workspace. The guard, audit, policy, ipc and system crates stay tokio-free. New dependencies must be pinned to a version older than 14 days; prefer crates already in `Cargo.lock` (`ring`, `hyper`, `rustls`, `tokio` are there).
- **Fail closed** everywhere: if saiife can't decide, the action is blocked.
- **Builder hard rules** (`.superpowers/sdd/hard-rules.md`) bind build agents: no sudo, no docker, no process-control tools, no network in tests. So every part that needs root, Docker or a real VM must be testable against mocks, and real-VM and real-Docker checks are owner-run smoke scripts (§12).
- **No cargo builds until the owner says the v2 fine-tune PR is merged.** **[owner]**
- Owner machine for sizing: i7-9850H (6 cores / 12 threads), 32 GB RAM, ext4 (no reflinks), `/dev/kvm` and `/dev/vhost-vsock` available, nested KVM on.

## 4. Decisions at a glance

| # | Decision | Who |
|---|---|---|
| D1 | Every agent gets a full VM able to run Docker, databases and whole stacks, even with one agent; accept the cost | owner |
| D2 | No container-only tier | owner |
| D3 | No desktop; terminal stream, logs, diff, app links | owner |
| D4 | Touch only for certain actions, not everything | owner |
| D5 | Phone access in 3 levels (§9.5) | call (owner unsure, accepted my recommendation) |
| D6 | First user is the owner; design must not assume the owner's workflow (templates) | owner |
| D7 | Claude Code first; Codex/Gemini later | owner |
| D8 | `saiife dev` ships first, as its own slice, if it is needed and fits best practice | owner (conditional), call (it is needed: app links) |
| D9 | VMM: Cloud Hypervisor | call |
| D10 | Box has no network card; vsock only to saiife | call |
| D11 | Touch = FIDO2/WebAuthn signatures only (no plain fprintd yes/no) | call |
| D12 | Workspace ↔ daemon: end-to-end encrypted relay through the hub; pairing at the machine | call |
| D13 | Imported never-rules can only add restrictions | call |
| D14 | Build order: dev → boxes → touch → never-rules → Workspace | call |

## 5. Architecture

```
 phone / browser (Workspace)            laptop (host)
 ───────────────────────────            ───────────────────────────────────────────
  app.saiife.com  ──E2E sealed──▶ hub relay ──▶ saiife-link (unprivileged, outbound WSS)
                                                        │ verified frames
                                                        ▼
  saiife CLI ───── IPC socket ──────────────▶  saiife daemon (user `saiife`, locked)
                                                 ├─ guard / policy / never-rules packs
                                                 ├─ approvals + touch verifier
                                                 ├─ vault + gateway (one listener per box)
                                                 ├─ box manager: queue, VMM, disks, cleanup
                                                 ├─ dev proxy (saiife dev, ports 80/443)
                                                 └─ audit chain (signed, forwarded)
                                                        │ vsock only
                                                        ▼
                                          ┌──────── box (Cloud Hypervisor VM) ────────┐
                                          │ saiife-guest init: proxy, PTY, diff export│
                                          │ Claude Code, dockerd, app stack, tests    │
                                          │ repo copy on its own disk                 │
                                          └───────────────────────────────────────────┘
```

Everything that matters stays outside the box: binary, policy, vault, audit, keys, approvals. The box talks to the host only through vsock channels the daemon opens and owns.

### 5.1 Privileges and install modes [call]
- **Boxes need locked mode** (v2 `system install`). The daemon keeps running as the unprivileged `saiife` user, as in v2 §5.1. Personal mode (`saiife daemon --user`) may start boxes for trying things out, labelled "not a security boundary", the same as v2 personal mode.
- `system install` (root, once) adds:
  - a `saiife-box` system user, which runs every VMM;
  - systemd `Delegate=yes` on `saiifed.service`, so the daemon can make a cgroup per box without root;
  - `/dev/kvm` and `/dev/vhost-vsock` access for `saiife-box`;
  - `CAP_NET_BIND_SERVICE` for the dev proxy (`AmbientCapabilities`), so 80/443 bind without root.
- **The user's files are touched only by the CLI, running as the user.** The CLI makes the repo snapshot at spawn and hands the image to the daemon. At `land`, the daemon verifies the touch and gives the CLI the validated diff, and the CLI writes the worktree and branch. The daemon never reads or writes a user's repo.
- `saiife dev` uses the host Docker socket from the **CLI as the user** (the user already has Docker), never from the daemon. In v3.0 the proxy runs as a labelled container that `saiife dev` starts; the daemon only tells it where box ports are.

## 6. Part A: `saiife dev` (environments), the first slice

Scope as in the vision §5, unchanged:
- one proxy owns 80/443;
- `<service>.<project>.localhost` names instead of ports;
- zero-edit use on any compose repo (an override written outside the repo);
- per-project mkcert certificates;
- `saiife dev up | ls | down | gc`;
- an ownership label `saiife.managed` on everything it creates, and volumes deleted only after confirmation;
- per-project quirks in `~/.config/saiife/dev/<project>.toml`.

**Why first [call]:** boxes need it. App links from a box (`https://app.box1.localhost`) go through this proxy. It is also useful alone, and it builds the label, cleanup and Docker-API code (`bollard`) the box manager reuses.

**v3 addition:** the proxy gets a second kind of backend, "a port inside box N". The daemon opens a vsock connection into the guest on demand. No host port is ever bound for a box.

**Release [call]:** ship as `saiife dev` in a 0.3.x release before boxes, labelled preview.

**Builder note:** host Docker is off-limits to build agents. Unit and integration tests use a loopback mock of the Docker Engine API. Owner smoke: `scripts/dev-smoke.sh`.

## 7. Part B: boxes

### 7.1 VMM [call]
**Cloud Hypervisor** (Rust, Apache-2.0/BSD-3), driven over its REST API on a Unix socket with `hyper`. Why:
- Firecracker-like security (seccomp, Landlock, small device set);
- vsock mapped to host Unix sockets;
- virtio-blk, virtio-mem/balloon;
- working snapshot/restore;
- direct kernel boot in about 100–200 ms.

Firecracker stays the documented alternative. QEMU microvm is the last fallback.

The VMM runs as an unprivileged `saiife-box` user, confined with Landlock (`crates/system/src/sandbox.rs`) and a cgroup per box.

### 7.2 Base image
- A reproducible recipe (mkosi or a Dockerfile flattened to a rootfs) builds a read-only erofs (or ext4) image plus a custom guest kernel with overlayfs, cgroup2, netfilter and bridge, for nested Docker.
- Contents: Claude Code at a pinned version, dockerd and containerd, git, common toolchains, `saiife-guest`.
- Versioned `base-<sha256>` with a signed manifest. Each box's start record holds the image hash. A Claude Code update means a new image.
- Users can add their own images through templates (§7.8).
- **Distribution [call]:** the saiife release pipeline builds and signs the image with the release key, and `saiife box image pull` downloads and verifies it. A local build (`saiife box image build`) is a developer option that needs container tooling. That makes image building, hosting and signing a release-infrastructure task (§11 step 3), and owner-only release steps.

### 7.3 Disks per box
- Under `<state>/boxes/<id>/`, labelled.
- Root: the base image, attached read-only. Inside the guest an overlay puts writes on a sparse per-box **data disk**, default 30 GiB, which also holds `/var/lib/docker`, home and caches.
- Repo: a separate disk (§7.5).
- Discard deletes the directory. `saiife box gc` sweeps orphans. Images stay while a snapshot references them.

### 7.4 Network: none [call]
- The box gets **no network card**. `saiife-guest` runs a local HTTP(S) proxy and sets `ANTHROPIC_BASE_URL`. Both forward over vsock to a **per-box gateway listener**, so all egress goes through the gateway by construction, and the box id is known from the listener it arrives on.
- Docker networking stays inside the guest.
- Image pulls, npm, pip and the like go through a new **allow-listed CONNECT proxy** in the gateway. It is new gateway code; the v2 gateway only knows named connectors.
- **Secrets in v3.0 [call]:** only the model endpoint and named v2 connectors get a secret added. The CONNECT proxy carries end-to-end TLS, which saiife does not open: no TLS interception and no saiife CA in the guest. So private registries and `git push` from inside a box are out for v3.0. Pushing happens on the host after `land` (§8.2). The CONNECT proxy is audited per host and byte count, not per request.
- This tier needs no root. An optional tap + nftables tier for raw TCP/UDP is reserved; it needs the root daemon, and it is not in v3.0.

### 7.5 Repo in, diff out
- **In:** at box start, a snapshot copy of the working tree goes onto a per-box disk image (`mkfs.ext4 -d`, unprivileged). It covers tracked files, untracked-not-ignored files, uncommitted edits and the base commit hash. The host's `.git` objects are never shared or hardlinked.
- **Out:** `saiife-guest` exports a tree diff against the base over vsock (binary-safe, including untracked files). The host treats it as **untrusted data**:
  - validate paths: no `.git/`, no hooks or git config, no symlinks pointing out;
  - enforce size caps;
  - never run git on the guest's `.git`.
- After approval the host applies the diff with its own applier, to a new branch in a fresh host worktree (`saiife/box-<id>`), never straight into the user's working tree. **[call]** Approve all, reject, or approve per file or hunk. The diff hash and the decision go into the audit.
- **Revise [owner]:** reject with a comment sends the comment back to the running agent, and the box keeps going.

### 7.6 Capacity and queue
- Default box: 2 vCPU, 4 GiB RAM (balloon up to 8 GiB), 30 GiB sparse disk. **[call]**
- Host reserve: 8 GiB RAM, 2 threads.
- Admission: committed RAM ≤ total − reserve (about 24 GiB here, so about 5 default boxes), vCPUs ≤ 2× threads, and free disk ≥ 30 GiB + the box's disk. Otherwise the box goes into a FIFO queue, shown as `queued`.
- An idle box is ballooned down after 10 min and stopped after a template-set idle timeout.
- Realistic load: 3 busy Rust builders at once on this machine.

### 7.7 Lifecycle and commands
```
saiife box spawn --template <t> [--repo .] [--task "..."]   # or run-agent alias
saiife box ls | attach <id> | say <id> "msg" | pause | resume | stop | discard
saiife box diff <id> | land <id> [--files ...] | revise <id> "comment"
saiife box gc
```
- States: `queued → starting → running ⇄ paused → done (waiting for review) → landed | discarded`.
- Every box is a v2 `session` issued by the runner. `saiife stop <session>`, limits, lockdown and approvals work unchanged (v2 §18).
- A snapshot is kept only on request (`--keep`). **[call]**

**Task model [call]:**
- Claude Code runs **interactively** in its TUI inside a PTY. `--task` is sent as the first prompt; `attach` shows the screen; `say` types a message.
- The box enters `done` when the in-box Claude Code Stop hook reports "turn finished" and the agent is idle for 30 s, or when the user runs `saiife box done <id>`.
- **A box can land several times.** Each review shows the diff against the last landed tree (the base moves forward), and each `land` adds one commit to `saiife/box-<id>`. `revise` puts the box back in `running`.
- The vsock protocol gets a version number from day one (`saiife-guest/1`).

### 7.8 Templates [owner intent, call on shape]
A template is the unit of "workflow", so v3 isn't wired to one person's flow:
- the agent and its start command;
- base image;
- box size;
- egress allow-list;
- which secrets (by name) the gateway may add;
- the rules profile (§10.5);
- touch classes.

Templates live in `/etc/saiife/templates.d/*.toml` (locked mode) or the user config (personal mode), **never in a project**. The first template is `claude-code`; the owner's own (saiife plans, Rust, `-j 4`) is a second.

### 7.9 Claude Code in a box
- Started by `saiife-guest` in a PTY inside the box.
- Model traffic goes through the gateway, which adds the credential. The key is never in the box.
- v2 guard hooks still run inside the box, but they are **advisory only** (the agent is root there). Real enforcement is the boundary: egress, gateway, diff review, touch, caps.
- **Login: both, per template [owner].**
  - **API key:** a vault secret. The gateway adds `x-api-key` to model calls, and the box only holds a placeholder.
  - **Claude subscription:** a long-lived token from `claude setup-token`, run on the host by the user, stored as a vault secret. The gateway puts it in the `Authorization` header, and the box only holds a placeholder.
  - The box spike (§11 step 2) checks that Claude Code in the box accepts the placeholder while the gateway swaps in the real credential, for both kinds. If a kind doesn't work that way, the fallback is to hand the token to the box, labelled in `box ls` and the audit as "credential inside box (weaker)".
  - Before shipping, check the current Anthropic terms for subscription use through a local proxy. If they don't allow it, ship API key only and say why.

### 7.10 Later platforms
The guest image and the vsock protocol stay the same; only the VMM adapter changes:
- macOS: Virtualization.framework (or libkrun/krunkit);
- Windows: Hyper-V HCS with hvsocket.

WSL2 does not count as per-box isolation.

## 8. Part C: touch approvals

### 8.1 What counts as a touch [call]
Only methods that produce a **signature the daemon (and later an auditor) can verify**:
- FIDO2 hardware key (YubiKey; YubiKey Bio for fingerprint) through the CLI over CTAP;
- WebAuthn passkey in the Workspace (phone Face ID or fingerprint);
- later: Windows Hello via `webauthn.dll`; macOS Secure Enclave key gated by biometry.

Plain fprintd, polkit and PAM answers are yes/no only, with no proof, so they **don't count** as a touch. The existing polkit reauth stays for v2 same-user approvals.

### 8.2 Touch classes (default) [owner: "only certain actions"; list is call]
| Touch needed | Just happens |
|---|---|
| `land`: a box's diff onto the real repo | editing, tests, builds inside the box |
| `push_protected`: push or merge to main or protected branches | Docker, packages, root inside the box |
| `deploy` | gateway calls to allow-listed hosts without a sensitive secret |
| `secret:sensitive`: gateway use of a secret marked sensitive | spawning from a no-secret template |
| `egress:external`: a gateway call to a host marked "real system" (prod DB, real server) | stop, pause, lockdown on |

**Who does it [call]:**
- `land`: the CLI on the host (§5.1).
- `push_protected`: `saiife box push <id>` runs `git push` on the host as the user, with the user's own git credentials, after the daemon has verified the touch. The touch digest names the remote, the ref and the commit hash.
- Opening a PR or merging: through a v2 connector (GitHub) if one is configured, else not offered.
- `deploy`: in v3.0 it is only a mark on a connector op (`deploy = true` in its policy). saiife has no deploy runner of its own.

"Reaching outside" is defined by marks the user sets on hosts and secrets, not guessed, so it doesn't spread into every gateway call (approval fatigue). Templates can add classes; nothing can remove `land`.

### 8.3 Binding the touch to the action
- `challenge = SHA-256("saiife-touch-v1" ‖ daemon_instance_id ‖ request_id ‖ nonce(32 B, single-use) ‖ expiry ‖ action_digest)`.
- `action_digest` is canonical JSON of the action, e.g. repo, base commit, target ref and diff SHA-256, or service, op, body hash and env.
- The daemon verifies:
  - the signature against the enrolled public key;
  - rpIdHash and origin (web), challenge equality;
  - UP, and UV for `land`, `deploy` and `secret:sensitive`;
  - expiry, then burns the nonce;
  - a non-decreasing signCount (0 tolerated for synced passkeys).
- Verification is about 300 lines on `ring`, plus a small CBOR/COSE parse at enrolment. No `webauthn-rs` (it pulls in openssl). **[call]**
- Screens show the action, the diff stats and a short code derived from the challenge.

### 8.4 Enrolment and recovery
- `saiife touch enrol` runs at the machine (root or a local approver). The first device needs host access, and each later one needs a touch from an existing device.
- Recommend 2 devices, e.g. key plus phone. **[call]**
- Enrolment and removal are signed audit records.
- No touch device reachable: refuse with `touch_unavailable`. **Never** fall back to a password.

### 8.5 Code
`reauth::Reauth` in `crates/daemon/src/reauth.rs` is the seam:
- add a `Touch` verifier that returns evidence, not a bool;
- `approvers::may_decide` gets `touch_required`;
- approval records gain a `touch` field: cred id, device label, flags, signCount, authenticatorData, clientDataJSON, signature, challenge preimage, `via: local|web`;
- new refusals `touch_failed`, `touch_unavailable`, `touch_mismatch`.

### 8.6 Timeouts
- 120 s per prompt, challenge valid 5 min. The request timeout stays as in v2.
- Timeout, error or the wrong device all mean deny.
- The existing cooldown backoff limits prompt floods.

## 9. Part D: web Workspace

### 9.1 Where it lives
A "Workspace" mode in app.saiife.com (Next.js frontend, FastAPI backend in `../saiife.com`), as in `../IDEAS-workspace.md`:
- header of app icons;
- brand glow;
- the normal dashboard stays as it is.

A localhost UI served by the daemon uses the same signed protocol. It is free and works offline. **[call]**

**Repos [call]:** the Workspace UI goes in `../saiife.com` (it already has passkeys through `py_webauthn`). The sealed-frame relay is new and goes in `../saiife-hub`, next to its `installs` registry, following the `../saiife-cloud` relay principle; nothing of it exists yet. The same hard rules and build-agent workflow apply in those repos. v3.0 ships **without billing gates**; §9.7 is the intended split for later.

### 9.2 Connection [call]
- An unprivileged `saiife-link` process keeps an outbound WSS connection (port 443) to the hub. The hub routes **sealed frames by machine id**: it can't read, forge or replay them. Same principle as the saiife-cloud relay design.
- **Pairing at the machine:**
  1. `saiife workspace pair` shows a QR code carrying the daemon's public key and a one-time secret in the URL fragment, which never reaches the server.
  2. The browser enrols a non-extractable WebCrypto key and its WebAuthn credential.
  3. The user compares a short code on both screens.
- Every command is a canonical frame (machine id, action, args, nonce, expiry) signed by an enrolled browser key and checked by the daemon. Hub account recovery can never add a device.

### 9.3 Phone features: first version **[owner: overview, change, revise; list is call]**
1. **Overview:** boxes, state, task, run time, machine load and free slots.
2. **Review:** changed files, diff, test results. Approve (touch), Reject, or Revise with a comment.
3. **Steer:** message the agent, pause, stop, reorder the queue.
4. **Approve inbox:** all pending touches in one list.
5. **Spawn:** template, repo, task, then start or queue.

### 9.4 Streams
- Terminal: the guest PTY goes over vsock to the daemon, which sends sealed snapshot + delta frames (xterm headless, as in `../localflow/src/main/terminal-screen.ts`). The view is read-only by default.
- Sessions are recorded as asciicast v2.
- The diff is computed by the host and rendered with diff2html or Monaco.
- The terminal is sandboxed: no OSC 52, no OSC 8 links, no action buttons inside the stream.
- App links in v3.0 open only on the machine (or over the user's own Tailscale). A hub proxy would break the end-to-end encryption.

### 9.5 Access levels [call, D5]
| Level | Actions |
|---|---|
| Signed browser key | view status, streams, logs, diffs; stop, pause, cancel or reorder; lockdown **on** |
| + touch (UV) | approve asks; spawn with secrets or egress; push, merge, PR; type into an agent (time-boxed); expose an app link |
| Machine only | policy, config, vault, connectors, egress; enrol or remove devices; lockdown **off**; raise caps; uninstall; anything about the audit |

Rule: anything that only **takes power away** is safe remotely.

### 9.6 Amendment to v2 §6.10.3 (signed off by the owner, 2026-11-10)
v2 says notifications never carry an approve link and approval happens on the machine. v3 changes it to: approval happens on the machine **or with a touch signature bound to the action**, verified by the daemon. Notifications still never carry a one-click approve link.

### 9.7 Free vs Pro [call, rough]
- Free: localhost UI, one paired machine, status, touch approvals. Safety features are never behind the paywall.
- Pro: several machines, live remote streams (the relay bandwidth cost), phone spawn, push, history.

## 10. Part E: never-rules become enforced policy

### 10.1 What it does
"Please don't" becomes "can't":
1. `saiife rules import CLAUDE.md` (also `AGENTS.md`, `GEMINI.md`, rules files) finds the "never / don't / must not / no" lines.
2. It proposes a concrete rule for each one.
3. The user confirms or edits each rule in a table: source line, proposed rule, examples it blocks or allows, host-only or everywhere, enforce / ask / skip.
4. The guard enforces confirmed rules and audits every attempt, with the source line quoted as the reason.

### 10.2 Extraction [call]
- **Deterministic pass first, offline:** commands in backticks or lists become command denies; `/`, `~/` and `$VAR` paths become `deny_path`.
- Lines with no concrete target are listed as **"not enforced (judgement)"**, never hidden.
- **Optional LLM pass, opt-in:** the user's own Claude Code headless (`claude -p`), with no tools. Its output must fit a strict JSON schema of rule kinds that has **no allow**. Each rule is compiled and must come with block/allow examples (Codex execpolicy style).
- Expect about half of a typical rules file to be enforceable. On the owner's `hard-rules.md` the research found ~13 lines enforceable now, ~7 needing new rule types, the rest judgement.

### 10.3 Storage and re-sync
- A generated pack goes in `policy.d/` (locked) or the user config (personal). It is never a project file that loosens anything. Each rule carries `source = {file, line, line_sha256}`.
- saiife stores the source file's hash; `status` warns when it changes; `rules sync` shows the diff.
- New lines are only proposed. Removed lines keep their rule until the user confirms, since removing a rule loosens policy.

### 10.4 Trust
- A project `CLAUDE.md` is attacker-controllable, so an import can only **add** deny, ask or `deny_path`. An `[[allow]]` only exempts within its own pack, for `--help`-style carve-outs.
- The "host only" tag is set by the user at confirm time, never by the file text, and it never touches built-in packs.
- Show the rule count and flag overly broad patterns (a hostile file can try to block all work).

### 10.5 Box-aware rules
- Each rule gets `where = "host" | "everywhere"`, default everywhere; an unknown value fails the load, like `platform`.
- The v3 key `profile` (reserved in v2, `crates/policy/src/load.rs` ~659) selects a profile. Box profiles drop `host` rules.
- Typical host-only: docker, systemctl, sudo, pkill, writes to `/etc`.
- Typical everywhere: push, secrets, keyring, `~/.claude`.
- The active profile is part of the policy hash.
- **Inside a box [call]:** "everywhere" rules are enforced **at the boundary**, wherever there is one:
  - push and secrets at the gateway and at `land`/`push`;
  - protected paths (`~/.claude`, `.git/hooks`, rule files) at the diff review: a diff that touches one is flagged and needs a touch.
  
  A rule with no boundary check is shown as "advisory in boxes" in `rules` output and in the Workspace, never as enforced.

### 10.6 Code needed
- **Wire user-pack loading.** `load_packs_dir` exists but nothing calls it; today only built-in packs load.
- New keys: `source`, `where`, and later rule types:
  - tool-name deny (e.g. "no subagents");
  - cwd/env condition (e.g. "commit only in your worktree");
  - content scan on Write/Edit (e.g. token-shaped literals).

  `pack_raw.rs` rejects unknown keys, so each key is a schema change.
- Mind the hook budget: user packs compile on load, and the hook loads on every call. Cache the compiled packs.

## 11. Delivery order [call]

| Step | What | Rough size (agent build time) |
|---|---|---|
| 0 | Builds start at the owner's go, given after the step 1 plan is approved [call; the owner left the gate to me] | owner |
| 1 | `saiife dev` (proxy, names, certs, ls/down/gc) | 2–3 plans |
| 2 | Box spike, throwaway: one Cloud Hypervisor VM with nested Docker and vsock, measuring RAM, boot, disk | 1 day + owner smoke run |
| 3 | Boxes: image, disks, vsock gateway + CONNECT proxy, repo in / diff out, queue, CLI, templates | 4–6 plans |
| 4 | Touch: FIDO2 local, verifier, touch classes, audit fields | 2 plans |
| 5 | Never-rules: user packs, import + confirm, `where`/profiles | 2 plans |
| 6 | Workspace: link + pairing, overview, review/revise, steer, inbox, spawn, WebAuthn touch | 3–4 plans (CLI + web) |
| 7 | Codex and Gemini templates (beta) | about 1–2 days each, plus owner accounts |

The touch and never-rules steps can run in parallel with late box plans; they don't depend on the VM.

## 12. Testing

- Unit and integration tests use mocks: a Docker Engine API mock, a Cloud Hypervisor REST mock, a fake vsock (Unix socket pair), FIDO2 and WebAuthn test vectors, and loopback rcgen TLS for `saiife-link`.
- The diff importer gets an adversarial test suite: path traversal, symlinks, `.git` writes, huge files.
- Real VM, real Docker and real hardware key are **owner-run smoke scripts** (`scripts/box-smoke.sh`, `scripts/dev-smoke.sh`, `scripts/touch-smoke.sh`). Build agents never run them (hard rules).
- Red-team scenarios for v3 (box tries to reach the host, forge a diff, exhaust disk, fake terminal UI) are added to the parked 9c suite.

## 13. Open questions

- O1 (login): answered: both, per template (§7.9).
- O2 (§6.10.3 amendment): signed off (§9.6).
- O3: the Free vs Pro split (§9.7) is a rough first cut; no gates in v3.0.
- To verify in the box spike: placeholder-credential swap for both login kinds (§7.9), nested Docker performance, and Cloud Hypervisor snapshot consistency with qcow2 backing chains.

## 14. Later (out of scope for v3.0)

- **Workspace Pro view:** a trading-style multi-pane advanced terminal for power users and vibecoders. **[owner]**
- macOS and Windows boxes.
- Multi-machine fleet.
- Team approvers.
- Cloud boxes.
- App links over the end-to-end channel (service-worker proxy).
- Push notifications with end-to-end encrypted Web Push (RFC 8291).
- A tap + nftables network tier.
- Keystroke input from the phone beyond a time-boxed grant.

## 15. Honest limits

- The agent is root inside its box. In-box hooks are advisory, and the boundary is what enforces. A VMM or KVM escape bug is the residual risk: minimal devices, seccomp, Landlock and an unprivileged VMM user reduce it but don't remove it.
- Data can still leave through allowed hosts (the model API, package registries). It is audited, not prevented.
- A compromised hub frontend serves the JavaScript that draws the approve screen, so it can mislead what the user sees. The signature still binds the real pending action, and the daemon only accepts actions it created. A native app or pinned build would close this; not in v3.0.
- A synced passkey means "any of the user's synced devices", not one phone. UP proves a touch, and UV is needed to prove who.
- Root on the host can still do anything. The audit and forwarding make that visible, not impossible.
- Never-rules: only about half of a typical file is enforceable. Obfuscation and interpreters (`python -c`) can still slip past a command rule.
- No reflinks on ext4, so repo and snapshot copies are full copies.
- The owner's account is in the `docker` group, which is a root path on the host outside saiife's model. `saiife doctor` should say so.
