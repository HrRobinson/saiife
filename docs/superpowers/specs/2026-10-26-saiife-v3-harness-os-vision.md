# saiife v3: the agent harness OS (vision)

Date: 2026-10-26
Status: **vision, not a design.** Captured from an owner brainstorm. A v3 design spec and plans come later, once v2.0 has shipped. Extends v1 spec §9.4 (isolated runner) and v2 spec §18 (v3 compatibility); nothing here changes v2.

## 1. The idea

Today an AI coding agent runs **on your machine**, as you. saiife v1/v2 put a guard and an audit around it, but the agent still shares your files, network, secrets and processes.

v3 turns that around: the agent runs **inside an environment the harness fully controls**. Every process, file, network call, secret and container goes through one layer that can allow, deny, ask a human, and record. saiife becomes the **agent harness OS**: the operating layer between agents and a machine.

The same foundation also runs **people's** dev environments (§5), so humans and agents use one way to start, route, isolate and clean up environments.

## 2. Layers

| Layer | What the harness controls | Where saiife is |
|---|---|---|
| Compute | The agent runs in a sandbox (microVM, gVisor or hardened container) with resource limits, kill switch, snapshot and rollback | **New in v3** (v1 §9.4) |
| Commands and tools | Every command and tool call is checked before it runs | v1 guard; v2 managed hooks, MCP gateway (v2.x) |
| Network | Egress denied by default; only the gateway and allow-listed hosts | v2 gateway; v3 adds sandbox egress rules (v2 §18) |
| Secrets | Keys never enter the sandbox; calls are brokered by name | v2 vault + gateway |
| Files | Workspace mounted copy-on-write; the human reviews the diff before it lands on the real tree | **New in v3** |
| Humans | Approvals, notifications, lockdown | v2 plan 11 |
| Record | Signed, hash-chained audit a non-developer can read | v2 audit |
| Environments | Start, name, route and clean up dev stacks (containers, proxy, certificates) | **New in v3**, first slice (§5) |

Most layers are already designed or built. **The missing core is compute** (and the file and environment layers that sit on it).

## 3. Why this matters

- **Agents that can really work.** Today agents are kept away from Docker, `sudo`, process control and real test stacks because they run on the host (the owner's rule after the 2026-10-22 `pkill` crash, plus harness classifiers). Inside a sandbox they can build, run containers and run integration tests safely, and the harness still sees and records everything.
- **Safe runs** (brand direction): "let AI touch production, contained and on the record" needs a contained place for the agent to work before anything lands.
- **Local and under your own policy.** The agent-sandbox market (E2B, Daytona, Modal, Northflank, Vercel Sandbox, Cloudflare Sandboxes; open source: Alibaba OpenSandbox) is mostly cloud-hosted. Hosted harnesses (Anthropic Managed Agents, Codex cloud) run in the vendor's cloud. Local CLIs (Claude Code, Codex CLI, Gemini CLI) are harnesses but run on the host. saiife's opening: **local sandboxes, your policy, signed audit**. This is a hypothesis to validate, not a claim.

## 4. Principles (carried from v1 §1.2, sharpened)

1. **Fail closed.** If the harness can't decide, the action is blocked (as v2 locked mode).
2. **The agent never holds what it must not misuse.** Secrets, policy, audit and the saiife binary stay outside the sandbox.
3. **Real isolation, not just containers.** Plain containers share the host kernel and are not enough for untrusted agent code. Default to microVM (e.g. Firecracker) or gVisor; a hardened rootless container is a fallback tier, labelled as weaker.
4. **Nothing lands without a record**, and the record outlives the sandbox.
5. **Clean by design.** Everything the harness creates carries an ownership label, and cleanup only touches what it owns. Data (volumes) is deleted only after an explicit confirmation.
6. **Honest limits.** Each isolation tier states what it does and doesn't protect against (as the honest-limits docs do for v1/v2).

## 5. First slice: `saiife dev` (environments)

A concrete, useful slice that builds the environment and container foundation the runner needs, and solves a real problem today: several dev stacks on one machine fight over ports (3000, 3001, 8000) and leave networks, containers and volumes behind.

- **One proxy owns ports 80/443** (e.g. Traefik). No project binds host ports.
- **Names instead of ports:** `<service>.<project>.localhost` (e.g. `app.saiife.localhost`); a second copy of a repo gets its folder name in the host (`app.saiife-pr2.localhost`). `*.localhost` resolves to the machine, so no DNS setup.
- **Works on any repo with zero edits:** `saiife dev up` reads `docker compose config`, writes an override outside the repo (`ports: !reset []`, shared proxy network, routing labels) and starts the stack. Needed for repos you don't own (e.g. work repos).
- **HTTPS automatically:** per-project mkcert certificates, stored centrally, loaded by the proxy.
- **Housekeeping:** `saiife dev ls` (all environments, URLs, state, last used, disk use), `saiife dev down <project>`, `saiife dev gc` (stopped environments, unused networks, dangling images; only `saiife.managed` resources; volumes only after confirmation; optional idle-stop after N days).
- **Per-project quirks** (e.g. an app that serves its own HTTPS) go in `~/.config/saiife/dev/<project>.toml`, not in the repo.
- A shell prototype exists: `dcu` (port pre-flight check before `docker compose up`) on the owner's machine.

Prior art for this slice (honest): DDEV and Lando (Traefik + project hostnames; popular with PHP), nginx-proxy, Docksal, OrbStack's `*.orb.local` (macOS only). The slice is not new on its own; what is less common is zero-edit use on any repo, ownership-based cleanup, and sharing one foundation with the agent sandbox and saiife's guard and audit.

## 6. The runner (compute, files)

Builds on §5 and v2 §18:

- `saiife run-agent <agent> --profile <name>` starts the agent in a sandbox: project mounted copy-on-write, explicit read-only paths, `gateway.sock` as the only route out, resource limits, `saiife stop <session>`.
- **Snapshots and rollback** of the sandbox; **diff review** before changes land on the real tree (approve, reject, or approve parts).
- **Agents can run environments inside the sandbox** (nested `saiife dev` / container runtime inside the microVM), so integration tests and Docker builds become safe.
- Every action is attributed to the runner-issued `session` (v2 §18) and lands in the audit chain.
- Profiles (`[[scope]]` → `profile`, reserved in v2) define what each agent role may do.

## 7. Language and code layout

Rust, in the saiife workspace, so environment control (Docker API via e.g. `bollard`, networks, labels, cleanup) is one crate shared by `saiife dev` and the runner. Go is the norm for Docker tooling; Rust is chosen for reuse with saiife, not because the problem requires it.

## 8. Open questions

1. First real use: what is the agent doing inside the sandbox, and what does the owner want to see or approve before its work touches the real machine? (asked 2026-10-26, unanswered)
2. Isolation tier per platform: Firecracker needs KVM (Linux); macOS needs a VM (Apple Virtualization framework). What is the minimum acceptable tier, and is a container-only tier ever offered?
3. Does `saiife dev` ship before v3 as its own small release (useful alone), or only as part of v3?
4. How do the local sandbox and the hub relate (fleet view of sessions, remote approvals)?
5. Cost: microVM images, cold start, disk use per sandbox; cleanup policy defaults.

## 9. Order (proposal)

1. Ship v2.0 (plans 9c–12). The 9c red-team suite is parked and blocks 0.2.0.
2. `saiife dev` slice (environments, proxy, cleanup): small, useful alone, builds the container foundation.
3. v3 design spec for the runner (compute, files, profiles), then plans.
