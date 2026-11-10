# Plan 24: `saiife dev up|ls|down|gc|ca`, the commands: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife dev` as the user runs it. `up` starts any compose repo behind the shared proxy with `https://<service>.<project>.localhost` names and no repo edit. `ls` shows every environment. `down` and `gc` clean up only what saiife labelled, and delete volumes only after a yes. `ca` prints where the local CA is and how to trust it.

**Architecture:**
- **The CLI only composes.** Every Docker, compose, route, cert and proxy step is a `saiife-dev` function from plans 22 and 23 (`crates/dev`). `crates/cli/src/dev_cmd.rs` parses the subcommand, orders the steps, owns the project files the CLI writes (`compose.json`, `urls.json`), asks for confirmations and prints. Every function takes `&dyn Docker` and `&DevPaths`. `run` builds them once from the environment (`DockerCli::from_env`, `DevPaths::from_env`).
- **Tests run the real binary against a fake `docker`.** The test writes a shell script into its tempdir, points `SAIIFE_DOCKER` at it, and sets `XDG_STATE_HOME`, `XDG_CONFIG_HOME`, `HOME` and `PATH` to tempdirs. The script logs each argv to a file and answers with canned stdout and an exit code chosen by glob rules. Pure helpers (state classification, `docker ps` parsing, the confirm prompt) are unit tests inside `dev_cmd`.
- **Cleanup selects by label, always.** Each listing that leads to a removal filters on `label=saiife.managed=true`. Network cleanup is `docker network prune` with that filter **and** `label=saiife.dev.project` (key present), so the shared `saiife-dev` network, which has no project label, is never pruned. Volumes go only through `docker volume rm` of names a labelled listing returned, after a yes.
- **The proxy and the shared network are plan 23's.** They carry `saiife.managed=true` and `saiife.dev.role=proxy|network` (`proxy::ROLE`) and **no** `saiife.dev.project`. `down`, `gc` and `ls` never select, list as a project, or remove them directly. Only `proxy::stop_proxy_if_unused` removes the proxy; the network stays (the next `up`'s `ensure_network` reuses it).

**Tech Stack:** Rust, `clap` 4 (derive), `serde_json`, `time` (RFC 3339), all already in `crates/cli`. One new path dependency: `saiife-dev = { path = "../dev" }`. No new crates. POSIX sh for the fake `docker` and for `scripts/dev-smoke.sh`.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5.1 (the CLI uses Docker as the user, never the daemon) and §6; vision §5 (`git show pr15:docs/superpowers/specs/2026-10-26-saiife-v3-harness-os-vision.md`). **Binding over both:** the shared contract for plans 22, 23 and 24 (`v3-step1-dev-contract.md`, copied into plan 22's header). Spec §6 already agrees with it (rcgen CA, `docker` CLI subprocesses, a fake `docker` executable).

## Contract changes

Each one is small. Items 1 and 3 are already taken up by plans 22 and 23.

1. **Plan 22, `project.rs`: `pub fn save(paths: &DevPaths, s: &ProjectState) -> Result<(), DevError>`** (atomic) and `load`, `check_name`. Plan 22 provides them (its "Contract changes" table), and `ProjectState` derives `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`. `up` needs `save` to set `last_up`.
2. **The `up` argv gains `--project-directory <DIR>`**: `docker compose -p saiife-<p> --project-directory <DIR> -f <state>/projects/<p>/compose.json up -d`. `docker compose config` already makes paths absolute. This flag makes any path it left relative resolve against the repo, not against the state dir. All `down` calls use the same `-p`, `--project-directory` and `-f`.
3. **Plan 23: no shared TLS file.** Plan 23 writes each project's certificate entry into that project's own `dynamic/<project>.toml` and writes **no** shared TLS file. The name `_tls.toml` stays reserved as `proxy::TLS_FILE` (`_` is never in a project name). Nothing in this plan expects, reads or writes a shared TLS file. Plan 24's `gc` only ever removes `dynamic/<name>.toml` where `<name>` is a valid project name, so `_tls.toml` is never touched if it ever appears.
4. **`down` gains `--yes`**: `down <PROJECT> [--volumes] [--yes]`, because volumes need a yes and a script has no terminal.
5. **Two files the CLI owns in `<state>/projects/<p>/`**: `compose.json` (the contract's) and `urls.json` (new: a JSON array of `https://...` strings, written by `up`, read by `ls`). Plan 22's `project::list` must read only `project.json` and ignore the other files.
6. **One file outside the contract's list:** `README.md` gains one bullet linking `docs/dev.md` (Task 6).

## Decisions

- **P1. Order in `up`:** read compose first, then assign the project. The brief listed "assign" first, but a folder with no compose file would then leave project state behind. `read_config` needs no project name, so this order costs nothing.
- **P2. Disk use is not in `ls`.** `docker system df -v` and `docker ps --size` both walk layers and volumes, which takes seconds on a busy host and runs on every `ls`. It is not cheap, so it is left out. The JSON has no `disk` field (not `null`), so adding one later breaks nothing. Follow-up: `ls --disk`.
- **P3. States**, from the project's labelled containers and its folder:

| containers (labelled, this project) | folder exists | state |
|---|---|---|
| all running (≥ 1) | any | `running` |
| some running | any | `partial` |
| none running, or none at all | yes | `stopped` |
| none running, or none at all | no, or no state (orphan) | `missing` |
| `docker ps` failed | any | `unknown` |

  `paused`, `restarting` and `created` count as not running.
- **P4. `gc` removes a stopped project's labelled containers and route file but keeps its state dir while its folder still exists**, so its name (and `-N` suffix, and URLs) stay stable. A **missing** project (folder gone) loses its state dir too (`project.json`, `compose.json`, `urls.json`). Partial and running projects are kept and named in the output. (Settled by the orchestrator on 2026-11-10: stable URLs beat a clean `ls`; `ls` shows such projects as `stopped`.)
- **P5. `down` keeps the project state**, so `ls` shows the project as `stopped` and a later `up` keeps its name.
- **P6. Anonymous volumes are never removed.** `compose down` runs without `--volumes`. Volumes go only through a labelled `docker volume ls` and then `docker volume rm`. The docs say anonymous volumes stay behind for `docker volume prune`.
- **P7. Foreign containers stop `down`.** If a container carries `com.docker.compose.project=saiife-<p>` but not `saiife.managed=true`, `down` refuses and touches nothing (Review Focus 2).
- **P8. `ca` creates the CA if it is missing** (`ensure_ca`, in saiife's own state, never a trust store), then prints the path and the trust steps for this OS only. `docs/dev.md` has all three OSes.
- **P9. `compose.json` is private.** It holds the interpolated model, which can include values from `.env`. Mode `0600` in a `0700` dir on Unix.
- **P10. Exit codes:** 0 done; 1 error (including a refused confirmation, and `ls` when `docker ps` failed, after printing what it could); 2 usage (clap).

## Consumes (verify at build time)

From `saiife-dev`, exactly as the contract names them:
- `docker::{Docker, DockerCli::from_env, run_ok, Output}`; `paths::DevPaths::{from_env, project_dir, proxy_dir, ca_dir, compose_file, project_file, quirks_file}` and fields `state`, `config`;
- `labels::{MANAGED, PROJECT, NETWORK, PROXY_CONTAINER, compose_project}`;
- `project::{ProjectState, dns_label, check_name, assign, list, load, save}`;
- `compose::{read_config, ComposeModel, ServiceInfo}`; `quirks::{load, Quirks}`; `rewrite::{rewrite, Rewritten, Route}` (`Route.host` is the full host `web.shop.localhost`; `Route.upstream` the full URL);
- `certs::{ensure_ca, ensure_project_cert, Ca, CertPaths}`;
- `proxy::{preflight_ports, ensure_network, ensure_proxy, write_routes, remove_routes, stop_proxy_if_unused, ROLE, TLS_FILE}`;
- `DevError` (`Display` gives a sentence with the fix; the CLI adds only the `saiife dev: ` prefix). Plan 24 adds **no** `DevError` variant: CLI errors are `String`s (`Res`).

This plan does not use `FakeDocker`: the unit tests in `dev_cmd` are pure, and the integration tests use the fake `docker` script. So `crates/cli` needs no `saiife-dev` dev-dependency and no `fake` feature. If a later unit test wants `FakeDocker`, add `[dev-dependencies] saiife-dev = { path = "../dev", features = ["fake"] }` and use plan 22's API (`new`, `on`, `once`, `calls`; unscripted = status 125).

**Every `docker` argv the fake must answer** (from plans 22 and 23; `$*` as the fake logs it, so `{{...}}` is literal). `base_rules()` holds the rows marked *rule*, in this order; the rest fall through to the default `*)` (exit 0, no output):

| From | argv (`$*`) | `base_rules()` answer |
|---|---|---|
| 22 `compose::read_config` | `compose --project-directory <dir> -f <dir>/compose.yaml [-f <override>] config --format json` | *rule* `*config --format json*`: `MODEL` |
| 23 `preflight_ports` | `ps --filter label=saiife.managed=true --filter label=saiife.dev.role=proxy --format {{.Names}}` | default (empty: no proxy) |
| 23 `preflight_ports` | `ps --filter publish=80 --format {{.Names}}`, same with `443` | default (empty: no holder) |
| 23 `ensure_network` | `network inspect saiife-dev --format {{json .Labels}}` | *rule* `network inspect saiife-dev*`: `{"saiife.managed":"true","saiife.dev.role":"network"}` (empty stdout is not JSON, so this needs a rule) |
| 23 `ensure_network` | `network create --driver bridge --label saiife.managed=true --label saiife.dev.role=network saiife-dev` | default (only called when inspect says not found) |
| 23 `ensure_proxy`, `stop_proxy_if_unused` | `container inspect saiife-dev-proxy` | *rule* `container inspect saiife-dev-proxy*`: exit 1, stderr `Error: No such container: saiife-dev-proxy` |
| 23 `ensure_proxy` | `run -d --name saiife-dev-proxy --network saiife-dev ... traefik:v3.7.16 --providers.file.directory=/saiife/dynamic ...` | *rule* `run -d --name saiife-dev-proxy *`: `0123456789ab` |
| 23 `ensure_proxy` | `start saiife-dev-proxy`, `rm -f saiife-dev-proxy` | default |
| 24 `up` | `compose -p saiife-<p> --project-directory <dir> -f <state>/saiife/dev/projects/<p>/compose.json up -d` | default |
| 24 `down` | the same prefix, then `down` | default |
| 24 `ls`, `gc` | `ps -a --filter label=saiife.managed=true --format <PS_FORMAT>` | default (tests add their own) |
| 24 `down` | `ps -a --filter label=com.docker.compose.project=saiife-<p> --format {{.Names}}\t{{.Label "saiife.managed"}}`; `ps -aq --filter label=saiife.managed=true --filter label=saiife.dev.project=<p>`; `rm [-f] <ids>`; `network ls -q <same filters>`; `network rm <ids>` | default |
| 24 `down`, `gc` | `volume ls -q --filter label=saiife.managed=true [--filter label=saiife.dev.project=<p>] [--filter dangling=true]`; `volume rm <names>` | default |
| 24 `gc` | `network prune -f --filter label=saiife.managed=true --filter label=saiife.dev.project` | default |

Write the fake and `base_rules()` from this table up front. At build time, check it against `crates/dev/src/{compose,proxy}.rs` (certs issue no docker call) and fix any drift in the table and the rules together.

**The host port probe:** the harness sets `SAIIFE_DEV_SKIP_PORT_BIND=1` (plan 23's seam, read only in debug builds; `cargo test` builds the binary in the debug profile). The probe then answers "unknown" without binding, and `preflight_ports` falls through to the `ps --filter publish=` rows above, which the fake answers. No `up` test skips.

## Global Constraints

- **Hard rules** (`.superpowers/sdd/hard-rules.md`) bind every executor: no docker ever, not even `docker --version`. No network. `TMPDIR` and `SAIIFE_TEST_TMP` go under `mktemp -d -p /home/jonas/projects/personal/saiife`. Use `CARGO_INCREMENTAL=0`, `-j 4` and `-- --test-threads=4`. Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` before each commit. Never commit `.superpowers/`.
- **`scripts/dev-smoke.sh` is owner-run only.** Executors check it with `bash -n`, and with `shellcheck` if it is installed (never through docker).
- **The repo is never written.** Every file the CLI writes is under `DevPaths.state`. The CLI writes nothing under `DevPaths.config`: quirks are the user's.
- **Label strings come from `saiife_dev::labels`** (and `saiife_dev::proxy::ROLE`), never as literals in `crates/cli/src`.
- **Every removal is preceded by a listing filtered on `label=<MANAGED>=true`**, or is `docker network prune -f --filter label=<MANAGED>=true --filter label=<PROJECT>`. A project name is checked with `valid_project` before it reaches a path or an argv. The proxy container is removed only by `proxy::stop_proxy_if_unused`; the shared network never.
- **Errors:** one line on stderr, `saiife dev: <sentence with the fix>`, exit 1. Text from Docker, folder names and project names from `docker ps` go through `crate::text::sanitize` before printing. Stdout goes through `out!` and `outln!` (`crates/cli/src/out.rs`).
- **Platforms:** `crates/cli` compiles on Linux, macOS and Windows (`bash scripts/check-windows.sh -p saiife`). `Cmd::Dev` returns `None` in `windows_refusal`. The tests that run the fake script are `#[cfg(unix)]`, and the docs test runs everywhere.
- **Fixed argv and copy** (tests pin these):
  - `PS_FORMAT = "{{.ID}}\t{{.Names}}\t{{.Label \"<PROJECT>\"}}\t{{.State}}"` (with `PROJECT` from `labels`), used as `docker ps -a --filter label=saiife.managed=true --format <PS_FORMAT>`;
  - up: `compose -p saiife-<p> --project-directory <DIR> -f <state>/projects/<p>/compose.json up -d`;
  - down: the same prefix, then `down`;
  - the `gc` image line, verbatim: `Dangling images are not touched: saiife removes only what it labelled saiife.managed=true. docker image prune removes them.`

## Review Focus

1. **A project argument that is not a project name** (`down ../../etc`, `down Shop`, `down ''`, `down tls/../x`). Expected: refused before any path join or docker call: `saiife dev: <name> is not a saiife dev project name. saiife dev ls lists them.`, exit 1, and the fake log is empty (Task 4: `down_rejects_a_bad_name`).
2. **Containers saiife did not create, in reach of a cleanup.** Examples: a user's own container in compose project `saiife-shop`, or an unlabelled stopped container, network or volume on the host. Expected: `down` refuses (P7). `gc` never names them in any `rm`, because every removal argv came from a labelled listing (Task 4: `down_refuses_foreign_containers`; Task 5: `gc_removes_only_labelled`, which checks the fake log line by line).
3. **Volume deletion with no terminal** (a script, CI, `| cat`) and no `--yes`. Expected: `saiife dev: deleting volumes needs a yes. Run it in a terminal, or add --yes.`, exit 1, and no `volume rm` in the log. `down` also stops before `compose down`, so nothing is half done (Task 4: `down_volumes_without_yes_deletes_nothing`; Task 5: `gc_volumes_without_yes_deletes_nothing`).
4. **Secrets from `.env` in the saved model.** Expected: `compose.json` is mode `0600` in a `0700` dir (Task 2: `compose_json_is_private`).
5. **A read-only repo, and a repo that must stay untouched.** Expected: `up` succeeds with the repo dir at mode `0555`, and the repo's file list and mtimes are the same before and after (Task 2: `up_never_writes_the_repo`).

Also covered: `compose up` fails, so no route file is written and compose's stderr is shown (Task 2: `failed_compose_up_writes_no_routes`). Docker is missing (Task 1: `no_docker_is_a_plain_error`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (wiring, `ca`, the fake `docker`).
- **Wave 2 (parallel):** Task 2 (`up`, `dev_cmd/up.rs`), Task 3 (`ls`, `dev_cmd/inventory.rs`), Task 4 (`down`, `dev_cmd/remove.rs`).
- **Wave 3:** Task 5 (`gc`; needs 3 and 4). Task 6 (docs and smoke script) runs alongside it.
- **Last:** the gates, a whole-branch review, one fix wave, push, PR. The owner merges.

**Shared files:** `crates/cli/tests/dev_cmd.rs`, where each task appends its own tests below Task 1's harness. A rebase conflict there is append-only. Only Task 1 touches `crates/cli/src/dev_cmd.rs` dispatch: it wires every arm to a stub that later tasks replace in their own module file.

---

### Task 1: wiring, `saiife dev ca`, and the fake `docker` (size S)

**Files:**
- Create `crates/cli/src/dev_cmd.rs`, plus stub files `crates/cli/src/dev_cmd/{up,inventory,remove}.rs`;
- Modify `crates/cli/src/main.rs` (`mod dev_cmd;`, `Cmd::Dev`, the early dispatch next to `Cmd::Env`, the `windows_refusal` list, and the `unreachable!("handled above")` arm), `crates/cli/Cargo.toml` (`saiife-dev = { path = "../dev" }` under `[dependencies]`);
- Test: `crates/cli/tests/dev_cmd.rs`.

**Interfaces (Produces):**
- `main.rs`: `/// Local dev environments: compose stacks behind one HTTPS proxy (preview).` `Dev { #[command(subcommand)] action: dev_cmd::DevAction }`.
- `dev_cmd.rs`:
  - `#[derive(Subcommand)] pub enum DevAction { Up { dir: Option<PathBuf> }, Ls { #[arg(long)] json: bool }, Down { project: String, #[arg(long)] volumes: bool, #[arg(long)] yes: bool }, Gc { #[arg(long)] volumes: bool, #[arg(long)] yes: bool }, Ca }`, with one doc line each, used as clap help;
  - `pub fn run(action: DevAction) -> ExitCode`: builds `DevPaths` (and for every action except `Ca`, `DockerCli`). It calls `up::up`, `inventory::ls`, `remove::down`, `remove::gc` or `ca`. An `Err(msg)` prints `saiife dev: {msg}` on stderr and exits 1;
  - `pub(crate) type Res = Result<(), String>`; a `DevError` becomes the message with `.map_err(|e| e.to_string())`;
  - `pub(crate) fn valid_project(name: &str) -> bool`: `saiife_dev::project::check_name(name).is_ok()` (one rule, plan 22's);
  - `pub(crate) fn confirm_with(question: &str, yes: bool, tty: bool, input: &mut dyn BufRead) -> Result<bool, String>`. With `yes`, `Ok(true)`. With no tty, `Err("deleting volumes needs a yes. Run it in a terminal, or add --yes.")`. Otherwise it prints `{question} [y/N] ` on stderr and reads a line: `y` or `yes` (any case, trimmed) gives `true`; anything else, or EOF, gives `false`. `pub(crate) fn confirm(question, yes)` wraps it with `stdin().is_terminal()` and the locked stdin;
  - `pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()>`: creates the parent dir if missing, and on Unix sets it to `0700` even when it exists (`project::assign` creates the project dir with the default mode); writes `<path>.tmp` with mode `0600` at open, then renames it over `path`;
  - `fn ca(paths: &DevPaths) -> Res`: `ensure_ca`, then the copy below.
- Stubs `up::up(d: &dyn Docker, paths: &DevPaths, dir: Option<&Path>) -> Res`, `inventory::ls(d, paths, json: bool) -> ExitCode`, `remove::down(d, paths, project: &str, volumes: bool, yes: bool) -> Res`, `remove::gc(d, paths, volumes: bool, yes: bool) -> Res` return `Err("not built yet".into())` (or exit 1) until their task.
- `ca` copy, verbatim. `{cert}` is `Ca.cert_path`, `{key}` is `Ca.key_path` and `{dir}` is `paths.ca_dir()`, all sanitized. Only the block for the OS it was built for is printed (`cfg!(target_os)`):

```
saiife dev CA certificate: {cert}
saiife never adds it to a trust store. To trust it yourself:
```
  - Linux:
```
  Debian, Ubuntu:   sudo cp {cert} /usr/local/share/ca-certificates/saiife-dev.crt && sudo update-ca-certificates
  Fedora, Arch:     sudo trust anchor --store {cert}
  Chrome, Chromium: certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n saiife-dev -i {cert}
  Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```
  - macOS:
```
  System:           sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert}
  Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```
  - Windows:
```
  Current user:     certutil -user -addstore Root {cert}
  Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```
  - All:
```
Node and Python keep their own lists: set NODE_EXTRA_CA_CERTS, SSL_CERT_FILE or REQUESTS_CA_BUNDLE to {cert}.
Keep {key} private: anyone who has it can make certificates this machine trusts.
To stop trusting it, remove it the same way and delete {dir}.
```

**Test harness** (top of `crates/cli/tests/dev_cmd.rs`; `mod common;` for `tmp::short_tempdir` and `set_profile`):
- `struct Dev { root: TempDir, repo_parent: PathBuf, state: PathBuf, config: PathBuf, log: PathBuf, docker: PathBuf }`. `Dev::new(rules: &[Rule])` creates `home/`, `state/`, `config/`, `bin/` (empty, used as `PATH`) and `fake/` under one short tempdir, and writes the fake.
- `struct Rule { glob: &'static str, stdout: String, code: i32 }`, with `Rule::ok(glob, stdout)` and `Rule::fail(glob, code, stderr)`. The fake script is `#!/bin/sh`, then `PATH=/usr/bin:/bin`. It appends `"$*"` to `$log` (one line per call), then runs a `case "$*" in` with one arm per rule, in order. Each arm `cat`s that rule's reply file (`fake/rN.out` to stdout, `fake/rN.err` to stderr) and exits with its code. The last arm `*)` exits 0 silently. Tests use the rules after `base_rules()`, so a test's own rules win.
- `fn base_rules() -> Vec<Rule>`: the *rule* rows of the argv table above, in that order.
- `fn saiife(&self, args: &[&str], dir: &Path) -> Output`: runs `CARGO_BIN_EXE_saiife` in `dir` with `env_clear()`, then `PATH=<bin>`, `SAIIFE_DOCKER=<docker>`, `SAIIFE_DEV_SKIP_PORT_BIND=1`, `XDG_STATE_HOME=<state>`, `XDG_CONFIG_HOME=<config>`, `XDG_RUNTIME_DIR=<home>/no-runtime`, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` under `root`, `set_profile(home)`, and stdin null. `fn saiife_with_stdin(&self, args, dir, input: &str) -> Output`.
- `fn calls(&self) -> Vec<String>` (the log's lines); `fn repo(&self, name: &str, files: &[(&str, &str)]) -> PathBuf` (a folder `repo_parent/<n>/<name>`, with a fresh `<n>` per call so two repos can share a folder name). A repo that `up` runs on must hold a `compose.yaml` (any content): plan 22's `read_config` looks for the file itself and fails with `NoComposeFile`, with no docker call, when there is none. Paths in log assertions use the canonicalized repo path.
- `const MODEL: &str`, the `docker compose config --format json` output for services `web` (`ports: [{target: 80, published: "8080", protocol: "tcp"}]`) and `worker` (no ports, no expose), with `name: "shop"`. The test answers `*config --format json*` with it.

- [ ] **Step 1: failing tests:**
  - unit tests in `dev_cmd.rs`: `confirm_yes_flag_skips_the_prompt`; `confirm_without_tty_is_an_error` (the exact text above); `confirm_reads_y_and_yes_only` (`"y\n"` and `" YES \n"` give true; `"n\n"`, `"\n"`, `"yep\n"` and EOF give false); `valid_project_rejects_paths_and_case` (`"shop"` and `"shop-2"` pass; `"../x"`, `"Shop"`, `""`, `"a/b"` and `"_tls"` fail); `write_private_sets_modes` (unix: file `0600`, new parent `0700`);
  - `crates/cli/tests/dev_cmd.rs`: `dev_help_lists_the_five_commands` (`saiife dev --help` names up, ls, down, gc and ca; runs on every OS, no fake); `ca_prints_the_path_and_the_linux_steps` (`#[cfg(target_os = "linux")]`): stdout has `saiife dev CA certificate: <state>/saiife/dev/`, `update-ca-certificates`, `trust anchor --store`, `certutil -d sql:$HOME/.pki/nssdb` and `saiife never adds it to a trust store`, the cert file exists under `<state>`, and nothing was written under `<home>` except what the test created; `no_docker_is_a_plain_error` (unix: `SAIIFE_DOCKER` unset and an empty `PATH`; `dev ls` exits 1 and stderr is one line starting `saiife dev: ` that names `docker`).
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd` and `cargo test -p saiife dev_cmd`; expect FAIL.
- [ ] **Step 3:** implement. `ca` must not build a `DockerCli`, so it works without Docker installed.
- [ ] **Step 4:** the tests pass; `bash scripts/check-windows.sh -p saiife` is clean; `cargo tree -e normal -p saiife-guard` is unchanged.
- [ ] **Step 5:** commit `feat(cli): saiife dev wiring and dev ca (trust steps, never a trust store)`.

### Task 2: `saiife dev up [DIR]` (size M)

**Files:** `crates/cli/src/dev_cmd/up.rs`; tests appended to `crates/cli/tests/dev_cmd.rs`.

**Interfaces:**
- Consumes Task 1's `Res`, `write_private`; all of plan 22 and 23's `up` functions.
- Produces `pub(crate) fn up(d: &dyn Docker, paths: &DevPaths, dir: Option<&Path>) -> Res`. Order (P1):
  1. `dir` (default: the cwd), canonicalized. If it is missing or not a folder: `Err("<dir> is not a folder. Pass the folder that holds the compose file.")`;
  2. `compose::read_config(d, &dir)`;
  3. `project::assign(paths, &dir)`; `quirks::load(paths, &p.name)`; `rewrite::rewrite(&model, &p.name, &q)`;
  4. `proxy::preflight_ports(d)`, then `proxy::ensure_network(d)`, then `proxy::ensure_proxy(d, paths)` (plan 23's order: the proxy takes 80/443 right after the check);
  5. remember whether `paths.ca_dir()` existed, then `certs::ensure_ca`, then `certs::ensure_project_cert`;
  6. `write_private(paths.compose_file(p), serde_json::to_vec_pretty(&rewritten.model))` (`rewrite` returns the model only and writes no file);
  7. `run_ok(d, ["compose", "-p", compose_project(p), "--project-directory", dir, "-f", compose.json, "up", "-d"])`. On error, call `proxy::stop_proxy_if_unused` (best effort, its error ignored), then return the compose error (`DevError::Docker` carries compose's stderr), with no routes written;
  8. `proxy::write_routes`, on every `up` even when nothing changed (plan 23 D2: Traefik rereads a reissued cert only on a change in the dynamic dir);
  9. `write_private(project_dir/urls.json, ["https://<route.host>", ...])`, sorted by service; `last_up = now` (RFC 3339 UTC, whole seconds, `time::format_description::well_known::Rfc3339`); `project::save`.
- Output (stdout), verbatim shape:

```
saiife dev: {p} is up (compose project saiife-{p}).
  https://web.{p}.localhost
Not routed (no port): worker. Set a port in {config}/{p}.toml.
New local CA: run saiife dev ca to trust it.
```
  The "Not routed" line lists every service of the model that has no route and no `skip` quirk, comma separated, and only when there is one. With no routes at all, the URL lines become `No service has a port, so there is no URL. Set one in {config}/{p}.toml.`. The CA line appears only when `ca_dir` did not exist before step 5.

- [ ] **Step 1: failing tests** (`#[cfg(unix)]`):
  - `up_routes_and_prints_urls`: repo `shop` and `MODEL`; exit 0; stdout has `https://web.shop.localhost` and `Not routed (no port): worker`. The log has exactly one call ending `up -d` and equal to `compose -p saiife-shop --project-directory <repo> -f <state>/saiife/dev/projects/shop/compose.json up -d`. That `compose.json` has no `"ports"` key anywhere and `"name": "saiife-shop"`. `project.json` has a `last_up` that parses as RFC 3339. `urls.json` is `["https://web.shop.localhost"]`. `<state>/saiife/dev/proxy/dynamic/shop.toml` exists;
  - `up_defaults_to_the_cwd` (no DIR, run in the repo: the same project);
  - `same_folder_name_gets_dash_two`: two repos both named `shop`; the second `up` prints `https://web.shop-2.localhost`; a third `up` of the first repo is `shop` again;
  - `compose_json_is_private`: modes `0600` and `0700`;
  - `up_never_writes_the_repo`: repo with `compose.yaml` and `.env`, dir chmod `0555`; exit 0; the sorted (path, len, mtime) list is the same before and after (restore `0755` before the tempdir drops);
  - `failed_compose_up_writes_no_routes`: `Rule::fail("compose * up -d", 1, "port is already allocated")`; exit 1; stderr starts `saiife dev: ` and contains `port is already allocated`; no `dynamic/shop.toml`; `project.json` has no `last_up`;
  - `not_a_folder_is_a_plain_error` (`dev up <repo>/nope`: exit 1, `is not a folder`, empty log);
  - `no_port_anywhere_says_how_to_add_one` (a model with only `worker`);
  - `first_up_says_trust_the_ca_once` (the line on the first `up`, not on the second).
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd up_`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy clean; the Windows check is clean.
- [ ] **Step 5:** commit `feat(cli): saiife dev up: compose behind the proxy, no repo edit`.

### Task 3: `saiife dev ls [--json]` (size M)

**Files:** `crates/cli/src/dev_cmd/inventory.rs`; tests appended.

**Interfaces (Produces, used by Task 5):**
- `pub(crate) fn ps_format() -> String` (the `PS_FORMAT` of Global Constraints);
- `pub(crate) struct Container { pub id: String, pub name: String, pub project: String, pub running: bool }`;
- `pub(crate) fn parse_ps(stdout: &str) -> Vec<Container>`: one per line with 4 tab-separated fields, where `running` means the state equals `running`. A line with another field count is skipped;
- `pub(crate) enum State { Running, Partial, Stopped, Missing, Unknown }`, with `as_str()` giving the lowercase word; `pub(crate) fn classify(folder_exists: bool, running: usize, total: usize) -> State` (P3, without `Unknown`);
- `pub(crate) struct Row { pub name: String, pub dir: Option<PathBuf>, pub urls: Vec<String>, pub state: State, pub last_up: Option<String>, pub running: usize, pub total: usize, pub containers: Vec<Container> }`;
- `pub(crate) enum Proxy { Running, Stopped, Absent, Unknown }` (from the labelled container whose name is exactly `PROXY_CONTAINER`; it has an empty project label, so it is never a row);
- `pub(crate) struct Inventory { pub rows: Vec<Row>, pub proxy: Proxy, pub docker_error: Option<String> }`;
- `pub(crate) fn inventory(d: &dyn Docker, paths: &DevPaths) -> Result<Inventory, String>`. A `project::list` error is fatal. A `docker ps` error sets every state to `Unknown` and fills `docker_error`. The rows are the state's projects, plus one per project label seen only on containers (an orphan, `dir: None`), sorted by name. Containers with an empty project label (the proxy) are not rows. `urls` come from `urls.json`, and a missing or bad file gives `[]`;
- `pub(crate) fn ls(d, paths, json: bool) -> ExitCode`.
- Text output:

```
PROJECT  STATE    LAST UP               DIR
shop     running  2026-11-10T09:12:00Z  /home/u/src/shop
         https://web.shop.localhost
old      missing  -                     /home/u/gone
proxy: running
```
  Columns are padded to the widest cell. `-` means none. A URL line appears only for `running` and `partial` rows. With no rows: `No saiife dev projects yet. Run saiife dev up in a folder with a compose file.`. With `docker_error`, stderr gets `saiife dev: docker did not answer, so states are unknown: {error}` and the exit is 1.
- JSON: `{"projects":[{"name","dir"(string|null),"urls":[..],"state","last_up"(string|null),"containers":{"running":n,"total":n}}],"proxy":"running"|"stopped"|"absent"|"unknown"}`.

- [ ] **Step 1: failing tests:**
  - unit: `parse_ps_reads_four_fields` (and skips a 3-field line); `classify_follows_the_table` (each row of P3);
  - `#[cfg(unix)]`, where each test seeds state with a real `up` against the fake, then answers `ps -a --filter label=saiife.managed=true*` with tab lines:
    - `ls_shows_running_partial_and_stopped`: three projects; JSON states `running`, `partial` and `stopped`, `containers` counts right, `urls` only from `urls.json`;
    - `ls_shows_missing_when_the_folder_is_gone`;
    - `ls_shows_an_orphan_from_labels` (a container labelled `saiife.dev.project=ghost` with no state: a `ghost` row, `dir: null`, `missing`);
    - `ls_proxy_line` (a `saiife-dev-proxy` row with an empty project label: `"proxy":"running"` and no `""` row);
    - `ls_docker_down_is_unknown_and_exit_1` (`Rule::fail("ps -a *", 1, "Cannot connect to the Docker daemon")`, so the seeding `up`'s pre-flight `ps --filter ...` calls still pass: the rows are still listed as `unknown`, stderr names the error, exit 1);
    - `ls_empty_says_how_to_start`;
    - `ls_text_has_no_escape_from_a_folder_name` (a repo folder named `a\x1b[31mb`: the printed dir is sanitized).
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd ls_` and `cargo test -p saiife inventory`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy clean.
- [ ] **Step 5:** commit `feat(cli): saiife dev ls: projects, URLs and state from state and labels`.

### Task 4: `saiife dev down <PROJECT> [--volumes] [--yes]` (size M)

**Files:** `crates/cli/src/dev_cmd/remove.rs`; tests appended.

**Interfaces (Produces, used by Task 5):**
- `pub(crate) fn label_filters(project: Option<&str>) -> Vec<String>`: `["--filter", "label=saiife.managed=true"]`, plus `["--filter", "label=saiife.dev.project=<p>"]` when given;
- `pub(crate) fn labelled_volumes(d, project: Option<&str>, dangling_only: bool) -> Result<Vec<String>, String>`: `docker volume ls -q <filters> [--filter dangling=true]`;
- `pub(crate) fn confirm_volumes(names: &[String], yes: bool, what: &str) -> Res`. With no names it returns `Ok`. Otherwise it prints the names and calls `confirm("Delete {n} volumes of {what}? Their data is gone for good.", yes)`. A no prints `Nothing deleted.` and returns `Err("volumes kept: the answer was not yes.")`;
- `pub(crate) fn rm_volumes(d, names: &[String]) -> Res`: `docker volume rm <names>`, and nothing for none;
- `pub(crate) fn remove_containers(d, ids: &[String], force: bool) -> Res`: `docker rm [-f] <ids>`, and nothing for none;
- `pub(crate) fn foreign_containers(d, project: &str) -> Result<Vec<String>, String>`: `docker ps -a --filter label=com.docker.compose.project=saiife-<p> --format {{.Names}}\t{{.Label "saiife.managed"}}`, the names whose second field is not `true`;
- `pub(crate) fn down(d, paths, project: &str, volumes: bool, yes: bool) -> Res`:
  1. `valid_project(project)`, or `Err("{p} is not a saiife dev project name. saiife dev ls lists them.")` before any other call;
  2. the project must be in `project::list`, or have labelled containers. Otherwise `Err("no project named {p}. saiife dev ls lists them.")`;
  3. `foreign_containers` must be empty. Otherwise `Err("compose project saiife-{p} has containers saiife did not create ({names}); nothing was touched.")`;
  4. with `--volumes`: `labelled_volumes(Some(p), false)`, then `confirm_volumes`, before anything is stopped;
  5. if `compose.json` exists and the project's folder (`ProjectState.dir`) still exists, run `compose -p saiife-<p> --project-directory <dir> -f <compose.json> down` (no `--volumes`, P6). Otherwise, `docker ps -aq <label_filters(p)>` → `remove_containers(force)`, then `docker network ls -q <label_filters(p)>` → `docker network rm`. Both filters carry the project label, so the proxy and the shared network are never selected;
  6. if the volumes were confirmed: `rm_volumes`;
  7. `proxy::remove_routes`, then `proxy::stop_proxy_if_unused`. Print `saiife dev: {p} is down.`, plus `Proxy stopped: no project is running.` when that returned true, plus `Volumes deleted: {names}.` when they were.

- [ ] **Step 1: failing tests** (`#[cfg(unix)]`, state seeded by `up`):
  - `down_runs_compose_down_and_removes_routes`: the log has `compose -p saiife-shop --project-directory <repo> -f <compose.json> down` with no `--volumes`, and no `volume rm`; `dynamic/shop.toml` is gone; `project.json` is still there;
  - `down_rejects_a_bad_name`: for each of `../../etc`, `Shop`, `''` and `a/b`: exit 1 with `is not a saiife dev project name`, and the log is empty;
  - `down_unknown_project`: exit 1, `no project named nope`;
  - `down_refuses_foreign_containers`: the foreign listing answers `mine\t` (no label value); exit 1; the log has no `down`, no `rm` and no `volume rm`;
  - `down_volumes_without_yes_deletes_nothing`: the volume listing answers `saiife-shop_db`; stdin null; exit 1 with the Review Focus 3 text; the log has no `down` and no `volume rm`;
  - `down_volumes_with_yes_removes_only_listed`: `--volumes --yes`; the log has `volume rm saiife-shop_db` and no other volume name; the labelled `volume ls` call precedes it and contains both label filters;
  - `down_volumes_piped_answer_is_not_a_yes` (`saiife_with_stdin` with `"y\n"`: stdin is a pipe, not a tty, so the no-tty refusal holds and the log has no `volume rm`. The y/n answers themselves are Task 1's `confirm_with` unit tests);
  - `down_without_compose_json_removes_by_label` (delete `compose.json` first: `ps -aq` with both label filters, then `rm -f <ids>` of exactly those ids, then `network ls -q` with both label filters).
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd down_`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy clean.
- [ ] **Step 5:** commit `feat(cli): saiife dev down: labelled only, volumes after a yes`.

### Task 5: `saiife dev gc [--volumes] [--yes]` (size M)

**Files:** `crates/cli/src/dev_cmd/remove.rs` (`gc`); tests appended.

**Interfaces:**
- Consumes `inventory`, `Row`, `State` (Task 3); `remove_containers`, `labelled_volumes`, `confirm_volumes`, `rm_volumes`, `label_filters` (Task 4).
- `pub(crate) fn gc(d, paths, volumes: bool, yes: bool) -> Res`:
  1. `inventory`. If `docker_error` is set, return `Err("docker did not answer, so nothing was removed: {e}")`;
  2. with `--volumes`, without `--yes` and with no tty on stdin: return the Review Focus 3 error now, so nothing at all is removed. The prompt itself comes at step 6, with the real list;
  3. for each row in `Stopped` or `Missing`: `remove_containers(&ids, false)`, `proxy::remove_routes`, then `fs::remove_dir_all(paths.project_dir(name))` only if `valid_project(name)`. Print `removed {name} ({state})`. A row in `Running` or `Partial` prints `kept {name}: still running`. One failing project prints `saiife dev: could not remove {name}: {e}` on stderr; the others go on, and the exit is 1 at the end;
  4. stale route files: each `<proxy_dir>/dynamic/<stem>.toml` where `valid_project(stem)` holds and `stem` is not a `Running` or `Partial` row goes through `proxy::remove_routes(paths, stem)`. Print `removed stale routes: {stems}`;
  5. `proxy::stop_proxy_if_unused`; then `docker network prune -f --filter label=saiife.managed=true --filter label=saiife.dev.project` (the project-label key is required, so the shared `saiife-dev` network is never pruned). Print `removed unused saiife networks: {names}` from the prune's stdout (the lines after `Deleted Networks:`);
  6. volumes: with `--volumes`, `labelled_volumes(None, true)` (listed after steps 3 to 5, so the removed projects' volumes are in it), then `confirm_volumes(.., "saiife dev")` and `rm_volumes`. Without it, print `{n} saiife volumes kept; saiife dev gc --volumes deletes them.` when `n > 0`;
  7. always, last: the image line of Global Constraints, verbatim.

- [ ] **Step 1: failing tests** (`#[cfg(unix)]`):
  - `gc_removes_stopped_and_missing_keeps_running`: three seeded projects (one running, one stopped, one with its folder deleted); stdout has `removed b (stopped)`, `removed c (missing)` and `kept a: still running`; the state dir of `c` is gone, `certs::remove_project_cert` removed `<state>/tls/c/`, the state dirs of `a` and `b` are kept (`b`'s `project.json` unchanged, so the next `up` of `b`'s folder reuses its name); the log has `rm <ids of b and c>` and no id of `a`;
  - `gc_removes_only_labelled`: every `rm`, `network rm` and `volume rm` line in the log names only ids or names that an earlier labelled listing returned (the one exception is `rm -f saiife-dev-proxy` from `stop_proxy_if_unused`, after its own label check). Every `prune` line contains both `--filter label=saiife.managed=true` and `--filter label=saiife.dev.project`. No line removes `saiife-dev` (the network). No log line contains `image`;
  - `gc_says_images_are_not_touched` (the verbatim line, also with nothing to do);
  - `gc_volumes_without_yes_deletes_nothing` (stdin null, exit 1, the Review Focus 3 text, and no `rm` of any kind in the log: the confirmation comes first);
  - `gc_volumes_with_yes`: the log has `volume ls -q --filter label=saiife.managed=true --filter dangling=true` and then `volume rm` of exactly its names;
  - `gc_removes_stale_route_files_only` (`dynamic/ghost.toml` with no project goes; `dynamic/a.toml` of the running `a` and `dynamic/_tls.toml` stay);
  - `gc_docker_down_removes_nothing` (exit 1; `project.json` files are untouched);
  - `gc_counts_kept_volumes`.
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd gc_`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy clean; the Windows check is clean.
- [ ] **Step 5:** commit `feat(cli): saiife dev gc: stopped projects, unused networks, stale routes; labelled only`.

### Task 6: `docs/dev.md`, README link, `scripts/dev-smoke.sh` (size S)

**Files:** create `docs/dev.md` and `scripts/dev-smoke.sh`; modify `README.md` (one bullet in the docs list, after the environments line: `- [Dev environments](docs/dev.md): saiife dev, compose stacks behind one HTTPS proxy (preview).`); test appended to `crates/cli/tests/dev_cmd.rs`.

**`docs/dev.md` headings, in order, each with the facts named:**
- `## Quick start`: `saiife dev up` in a compose repo; the URL; `saiife dev ca` once;
- `## Names`: `<service>.<project>.localhost`; the folder name, lowercased, at most 40 characters; `-2` for a second folder with the same name; a service with no port has no URL;
- `## HTTPS and the local CA`: the CA lives under `$XDG_STATE_HOME/saiife/dev`; saiife never writes a trust store; the trust commands for Linux, macOS and Windows exactly as `ca` prints them; Node and Python; keep the key private;
- `## Quirks`: `~/.config/saiife/dev/<project>.toml` (`$XDG_CONFIG_HOME`), never in the repo; keys `port`, `scheme` (`http` or `https`), `skip` and `host` under `[services.<name>]`, with one example; an unknown key is an error;
- `## Commands`: up, ls (the states table of P3), down, gc, ca, with each flag;
- `## Cleanup and labels`: `saiife.managed=true` and `saiife.dev.project=<project>` on everything saiife creates; cleanup selects only by those labels; volumes only after a yes or `--yes`; dangling images and anonymous volumes are not touched (`docker image prune`, `docker volume prune`);
- `## Limits`: preview; Linux first (macOS and Windows build, untested against Docker); Docker Compose v2 (2.0.0 or later; plan 22 F2); only the compose files in the folder itself are read (`compose.yaml`, `compose.yml`, `docker-compose.yml`, `docker-compose.yaml`, plus one `compose.override.*` or `docker-compose.override.*`), with no search in parent folders, and `COMPOSE_FILE` (from the environment or `.env`) is ignored (plan 22 D4); ports 80 and 443 must be free (rootless Docker needs `net.ipv4.ip_unprivileged_port_start`); not a security boundary: the stack runs with your own Docker, and membership of the `docker` group is root on the host; `ls` shows no disk use; `compose.json` under the state dir holds values from `.env`.

**`scripts/dev-smoke.sh`** (owner-run, `set -euo pipefail`, Linux):
- the header says owner-run only, real Docker, pulls images, binds 80 and 443; `SAIIFE=${SAIIFE:-target/debug/saiife}`;
- `XDG_STATE_HOME`, `XDG_CONFIG_HOME` and the repo go under one `mktemp -d`, with a `trap` that runs `down --volumes --yes` and removes the canaries and the dir;
- the repo's `compose.yaml` has `web` (`traefik/whoami:v1.10.1`, `ports: ["8080:80"]`, a named volume `data`) and `worker` (`busybox:1.36`, `sleep 3600`);
- canaries, unlabelled: `docker network create smoke-canary-net`, `docker volume create smoke-canary-vol`, `docker create --name smoke-canary busybox:1.36`;
- checks, each printing `ok:` or `FAIL:` and counting failures:
  1. `up` prints `https://web.<p>.localhost`;
  2. `curl -fsS --cacert <ca> https://web.<p>.localhost/` returns whoami's `Hostname:`;
  3. `curl http://127.0.0.1:8080` fails (the port was stripped);
  4. the repo's `find -printf '%p %s %T@'` listing is the same as before `up`;
  5. `ls --json` has the project `running`;
  6. `down`, then `ls --json` has it `stopped`, and the volume still exists;
  7. `gc --volumes --yes`, then `docker ps -a`, `docker network ls` and `docker volume ls`, all with `--filter label=saiife.managed=true`, show nothing but the shared `saiife-dev` network (`saiife.dev.role=network`; the proxy went with the last `down`), and all three canaries still exist;
  8. `gc` output has `Dangling images are not touched`;
- exit status = the failure count (capped at 1).

- [ ] **Step 1: failing test** `dev_page_states_its_facts` (every OS): `docs/dev.md` has each heading above, `saiife.managed=true`, `saiife.dev.project`, `update-ca-certificates`, `trust anchor --store`, `add-trusted-cert -d -r trustRoot`, `certutil -user -addstore Root`, `Dangling images are not touched`, `--yes`, `COMPOSE_FILE` and `not a security boundary`. `README.md` links `docs/dev.md`.
- [ ] **Step 2:** `cargo test -p saiife --test dev_cmd dev_page`; expect FAIL.
- [ ] **Step 3:** write the page, the README line and the script.
- [ ] **Step 4:** the test passes; `cargo test -p saiife --test docs_wording` passes; `bash -n scripts/dev-smoke.sh`, and `shellcheck scripts/dev-smoke.sh` if it is installed. **Do not run the script.**
- [ ] **Step 5:** commit `docs(dev): saiife dev page and owner smoke script`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`): `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test -p saiife -p saiife-dev`; `bash scripts/check-windows.sh -p saiife`; `bash scripts/check-unsafe.sh`; `bash -n` on the changed shell files.
- [ ] `grep -rn '"saiife.managed\|"saiife.dev.project\|"saiife-dev' crates/cli/src` finds nothing (the labels come from `saiife_dev::labels`).
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. The owner merges. No tag.

## Follow-ups (not in this plan)

- `ls --disk` (P2), and idle-stop after N days (vision §5).
- `saiife doctor` saying that membership of the `docker` group is root on the host (spec §15).

## Owner questions

None. P4 was settled on 2026-11-10 (see P4).

## Owner handwork

Nothing here runs on a build agent's machine.

- [ ] On the Linux laptop, with Docker and Compose v2 (2.0.0 or later), ports 80 and 443 free, and network for image pulls: `cargo build -p saiife && bash scripts/dev-smoke.sh`. Expect 8 `ok:` lines and exit 0.
- [ ] Trust the CA once with the commands from `saiife dev ca` (Arch: `sudo trust anchor --store <cert>`). Then `saiife dev up` a real repo of yours, open its URL in Firefox and Chrome with no warning, and `saiife dev down` it.
