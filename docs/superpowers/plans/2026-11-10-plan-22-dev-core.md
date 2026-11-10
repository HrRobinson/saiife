# Plan 22: `saiife dev` core (docker runner, paths, labels, projects, compose read, quirks, rewrite): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new tokio-free crate `saiife-dev` (`crates/dev`) that, with no Docker daemon in any test, can:
- run the `docker` CLI as a subprocess, or a scripted `FakeDocker` in tests;
- find saiife's dev state and config dirs;
- give each repo dir a stable project name;
- read a repo's compose model with `docker compose config --format json`;
- load per-project quirks from `~/.config/saiife/dev/<project>.toml`;
- rewrite the model into the JSON file `saiife dev up` starts: no host ports, saiife labels, routed services on the shared network `saiife-dev` with an alias each, and a list of routes for the proxy.

**Architecture:**
- **No Docker API client.** Every call goes through the trait `Docker` (`run(args, stdin)`), so every test can script it. `DockerCli` is the real one: `SAIIFE_DOCKER`, or `docker` on `PATH`.
- **No YAML.** We read the merged, normalized model as JSON. We write the whole rewritten model back as JSON, which is valid YAML, outside the repo. Plan 24 starts it with `docker compose -p saiife-<project> --project-directory <repo dir> -f <state>/projects/<project>/compose.json up -d`.
- **Pure core.** `compose::parse_model`, `rewrite::rewrite`, `project::dns_label` and `quirks::parse` are pure functions, and most tests target them. Only `read_config`, `assign`, `list` and `load` touch a `Docker` or the file system.

**Tech Stack:** Rust workspace crate, `serde`, `serde_json`, `toml` 0.8, and `time` 0.3 (all already in `Cargo.lock`, at the versions other crates use). No new crates. `tempfile` for tests.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5.1 (the CLI uses Docker as the user, never the daemon) and §6 (Part A). The binding shared contract for plans 22, 23 and 24 is `v3-step1-dev-contract.md`, in the coordinator's scratchpad. Its "Interfaces" block is copied below where this plan uses it. Vision §5 (`git show pr15:docs/superpowers/specs/2026-10-26-saiife-v3-harness-os-vision.md`) has the background.

## Contract changes

**No names or signatures change.** These are **additions** (new public items that plans 23 and 24 may use; nothing in the contract is removed or renamed):

| Module | Addition | Why |
|---|---|---|
| `docker` | `DockerCli::new(bin: PathBuf) -> DockerCli`, `DockerCli::from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Result<DockerCli, DevError>`, `DockerCli::bin(&self) -> &Path` | Tests must not change the process environment. |
| `docker` | `Output::ok(stdout: impl Into<Vec<u8>>) -> Output`, `Output::fail(status: i32, stderr: &str) -> Output` | Makes FakeDocker scripts short. |
| `docker` (fake) | `FakeDocker::{new, on, once, calls}`, `pub struct Call { pub args: Vec<String>, pub stdin: Option<Vec<u8>> }` | The contract names `FakeDocker` but not its methods. Task 2 fixes them. |
| `paths` | `DevPaths::from_env_with(env)`, `DevPaths::quirks_file(&self, p) -> PathBuf`, `DevPaths::compose_file(&self, p) -> PathBuf`, `DevPaths::project_file(&self, p) -> PathBuf` | One place for each file name. |
| `labels` | `pub fn label_map(project: &str) -> BTreeMap<String, String>` | Used by `rewrite`. Plan 23 does **not** use it for the proxy container and the network: those carry `MANAGED=true` and `saiife.dev.role`, with no project label. |
| `project` | `pub fn check_name(p: &str) -> Result<(), DevError>`, `pub fn load(paths, name) -> Result<Option<ProjectState>, DevError>`, `pub fn save(paths, &ProjectState) -> Result<(), DevError>` | Plan 24 checks a `<PROJECT>` from argv with `check_name` before it builds a path from it, and sets `last_up` with `save`. |
| `compose` | `pub fn parse_model(json: &[u8]) -> Result<ComposeModel, DevError>` | Pure parsing, for tests. |
| `quirks` | `pub fn parse(text: &str) -> Result<Quirks, String>` | Pure parsing, for tests. |

**Contract reading, pinned here so plans 23 and 24 agree:**
- `lib.rs` from this plan declares only plan 22's modules. Plan 23 adds `pub mod certs; pub mod proxy;` with its files.
- `error.rs` keeps one `DevError` enum. Each plan adds its variants and their `Display` arms under a comment `// plan 23` or `// plan 24`, so parallel merges conflict only by adjacent lines.
- `Route.upstream` is the full URL (`http://web.shop:3000`). `Route.upstream_scheme` repeats its scheme. `Route.host` is the full host (`web.shop.localhost`).
- `ProjectState` derives `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`. `project::save` writes atomically (a temp file, then a rename). This was asked for by plan 24.
- `<state>/projects/<p>/` also holds the CLI-owned files `compose.json` and `urls.json` (plan 24). `project::list` reads only `project.json` and ignores every other file there (asked for by plan 24).
- `rewrite` returns the model as a `Value` and writes no file. Plan 24 writes `compose.json` with mode `0600` on Unix, because it holds values from `.env`.
- `ComposeModel.services` and `Rewritten.routes` are sorted by service name. `serde_json` map order depends on whether `preserve_order` is unified into the build (saiife-agents turns it on), so nothing may rely on map order.

## Facts checked (2026-11-10)

**D** marks a fact that changes the design. The changes are listed after the table.

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | `docker compose config` has `--format` with values `yaml` and `json`. It also has `--no-interpolate`, `--no-normalize`, `--no-path-resolution`, `--no-env-resolution`, and `-o`. | docs.docker.com/reference/cli/docker/compose/config | Confirmed. We call it with defaults (interpolated, normalized, absolute paths), plus `--format json`. |
| F2 | **Minimum version:** Compose **v2.0.0** already has `--format` on `convert`, with alias `config`: `flags.StringVar(&opts.Format, "format", "yaml", "Format the output. Values: [yaml \| json]")`. | github.com/docker/compose, tag `v2.0.0`, `cmd/compose/convert.go`, `docs/reference/compose_convert.md` | Confirmed. Any Compose v2 has it. `docker-compose` v1 is a separate binary, and `docker compose` without the plugin fails (F11). |
| F3 | Ports long syntax in the JSON output: `ServicePortConfig { name, mode, host_ip, target: uint32, published: string, protocol, app_protocol }`, all `omitempty`. `published` "is defined as a string and can be set as a range using syntax `start-end`". `protocol` defaults to `tcp`. | compose-spec/compose-go `main` `types/types.go`; docs.docker.com/reference/compose-file/services (`ports`) | **D1.** `published` is a string (`"8080"`, `"8000-8005"`) and may be absent. |
| F4 | In compose-go **v1.0.0** (early Compose v2), `Published` was a `uint32`. | compose-go tag `v1.0.0`, `types/types.go` | **D1.** The parser accepts a number or a string for both `target` and `published`. |
| F5 | `expose` is a `StringOrNumberList` (`json:"expose,omitempty"`): a list of strings, which can be a port, a range or `port/proto`. | compose-go `types/types.go` (v1.0.0 and `main`); compose-file services docs | **D1.** It is parsed as strings or numbers: `"3000"`, `"3000/tcp"`, `"3000-3005"`. |
| F6 | Top-level JSON: `name` (`omitempty`, but Compose always sets it), `services` (always), and `networks`, `volumes`, `secrets`, `configs` when non-empty. Extensions (`x-*`) are merged in. | compose-go `main` `types/project.go`, `Project.MarshalJSON` | Confirmed. We set `name` to `saiife-<project>` and keep every other key as is. |
| F7 | Service networks: `networks` is `map[string]*ServiceNetworkConfig`. A value may be `null`. `aliases` is `[]string`. | compose-go `types/types.go`; compose-file services docs (`networks.aliases`) | Confirmed. We add `"saiife-dev": {"aliases": ["<service>.<project>"]}` and keep the other entries (`null` included). |
| F8 | Normalization attaches each service with no `networks` to `default` (`{"default": null}`), but not services with `network_mode` or `provider`. It adds a top-level `default` network only if a service uses it. Each network, volume, config and secret with no `name` gets `name = "<project>_<key>"`. External ones get `name = <key>`. | compose-go `main` `loader/normalize.go` | **D2.** The output already has the *original* project name baked into resource names. |
| F9 | `external: true`: "Compose doesn't attempt to create these networks, and returns an error if one doesn't exist." "All other attributes apart from name are irrelevant. If Compose detects any other attribute, it rejects the Compose file as invalid." `name` "is used as is and is not scoped with the project name". | docs.docker.com/reference/compose-file/networks | **D3.** No labels on external networks or volumes. The `saiife-dev` entry is exactly `{"name": "saiife-dev", "external": true}`. |
| F10 | Default files: `compose.yaml`, `compose.yml`, `docker-compose.yml`, `docker-compose.yaml`; override: `compose.override.yml`, `compose.override.yaml`, `docker-compose.override.yml`, `docker-compose.override.yaml`. Found in the working dir, then in each parent dir. Skipped if `-f` or `COMPOSE_FILE` is given. | compose-go `main` `cli/options.go` | **D4.** The docs do not say the search starts at `--project-directory`. We find the files ourselves in the given dir and pass `-f` for each. |
| F11 | A JSON compose file works with `-f`: "Yes. YAML is a superset of JSON so any JSON file should be valid YAML. To use a JSON file with Compose, specify the filename to use, for example: `docker compose -f compose.json up`." | docs.docker.com/compose/support-and-feedback/faq | Confirmed (design call 2 of the contract stands). |
| F12 | Project names "must contain only lowercase letters, decimal digits, dashes, and underscores", and must start with a lowercase letter or a digit. `-p` beats `COMPOSE_PROJECT_NAME`, which beats the top-level `name:`. | docs.docker.com/reference/cli/docker/compose | Confirmed. `saiife-<dns label>` is valid. The rewritten file's `name` and plan 24's `-p` agree. |
| F13 | Is `$` in the config output escaped again as `$$`, so that compose's re-read of `compose.json` does not interpolate twice? Community reports show `config` output that keeps `$$` (for example a bcrypt hash `$$2a$$08$$...`). | search results only (docker/compose issue tracker, blog posts); no official doc found | **Not confirmed by an official doc.** `rewrite` passes strings through unchanged. Owner handwork step 2 checks it with a real Compose. |

### Design changes and notes (flagged for the owner)

- **D1. Ports and expose are parsed leniently.** `target` and `published` can each be a JSON number or a decimal string. A `published` range `"8000-8005"` gives its start (`8000`), and an empty or absent `published` gives `None`. An `expose` entry `"3000"`, `3000`, `"3000/tcp"` or `"3000-3005"` gives `3000`. An entry ending `/udp` is dropped (proxy routes are HTTP). A `ports` entry that is not an object is an error naming the service. Compose always writes the long syntax in JSON, so a short-syntax string means the output is not what we expect.
- **D2. Resource names are renamed to the saiife project.** A network or volume (also `configs` and `secrets`) whose `name` equals `"<raw name>_<key>"` (F8) gets `name = "saiife-<project>_<key>"` and the saiife labels. Otherwise `saiife dev up` would share networks and volumes with the user's own `docker compose up` of the same repo, and `gc` might delete the user's data. A resource with a custom `name`, or `external: true`, is the user's. It keeps its name and gets **no** labels, so cleanup never selects it.
- **D3. The shared network.** The top-level `networks` gets the key `saiife-dev` with value `{"name": "saiife-dev", "external": true}`. If the user's model already has a network key `saiife-dev`, `rewrite` fails with `DevError::Rewrite`. Plan 23's `ensure_network` creates the network before `up`.
- **D4. `read_config` finds the compose files itself, in `dir` only** (F10 order, no parent walk). It runs `docker compose --project-directory <dir> -f <base> [-f <override>] config --format json`. Explicit `-f` makes compose ignore `COMPOSE_FILE`, which is a documented limit (plan 24's `docs/dev.md`). The `Docker` trait has no working dir. Everything is absolute, so none is needed.
- **D5. Which services get a route.** A service is routed unless:
  - its quirk has `skip = true`;
  - it has `network_mode` (it cannot join networks; for example `host` or `service:db`);
  - no port is found (quirk `port`, else the first TCP `ports` target, else the first `expose`).

  A routed service joins `saiife-dev` with alias `<label>.<project>`, where `<label>` is the quirk's `host`, or else `dns_label(service name)`. Its route is `host = "<label>.<project>.localhost"` and `upstream = "<scheme>://<label>.<project>:<port>"`, with scheme from the quirk, else `http`. Two routed services with the same `<label>` fail with `DevError::Rewrite` naming both. A quirk `host` must already be a DNS label (`dns_label(h) == Some(h)`), so a quirk can never claim a name under another project.
- **D6. `ports` are stripped from every service**, routed or not, as the contract says. This includes a database's `5432:5432` that host tools may use (owner question 1).
- **D7. Spec §6 no longer says `bollard` or "a loopback mock of the Docker Engine API".** The spec on `v3-design` already names the `docker` CLI subprocess and a fake `docker` executable, matching design call 1 of the contract. Nothing to change (owner question 2 is closed).
- **D8. Quirks for unknown services are ignored.** `docker compose config` leaves out services in inactive profiles, so a quirk for one is not an error. Unknown *keys* are errors (`deny_unknown_fields`), as the contract says.
- **D9. Project claims are atomic.** `assign` claims a name with `fs::create_dir` (not `create_dir_all`) of `<state>/projects/<name>`. On `AlreadyExists` it tries the next suffix, so two concurrent `up`s for two folders named `shop` get `shop` and `shop-2`.

### Owner questions

1. **D6:** strip host ports from every service (contract), or keep `ports` on services that are not routed (databases, for example)? Default: strip all, and add a quirk `keep_ports = true` later if asked.
2. **D7:** closed. The spec already names the CLI subprocess and a fake `docker`.

## Global Constraints

- **Tokio-free:** `saiife-dev` never depends on tokio. Task 1 adds it to the CI gate "no tokio in hook crates".
- **No unsafe:** `[lints] workspace = true`, and `#![forbid(unsafe_code)]` at column 0 of `crates/dev/src/lib.rs` (`scripts/check-unsafe.sh` checks both).
- **Portable:** compiles on Linux, macOS and Windows. Tests that write a shell script are `#[cfg(unix)]`. `bash scripts/check-windows.sh -p saiife-dev` is clean.
- **No new crates:** `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `toml = "0.8"`, `time = { version = "0.3", features = ["formatting", "macros"] }` (as in `crates/daemon/Cargo.toml`); dev-dep `tempfile = "3"`.
- **No docker, ever, in any test or step.** Tests use `FakeDocker`, or a shell script under a tempdir passed to `DockerCli::new`. No test reads the real `PATH` or `HOME`.
- **The repo is never written.** Only `<state>` and `<config>` paths are written (`<state>` = `$XDG_STATE_HOME/saiife/dev`, else `$HOME/.local/state/saiife/dev`; `<config>` = `$XDG_CONFIG_HOME/saiife/dev`, else `$HOME/.config/saiife/dev`).
- **Fixed values (contract):** labels `saiife.managed=true` and `saiife.dev.project=<project>`; network `saiife-dev`; proxy container `saiife-dev-proxy`; compose project `saiife-<project>`; project names `[a-z0-9-]`, at most 40 characters, no leading or trailing `-`, and duplicates get `-2`, `-3`, and so on.
- **Commands for every task** (hard rules), in the worktree:
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p22-tN-XXXXXX)" SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0
  cargo test -p saiife-dev -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy -p saiife-dev --all-targets -j 4 -- -D warnings
  ```
  (`N` is the task number.) Remove `$TMPDIR` at the end.

## Review Focus

1. **A project name taken from argv or a file is used as a path** (`saiife dev down ../../.ssh`). Expected: `check_name` rejects anything that is not a DNS label, and `quirks::load`, `project::load` and `rewrite` call it first (Task 3: `check_name_rejects_traversal`; Task 4: `load_rejects_a_bad_project_name`).
2. **The user's own run of the same repo shares resources with saiife's.** Expected: every `<orig>_<key>` resource is renamed to `saiife-<p>_<key>` and labelled; custom-named and external ones are untouched and unlabelled (Task 6: `renames_default_named_resources`, `custom_and_external_resources_are_not_labelled`).
3. **Service names that are not DNS labels** (`Web_UI`, `api.v2`), or two that reduce to the same label. Expected: host `web-ui.<p>.localhost`, and a clash is a clear error, never a silent overwrite (Task 6: `service_names_become_labels`, `label_clash_is_an_error`).
4. **Docker without the compose plugin, or a compose file with an error.** Expected: `ComposeMissing` with a one-line hint for the first; `Docker { stderr }` with compose's own message for the second, never a JSON parse error (Task 5: `compose_plugin_missing_is_named`, `config_error_keeps_compose_stderr`).
5. **A large `docker` stdin or stdout** (a `compose.json` of a big stack piped in, a long `ps` listing). Expected: no deadlock (Task 2: `big_stdin_and_stdout_do_not_deadlock`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (crate, errors, labels, paths).
- **Wave 2 (parallel):** Task 2 (docker), Task 3 (project), Task 4 (quirks).
- **Wave 3:** Task 5 (compose read; needs 2).
- **Wave 4:** Task 6 (rewrite; needs 3, 4, 5).
- **Last:** the gates, a whole-branch review, one fix wave, push, PR. Plans 23 and 24 start from this branch.

**Shared files:** `crates/dev/src/error.rs` (Tasks 2 to 6 add variants; Task 1 creates all of plan 22's variants up front, so later tasks add none), `crates/dev/src/lib.rs` (Task 1 declares all modules, with empty files for Tasks 2 to 6).

---

### Task 1: the crate, errors, labels and paths (size S)

**Files:**
- Create `crates/dev/Cargo.toml`, `crates/dev/src/lib.rs`, `crates/dev/src/error.rs`, `crates/dev/src/labels.rs`, `crates/dev/src/paths.rs`, and empty `docker.rs`, `project.rs`, `compose.rs`, `quirks.rs`, `rewrite.rs` (one `//!` line each).
- Modify `.github/workflows/ci.yml` (the "no tokio in hook crates" step: add `-p saiife-dev`), `Cargo.lock` (by cargo).

**Interfaces (Produces):**
- `Cargo.toml`: `name = "saiife-dev"`, `description = "saiife dev: compose stacks on one local proxy, by name instead of port."`, `edition`, `version`, `license` and `repository` from the workspace, `[lib] name = "saiife_dev"`, `[features] fake = []`, the dependencies from Global Constraints, and `[lints] workspace = true`.
- `lib.rs`: a `//!` doc, `#![forbid(unsafe_code)]`, `pub mod docker; pub mod paths; pub mod labels; pub mod project; pub mod compose; pub mod rewrite; pub mod quirks; mod error; pub use error::DevError;`.
- `error.rs`: `#[derive(Debug)] pub enum DevError`, with hand-written `Display` and `std::error::Error` (`source()` returns the `io::Error` where there is one). No thiserror. Plan 22's variants and their exact `Display` text:

| Variant | Display |
|---|---|
| `NoHome` | `cannot find your home directory (HOME is not set or not absolute)` |
| `Io { path: PathBuf, source: io::Error }` | `{path}: {source}` |
| `DockerNotFound { tried: String }` | `docker not found ({tried}); install Docker or set SAIIFE_DOCKER to its path` |
| `Spawn { bin: PathBuf, source: io::Error }` | `cannot run {bin}: {source}` |
| `Docker { args: Vec<String>, status: i32, stderr: String }` | `docker {args joined by " "} failed (exit {status}): {stderr}` |
| `ComposeMissing` | `docker compose is not available; saiife dev needs Docker Compose v2` |
| `NoComposeFile { dir: PathBuf }` | `no compose file in {dir} (looked for compose.yaml, compose.yml, docker-compose.yml, docker-compose.yaml)` |
| `NonUtf8Path(PathBuf)` | `path is not valid UTF-8: {path}` |
| `ComposeJson(String)` | `unexpected docker compose config output: {msg}` |
| `BadProjectName(String)` | `not a valid saiife dev project name: {name:?} (lowercase letters, digits and -, at most 40)` |
| `State { path: PathBuf, msg: String }` | `{path}: {msg}` |
| `Quirks { path: PathBuf, msg: String }` | `{path}: {msg}` |
| `Rewrite(String)` | `cannot prepare the compose model: {msg}` |

  Paths print with `.display()`.
- `labels.rs`: the four constants and `compose_project` exactly as in the contract; `pub fn label_map(project: &str) -> BTreeMap<String, String>` returns `{MANAGED: "true", PROJECT: project}`.
- `paths.rs`: `DevPaths { pub state: PathBuf, pub config: PathBuf }`.
  - `from_env()` calls `from_env_with(&|k| std::env::var_os(k))`.
  - `from_env_with`: `XDG_STATE_HOME` and `XDG_CONFIG_HOME` count only when set and absolute. `HOME` is the fallback (`USERPROFILE` when `HOME` is unset, for Windows), and must be absolute, else `NoHome`.
  - `project_dir(p) = state/projects/<p>`, `proxy_dir() = state/proxy`, `ca_dir() = state/ca`, `compose_file(p) = project_dir(p)/compose.json`, `project_file(p) = project_dir(p)/project.json`, `quirks_file(p) = config/<p>.toml`.
  - Nothing is created on disk.

- [ ] **Step 1: failing tests** (unit tests in `labels.rs`, `paths.rs` and `error.rs`):
  - `compose_project_prefixes`: `compose_project("shop") == "saiife-shop"`; `label_map("shop")` has exactly two entries, `saiife.managed=true` and `saiife.dev.project=shop`;
  - `xdg_dirs_win`: env `{XDG_STATE_HOME=/x/state, XDG_CONFIG_HOME=/x/cfg, HOME=/h}` gives `state=/x/state/saiife/dev`, `config=/x/cfg/saiife/dev`;
  - `home_fallback`: `{HOME=/h}` gives `/h/.local/state/saiife/dev` and `/h/.config/saiife/dev`;
  - `relative_xdg_is_ignored`: `{XDG_STATE_HOME=rel, HOME=/h}` gives `/h/.local/state/saiife/dev`;
  - `no_home_is_an_error`: `{}` and `{HOME=rel}` give `Err(DevError::NoHome)`;
  - `file_names`: `project_dir("shop")`, `compose_file`, `project_file`, `quirks_file`, `proxy_dir` and `ca_dir` give the paths above (built with `Path::join`, so the test holds on Windows too);
  - `docker_error_display`: `Docker { args: ["compose","up"], status: 1, stderr: "boom" }` displays `docker compose up failed (exit 1): boom`.
- [ ] **Step 2:** `cargo test -p saiife-dev` (commands as in Global Constraints); expect FAIL (unresolved items).
- [ ] **Step 3:** implement. Use `Path::is_absolute` for the absolute checks (on Windows, `/h` is not absolute; gate the two Unix-path tests with `#[cfg(unix)]` and add a `#[cfg(windows)]` twin with `C:\h`).
- [ ] **Step 4:** the tests pass; `bash scripts/check-unsafe.sh` exits 0; `cargo tree -e normal -p saiife-dev | grep -c tokio` prints `0`; `bash scripts/check-windows.sh -p saiife-dev` is clean.
- [ ] **Step 5:** commit `feat(dev): the saiife-dev crate: errors, labels, state and config paths`.

### Task 2: the docker runner and FakeDocker (size M)

**Files:**
- Modify `crates/dev/src/docker.rs`. Create `crates/dev/src/docker/fake.rs` (declared in `docker.rs` as `#[cfg(any(test, feature = "fake"))] mod fake; #[cfg(any(test, feature = "fake"))] pub use fake::{Call, FakeDocker};`).

**Interfaces:**
- Consumes `DevError` (Task 1).
- Produces (contract, plus the additions):
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Output { pub status: i32, pub stdout: Vec<u8>, pub stderr: Vec<u8> }`, with `Output::ok(stdout)` (status 0, empty stderr) and `Output::fail(status, stderr)`;
  - `pub trait Docker { fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, DevError>; }`. `Err` only when the process cannot run at all (`Spawn`, or `Io` on a pipe). A non-zero exit is `Ok` with that status, and a signal death is status `-1`;
  - `pub struct DockerCli { bin: PathBuf }`:
    - `new(bin)`;
    - `bin()`;
    - `from_env()`, which is `from_env_with(&|k| std::env::var_os(k))`;
    - `from_env_with`: a non-empty `SAIIFE_DOCKER` is used if it names an existing file, else `DockerNotFound { tried: "SAIIFE_DOCKER=<value>" }`. Otherwise `PATH` is searched (`std::env::split_paths`) for a file `docker` (on Windows `docker.exe`), and a miss is `DockerNotFound { tried: "PATH" }`;
  - `DockerCli::run` inherits the environment, so `DOCKER_HOST` and `DOCKER_CONTEXT` still work. With `stdin`, it writes stdin from a scoped thread while `wait_with_output` reads stdout and stderr. Without `stdin`, stdin is `Stdio::null()`;
  - `pub fn run_ok(d: &dyn Docker, args: &[&str]) -> Result<Vec<u8>, DevError>`: stdout on exit 0. Otherwise `Docker { args, status, stderr }`, where stderr is lossy UTF-8, trimmed, and cut to its first 4096 bytes (on a char boundary);
  - `FakeDocker` (`Send + Sync`, state in a `Mutex`):
    - `new()`;
    - `on(&self, prefix: &[&str], out: Output) -> &Self` (sticky);
    - `once(&self, prefix: &[&str], out: Output) -> &Self` (used once);
    - `calls(&self) -> Vec<Call>`, in call order;
    - `run` records every call. It answers with the first unused `once` whose prefix matches (insertion order). Else it answers with the **last**-registered matching `on`, so a later `on` overrides an earlier one. Else `Output { status: 125, stdout: [], stderr: "fake docker: no reply for: <args joined by space>" }`. A prefix matches when `args` starts with it, and `&[]` matches all.

- [ ] **Step 1: failing tests** (unit tests in `docker.rs` and `fake.rs`):
  - `fake_records_and_answers`: `on(&["ps"], Output::ok("a"))`; `run(&["ps","-a"], Some(b"x"))` gives stdout `a`; `calls()` is `[Call { args: ["ps","-a"], stdin: Some(b"x") }]`;
  - `fake_once_then_sticky`: `on(&["ps"], ok("s"))` and `once(&["ps"], ok("1"))`: three `ps` calls give `1`, `s`, `s`;
  - `fake_later_on_overrides`: `on(&["ps"], ok("a"))`, then `on(&["ps"], ok("b"))`, gives `b`;
  - `fake_unscripted_is_125`: status `125`, and stderr contains `no reply for: network ls`;
  - `run_ok_maps_failure`: a fake failing `["compose","up"]` with status 1 and stderr `" boom \n"` gives `Docker { args: ["compose","up"], status: 1, stderr: "boom" }`; a 10 000-byte stderr is cut to 4096 bytes;
  - `from_env_prefers_saiife_docker` (`#[cfg(unix)]`, a tempdir file `d`): `{SAIIFE_DOCKER=<d>, PATH=<other dir with docker>}` gives `bin() == d`;
  - `from_env_searches_path`: `{PATH=<a>:<b>}` with `docker` only in `<b>` gives `<b>/docker`;
  - `from_env_not_found`: `{PATH=<empty dir>}` gives `DockerNotFound { tried: "PATH" }`; `{SAIIFE_DOCKER=/nope}` gives `tried` containing `SAIIFE_DOCKER=/nope`;
  - `cli_runs_a_script` (`#[cfg(unix)]`): a tempdir script `#!/bin/sh` + `printf '%s\n' "$@"; cat >&2; exit 3` (mode 0o755) run through `DockerCli::new` with `run(&["a b","c"], Some(b"in"))` gives status `3`, stdout `a b\nc\n`, stderr `in`;
  - `big_stdin_and_stdout_do_not_deadlock` (`#[cfg(unix)]`, Review Focus 5): a script `cat; cat /dev/null >&2` with 4 MiB of stdin gives the same 4 MiB on stdout;
  - `missing_binary_is_spawn_error`: `DockerCli::new("<tempdir>/none").run(&["ps"], None)` gives `Err(Spawn { .. })`.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `cargo test -p saiife-dev --features fake` builds; clippy is clean; the Windows check is clean.
- [ ] **Step 5:** commit `feat(dev): the docker CLI runner and a scripted FakeDocker`.

### Task 3: project names and state (size M)

**Files:** modify `crates/dev/src/project.rs`.

**Interfaces:**
- Consumes `DevPaths` (`project_dir`, `project_file`) and `DevError` (Task 1).
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct ProjectState { pub name: String, pub dir: PathBuf, pub created: String, pub last_up: Option<String> }`. Times are `YYYY-MM-DDTHH:MM:SSZ` (UTC, formatted with `time` like `crates/daemon/src/tokens.rs` `rfc3339`);
  - `pub fn dns_label(folder: &str) -> Option<String>`. The algorithm:
    1. lowercase it (Unicode `to_lowercase`);
    2. map every character not in `[a-z0-9]` to `-`;
    3. collapse runs of `-`, and trim `-` from both ends;
    4. keep the first 40 characters, then trim a trailing `-` again;
    5. an empty result is `None`;
  - `pub fn check_name(p: &str) -> Result<(), DevError>`: `Ok` only when `dns_label(p) == Some(p)`, else `BadProjectName(p)`;
  - `pub fn assign(paths: &DevPaths, dir: &Path) -> Result<ProjectState, DevError>`:
    1. `fs::canonicalize(dir)` (an `Io` error if it fails);
    2. if `list` has a state whose `dir` equals it, return that state unchanged;
    3. otherwise take `base = dns_label(file name)`, and `BadProjectName(<file name>)` when that is `None`;
    4. try `base`, then `base-2`, `base-3` and so on. A suffixed name cuts `base` so the whole is at most 40, then trims a trailing `-` before the suffix;
    5. claim each name with `fs::create_dir_all(state/projects)` then `fs::create_dir(project_dir)`, and on `AlreadyExists` move to the next (D9);
    6. write `project.json` with `save`, `created` = now, `last_up = None`;
  - `pub fn save(paths, s)`: `check_name(&s.name)`, then write the pretty JSON to `project.json.tmp` and rename it over `project.json`;
  - `pub fn load(paths, name) -> Result<Option<ProjectState>, DevError>`: `check_name` first. A missing file is `None`. A file that does not parse is `State { path, msg }`;
  - `pub fn list(paths) -> Result<Vec<ProjectState>, DevError>`: each `state/projects/*/project.json`, sorted by name. A missing `projects` dir is `[]`. A dir with no `project.json` (a claim cut short) is skipped. A corrupt file is `State` naming it. Every other file in a project dir (`compose.json`, `urls.json`, `project.json.tmp`) and every non-dir entry in `projects` is ignored.

- [ ] **Step 1: failing tests** (unit tests, `DevPaths` built from a tempdir):
  - `dns_label_cases`: `"Shop"` gives `shop`, `"My_App.v2"` gives `my-app-v2`, `"--a--b--"` gives `a-b`, `"..."` gives `None`, `""` gives `None`, `"Über"` gives `ber`, and a 50-char `"a".repeat(39) + "-bbbb…"` gives 39 `a`s with no trailing `-`;
  - `check_name_rejects_traversal` (Review Focus 1): `"../x"`, `"a/b"`, `"A"`, `"-a"`, `""` and a 41-char name are `Err(BadProjectName)`; `"shop-2"` is `Ok`;
  - `assign_is_stable`: two `assign`s of the same dir (once as given, once through a `..` path to it) give equal states, and one dir under `projects`;
  - `same_folder_name_gets_suffix`: `<t>/a/shop` then `<t>/b/shop` give `shop` then `shop-2`; a third gives `shop-3`; assigning `<t>/a/shop` again still gives `shop`;
  - `suffix_respects_length`: a 40-char folder name's second copy is 40 characters long and ends with `-2`;
  - `unnamable_folder_is_an_error`: a dir named `___` gives `BadProjectName("___")`;
  - `claimed_dir_is_skipped`: a pre-made empty `projects/shop` (no `project.json`) makes `assign(<t>/shop)` give `shop-2`, and `list` does not show `shop`;
  - `save_and_load_round_trip`: `last_up` set and saved, then `load` gives it; `load(paths, "none")` gives `Ok(None)`; `load(paths, "../x")` gives `BadProjectName`;
  - `cli_files_are_ignored`: a project dir that also holds `compose.json` = `{`, `urls.json` = `[` and a stray file `projects/README` still lists one project, and gives no error;
  - `save_is_atomic`: after `save`, there is no `project.json.tmp` left, and a second `save` replaces the file (it does not append to it);
  - `corrupt_state_is_named`: `projects/shop/project.json` = `{` makes `list` give `State { path }` ending in `project.json`;
  - `created_is_utc`: `created` matches `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$` (checked by hand, with no regex crate).
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean.
- [ ] **Step 5:** commit `feat(dev): stable project names for repo dirs, kept in saiife's state dir`.

### Task 4: per-project quirks (size S)

**Files:** modify `crates/dev/src/quirks.rs`.

**Interfaces:**
- Consumes `DevPaths::quirks_file`, `project::check_name` (Task 3; until it lands, the builder may call a local copy, removed when Wave 2 merges), and `project::dns_label`.
- Produces:
  - `#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)] #[serde(deny_unknown_fields)] pub struct ServiceQuirk { pub port: Option<u16>, pub scheme: Option<String>, #[serde(default)] pub skip: bool, pub host: Option<String> }`;
  - `#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)] #[serde(deny_unknown_fields)] pub struct Quirks { #[serde(default)] pub services: BTreeMap<String, ServiceQuirk> }`;
  - `pub fn parse(text: &str) -> Result<Quirks, String>`, which is `toml::from_str` followed by these checks. Each error names the service:
    - `port` is not `0`;
    - `scheme` is `"http"` or `"https"`;
    - `host` is a DNS label (`dns_label(h) == Some(h)`);
  - `pub fn load(paths: &DevPaths, project: &str) -> Result<Quirks, DevError>`: `check_name(project)` first. A missing file is `Quirks::default()`. A read error is `Io`, and a parse error is `Quirks { path, msg }`.
- File format (plan 24's `docs/dev.md` copies it):
  ```toml
  [services.web]
  port = 3000        # the container port the proxy sends to
  scheme = "https"   # the app serves its own TLS
  host = "app"       # app.<project>.localhost instead of web.<project>.localhost
  [services.worker]
  skip = true        # no route
  ```

- [ ] **Step 1: failing tests:**
  - `parses_the_documented_example`: the block above gives `web = { port: Some(3000), scheme: Some("https"), host: Some("app"), skip: false }` and `worker.skip == true`;
  - `unknown_key_is_an_error`: `[services.web]\nprot = 3000` gives an `Err` that contains `prot`; so does a top-level `[service.web]`;
  - `bad_values_are_errors`: `port = 0`, `port = 70000`, `scheme = "ftp"` and `host = "App.x"` each give an `Err` that contains `web`;
  - `missing_file_is_empty`: `load` in an empty tempdir gives `Quirks::default()`;
  - `load_reports_the_path`: a bad file gives `DevError::Quirks { path }` with `path == paths.quirks_file("shop")`;
  - `load_rejects_a_bad_project_name` (Review Focus 1): `load(paths, "../shop")` gives `BadProjectName`, and no file is read.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean.
- [ ] **Step 5:** commit `feat(dev): per-project quirks from ~/.config/saiife/dev/<project>.toml`.

### Task 5: read the compose model (size M)

**Files:** modify `crates/dev/src/compose.rs`. Create `crates/dev/tests/fixtures/config-v2.json` (a current `config --format json` shape: string `published`, a range, `expose`, `network_mode`, `default` networks, a named volume, an external network) and `crates/dev/tests/fixtures/config-v1.json` (the compose-go v1.0 shape: numeric `published`). Both are written by hand from F3 to F8 and say so in a `"x-saiife-fixture"` key.

**Interfaces:**
- Consumes `Docker`, `run_ok`, `FakeDocker`, `Output` (Task 2), and `DevError` (Task 1).
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct PublishedPort { pub target: u16, pub published: Option<u16>, pub protocol: String }`;
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ServiceInfo { pub name: String, pub ports: Vec<PublishedPort>, pub expose: Vec<u16> }`;
  - `#[derive(Debug, Clone)] pub struct ComposeModel { pub raw: serde_json::Value, pub services: Vec<ServiceInfo> }`, with services sorted by name;
  - `pub fn parse_model(json: &[u8]) -> Result<ComposeModel, DevError>`. `ComposeJson(msg)` when the input is not a JSON object, when `services` is not an object, or when a `ports` entry is not an object. Ports and expose are read as in D1. `protocol` defaults to `"tcp"`. A `target` that is missing, `0`, or over 65535 is `ComposeJson` naming the service;
  - `pub fn read_config(d: &dyn Docker, dir: &Path) -> Result<ComposeModel, DevError>`:
    1. find the base and override files in `dir` (F10 order, D4), else `NoComposeFile { dir }`. A non-UTF-8 path is `NonUtf8Path`;
    2. run exactly `["compose", "--project-directory", <dir>, "-f", <base>, ("-f", <override>)?, "config", "--format", "json"]` with no stdin;
    3. on a non-zero exit whose stderr contains `is not a docker command` or `unknown command`, return `ComposeMissing`; any other failure is `run_ok`'s `Docker` error;
    4. `parse_model(stdout)`. stderr warnings (`version is obsolete`) are ignored on success.

- [ ] **Step 1: failing tests** (unit tests in `compose.rs`, where `cfg(test)` gives `FakeDocker`; the fixtures are loaded with `include_bytes!("../tests/fixtures/…")`):
  - `parses_current_shape`: `config-v2.json` gives the service `web` with `ports == [PublishedPort { target: 3000, published: Some(8080), protocol: "tcp" }]`; a range `"8000-8005"` gives `published: Some(8000)`; `expose: ["9000/tcp", "9001-9003", "53/udp"]` gives `[9000, 9001]`;
  - `parses_v1_shape`: `config-v1.json` (numeric `published: 8080`) gives the same `PublishedPort`;
  - `services_are_sorted`: the names come out in sorted order whatever the file order is;
  - `bad_shapes_are_compose_json`: `[]`, `{"services": []}` and a `ports: ["8080:80"]` entry give `ComposeJson`, and the last names the service;
  - `read_config_args`: a tempdir with `compose.yaml` and `compose.override.yml`, and FakeDocker `on(&["compose"], Output::ok(<v2 fixture>))`. One call, with args exactly `["compose","--project-directory",<dir>,"-f",<dir>/compose.yaml,"-f",<dir>/compose.override.yml,"config","--format","json"]`;
  - `base_file_order`: with both `docker-compose.yml` and `compose.yml` present, `compose.yml` is used, and no override `-f` is passed;
  - `no_compose_file`: an empty dir gives `NoComposeFile`, and FakeDocker saw no call;
  - `compose_plugin_missing_is_named` (Review Focus 4): `Output::fail(1, "docker: 'compose' is not a docker command.")` gives `ComposeMissing`;
  - `config_error_keeps_compose_stderr` (Review Focus 4): `Output::fail(15, "services.web Additional property foo is not allowed")` gives `Docker { status: 15, stderr }` with that text;
  - `stderr_warning_is_ignored`: status 0, a stderr warning and the fixture on stdout give `Ok`.
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; clippy is clean.
- [ ] **Step 5:** commit `feat(dev): read a repo's merged compose model with docker compose config --format json`.

### Task 6: rewrite the model and compute routes (size M)

**Files:** modify `crates/dev/src/rewrite.rs`. Tests are in `rewrite.rs` (unit), and use `compose::parse_model` on the Task 5 fixtures and on small `serde_json::json!` models.

**Interfaces:**
- Consumes `ComposeModel` and `ServiceInfo` (Task 5), `Quirks` and `ServiceQuirk` (Task 4), `check_name` and `dns_label` (Task 3), and `labels::{compose_project, label_map, NETWORK}` (Task 1).
- Produces (contract):
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Route { pub host: String, pub upstream: String, pub upstream_scheme: String, pub service: String }`, where `service` is the compose service name as written;
  - `#[derive(Debug, Clone)] pub struct Rewritten { pub model: serde_json::Value, pub routes: Vec<Route> }`, with routes sorted by `service`;
  - `pub fn rewrite(m: &ComposeModel, project: &str, q: &Quirks) -> Result<Rewritten, DevError>`. It works on a clone of `m.raw`, in this order:
    1. `check_name(project)`. Let `orig` be the string `raw["name"]` (missing gives `ComposeJson`), and `cp = compose_project(project)`;
    2. set the top-level `name` to `cp`;
    3. remove `ports` from every service;
    4. merge `label_map(project)` into every service's `labels` (an object; an array `["k=v"]` is first turned into an object). saiife's keys win;
    5. for each of `networks`, `volumes`, `configs` and `secrets` at the top level: an entry that is not `external` and whose `name == "<orig>_<key>"` gets `name = "<cp>_<key>"`, and `label_map` merged into its `labels` (D2). Other entries are left exactly as they are;
    6. pick routes as in D5. A routed service with no `networks` key gets `{"default": null}` first, and a top-level `default` network `{"name": "<cp>_default", "labels": label_map}` if there is none. It then gets `networks["saiife-dev"] = {"aliases": ["<label>.<project>"]}`;
    7. if any service is routed, add the top-level `networks["saiife-dev"] = {"name": "saiife-dev", "external": true}`. A user network key `saiife-dev` is `Rewrite("the network name saiife-dev is reserved for saiife")`, checked before any change (D3).

- [ ] **Step 1: failing tests:**
  - `strips_all_ports`: no service in `rewrite(config-v2)`'s model has a `ports` key, routed or not;
  - `sets_project_name`: `model["name"] == "saiife-shop"`;
  - `labels_every_service`: each service has `labels["saiife.managed"] == "true"` and `labels["saiife.dev.project"] == "shop"`, and a user label `com.example=1` is kept; an array `labels: ["a=b"]` becomes `{"a":"b", …saiife's}`;
  - `renames_default_named_resources` (Review Focus 2): with `name: "myrepo"`, the volume `data` with `name: "myrepo_data"` becomes `saiife-shop_data` with saiife's labels; the network `default` becomes `saiife-shop_default`;
  - `custom_and_external_resources_are_not_labelled` (Review Focus 2): a volume with `name: "pgdata"` and a network with `external: true` are byte-for-byte equal to the input (compare the `Value`s);
  - `route_from_published_target`: `web` with ports target 3000 gives `Route { host: "web.shop.localhost", upstream: "http://web.shop:3000", upstream_scheme: "http", service: "web" }`, and `web`'s networks hold `saiife-dev: {aliases: ["web.shop"]}` next to the `default: null` it had;
  - `route_from_expose`: no ports and `expose: ["9000"]` give port 9000; a service with neither gives no route and does not join `saiife-dev`;
  - `udp_only_gets_no_route`: ports with only `protocol: "udp"` and no expose give no route;
  - `quirks_apply`: `port = 4000`, `scheme = "https"` and `host = "app"` give `Route { host: "app.shop.localhost", upstream: "https://app.shop:4000", upstream_scheme: "https" }` and alias `app.shop`; `skip = true` gives no route and no `saiife-dev` entry, but the labels stay;
  - `network_mode_gets_no_route`: a service with `network_mode: "host"` and ports gives no route, and its model has no `networks` key added;
  - `service_names_become_labels` (Review Focus 3): service `Web_UI` gives host `web-ui.shop.localhost`, alias `web-ui.shop`, and `Route.service == "Web_UI"`;
  - `label_clash_is_an_error` (Review Focus 3): services `web_ui` and `web-ui`, both routed, give `Rewrite` whose message names both; a quirk `host = "api"` on `web` next to a routed service `api` clashes the same way;
  - `shared_network_added_once`: `model["networks"]["saiife-dev"] == {"name": "saiife-dev", "external": true}`; with no routed service, there is no such key;
  - `reserved_network_name`: a user network key `saiife-dev` gives `Rewrite`;
  - `bad_project_name`: `rewrite(m, "../x", q)` gives `BadProjectName`;
  - `routes_sorted_and_input_untouched`: routes are sorted by service; `m.raw` is unchanged after the call;
  - `dollar_strings_pass_through`: an `environment` value `"$$HOME"` and a `command` string `"echo $${X}"` are unchanged in the output (F13).
- [ ] **Step 2:** run the tests; expect FAIL.
- [ ] **Step 3:** implement. Run each step on `serde_json::Map`s. For the clash check, build a `BTreeMap<label, service>` before step 6 changes anything.
- [ ] **Step 4:** the tests pass; clippy is clean; the Windows check is clean.
- [ ] **Step 5:** commit `feat(dev): rewrite the compose model: no host ports, saiife labels, shared network aliases and routes`.

## Finish

- [ ] **Gates** (TMPDIR and SAIIFE_TEST_TMP under `mktemp -d -p /home/jonas/projects/personal/saiife`, `CARGO_INCREMENTAL=0`, `-j 4`, `--test-threads=4`):
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -j 4 -- -D warnings`;
  - `cargo test -p saiife-dev -j 4 -- --test-threads=4` and `cargo test -p saiife-dev --features fake -j 4 -- --test-threads=4`;
  - `cargo tree -e normal -p saiife-dev | grep -c tokio` prints `0`; `bash scripts/check-unsafe.sh`;
  - `bash scripts/check-windows.sh -p saiife-dev`; `cargo check -p saiife-dev --target aarch64-apple-darwin` if that target is installed (no C code in this crate, so no SDK is needed);
  - `scripts/test-offline.sh` (the crate makes no network calls).
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. The owner merges. Plans 23 and 24 start from the merged branch.

## Follow-ups (not in this plan)

- A quirk `keep_ports` (owner question 1).
- `COMPOSE_FILE` and `.env`-set compose files (D4). Read `COMPOSE_FILE` from the repo's `.env` if users ask.
- Routes for `network_mode: service:<x>` services, through `<x>`'s alias.

## Owner handwork

Nothing here runs on Claude's machine. These steps need a real Docker, so they are folded into plan 24's `scripts/dev-smoke.sh`. Run them by hand only if plan 24 is late.

- [ ] Answer owner question 1.
- [ ] On a machine with Docker and Compose v2 (`docker compose version` ≥ 2.0.0):
  1. In a sample repo, compare `docker compose config --format json` with `config-v2.json`'s shape (`published` a string, `expose` strings, `name` set, and `default` networks named `<folder>_default`). Report any difference, and the fixture is updated from it.
  2. **F13:** with a service `environment: {X: "$$HOME"}`, run `config --format json` and check that the output keeps `$$HOME`. Then `docker compose -f out.json config` must show `$HOME`, not the expanded home dir. If it is expanded, `rewrite` must escape `$` again (a follow-up task).
  3. `docker compose -p saiife-x -f <rewritten>.json config` accepts the rewritten model, including the external `saiife-dev` network and the renamed volumes.
