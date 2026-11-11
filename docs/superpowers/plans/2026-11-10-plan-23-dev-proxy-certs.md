# Plan 23: `saiife dev` proxy and certificates: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife-dev` gains its own local CA and per-project certificates (`certs.rs`), and one Traefik proxy container that owns 127.0.0.1:80/443 on the shared `saiife-dev` network, fed only by TOML files that saiife writes (`proxy.rs`). Plan 24's `saiife dev up` can then call, in this order: `preflight_ports`, `ensure_network`, `ensure_proxy`, `ensure_ca`, `ensure_project_cert`, `write_routes`.

**Architecture:**
- **Certificates:** an ECDSA P-256 CA made with rcgen. It is name-constrained to `localhost` and kept at `<state>/ca/`, with the key at mode 0600. Each project gets one leaf for `*.<project>.localhost` and `<project>.localhost`, at `<state>/tls/<project>/` (D9: outside `<state>/projects`, so the proxy never sees `compose.json`). The CA is reloaded with no X.509 parsing: the issuer is rebuilt from fixed parameters and the stored key (D3).
- **The proxy:** Traefik v3 with only its file provider. It has no docker provider and no socket mount. Two directories are mounted read-only: `<state>/proxy/dynamic` (routes, watched) and `<state>/tls` (leaf certs only). `<state>/projects` (which holds `compose.json` with `.env` values) and the CA directory are never mounted.
- **Docker:** all of it goes through plan 22's `Docker` trait (`docker` CLI subprocess). Every test uses `FakeDocker`.

**Tech Stack:** Rust, sync code in `crates/dev` (`saiife-dev`, made by plan 22). Dependencies:
- `rcgen =0.14.10` (`default-features = false, features = ["ring", "pem", "crypto"]`, as in `crates/cli/Cargo.toml`);
- `time`, `toml`, `serde` and `serde_json` are already in `crates/dev/Cargo.toml` from plan 22 (`time = { version = "0.3", features = ["formatting", "macros"] }`). Do not add a second line for any of them; `rcgen` is the only new `[dependencies]` line.

Dev-dependencies: `rustls =0.23.45` (`default-features = false, features = ["ring", "std", "tls12"]`), for verifying the chain in tests, added next to plan 22's `tempfile = "3"`. Every crate here is already in `Cargo.lock`, so there is no new dependency.

**Spec:**
- `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5.1 and §6.
- The binding step 1 contract (`v3-step1-dev-contract.md`, handed to the builder with this plan). Spec §6 already agrees with it: rcgen, the docker CLI, and a fake `docker`.
- Read plan 22 first. This plan consumes its interfaces exactly as the contract names them.

## Contract changes

These are additions and clarifications. No contract name is renamed. Plan 24's builder must read this list.

1. **No shared TLS file is written.** Each project's certificate goes in its own `<state>/proxy/dynamic/<project>.toml`, next to its routers. Traefik merges `tls.certificates` across the files in the directory (F3). So `remove_routes` removes the project's certificate entry too, and no shared file has to be rewritten.
   - The plan 24 author renamed the contract's `tls.toml` to `_tls.toml`, so that a project named `tls` cannot collide with it. The name stays reserved as `proxy::TLS_FILE = "_tls.toml"` for any shared TLS options later. A leading `_` is never a valid project label, so it never collides.
   - This plan does not create that file. `write_routes`, `remove_routes` and `stop_proxy_if_unused` ignore it.
   - Route files stay `<project>.toml`. Plan 24's `gc` removes only route files whose stem is a valid project name.
2. **New label `proxy::ROLE = "saiife.dev.role"`.** The shared network carries `saiife.dev.role=network` and the proxy container carries `saiife.dev.role=proxy`. Both carry `saiife.managed=true` but **no** `saiife.dev.project`. Plan 24's `gc` must not remove role-labelled resources directly. It calls `stop_proxy_if_unused` instead.
3. **`Route.upstream`:** plan 22 pins it as the full URL (`http://web.shop:3000`), and `Route.host` as the full host (`web.shop.localhost`). `write_routes` uses an upstream that starts with `http://` or `https://` as it is. As a tolerance only, a bare `<service>.<project>:<port>` gets `<upstream_scheme>://` in front. Both are tested.
4. **Call order for plan 24:** `preflight_ports`, `ensure_network`, `ensure_proxy`, `ensure_ca`, `ensure_project_cert`, then (after `compose up`) `write_routes`. In particular:
   - `ensure_project_cert` before `write_routes`;
   - `write_routes` on every `up`, even when nothing has changed. A reissued certificate is read only when the dynamic directory changes (F4), and the rewrite is that change.
5. **Added public items:**
   - `certs::LEAF_DAYS`, `certs::CA_DAYS`, `certs::RENEW_BEFORE_DAYS`;
   - `proxy::PROXY_IMAGE`, `proxy::ROLE`, `proxy::TLS_FILE`, `proxy::Probe`, `proxy::preflight_ports_with`.
6. **Added `DevError` variants** (in `crates/dev/src/error.rs`, plan 22's file):
   - `Cert(String)`;
   - `CaInvalid { path: PathBuf, reason: String }`;
   - `RouteHost { host: String, reason: &'static str }`;
   - `PortBusy { port: u16, holder: Option<String> }`;
   - `NotOurs { kind: &'static str, name: String }`.

   They go, with their `Display` arms, under a `// plan 23` comment (plan 22's rule). File errors use plan 22's `Io { path: PathBuf, source: io::Error }`; this plan adds no `Io` variant. A project name is checked with plan 22's `project::check_name` (`BadProjectName`).
7. **A seam for the port check:**
   - `SAIIFE_DEV_SKIP_PORT_BIND=1` is read only under `cfg(debug_assertions)`. It makes the host bind probe answer `Probe::Unknown` without binding, so the check falls through to the `docker ps --filter publish=` lookup, which a fake docker answers. Release builds never read it.
   - For library tests there is also `pub fn preflight_ports_with(d: &dyn Docker, probe: &dyn Fn(u16) -> Probe)`, with `pub enum Probe`.

## Facts checked (2026-11-10)

**D** marks a fact that changes the design. The changes are listed after the table.

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | The file provider takes `providers.file.directory` (or `filename`; the two are mutually exclusive). `providers.file.watch` defaults to `true`. Watching uses fsnotify. If a bind mount loses the link to its source, for example because a mounted *file* is renamed, updates stop. The docs say to mount the parent directory. | doc.traefik.io, reference › providers › others › file | **D1.** saiife mounts directories, never files. Every write is a temp file plus a rename inside the mounted directory. |
| F2 | A directory load recurses into subdirectories and reads only `.toml`, `.yaml` and `.yml` files. Any event in the watched directory reloads the whole directory. If **one** file fails to parse, the whole load fails. Files are parsed as Go templates (`parseTemplate = true`). | traefik `pkg/provider/file/file.go` at tag v3.7.16 (`collectFileConfigs`, `isFileSupported`, `addWatcher`, `loadFileConfig`) | **D1.** Temp files are named `.<project>.toml.tmp`, so they are skipped. Output is built from validated hosts and names only (no `{{`), and a test parses every file saiife writes. One bad project file would take down every project's routes. |
| F3 | Files in a directory are merged with `ResourceStrategySkipDuplicates`: a router or service name that appears twice is skipped. `tls.certificates` are appended across files (`mergeCertificates`). | traefik `pkg/provider/merge.go` v3.7.16 | Contract change 1. Every router, service and transport name is prefixed `<project>-`, so names cannot collide across projects. |
| F4 | `certFile` and `keyFile` contents are read when the configuration loads (`flattenCertificates`). The watcher watches only the dynamic directory. | `file.go` v3.7.16 | **D2.** A new leaf is picked up only after the next change in the dynamic directory. Contract change 4. |
| F5 | Outside Kubernetes, the file provider is the only way to configure TLS certificates. `stores` is ignored and set to `["default"]`. The certificate is chosen by SNI during the handshake. With no match, Traefik serves the default certificate, which it generates itself if none is set. | doc.traefik.io, routing › http › tls › tls-certificates | Confirmed. A host saiife does not serve gets Traefik's own certificate, which the browser rejects. That is the right outcome for a name saiife does not know. |
| F6 | `--entryPoints.<name>.address`, `--entryPoints.<name>.http.redirections.entryPoint.to`, `.scheme` and `.permanent`. "The target element can be an entry point name (ex: `websecure`), or a port (`:443`)." | doc.traefik.io, reference › install-configuration › entrypoints | **D4.** The container listens on 8080 and 8443, and the host publishes them as 80 and 443. The redirect goes to `:443`. The container then needs no capability and no sysctl to bind, and can run as the user's uid. |
| F7 | `[http.serversTransports.<n>] insecureSkipVerify = true`, referenced from `[http.services.<s>.loadBalancer] serversTransport = "<n>"`. | doc.traefik.io, routing › http › load-balancing › serverstransport | Used only for routes with `upstream_scheme = "https"` (a dev server with its own self-signed certificate). |
| F8 | Traefik enables only the providers its static configuration names. | Traefik static configuration model (no docker flag means no docker provider) | No `--providers.docker*` flag and no `/var/run/docker.sock` mount. A test asserts both are absent, and owner handwork 2c checks the running container. |
| F9 | The newest Traefik v3 release is v3.7.17 (2026-10-30, 11 days old, which is too young). The one before it is v3.7.16 (2026-10-20). | github.com/traefik/traefik/releases | `PROXY_IMAGE = "traefik:v3.7.16"`. The owner adds the digest (owner handwork 1). |
| F10 | Firefox 84 and later resolve `localhost` and `*.localhost` to loopback themselves (bug 1220810, RFC 6761 §6.3). Chrome does the same. curl 7.78 and later resolve `*.localhost` to loopback. | bugzilla.mozilla.org 1220810; daniel.haxx.se 2021-05-31; Chrome behaviour not re-read here | No hosts-file edits. Browsers may try `::1` first. The proxy publishes on 127.0.0.1 only (D5), and owner handwork 2 checks that the fallback is quick. |
| F11 | Browsers refuse a wildcard directly under a top-level name. mkcert warns that "many browsers don't support second-level wildcards like `*.localhost`", and Chrome was reported to reject one. A wildcard matches exactly one label. | teratail 218121 (mkcert warning, 2019); serverfault 811111 | **D3.** The leaf carries `*.<project>.localhost`, a third-level wildcard, plus `<project>.localhost`. `write_routes` refuses a host that is deeper than one label under the project. Owner handwork 2a confirms Chrome and Firefox accept it. If either does not, the fallback is per-host SANs, which needs a contract change (`ensure_project_cert` would take the hosts). |
| F12 | Apple, for TLS server certificates issued after 2019-07-01: the name must be in the SAN, EKU `serverAuth` is required, and validity must be 825 days or fewer. The later 398-day rule "will not affect certificates issued from user-added or administrator-added Root CAs". Chrome's root policy does not apply to locally trusted CAs. | support.apple.com 103769 and 102028; chromium.org root-ca-policy | `LEAF_DAYS = 365`, reissued when fewer than `RENEW_BEFORE_DAYS = 30` remain. The leaf has SAN DNS names only, EKU `ServerAuth`, and key usage `DigitalSignature`. |
| F13 | rcgen 0.14.10 provides: `CertificateParams.name_constraints: Option<NameConstraints { permitted_subtrees, excluded_subtrees }>`, `GeneralSubtree::DnsName(String)`, `KeyPair::generate()` (P-256), `KeyPair::from_pem`, `Issuer::new(params, key)` (uses only the DN, the key-id method and the key usages), and `CertificateParams::signed_by(&pubkey, &issuer)`. `Issuer::from_ca_cert_pem` needs the `x509-parser` feature, which the workspace does not enable. | `~/.cargo/registry/src/*/rcgen-0.14.10/src/{lib.rs,certificate.rs,key_pair.rs}` | **D3.** The CA reloads through `Issuer::new(ca_params(created), key)`, so no feature is added. The authority key id is the SHA-256 of the CA key in both certificates, so the IDs match. |
| F14 | With no `serial_number`, rcgen derives the serial from the SHA-256 of the subject public key. | rcgen `certificate.rs` 458-468 | **D3.** Every issuance makes a **new key**. Reusing a key would repeat the issuer and serial pair, which Firefox rejects (`SEC_ERROR_REUSED_ISSUER_AND_SERIAL`). |
| F15 | Name constraints on a trust anchor: webpki (rustls) enforces them. Chrome 112 and later were reported to enforce them for user-imported roots, which is not confirmed in release notes. | rustls-webpki 0.103 trust-anchor handling; robalexdev.substack.com "name constraint on chrome" (2023) | Defence in depth only. The real control is the 0600 key that never leaves `<state>/ca/`. The tests prove the constraint with webpki. |
| F16 | `docker ps --filter publish=<port>[/<proto>]` lists containers that publish or expose a port. The `name` filter matches any part of the name, with no anchors. `--format '{{.Names}}'`. | docs.docker.com, reference › docker container ls | **D6.** saiife filters by label and then compares names exactly. It never relies on the `name` filter alone. |
| F17 | Linux: an unprivileged `bind(127.0.0.1:80)` fails with `EACCES` while `net.ipv4.ip_unprivileged_port_start` is 1024 (the default), and with `EADDRINUSE` if a listener holds the port (also through `0.0.0.0`). Rootful Docker publishes through a root `docker-proxy`, so the user's `EACCES` says nothing about the port. | ip(7); kernel `ip-sysctl` docs | **D6.** `EADDRINUSE` means the port is busy. `EACCES` means unknown, and the check then asks `docker ps --filter publish=`. A failure in `docker run` or `docker start` that names an address in use becomes `PortBusy` too. |

### Design notes (flagged for the owner)

- **D1. Atomic writes everywhere.**
  - Each file is written to a dot-named temp file in the same directory, then renamed over the target.
  - Keys are opened with mode 0600 at creation (`OpenOptionsExt::mode`, Unix only).
  - Before `docker run`, `ensure_proxy` creates `<state>/proxy/dynamic` and `<state>/tls`. If they were missing, Docker would create them, owned by root.
- **D2. A reissued certificate needs a route rewrite** (F4). `write_routes` always renames a fresh file, even when the content is the same, so Traefik reloads every time.
- **D3. CA design.**
  - The DN is fixed, `CN=saiife dev CA, OU=created <YYYY-MM-DD>`, with the date from `ca.json`. The CA can then be rebuilt with no parser (F13), and two CAs in one trust store can be told apart.
  - `BasicConstraints` has path length 0, with key usages `KeyCertSign`, `CrlSign` and `DigitalSignature`. The permitted subtree is `DnsName("localhost")`, and validity is `CA_DAYS = 3650`.
  - A broken or partial CA directory is **never** regenerated silently: that would quietly break the trust the user installed. It gives `CaInvalid`, which names the directory and says to delete it and trust the new CA.
  - Two `up` runs at once: each builds the CA in `<state>/.ca.tmp-<pid>-<nanos>` and renames it to `<state>/ca`. The loser deletes its own copy and loads the winner's.
- **D4. The container**, with fixed `docker run` arguments (Task 5):
  - read-only root filesystem with a `/tmp` tmpfs, `--cap-drop ALL`, `no-new-privileges`;
  - on Unix, `--user <uid>:<gid>` of the owner of `paths.state` (from `MetadataExt`, so no `unsafe`), so that it can read the user's 0600 leaf keys;
  - container ports 8080 and 8443 (F6).
- **D5. Loopback only.** `-p 127.0.0.1:80:8080 -p 127.0.0.1:443:8443`. A phone on the LAN cannot reach a dev app (settled: loopback only). There is no `[::1]` publish: on daemons without IPv6 support it can make `docker run` fail, and browsers fall back to 127.0.0.1 (F10).
- **D6. Port pre-flight.**
  - If the running `saiife-dev-proxy` (label match, then an exact name match) already holds 80 and 443, the check passes.
  - Otherwise each port is checked with a plain `TcpListener::bind` on 127.0.0.1. No process tool is used.
  - When the bind says "unknown" (`EACCES`), a container that publishes the port is looked for by name. The last word goes to the error from `docker run` or `docker start` (F17).
  - Known limit: a non-Docker program on port 80, on a host where the user cannot bind 80, is reported only when `docker run` fails, as `PortBusy { holder: None }`.
- **D7. Drift.** The proxy carries `saiife.dev.proxy-spec=<16 hex>`, the FNV-1a 64-bit hash of its full `docker run` argument list. Different arguments (image, paths, uid) mean `rm -f` and run again. FNV is hand-written (6 lines). It is not security-relevant.
- **D8. Restart policy `unless-stopped`.** After a reboot the proxy returns together with project containers whose own policy brings them back (settled: keep).

- **D9. Certificates live outside the project state (orchestrator, 2026-11-10).** The proxy runs as the user's uid with a read-only mount, so whatever is mounted it can read. Mounting `<state>/projects` would expose every project's `compose.json` (`.env` values). Leaf certs therefore live in `<state>/tls/<p>/`, and only `<state>/tls` is mounted. Test `run_args_are_locked_down` also asserts no argument contains `/projects`.

### Owner questions

None. Settled on 2026-11-10: D8 keeps `--restart unless-stopped` (the proxy is removed with the last project anyway), and D5 keeps loopback only; LAN access for phone testing is a later opt-in.

## Consumes (plan 22, names from the contract)

- `Docker`, `Output { status, stdout, stderr }` (with `Output::ok(stdout)` and `Output::fail(status, stderr)`), `run_ok`, and `FakeDocker` from `docker.rs`. FakeDocker's API (plan 22 Task 2): `FakeDocker::new()`; `on(&[prefix..], Output)` (sticky; a later `on` wins); `once(&[prefix..], Output)` (used once, before any `on`); `calls() -> Vec<Call { args: Vec<String>, stdin: Option<Vec<u8>> }>`; an unscripted call answers status `125`. Every scripted reply in this plan's tests is an `on` or `once`.
- `DevPaths { state, config }`, `project_dir`, `proxy_dir` (`<state>/proxy`) and `ca_dir` (`<state>/ca`) from `paths.rs`.
- `MANAGED`, `PROJECT`, `NETWORK` and `PROXY_CONTAINER` from `labels.rs`.
- `project::{dns_label, check_name}` and `rewrite::Route { host, upstream, upstream_scheme, service }`.
- `DevError` from `error.rs`, and its `Io { path, source }`, `BadProjectName` and `Docker { args, status, stderr }` variants.

Where plan 22 landed something under another name, the code wins. Adjust the task before starting it.

## Global Constraints

- Hard rules (`.superpowers/sdd/hard-rules.md`) are binding:
  - never run docker, not even `docker --version`. Tests use `FakeDocker`, or a fake `docker` script via `SAIIFE_DOCKER`;
  - no network in tests (loopback binds only);
  - `TMPDIR` and `SAIIFE_TEST_TMP` from `mktemp -d -p /home/jonas/projects/personal/saiife`, with `XDG_*` and `HOME` pointed at tempdirs;
  - `CARGO_INCREMENTAL=0`, `-j 4`, `-- --test-threads=4`;
  - `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` before every commit.
- **No `unsafe`.** `saiife-dev` keeps `[lints] workspace = true`.
- **No new crates.** Only the versions listed under Tech Stack, all already in `Cargo.lock`.
- **Fixed values:**
  - `LEAF_DAYS = 365`, `CA_DAYS = 3650`, `RENEW_BEFORE_DAYS = 30`;
  - `not_before = now - 1 hour` for both certificates;
  - key type: ECDSA P-256 (`KeyPair::generate()`).
- **Files:**
  - `<state>/ca/` (mode 0700) holds `ca.pem` (0644), `ca-key.pem` (0600) and `ca.json` (`{"created": <unix s>, "not_after": <unix s>}`);
  - `<state>/tls/<p>/` (mode 0700; `<state>/tls` itself 0700) holds `cert.pem` (the leaf only), `key.pem` (0600) and `meta.json` (`{"sans": [..], "ca_key": "<hex of CA public_key_raw>", "not_after": <unix s>}`);
  - `<state>/proxy/dynamic/<p>.toml`.
- **The proxy container:**
  - mounts, both `:ro`: `<state>/proxy/dynamic` at `/saiife/dynamic` and `<state>/tls` at `/saiife/tls`;
  - never mounts `<state>/ca` or the docker socket;
  - carries the labels `saiife.managed=true`, `saiife.dev.role=proxy` and `saiife.dev.proxy-spec=<hash>`;
  - the network carries `saiife.managed=true` and `saiife.dev.role=network`.
- **Traefik flags**, exactly:
  - `--providers.file.directory=/saiife/dynamic` and `--providers.file.watch=true`;
  - `--entryPoints.web.address=:8080`, `--entryPoints.web.http.redirections.entryPoint.to=:443`, `--entryPoints.web.http.redirections.entryPoint.scheme=https` and `--entryPoints.web.http.redirections.entryPoint.permanent=true`;
  - `--entryPoints.websecure.address=:8443`;
  - `--global.checkNewVersion=false`, `--global.sendAnonymousUsage=false` and `--log.level=INFO`.
- **Portability:** the crate builds on macOS and Windows. Modes and `--user` are `#[cfg(unix)]`, and no field is left unread off Unix.

## Review Focus

1. **A second `saiife dev up` while the first is still creating the CA.** Expected: one CA, with key and certificate matching, and both runs return the same `Ca` (Task 1: `concurrent_ensure_ca_yields_one_ca`).
2. **A user's existing web server on port 80 or 443**, or a foreign container named `saiife-dev-proxy`, or a network named `saiife-dev`. Expected: a clear `PortBusy` or `NotOurs` that names the holder. Nothing that saiife does not own is removed or reused (Task 4: `busy_port_names_the_container`, `foreign_network_is_refused`; Task 5: `foreign_container_is_refused`).
3. **`docker run` fails halfway**, for example with the port taken after the pre-flight. Expected: the created container is removed, so the next `up` starts clean, and the error is `PortBusy` (Task 5: `failed_run_removes_the_container`).
4. **A route host Traefik or the certificate cannot serve:** two labels deep (`a.b.shop.localhost`), outside the project (`web.other.localhost`), or with a backtick, a brace or upper case. Expected: `RouteHost` is returned **before** any file is written. A bad file would stop every project's routes (F2) (Task 3: `bad_hosts_write_nothing`).
5. **The CA's key mode was loosened by hand, or the CA directory was half deleted.** Expected: `CaInvalid` that names the path. saiife never quietly makes a new CA (Task 1: `loose_key_mode_is_refused`, `partial_ca_dir_is_refused`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (the CA; adds `Ca`, `CertPaths` and the cert `DevError` variants).
- **Wave 2 (in parallel):** Task 2 (project leaf, `certs.rs`) and Task 3 (route files, `proxy.rs`).
- **Wave 3:** Task 4 (pre-flight and network), then Task 5 (the proxy container). Both are in `proxy.rs`, so they run one after the other.
- **Shared files:**
  - `crates/dev/src/error.rs`: Tasks 1, 3 and 4 add variants;
  - `crates/dev/Cargo.toml`: Task 1 only.

---

### Task 1: the local CA (size M)

**Files:**
- Create `crates/dev/src/certs.rs` (with `#[cfg(test)] mod tests`).
- Modify `crates/dev/src/lib.rs` (`pub mod certs;`; plan 22 declares only its own modules), `crates/dev/src/error.rs` (`Cert`, `CaInvalid`) and `crates/dev/Cargo.toml` (rcgen, and the rustls dev-dependency; nothing else).

**Interfaces (Produces):**
- `pub struct Ca { pub cert_pem: String, pub key_path: PathBuf, pub cert_path: PathBuf }` and `pub struct CertPaths { pub cert: PathBuf, pub key: PathBuf }`.
- `pub const CA_DAYS: i64 = 3650; pub const LEAF_DAYS: i64 = 365; pub const RENEW_BEFORE_DAYS: i64 = 30;`
- `pub fn ensure_ca(paths: &DevPaths) -> Result<Ca, DevError>`, which calls `ensure_ca_at(paths, OffsetDateTime::now_utc())`.
- `pub(crate) fn ensure_ca_at(paths: &DevPaths, now: OffsetDateTime) -> Result<Ca, DevError>`.
- `pub(crate) fn ca_issuer(ca: &Ca) -> Result<(Issuer<'static, KeyPair>, Vec<u8> /* CA public_key_raw */), DevError>`. It reads `ca.json` next to `ca.cert_path` and the key at `ca.key_path`, and rebuilds `ca_params(created)`.
- `fn ca_params(created: OffsetDateTime, now: OffsetDateTime) -> CertificateParams` (D3 values).
- `pub(crate) fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), DevError>`. It writes the dot-named temp file and renames it into place; with `secret`, the mode is 0600 at open. Task 2 and Task 3 reuse it.

- [ ] **Step 1: failing tests** (`certs::tests`, with `DevPaths { state: tmp.join("state"), config: tmp.join("config") }`):
  - `first_call_creates_ca_files`: `ca.pem`, `ca-key.pem` and `ca.json` exist. `Ca.cert_pem` equals the contents of `ca.pem`. On Unix the key is mode `0o600` and the directory `0o700`.
  - `second_call_reuses_ca`: two calls give the same `cert_pem`.
  - `ca_is_name_constrained_to_localhost`, with rustls/webpki and `ca.pem` as the only root:
    - a leaf for `web.shop.localhost`, signed through `ca_issuer` by a test helper, verifies;
    - a leaf for `evil.example`, signed the same way, fails with a name-constraint error.
  - `reloaded_issuer_matches_stored_ca`: from a second `Ca` value read back from disk, a leaf verifies against `ca.pem` (this proves the DN, the key id and the key match, D3).
  - `loose_key_mode_is_refused` (Unix): chmod the key to 0644. The next call gives `CaInvalid { path: <ca-key.pem>, .. }`.
  - `partial_ca_dir_is_refused`: delete `ca-key.pem`. The result is `CaInvalid`, and `ca.pem` is unchanged.
  - `expiring_ca_is_refused`: `ensure_ca_at(now + 3650 - 29 days)` gives `CaInvalid`, and the reason contains `expires`.
  - `concurrent_ensure_ca_yields_one_ca`: 4 threads call `ensure_ca` on one fresh state. All `cert_pem` values are equal, and no `.ca.tmp-*` is left in `<state>`.
- [ ] **Step 2:** `cargo test -p saiife-dev certs -- --test-threads=4`. Expect FAIL (not defined).
- [ ] **Step 3:** implement. `ensure_ca_at`:
  1. If the CA directory exists, load and check it.
  2. Otherwise build in a temp directory and `fs::rename` it into place.
  3. If that rename fails and the CA directory now exists, remove the temp directory and load.
- [ ] **Step 4:** the tests pass. `cargo clippy -p saiife-dev --all-targets -- -D warnings` is clean.
- [ ] **Step 5:** commit `feat(dev): a local CA for saiife dev, name-constrained to localhost`.

### Task 2: per-project certificates (size S)

**Files:** Modify `crates/dev/src/certs.rs`.

**Interfaces:**
- Consumes `Ca`, `CertPaths`, `ca_issuer` and `write_atomic` (Task 1), `DevPaths::project_dir` and `project::check_name` (called first).
- Produces `pub fn ensure_project_cert(paths: &DevPaths, ca: &Ca, project: &str) -> Result<CertPaths, DevError>`, which calls `ensure_project_cert_at(.., OffsetDateTime::now_utc())`. It returns `<state>/tls/<project>/cert.pem` and `key.pem`. Produces `pub fn tls_dir(paths: &DevPaths) -> PathBuf` (`<state>/tls`) and `pub fn remove_project_cert(paths: &DevPaths, project: &str) -> Result<(), DevError>` (idempotent; plan 24's `gc` calls it for a missing project).
- Produces `pub fn project_sans(project: &str) -> Vec<String>`, which returns `["*.<project>.localhost", "<project>.localhost"]`. Task 3 uses the same rule for hosts.

- [ ] **Step 1: failing tests:**
  - `leaf_verifies_for_project_hosts`: with webpki and `ca.pem` as the root, `web.shop.localhost` and `shop.localhost` verify at `now`.
  - `leaf_rejects_other_hosts`: `a.web.shop.localhost` and `web.other.localhost` fail to verify.
  - `leaf_lifetime_is_365_days`: it verifies at `now + 364 days` and fails at `now + 366 days`.
  - `leaf_key_is_private` (Unix): `key.pem` is 0600 and `tls/` is 0700.
  - `unchanged_leaf_is_reused`: a second call leaves `cert.pem` unchanged, byte for byte.
  - `leaf_is_reissued`: in each of these cases the second call writes a different `cert.pem` **and** a different `key.pem` (F14):
    - `ensure_project_cert_at(now + 336 days)`, that is, fewer than 30 days left;
    - after `meta.json` is edited to another `ca_key`;
    - after `key.pem` is deleted.
  - `bad_project_name_is_refused`: `"Shop"`, `"a/b"` and `""` give an error, and nothing is created.
- [ ] **Step 2:** `cargo test -p saiife-dev certs`. Expect FAIL.
- [ ] **Step 3:** implement. The leaf parameters are:
  - SANs `project_sans`; DN `CN=<project>.localhost`; `IsCa::NoCa`;
  - EKU `ServerAuth`, key usage `DigitalSignature`, `use_authority_key_identifier_extension = true`;
  - a new `KeyPair::generate()` every time.

  Write `key.pem`, then `cert.pem`, then `meta.json`, last. When `meta.json` is missing or does not match, the leaf is reissued.
- [ ] **Step 4:** the tests pass. Clippy is clean.
- [ ] **Step 5:** commit `feat(dev): per-project certificates for *.<project>.localhost`.

### Task 3: route files (size M)

**Files:** Create `crates/dev/src/proxy.rs` (route part, with tests). Modify `crates/dev/src/error.rs` (`RouteHost`) and `lib.rs` (`pub mod proxy;`).

**Interfaces:**
- Consumes `Route` (plan 22), `CertPaths`, `project_sans` and `write_atomic` (Tasks 1 and 2), and `DevPaths::proxy_dir` and `project_dir`.
- Produces:
  - `pub fn write_routes(paths: &DevPaths, project: &str, routes: &[Route], cert: &CertPaths) -> Result<(), DevError>`;
  - `pub fn remove_routes(paths: &DevPaths, project: &str) -> Result<(), DevError>`;
  - `pub(crate) fn dynamic_dir(paths: &DevPaths) -> PathBuf` (`<proxy_dir>/dynamic`).
- The file format is per project `p` and route `r`, with the name `n = "<p>-<r.service>"`:

```toml
[http.routers."<n>"]
rule = "Host(`<r.host>`)"
entryPoints = ["websecure"]
service = "<n>"
[http.routers."<n>".tls]

[http.services."<n>".loadBalancer]
serversTransport = "<p>-insecure"          # only when the scheme is https
[[http.services."<n>".loadBalancer.servers]]
url = "<scheme>://<host:port>"             # contract change 3

[http.serversTransports."<p>-insecure"]    # only if any route is https
insecureSkipVerify = true

[[tls.certificates]]
certFile = "/saiife/tls/<p>/cert.pem"
keyFile = "/saiife/tls/<p>/key.pem"
```

  Serialize it through `toml` from `serde` structs held in `BTreeMap`s, so the order is fixed. Do not build the TOML from strings.

- [ ] **Step 1: failing tests** (each file is read back with `toml::from_str::<toml::Value>`):
  - `routes_file_has_router_service_and_cert`: routes `web` (`web.shop.localhost` → `web.shop:3000`, http) and `api` (`api.shop.localhost`, https). Assert:
    - router `shop-web` has rule ``Host(`web.shop.localhost`)``, entryPoints `["websecure"]` and a `tls` table;
    - the URL of `shop-api` is `https://api.shop:8443`, and its `serversTransport` is `shop-insecure`;
    - `shop-insecure.insecureSkipVerify = true`;
    - `tls.certificates[0].certFile = "/saiife/tls/shop/cert.pem"`.
  - `full_url_upstream_is_kept`: `upstream = "http://web.shop:3000"` gives that URL, with no second scheme.
  - `bad_hosts_write_nothing`: each of these gives `RouteHost`, and no `shop.toml` and no temp file exist afterwards:
    - `a.b.shop.localhost`, `web.other.localhost`, ``we`b.shop.localhost``, `Web.shop.localhost`, `{{x}}.shop.localhost`;
    - two routes that both use the service name `web`.
  - `apex_host_is_allowed`: `shop.localhost` is accepted.
  - `cert_outside_project_is_refused`: `CertPaths` outside `<state>/tls/<project>/` gives `RouteHost`, with the reason `certificate is not in the project's tls directory`.
  - `rewrite_always_renames`: calling `write_routes` twice with the same input changes the file's inode on Unix (D2).
  - `empty_routes_remove_the_file`; `remove_routes_is_idempotent`.
  - `no_template_braces_in_output`: no written file contains `{{`.
- [ ] **Step 2:** `cargo test -p saiife-dev proxy`. Expect FAIL.
- [ ] **Step 3:** implement. A host is accepted when:
  - it matches `^[a-z0-9-]+(\.[a-z0-9-]+)*$` (checked by hand, with no regex dependency);
  - and it equals `<p>.localhost` or is exactly one label plus `.<p>.localhost`.

  The project must pass `project::check_name(p)`. Validate everything first, then write once.
- [ ] **Step 4:** the tests pass. Clippy is clean.
- [ ] **Step 5:** commit `feat(dev): Traefik route files for each project`.

### Task 4: port pre-flight and the shared network (size S)

**Files:** Modify `crates/dev/src/proxy.rs` and `crates/dev/src/error.rs` (`PortBusy`, `NotOurs`).

**Interfaces:**
- Consumes `Docker`, `Output`, `FakeDocker`, `MANAGED`, `NETWORK` and `PROXY_CONTAINER`.
- Produces:
  - `pub const ROLE: &str = "saiife.dev.role";`;
  - `pub const TLS_FILE: &str = "_tls.toml";` (reserved, never written; contract change 1);
  - `pub fn preflight_ports(d: &dyn Docker) -> Result<(), DevError>`, which calls `preflight_ports_with(d, &probe_bind)`;
  - `pub enum Probe { Free, InUse, Unknown }`;
  - `pub(crate) fn probe_bind(port: u16) -> Probe`:
    - in debug builds only (`#[cfg(debug_assertions)]`), `SAIIFE_DEV_SKIP_PORT_BIND=1` returns `Unknown` with no bind (the seam for plan 24's tests);
    - otherwise `TcpListener::bind(("127.0.0.1", port))`: `AddrInUse` gives `InUse`, `PermissionDenied` gives `Unknown`, `Ok` gives `Free`, and any other error gives `Unknown`;
  - `pub fn preflight_ports_with(d: &dyn Docker, probe: &dyn Fn(u16) -> Probe) -> Result<(), DevError>`;
  - `pub fn ensure_network(d: &dyn Docker) -> Result<(), DevError>`.
- Docker calls, exactly:
  - is the proxy up: `ps --filter label=saiife.managed=true --filter label=saiife.dev.role=proxy --format {{.Names}}`;
  - who holds a port: `ps --filter publish=<port> --format {{.Names}}`;
  - `network inspect saiife-dev --format {{json .Labels}}`;
  - `network create --driver bridge --label saiife.managed=true --label saiife.dev.role=network saiife-dev`.
- `PortBusy` Display: `port <port> on 127.0.0.1 is in use by container <name>; stop it, then run saiife dev up again`, or with no holder, `... is in use by another program; ...`.

- [ ] **Step 1: failing tests:**
  - `probe_sees_a_held_port`: a test `TcpListener` on `127.0.0.1:0` makes `probe_bind(its port)` return `InUse`.
  - `skip_env_makes_probe_unknown`: with `SAIIFE_DEV_SKIP_PORT_BIND=1` set, `probe_bind` on a held port returns `Unknown`. The test is `#[cfg(debug_assertions)]` and sets the variable inside a test-local lock: `std::env::set_var` is process-wide, so the other probe tests take the same lock.
  - `running_proxy_passes`: `ps` replies `saiife-dev-proxy\n`. The probe is never called (a probe that panics proves it).
  - `similar_name_is_not_the_proxy`: `ps` replies `saiife-dev-proxy-old\n`. The probe is called (F16).
  - `free_ports_pass`.
  - `busy_port_names_the_container`: the probe gives `InUse` for 443, and `ps --filter publish=443` replies `web-1`. The result is `PortBusy { port: 443, holder: Some("web-1") }`.
  - `unknown_port_with_no_container_passes`.
  - `unknown_port_with_container_is_busy`.
  - `network_is_created_when_missing`: inspect exits 1 with `network saiife-dev not found`. Then `create` is called with exactly the arguments above.
  - `existing_network_is_kept`: inspect replies `{"saiife.managed":"true","saiife.dev.role":"network"}`. No `create` call is made.
  - `foreign_network_is_refused`: inspect replies `{}`. The result is `NotOurs { kind: "network", name: "saiife-dev" }`.
  - `create_race_is_tolerated`: create exits 1 with `already exists`, and the second inspect is ours, so the result is `Ok`.
  - `docker_down_is_an_error`: inspect exits 1 with `Cannot connect to the Docker daemon`. The result is `DevError::Docker`, and no `create` call is made.
- [ ] **Step 2:** `cargo test -p saiife-dev proxy`. Expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass. Clippy is clean.
- [ ] **Step 5:** commit `feat(dev): port pre-flight and the shared saiife-dev network`.

### Task 5: the proxy container (size M)

**Files:** Modify `crates/dev/src/proxy.rs`.

**Interfaces:**
- Consumes Task 3's `dynamic_dir`, Task 4's `ROLE`, `NotOurs` and `PortBusy`, and `DevPaths`.
- Produces:
  - `pub const PROXY_IMAGE: &str = "traefik:v3.7.16";` (the owner appends `@sha256:<digest>`);
  - `pub fn ensure_proxy(d: &dyn Docker, paths: &DevPaths) -> Result<(), DevError>`;
  - `pub fn stop_proxy_if_unused(d: &dyn Docker, paths: &DevPaths) -> Result<bool, DevError>`, which returns `true` when it removed the proxy;
  - `pub(crate) fn run_args(paths: &DevPaths) -> Vec<String>` (the full `docker run` argument list, without the spec label);
  - `pub(crate) fn spec_hash(args: &[String]) -> String` (FNV-1a 64-bit over the arguments joined with `\0`, as 16 lowercase hex digits).
- `run_args` in order:
  1. `run -d --name saiife-dev-proxy --network saiife-dev --restart unless-stopped`;
  2. `--label saiife.managed=true --label saiife.dev.role=proxy`;
  3. `-p 127.0.0.1:80:8080 -p 127.0.0.1:443:8443`;
  4. `-v <state>/proxy/dynamic:/saiife/dynamic:ro -v <state>/tls:/saiife/tls:ro`;
  5. `--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges`;
  6. on Unix only, `--user <uid>:<gid>`;
  7. `PROXY_IMAGE`, then the Traefik flags from Global Constraints, in that order.

  `ensure_proxy` inserts `--label saiife.dev.proxy-spec=<spec_hash(run_args)>` after the role label.
- The flow of `ensure_proxy`:
  1. Create `dynamic_dir` and `tls_dir` (D1).
  2. `container inspect saiife-dev-proxy`, with "missing" detected as in `ensure_network` (`No such container`).
  3. `Config.Labels` has no `saiife.managed=true`: return `NotOurs { kind: "container", .. }`.
  4. The spec label differs: `rm -f saiife-dev-proxy`, then `run`.
  5. `State.Running` is false: `start saiife-dev-proxy`.
  6. Otherwise: `Ok`.

  If `run` or `start` fails, the container is removed (`rm -f`). Stderr containing `address already in use` or `port is already allocated` becomes `PortBusy { port: 443 if it contains ":443" else 80, holder: None }`. Any other failure is `DevError::Docker`.
- `stop_proxy_if_unused`:
  1. Any `*.toml` in `dynamic_dir` other than `TLS_FILE` returns `Ok(false)`.
  2. Otherwise inspect. A missing container, or one that is not ours, returns `Ok(false)` and is left untouched.
  3. A proxy that is ours is removed with `rm -f saiife-dev-proxy`, which returns `Ok(true)`.

- [ ] **Step 1: failing tests** (`FakeDocker`; inspect replies are minimal JSON arrays):
  - `run_args_are_locked_down`:
    - the arguments contain `--read-only`, `--cap-drop ALL`, `127.0.0.1:80:8080`, `127.0.0.1:443:8443`, and both mounts ending in `:ro`;
    - `--providers.file.directory=/saiife/dynamic` and `--entryPoints.web.http.redirections.entryPoint.to=:443` are present;
    - **no** argument contains `docker.sock`, `providers.docker`, `/projects`, or the CA directory's path.
  - `image_is_pinned`: `PROXY_IMAGE` is `traefik:v3.7.16`, optionally followed by `@sha256:` and 64 hex digits.
  - `missing_proxy_is_run`: dirs exist afterwards. The recorded `run` call equals `run_args` plus the spec label.
  - `running_proxy_with_same_spec_is_left_alone`: no `run`, `start` or `rm` call.
  - `stopped_proxy_is_started`.
  - `changed_spec_is_recreated`: `rm -f`, then `run`.
  - `foreign_container_is_refused`: `NotOurs`, with no `rm` call.
  - `failed_run_removes_the_container`: `run` exits 125 with `Bind for 127.0.0.1:443 failed: port is already allocated`. The calls end with `rm -f saiife-dev-proxy`, and the error is `PortBusy { port: 443, holder: None }`.
  - `proxy_kept_while_routes_exist`.
  - `tls_file_alone_does_not_keep_the_proxy`: a `_tls.toml` alone in `dynamic_dir` still counts as unused.
  - `unused_proxy_is_removed`.
  - `foreign_proxy_is_not_removed`.
  - `spec_hash_is_stable`: a fixed vector gives a fixed hex string, and changing one argument changes it.
- [ ] **Step 2:** `cargo test -p saiife-dev proxy`. Expect FAIL.
- [ ] **Step 3:** implement. Parse the inspect output with `serde_json::Value`, reading only `[0].Config.Labels` and `[0].State.Running`.
- [ ] **Step 4:** the tests pass. Clippy is clean.
- [ ] **Step 5:** commit `feat(dev): one Traefik proxy for every project, file provider only`.

## Finish

- [ ] **Gates** (with `TMPDIR` and `SAIIFE_TEST_TMP` from `mktemp -d -p /home/jonas/projects/personal/saiife`, `CARGO_INCREMENTAL=0`, `-j 4` and `--test-threads=4`):
  - `cargo fmt --all --check`;
  - `cargo clippy --workspace --all-targets -- -D warnings`;
  - `cargo test -p saiife-dev`;
  - `scripts/test-offline.sh -p saiife-dev` (or the whole script, if it takes no package filter);
  - `bash scripts/check-unsafe.sh`;
  - `cargo check -p saiife-dev --target x86_64-pc-windows-gnu` and the macOS target, as plan 21's gates do. The Windows check is `bash scripts/check-windows.sh`.
- [ ] Remove the scratch directory. Whole-branch review, one fix wave. The owner merges.

## Owner handwork

Nothing here runs on a build agent's machine.

1. **Pin the digest:** run `docker buildx imagetools inspect traefik:v3.7.16`. Set `PROXY_IMAGE = "traefik:v3.7.16@sha256:<index digest>"` and commit. `image_is_pinned` accepts that form.
2. **Smoke test**, after plan 24, with `scripts/dev-smoke.sh` or by hand on a compose repo with a `web` service, after trusting the CA as `saiife dev ca` says:
   - a. `https://web.<p>.localhost` shows a valid certificate in **Chrome** and in **Firefox** (Firefox uses its own NSS store on Linux). This checks F11, the third-level wildcard. If either rejects it, tell the coordinator: the fallback is per-host SANs, a contract change.
   - b. `curl -sI http://web.<p>.localhost` returns `308`, with `Location: https://web.<p>.localhost/`. `curl -v https://web.<p>.localhost` connects to 127.0.0.1. The page loads quickly in both browsers, which shows the `::1` fallback is fast (D5).
   - c. `docker inspect saiife-dev-proxy` shows no `docker.sock`, two `ro` binds and `ReadonlyRootfs: true`. Neither `ss` nor any other tool is needed: `curl http://<your LAN IP>` is refused.
   - d. `stat -c %a <state>/ca/ca-key.pem` gives `600`.
   - e. Run `up` on a second project, then `down` the first: the second still serves. `down` the last: `saiife-dev-proxy` is gone.
