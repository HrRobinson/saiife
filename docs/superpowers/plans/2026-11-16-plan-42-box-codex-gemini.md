# Plan 42: Codex and Gemini templates in a box, beta (v3 step 7): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Depends on:** plan 40 merged into `v3-dev` (done at `ea324ebe`, in `bac68f00`): the model forwarder `crates/daemon/src/box_gateway/model.rs`, the placeholder `crates/boxhost/src/placeholder.rs` behind `RecordPaths::placeholder()` (R1, R2, R15), `TemplateSetup::setup_for` (`crates/daemon/src/box_setup.rs`), R3 (no credential in the box), R9/R13 (parked minors; this plan closes R13 M5, the path allow-list). Plan 36's recipe and bake (`assets/box/recipe.toml`, `crates/boxhost/src/image.rs`, `crates/boxhost/src/bake.rs`, `assets/box/bake/saiife-bake.sh`). The owner's smoke runs need owner accounts for OpenAI and Google AI Studio.

**Goal:** Two more built-in box templates, `codex` (OpenAI Codex CLI) and `gemini` (Google Gemini CLI), marked **beta** in `saiife box templates` and the Workspace. Each runs interactively in its TUI inside the box and talks to its model only through the host gateway, which swaps the box's placeholder for the real API key. The real key never enters the box.

**Architecture:**
- **One forwarder, three routes.** Plan 40's forwarder gets a fixed route table: Anthropic, OpenAI, Google. A route fixes the upstream host, the one header that carries the credential, the vault services and the path allow-list. **The box does not pick the route.** The route comes from the box's template (`AgentKind::provider()`), read per request as plan 40 already reads `login`. The guest side does not change: one model port (`vsock 5002`, `127.0.0.1:3129` in the box).
- **Per-provider placeholders and secrets.** Each provider has its own placeholder shape (so a file made for one route never passes on another) and its own vault service, `box-model-<provider>`.
- **Per-agent guest setup.** Codex gets `~/.codex/config.toml`, a custom model provider pointing at the gateway (HTTP Responses API, no websockets). Gemini gets `~/.gemini/settings.json` and `GOOGLE_GEMINI_BASE_URL`, which puts Gemini CLI in its `gateway` auth mode. Each gets its saiife hooks (PreToolUse/BeforeTool advisory, plus the turn-finished signal).
- **Optional agent binaries in the image.** The recipe has `[codex]` and `[gemini]` sections, off by default and `UNPINNED` until the owner pins them. The manifest lists the agents baked in. A box whose image lacks its agent is refused at boot with a message naming the fix.

**Tech Stack:** Rust; the crates plan 40 uses (`hyper 1.12`, `hyper-util`, `http-body-util`, `tokio-rustls`, `ring`, `zeroize`, `rustix`); `toml` and `serde_json` (already in the workspace) for the generated configs; Workspace JS (`node --test`). No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §2 (non-goals: Codex and Gemini as "beta" templates), §7.2 (base image, pinned agents), §7.4 (secrets only for the model endpoint), §7.7 (task model), §7.8 (templates), §7.9 (the Claude Code pattern this plan generalises), §7.10, §11 step 7, §13 (the placeholder swap is verified in the owner's smoke run), §15. Plan 40 and its ledger rulings R1–R17 (`.worktrees/p40/.superpowers/sdd/2026-11-11-plan-40-box-claude-code/progress.md`).

## Research (2026-11-16; public docs and source; the owner's smoke run confirms the client internals)

| | OpenAI Codex CLI | Google Gemini CLI |
|---|---|---|
| Install | Static musl Rust binary per release on GitHub, `rust-v<ver>` tags (latest `rust-v0.169.0`, 2026-11-13). Asset `codex-x86_64-unknown-linux-musl.tar.gz` (also `.zst`, `.sigstore` bundles, `codex-package_SHA256SUMS`). npm `@openai/codex` wraps the same binary. | `@google/gemini-cli` on npm (needs Node ≥ 20, `package.json` `engines`); `bin` is `bundle/gemini.js`. GitHub release `v0.68.0` (2026-11-10) carries `gemini-cli-bundle.zip` (self-contained bundle; the API gives each asset a `sha256:` digest). Ubuntu noble's `nodejs` is 18, so Node is pinned separately (nodejs.org `node-v<ver>-linux-x64.tar.xz`, `SHASUMS256.txt` signed by the Node release keys). |
| API-key auth | `[model_providers.<id>] env_key = "OPENAI_API_KEY"` → `Authorization: Bearer <key>` | `GEMINI_API_KEY` → `x-goog-api-key: <key>` (`GEMINI_API_KEY_AUTH_MECHANISM` defaults to `x-goog-api-key`) |
| Custom base URL | `[model_providers.<id>] base_url`, `wire_api = "responses"` (the `OPENAI_BASE_URL` env var is deprecated in favour of `openai_base_url`; a custom provider avoids both) | `GOOGLE_GEMINI_BASE_URL`: when set, `getAuthTypeFromEnv` picks `AuthType.GATEWAY` (`packages/core/src/core/contentGenerator.ts`), the key from `GEMINI_API_KEY` |
| Upstream | `api.openai.com`, `POST /v1/responses` (also `/v1/responses/compact`), `GET /v1/models` | `generativelanguage.googleapis.com`, `/v1beta/models/<m>:streamGenerateContent?alt=sse`, `:generateContent`, `:countTokens`, `GET /v1beta/models` |
| Streaming | SSE over HTTP. Recent versions try a websocket to the Responses API first and fall back to HTTP. `supports_websockets = false` on the provider skips the attempt. | SSE (`alt=sse`) |
| Subscription login | "Sign in with ChatGPT": OAuth tokens in `~/.codex/auth.json`, refreshed by the client; upstream is the ChatGPT backend, not `api.openai.com` | "Login with Google" (`oauth-personal`, Code Assist): OAuth refresh tokens in `~/.gemini/`; it calls `cloudcode-pa.googleapis.com` and **ignores `GOOGLE_GEMINI_BASE_URL`** |
| Hooks | `[[hooks.PreToolUse]]`, `[[hooks.Stop]]` in `config.toml`. Non-managed hooks must be trusted once; `--dangerously-bypass-hook-trust` skips that for one run. | `hooks.BeforeTool`, `hooks.AfterAgent` in `settings.json` |
| Noise off | `[analytics] enabled = false`, `[feedback] enabled = false`, `[otel]` is off by default | `privacy.usageStatisticsEnabled = false`, `telemetry.enabled = false`, `general.enableAutoUpdate = false`, `general.enableAutoUpdateNotification = false` |

Sources:
- Codex: [advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced), [auth](https://learn.chatgpt.com/docs/auth), [hooks](https://learn.chatgpt.com/docs/hooks), [releases](https://github.com/openai/codex/releases), the websocket fallback and `supports_websockets` ([Coder AI Gateway: Codex](https://coder.com/docs/ai-coder/ai-gateway/clients/codex), [openai/codex#13041](https://github.com/openai/codex/issues/13041)), and saiife's own `docs/superpowers/research/2026-10-13-codex-hooks.md`.
- Gemini: [configuration reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) (`GOOGLE_GEMINI_BASE_URL`, settings keys), [`contentGenerator.ts`](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/contentGenerator.ts), [`code_assist/oauth2.ts`](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/code_assist/oauth2.ts), [hooks reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md), [releases](https://github.com/google-gemini/gemini-cli/releases), the OAuth-bypasses-base-URL report ([DEV: Gemini CLI through LiteLLM](https://dev.to/polar3130/using-gemini-cli-through-litellm-proxy-1627)), and saiife's `docs/superpowers/research/2026-10-13-gemini-hooks.md`.

**The placeholder swap and what it covers.** The swap works for the **API-key** login of both agents. Both let the base URL point at the gateway, and both send the key in one fixed header. It **cannot work as built for either subscription login**:
- Codex's ChatGPT sign-in uses OAuth tokens. The client reads the token's claims, refreshes it against OpenAI's auth host, and calls the ChatGPT backend.
- Gemini's Google login ignores the base URL and refreshes hourly tokens itself.

So a placeholder in the box would either be read as a token or bypass the gateway. Both subscription logins are refused at template load (D2). Supporting either needs a host-side token refresher and the owner's terms check, which is a later plan.

## Decisions

- **D1. Route table** (`crates/daemon/src/box_gateway/routes.rs`, pure, pinned by a test):

  | Provider | Host (port 443) | Credential header | Vault services accepted | Paths (segment prefixes) |
  |---|---|---|---|---|
  | `anthropic` | `api.anthropic.com` | api-key: `x-api-key: <key>`; subscription (still gated by C4): `authorization: Bearer <key>` | `box-model-anthropic`, `box-model` (plan 40 name, kept for the owner's existing entry, D6) | `/v1/messages`, `/v1/models` |
  | `openai` | `api.openai.com` | `authorization: Bearer <key>` | `box-model-openai` | `/v1/responses`, `/v1/models` |
  | `google` | `generativelanguage.googleapis.com` | `x-goog-api-key: <key>` | `box-model-google` | `/v1beta/models`, `/v1/models` |

  "Segment prefix" means the path equals the prefix or continues with `/` (so `/v1/messages/count_tokens` and `/v1beta/models/m:streamGenerateContent` pass, and `/v1/messagesX` does not). The path is the raw origin-form path before any query.
- **D2. Logins.** `codex` and `gemini` accept only `login = "api-key"`. `login = "subscription"` for them is a template **load** error: ``login = "subscription" is not available for <kind>: only "api-key" (the gateway cannot hold its OAuth login yet; plan 42 D2)``. The file is skipped with a warning, the same path as any bad template. Claude's subscription gate (plan 40 C4, `SUBSCRIPTION_LOGIN_CLEARED`) is unchanged.
- **D3. Placeholders.** `ModelCred { AnthropicApiKey, AnthropicSubscription, OpenAiApiKey, GoogleApiKey }`.
  - Prefixes: the two Anthropic ones as plan 40 C1 (unchanged); `saiife-openai-` and `saiife-google-` for the new ones.
  - Each is followed by 64 random hex characters.
  - Neither client checks the key's format. The owner's smoke run confirms that (`placeholder_accepted_<agent>`).
  - A file whose content has the shape of **another** `ModelCred` is never accepted and never remade. This happens when the template was switched to another agent after spawn. `read_or_make_placeholder` returns `InvalidData` ("the box placeholder is for another agent or login: discard the box and spawn it again"), so setup and the forwarder both fail closed.
- **D4. Request rules on every route** (in addition to plan 40 C5, which stays as built):
  - **Path allow-list (D1).** A path outside the list gets `403 "this path is not forwarded to the model service"` (fixed text, never the path). The refusal is recorded as `model_denied` with reason `path_not_allowed` and `path` (cut to 256 bytes, no query).
  - **Path tricks.** Each of these gets `400 "the request path is not plain"`, reason `path`, before the allow-list check: a `.` or `..` segment, an empty segment (`//`), a `\`, a case-insensitive `%2e`, `%2f` or `%5c`, a NUL, or any byte outside visible ASCII.
  - **The placeholder in the target.** The box's placeholder anywhere in the target (path or query) gets `401 NOT_VALID`. This extends plan 40's "nowhere else in the headers".
  - **Google key parameter.** On the Google route, a query parameter named `key` gets `400 "the key query parameter is not forwarded"`, reason `query_key`.
  - **Removed headers.** Plan 40's `REQUEST_REMOVED` gains `x-goog-api-key`, `openai-organization`, `openai-project` and `x-goog-user-project`. These are any provider's credential, or headers that steer billing to another project of the owner's account. Then only the route's own header is set.
  - **Unchanged.** `Upgrade` is still refused (`400`). This is what makes Codex fall back to HTTP if it ever tries a websocket.
- **D5. Guest setup per agent** (`AgentKind` → env + files; command from the template):
  - **claude-code:** plan 40 as built (C2), unchanged.
  - **codex:** env `OPENAI_API_KEY=<placeholder>`. File `/home/agent/.codex/config.toml`, 0600, `keep_existing = false`: saiife's file wins on every setup, and the in-box agent's own edits to it last until the next cold boot. The file holds:
    - `model_provider = "saiife"`, `sandbox_mode = "danger-full-access"` (the VM is the boundary, spec §7.9), `check_for_update_on_startup = false`;
    - `[model_providers.saiife]` with `name = "OpenAI through saiife"`, `base_url = "http://127.0.0.1:3129/v1"`, `env_key = "OPENAI_API_KEY"`, `wire_api = "responses"`, `supports_websockets = false`;
    - `[analytics] enabled = false`, `[feedback] enabled = false`, `[projects."/work"] trust_level = "trusted"`;
    - `[[hooks.PreToolUse]]` with `matcher = saiife_agents::codex::MATCHER` and one command hook `"/usr/local/bin/saiife check --hook-exit --agent codex --profile box"`, `timeout = saiife_agents::codex::TIMEOUT_SECS`;
    - `[[hooks.Stop]]` with one command hook `"/usr/local/bin/saiife __guest event turn-finished"`.

    Built-in command: `["codex", "--dangerously-bypass-hook-trust"]`. The hooks are saiife's own and advisory, so a one-run trust bypass replaces the `/hooks` trust screen.
  - **gemini:** env `GEMINI_API_KEY=<placeholder>`, `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:3129`, `GEMINI_TELEMETRY_ENABLED=false`. File `/home/agent/.gemini/settings.json`, 0600, `keep_existing = false`, holding:
    - `{"security": {"auth": {"selectedType": "gateway"}, "folderTrust": {"enabled": false}}`;
    - `"privacy": {"usageStatisticsEnabled": false}`;
    - `"general": {"enableAutoUpdate": false, "enableAutoUpdateNotification": false}`;
    - `"telemetry": {"enabled": false}`;
    - `"hooks": {"BeforeTool": [{"matcher": saiife_agents::gemini::MATCHER, "hooks": [{"type": "command", "command": "/usr/local/bin/saiife check --hook-exit --agent gemini --profile box", "timeout": saiife_agents::gemini::TIMEOUT_MS}]}], "AfterAgent": [{"hooks": [{"type": "command", "command": "/usr/local/bin/saiife __guest event turn-finished", "timeout": saiife_agents::gemini::TIMEOUT_MS}]}]}}`.

    Built-in command `["gemini"]`.
  - **Variables never set by the setup:** `ANTHROPIC_*` for codex and gemini, and `GOOGLE_GENAI_USE_GCA`, `GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_API_KEY`, `GOOGLE_CLOUD_ACCESS_TOKEN`, `OPENAI_BASE_URL` for any agent. A test pins this list.
- **D6. Vault services.** The owner stores keys with:
  - `saiife secret add openai --kind token --service box-model-openai`
  - `saiife secret add gemini --kind token --service box-model-google`
  - `saiife secret add anthropic --kind token --service box-model-anthropic`

  The plan 40 name `box-model` is still accepted on the Anthropic route only, so the owner's existing entry keeps working. Whether to drop it before release is an owner decision. The missing-secret answer names the route's first service: `the vault has no secret <name> for <service>: saiife secret add <name> --kind token --service <service>`.
- **D7. Built-in templates:**
  - `crates/boxes/src/builtin/codex.toml`: name `codex`, description `OpenAI Codex CLI in its TUI (beta)`, `kind = "codex"`, the D5 command, `login = "api-key"`, `credential = "openai"`.
  - `crates/boxes/src/builtin/gemini.toml`: name `gemini`, description `Google Gemini CLI in its TUI (beta)`, `kind = "gemini"`, `login = "api-key"`, `credential = "gemini"`.
  - The size, egress (`[]`), secrets (`[]`), rules, touch and idle values are the same as `claude-code`. With no egress and no secrets, a phone spawn is Signed only (plan 40 O4, plan 34 R11).
- **D8. Beta and the credential label.** `AgentKind::beta()` is true for `Codex` and `Gemini`. The beta label in the CLI and the Workspace comes only from that. The credential label comes only from `BoxTemplate::credential_mode()` (plan 40), never from the agent. The wire `Template` gains `agent` (`"claude-code"|"codex"|"gemini"`), `beta: bool` and `credential` (`credential_mode()`), all `#[serde(default)]`.
- **D9. Recipe sections** (`assets/box/recipe.toml`; both sections `#[serde(default)]`, so plan 36's recipe without them still parses as disabled):
  ```toml
  [codex]
  enabled = false
  version = "UNPINNED"
  url = "UNPINNED"      # https://github.com/openai/codex/releases/download/rust-v<ver>/codex-x86_64-unknown-linux-musl.tar.gz
  sha256 = "UNPINNED"
  [gemini]
  enabled = false
  version = "UNPINNED"
  url = "UNPINNED"      # https://github.com/google-gemini/gemini-cli/releases/download/v<ver>/gemini-cli-bundle.zip
  sha256 = "UNPINNED"
  node_version = "UNPINNED"
  node_url = "UNPINNED" # https://nodejs.org/dist/v<ver>/node-v<ver>-linux-x64.tar.xz
  node_sha256 = "UNPINNED"
  ```
  - **Validation.** A disabled section is not validated at all (it may stay `UNPINNED`). An enabled section with any field `UNPINNED` is an error naming it, for example ``codex.sha256 is UNPINNED; pin the Codex release first (or set codex.enabled = false)``.
  - **Enabled values.** Each `sha256` must be 64 lowercase hex. Each url must start with `https://` and end with `.tar.gz` (codex), `.zip` (gemini) or `.tar.xz` (node). A version must not be empty.
  - **Override.** `saiife box image build --with <codex|gemini>` (repeatable) turns a section on for one build, the way `--direct-kernel` overrides `boot.direct_kernel`.
  - **Claude stays mandatory**, as plan 36 built it.
- **D10. Bake and manifest.**
  - **Payload.** An enabled pin is fetched with `pins::fetch` into the cache (`codex-<sha256>`, `gemini-<sha256>`, `node-<sha256>`, mode 0644) and copied into the payload as `codex.tar.gz`, `gemini.zip` or `node.tar.xz`. The payload stays 512 MiB.
  - **Codex in the bake script.** `install_agents()` runs only for the payload files present. It extracts `codex.tar.gz` into a fresh temp dir with `--no-same-owner` and requires exactly one regular file, `codex-x86_64-unknown-linux-musl`, then installs it as `/usr/local/bin/codex` (0755).
  - **Gemini in the bake script.** `node.tar.xz` is extracted into `/opt/saiife-node` (`--strip-components=1`, `--no-same-owner`). `gemini.zip` is unpacked with `python3 -I -m zipfile -e` into `/opt/gemini-cli`, and exactly one `gemini.js` must exist at its root or in `bundle/`. Then the script writes `/usr/local/bin/gemini` (0755): `#!/bin/sh` and `exec /opt/saiife-node/bin/node /opt/gemini-cli/<rel>/gemini.js "$@"`.
  - **Version check.** Each installed agent must answer `--version` with exit 0, or the bake fails.
  - **Manifest.** It gains `#[serde(default, skip_serializing_if = "BTreeMap::is_empty")] agents: BTreeMap<String, ManifestPin>` with keys `codex`, `gemini` and `node`, taken from the recipe as plan 36 does for `claude`. Images built before this plan keep their exact JSON and signature.
  - **Boot check.** `ResolvedImage` gains `agents: Vec<String>`: always `"claude-code"`, plus `"codex"`, plus `"gemini"` when the manifest has both `gemini` and `node`. `VmSpec` gains `agent: AgentKind`. At boot, `ChVmm` refuses `Failed("the image <id> has no <agent>: build one with \"saiife box image build --with <agent>\"")` before anything is created.

## Global Constraints

Plan 35's Global Constraints apply (`CARGO_PROFILE_DEV_DEBUG=0` for every build), with worktree `.worktrees/p42`, branch `v3-p42`, and scratch prefix `p42-tN-`. In addition:
- **Hard rules** (`.superpowers/sdd/hard-rules.md`): no sudo, docker, VMs or process-control tools; no network in tests; TMPDIR made with `mktemp -d -p /home/jonas/projects/personal/saiife`; `-j 4 -- --test-threads=4`.
- **Never contact OpenAI, Google or Anthropic in tests.** The upstream is plan 40's loopback rustls server, with one rcgen certificate whose SANs are the three D1 hosts, and a test resolver that maps exactly those three to loopback.
- **No real keys, no token-shaped literals.** Test secrets are built with `concat!`.
- Never touch `~/.claude`, `~/.codex` or `~/.gemini` on the host. The setup writes those paths **inside the box** only (`/home/agent/...`).
- **Plan 40's tests are not weakened.** No assertion in `crates/daemon/tests/box_model.rs`, `crates/boxhost/src/placeholder.rs` tests, `crates/daemon/src/box_setup.rs` tests or `crates/cli/src/box_cmd.rs` tests is removed or loosened. The only allowed edits are:
  - call-site renames where a function now takes `ModelCred`: `placeholder`, `read_placeholder`, `read_or_make_placeholder`, `rewrite_request` and `check_credential` (`Login::ApiKey` → `ModelCred::AnthropicApiKey`, `Login::Subscription` → `ModelCred::AnthropicSubscription`);
  - the four fake-upstream paths `/sse`, `/forever`, `/stall`, `/nohead` becoming `/v1/messages/sse`, `/v1/messages/forever`, `/v1/messages/stall`, `/v1/messages/nohead` (request and fake-upstream match alike);
  - the two missing-secret strings changing `--service box-model` to `--service box-model-anthropic` and `for box-model` to `for box-model-anthropic` (exact equality kept).

  If any other existing assertion would have to change, stop and report it for a ruling.
- The tokio gate stays `0` for `saiife-boxes` and `saiife-boxhost`.

### Fixed values

| Name | Value |
|---|---|
| route table | D1 |
| placeholder prefixes | D3: Anthropic as plan 40 C1; `saiife-openai-`, `saiife-google-`; plus 64 hex |
| guest env and files | D5 |
| `CODEX_CONFIG_PATH` | `/home/agent/.codex/config.toml` |
| `GEMINI_SETTINGS_PATH` | `/home/agent/.gemini/settings.json` |
| vault services | D6 |
| refusal texts | D2, D3, D4, D9, D10 (exact) |
| recipe sections | D9 |
| manifest keys | `agents.codex`, `agents.gemini`, `agents.node` |

## Review Focus

1. **A box steering its traffic to another provider or path.** Cases: a codex box sending Anthropic's header or path; a gemini box asking for `/v1/responses`; a lookalike prefix `/v1/messagesX`; encoded dot segments `/v1/models/%2e%2e/files`; `//`; a backslash. Expected: the route is the template's, every other host is never resolved, `403` for off-list paths and `400` for tricks, and one `model_denied` record (Task 3: `route_comes_from_the_template`, `paths_outside_the_route_are_403`, `path_tricks_are_400`).
2. **Credential or billing smuggled outside the swapped header.** Cases: the placeholder in the query; `?key=` on Google; `openai-organization`, `openai-project`, `x-goog-user-project`; another provider's credential header. Expected: `401`, `400` or the header stripped, and the upstream sees only the real key in the route's header (Task 3: `placeholder_in_target_is_401`, `query_key_is_400`, `provider_headers_are_stripped`).
3. **The wrong secret for a route.** Cases: an OpenAI box whose vault entry allows only `box-model-anthropic` or the legacy `box-model`; an Anthropic box with the legacy name. Expected: `503` naming `--service box-model-openai` for the first two; the Anthropic box gets `200` (Task 3: `secret_services_are_per_provider`).
4. **Images and recipes half done.** Cases: `[codex] enabled = true` with one field `UNPINNED`; a disabled section with garbage; a codex box on a claude-only image; a pre-plan-42 manifest. Expected: the recipe error names the field, the disabled section is ignored, boot is refused with the D10 text before anything is created, and the old manifest parses with its signature unchanged (Task 4: `enabled_unpinned_is_refused`, `disabled_section_is_ignored`, `boot_refuses_missing_agent`, `old_manifest_round_trips`).
5. **A template edited after spawn to another agent, or to a subscription login on codex or gemini.** Expected: the template edited to a subscription login is skipped at load with D2's text. A running box whose template now names another agent fails closed: setup refuses with D3's text, and the forwarder answers `401`. No new placeholder is made (Task 1: `subscription_refused_for_codex_and_gemini`, `other_cred_placeholder_is_not_remade`; Task 3: `template_switched_agent_is_401`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (template kinds, `ModelCred`, placeholders, wire fields). Everything else uses its names.
- **Wave 2 (parallel):** Task 2 (guest setup), Task 3 (forwarder routes), Task 4 (recipe, bake, manifest, boot check), Task 5 (CLI and Workspace labels). Their files do not overlap.
- **Wave 3:** Task 6 (owner smoke fragments, the plan 40 smoke's service names).

---

### Task 1: agent kinds, model credentials and placeholders (size M)

**Files:**
- Modify: `crates/boxes/src/template.rs`
- Create: `crates/boxes/src/builtin/codex.toml`, `crates/boxes/src/builtin/gemini.toml`
- Modify: `crates/boxhost/src/placeholder.rs`, `crates/wire/src/source.rs` (`Template`), `crates/wire/src/fake.rs`
- Test: `crates/boxes/tests/templates.rs`, `crates/boxhost/src/placeholder.rs` (tests module)

**Interfaces (Produces):**
```rust
// saiife-boxes template.rs
pub enum AgentKind { ClaudeCode, Codex, Gemini }
impl AgentKind {
    pub fn name(self) -> &'static str;          // "claude-code" | "codex" | "gemini"
    pub fn beta(self) -> bool;                  // D8
    pub fn provider(self) -> Provider;
}
pub enum Provider { Anthropic, OpenAi, Google }
impl Provider { pub fn name(self) -> &'static str; }   // "anthropic" | "openai" | "google"
pub enum ModelCred { AnthropicApiKey, AnthropicSubscription, OpenAiApiKey, GoogleApiKey }   // D3
impl BoxTemplate { pub fn model_cred(&self) -> ModelCred; }
// saiife-boxhost placeholder.rs: plan 40's functions take ModelCred instead of Login
pub fn placeholder(cred: ModelCred) -> io::Result<String>;
pub fn read_placeholder(record: &RecordPaths, cred: ModelCred) -> io::Result<Option<String>>;
pub fn read_or_make_placeholder(record: &RecordPaths, cred: ModelCred) -> io::Result<String>;
pub const OTHER_AGENT: &str = "the box placeholder is for another agent or login: discard the box and spawn it again";
// saiife-wire source.rs Template gains (serde default): agent: String, beta: bool, credential: String
```
`BoxTemplate::wire()` fills them from `agent.name()`, `agent.beta()` and `credential_mode()`.

- [ ] **Step 1: Write the failing tests.**
  - Templates:
    - `builtins_are_three` (names `claude-code`, `codex`, `gemini`; codex and gemini `beta()`; claude-code not);
    - `codex_builtin_is_pinned` (kind, command, `login = api-key`, `credential = "openai"`, `egress` and `secrets` empty, `model_cred() == OpenAiApiKey`);
    - `gemini_builtin_is_pinned` (likewise; `credential = "gemini"`, `GoogleApiKey`);
    - `subscription_refused_for_codex_and_gemini` (the exact D2 text, from `parse`);
    - `unknown_kind_still_refused`;
    - `wire_carries_agent_beta_credential` (`"codex"`, `true`, `"gateway"`);
    - `old_wire_template_parses` (JSON without the new keys → `agent == ""`, `beta == false`, `credential == ""`).
  - Placeholders:
    - `placeholder_shape_per_cred` (each prefix, 64 hex, two calls differ);
    - `placeholder_of_another_cred_is_refused` (a file made for `OpenAiApiKey`, read as each other kind → `Err`);
    - `other_cred_placeholder_is_not_remade` (`read_or_make_placeholder(GoogleApiKey)` on an `OpenAiApiKey` file → `Err` whose text is `OTHER_AGENT`, file content unchanged).

  Plan 40's placeholder tests move to `ModelCred::Anthropic*` call sites, with assertions unchanged. If one asserts that `read_or_make` remakes another login's file, stop and report.
- [ ] **Step 2: Run** `cargo test -p saiife-boxes --features fake --test templates -j 4 -- --test-threads=4` and `cargo test -p saiife-boxhost --features fake placeholder -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement.** `parse` maps `kind` to `AgentKind`, then applies D2 before building. `builtin()` parses the three files, each with `expect("built-in <name> template is valid")`. In `placeholder.rs`, a content check that matches a *different* `ModelCred` shape returns `OTHER_AGENT`. Other bad content keeps plan 40's remove-and-remake-once rule.
- [ ] **Step 4: Run** the same commands, plus `cargo test -p saiife-wire -j 4` → PASS. Run `cargo build -p saiife-daemon --features fake-vmm -j 4` and fix only the call sites the rename breaks (the forwarder's `read_placeholder` and the setup's `read_or_make_placeholder` get `t.model_cred()`).
- [ ] **Step 5: Commit** `feat(boxes): codex and gemini agent kinds (beta), per-provider model placeholders`.

---

### Task 2: guest setup for Codex and Gemini (size M)

**Files:**
- Modify: `crates/boxhost/src/guest.rs` (beside `claude_env`), `crates/daemon/src/box_setup.rs`
- Test: both files' tests modules

**Interfaces:**
- Consumes: Task 1 `AgentKind`, `ModelCred`, `read_or_make_placeholder`; plan 38 `Setup`, `SetupFile`; `saiife_agents::{codex, gemini}::{MATCHER, TIMEOUT_*}`; `ports::MODEL_TCP`.
- Produces:
```rust
// boxhost guest.rs
pub fn codex_env(placeholder: &str) -> Vec<(String, String)>;   // D5
pub fn codex_config() -> String;                                // D5 TOML (no placeholder in it)
pub fn gemini_env(placeholder: &str) -> Vec<(String, String)>;  // D5
pub fn gemini_settings() -> String;                             // D5 JSON
pub const NEVER_SET: [&str; 5] = ["GOOGLE_GENAI_USE_GCA", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_API_KEY", "GOOGLE_CLOUD_ACCESS_TOKEN", "OPENAI_BASE_URL"];
// daemon box_setup.rs
pub const CODEX_CONFIG_PATH: &str = "/home/agent/.codex/config.toml";
pub const GEMINI_SETTINGS_PATH: &str = "/home/agent/.gemini/settings.json";
pub struct AgentSetup { pub env: Vec<(String, String)>, pub files: Vec<SetupFile> }
pub fn agent_setup(agent: AgentKind, cred: ModelCred, placeholder: &str) -> AgentSetup;
pub fn build_agent_setup(id: &BoxId, command: &[String], agent: AgentSetup, packs: &[(String, String)]) -> Result<Setup, String>;
```
`build_setup` (plan 38/40) keeps its signature and behaviour and becomes `build_agent_setup` with Claude's files (settings, plus the seed when a `ModelSetup` is given). `setup_for` matches `t.agent`: Claude unchanged; Codex and Gemini call `read_or_make_placeholder(&record, t.model_cred())`, then `agent_setup`, then `build_agent_setup`. Codex and Gemini boxes get none of Claude's files.

- [ ] **Step 1: Write the failing tests.**
  - `codex_env_is_pinned`: exactly `[("OPENAI_API_KEY", ph)]`.
  - `codex_config_is_pinned`: parsed with `toml`, every D5 key and value; the `PreToolUse` and `Stop` commands equal the D5 strings.
  - `gemini_env_is_pinned`: exactly the three D5 variables.
  - `gemini_settings_are_pinned`: parsed with `serde_json`, every D5 key, both hook commands.
  - `never_set_vars_absent`: for each agent's env, no `NEVER_SET` name; codex and gemini have no `ANTHROPIC_*`.
  - `codex_box_has_no_claude_files` and `gemini_box_has_no_claude_files`: no `SETTINGS_PATH` or `CLAUDE_JSON_PATH`.
  - `agent_files_are_0600_and_authoritative`: mode `0o600`, `keep_existing == false`.
  - `setup_has_no_secret_for_every_agent`: a vault seeded with a `concat!`-built value under each route's service; the serialized `Setup` of a codex and a gemini box does not contain it.
  - `second_setup_same_placeholder_per_agent`.
  - `switched_agent_setup_is_refused`: a box spawned as codex whose template is then replaced by a gemini one → `Err` containing `OTHER_AGENT`.

  Plan 38/40 setup tests stay as they are.
- [ ] **Step 2: Run** `cargo test -p saiife-boxhost --features fake guest -j 4 -- --test-threads=4` and `cargo test -p saiife-daemon --features fake-vmm box_setup -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement** as in the Interfaces block. `Setup::check` runs last, as today.
- [ ] **Step 4: Run** the same commands → PASS.
- [ ] **Step 5: Commit** `feat(boxes): Codex and Gemini setup in the box: gateway provider, placeholder key, saiife hooks`.

---

### Task 3: per-provider routes in the model forwarder (size L)

**Files:**
- Create: `crates/daemon/src/box_gateway/routes.rs`
- Modify: `crates/daemon/src/box_gateway/model.rs`, `crates/daemon/src/box_gateway/mod.rs` (`mod routes;`), `crates/daemon/tests/box_model.rs` (harness: Opts gains `agent: AgentKind`; the certificate's SANs are the three hosts; the test resolver is `OnlyModelHosts`, three hosts, and records each host asked; plus the Global Constraints renames)

**Interfaces:**
- Consumes: Task 1 `ModelCred`, `Provider`, `BoxTemplate::model_cred`, `read_placeholder`.
- Produces:
```rust
// routes.rs (pure)
pub struct Route {
    pub provider: Provider,
    pub host: &'static str,
    pub services: &'static [&'static str],
    pub paths: &'static [&'static str],
}
pub fn route(provider: Provider) -> &'static Route;                       // D1
pub fn cred_header(cred: ModelCred) -> (HeaderName, bool /* bearer */);   // D1
pub fn path_plain(raw_path: &str) -> bool;                                // D4 tricks
pub fn path_allowed(route: &Route, raw_path: &str) -> bool;               // D1 segment prefix
// model.rs: plan 40's pure functions take the cred and route
pub fn rewrite_request(req: &mut http::request::Parts, cred: ModelCred, real: &str) -> Result<(), &'static str>;
pub fn check_credential(parts: &http::request::Parts, cred: ModelCred, expected: &str) -> Result<(), &'static str>;
```
- `MODEL_HOST`, `MODEL_SERVICE` and plan 40's constants stay as aliases of the Anthropic route, so plan 40's unit tests compile unchanged apart from the rename.
- **Per request, the order is:**
  1. plan 40's lockdown, method, target and upgrade checks;
  2. `box_info`, which now also returns `cred` and `provider` from the template;
  3. C4;
  4. `path_plain`, then `path_allowed`, then on Google the `key` query check;
  5. `check_credential` (headers, then the target);
  6. the body cap;
  7. the vault value, accepted when `allowed_services` contains any of `route.services`; the message names `services[0]`;
  8. `rewrite_request`, with `host` set to `route.host`;
  9. connect, where the resolver, the TLS server name and the `upstream_addr` port use `route.host` and 443.
- The `model` record gains `provider`, and `model_denied` gains `path` for `path_not_allowed`.

- [ ] **Step 1: Write the failing tests.**
  - In `box_model.rs`:
    - `openai_swap`: a codex box, `POST /v1/responses` with `authorization: Bearer <ph>`. The upstream sees `host: api.openai.com`, `authorization: Bearer <real>`, and the placeholder nowhere; the box sees the body.
    - `google_swap`: a gemini box, `POST /v1beta/models/m:streamGenerateContent?alt=sse` with `x-goog-api-key: <ph>`. The upstream sees `host: generativelanguage.googleapis.com`, `x-goog-api-key: <real>`, and the target unchanged.
    - `route_comes_from_the_template`: a codex box sending `x-api-key: <its ph>` → 401; `/v1/messages` → 403. The resolver was asked only for `api.openai.com`, or nothing.
    - `paths_outside_the_route_are_403`: Anthropic `/v1/responses` and `/api/hello`; OpenAI `/v1/messages` and `/v1/files`; Google `/upload/v1beta/files`. A record has reason `path_not_allowed` and `path` without the query.
    - `path_tricks_are_400`: `/v1/messages/../x`, `/v1/messages/%2E%2E/x`, `/v1//messages`, `/v1/messages%2fx`, `/v1/messages\x`.
    - `lookalike_prefix_is_403`: `/v1/messagesX`, `/v1beta/modelsX`.
    - `placeholder_in_target_is_401`: in the path and in the query, on each route.
    - `query_key_is_400`: Google `?alt=sse&key=x`.
    - `provider_headers_are_stripped`: a codex box sends `x-api-key`, `x-goog-api-key`, `openai-organization`, `openai-project` and `x-goog-user-project`; the upstream sees none of them.
    - `secret_services_are_per_provider`: Review Focus 3.
    - `records_name_the_provider`: `provider`, `login: "api-key"`, `credential: "gateway"`.
    - `upgrade_refused_on_every_route`: `GET /v1/responses` with `upgrade: websocket` → 400.
    - `sse_streams_on_every_route`: three events 300 ms apart reach the box incrementally on the OpenAI and Google routes.
    - `new_routes_never_echo_credentials`: every error body on the two new routes is checked for the placeholder and the key.
    - `template_switched_agent_is_401`: a box spawned as claude-code whose template is now codex; its Anthropic-shaped placeholder → 401, the upstream sees nothing.
  - Unit tests in `routes.rs`:
    - `route_table_is_pinned`: D1 exactly.
    - `path_rules`: a table of the D4 tricks and the D1 prefixes.
    - `rewrite_request_per_cred_is_pinned`: the sorted header list per cred, as in plan 40's `rewrite_request_is_pinned`.
  - Every plan 40 test keeps passing, with only the Global Constraints edits.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm --test box_model -j 4 -- --test-threads=4` and `cargo test -p saiife-daemon --features fake-vmm box_gateway -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement** in the Interfaces order. `routes.rs` holds no I/O, and `model.rs` stays the only place that touches the network.
- [ ] **Step 4: Run** the same commands → PASS (all plan 40 tests included).
- [ ] **Step 5: Commit** `feat(daemon): model forwarder routes for OpenAI and Google; path allow-list on every route`.

---

### Task 4: agent binaries in the image recipe, bake and boot check (size M)

**Files:**
- Modify: `assets/box/recipe.toml`, `crates/boxhost/src/image.rs` (`Recipe`, `parse_recipe`, `Manifest`), `crates/boxhost/src/bake.rs` (`BakeInputs.agents`, `make_payload`), `assets/box/bake/saiife-bake.sh` (`install_agents`), `crates/cli/src/box_image_cmd.rs` (`--with`, fetch, manifest), `crates/boxhost/src/image/store.rs` (`ResolvedImage.agents`), `crates/boxhost/src/vmm.rs` (`ResolvedImage.agents`; the boot check), `crates/boxes/src/vmm.rs` (`VmSpec.agent`), `crates/boxes/src/manager.rs` (fills `VmSpec.agent` from the template, `:631`)
- Test: `crates/boxhost/src/image.rs`, `crates/boxhost/src/bake.rs`, `crates/boxhost/src/image/store.rs` tests; `crates/boxhost/tests/ch_vmm.rs`; `crates/cli/tests/box_image_build.rs`

**Interfaces (Produces):**
```rust
// boxhost image.rs
pub struct AgentPin { pub version: String, pub url: String, pub sha256: String }
pub struct GeminiPin { pub cli: AgentPin, pub node: AgentPin }
// Recipe gains:
pub codex: Option<AgentPin>,    // Some only when enabled (and valid)
pub gemini: Option<GeminiPin>,
pub fn parse_recipe_with(text: &str, with: &[AgentKind]) -> Result<Recipe, String>;   // D9; parse_recipe(text) = parse_recipe_with(text, &[])
// Manifest gains (D10): pub agents: BTreeMap<String, ManifestPin>
// boxhost vmm.rs: ResolvedImage gains pub agents: Vec<String>
// boxes vmm.rs: VmSpec gains pub agent: AgentKind
pub fn missing_agent(image_id: &str, agent: AgentKind) -> String;   // the D10 text
```
`--with claude-code` is refused, since it is always in the image.

- [ ] **Step 1: Write the failing tests.**
  - Recipe:
    - `default_recipe_parses_without_agents` (the shipped recipe: `codex` and `gemini` are `None`);
    - `enabled_unpinned_is_refused` (each of the 3 + 6 fields in turn, the exact D9 text);
    - `disabled_section_is_ignored` (garbage values, `enabled = false` → Ok);
    - `with_enables_a_section`;
    - `agent_url_rules` (http, a wrong suffix);
    - `recipe_without_sections_parses` (plan 36's text).
  - Manifest:
    - `old_manifest_round_trips` (a plan 36 manifest JSON parses, re-serializes byte-identical, and its signature still verifies);
    - `manifest_lists_agents`.
  - Bake:
    - `payload_carries_enabled_agents` (the fake mtools sees `codex.tar.gz`, `gemini.zip` and `node.tar.xz` only when enabled);
    - `bake_script_checks` (`bash -n`; the script contains `install_agents`, `--no-same-owner`, and `python3 -I -m zipfile -e`).
  - Store and VMM:
    - `resolved_image_agents` (store: claude only, plus codex, plus gemini only with node);
    - `boot_refuses_missing_agent` (`ch_vmm` fake: a codex spec on a claude-only image → `Failed` with `missing_agent` text, and no runtime dir or overlay created).
  - CLI: `image_build_with_codex_unpinned_fails` (the default recipe plus `--with codex` → exit non-zero with the D9 text, and nothing fetched).
- [ ] **Step 2: Run** `cargo test -p saiife-boxhost --features fake -j 4 -- --test-threads=4` and `cargo test -p saiife --features fake-vmm --test box_image_build -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement** D9 and D10. The bake script keeps `set -euxo pipefail`, quotes every path, and never evaluates archive content. `recipe.env` is unchanged: whether an agent is installed comes from which payload files are present.
- [ ] **Step 4: Run** the same commands, plus `bash -n assets/box/bake/saiife-bake.sh` (and shellcheck if installed) → PASS.
- [ ] **Step 5: Commit** `feat(boxes): optional pinned Codex and Gemini in the base image; boot refuses a box whose image lacks its agent`.

---

### Task 5: beta and credential labels in the CLI and the Workspace (size S)

**Files:**
- Modify: `crates/cli/src/box_cmd.rs` (`template_lines`), `crates/link/assets/js/inboxlogic.js`, `crates/link/assets/js/views/spawn.js`
- Test: `crates/cli/src/box_cmd.rs` tests, `crates/link/assets/tests/inbox.test.mjs`

**Interfaces:**
- Consumes: Task 1's wire fields `agent`, `beta` and `credential`.
- Produces: the `saiife box templates` header `NAME  AGENT  LOGIN  CREDENTIAL  NEEDS  DESCRIPTION`. AGENT is `agent` (empty → `claude-code`), with ` (beta)` appended when `beta`. CREDENTIAL is `credential`, empty → `in_box` if `credential_in_box`, else `gateway`. Plan 40's under-line for `credential_in_box` stays.
- JS:
  - `export function templateLabel(t)` returns `t.name`, plus ` (beta)` when `t.beta === true`.
  - `export function credentialLabel(t)` returns `"key stays on this computer"` for `"gateway"` or an absent value, and `"credential inside box (weaker)"` for `"in_box"`.
  - `spawn.js` uses `templateLabel` for the option text and adds a `badge` span `beta` in `describe()` when `t.beta`, beside the existing touch badge, with `credentialLabel(t)` as muted text.

- [ ] **Step 1: Write the failing tests.**
  - Rust:
    - `templates_show_agent_and_beta` (a codex row has `codex (beta)` and `gateway`);
    - `templates_from_an_old_daemon` (no `agent`, `beta` or `credential` keys → `claude-code`, not beta, and `gateway`).
  - JS:
    - `templateLabel marks beta`;
    - `credentialLabel follows the credential mode` (`gateway`, absent, `in_box`);
    - `templateLabel and credentialLabel take untrusted names through visible()` (a bidi character in a name is shown escaped, as `visible` does today).
  - Plan 40's `templates_show_login` keeps passing unchanged (4 lines).
- [ ] **Step 2: Run** `cargo test -p saiife box_cmd -j 4 -- --test-threads=4` and `node --test crates/link/assets/tests/` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same commands → PASS.
- [ ] **Step 5: Commit** `feat(cli,link): mark Codex and Gemini templates as beta; credential label from the credential mode`.

---

### Task 6: owner smoke fragments (size S)

**Files:**
- Create: `scripts/box-smoke.d/60-codex.sh`, `scripts/box-smoke.d/70-gemini.sh`
- Modify: `scripts/box-smoke.sh` (header knobs only), `scripts/box-smoke.d/50-claude.sh` (service names in comments and the spawn hint: `box-model-anthropic`, with the legacy `box-model` noted)

Owner-run checks. Agents only write the fragments and check them with `bash -n` (and shellcheck if installed); they never run them. Result keys per agent `<a>` ∈ {`codex`, `gemini`}:
- **Prerequisites:**
  - an image built with `--with <a>` after the owner pinned D9;
  - `SAIIFE_BOX_SMOKE_OPENAI_KEY_FILE` or `SAIIFE_BOX_SMOKE_GEMINI_KEY_FILE` (one line), read by `grep -f` only and never printed;
  - the vault entry, made by the owner: `saiife secret add openai --kind token --service box-model-openai --from-file …` (or `gemini` with `box-model-google`). A missing prerequisite is a FAIL or skip naming the step.
- `<a>_turn_ok`: `saiife box spawn --template <a> --task "Reply with the single word ok, then stop."` reaches `running`, then `done` within 180 s. That covers the Stop/AfterAgent hook and the 30 s idle.
- `<a>_no_prompt`: `saiife box attach` shows the reply with no login, trust, hook-trust, theme or update screen (the owner confirms by eye).
- `model_records_<a>`: the audit has `model` records with `provider` `openai` or `google`, status 200, and `credential: "gateway"`.
- `placeholder_accepted_<a>`: the turn succeeding with only the placeholder in the box is the proof (§13). If it fails, record the client's error from the terminal and report it to the owner. There is no fallback (plan 40 R3).
- `model_paths_<a>`: list the distinct `path` values of `model_denied` records with reason `path_not_allowed` during the turn. PASS when there are none. The owner widens D1 only from this list.
- `key_not_on_disk_<a>`: after `saiife box stop`, the plan 40 count check over `root.qcow2` and `repo.img` prints `0`.
- `no_placeholder_401_<a>`: through the plan 38 `bash` template run against the same route, a `curl` with no key gets `401`. The fragment installs a `bash-<a>` template whose `kind` is `<a>` and whose command is `["bash"]`.
- `websocket_fallback_codex` (codex only): every model record of the turn is a `POST /v1/responses` (no `400 upgrade` refusals). The first record comes within 30 s of the spawn reaching `running`.

- [ ] **Step 1:** Write both fragments in the style of `50-claude.sh`: functions only, no top-level effects, `leg_fail` on early returns, locked-mode reads with `sudo -n` named in the FAIL. Run `bash -n` on all three fragments and `box-smoke.sh`.
- [ ] **Step 2: Commit** `test(boxes): owner smoke for Codex and Gemini in a box (beta)`.

---

## Gates

- [ ] `cargo test -p saiife-boxes --features fake -p saiife-boxhost --features fake -p saiife-daemon --features fake-vmm -p saiife --features fake-vmm -p saiife-wire`, and the daemon and CLI suites without features; `-j 4 -- --test-threads=4`. All of plan 40's `box_model` tests pass.
- [ ] `node --test crates/link/assets/tests/`.
- [ ] `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings` (and with the features above); `scripts/check-unsafe.sh`; `scripts/check-windows.sh -p saiife-boxes -p saiife-daemon -p saiife`; the tokio gate prints `0` for `saiife-boxes` and `saiife-boxhost`.
- [ ] `grep -rn 'SUBSCRIPTION_LOGIN_CLEARED: bool = true' crates/` finds nothing. `grep -n 'UNPINNED' assets/box/recipe.toml` still shows the `[claude]`, `[codex]` and `[gemini]` pins (the owner fills them).
- [ ] `bash -n` on `assets/box/bake/saiife-bake.sh` and every `scripts/box-smoke.d/*.sh`.
- [ ] A whole-branch review against the Review Focus, one fix wave, then a PR to `v3-dev`. The owner merges.

## Owner handwork

- [ ] **Pins (D9):** fill `[codex]`, `[gemini]` and the Node fields from the releases. Take the sha256 from the GitHub asset digest or `codex-package_SHA256SUMS`, and check it against the `.sigstore` bundle (Codex), the release digest (Gemini) and the signed `SHASUMS256.txt` (Node). Each pin goes in its own commit naming the version. Then build with `--with codex --with gemini`.
- [ ] **Terms check, OpenAI (API key):** confirm that OpenAI's current API terms allow an API key used through a local, single-user forwarding proxy. The plan assumes yes, and OpenAI ships its own `codex-responses-api-proxy`. ChatGPT sign-in for Codex is not built (D2). Building it needs this terms check plus a host-side OAuth refresher, in a later plan.
- [ ] **Terms check, Google (API key):** read the Gemini API Additional Terms. For unpaid (free tier) keys Google may use prompts and responses to improve its products. Decide whether the `gemini` template's docs require a billing-enabled key for private code. "Login with Google" for Gemini CLI is not built (D2), and it bypasses the base URL in any case.
- [ ] **Anthropic path list (D1, closes plan 40 R13 M5):** run `scripts/box-smoke.sh --only claude` on this branch. If `model_paths` shows Claude Code needs another path, widen D1 in its own commit, or rule that the list stays.
- [ ] **The legacy `box-model` service name (D6):** keep it, or move the vault entry to `box-model-anthropic` and drop the alias before release.
- [ ] Run `scripts/box-smoke.sh --only codex` and `--only gemini`. Codex internals (`--dangerously-bypass-hook-trust`, `supports_websockets`, no login screen with a custom provider) and Gemini internals (`gateway` auth, `AfterAgent`, no first-run screens) are confirmed or reported there.
