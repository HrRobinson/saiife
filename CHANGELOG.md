# Changelog

## 0.2.0 — YYYY-MM-DD (unreleased: waiting for the red-team suite)

0.2.0 adds locked mode on Linux (v2.0) and macOS (v2.1), and Windows (v2.2):
developer mode, and locked mode. Windows locked mode is a preview for Codex and
Gemini CLI, and not for Claude Code. It also adds the connector broker, the MCP
server and gateway, the personal broker and fleet packages.

### Developer mode and the guard

- A shell reserved word in front of a command no longer hides it from the shell-command rules. `! rm -rf /`, `! cat .env`, `! saiife init --off`, `if rm -rf /; then …`, `while …`, `until …`, `coproc …`, `time ! …` and `for x do …` (also `select`) are judged as the command itself.
- That holds in every rule: paths, redirections, `cd` tracking, whole-segment rules, and a here-document read by a shell (`! bash <<EOF`, `then bash <<EOF`). The same goes for zsh's `noglob`, `nocorrect`, `-` and `repeat N`, and fish's `not`, `and`, `or` and `begin`.
- A `!` that is not where a command starts (`echo !`, `grep ! x`), or is quoted (`"!" cmd`), stays an argument or a command name.
- A substitution in command position no longer ends the judging of its segment: `$(true) $(cat .env)`, `$(true) < .env` and `X=$(true) Y=$(cat .env)` are denied.
- An unquoted word that may expand to nothing no longer hides the next one, as bash runs `rm` when the word is empty. `$(true) rm -rf /`, `$x rm -rf /`, `$! rm -rf /`, `"$@" rm -rf /`, `"${a[@]}" rm -rf /` and `{,} rm -rf /` are denied, also across wrappers (`$x env $y rm -rf /`). `"$@"` alone or as an argument stays allowed.
- An empty variable leaves a bare `env`, so `$GO env`, `$(which go) env`, `$NPM env`, `$CARGO env` and `"${GO[@]}" env` are denied. `$GO env GOPATH` stays allowed.
- A line of many here-documents (`cat <<A <<A …`), `[[` or `case` words no longer takes time that grows with the square of its length. That could run out the budget and fail open in developer mode. `function f if cat .env; then :; fi` and zsh's `if [[ x ]] rm -rf /` and `if (( 1 )) rm -rf /` are judged too.
- Running out of the latency budget is no longer a way past the rules. What is left of the line still gets the pack rules and the path rules, with symlinks, globs and `cd`. A padded `! cd x; ! cd x; … rm -rf /`, `$(true) $(true) … cat .env` or `$(true) … x; cat link` is a normal deny with its rule.
- That last look has no clock. It makes at most 16 Ki system calls in one reading of a line; past that, the line is denied. Past 16 tracked directories, a `cd` makes the directory unknown and resolves nothing. Bash on Windows still closes a line that reads through a moved profile variable there.
- Only if nothing denies does the line stay a recorded fail-open in developer mode, and `error_denied` in locked mode. This is one path for every dialect and host: POSIX, PowerShell and cmd, on Linux, macOS and Windows.
- A shell line over the 256 KiB size limit is denied in every mode, as `error_denied`, with a message telling the agent to split it. In developer mode it was an `error_allowed` with nothing judged. File tools are not affected, and a broken stdin stays as it is.
- A hook payload over the 64 MiB parse cap is denied in every mode, as `error_denied`, whatever tool it names: a huge `Write` or `Edit` too ("hook payload larger than 67108864 bytes; not judged"). In developer mode a file tool there was an `error_allowed`.
- A line that makes more than 64 Ki words (or 8 MiB) by brace expansion is denied too, as is one that passes the work limit of the last look. Both can be ordinary commands: a generated script of `cd pkgN; cp a b c d; cd ../..` 1600 times (92 KB), or `mkdir -p` brace lines of 71 K words, is denied as `line-too-costly-to-judge`, and the message says to split it.
- A project `.saiife/config.toml` that is not a regular file (a FIFO or device, also through a symlink), or is over 64 KiB, is not read. The default packs apply, with a warning.
- A project `.saiife/config.toml` symlinked to a file outside the project is refused, never opened or quoted, by the hook and by `saiife init`. Links that stay inside the project still work. `saiife init` and `saiife status` read the project config with the same bounded, race-free read as the hook.
- Developer mode can opt in to fail closed with `[guard] fail = "closed"` in `/etc/saiife/config.toml`.
- Guard records keep `rule` (the regex) and gain `rule_id`. In v2.0 only `core.git`, `db.postgres` and the Kubernetes delete-namespace rule have ids.
- Audit records are now v2. Each carries a sequence number and the SHA-256 of the previous line (a hash chain), plus kind, mode, host and policy. 0.1.0 can still read them.
- New `saiife audit verify` checks the chain (exit 0 intact, 1 broken, 2 unreadable), and the checkpoint and key-rotation signatures.
- `saiife audit --report` gains sections: Audit chain, Policy in force, Mode per host, connectors, approvals, `error_denied`, daemon restarts and forwarding outages. `error_denied` now counts as blocked in `saiife audit`, `--blocked` and the report.
- `scripts/bench-check.sh` prints the p95 of the developer hook too, and `BENCH_MAX_P95_MS` now applies to it.
- The built-in packs are prebuilt into the binary, and each rule's regex is compiled on first use. Building the guard engine went from 30-54 ms to under 1.3 ms (plan 21).
- The guard can judge a call lexically, for the service's own judgment (plan 21). It then does not follow symlinks or junctions, expand globs, or read the project's config. Those stay the hook's checks.

### Locked mode on Linux

- New `sudo saiife system install` and `sudo saiife system uninstall` set up or remove locked mode on Ubuntu 22.04+, Debian 12+ and RHEL 9+ (Rocky, Alma) with systemd.
- Install creates the `saiife` user and groups, puts the binary in `/opt/saiife/bin`, and writes `/etc/saiife`, the vault key and the `saiifed` unit. It adds managed hooks for Claude Code, Codex and Gemini CLI, starts the daemon and runs `saiife doctor`. It exits 2 on an install error or an unsupported system, and 1 when installed but `doctor` found a failure.
- The binary `/opt/saiife/bin/saiife` is installed at `0711`, so no process of the agent's user can trace or read a running hook. A reinstall moves a `0755` binary to `0711`, and `doctor` warns on any other mode.
- Uninstall removes exactly what install listed. `--purge` also removes the state, the audit and the users.
- New `saiife daemon --system`: the locked-mode daemon. It is the single writer of the audit log, stamps every record's time and identity, and signs checkpoints with an Ed25519 key.
- New `saiife check --managed`: the locked-mode hook. The guard runs in a separate worker process, and the call is allowed only after the daemon has recorded it. Every error blocks the call (it fails closed): a worker crash or hang, a daemon that is down, slow or refuses, or a policy that cannot be loaded.
- Claude Code's managed hook judges in its own process, without a worker (plan 21). A crash is still blocked by `onFailure` and the co-signer.
- New `saiife check --managed --event config-change`: Claude Code's ConfigChange hook. A change to user, project or local settings that sets a locked key is denied.
- Under a managed hook, the project hook of that agent goes quiet: no double judging, no second record. In locked mode `saiife init` writes no project hook for an agent with a managed hook, and `saiife init --off` keeps the project config.
- A killed or crashed hook never counts as an allow without a trace (plan 20).
- Claude Code: the managed drop-in gains a second `PreToolUse` hook, the co-signer. It is an `http` hook to `http://127.0.0.1:7433/v1/cosign/claude`, with `onFailure: "block"`. The drop-in also sets `"allowedHttpHookUrls": ["http://127.0.0.1:7433/*"]`.
- The daemon answers the co-signer with an empty `200` only when the command hook recorded an allow for the same session, tool call id and input hash. Otherwise it answers deny. It never answers allow.
- The co-signer port is fixed. If the daemon cannot bind it, the daemon keeps running and records `cosign_bind_failed`, and `doctor` fails `cosign.listen`. Claude Code then blocks every call.
- With `HTTPS_PROXY` or `HTTP_PROXY` set for Claude Code, add `127.0.0.1` to `NO_PROXY`. saiife does not set it, and `doctor` warns.
- Exit watch, for every agent: the hook registers with the daemon (`hook.begin`) before it reads its input, and names the call (`hook.bind`) once it has. A hook that ends without a verdict becomes a `hook` record with decision `no_verdict`, and `doctor` warns (`hooks.no-verdict`). This is a record only; there is no automatic lockdown.
- Codex and Gemini CLI get this detection and no co-signer, so their calls still run.
- The service judges each Claude Code call itself (plan 21), on Linux, macOS and Windows.
- The co-signer answers "no opinion" only when the hook recorded an allow and the service's own judgment of the input Claude Code sent allows too. Otherwise it denies with `the saiife service's own judgment denies this call` and writes a `hook` record with `event: "rejudge_denied"`, one per call.
- So a process of the agent's user that forges the hook's allow (begin, bind, append an allow, then end the hook) cannot let a call the policy denies run.
- The service judges with the system policy of the user who asks, as that user's account record gives the paths. It reads none of that user's files: it does not follow symlinks or junctions, expand globs, or read the project's config. Those stay the hook's checks.
- One case is stricter than the hook: `cp review.md .claude` is denied.
- A call that only `[guard] ask` rules deny passes when the same hook connection used an approval for that command.
- If the service cannot judge, the call is denied (`rejudge_failed`). It keeps 4 warm judge workers (`REJUDGE_POOL`), runs at most 3 calls per user at once (`REJUDGE_PER_PRINCIPAL`), and lets at most 32 wait (`REJUDGE_MAX_WAITING`).
- A burst of co-signed calls over the co-signer's caps (8 in flight per user, 16 in all) waits for a slot within the co-sign wait instead of getting `503`, which Claude Code blocked. Ten or more parallel sessions of one user no longer have calls blocked by the caps.
- The open-connection caps are doubled: the co-signer takes 64 per user (per process on Windows) and 128 in all, and the service's own socket or pipe 64 per user. At 48 parallel calls of one user, the 32 per user closed some connections, which blocked those calls.
- The co-signer now finds who asks on every OS. On Linux it reads the socket's uid from `/proc/net/tcp`, and on macOS from `net.inet.tcp.pcblist_n`. Windows is below. When it cannot tell who asks, it denies.
- `doctor` gains `cosign.rejudge`, `cosign.asker` and `hooks.rejudge-denied`.
- The managed hook benches gate CI again, with budgets per OS taken from plan 21's CI runs. The managed bash p95 measured 41.2 to 50.0 ms on Linux (budget 60 ms) and under 40 ms on macOS (budget 40 ms).
- New `core.lock` pack, on in locked mode. It protects saiife's own install: `/etc/saiife`, `/opt/saiife`, the state, audit and socket dirs, the unit and the managed agent settings.
- New `saiife doctor [--user <name>] [--json]` checks what locked mode relies on: files, owners and modes, keys, the daemon, agent users, sudo and root-equivalent groups, and plaintext credentials. Exit 0 all pass, 1 a warning, 2 a failure. It also warns when re-authentication is unavailable.
- `saiife status` shows a Locked mode block: mode, daemon health and chain head, policy hash, each managed agent's lock label and the MCP warnings.
- Lock labels: Claude Code is lockable. Codex and Gemini CLI are unverified: their managed hooks are installed, and `doctor` warns.
- Approvals. A connector capability in a service's `ask` list, or a command denied by a rule in the new `[guard] ask`, waits for a person in `[approval] approvers`. At most 20 pending requests per user. See `docs/approvals.md`.
- `saiife api` exits 3 with the request id. `--wait` polls for the result, and `saiife api result <id>` fetches it. Over HTTP the answer is 202, and `GET /v1/requests/{id}` fetches the result.
- New `saiife approvals [show]`, `saiife approve` (`--accept-truncated`) and `saiife reject`. `same_user = "reauth"` lets one person approve their own requests through polkit (`com.saiife.approve`); the default `"deny"` needs a second account. An approved command becomes a one-use grant for that exact command in the project, for 15 minutes.
- New `[notify]`: webhook, SMTP and command targets for `approval_created`, `limit_reached`, `error_denied_burst`, `chain_break` and `lockdown`. It sends masked one-line summaries only, never a body or a secret. See `docs/notifications.md`.
- New `saiife lockdown on|off` (root, `[admin]` groups and approvers) denies connector requests, or with `--scope all` every hook call too. It survives restarts and is recorded and notified. See `docs/threats.md`.
- Audit forwarding: the daemon sends a copy of the audit to syslog (RFC 5424, also over TLS), to a file, or to an HTTPS endpoint (batches, Splunk HEC). Each target has its own cursor, and delivery is at-least-once. Configure it with `[audit.forward.*]`. See `docs/forwarding.md`.
- New `saiife audit verify --external <file|dir>` compares the local chain with a forwarded copy, so a cut or rewrite of records that were already forwarded shows.
- Auditors: the `saiife-audit` group reads the audit, and a per-user `audit.query` lets others query their own records through the daemon. `saiife audit` gains `--kind` and `--service`. See `docs/auditors.md`.
- New `saiife policy check|test|show|reload`. It validates a policy (overlapping scopes included), runs its `[[example]]` entries (exit 1 on a mismatch), prints the merged policy and its hash, and reloads it (admin).
- The CLI commands that talk to the locked daemon now require the daemon's hello to say `mode = "locked"`: `secret`, `connect`, `api`, `run --secret`, `approvals`/`approve`/`reject`, `lockdown` and the locked `saiife audit` query. A personal broker or an older daemon on that socket is refused.
- The locked `saiife audit` query goes through the shared resolver. A system config without `locked = true` is refused with "<config>: locked is not true", and a daemon that does not answer as locked is "cannot reach the saiife daemon: …".
- `saiife audit verify` on a keyless chain whose genesis says `locked` prints "locked mode: no signing key" (it said "developer mode"). A personal broker chain says "personal broker".
- The control socket's answers may be up to 16 MiB; requests stay at 1 MiB.
- Docs: threat coverage for each of the four setups, an egress recipe (nftables) with a `doctor` hint, and the forwarding and auditors pages.
- CI: the `locked-linux` job runs a locked end-to-end demo.
- Carry-over fixes from plans 10 and 11: the approval outcome in the report, open outages, section filters, stricter forward target validation, forwarder resume after a chain restart, and polkit and install edge cases.

### macOS locked mode

- Locked mode on macOS (v2.1): `sudo saiife system install` works on macOS 15 or later, Apple silicon and Intel.
- It creates the hidden `_saiife` user and group and the `_saiifeaudit` group with `dscl`. It runs `saiifed` as the launchd daemon `com.saiife.saiifed`, with stderr in `/var/log/saiife/daemon.log`.
- State is in `/var/db/saiife`, the vault key in `/var/db/saiife/keys/vault.key` (`daemon_file`, 0400), and the sockets in `/var/db/saiife-run`.
- It writes the managed hooks for Claude Code (`/Library/Application Support/ClaudeCode/managed-settings.d/`), Codex and Gemini CLI, and registers the authorization right `com.saiife.approve`.
- The daemon reads the peer uid with `LOCAL_PEERCRED`. The pid (`LOCAL_PEERPID`) and the process names (`sysctl(KERN_PROC_PID)`) are attribution only. They live in the new `saiife-darwin` crate, the only crate allowed `unsafe`.
- The macOS binary keeps mode `0755` and the hardened runtime.
- Install requires the hardened runtime and warns on an ad-hoc signature. Tagged releases with the signing secrets are signed with a Developer ID and notarized. Other builds are ad-hoc signed, and the release notes say so.
- `doctor` gains the macOS checks: launchd, the signature, the auth right, `_saiifeaudit` and the Claude MDM profile.
- `saiife mcp` works on macOS. `run --secret` and `run --cloud` work. `DYLD_*` is removed from the command's environment on every platform. A `run_allow` entry through `/etc`, `/var` or `/tmp` is refused on macOS, with a `/private` hint.
- `core.lock` denies `security authorizationdb` writes, and `dscl`/`dseditgroup` on `_saiife*`.
- Lock labels are per platform. See `docs/install.md`.

### Windows (developer mode and locked mode)

- Developer mode on Windows (v2.2): Windows 11 23H2 or later and Server 2022 or later, x64 and ARM64, no administrator rights. `install.ps1` installs `saiife.exe` from a zip checked against `SHA256SUMS`. The audit is in `%LOCALAPPDATA%\saiife\audit`. See `docs/windows.md`.
- The guard has PowerShell and cmd readers. Claude Code's `PowerShell` tool is read as PowerShell on every OS, and its project matcher now includes it: run `saiife init` once, and `saiife status` warns until you do.
- Codex and Gemini CLI calls on Windows are read as both PowerShell and POSIX, and the stricter verdict wins.
- Windows paths are folded to one spelling. `core.filesystem`, `core.secrets`, `core.self`, `core.process` and `core.lock` gain Windows rules.
- Program names lose their extension in every shell (`rm.exe`, `git.cmd`), and a Windows tool's `-x` counts as its `/x`. `dir env:` is denied, like `env`.
- From Git Bash, a nested PowerShell or cmd line the reader cannot read is denied, `wsl` is judged inside, and a shell reading its stdin is denied.
- The reserved-word and vanishing-word rules hold for Windows program names too. `! rm.exe -rf /c/Windows`, `if cat.exe .env; then x; fi`, `! powershell -c "gc .env"` and `$v rm.exe -rf /c/Windows` are denied.
- `while`, `until`, `for x do`, `select x do` and `function` still count as running text out of order when a profile variable moves on the line (`while cat ~/y; do HOME=/x; done`).
- Locked mode on Windows (v2.2, plan 19b). Windows locked mode is a preview for Codex and Gemini CLI. Since plan 21 it is not a preview for Claude Code; see Known limits.
- `saiife system install`, from an elevated terminal, copies the binary to `C:\ProgramData\saiife\bin\saiife.exe`. It creates the service `saiifed` as the virtual account `NT SERVICE\saiifed`. The service restarts after 1 s, without end, and only SYSTEM and Administrators can stop or change it.
- It writes the managed hooks for Claude Code (`C:\Program Files\ClaudeCode\managed-settings.d\`), Codex (`C:\ProgramData\OpenAI\Codex\requirements.toml`) and Gemini CLI (`C:\ProgramData\gemini-cli\settings.json`). The hook command is `C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <a>`.
- Every path it makes has a protected access list, which `doctor` reads back.
- The daemon listens on the named pipe `\\.\pipe\saiife` and refuses to start when the name is taken. It reads each caller's SID and groups from its token; records carry `sid`.
- Release builds load DLLs only from System32. `doctor` checks the build, its imports and its signature. It also fails when Claude Code's `HKLM\SOFTWARE\Policies\ClaudeCode` would replace the managed files, and when an agent user can become an admin.
- With the co-signer (plan 20), a hook ended with `TerminateProcess(hook, 0)` is a deny for Claude Code. After plan 20 a forged allow still got through, with no code injection: any process of the agent's user could open the service's pipe, send `hook.begin`, bind the call's key, append an allow, and then end the real hook. The co-signer saw a recorded allow and accepted it. Code injected into the hook could do the same.
- Plan 21 closes this for Claude Code: the service judges each call itself, so a forged allow cannot let a call the policy denies run. `locked-windows` showed the forged allow and the hook kill denied on `windows-2022` and `windows-2025` (CI run 42673682022).
- On Windows the co-signer finds who asks by the pid that owns the socket in the TCP table. That pid must be at most 3 parent steps above the hook that bound the call. Code of the agent's user can re-parent a process under Claude Code, so there the service's own judgment, not the tie, is the barrier.
- An elevated `doctor` keeps the `locked.preview` line, because it does not run `claude.exe`. The agent user runs `saiife doctor --user <name>`.
- The managed bash p95 on Windows measured 59.1 ms (`windows-2022`) and 59.6 ms (`windows-2025`), with a budget of 130 ms. It was about 150 ms before plan 21.
- CI's new `locked-windows` and `package-windows` jobs run it on throwaway runners. `windows-latest` checks the readers against real PowerShell and cmd.

### Connectors, MCP and the personal broker

- Locked mode on Linux gets an encrypted vault. New `saiife secret add|list|rotate|remove|import` store credentials (token, basic, header) in a vault the agent cannot read. `import` moves plaintext credentials out of a home and keeps a 7-day backup.
- New `saiife connect <service>` writes a deny-all policy file. With `--secret <name>` it reuses an existing secret that allows the service. It refuses a host parameter that is not a bare lower-case hostname, instead of writing a policy file that would not load.
- New `saiife api <service> <operation>`: the daemon checks the call against the policy and limits, adds the vault credential, sends it and masks the answer.
- First connectors: Shopify, HubSpot, GitHub and a generic HTTP service. Waves 2 and 3 add Stripe, Slack, Discord, Linear, Intercom, Airtable, GitLab, Sentry, PagerDuty, Zendesk, Segment, WooCommerce, Salesforce and Email (SMTP send, IMAP read). Each has a docs page with a suggested policy that puts every write under `ask`. Stripe and WooCommerce refunds have amount caps. See `docs/connectors/README.md`.
- Manifests gain host parameters, built bodies (form, GraphQL, text), pagination and prefixed auth headers. `policy check` no longer warns "matches no operation" for a concrete qualifier rule such as `messages:read:channel=C0123`.
- Cloud connectors: Amazon S3 and STS (`aws-s3`, `aws-sts`), Google Cloud Storage (`gcp-storage`), Azure Resource Manager (`azure-arm`) and Azure Blob Storage (`azure-blob`). Each has a docs page.
- In `mode = "sign"` (the default) the daemon signs each request with AWS SigV4, or attaches an OAuth2 token it mints from a `gcp_sa` or `azure_sp` secret. The agent never sees a credential. Capabilities follow the IAM action.
- New vault kinds `aws`, `gcp_sa` and `azure_sp`. Object keys may contain `/` (`objectkey`, `objectname`). The cloud key shapes are masked.
- STS mode (AWS only, opt-in): `saiife run --cloud <service> -- <command>` runs the command with an `sts:AssumeRole` credential of 900 s and an inline session policy built from the saiife policy. A project overlay can only narrow it. `doctor` warns for every service in STS mode. Only `requests_per_minute` applies to leases. Each lease is a `secret` record with `event = "cloud_lease"`. See `docs/connectors/aws-s3.md`.
- OAuth2 secrets (`saiife secret add --kind oauth2`, paste flow): the daemon refreshes access tokens itself, keeps them in memory, and persists a rotated refresh token before using it. `saiife run --secret` refuses an oauth2 secret (`run_not_allowed`): it is for connectors only, and its refresh token is never handed out.
- New HTTP gateway on `gateway.sock`, and an optional loopback TCP listener with `saiife api token` (12 h bearer tokens bound to your uid).
- New `saiife run --secret` runs a command from the daemon's `run_allow` list with a leased secret in its environment, and masks its output.
- Per-service limits: requests per minute, writes, deletes, bulk and amount. The `connector` audit record.
- A connector or MCP gateway call still waiting for an upstream slot is no longer sent after a reload or a lockdown. It is denied with `policy_changed` or `lockdown`; nothing is sent, and it does not count against limits. Any change to the config or a connector manifest does this, whichever call it touches. `policy_changed` tells the agent to call again.
- In that case an oauth2 401 is not refreshed or resent: the 401 is the answer, and the record says `auth_retry_skipped`. A gateway call that gets no slot in time is now the `concurrency` limit, and one to a server that is not running is `upstream_unavailable`. Both were `upstream_failed` and counted.
- Masking: the audit masks the token shapes of the new services, also when glued to other text. That covers Stripe `sk_`/`rk_` keys and `whsec_` signing secrets, Slack `xox*-`, `xoxe` and `xapp-` tokens, Slack and Discord webhook URLs after their host path, Discord bot tokens, Linear `lin_api_`/`lin_oauth_`, Sentry `sntrys_`/`sntryu_`, GitLab `glpat-` and the other `gl*-` prefixes, Salesforce session ids, Intercom tokens, Airtable `pat…`, and WooCommerce `ck_`/`cs_` keys.
- Environments: `[environments.<name>]` adds packs and overrides service settings. In locked mode an environment is bound to a scope (`[[scope]] env`) and is part of the policy hash. New `saiife env list|use`; `env use --scope` is root only. `env --system-config <file>` means locked mode and refuses a file without `locked = true`. See `docs/environments.md`.
- In developer mode and under the personal broker, the project's `env` (`saiife env use`) selects the environment of `saiife api` calls. An environment changes connector calls only there; its guard packs apply in locked mode, and a developer-mode `policy show` says so.
- A well-formed `env` that no environment defines falls back to the base config, with a warning. In locked mode the project's `env` is ignored.
- `saiife status` and `saiife policy show` print the policy hash of each environment (`policy (env <name>): sha256:…`) beside the base one, so a record's `policy` names the environment it ran under. `policy show` shows a non-admin only their own environment's hash.
- The managed hook applies the caller's scope environment: its packs, and its hash in the record. Only when some scope binds an `env` does it look up the caller's groups. It reads `/etc/group` when the user is local and `nsswitch.conf` takes groups from `files` alone, and uses NSS (`getent`/`id`) otherwise.
- A group lookup that fails denies the call as `error_denied` with policy `unavailable`, recorded like any other failure. `env list` and the daemon's `policy.show` fail the same way rather than show "no environment".
- An approved connector request is sent under the environment it was asked under, or not at all. A locked scope rebound to another environment, or a developer-mode environment no longer defined, makes the send `send_failed` with `env_changed`. `approvals show`, the list and the `approval_created` notification name the environment. A request stored with no environment (the base config, or sealed before environments existed) is not checked.
- Collections: `saiife api collection list|run` runs saved calls from `.saiife/collections/`. Each step goes through the full pipeline. See `docs/collections.md`.
- MCP: `saiife mcp` is a stdio MCP server. It lists brokered connector operations (`shopify_orders_list`) and gateway tools (`linear__create_issue`) as tools, and sends every call through the daemon's pipeline (`via = "mcp"`). `saiife_result` fetches a pending result, and `--wait` waits for an approval. See `docs/mcp.md`.
- The MCP gateway (Linux, locked mode only) runs third-party stdio servers declared as `[mcp.<name>]` under the daemon. Their tokens are in the vault, they run in a Landlock sandbox (`saiife __mcp-spawn`), and they get per-tool `allow`/`ask`/`deny`, limits and one `connector` record per call. Results are masked and cut at `max_response_bytes`. Approvals gain the type `mcp`.
- `system install` writes the Claude Code managed MCP allowlist drop-in `60-saiife-mcp.json` from policy; it replaces `--mcp-allow`. `doctor` and `status` gain the MCP checks.
- Locked mode denies MCP tools whose server is not in `[guard.mcp] allow_servers`. `doctor` and `status` warn about each listed server: its requests are not brokered or limited. On Codex and Gemini CLI, `saiife mcp` needs `[guard.mcp] allow_servers = ["saiife"]`.
- Personal broker: `saiife daemon --user` runs the broker as your own user. On Linux the vault key is in the Secret Service (GNOME Keyring, KWallet) and `vault.bin` is sealed under it. On macOS the key is in the login Keychain and the sockets are in `~/Library/Caches/saiife/run`. On Windows the key is in Credential Manager, with a pipe per user. See `docs/personal-broker.md`.
- `--print-unit systemd|launchd` prints a login unit. The broker's audit chain is unsigned, and `saiife audit --broker` reads it. `secret import` and `audit.rotate_key` are refused.
- New `saiife-keychain` crate: the Secret Service over zbus, and a macOS Keychain backend. `core.self` and `core.secrets` gain mistake-layer rules for the broker.

### Fleet packaging

- Linux: `.deb` and `.rpm` packages (amd64/arm64; the rpm is signed when the key is set). Their scripts run the new `saiife system install --fleet`, which reads `/etc/saiife/fleet/config.toml` and `install.toml`.
- A changed config now reloads a running daemon, and install exits 1 when the daemon did not take it. `doctor` gains `files.package` and an `agents` warning.
- The release adds `SHA256SUMS` over all assets, and `SHA256SUMS.asc` when signed. There is an Ansible role and an Intune Linux compliance policy.
- macOS: one signed, notarized `.pkg` per architecture (`saiife-<version>-arm64.pkg`, `saiife-<version>-x86_64.pkg`). Its `postinstall` runs `saiife system install --fleet` and fails loudly when install refuses (when SIP is off, say).
- A release without the installer certificate has no pkg; it never publishes an unsigned one. Jamf and Intune macOS recipes are in `deploy/`.
- `doctor` checks `files.package` on macOS too, and warns when the staging path is not root's alone. Root refuses to run a staging copy on such a path.
- `system install` now holds a root-only lock (`/etc/saiife-install.lock`), on Linux too. An overlapping install waits up to 2 minutes, then exits 2. `--allow-test-build` exists only in builds with debug assertions.
- Windows: an MSI per architecture, Authenticode-signed when the release has the signing secrets, with Intune and GPO recipes.
- See `docs/fleet.md`.

### Known limits

- Windows locked mode is a preview for Codex and Gemini CLI. A process running as the agent's own user can end a hook with `TerminateProcess(hook, 0)`. Before plan 20 the agent read that exit 0 as allow, and nothing was recorded (measured on `windows-2022` and `windows-2025`). `doctor` says so on every locked run (`locked.preview`). An elevated `doctor` says so for Claude Code too, as it does not run `claude.exe`.
- For Claude Code it is not a preview since plan 21. After plan 20 the co-signer blocked a forged exit 0, but not a forged allow, which needs no code injection. Code injected into the hook could do the same, as Windows gives a user full access to its own processes. Plan 21's own judgment by the service closes both: a forged allow cannot let a call the policy denies run (CI run 42673682022).
- Not closed: a program that takes `127.0.0.1:7433` while the service restarts. This is accepted.
- The service's judgment reads none of the asking user's files. Symlinks, junctions, globs and the project's config stay the hook's checks, and code of the agent's user can change them after any judgment anyway.
- On Windows the co-signer ties the asker to the hook only by parent steps, and code of the agent's user can re-parent a process under Claude Code. The service's own judgment is the barrier there.
- Codex and Gemini CLI get detection only: a hook that ends without a verdict is recorded, but the call still runs.
- In locked mode, a Claude Code tool call whose input is over 16 MiB is blocked (the co-signer's body cap).
- Behind a proxy, add `127.0.0.1` to `NO_PROXY` for Claude Code, or the co-signer blocks every call.
- Before plan 21 the managed hook cost about 90 ms on Linux, and 104 to 139 ms on Windows. Plan 21 brought the managed bash p95 to 41.2 to 50.0 ms on Linux and about 59 ms on Windows.
- Nothing has run on real Windows outside CI.
- Every macOS lock label is `unverified` until the new `scripts/lock-check/macos-vm.sh` has run in a macOS VM. Every Windows lock label is `unverified` until the new `scripts/lock-check/windows-vm.ps1` has run in a VM.
- Same-user approval is off on macOS and Windows; approvals need a second account. On macOS the prompt cannot show what is approved, so `same_user = "reauth"` acts as `"deny"`. On Windows the approver needs a separate session, and saiife never handles a Windows password.
- The MCP gateway and the egress recipe are Linux only. On macOS `[mcp.*]` is a load error.
- The MCP gateway child's network is not sandboxed.
- Codex and Gemini MCP servers are restricted by the hook only. The `allow_servers = ["saiife"]` listing is unpinned: any server registered as `saiife` is allowed.
- The personal broker is not a security boundary: a script of the same user can read the key.
- STS mode hands a credential to agent-controlled code. Any process of your user can ask the daemon for a lease, and the `run_allow` check binds only the `saiife` client.
- Under the personal broker, the HTTP gateway (`gateway.sock`) runs every call under the base config, not the project's `env`. Only `saiife api` sends the project's environment, so agents should use it. Binding an environment to an `api token` is a later item.
- `forward_failing` is a defined `[notify]` event, but nothing sends it yet.

## 0.1.1 — 2026-10-19

- Guard: `rm` targets are judged against a `cd` earlier in the same command line (`cd / && rm -rf *` is now blocked).
- status: warns about nested `.saiife/config.toml` files that `saiife init` did not create.

## 0.1.0 — 2026-10-19

First release.

- 13 guard packs: filesystem, git, secrets, self-protection, Docker, Kubernetes, AWS, Azure, Google Cloud, Terraform, Postgres, MySQL and MongoDB. Each has a docs page in `docs/packs`.
- Audit log of every decision, with secrets masked. Read it with `saiife audit`.
- `saiife audit --report` writes a self-contained HTML report that a non-developer can read.
- `saiife init`, `saiife init --off` and `saiife status` for Claude Code, Codex and Gemini CLI. `status` detects when a hook or config was changed.
- Agent docs in `docs/agents`, a Codex with Ollama recipe, and a demo script.
- Prebuilt binaries for Linux and macOS (Intel and ARM), and `install.sh` with checksum verification.

Known limit: the Codex and Gemini CLI hooks are not yet verified against live installs.
