# MCP: `saiife mcp` and the MCP gateway

Locked mode (Linux; on macOS `saiife mcp` only, see below). Two parts, both
about the Model Context Protocol (MCP):

- **`saiife mcp`** is a stdio MCP server that the agent's own config starts.
  It lists brokered connector operations (and gateway tools, below) as
  typed tools and sends every call to the saiife daemon. It decides nothing,
  caches no verdict and holds no credential.
- **The MCP gateway** runs third-party stdio MCP servers under the daemon,
  with their tokens in the vault, sandboxed, with a per-tool policy. It moves
  such a server out of the unbrokered gap of `[guard.mcp] allow_servers`.

The gateway needs locked mode. `[mcp.<name>]` in a personal broker config is
a load error: "the MCP gateway needs locked mode: in personal broker mode
its servers would run as you". `saiife mcp` itself works against the locked
daemon and the personal broker; the connector tools are the same.

**The MCP gateway is Linux only in v2.1.** Its children are confined with
Landlock, which macOS does not have, and `sandbox-exec` is deprecated, so it
is not used. On macOS `[mcp.<name>]` is a load error in every mode:
"the MCP gateway needs Linux (Landlock) in this version". `saiife mcp` works on macOS
(locked daemon or personal broker), with the connector tools; it lists no
gateway tools there.

## `saiife mcp`: connectors as tools

Register it in the agent. The program must be the installed one:

```bash
claude mcp add saiife -- /opt/saiife/bin/saiife mcp
```

Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.saiife]
command = "/opt/saiife/bin/saiife"
args = ["mcp"]
```

Gemini CLI, in its `settings.json`:

```json
{ "mcpServers": { "saiife": { "command": "/opt/saiife/bin/saiife", "args": ["mcp"] } } }
```

`saiife` is a reserved server name. On Claude Code with saiife's managed
settings, the server is allowed by its command, so a project `.mcp.json`
cannot define its own server called `saiife` (see
[Claude Code](agents/claude-code.md#locked-mode-v2)). There the hook
brokers it: it lets each call through and the daemon judges it.

On Codex and Gemini CLI nothing pins that command, so a project or user
config could register its own `saiife` server, running any program as the
agent user. There the hook does not broker `saiife`: it denies the
server's tools unless `[guard.mcp] allow_servers` lists `"saiife"`. To use
`saiife mcp` on those agents:

```toml
[guard.mcp]
allow_servers = ["saiife"]
```

Listing `"saiife"` accepts the same risk as any listed server: a project
or user config can register its own `saiife` server, and its calls are
allowed by name and not brokered. While Codex or Gemini CLI is installed,
`doctor` and `status` warn: `MCP server saiife is listed: on Codex and
Gemini CLI any server named saiife is allowed, and nothing pins its
command`. Only `saiife` spelled exactly so may be listed. Claude Code's
managed settings never allow it by name.

### Tool names

| Tool | Meaning |
|---|---|
| `<service>_<operation>` | a connector operation, for example `shopify_orders_list`; `.` and `-` become `_` |
| `<server>__<tool>` | a tool of a gateway server, for example `linear__create_issue`; every character outside `[a-z0-9_-]` becomes `_` |
| `saiife_result` | fetches the result of a pending call: `{"request": <id>}` |

Rules:

- A name is at most 51 characters, because Claude Code adds `mcp__saiife__`
  and the whole name must fit 64.
- Only operations and tools whose policy action is `allow` or `ask` are
  listed. The description ends with `Policy: allowed.` or `Policy: needs
  approval; the result says how to get it.` Listing grants nothing: every
  call is decided by the daemon under the policy as it is then.
- A name that would collide with another server's tool or a connector tool
  is not listed, and neither is the one it collides with. saiife prints a
  warning on stderr and never routes by guesswork. A connector tool name
  that holds `__` is not listed either.
- Collections are not tools. Connector operations that a collection calls
  are.
- The list is rebuilt on each `tools/list`. Every 30 seconds `saiife mcp`
  compares the daemon's hash of the lists and sends
  `notifications/tools/list_changed` when it moved (a policy reload, a
  server that started or stopped).
- Connector tools carry `readOnlyHint` for reads and `destructiveHint` for
  deletes and bulk operations. Gateway tools carry no hints, because a
  third-party hint is not trusted.

Every call goes through the daemon's pipeline, as `saiife api` does, and
writes one `connector` record. The record's `via` is `mcp`.

`via` is declared by the client and is never used for a security decision.
It is attribution only, like the project name. The daemon accepts `cli` and
`mcp` from a client; anything else (including `approval`) is refused as
`bad_request`.

### Results and errors

- A finished call returns the masked body as text. A body that is not UTF-8
  comes as a resource item (`saiife://response`). When there is another page
  of results, a second text item says how to ask for it.
- Denied, limited, upstream-failed and "saiife unavailable" outcomes are
  results with `isError: true` and the one-line reason `saiife api` prints.
  Policy outcomes are never JSON-RPC errors.
- JSON-RPC errors are only for a malformed request (`-32700`, `-32600`), an
  unknown method (`-32601`) and an unknown tool or arguments of the wrong
  shape (`-32602`). Nothing runs in these cases.
- A JSON-RPC batch is always refused (`-32600`).

### `ask`, pending results and `--wait`

A call whose action is `ask` waits for a person (see [approvals](approvals.md)).
Without a wait, the result is a normal (not error) answer:

```
waiting for approval #42. Call the tool saiife_result with {"request": 42} later to get the result. Do not repeat this call.
```

with `structuredContent` `{"pending": 42}`. A repeated identical call returns
the same id (see [approvals of type `mcp`](#approvals-of-type-mcp)).

`saiife mcp --wait 5m` makes a tool call that needs approval wait, polling
every 2 seconds, for at most the given time (never more than 1 hour). When
the client sent a `progressToken`, each poll sends `notifications/progress`.
When the time is up, the answer is the pending text above. Set it below the
client's own tool-call timeout. Which timeout each client uses has not been
checked yet.

The environment variable `SAIIFE_MCP_WAIT` sets the same thing, with the
same rules (`SAIIFE_MCP_WAIT=5m`; unset or empty means no wait). `--wait`
wins when both are set. On Claude Code use the variable, not the flag:
saiife's managed settings pin the server's command as exactly
`/opt/saiife/bin/saiife mcp`, so an extra argument such as `--wait 5m`
makes the server unavailable there:

```bash
claude mcp add -e SAIIFE_MCP_WAIT=5m saiife -- /opt/saiife/bin/saiife mcp
```

saiife never uses MCP elicitation or sampling to ask. An answer given inside
the agent's own UI would come from the requester's session, which is
self-approval. An approver decides outside the agent, with `saiife approve`.

## The gateway

An admin declares each server in a root-owned drop-in, for example
`/etc/saiife/policy.d/mcp-linear.toml`:

```toml
[mcp.linear]
command = "/opt/mcp/linear/bin/linear-mcp"
args = ["--stdio"]
read_paths = ["/opt/mcp/linear"]
env = { LINEAR_API_KEY = "linear-mcp" }
allow = ["list_*", "get_*"]
ask = ["create_*", "update_*"]
deny = ["delete_*"]
read_tools = ["list_*", "get_*"]
timeout = "30s"
limits = { requests_per_minute = 60, writes_per_hour = 30, max_response_bytes = 1048576 }
```

Then:

1. Store the token, allowed for the server's service name `mcp:<name>`:

   ```bash
   saiife secret add linear-mcp --kind token --service mcp:linear
   ```

2. Add `mcp:linear` to the `services` of the `[[scope]]` of the users who
   may use it (a call without it is denied as `no_scope`).
3. `saiife policy check` the files, then `saiife policy reload`.

Keys of `[mcp.<name>]`:

| Key | Meaning |
|---|---|
| `command` | absolute path of the program. Its whole path must be root-owned, checked at every start. Interpreters are allowed, since the file is admin-written |
| `args` | arguments, passed as they are |
| `env` | `{ VARIABLE = "vault secret name" }`. The value reaches the child's environment only. The variable is `[A-Z_][A-Z0-9_]*` and not `PATH`, `HOME`, `LANG`, `TMPDIR`, `LD_*`, `DYLD_*` or a few other loader variables |
| `read_paths` | extra paths the server may read and execute (its own install dir, a runtime). Every entry must exist; one that cannot be opened fails the start |
| `allow`, `ask`, `deny` | tool name globs. Any `deny` wins, then `ask`, then `allow`; nothing matching is denied (`default_deny`). `deny` and `ask` match case-insensitively |
| `read_tools` | tools counted as reads by the limiter |
| `limits` | `requests_per_minute`, `writes_per_hour`, `max_response_bytes` (default 5 MiB). The delete, bulk and amount limits are refused at load |
| `timeout` | per call, `1s` to `300s`, default `30s`. On a timeout saiife sends `notifications/cancelled` |
| `sandbox` | `"landlock"` (default) or `"off"` |

A server name is `[a-z0-9-]{1,32}` and is never `saiife`. A name may not be in
`[guard.mcp] allow_servers` too (load error: "MCP server <s> is both
unbrokered ... and brokered ...; remove it from allow_servers").

A server is not a connector. It takes no environments, and saiife does not
check a call against the server's own `inputSchema`: that is the server's
job and not a control.

### What the daemon does

- One child per server, at most 4 calls in flight, restarted after a crash
  with a backoff of 1 s up to 60 s. Lifecycle events are `daemon` records:
  `mcp_server_started`, `mcp_server_exited`, `mcp_server_failed`. A server
  that answers an unsupported protocol version is stopped
  (`mcp_version_unsupported`).
- The daemon speaks protocol version `2025-11-25` to servers and declares no
  client capabilities. A server's requests (`sampling/*`, `elicitation/*`,
  `roots/list`) are answered `-32601`.
- A server's stderr is masked with its secrets and written to the daemon's
  stderr as `saiife: mcp <name>: ...`, at most 64 KiB a minute.
- A server's output is bounded. A line over `max_response_bytes` plus
  64 KiB stops the child. So do more than 5000 lines, or more than 8 MiB,
  in 10 seconds that answer no call of the daemon's (notifications, server
  requests, unreadable lines, answers to a call already given up). Either
  way the child is restarted with the backoff, and the
  `mcp_server_exited` record says why. A `notifications/tools/list_changed`
  makes the daemon list the tools again, at most once every 5 seconds;
  notifications that arrive in between are folded into the next list.
- Tool names are kept as the server lists them. A tool whose name is not 1
  to 128 of `A-Z a-z 0-9 _ . -`, or holds a secret, is dropped; the
  daemon's stderr says how many, never the names.
- A secret added, rotated or removed restarts (or starts, or fails) the
  servers that name it, at once. A policy reload restarts servers whose
  settings changed.

### The pipeline for a gateway call

lockdown, then scope (`mcp:<name>` must be listed), then resolve (the tool
must be in the server's current list: `unknown_operation`), validate, policy,
limits, ask, send, mask, record. A denied call costs nothing upstream.

Arguments:

- The agent's exact text is forwarded; saiife does not re-write it.
- Duplicate keys are refused (`bad_param`).
- More than 256 KiB is refused.
- A number that would change on a round trip is refused with `bad_param`:
  any exponent form (`1e2`), an integer beyond 64 bits, and a decimal that
  is not exact in a double. A tool that needs such a value takes it as a
  string.

Results:

- Every string is masked with the server's secret values (all their
  encodings) and the v1 patterns, keys and `structuredContent` included.
- Image and audio items are replaced by `[image content omitted by saiife]`.
- A result is cut at `max_response_bytes` and says so in a closing note; the
  answer carries a `truncated` flag.
- A tool whose name masking would change (it holds a secret) is dropped from
  the list.

The record has `kind = "connector"`, `tool = "mcp"`, `service = "mcp:<name>"`,
`operation` the tool, `mcp_is_error`, `resp_bytes`, `secret` (the server's
secret names) and `via`. `saiife audit --service mcp:linear` works as for any
service. Arguments are shown masked, each value cut at 1 KiB.

A call can be denied with: `lockdown`, `no_scope`, `scope_conflict`,
`policy_invalid`, `upstream_unavailable` (the server is not running),
`unknown_operation`, `bad_param`, `default_deny` or `deny:<glob>`,
`limits_unavailable` and `masked_content`; and, after an approval,
`policy_changed`, `env_changed` and `body_changed`.

### Approvals of type `mcp`

An `ask` tool call creates an approval request of type `mcp`: `service` is
`mcp:<name>`, `operation` is the tool, and the display holds the masked
canonical arguments.

- Identical pending calls share one id (same user, server, tool and
  arguments), but only when nothing in them was masked. A retrying agent
  gets one request, and each call writes an `ask` record that names it.
- Arguments or a tool name that masking would change cannot be approved
  (`masked_content`): the approver could not see what would be sent.
- On approval, the current policy and the server's current tool list are
  checked again. A tool that is now denied or gone is not sent
  (`policy_changed`, `unknown_operation`).
- The display is cut at 4 KiB. A cut display needs
  `saiife approve <id> --accept-truncated`.
- An approved call is recorded with `via = "approval"`.

## The sandbox, and its limits

The daemon starts each server through `saiife __mcp-spawn`, which sets
`no_new_privs`, starts a new session, closes inherited descriptors above 2,
clears the environment (only `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME`,
`LANG=C.UTF-8`, `TMPDIR` set to the server's home, and the listed secrets
stay) and applies a Landlock ruleset:

- read and execute: `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`, the
  server's `read_paths`, and a few files under `/etc` (TLS roots, resolver,
  `hosts`, `nsswitch.conf`, `localtime`, `passwd`, `group`);
- read and write, never execute: the server's home and working dir
  `<state>/mcp/<name>/` (0700) and `/dev/null`;
- nothing else: not the config, the vault, the credentials, the audit or the
  state dirs.

The limits, as built:

- **The network is not sandboxed.** Landlock covers files and exec, not
  network. A server can connect anywhere the daemon user can, and it needs
  to, to call its API. A server that turns hostile can send what it reads
  (its own token, and anything in its `read_paths`) to a host of its choice.
  The [egress recipe](egress.md) matches the agent's account, not the daemon
  user, so it does not limit a gateway server. The daemon also refuses socket
  peers that are gateway children (`mcp_child_peer`, recorded at most once a
  minute), and in locked mode it refuses any peer whose uid is the daemon's
  own, because Landlock does not stop a connect to a pathname Unix socket.
  A child cannot reach the control socket or the gateway socket, and no
  legitimate client runs as the daemon user.
- **Landlock ABI.** ABI 0 (no Landlock, or a kernel without it) fails closed:
  the server does not start (`sandbox_unavailable`) unless it has
  `sandbox = "off"`. A partial ABI (1 to 5) confines files only: signals to
  the daemon user's processes and abstract Unix sockets are not scoped until
  ABI 6 (Linux 6.12). `saiife doctor` warns about it.
- **Protected directories.** A `read_paths` entry may not be `/`, hold `..`,
  or equal, contain or sit inside the config, state, audit or socket dirs,
  `/run/credentials`, `$CREDENTIALS_DIRECTORY` or the daemon's
  credentials dir. Policy load refuses the fixed ones, and the spawn helper
  checks the opened path against all of them again, so a symlink changed
  after load is caught.
- **`read_paths` must exist.** An entry that cannot be opened fails the
  spawn (exit 126), as a missing allow-list entry is safer to fix than to
  skip.
- **Hardlinks and bind mounts** of a protected directory are not detected.
  The checks compare paths and the identity of directories, not every name a
  file may have.
- **No exec from under the server's home.** The writable home is not
  executable, so a server cannot write a program and run it. Install
  programs and runtimes root-owned, under `/opt` or `/usr`.
- **`/tmp` is not writable.** `TMPDIR` points at the server's home; a
  server that ignores `TMPDIR` and writes to `/tmp` fails.
- **No JIT under the unit.** The daemon's systemd unit sets
  `MemoryDenyWriteExecute=yes`, which its children inherit. Node.js
  servers need `--jitless` (for example `args = ["--jitless",
  "/opt/mcp/x/index.js"]`); other runtimes with a JIT need the same.
- **`/proc` is limited to the server itself.** The ruleset allows reading
  only the server's own `/proc/<pid>` (the process saiife started). The rest
  of `/proc` (`/proc/cpuinfo`, `/proc/meminfo`, other processes, and the
  `/proc/self` of a process the server starts) is denied, so a runtime that
  reads it at start may need a flag to skip that.
- **A process that leaves the group is not killed with it.** When a server
  stops, the daemon kills its whole process group. A grandchild that calls
  `setsid` itself leaves that group and keeps running. It is still under
  the same Landlock ruleset and `no_new_privs`, and the daemon refuses it at
  its sockets like any gateway child.
- A server runs as the **daemon user**, not as a separate account. A
  separate uid is a follow-up.
- `doctor` warns on `npx` and `uvx`, which download code at run time, and on
  an absolute-path argument that is not root-owned.

## `doctor` and `status`

| Check id | Meaning |
|---|---|
| `mcp.gateway.<name>` | pass: `MCP server <name> is brokered (<n> tools)`. Fail: `MCP server <name> is not running: <reason>` (or the daemon is unreachable), or `sandbox unavailable`. Warn: `sandbox is off`, an argument that is not root-owned, `npx`/`uvx` |
| `mcp.landlock` | info: `Landlock ABI <n>`, shown when a gateway server exists |
| `mcp.sandbox` | warn for ABI 1 to 5, when a server runs with `sandbox = "landlock"`: `MCP server sandbox is weaker than full`, with the missing part |
| `mcp.claude.allowlist` | pass: `Claude Code MCP allowlist matches policy`. Warn: `the Claude Code MCP allowlist differs from policy; run saiife system install again` |
| `mcp.codex.restriction`, `mcp.gemini.restriction` | info: `MCP servers for Codex are restricted by the hook only` (and the same for Gemini CLI). The detail says the `saiife` server is not brokered there, and whether `allow_servers` lists it |
| `mcp.saiife` | warn, when `allow_servers` lists `saiife` and Codex or Gemini CLI is installed: `MCP server saiife is listed: on Codex and Gemini CLI any server named saiife is allowed, and nothing pins its command` |
| `mcp.<server>` | warn, for each server in `allow_servers` other than `saiife`: `MCP server <server> bypasses saiife: its requests are not brokered or limited` |

`saiife status` prints one line for each gateway server:

```
MCP server linear: brokered, running (12 tools)
```

and, for each unbrokered server in `[guard.mcp] allow_servers` (not
`saiife`), the warning

```
MCP server linear bypasses saiife: its requests are not brokered or limited
```

When `doctor` finds a credential in an agent's MCP config, the finding ends
with `; move it behind the MCP gateway: docs/mcp.md`. That is this page.

## Managed restrictions

- **Claude Code.** `system install` writes
  `/etc/claude-code/managed-settings.d/60-saiife-mcp.json` from policy: the
  `saiife` server by command, and each `[guard.mcp] allow_servers` by name.
  It replaces a hand-kept `--mcp-allow` list, so the two cannot disagree.
  `doctor` warns when it drifts after a reload. `uninstall` removes it.
  The hook brokers `saiife` only while that file is root-owned, not group-
  or world-writable, and holds exactly saiife's pin. Test builds
  (`ci-locked`, debug assertions on) compile in the seam
  `SAIIFE_TEST_CLAUDE_MCP_DROPIN`, which can point the hook at another file
  and so grant `Brokered`. That is one reason those builds are CI-only and
  install only with `--allow-test-build`.
- **Codex and Gemini CLI.** saiife does not restrict their MCP servers yet:
  `doctor` says "restricted by the hook only", and the hook judges each call
  (`[guard.mcp] allow_servers`, as in the agent pages). Nothing stops either
  agent from configuring more servers, and nothing pins the command of a
  server called `saiife` there, so the hook does not broker it: list
  `"saiife"` in `allow_servers` to use it (see above). The managed keys of
  both agents are not verified live, so none is written.

## Moving a server out of `allow_servers`

1. Remove it from `[guard.mcp] allow_servers` (it may not be in both).
2. Store its token: `saiife secret add <name> --kind token --service mcp:<server>`.
3. Declare `[mcp.<server>]` as above, with `env` naming the secret.
4. Remove the token from the agent's own MCP config and from any plaintext
   file.
5. Remove the server from the agent's config. The agent now sees its tools
   through `saiife mcp`, as `<server>__<tool>`.
6. `saiife policy check`, `saiife policy reload`, `saiife doctor`. The
   "bypasses saiife" warning is gone for that server.

## Prefer a native connector

Where saiife has a [connector](connectors/README.md) for the service (Linear,
Sentry, GitHub, Slack and others), use it. A connector has typed operations,
capabilities, amount caps and a fixed set of hosts. A gateway server is a
third-party program that decides for itself what it sends and where, so it
is the second choice: use it for a service with no connector.

## Not covered

- The server's network traffic (above), and what a server does with data it
  was legitimately given.
- A tool that exfiltrates through its own result is masked for vault values
  and known token shapes only.
- Remote MCP servers over HTTP (OAuth), and MCP resources and prompts. Only
  stdio servers and tools are brokered.
- See [threat coverage](threats.md).
