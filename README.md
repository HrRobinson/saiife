# saiife

saiife guards AI coding agents (Claude Code, Codex, Gemini CLI) on your own
machine. It blocks destructive and secret-leaking actions before the agent
runs them, and keeps an audit log that a non-developer can read.

Status: pre-release.

## Install

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh
```

The script verifies the SHA-256 checksum and installs `saiife` to `~/.local/bin`.
More options (pinned version, all users, manual install, uninstall):
[docs/install.md](docs/install.md).

To build from source instead, with Rust installed:
`cargo install --path crates/cli` (this puts `saiife` in `~/.cargo/bin`, which
must be on your `PATH`).

## Quickstart

Run these in your own terminal, in the project folder:

```sh
saiife init                         # hook your agents into this project
saiife status                       # check that the guard is in place
saiife audit                        # see what the agents did and what was blocked
saiife audit --report report.html   # the same as one HTML file to share
saiife audit verify                 # check that the audit log was not edited
```

`saiife init` finds the agents installed on your machine and tells you one
last step to do in each agent (accepting a trust prompt). `saiife init --off`
removes exactly what `init` added. It keeps `.saiife/config.toml` if you edited
it.

`saiife audit verify` checks that every audit record still follows the one
before it (each record carries the hash of the previous line). It catches
edited, deleted, inserted or reordered lines, and reports the file and line of
the first break. Exit code 0 means intact, 1 broken, 2 the log could not be
read. In developer mode there is no signing key, so it catches accidental edits
and clumsy tampering, not a deliberate rewrite by someone with your rights,
and it does not notice that the newest records were removed (see
[threat coverage](docs/threats.md)).
`saiife audit --report` shows the same chain status.

## Brokered services

In locked mode on Linux, saiife can make API calls for the agent. You store a
credential in saiife's vault (`saiife secret add`, or `saiife secret import`
to move plaintext credentials out of the home), connect a service with
`saiife connect shopify|hubspot|github`, and the agent calls it through
`saiife api`. The saiife daemon checks each call against your policy, adds
the credential, sends the request and masks the answer. So the agent never
holds a credential for a brokered service; it holds its own model-provider
login unless you run a local model. See [Connectors](docs/connectors/README.md).

## Personal broker

`saiife daemon --user` runs a broker as your own user, with the vault key in
the OS keychain (Linux, Secret Service). It is for trying connectors on your
own machine; **not a security boundary**: a script of the same user can read
the key. The agent never holds a credential for a brokered service; it holds
its own model-provider login unless you run a local model, but in this mode
that is a workflow aid, not a control. See
[Personal broker](docs/personal-broker.md).

## Locked mode, audit forwarding and policy checks

Locked mode is Linux only (macOS follows in v2.1). On supported Linux an
admin can install saiife as root (`saiife system install`): for agents
labelled lockable (currently Claude Code) the agent cannot turn the guard
off, the audit is written by a daemon the agent cannot touch, and locked
mode fails closed. The agent never holds a credential for a brokered
service; it holds its own model-provider login unless you run a local
model.

- Send a copy of the audit elsewhere, so that a cut or rewrite of records
  that were already forwarded shows: [Audit forwarding](docs/forwarding.md)
  (syslog, file, HTTPS), checked with `saiife audit verify --external
  <file|dir>`.
- Who may read the audit, and `audit.query` for everyone else:
  [Auditors](docs/auditors.md).
- For a dedicated agent account, limit where it can send data:
  [Egress recipe](docs/egress.md) (nftables, Linux).
- Check a policy before you load it: `saiife policy check <config.toml>`
  validates it, including overlapping scopes, without loading it into a
  daemon; `saiife policy test <config.toml>` runs its `[[example]]` entries
  and exits 1 on a mismatch, an invalid policy or a file without examples,
  and 2 on a malformed example, an unknown user or a file it cannot read.
  In CI, where the agent accounts do not exist, give both `--passwd <file>
  --group <file>` to resolve users from files.
- `saiife policy show` prints your scope, its services and the policy hash,
  from the daemon in locked mode (exit 5 if it cannot be reached; it never
  falls back to the file there). `--user <name>` for anyone but yourself
  and `--effective` (the whole merged policy) are for admins only.
  `saiife policy reload` (admin) loads the policy again, like SIGHUP, and
  prints `loaded` or `rejected: <reason>` (exit 1; the old policy stays).

## What it covers

- [Threat coverage](docs/threats.md): which risks saiife covers, and which it
  does not, for each of the four setups (developer, personal broker, locked on
  a person's account, locked on a dedicated account).
- [Personal broker](docs/personal-broker.md): `saiife daemon --user`, what it
  protects and what it does not.
- [Audit forwarding](docs/forwarding.md), [auditors](docs/auditors.md) and
  the [egress recipe](docs/egress.md).
- [Approvals](docs/approvals.md) and [notifications](docs/notifications.md).
- [Packs](docs/packs/README.md): the rule sets, what each blocks and allows.
- Agents: [Claude Code](docs/agents/claude-code.md),
  [Codex](docs/agents/codex.md), [Gemini CLI](docs/agents/gemini.md).
- Recipe: [Codex with a local Ollama model](docs/recipes/codex-ollama.md).
- [Live lock checks](docs/lock-check.md): the harness that tests whether a
  managed hook can lock each agent (run by the owner, not CI).

Design: `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`.

## License

[Functional Source License 1.1, Apache 2.0 future license](LICENSE) (`FSL-1.1-ALv2`). You may use, change and share saiife for any purpose, including inside your company, except offering it as a competing commercial product or service. Each version becomes Apache 2.0 two years after its release. Versions published before this change remain available under MIT.
