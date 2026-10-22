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
and clumsy tampering, not a deliberate rewrite by someone with your rights.
`saiife audit --report` shows the same chain status.

## What it covers

- [Threat coverage](docs/threats.md): which risks saiife covers, and which it
  does not, for each way of working.
- [Packs](docs/packs/README.md): the rule sets, what each blocks and allows.
- Agents: [Claude Code](docs/agents/claude-code.md),
  [Codex](docs/agents/codex.md), [Gemini CLI](docs/agents/gemini.md).
- Recipe: [Codex with a local Ollama model](docs/recipes/codex-ollama.md).
- [Live lock checks](docs/lock-check.md): the harness that tests whether a
  managed hook can lock each agent (run by the owner, not CI).

Design: `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md`.

## License

[Functional Source License 1.1, Apache 2.0 future license](LICENSE) (`FSL-1.1-ALv2`). You may use, change and share saiife for any purpose, including inside your company, except offering it as a competing commercial product or service. Each version becomes Apache 2.0 two years after its release. Versions published before this change remain available under MIT.
