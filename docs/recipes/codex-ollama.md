# Recipe: Codex with a local Ollama model

> **Status: manual verification pending (plan 5c).** These steps have not yet
> been run end to end. Check each step against the Codex and Ollama docs for
> your versions.

This recipe runs Codex CLI against a model on your own machine (through
Ollama) and guards it with saiife. If Codex is set to use only the local
provider, no prompt or code leaves your machine for a model provider. Check
your Codex settings for this.

saiife hooks into the agent (Codex), not into the model. So the guard works
the same whether Codex talks to a cloud model or to a local one.

## 1. Start Ollama with a model

Install [Ollama](https://ollama.com), download a model that can use tools,
and make sure Ollama is running. By default it listens on
`http://localhost:11434`.

## 2. Point Codex at Ollama

In your own terminal (not through an agent), add a provider block for Ollama
to `~/.codex/config.toml`:

```toml
[model_providers.ollama]
base_url = "http://localhost:11434/v1"
```

Then select this provider and your model as the Codex docs describe. The
exact settings for that are part of the plan 5c check.

An agent cannot make this change for you: saiife's
[core.self](../packs/core.self.md) pack blocks agents from editing
`~/.codex/config.toml`, because the same file can switch hooks off.

## 3. Turn saiife on in the project

In the project folder, in your own terminal:

```sh
saiife init --agent codex
saiife status
```

Then start `codex` in the project folder, run `/hooks` and trust the saiife
hook once. See the [Codex page](../agents/codex.md) for what `init` writes
and what `status` checks.

## 4. Check that it works

Ask Codex to run a command saiife blocks, for example `cat .env` in a project
that has a `.env` file. Codex should report that the command was blocked.
Then run:

```sh
saiife audit --blocked
```

The blocked command shows up with `codex` as the agent.

## Not yet verified live

- Every step above (plan 5c).
- The Codex settings that pick the provider and model.
- Whether a given Ollama model calls Codex's tools well enough to be useful.
- Everything listed under "Not yet verified live" on the
  [Codex page](../agents/codex.md).
