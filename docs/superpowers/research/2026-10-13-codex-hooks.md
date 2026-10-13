# Codex CLI hook contract (researched 2026-10-13, Codex rust-v0.162.1)

Sources: https://developers.openai.com/codex/hooks (→ learn.chatgpt.com/docs/hooks); openai/codex `codex-rs/hooks/src/` (`events/pre_tool_use.rs`, `engine/command_runner.rs`, `engine/dispatcher.rs`, `config_rules.rs`).

## Config
- Hooks in `hooks.json` or inline `[hooks]` in `config.toml`, per layer: `~/.codex/{hooks.json,config.toml}`, `<repo>/.codex/{hooks.json,config.toml}`. Higher layers do not replace lower-layer hooks.
- Project layer loads only if the project `.codex/` is trusted. Every non-managed hook needs hash-based trust review (`/hooks` in the CLI; `--dangerously-bypass-hook-trust` skips for one run). Editing a hook re-triggers review. → `saiife init` must tell the user to trust the hook once via `/hooks`.
- TOML:
  ```toml
  [[hooks.PreToolUse]]
  matcher = "^(Bash|apply_patch)$"
  [[hooks.PreToolUse.hooks]]
  type = "command"
  command = "saiife check --agent codex"
  timeout = 10
  statusMessage = "saiife guard"
  ```
- `matcher` is a regex; tool names: `Bash`, `apply_patch` (aliases `Edit`/`Write` match it, stdin still says `apply_patch`), MCP `mcp__server__tool`, local fn tools. Hosted tools (WebSearch) don't trigger hooks.
- Handler fields: type, command, command_windows, timeout (seconds, default 600), statusMessage, async, additionalContextLimit. Hooks on by default (`[features] hooks=false` disables).

## Stdin (PreToolUse)
session_id, transcript_path, cwd, hook_event_name, model, permission_mode, turn_id, tool_name, tool_use_id, tool_input. Bash: `tool_input.command` (string). apply_patch: `tool_input.command` = patch text.

## Output
- Exit 0, no output: success (no decision).
- Exit 2 + non-empty stderr: block. Exit 2 with EMPTY stderr = failed hook → proceeds.
- JSON deny: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}` (legacy `{"decision":"block","reason":"…"}`).
- `permissionDecision:"allow"` only valid with `updatedInput`; allow without it = failed hook (fails open). `ask`, `approve`, `continue:false` unsupported (failed hook). Non-parsing JSON-like stdout = failed hook.
- → For Codex: allow = exit 0 with NO stdout; deny = exit 2 + stderr reason (or JSON deny).

## Failure
Missing binary (spawn_error), timeout, any other non-zero exit → run Failed, shown in UI, tool call proceeds (fail open). Async hooks cannot block.

## Admin / managed (v2 lock)
`requirements.toml` inline `[hooks]` in `managed_dir` (path UNVERIFIED, likely /etc/codex/). Managed hooks skip trust. `allow_managed_hooks_only = true` ignores user/project/session/plugin hooks. `[features].hooks = true` pin forces hooks on. Cloud-managed config supports only `mcp_tool` hooks.

## localflow notes
Old `-c hooks.PreToolUse=[...]` inline override grammar is UNVERIFIED; other events used `command=[...]` arrays that don't match the documented shape (likely never fired).
