# Claude Code hook contract (researched 2026-10-13)

Sources: https://code.claude.com/docs/en/hooks, https://code.claude.com/docs/en/settings, https://code.claude.com/docs/en/managed-settings, settings-reference#allowmanagedhooksonly.

## Settings
- Precedence (high→low): managed (`/etc/claude-code/managed-settings.json` Linux/WSL; `/Library/Application Support/ClaudeCode/managed-settings.json` macOS; drop-ins `managed-settings.d/*.json`), `--settings`, `.claude/settings.local.json`, `.claude/settings.json`, `~/.claude/settings.json`.
- Hook entries MERGE across levels.
- `allowManagedHooksOnly` (managed) blocks user/project/local/plugin hooks → a project/user saiife hook won't run on such machines (v2 lock installs via managed settings).
- `disableAllHooks: true` disables hooks; read after precedence; `--settings '{"disableAllHooks": true}'` disables for one run → bypass vector for core.self / status.

## Shape
```json
{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit",
  "hooks":[{"type":"command","command":"saiife check --hook-exit --agent claude","timeout":10}]}]}}
```
- Matcher: `*`/""/omitted = all; only [A-Za-z0-9_- ,|] → exact-name list; else unanchored JS regex. MCP `mcp__<server>__<tool>`.
- timeout seconds (command default 600). Optional `if`, `args`, `onFailure: "block"` (default continue; needs v2.1.295+).

## Stdin (PreToolUse)
session_id, prompt_id, transcript_path, cwd, scratchpad_dir, permission_mode, effort, hook_event_name, tool_name, tool_input, tool_use_id (treat beyond session_id/transcript_path/cwd/hook_event_name as optional).
tool_input: Bash `command` (+description, timeout, run_in_background); Read `file_path` (+offset, limit); Grep `pattern`, `path` (optional), glob, output_mode…; Write `file_path`, `content`; Edit `file_path`, `old_string`, `new_string`, replace_all; NotebookEdit `notebook_path` (UNVERIFIED); MultiEdit UNVERIFIED (historically file_path + edits[]). file_path is always absolute (Claude expands ~ and relative); symlinks/.. not resolved.

## Output
- Exit 0, no output: no decision → normal permission flow ("staying silent doesn't approve it").
- Exit 2: block, stderr = reason; stdout JSON ignored.
- Other exit codes (incl. 1): non-blocking error, action proceeds.
- JSON `permissionDecision`: allow (SKIPS permission prompt), deny, ask, defer. Precedence deny > defer > ask > allow. User deny/ask rules still evaluated.
- → Guard must NEVER emit allow. Pass = exit 0 silent; deny = exit 2 + stderr (or JSON deny + exit 0).

## Failure
Timeout, can't start (exit 127), crash (non-2) → fail open (proceeds), unless `onFailure: "block"` (v2.1.295+). v1 developer mode keeps fail-open (spec §1.2 rule 4); locked mode (v2) sets onFailure block.

## Trust and reload
- Interactive sessions hold back ALL hooks until the workspace trust dialog is accepted; `-p`/SDK sessions treat folder as trusted.
- Settings files are watched; hook edits apply mid-session → agent can remove the hook mid-session → core.self must block writes to `.claude/settings*.json` and `~/.claude/settings.json`. A `ConfigChange` hook can block changes to user/project/local settings (candidate for plan 3 / v2).
