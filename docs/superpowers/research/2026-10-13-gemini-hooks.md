# Gemini CLI hook contract (researched 2026-10-13, gemini-cli stable v0.63.0 / nightly v0.65.0)

Sources: google-gemini/gemini-cli `docs/hooks/reference.md`, `docs/hooks/index.md`, `docs/cli/settings.md`; `packages/core/src/hooks/{hookRunner,hookEventHandler,hookAggregator,hookRegistry,trustedHooks,types}.ts`; `packages/core/src/scheduler/{scheduler,hook-utils}.ts`; `packages/core/src/tools/definitions/base-declarations.ts`; `packages/cli/src/config/settings.ts`.

## Settings
- Project `<project>/.gemini/settings.json`, user `~/.gemini/settings.json`.
- System (admin lock): Linux `/etc/gemini-cli/settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json` (override `GEMINI_CLI_SYSTEM_SETTINGS_PATH`); plus system-defaults (`GEMINI_CLI_SYSTEM_DEFAULTS_PATH`).
- Precedence (code, lowest→highest): defaults, system-defaults, user, workspace, system. System wins → admin lock works. (Docs say otherwise; trust code.) Merge of hooks arrays across layers UNVERIFIED.
- Project hooks only load in trusted folders (untrusted → whole workspace settings dropped). In trusted folders, new/changed hooks only print a WARNING, not blocked. → `saiife init` must warn when the folder is untrusted; consider also user-level install.

## Shape
```json
{"hooks":{"BeforeTool":[{"matcher":"run_shell_command|read_file|read_many_files|glob|grep_search|write_file|replace",
  "hooks":[{"type":"command","command":"saiife check --agent gemini","name":"saiife","timeout":10000}]}]}}
```
- matcher: regex on tool name; omitted = all. timeout in **milliseconds** (default 60000).
- Tool names: shell `run_shell_command`; read `read_file`, `read_many_files`, `list_directory`; search `glob`, `grep_search` (was `search_file_content`); write `write_file`, `replace`; others `web_fetch`, `google_web_search`, `write_todos`, `activate_skill`, `ask_user`, `invoke_agent`; MCP `mcp_<server>_<tool>`.

## Stdin (BeforeTool)
session_id, transcript_path, cwd, hook_event_name ("BeforeTool"), timestamp, tool_name, tool_input, optional mcp_context, original_request_name.
tool_input: run_shell_command `command`; read_file/write_file/replace `file_path` (+ write_file `content`, replace `old_string`/`new_string`); list_directory `dir_path`; glob/grep_search `pattern` (+ optional `dir_path`); read_many_files `include` (array of globs), `exclude`.

## Output
- Exit 0 + JSON stdout parsed: `{"decision":"deny","reason":"…"}` (alias "block") blocks — agent sees "Tool execution blocked: <reason>". `{"decision":"allow"}` or empty = no objection. `ask` forces user confirmation. `continue:false` stops the loop. `hookSpecificOutput.tool_input` rewrites args.
- Exit 2: block, reason = stdout.trim() || stderr.trim(). Non-JSON output: any exit other than 0/1 → deny. Exit 1 = warning, tool proceeds.
- Valid JSON on stdout is parsed regardless of exit code.
- Allow does NOT bypass Gemini's policy/confirmation (hook first, then checkPolicy + confirmation).
- Multiple hooks: any deny wins.
- → For Gemini: allow = exit 0, no stdout; deny = exit 2 + stderr reason (works) or JSON deny + exit 0.

## Failure
Timeout (SIGTERM→SIGKILL), spawn error, exit 1, hook-system exception → tool proceeds (fail open). Shell "command not found" exit 127 → may be treated as deny (UNVERIFIED). Crash with code ≠0/1 and no JSON → block.
