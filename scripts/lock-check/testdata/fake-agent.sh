#!/usr/bin/env bash
# Fake agent for the offline lock-check tests (test-lib.sh); never used live.
# It stands in for claude/codex/gemini: given a prompt that names a marker
# path ".../markers/<12 hex>", it "runs" `touch <marker>` the way an agent
# with managed hooks would:
#   - every hook command in $LC_ROOT/etc/fake/hooks (one per line) gets the
#     tool call as JSON on stdin: {"tool_name":"Bash","tool_input":{"command":"touch <marker>"}}
#   - no hooks run if $LC_ROOT/etc/fake/disabled exists or the user settings
#     ($HOME/.fake/settings.json) say "disabled": true
#   - the touch is skipped if any hook exits 2, or if the stub saiife is
#     missing and $LC_ROOT/etc/fake/fail-closed exists; else the marker is touched
#   - `--bogus` prints an unknown-flag error and exits 2; `--refuse` does
#     nothing and exits 0 (a model that ignores the prompt)
# It touches only the marker, under $LC_ROOT.
#
#   fake-agent <prompt> [--bogus|--refuse]
set -euo pipefail

root="${LC_ROOT:?fake-agent runs only in the offline tests (LC_ROOT)}"
conf="$root/etc/fake"
prompt="${1:-}"
shift || true
for arg in "$@"; do
  case "$arg" in
    --bogus)
      echo "error: unexpected argument '--bogus' found" >&2
      exit 2
      ;;
    --refuse) exit 0 ;;
  esac
done

if [[ "$prompt" =~ markers/([0-9a-f]{12}) ]]; then
  nonce="${BASH_REMATCH[1]}"
else
  echo "fake-agent: no marker in the prompt; nothing to do"
  exit 0
fi
marker="$root/work/project/markers/$nonce"
payload="$(printf '{"tool_name":"Bash","tool_input":{"command":"touch %s"}}' "$marker")"

disabled=0
if [[ -e "$conf/disabled" ]] || grep -qsE '"disabled": *true' "$HOME/.fake/settings.json"; then
  disabled=1
fi
blocked=0
if ((!disabled)) && [[ -f "$conf/hooks" ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -ra hook <<<"$line"
    rc=0
    printf '%s\n' "$payload" | "${hook[@]}" || rc=$?
    echo "fake-agent: hook ${hook[0]} exited $rc"
    if ((rc == 2)); then
      blocked=1
    fi
  done <"$conf/hooks"
fi
if ((!disabled)) && [[ ! -e "$root/opt/saiife/bin/saiife" && -e "$conf/fail-closed" ]]; then
  blocked=1
fi

if ((blocked)); then
  echo "fake-agent: tool call blocked by a hook"
else
  touch "$marker"
fi
echo DONE
