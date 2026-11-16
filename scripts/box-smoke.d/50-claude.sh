# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 40 smoke: Claude Code in its TUI inside a box, talking to the model
# only through the host gateway (127.0.0.1:3129 in the box), which swaps the
# per-box placeholder for the real credential. Defines smoke_claude; no
# top-level effects.
#
# Owner prerequisites (each missing one is a FAIL or a skip naming the step):
#   - a saiife built with `--features boxes`, an image with Claude Code and
#     the plan 38 guest units;
#   - api-key leg (always runs):
#       SAIIFE_BOX_SMOKE_KEY_FILE=<file holding your Anthropic API key, one
#       line, nothing else>; the vault entry, made by you beforehand:
#         saiife secret add anthropic --kind token --service box-model-anthropic \
#           --from-file "$SAIIFE_BOX_SMOKE_KEY_FILE"
#     (D6, plan 42: the plan 40 name `box-model` is still accepted on the
#     Anthropic route as a legacy alias, OD4; use the new name)
#     the built-in `claude-code` template is used (credential "anthropic");
#   - subscription leg (runs only with SAIIFE_BOX_SMOKE_SUBSCRIPTION=1): FIRST
#     do the terms check (Anthropic's current terms for using a Claude
#     subscription through a local proxy, spec 7.9 and 13). Only if it
#     allows it, flip SUBSCRIPTION_LOGIN_CLEARED in crates/boxes in a LOCAL
#     build (its own commit if you keep it), then
#       export SAIIFE_BOX_SMOKE_SUB_KEY_FILE=<file with the `claude setup-token` token>
#       saiife secret add anthropic-sub --kind token --service box-model-anthropic \
#         --from-file "$SAIIFE_BOX_SMOKE_SUB_KEY_FILE"
#       install scripts/box-smoke.d/templates/claude-subscription.toml into
#       templates.d (as 30-guest does for bash.toml) and restart the daemon;
#   - for the no_placeholder_401 check, the bash template of 30-guest
#     (otherwise the check types the curl into Claude Code's `!` shell mode);
#   - a terminal on stdin for the by-eye prompt check.
#
# The key files are read by grep (-f) only: a key is never printed, never put
# on a command line, never written to a log or a copy.
#
# If the placeholder is refused for a login kind there is NO fallback (the
# real credential never enters the box): placeholder_accepted_<kind> is FAIL,
# and the Claude Code error on the terminal must be reported to the owner.
#
# Locked mode: the runtime dirs and the audit dir belong to saiife /
# saiife-box; reads there use `sudo -n` (a refusal is a FAIL naming the read).
#
# Result keys, per kind (api_key, subscription): claude_turn_ok_<kind>,
# claude_no_prompt_<kind>, model_records_<kind>, placeholder_accepted_<kind>,
# key_not_on_disk_<kind>, model_paths_<kind>; and once: no_placeholder_401.
# model_paths_<kind> (plan 42 R4, OD3, R12): every distinct "METHOD PATH" the
# gateway refused with reason path_not_allowed is printed for the owner; PASS
# when none. The owner widens the Anthropic allow-list only from that output.

P40_TASK="Reply with the single word ok, then stop."
P40_RUN_LIMIT_S=120
P40_DONE_LIMIT_S=120
P40_BOX=""
P40_KEYFILE=""
P40_LOCKED_UNIT=/etc/systemd/system/saiife-box@.service
P40_LOCKED_AUDIT=/var/log/saiife/audit
P40_LOCKED_RUN=/var/lib/saiife-box/boxes

p40_log() { printf '%s\n' "$*" >&2; }

p40_result() { RESULTS+=("$1=${2-}"); }

p40_now_ms() { date +%s%3N; }

p40_locked() { [ -e "$P40_LOCKED_UNIT" ]; }

# p40_as CMD...: a read of the runtime or audit dirs; `sudo -n` when locked
p40_as() {
  if p40_locked; then sudo -n "$@"; else "$@"; fi
}

p40_run_dir() {
  if p40_locked; then
    printf '%s/%s\n' "$P40_LOCKED_RUN" "$1"
  else
    printf '%s/saiife/broker/box-run/%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}" "$1"
  fi
}

# the daemon-only record dir (personal mode only; locked: not readable by you)
p40_record_dir() {
  printf '%s/saiife/broker/boxes/%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}" "$1"
}

p40_audit_dirs() {
  local data=${XDG_DATA_HOME:-$HOME/.local/share}
  case "${SAIIFE_AUDIT_DIR:-}" in
    /*) printf '%s\n' "$SAIIFE_AUDIT_DIR" ;;
    *) printf '%s\n' "$data/saiife/audit" ;;
  esac
  printf '%s\n' "$data/saiife/broker/audit"
  ! p40_locked || printf '%s\n' "$P40_LOCKED_AUDIT"
}

p40_state() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .state' 2>/dev/null
}

p40_error() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .error // ""' 2>/dev/null
}

p40_template() {
  saiife box templates --json 2>/dev/null |
    jq -e --arg n "$1" '[.templates[]? | select(.name == $n)] | length == 1' >/dev/null
}

# p40_keyfile_ok FILE: a readable one-line key file (no blank line: an empty
# grep pattern would match everything; no carriage return (CRLF) and no
# trailing blank: grep -F -f would then search for "key\r" or "key " and
# never match, so the key-on-disk checks would pass falsely). Prints nothing
# from the file.
p40_keyfile_ok() {
  [ -n "$1" ] && [ -f "$1" ] && [ -r "$1" ] && [ -s "$1" ] || return 1
  ! grep -q '^$' "$1" || return 1
  ! grep -q $'\r' "$1" || return 1
  ! grep -q '[[:blank:]]$' "$1" || return 1
  ! grep -q '^[[:blank:]]' "$1" || return 1
  [ "$(grep -c . "$1")" = 1 ]
}

# p40_spawn TEMPLATE TASK: sets P40_BOX (exactly one id from "box <id> <state>")
p40_spawn() {
  local out ids n
  P40_BOX=""
  out=$(timeout 90 saiife box spawn --template "$1" --now --task "$2" \
    --repo "$SMOKE_WORK") || return 1
  ids=$(printf '%s\n' "$out" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p40_log "box spawn printed $n box ids, expected 1"; return 1; }
  [[ "$ids" =~ ^b[0-9]+$ ]] || return 1
  P40_BOX=$ids
}

# p40_wait_state WANT LIMIT_S: the box reaches WANT (running|done); a box
# that is discarded or ends in a state it cannot leave is a failure
p40_wait_state() {
  local deadline st
  deadline=$(($(p40_now_ms) + $2 * 1000))
  while [ "$(p40_now_ms)" -lt "$deadline" ]; do
    st=$(p40_state "$P40_BOX")
    if [ "$st" = "$1" ]; then return 0; fi
    case "$st" in
      discarded)
        p40_log "box $P40_BOX is discarded: $(p40_error "$P40_BOX")"
        return 1
        ;;
      done)
        if [ "$1" = running ]; then return 0; fi
        ;;
    esac
    sleep 0.5
  done
  p40_log "box $P40_BOX is not $1 after $2 s (state: ${st:-unknown}) $(p40_error "$P40_BOX")"
  return 1
}

p40_screen() { timeout 15 saiife box attach "$P40_BOX" </dev/null 2>/dev/null; }

p40_end_box() {
  [ -z "$P40_BOX" ] || {
    saiife box stop "$P40_BOX" >/dev/null 2>&1 || true
    saiife box discard "$P40_BOX" --yes >/dev/null 2>&1 || true
  }
  P40_BOX=""
}

# by eye: the TUI showed the reply and no first-run, trust or key prompt
p40_no_prompt_by_eye() {
  local kind=$1 ans
  if [ ! -t 0 ]; then
    p40_log "MANUAL: claude_no_prompt_$kind needs a terminal. Run 'saiife box attach $P40_BOX' and confirm there is no first-run, theme, trust-this-folder or API-key prompt, and the reply is shown."
    p40_result "claude_no_prompt_$kind" manual
    return 0
  fi
  p40_log "box attach: you should see Claude Code's reply and NO first-run, theme, trust or API-key prompt; press q to leave"
  saiife box attach "$P40_BOX" || true
  printf 'No first-run, trust or API-key prompt, and the reply was shown? [y/N] ' >&2
  read -r ans || ans=n
  if [ "$ans" = y ] || [ "$ans" = Y ]; then
    p40_result "claude_no_prompt_$kind" 1
    check "claude_no_prompt_$kind: the TUI showed no first-run, trust or key prompt (by eye)" true
  else
    p40_result "claude_no_prompt_$kind" 0
    check "claude_no_prompt_$kind: the TUI showed no first-run, trust or key prompt (by eye)" false
  fi
}

# model records of this box: status 200 and credential "gateway", and no
# record of this box with another credential mode (the audit Record
# flattens its extra map, so box, status and credential are top-level keys)
p40_model_records() {
  local dir f files=()
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    if [ -d "$dir" ] && [ ! -r "$dir" ]; then
      p40_log "audit dir $dir is not readable by you (locked: rerun as a user who can read it)"
      continue
    fi
    for f in "$dir"/*.jsonl; do
      [ -r "$f" ] && files+=("$f")
    done
  done < <(p40_audit_dirs)
  [ "${#files[@]}" -gt 0 ] || { p40_log "no readable audit files in: $(p40_audit_dirs | tr '\n' ' ')"; return 1; }
  jq -en --arg b "$P40_BOX" \
    '[inputs | select(.kind == "model" and .box == $b)] as $m
     | ($m | length > 0)
       and ([$m[] | select(.status == 200 and .credential == "gateway")] | length > 0)
       and ([$m[] | select(.credential != "gateway")] | length == 0)' \
    "${files[@]}" >/dev/null
}

# the placeholder is not the key, and (personal mode) the file is 0600
p40_placeholder_ok() {
  local f
  f="$(p40_record_dir "$P40_BOX")/placeholder"
  if [ ! -r "$f" ]; then
    p40_log "the record dir is daemon-only (locked mode): placeholder not compared"
    return 0
  fi
  if grep -q -x -F -f "$P40_KEYFILE" "$f"; then
    p40_log "the placeholder file equals the real key"
    return 1
  fi
  [ "$(stat -c %a "$f")" = 600 ]
}

# p40_disk_clean DISK: the key (patterns from $P40_KEYFILE) is not in DISK.
# NULs become newlines so a sparse disk is never one huge line.
p40_disk_clean() {
  local out n sts
  out=$({ p40_as cat "$1" | tr '\0' '\n' | grep -c -a -F -f "$P40_KEYFILE"; printf 'S %s' "${PIPESTATUS[*]}"; } 2>/dev/null) || true
  n=$(printf '%s' "$out" | head -n 1 | tr -d '[:space:]')
  sts=${out##*S }
  p40_log "key matches in $(basename "$1"): ${n:-?}"
  # grep exit 2 (error) or an unreadable disk is a FAIL, never a pass
  case "$sts" in
    "0 0 0" | "0 0 1") ;;
    *) p40_log "could not read $1 (locked mode needs sudo -n)"; return 1 ;;
  esac
  [ "$n" = 0 ]
}

# after `box stop`: neither disk of the box holds the key
p40_key_not_on_disk() {
  local dir d ok=1
  dir=$(p40_run_dir "$P40_BOX")
  for d in root.qcow2 repo.img; do
    p40_as test -r "$dir/$d" || { p40_log "$dir/$d is not readable"; return 1; }
    p40_disk_clean "$dir/$d" || ok=0
  done
  [ "$ok" = 1 ]
}

# p40_curl_401 BOX PREFIX: type a keyless curl to the model listener into the
# box's shell (PREFIX "!" for Claude Code's shell mode, empty for bash)
p40_curl_401() {
  local deadline m
  P40_BOX=$1
  timeout 30 saiife box say "$P40_BOX" "${2}curl -s -o /dev/null -w 'NP''_401=%{http_code}\\n' http://127.0.0.1:3129/v1/models" >/dev/null || return 1
  deadline=$(($(p40_now_ms) + 60000))
  while [ "$(p40_now_ms)" -lt "$deadline" ]; do
    m=$(p40_screen | grep -Eo 'NP_401=[0-9]+' | tail -n 1 || true)
    if [ -n "$m" ]; then
      p40_result no_placeholder_401 "${m#*=}"
      [ "${m#*=}" = 401 ]
      return
    fi
    sleep 0.5
  done
  return 1
}

# model_paths: distinct "METHOD PATH" of this box's model_denied records with
# reason path_not_allowed (audit Record extra is flattened: top-level keys)
p40_model_paths() {
  local dir f files=() list
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    [ -d "$dir" ] && [ ! -r "$dir" ] && continue
    for f in "$dir"/*.jsonl; do
      [ -r "$f" ] && files+=("$f")
    done
  done < <(p40_audit_dirs)
  [ "${#files[@]}" -gt 0 ] || { p40_log "no readable audit files in: $(p40_audit_dirs | tr '\n' ' ')"; return 1; }
  list=$(jq -rn --arg b "$P40_BOX" \
    '[inputs | select(.kind == "model_denied" and .box == $b and .reason == "path_not_allowed")
      | "\(.method // "?") \(.path // "?")"] | unique | .[]' "${files[@]}") || return 1
  if [ -n "$list" ]; then
    p40_log "model_paths: refused (method path) pairs for box $P40_BOX:"
    printf '%s\n' "$list" >&2
    return 1
  fi
  p40_log "model_paths: none refused for box $P40_BOX"
}

# p40_leg_fail KIND: every result key of the leg is FAIL (it could not run)
p40_leg_fail() {
  local k
  for k in claude_turn_ok claude_no_prompt model_records model_paths placeholder_accepted key_not_on_disk; do
    p40_result "${k}_$1" FAIL
  done
}

# the whole leg for one login kind: p40_leg KIND TEMPLATE KEYFILE
p40_leg() {
  local kind=$1 tpl=$2 t0
  P40_KEYFILE=$3
  p40_log "== claude, login kind $kind (template $tpl)"
  if ! check "[$kind] key file readable, one line, no blank line, no CR (CRLF), no trailing blank" p40_keyfile_ok "$P40_KEYFILE"; then
    p40_leg_fail "$kind"
    return 0
  fi
  if ! check "[$kind] template $tpl is loaded" p40_template "$tpl"; then
    p40_leg_fail "$kind"
    return 0
  fi
  t0=$(p40_now_ms)
  if ! check "[$kind] box spawn --template $tpl --task (secret must be in the vault with --service box-model-anthropic; legacy: box-model)" p40_spawn "$tpl" "$P40_TASK"; then
    p40_leg_fail "$kind"
    return 0
  fi
  if check "[$kind] box reaches running within ${P40_RUN_LIMIT_S} s" p40_wait_state running "$P40_RUN_LIMIT_S"; then
    p40_result "ready_ms_$kind" "$(($(p40_now_ms) - t0))"
  else
    p40_leg_fail "$kind"
    p40_end_box
    return 0
  fi
  if check "[$kind] claude_turn_ok: the turn ends with the box done within ${P40_DONE_LIMIT_S} s" p40_wait_state done "$P40_DONE_LIMIT_S"; then
    p40_result "claude_turn_ok_$kind" 1
    # the turn succeeded with only the placeholder in the box
    p40_result "placeholder_accepted_$kind" 1
    check "[$kind] placeholder_accepted: the turn worked with only the placeholder in the box" true
  else
    p40_result "claude_turn_ok_$kind" 0
    p40_result "placeholder_accepted_$kind" 0
    check "[$kind] placeholder_accepted: the turn worked with only the placeholder in the box" false
    p40_log "The placeholder may have been refused for login kind $kind. There is NO fallback: the real credential must not be put in the box. Run 'saiife box attach $P40_BOX' now and report the Claude Code error shown in the terminal to the owner."
  fi
  p40_no_prompt_by_eye "$kind"
  # the gateway writes a record when the response ends
  sleep 2
  if check "[$kind] model_records: model records with status 200 and credential gateway" p40_model_records; then
    p40_result "model_records_$kind" 1
  else
    p40_result "model_records_$kind" 0
  fi
  if check "[$kind] model_paths_$kind: no model_denied path_not_allowed during the turn (any listed above are for the owner, OD3)" p40_model_paths; then
    p40_result "model_paths_$kind" 1
  else
    p40_result "model_paths_$kind" 0
  fi
  check "[$kind] the placeholder is not the key; its file is 0600" p40_placeholder_ok
  saiife box stop "$P40_BOX" >/dev/null 2>&1 || true
  sleep 3
  if check "[$kind] key_not_on_disk: no key bytes in root.qcow2 or repo.img after box stop" p40_key_not_on_disk; then
    p40_result "key_not_on_disk_$kind" 1
  else
    p40_result "key_not_on_disk_$kind" 0
  fi
  p40_end_box
}

smoke_claude() {
  command -v jq >/dev/null || { check "jq is installed (the fragment reads box ls --json)" false; return 0; }

  p40_leg api_key claude-code "${SAIIFE_BOX_SMOKE_KEY_FILE:-}"

  if [ "${SAIIFE_BOX_SMOKE_SUBSCRIPTION:-}" = 1 ]; then
    p40_log "subscription leg: you must have done the terms check (spec 7.9) and flipped SUBSCRIPTION_LOGIN_CLEARED in a LOCAL build only"
    p40_leg subscription claude-subscription "${SAIIFE_BOX_SMOKE_SUB_KEY_FILE:-}"
  else
    p40_log "skip: the subscription leg runs only with SAIIFE_BOX_SMOKE_SUBSCRIPTION=1, after the owner's terms check and a local SUBSCRIPTION_LOGIN_CLEARED flip (spec 7.9); spawn refuses it otherwise"
  fi

  # a request with no key at all gets 401: from the bash template's box, or,
  # when that template is not installed, Claude Code's `!` shell mode
  if p40_template bash; then
    if p40_spawn bash ""; then
      if p40_wait_state running "$P40_RUN_LIMIT_S"; then
        check "no_placeholder_401: curl to 127.0.0.1:3129/v1/models with no key gets 401" p40_curl_401 "$P40_BOX" ""
      else
        p40_result no_placeholder_401 0
        check "no_placeholder_401: the bash box reaches running" false
      fi
      p40_end_box
    else
      p40_result no_placeholder_401 0
      check "no_placeholder_401: box spawn --template bash" false
    fi
  elif p40_keyfile_ok "${SAIIFE_BOX_SMOKE_KEY_FILE:-}" && p40_spawn claude-code ""; then
    if p40_wait_state running "$P40_RUN_LIMIT_S"; then
      sleep 5
      check "no_placeholder_401: curl typed into Claude Code's ! shell mode gets 401 (install the bash template of 30-guest for a surer check)" p40_curl_401 "$P40_BOX" "!"
    else
      check "no_placeholder_401: the claude-code box reaches running" false
    fi
    p40_end_box
  else
    p40_result no_placeholder_401 0
    check "no_placeholder_401: needs the bash template or a spawnable claude-code box" false
  fi
  return 0
}
