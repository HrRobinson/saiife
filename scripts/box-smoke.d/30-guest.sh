# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 38 smoke: the guest channel and the box gateway. A box from the
# `bash` template (scripts/box-smoke.d/templates/bash.toml: the agent is a
# plain bash, so `saiife box say` types shell commands) reaches Ready,
# takes typed input, shows its screen, keeps OSC 52 inert, and its egress
# goes through the per-box CONNECT gateway's allow-list. Defines
# smoke_guest; no top-level effects.
#
# Owner prerequisites (each missing one is a FAIL naming the step):
#   - a saiife built with `--features boxes` and an image rebuilt (plan 36)
#     with this plan's guest units;
#   - the bash template installed where the daemon reads templates, then the
#     daemon restarted (templates are read at start):
#       personal: install -m 0644 scripts/box-smoke.d/templates/bash.toml \
#                   "${XDG_CONFIG_HOME:-$HOME/.config}/saiife/templates.d/"
#       locked:   sudo install -o root -g root -m 0644 \
#                   scripts/box-smoke.d/templates/bash.toml /etc/saiife/templates.d/
#   - SAIIFE_SMOKE_BUSYBOX_DIGEST: the busybox sha256 digest (64 hex) for the
#     docker pull (the same one 05-image uses); this script never invents one;
#   - a terminal on stdin for the `box attach` look (by eye).
#
# How it reads results: `saiife box say` types a command with a marker,
# `saiife box attach` without a terminal prints the screen once, and the
# marker's output line is grepped. The typed command echoes the marker
# split (`EG''_ALLOW`), so only the command's output can match.
#
# Results keys: ready_ms, say_ok, osc52_inert, egress_allow, egress_deny,
# egress_private, docker_pull_ok, egress_audit.
#
# Not checked here: a Claude Code Stop hook moving the box to `done` within
# ~30 s of a turn needs plan 40 (the template's agent is bash); the fragment
# prints that as a note.

P38_TEMPLATE="bash"
P38_READY_LIMIT_S=120
P38_OUT_LIMIT_S=60
P38_BOX=""

p38_log() { printf '%s\n' "$*" >&2; }

p38_result() { RESULTS+=("$1=${2-}"); }

p38_now_ms() { date +%s%3N; }

# The audit dirs the daemon's egress records can be in, one per line: as
# 05-image's p36_audit_dir ($SAIIFE_AUDIT_DIR when absolute, else
# <data base>/saiife/audit), the personal daemon's own dir
# (<data base>/saiife/broker/audit, crates/system/src/personal.rs) and, when
# the daemon is locked (10-vmm's test: the saiife-box@ unit is installed),
# the locked audit dir (/var/log/saiife/audit, crates/system/src/default_config.rs).
P38_LOCKED_UNIT=/etc/systemd/system/saiife-box@.service
P38_LOCKED_AUDIT=/var/log/saiife/audit

p38_audit_dirs() {
  local data=${XDG_DATA_HOME:-$HOME/.local/share}
  case "${SAIIFE_AUDIT_DIR:-}" in
    /*) printf '%s\n' "$SAIIFE_AUDIT_DIR" ;;
    *) printf '%s\n' "$data/saiife/audit" ;;
  esac
  printf '%s\n' "$data/saiife/broker/audit"
  [ ! -e "$P38_LOCKED_UNIT" ] || printf '%s\n' "$P38_LOCKED_AUDIT"
}

p38_state() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .state' 2>/dev/null
}

p38_error() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .error // ""' 2>/dev/null
}

# the bash template is loaded by the daemon
p38_template() {
  saiife box templates --json 2>/dev/null |
    jq -e --arg n "$P38_TEMPLATE" '[.templates[]? | select(.name == $n)] | length == 1' >/dev/null
}

# p38_spawn: a box from the bash template with an empty task; sets P38_BOX
# (exactly one id from "box <id> <state>", nothing guessed)
p38_spawn() {
  local out ids n
  P38_BOX=""
  out=$(timeout 60 saiife box spawn --template "$P38_TEMPLATE" --now --task "" \
    --repo "$SMOKE_WORK") || return 1
  ids=$(printf '%s\n' "$out" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p38_log "box spawn printed $n box ids, expected 1"; return 1; }
  [[ "$ids" =~ ^b[0-9]+$ ]] || return 1
  P38_BOX=$ids
}

# p38_wait_running T0_MS: the box is running; prints ms since T0_MS
p38_wait_running() {
  local deadline st
  deadline=$(($(p38_now_ms) + P38_READY_LIMIT_S * 1000))
  while [ "$(p38_now_ms)" -lt "$deadline" ]; do
    st=$(p38_state "$P38_BOX")
    case "$st" in
      running)
        printf '%s\n' "$(($(p38_now_ms) - $1))"
        return 0
        ;;
      discarded | done)
        p38_log "box $P38_BOX is $st: $(p38_error "$P38_BOX")"
        return 1
        ;;
    esac
    sleep 0.2
  done
  p38_log "box $P38_BOX is not running after ${P38_READY_LIMIT_S} s"
  return 1
}

# the box's screen, printed once (no terminal: `box attach` prints and exits)
p38_screen() { timeout 15 saiife box attach "$P38_BOX" </dev/null 2>/dev/null; }

# p38_say TEXT: type TEXT and Enter into the box's bash
p38_say() { timeout 30 saiife box say "$P38_BOX" "$1" >/dev/null; }

# p38_wait_out REGEX [LIMIT_S]: the first screen match of REGEX (grep -Eo)
p38_wait_out() {
  local deadline m
  deadline=$(($(p38_now_ms) + ${2:-$P38_OUT_LIMIT_S} * 1000))
  while [ "$(p38_now_ms)" -lt "$deadline" ]; do
    m=$(p38_screen | grep -Eo "$1" | tail -n 1 || true)
    if [ -n "$m" ]; then
      printf '%s\n' "$m"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# p38_run MARKER CMD: type CMD, which ends by printing MARKER=<value>;
# prints the value
p38_run() {
  local m
  p38_say "$2" || return 1
  m=$(p38_wait_out "$1=[^ ]+" "${3:-$P38_OUT_LIMIT_S}") || return 1
  printf '%s\n' "${m#*=}"
}

p38_say_ok() {
  p38_say "echo SAY''_OK" || return 1
  p38_wait_out '^SAY_OK *$' >/dev/null
}

# by eye: the owner looks at the attached screen and answers
p38_attach_by_eye() {
  local ans
  [ -t 0 ] || { p38_log "box attach by eye needs a terminal on stdin"; return 1; }
  p38_log "box attach: you should see the box's bash prompt and SAY_OK; press q to leave"
  saiife box attach "$P38_BOX" || true
  printf 'Did box attach show the bash screen? [y/N] ' >&2
  read -r ans || return 1
  [ "$ans" = y ] || [ "$ans" = Y ]
}

p38_clipboard() {
  if command -v wl-paste >/dev/null && [ -n "${WAYLAND_DISPLAY:-}" ]; then
    wl-paste --no-newline 2>/dev/null || true
  elif command -v xclip >/dev/null && [ -n "${DISPLAY:-}" ]; then
    xclip -o -selection clipboard 2>/dev/null || true
  else
    return 1
  fi
}

# OSC 52 typed into the box never reaches the host clipboard, and the
# screen the daemon serves carries no escape (neither raw nor shown as \x1b)
p38_osc52_inert() {
  local before after screen ok=1
  before=$(p38_clipboard) || { before=""; p38_log "no wl-paste/xclip: the clipboard is checked by eye"; }
  p38_run OSC_DONE "printf '\\e]52;c;aGVsbG8=\\a'; echo OSC''_DONE=1" >/dev/null || return 1
  if after=$(p38_clipboard); then
    [ "$after" = "$before" ] || { p38_log "the host clipboard changed"; ok=0; }
    [ "$after" != hello ] || ok=0
  fi
  screen=$(p38_screen) || return 1
  if printf '%s' "$screen" | grep -q $'\x1b'; then
    p38_log "the screen has a raw ESC"
    ok=0
  fi
  if printf '%s' "$screen" | grep -qF '\x1b'; then
    p38_log "the daemon sent an escape (shown as \\x1b)"
    ok=0
  fi
  [ "$ok" = 1 ]
}

p38_egress_audit() {
  local dir f files=()
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    if [ -d "$dir" ] && [ ! -r "$dir" ]; then
      p38_log "audit dir $dir is not readable by you (locked: rerun as a user who can read it)"
      continue
    fi
    for f in "$dir"/*.jsonl; do
      [ -r "$f" ] && files+=("$f")
    done
  done < <(p38_audit_dirs)
  [ "${#files[@]}" -gt 0 ] || { p38_log "no readable audit files in: $(p38_audit_dirs | tr '\n' ' ')"; return 1; }
  jq -en --arg b "$P38_BOX" \
    '[inputs | select(.kind == "egress" and .extra.box == $b
       and (.extra.bytes_up | type) == "number"
       and (.extra.bytes_down | type) == "number")] | length > 0' \
    "${files[@]}" >/dev/null
}

p38_end_box() {
  [ -z "$P38_BOX" ] || {
    saiife box stop "$P38_BOX" >/dev/null 2>&1 || true
    saiife box discard "$P38_BOX" --yes >/dev/null 2>&1 || true
  }
  P38_BOX=""
}

smoke_guest() {
  local t0 ms v digest
  command -v jq >/dev/null || { check "jq is installed (the fragment reads box ls --json)" false; return 0; }
  if ! check "the bash template is loaded (install templates/bash.toml, restart the daemon)" p38_template; then
    return 0
  fi
  t0=$(p38_now_ms)
  if ! check "box spawn --template bash" p38_spawn; then
    return 0
  fi
  if ms=$(p38_wait_running "$t0"); then
    p38_result ready_ms "$ms"
    check "box running (Ready) within ${P38_READY_LIMIT_S} s" true
  else
    check "box running (Ready) within ${P38_READY_LIMIT_S} s" false
    p38_end_box
    return 0
  fi

  if check "box say types into the agent's terminal" p38_say_ok; then
    p38_result say_ok 1
  else
    p38_result say_ok 0
  fi
  check "box attach shows the screen (by eye)" p38_attach_by_eye

  if check "OSC 52 is inert (host clipboard unchanged, no escape in box.term.read)" p38_osc52_inert; then
    p38_result osc52_inert 1
  else
    p38_result osc52_inert 0
  fi

  # egress through the gateway (HTTPS_PROXY is the guest's 127.0.0.1:3128)
  v=$(p38_run EG_ALLOW "curl -sS -o /dev/null -w 'EG''_ALLOW=%{http_code}\\n' https://registry.npmjs.org/" || true)
  p38_result egress_allow "$v"
  check "egress to an allow-listed host: 200 (registry.npmjs.org)" test "$v" = 200
  v=$(p38_run EG_DENY "curl -sS -o /dev/null -w 'EG''_DENY=%{http_connect}\\n' https://example.com/" || true)
  p38_result egress_deny "$v"
  check "egress to a host not on the list: proxy 403" test "$v" = 403
  v=$(p38_run EG_PRIV "curl -sS -o /dev/null -w 'EG''_PRIV=%{http_connect}\\n' https://localtest.me/" || true)
  p38_result egress_private "$v"
  check "egress to an allow-listed name that resolves to 127.0.0.1: proxy 403" test "$v" = 403

  digest=${SAIIFE_SMOKE_BUSYBOX_DIGEST:-}
  if [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    v=$(p38_run DOCKER_RC "docker pull busybox@sha256:$digest >/dev/null 2>&1; echo DOCKER''_RC=\$?" 300 || true)
    if [ "$v" = 0 ]; then p38_result docker_pull_ok 1; else p38_result docker_pull_ok 0; fi
    check "docker pull busybox@sha256 through the proxy (Docker Hub allow-listed)" test "$v" = 0
  else
    p38_result docker_pull_ok 0
    check "docker pull (set SAIIFE_SMOKE_BUSYBOX_DIGEST to the busybox sha256, 64 hex)" false
  fi

  # tunnels close when they end; the records follow
  sleep 2
  if check "audit: egress records of this box with byte counts" p38_egress_audit; then
    p38_result egress_audit 1
  else
    p38_result egress_audit 0
  fi
  p38_log "note: the Claude Code Stop hook -> done within ~30 s needs plan 40 (this template's agent is bash): not checked"
  p38_end_box
  return 0
}
