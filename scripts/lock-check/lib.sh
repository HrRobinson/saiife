#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034,SC2317,SC2329
# lib.sh: runner library for the live lock checks (scripts/live-check-locked.sh).
#
# Sourced (not run) by in-container.sh, macos-vm.sh, by every
# checks-<agent>.sh they load, and by test-lib.sh. It expects the caller to
# have `set -euo pipefail` (and bash 4 or later).
# Inside the container it runs as root and writes only container paths:
# /run/lockcheck, /opt/saiife, /opt/lockcheck, /work/project, the managed
# files the agent script names, /out, and the settings files it snapshots
# and restores under /home/agent. With LC_ROOT set (tests), every one of
# those paths is under $LC_ROOT and nothing runs as another user.
#
# ---------------------------------------------------------------------------
# API (Tasks 3-5 write checks-<agent>.sh against this)
# ---------------------------------------------------------------------------
# Platform: LOCKCHECK_PLATFORM=linux (default; the Docker container), macos
# (a throwaway macOS VM, scripts/lock-check/macos-vm.sh) or windows (a
# throwaway Windows VM, scripts/lock-check/windows-vm.ps1). It is read once,
# when sourced, into LC_PLATFORM. macOS has no writable /run or /work, so the
# harness dirs move under /opt/lockcheck there; the agents' managed paths are
# the spec 5.3 ones (the checks-<agent>.sh files pick them).
#
# Windows always has LC_ROOT set. It is a staging dir, and `$LC_ROOT/C/x`
# stands for `C:\x` (spec 5.3a, W9): `C/Program Files/ClaudeCode/...`,
# `C/ProgramData/OpenAI/Codex/...`, `C/ProgramData/gemini-cli/...`, and the
# home `C/Users/agent`. Bash on Windows cannot start a program as another
# user, so lib.sh never runs the agent there. With LC_WIN_XCHG set, each run
# is a plan handed to windows-vm.ps1 (see "Windows plans" below): the files
# to write (managed files, settings, the project) and the prompt. The ps1
# writes them to C:\, runs the agent as `agent`, and hands back the logs and
# markers. lib.sh then observes and records as on the other platforms.
#
# Paths (set when sourced; all already prefixed by $LC_ROOT, so agent scripts
# must use them, or "$LC_ROOT/etc/...", never a bare /etc or ~):
#   LC_ROOT     ""        (tests: a temp dir)
#   LC_SRC      dir of lib.sh (/lockcheck in the container)
#   LC_MANAGED  $LC_ROOT/lockcheck-managed (override with LC_MANAGED=...)
#   LC_HOME     the agent's HOME ("~"): $LC_ROOT/home/agent
#               (macos: $LC_ROOT/Users/agent; windows: $LC_ROOT/C/Users/agent)
#   LC_WORK     $LC_ROOT/work (macos: $LC_ROOT/opt/lockcheck/work;
#               windows: $LC_ROOT/C/lockcheck/work)
#   LC_PROJECT  $LC_WORK/project         the agent's cwd
#   LC_MARKERS  $LC_PROJECT/markers
#   LC_RUN      mode files, calls.log, witness.log: $LC_ROOT/run/lockcheck
#               (macos: $LC_ROOT/opt/lockcheck/run; windows: $LC_ROOT/C/lockcheck/run)
#   LC_STUB     $LC_ROOT/opt/saiife/bin/saiife (windows:
#               $LC_ROOT/C/ProgramData/saiife/bin/saiife, which the hook runs
#               as C:/ProgramData/saiife/bin/saiife.exe, a launcher)
#   LC_WITNESS  $LC_ROOT/opt/lockcheck/witness (windows: $LC_ROOT/C/lockcheck/bin/witness)
#   LC_WITNESS_CMD  the witness as a hook command names it: $LC_WITNESS
#               (windows: C:/lockcheck/bin/witness.exe)
#   LC_RESULTS  the result .tsv (set by the runner); LC_LOG its .log
#   LC_AGENT_GROUP, LC_ROOT_GROUP   agent and root (macos: staff and wheel)
#   LC_SECRET_ENV=(K=V ...)  extra env for every agent run, never logged
#                            (macos-vm.sh fills it from LOCKCHECK_AGENT_ENV_FILE)
#
# Per-check state (cleared by lc_reset; setup fns set these):
#   LC_AGENT_ENV=(K=V ...)  extra env for the agent run
#   LC_AGENT_ARGS=(...)     extra args passed to agent_invoke after the prompt
#   LC_PROMPT               replaces the default touch prompt; may use $LC_NONCE
#   LC_FIRED_EVENT          e.g. config-change: `fired` = any line of that event
#   LC_POST                 fn name; called as `$LC_POST <nonce>` after the
#                           run, its stdout is appended to the row's detail
#   LC_NONCE                (read-only for setup fns) this check's nonce
#   LC_LAST_EXIT            exit code of the last lc_run_agent (124 = timeout)
#
# Result rows and labels:
#   lc_status <class> <expect> <observed>        -> PASS|FAIL|ERROR|SKIP|INFO
#   lc_record <id> <class> <expect> <observed> <detail>   append a row
#   lc_probe <id> <found|not-found> <detail>     info row, expect `-`, no run
#   lc_label <results.tsv>                       -> machine label
#   lc_label_text <label>                        -> §6.1.3 wording
#   lc_summarize <results.tsv>    append `# label=`, print rows + `label: ...`
#   lc_validate <results.tsv>     exit 0 iff header, rows and label are valid
#
# Running a check:
#   lc_check <id> <class> <expect> <mode> <setup-fn|-> [control-id]
#       skip (observed inconclusive) if a control row is not PASS; else
#       lc_reset, new LC_NONCE, run setup fn, lc_set_mode <mode>, run the
#       agent with LC_PROMPT or lc_prompt_touch, observe, record. expect
#       fired/not-fired observes the stub's calls.log, anything else the
#       marker and witness. control-id: the row whose `ran` makes
#       "no marker, no witness" read as `unavailable` (MCP checks).
#   lc_set_mode <mode> [config-change]   stub mode; `missing` deletes the stub
#   lc_nonce                             -> 12 hex chars
#   lc_prompt_touch <nonce>              -> the default prompt
#   lc_run_agent <prompt>    run agent_invoke as `agent` under timeout;
#                            always returns 0, exit code in LC_LAST_EXIT
#   lc_observe <nonce> [control-id]  -> ran|blocked|unsupported|unavailable|inconclusive
#   lc_observe_fired <nonce> [event] -> fired|not-fired|unsupported|inconclusive
#   lc_hook_fired <nonce|-> [event]  exit 0 iff calls.log has the nonce
#                                    (`-`: any line; event filters the lines)
#   lc_calls_tool_names <nonce>      tool_name values in calls.log for nonce
#   lc_snapshot / lc_reset / lc_restore_snapshot   see below
#   lc_as_agent_write <path> <content>   write a file as `agent` (with parents)
#   lc_agent_call <fn> [args...]  run a self-contained fn as `agent` with the
#                            agent env (used for agent_version); prints its output
#   lc_real <path>           the path as the agent sees it: on Windows
#                            $LC_ROOT/C/x is C:/x; elsewhere unchanged
#   lc_touch_cmd <path>      a hook command that creates <path> (on Windows
#                            through the lc-touch launcher: PowerShell has
#                            no `touch`)
#   lc_managed_file <rel>    the managed fixture <rel> (claude/50-saiife.json);
#                            on Windows a copy whose hooks run the W9 command
#                            C:/ProgramData/saiife/bin/saiife.exe
#   lc_require_path <path>   exit 0 iff path may be written by the harness:
#                            under $LC_ROOT/ offline, under /home/agent/ or
#                            /work/ in the container, under /Users/agent/ or
#                            /opt/lockcheck/work/ in the macOS VM (settings,
#                            login files and lc_as_agent_write are checked
#                            with it)
#
# Safety (offline): sourcing lib.sh with LC_ROOT set canonicalizes LC_ROOT
# (realpath; `/` refused), exports HOME=$LC_ROOT/root so a stray `~` cannot
# reach the real home, and agent runs get a PATH of $LC_ROOT/usr/local/bin
# plus $LC_ROOT/.lc-hostbin, which links only basic tools (no claude, codex,
# gemini, node). Sourcing it with LC_ROOT empty outside a container aborts.
#
# Evidence: `blocked` needs a witness.log line holding both the nonce and
# $LC_WITNESS_TOOL_KEY (default "tool_name"), so register the witness on
# pre-tool events only, never on prompt/model events. Each row's detail
# also says stub=seen|unseen (the stub's calls.log had the nonce) and
# witness=seen|unseen. A mode `deny` row reads `blocked` only when the stub
# was called too; witness without stub reads `inconclusive`.
# Threat assumption: calls.log and witness.log are owned by `agent` (the
# hooks run as agent), so a hostile agent could forge them; the checks
# assume the model is not adversarial.
#
# Per-agent contract: checks-<agent>.sh defines
#   agent_version          print the agent's version (one line)
#   agent_invoke <prompt> [args...]   run the agent once. Self-contained: it
#                          is shipped to the agent's shell with `declare -f`,
#                          so it may call programs only, no other functions
#                          or unexported variables.
#   agent_baseline         write the managed files + witness hook (as root)
#   agent_settings_files   absolute paths, one per line; snapshotted at start,
#                          restored before every check and at exit
#   agent_login_files      absolute paths reset must never touch
#   agent_checks           the lc_check / lc_probe calls, control first
#   agent_managed_paths    the managed files and dirs that the baseline and
#                          the setups write, one per line (Windows plans:
#                          windows-vm.ps1 writes them as admin, read-only
#                          for users)
#   agent_fires_hint       (optional) one line, appended as "hint: ..." to a
#                          gate row that expected `fired` and read
#                          `not-fired` (which knob names the managed file)
# ---------------------------------------------------------------------------

LC_ROOT="${LC_ROOT:-}"
LC_PLATFORM="${LOCKCHECK_PLATFORM:-linux}"
if [[ "$LC_PLATFORM" != linux && "$LC_PLATFORM" != macos && "$LC_PLATFORM" != windows ]]; then
  echo "lib.sh: LOCKCHECK_PLATFORM must be linux, macos or windows, not '$LC_PLATFORM'" >&2
  return 2
fi
if [[ "$LC_PLATFORM" == windows && -z "$LC_ROOT" ]]; then
  echo "lib.sh: windows needs LC_ROOT, the staging dir that windows-vm.ps1 makes; refusing" >&2
  return 2
fi
if [[ -n "$LC_ROOT" ]]; then
  if ! LC_ROOT="$(realpath -e -- "$LC_ROOT" 2>/dev/null)" || [[ ! -d "$LC_ROOT" || "$LC_ROOT" == / ]]; then
    echo "lib.sh: LC_ROOT must be an existing directory other than /" >&2
    return 2
  fi
  HOME="$LC_ROOT/root"
  export HOME
elif [[ "$LC_PLATFORM" == macos ]]; then
  if [[ "$(uname -s)" != Darwin || "${SAIIFE_LOCKCHECK_MACOS_VM:-}" != 1 ]]; then
    echo "lib.sh: LC_ROOT is empty and this is not a lock-check macOS VM; refusing" >&2
    return 2
  fi
elif [[ ! -e /.dockerenv ]]; then
  echo "lib.sh: LC_ROOT is empty and this is not the lock-check container; refusing" >&2
  return 2
fi
LC_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# On Windows the C:/ form, which Node and the agents read, and bash too.
if [[ "$LC_PLATFORM" == windows ]] && command -v cygpath >/dev/null 2>&1; then
  LC_SRC="$(cygpath -m "$LC_SRC")"
fi
LC_MANAGED="${LC_MANAGED:-$LC_ROOT/lockcheck-managed}"
if [[ "$LC_PLATFORM" == windows ]]; then
  LC_HOME="$LC_ROOT/C/Users/agent"
  LC_WORK="$LC_ROOT/C/lockcheck/work"
  LC_RUN="$LC_ROOT/C/lockcheck/run"
  LC_AGENT_GROUP=agent
  LC_ROOT_GROUP=Administrators
  LC_AGENT_PATH=""
elif [[ "$LC_PLATFORM" == macos ]]; then
  LC_HOME="$LC_ROOT/Users/agent"
  LC_WORK="$LC_ROOT/opt/lockcheck/work"
  LC_RUN="$LC_ROOT/opt/lockcheck/run"
  LC_AGENT_GROUP=staff
  LC_ROOT_GROUP=wheel
  # Node and the agents: Homebrew (Apple silicon, then Intel) or nodejs.org.
  LC_AGENT_PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
else
  LC_HOME="$LC_ROOT/home/agent"
  LC_WORK="$LC_ROOT/work"
  LC_RUN="$LC_ROOT/run/lockcheck"
  LC_AGENT_GROUP=agent
  LC_ROOT_GROUP=root
  LC_AGENT_PATH="/usr/local/bin:/usr/bin:/bin"
fi
LC_PROJECT="$LC_WORK/project"
LC_MARKERS="$LC_PROJECT/markers"
if [[ "$LC_PLATFORM" == windows ]]; then
  LC_STUB="$LC_ROOT/C/ProgramData/saiife/bin/saiife"
  LC_WITNESS="$LC_ROOT/C/lockcheck/bin/witness"
  LC_WITNESS_CMD="C:/lockcheck/bin/witness.exe"
else
  LC_STUB="$LC_ROOT/opt/saiife/bin/saiife"
  LC_WITNESS="$LC_ROOT/opt/lockcheck/witness"
  LC_WITNESS_CMD="$LC_WITNESS"
fi
# Windows plans (see below): the exchange dir shared with windows-vm.ps1,
# and the shell the agent's tool runs (posix for Claude Code's Bash, which is
# Git Bash; powershell for Codex and Gemini CLI). Set by checks-<agent>.sh.
LC_WIN_XCHG="${LC_WIN_XCHG:-}"
LC_WIN_SHELL="${LC_WIN_SHELL:-powershell}"
LC_WIN_SEQ=0
LC_RESULTS="${LC_RESULTS:-}"
LC_LOG="${LC_LOG:-/dev/null}"
LC_UNSUPPORTED_RE='unknown (option|argument)|unexpected argument|unrecognized|invalid option'
LC_AGENT_ENV=()
LC_AGENT_ARGS=()
LC_SECRET_ENV=()
LC_PROMPT=""
LC_FIRED_EVENT=""
LC_POST=""
LC_NONCE=""
LC_LAST_EXIT=0
LC_SNAPSHOT="$LC_HOME/.lockcheck-snapshot"
LC_WITNESS_TOOL_KEY="${LC_WITNESS_TOOL_KEY:-\"tool_name\"}"
# Host tools the offline agent env may use (linked into $LC_ROOT/.lc-hostbin).
LC_HOSTBIN_TOOLS=(bash sh env cat touch mkdir rm cp mv ln chmod grep sed awk tr date sleep head tail cut sort tee dirname basename id od jq)
export LC_ROOT LC_MANAGED

# --- result rows -------------------------------------------------------------

lc_status() {
  local class="$1" expect="$2" observed="$3"
  if [[ "$class" == info ]]; then
    echo INFO
  elif [[ "$observed" == unsupported ]]; then
    echo SKIP
  elif [[ "$observed" == inconclusive ]]; then
    echo ERROR
  elif [[ "$observed" == "$expect" ]]; then
    echo PASS
  else
    echo FAIL
  fi
}

lc_record() {
  local id="$1" class="$2" expect="$3" observed="$4" detail="${5:-}" status
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\r'/ }"
  detail="${detail//$'\n'/ }"
  [[ -n "$detail" ]] || detail="-"
  status="$(lc_status "$class" "$expect" "$observed")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$class" "$expect" "$observed" "$status" "$detail" \
    >>"${LC_RESULTS:?LC_RESULTS is not set}"
  printf '[lockcheck] %-5s %s (expect %s, observed %s)\n' "$status" "$id" "$expect" "$observed"
}

lc_probe() {
  lc_record "$1" info - "$2" "${3:-}"
}

lc_label() {
  awk -F'\t' '
    /^#/ || NF == 0 { next }
    {
      if ($2 == "gate") { gates++; if ($5 == "FAIL") gfail = 1; if ($5 == "ERROR") gerr = 1 }
      if ($2 == "control") { controls++; if ($5 != "PASS") cbad = 1 }
      if ($2 == "caveat" && $4 == "ran") caveat = 1
      if ($2 == "gap" && $4 == "ran") gap = 1
    }
    END {
      if (gfail) print "not-lockable"
      else if (!gates || gerr || !controls || cbad) print "unverified"
      else if (caveat) print "lockable-with-caveats"
      else if (gap) print "lockable-with-gaps"
      else print "lockable"
    }' "$1"
}

lc_label_text() {
  case "$1" in
    lockable) echo "lockable" ;;
    lockable-with-gaps) echo "lockable, fail-open gaps listed" ;;
    lockable-with-caveats) echo "lockable with caveats" ;;
    not-lockable) echo "not lockable" ;;
    unverified) echo "unverified (a gate or control check was inconclusive; rerun)" ;;
    *)
      echo "lc_label_text: unknown label '$1'" >&2
      return 1
      ;;
  esac
}

lc_summarize() {
  local f="$1" label
  # Not `sed -i`: BSD sed (macOS) spells it differently.
  awk '!/^# label=/' "$f" >"$f.tmp"
  cat "$f.tmp" >"$f"
  rm -f "$f.tmp"
  label="$(lc_label "$f")"
  printf '# label=%s\n' "$label" >>"$f"
  awk -F'\t' '!/^#/ && NF { printf "%-5s %s  expect=%s observed=%s  %s\n", $5, $1, $3, $4, $6 }' "$f"
  printf 'label: %s\n' "$(lc_label_text "$label")"
  # Rows whose detail carries a hint (a harness setting to check) are
  # repeated at the end, so they are not lost in the table.
  awk -F'\t' '!/^#/ && NF && index($6, "hint: ") { printf "hint: %s: %s\n", $1, substr($6, index($6, "hint: ") + 6) }' "$f"
}

lc_validate() {
  local f="$1" key label
  if [[ ! -f "$f" ]]; then
    echo "lc_validate: $f: no such file" >&2
    return 1
  fi
  for key in agent agent_version node_version image saiife_commit kernel date; do
    if ! grep -q "^# $key=" "$f"; then
      echo "lc_validate: $f: missing header '# $key='" >&2
      return 1
    fi
  done
  awk -F'\t' '
    BEGIN {
      split("control gate gap caveat design info", a, " "); for (i in a) class[a[i]] = 1
      split("- ran blocked fired not-fired unavailable", a, " "); for (i in a) expect[a[i]] = 1
      split("found not-found ran blocked fired not-fired unavailable inconclusive unsupported", a, " ")
      for (i in a) observed[a[i]] = 1
    }
    /^#/ { next }
    NF == 0 { bad = bad "line " NR ": empty line\n"; next }
    {
      if (NF != 6) { bad = bad "line " NR ": " NF " fields\n"; next }
      if (!($2 in class)) bad = bad "line " NR ": unknown class " $2 "\n"
      if (!($3 in expect)) bad = bad "line " NR ": unknown expect " $3 "\n"
      if (!($4 in observed)) bad = bad "line " NR ": unknown observed " $4 "\n"
      if ($2 == "info") st = "INFO"
      else if ($4 == "unsupported") st = "SKIP"
      else if ($4 == "inconclusive") st = "ERROR"
      else if ($4 == $3) st = "PASS"
      else st = "FAIL"
      if ($5 != st) bad = bad "line " NR ": status " $5 ", expected " st "\n"
    }
    END { if (bad != "") { printf "%s", bad > "/dev/stderr"; exit 1 } }' "$f" || {
    echo "lc_validate: $f: bad rows" >&2
    return 1
  }
  if [[ "$(grep -c '^# label=' "$f")" != 1 ]]; then
    echo "lc_validate: $f: needs exactly one '# label=' line" >&2
    return 1
  fi
  label="$(sed -n 's/^# label=//p' "$f")"
  if [[ "$label" != "$(lc_label "$f")" ]]; then
    echo "lc_validate: $f: label $label, rows give $(lc_label "$f")" >&2
    return 1
  fi
}

# --- state -------------------------------------------------------------------

# chown to agent; a no-op under LC_ROOT (tests run unprivileged).
lc_chown_agent() {
  if [[ -z "$LC_ROOT" ]]; then
    chown "agent:$LC_AGENT_GROUP" "$@"
  fi
}

# Run "$@" as the user `agent` (as root, never offline).
lc_as_agent() {
  if [[ "$LC_PLATFORM" == macos ]]; then
    sudo -u agent -- "$@"
  else
    setpriv --reuid=agent --regid=agent --init-groups -- "$@"
  fi
}

lc_require_path() {
  local path="$1" real
  real="$(realpath -m -- "$path")"
  if [[ -n "$LC_ROOT" ]]; then
    [[ "$real" == "$LC_ROOT/"* ]] && return 0
  elif [[ "$LC_PLATFORM" == macos ]]; then
    [[ "$real" == /Users/agent/* || "$real" == /opt/lockcheck/work/* ]] && return 0
  else
    [[ "$real" == /home/agent/* || "$real" == /work/* ]] && return 0
  fi
  echo "lib.sh: refusing path outside the lock-check root: $path" >&2
  return 1
}

lc_as_agent_write() {
  local path="$1" content="$2"
  lc_require_path "$path" || return 1
  if [[ -n "$LC_ROOT" ]]; then
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" >"$path"
  else
    # shellcheck disable=SC2016 # expanded by the inner shell
    lc_as_agent \
      bash -c 'mkdir -p "$(dirname "$1")" && printf "%s\n" "$2" >"$1"' lc-write "$path" "$content"
  fi
}

lc_set_mode() {
  local mode="$1" file="$LC_RUN/mode"
  if [[ "${2:-}" == config-change ]]; then
    file="$LC_RUN/mode.config-change"
  fi
  if [[ "$mode" == missing ]]; then
    rm -f "$LC_STUB"
  fi
  printf '%s\n' "$mode" >"$file"
  chmod 0644 "$file"
}

lc_snapshot() {
  local dir="$LC_SNAPSHOT" i=0 f login
  while IFS= read -r f; do
    if [[ -n "$f" ]] && ! lc_require_path "$f"; then
      return 1
    fi
  done < <(agent_settings_files; agent_login_files)
  rm -rf "$dir"
  mkdir -p "$dir"
  chmod 0700 "$dir"
  : >"$dir/list.tmp"
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    while IFS= read -r login; do
      if [[ -n "$login" && "$login" == "$f" ]]; then
        echo "lc_snapshot: $f is both a settings and a login file" >&2
        return 1
      fi
    done < <(agent_login_files)
    i=$((i + 1))
    if [[ -e "$f" || -L "$f" ]]; then
      cp -a "$f" "$dir/$i"
      printf '%s\t%s\n' "$i" "$f" >>"$dir/list.tmp"
    else
      printf -- '-\t%s\n' "$f" >>"$dir/list.tmp"
    fi
  done < <(agent_settings_files)
  mv "$dir/list.tmp" "$dir/list"
}

lc_restore_snapshot() {
  local dir="$LC_SNAPSHOT" i f
  [[ -f "$dir/list" ]] || return 0
  while IFS=$'\t' read -r i f; do
    lc_require_path "$f" || continue
    rm -f "$f"
    if [[ "$i" != - ]]; then
      mkdir -p "$(dirname "$f")"
      cp -a "$dir/$i" "$f"
    fi
  done <"$dir/list"
}

# Install hook script $1 at $2 (0755). The stub and the witness log to
# ${LC_ROOT:-}/run/lockcheck; where LC_RUN is elsewhere (macOS) that path is
# written into the copy, because a hook gets no harness environment.
lc_install_hook() {
  local src="$1" dst="$2" tmp run="$LC_RUN"
  if [[ "$LC_RUN" == "$LC_ROOT/run/lockcheck" ]]; then
    install -m 0755 "$src" "$dst"
    return 0
  fi
  # On Windows the hook runs in Git Bash on the real machine: /c/lockcheck/run.
  if [[ "$LC_PLATFORM" == windows ]]; then
    run="$(lc_real_posix "$LC_RUN")"
  fi
  tmp="$dst.tmp"
  awk -v run="$run" '{ gsub(/[$][{]LC_ROOT:-[}]\/run\/lockcheck/, run); print }' "$src" >"$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$dst"
}

lc_reset() {
  lc_restore_snapshot
  rm -rf "$LC_HOME/alt"
  mkdir -p "$(dirname "$LC_STUB")" "$(dirname "$LC_WITNESS")" "$LC_RUN" "$LC_MARKERS"
  chmod 0755 "$LC_RUN"
  lc_install_hook "$LC_SRC/stub-saiife.sh" "$LC_STUB"
  lc_install_hook "$LC_SRC/witness.sh" "$LC_WITNESS"
  if [[ "$LC_PLATFORM" == windows ]]; then
    # shellcheck disable=SC2016 # "$@" is for the script
    printf '#!/usr/bin/env bash\nexec touch -- "$@"\n' >"$(dirname "$LC_WITNESS")/lc-touch"
    chmod 0755 "$(dirname "$LC_WITNESS")/lc-touch"
  fi
  lc_set_mode allow
  lc_set_mode allow config-change
  : >"$LC_RUN/calls.log"
  : >"$LC_RUN/witness.log"
  chmod 0644 "$LC_RUN/calls.log" "$LC_RUN/witness.log"
  lc_chown_agent "$LC_RUN/calls.log" "$LC_RUN/witness.log"
  find "$LC_MARKERS" -mindepth 1 -delete
  lc_chown_agent "$LC_PROJECT" "$LC_MARKERS"
  rm -f "$LC_RUN/last-output"
  LC_AGENT_ENV=()
  LC_AGENT_ARGS=()
  LC_PROMPT=""
  LC_FIRED_EVENT=""
  LC_POST=""
  LC_LAST_EXIT=0
  agent_baseline
}

# --- running the agent -------------------------------------------------------

lc_nonce() {
  od -An -N6 -tx1 /dev/urandom | tr -d ' \n'
}

lc_prompt_touch() {
  local cmd="touch $LC_MARKERS/$1"
  if [[ "$LC_PLATFORM" == windows && "$LC_WIN_SHELL" == powershell ]]; then
    cmd="New-Item -ItemType File -Force -Path $(lc_real "$LC_MARKERS/$1")"
  elif [[ "$LC_PLATFORM" == windows ]]; then
    cmd="touch $(lc_real "$LC_MARKERS/$1")"
  fi
  printf 'Use your shell tool to run exactly this command, and nothing else, then reply DONE: %s' "$cmd"
}

# --- paths as the agent sees them ---------------------------------------------

# $LC_ROOT/C/x is C:/x on Windows; every other path, and every other
# platform, is unchanged.
lc_real() {
  local p="$1"
  if [[ "$LC_PLATFORM" == windows && "$p" == "$LC_ROOT/C/"* ]]; then
    printf 'C:/%s\n' "${p#"$LC_ROOT/C/"}"
  else
    printf '%s\n' "$p"
  fi
}

# The Git Bash form of lc_real: /c/x.
lc_real_posix() {
  local p="$1"
  if [[ "$LC_PLATFORM" == windows && "$p" == "$LC_ROOT/C/"* ]]; then
    printf '/c/%s\n' "${p#"$LC_ROOT/C/"}"
  else
    printf '%s\n' "$p"
  fi
}

# Text with every staging path in it replaced by its C:/ form (Windows).
lc_real_text() {
  local t
  t="$(cat; printf x)"
  t="${t%x}"
  if [[ "$LC_PLATFORM" == windows ]]; then
    t="${t//"$LC_ROOT/C/"/C:/}"
  fi
  printf '%s' "$t"
}

lc_touch_cmd() {
  if [[ "$LC_PLATFORM" == windows ]]; then
    printf 'C:/lockcheck/bin/lc-touch.exe %s\n' "$(lc_real "$1")"
  else
    printf 'touch %s\n' "$1"
  fi
}

# The hook command every managed fixture names, and the W9 one for Windows.
LC_FIXTURE_CMD=/opt/saiife/bin/saiife
LC_WIN_HOOK_CMD=C:/ProgramData/saiife/bin/saiife.exe

lc_managed_file() {
  local rel="$1" src="$LC_MANAGED/$1" dst t
  if [[ "$LC_PLATFORM" != windows ]]; then
    printf '%s\n' "$src"
    return 0
  fi
  dst="$LC_ROOT/.lc-managed/$rel"
  mkdir -p "$(dirname "$dst")"
  t="$(cat "$src"; printf x)"
  t="${t%x}"
  printf '%s' "${t//"$LC_FIXTURE_CMD"/$LC_WIN_HOOK_CMD}" >"$dst"
  printf '%s\n' "$dst"
}

# Offline only: a bin dir with links to the basic host tools in
# LC_HOSTBIN_TOOLS, so an offline agent run can never find a real agent CLI.
lc_hostbin() {
  local dir="$LC_ROOT/.lc-hostbin" tool path
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
    for tool in "${LC_HOSTBIN_TOOLS[@]}"; do
      if path="$(command -v "$tool")" && [[ "$path" == /* ]]; then
        ln -sf "$path" "$dir/$tool"
      fi
    done
  fi
  printf '%s\n' "$dir"
}

# The command prefix that runs something as the agent, into array `LC_CMD`.
lc_agent_cmd() {
  if [[ -n "$LC_ROOT" ]]; then
    LC_CMD=(env -i "HOME=$LC_HOME" "PATH=$LC_ROOT/usr/local/bin:$(lc_hostbin)" TERM=dumb
      "LC_ROOT=$LC_ROOT" "${LC_SECRET_ENV[@]}" "${LC_AGENT_ENV[@]}")
  elif [[ "$LC_PLATFORM" == macos ]]; then
    LC_CMD=(sudo -u agent --
      env -i "HOME=$LC_HOME" USER=agent LOGNAME=agent "PATH=$LC_AGENT_PATH" TERM=dumb
      "${LC_SECRET_ENV[@]}" "${LC_AGENT_ENV[@]}")
  else
    LC_CMD=(setpriv --reuid=agent --regid=agent --init-groups --
      env -i HOME=/home/agent "PATH=$LC_AGENT_PATH" TERM=dumb "${LC_SECRET_ENV[@]}" "${LC_AGENT_ENV[@]}")
  fi
}

lc_agent_call() {
  local fn="$1" script
  shift
  # shellcheck disable=SC2016 # "$@" is for the agent's shell
  script="$(declare -f "$fn")"$'\n'"$fn"' "$@"'
  if [[ -n "$LC_WIN_XCHG" ]]; then
    local d
    d="$(lc_win_handoff call "${AGENT_TIMEOUT:-240}" "$script" "$@")" || return 1
    cat "$d/back/output" 2>/dev/null || true
    return "$(cat "$d/back/exit" 2>/dev/null || echo 1)"
  fi
  lc_agent_cmd
  (cd "$LC_PROJECT" 2>/dev/null || cd /; "${LC_CMD[@]}" bash -c "$script" lc-agent "$@") </dev/null
}

lc_run_agent() {
  local prompt="$1" out="$LC_RUN/last-output" rc=0 script
  local -a cmd
  # shellcheck disable=SC2016 # "$@" is for the agent's shell
  script="$(declare -f agent_invoke)"$'\nagent_invoke "$@"'
  if [[ -z "$LC_WIN_XCHG" ]]; then
    lc_agent_cmd
    cmd=("${LC_CMD[@]}")
  fi
  {
    printf '\n===== %s =====\n' "${LC_CURRENT:-agent run}"
    printf 'prompt: %s\n' "$prompt"
    printf 'args: %s\n' "${LC_AGENT_ARGS[*]}"
    printf 'env: %s\n' "${LC_AGENT_ENV[*]}"
    printf -- '-----\n'
  } >>"$LC_LOG"
  if [[ -n "$LC_WIN_XCHG" ]]; then
    local d
    if d="$(lc_win_handoff run "${AGENT_TIMEOUT:-240}" "$script" "$prompt" "${LC_AGENT_ARGS[@]}")"; then
      rc="$(cat "$d/back/exit" 2>/dev/null || echo 1)"
      lc_win_collect "$d"
    else
      rc=124
      printf 'windows-vm.ps1 did not answer the plan in time\n' >"$out"
    fi
    {
      cat "$out"
      printf -- '----- exit %s\n' "$rc"
    } >>"$LC_LOG"
    LC_LAST_EXIT="$rc"
    return 0
  fi
  (
    cd "$LC_PROJECT"
    exec timeout -k 5 "${AGENT_TIMEOUT:-240}" "${cmd[@]}" \
      bash -c "$script" lc-agent "$prompt" "${LC_AGENT_ARGS[@]}"
  ) >"$out" 2>&1 </dev/null || rc=$?
  if [[ -z "$LC_ROOT" ]]; then
    # Hooks or tools the agent started in their own process group outlive
    # `timeout`; they must not write into the next check's logs.
    pkill -KILL -u agent >/dev/null 2>&1 || true
  fi
  {
    cat "$out"
    printf -- '----- exit %s\n' "$rc"
  } >>"$LC_LOG"
  LC_LAST_EXIT="$rc"
  return 0
}

# --- observing ---------------------------------------------------------------

lc_hook_fired() {
  local nonce="$1" event="${2:-}"
  [[ -f "$LC_RUN/calls.log" ]] || return 1
  awk -F'\t' -v n="$nonce" -v e="$event" '
    (e == "" || $2 == e) && (n == "-" || index($4, n)) { found = 1 }
    END { exit !found }' "$LC_RUN/calls.log"
}

# A witness line counts only if it holds the nonce and the tool key: the
# nonce in a prompt or model event is not a tool call.
lc_witness_saw() {
  [[ -f "$LC_RUN/witness.log" ]] || return 1
  awk -v n="$1" -v k="$LC_WITNESS_TOOL_KEY" 'index($0, n) && index($0, k) { found = 1 } END { exit !found }' \
    "$LC_RUN/witness.log"
}

lc_last_unsupported() {
  [[ "$LC_LAST_EXIT" != 0 && -f "$LC_RUN/last-output" ]] &&
    grep -qiE -- "$LC_UNSUPPORTED_RE" "$LC_RUN/last-output"
}

lc_row_observed() {
  [[ -n "$LC_RESULTS" && -f "$LC_RESULTS" ]] || return 0
  awk -F'\t' -v id="$1" '!/^#/ && $1 == id { o = $4 } END { print o }' "$LC_RESULTS"
}

lc_control_failed() {
  [[ -n "$LC_RESULTS" && -f "$LC_RESULTS" ]] || return 1
  awk -F'\t' '!/^#/ && $2 == "control" && $5 != "PASS" { bad = 1 } END { exit !bad }' "$LC_RESULTS"
}

lc_observe() {
  local nonce="$1" control="${2:-}"
  if [[ -e "$LC_MARKERS/$nonce" ]]; then
    echo ran
  elif lc_witness_saw "$nonce"; then
    echo blocked
  elif lc_last_unsupported; then
    echo unsupported
  elif [[ -n "$control" && "$(lc_row_observed "$control")" == ran ]]; then
    echo unavailable
  else
    echo inconclusive
  fi
}

# `not-fired` needs evidence that the agent acted (marker or witness);
# with neither, the model may simply not have tried: inconclusive.
lc_observe_fired() {
  local nonce="$1" event="${2:-}" match
  match="$nonce"
  if [[ -n "$event" ]]; then
    match="-"
  fi
  if lc_hook_fired "$match" "$event"; then
    echo fired
  elif lc_last_unsupported; then
    echo unsupported
  elif [[ -e "$LC_MARKERS/$nonce" ]] || lc_witness_saw "$nonce"; then
    echo not-fired
  else
    echo inconclusive
  fi
}

lc_calls_tool_names() {
  [[ -f "$LC_RUN/calls.log" ]] || return 0
  awk -F'\t' -v n="$1" 'index($4, n) { print $4 }' "$LC_RUN/calls.log" |
    jq -r '.tool_name // empty' 2>/dev/null | sort -u | paste -sd, -
}

lc_check() {
  local id="$1" class="$2" expect="$3" mode="$4" setup="${5:--}" control="${6:-}"
  local nonce observed detail prompt
  if lc_control_failed; then
    lc_record "$id" "$class" "$expect" inconclusive "control failed: log in with --setup"
    return 0
  fi
  lc_reset
  LC_CURRENT="$id"
  nonce="$(lc_nonce)"
  LC_NONCE="$nonce"
  if [[ "$setup" != - ]]; then
    "$setup"
  fi
  lc_set_mode "$mode"
  prompt="${LC_PROMPT:-$(lc_prompt_touch "$nonce")}"
  lc_run_agent "$prompt"
  case "$expect" in
    fired | not-fired) observed="$(lc_observe_fired "$nonce" "$LC_FIRED_EVENT")" ;;
    *) observed="$(lc_observe "$nonce" "$control")" ;;
  esac
  detail="mode=$mode exit=$LC_LAST_EXIT"
  if lc_hook_fired "$nonce"; then
    detail+=" stub=seen"
  else
    detail+=" stub=unseen"
    # A deny only counts if the stub was asked: a call stopped by anything
    # else (trust prompt, sandbox, approval mode) is no evidence of the lock.
    if [[ "$mode" == deny && "$observed" == blocked ]]; then
      observed=inconclusive
      detail+=" (blocked, but the stub never ran: something else stopped the call)"
    fi
  fi
  if lc_witness_saw "$nonce"; then
    detail+=" witness=seen"
  else
    detail+=" witness=unseen"
    if [[ "$class" == control ]]; then
      detail+=" hint: the witness hook did not log this call (not registered, or its"
      detail+=" payload lacks $LC_WITNESS_TOOL_KEY); blocked rows will read inconclusive"
    fi
  fi
  if [[ "$class" == gate && "$expect" == fired && "$observed" == not-fired ]] &&
    declare -F agent_fires_hint >/dev/null; then
    detail+=" hint: $(agent_fires_hint)"
  fi
  if [[ "$LC_LAST_EXIT" == 124 || "$LC_LAST_EXIT" == 137 ]]; then
    detail+=" (agent timed out after ${AGENT_TIMEOUT:-240}s)"
  fi
  if [[ -n "$LC_POST" ]]; then
    detail+=" $("$LC_POST" "$nonce")"
  fi
  lc_record "$id" "$class" "$expect" "$observed" "$detail"
}

# --- Windows plans -------------------------------------------------------------
#
# windows-vm.ps1 runs bash elevated, with LC_ROOT a staging dir and
# LC_WIN_XCHG an exchange dir, and calls lc_win_main. Every agent run (and
# every lc_agent_call) becomes a plan dir $LC_WIN_XCHG/<nnnn>/:
#   kind      run | call | restore
#   timeout   seconds for the agent run
#   cwd       the agent's working dir (C:/ form)
#   argv      NUL-separated arguments for bash.exe, run as `agent`
#   env       NUL-separated NAME=value lines added to the agent's env
#   mirror    TSV lines, each with a path relative to C:\ (run and restore):
#               admin <rel>          write files/<rel> (a file or a tree) as
#                                    admin: SYSTEM and Administrators full,
#                                    Users read (managed files, stub, witness)
#               agent <rel>          write files/<rel>, `agent` full control
#               log <rel>            an empty file that `agent` may write
#               gone <rel>           delete it
#               link <rel> <target>  a copy of the real file <target> (the
#                                    agent's logins, in an alternate config dir)
#   files/    the staged files, with every staging path written as C:/...
# and last an empty `ready`. The ps1 deletes each real path it mirrors
# before writing it, runs the agent, and answers with back/exit,
# back/output, back/calls.log, back/witness.log, back/markers (one marker
# name per line) and last an empty `done`.

lc_win_mirror_entry() {
  local tmp="$1" kind="$2" p="$3" rel f t
  if [[ "$p" != "$LC_ROOT/C/"* || "/$p/" == */../* ]]; then
    echo "lib.sh: not a staging path: $p" >&2
    return 1
  fi
  rel="${p#"$LC_ROOT/C/"}"
  if [[ "$kind" == log ]]; then
    printf 'log\t%s\n' "$rel" >>"$tmp/mirror"
    return 0
  fi
  if [[ ! -e "$p" && ! -L "$p" ]]; then
    printf 'gone\t%s\n' "$rel" >>"$tmp/mirror"
    return 0
  fi
  printf '%s\t%s\n' "$kind" "$rel" >>"$tmp/mirror"
  while IFS= read -r -d '' f; do
    rel="${f#"$LC_ROOT/C/"}"
    if [[ -L "$f" ]]; then
      t="$(readlink -- "$f")"
      if [[ "$t" != "$LC_ROOT/C/"* || "/$t/" == */../* ]]; then
        echo "lib.sh: a link out of the staging tree: $f -> $t" >&2
        return 1
      fi
      printf 'link\t%s\t%s\n' "$rel" "${t#"$LC_ROOT/C/"}" >>"$tmp/mirror"
    elif [[ -d "$f" ]]; then
      mkdir -p "$tmp/files/$rel"
    else
      mkdir -p "$(dirname "$tmp/files/$rel")"
      lc_real_text <"$f" >"$tmp/files/$rel"
    fi
  done < <(find "$p" -print0)
}

# The paths every run mirrors: the managed files, the stub and witness, the
# mode files and logs, the settings files, the work dir and ~/alt.
lc_win_plan_mirror() {
  local tmp="$1" p
  while IFS= read -r p; do
    if [[ -n "$p" ]]; then
      lc_win_mirror_entry "$tmp" admin "$p" || return 1
    fi
  done < <(
    agent_managed_paths
    dirname "$LC_STUB"
    dirname "$LC_WITNESS"
    printf '%s\n' "$LC_RUN/mode" "$LC_RUN/mode.config-change"
  )
  lc_win_mirror_entry "$tmp" log "$LC_RUN/calls.log" || return 1
  lc_win_mirror_entry "$tmp" log "$LC_RUN/witness.log" || return 1
  while IFS= read -r p; do
    if [[ -n "$p" ]]; then
      lc_win_mirror_entry "$tmp" agent "$p" || return 1
    fi
  done < <(
    agent_settings_files
    printf '%s\n' "$LC_WORK" "$LC_HOME/alt"
  )
}

# lc_win_handoff <kind> <timeout> <script> [args...]: write a plan, wait for
# the answer, print the plan dir. Fails when no answer comes in time.
lc_win_handoff() {
  local kind="$1" timeout="$2" script="$3" d tmp a e waited=0 limit
  shift 3
  LC_WIN_SEQ=$((LC_WIN_SEQ + 1))
  d="$LC_WIN_XCHG/$(printf '%04d' "$LC_WIN_SEQ")"
  tmp="$d.tmp"
  rm -rf "$tmp" "$d"
  mkdir -p "$tmp/files"
  printf '%s\n' "$kind" >"$tmp/kind"
  printf '%s\n' "$timeout" >"$tmp/timeout"
  lc_real "$LC_PROJECT" >"$tmp/cwd"
  {
    if [[ -n "$script" ]]; then
      printf '%s\0' -c "$script" lc-agent
    fi
    for a in "$@"; do
      printf '%s\0' "$(printf '%s' "$a" | lc_real_text)"
    done
  } >"$tmp/argv"
  {
    for e in "${LC_SECRET_ENV[@]}" "${LC_AGENT_ENV[@]}"; do
      printf '%s\0' "$(printf '%s' "$e" | lc_real_text)"
    done
  } >"$tmp/env"
  : >"$tmp/mirror"
  if [[ "$kind" != call ]]; then
    lc_win_plan_mirror "$tmp" || return 1
  fi
  mv "$tmp" "$d"
  : >"$d/ready"
  limit=$(((timeout + 120) * 5))
  while [[ ! -e "$d/done" ]]; do
    if ((waited >= limit)); then
      echo "lib.sh: no answer to plan $d" >&2
      return 1
    fi
    sleep 0.2
    waited=$((waited + 1))
  done
  printf '%s\n' "$d"
}

# Copy a run's answer into the staging tree, where lc_observe looks.
lc_win_collect() {
  local d="$1" n
  if [[ -f "$d/back/output" ]]; then
    cp "$d/back/output" "$LC_RUN/last-output"
  else
    : >"$LC_RUN/last-output"
  fi
  for n in calls.log witness.log; do
    if [[ -f "$d/back/$n" ]]; then
      cp "$d/back/$n" "$LC_RUN/$n"
    fi
  done
  if [[ -f "$d/back/markers" ]]; then
    while IFS= read -r n || [[ -n "$n" ]]; do
      n="${n%$'\r'}"
      if [[ "$n" =~ ^[A-Za-z0-9._-]+$ ]]; then
        : >"$LC_MARKERS/$n"
      fi
    done <"$d/back/markers"
  fi
}

# lc_win_main <agent> <results.tsv>: the Windows runner, as in-container.sh
# `run` and macos-vm.sh are elsewhere. windows-vm.ps1 sets
# LOCKCHECK_WIN_IMAGE (the Windows build) and SAIIFE_COMMIT.
lc_win_main() {
  local agent="$1" out="$2" version node_version
  if [[ "$LC_PLATFORM" != windows || -z "$LC_WIN_XCHG" ]]; then
    echo "lc_win_main: needs LOCKCHECK_PLATFORM=windows and LC_WIN_XCHG" >&2
    return 2
  fi
  if [[ ! "$agent" =~ ^[a-z0-9]+$ || ! -f "$LC_SRC/checks-$agent.sh" ]]; then
    echo "lc_win_main: no checks for '$agent'" >&2
    return 2
  fi
  # shellcheck source=/dev/null
  source "$LC_SRC/checks-$agent.sh"
  mkdir -p "$LC_MARKERS" "$LC_RUN" "$(dirname "$out")"
  LC_RESULTS="$out"
  LC_LOG="${out%.tsv}.log"
  : >"$LC_LOG"
  version="$(lc_agent_call agent_version 2>/dev/null | head -n1 || true)"
  node_version="$(node --version 2>/dev/null || true)"
  {
    printf '# agent=%s\n' "$agent"
    printf '# agent_version=%s\n' "${version:-unknown}"
    printf '# node_version=%s\n' "${node_version:-none}"
    printf '# image=%s\n' "${LOCKCHECK_WIN_IMAGE:-windows-unknown}"
    printf '# saiife_commit=%s\n' "${SAIIFE_COMMIT:-unknown}"
    printf '# kernel=%s\n' "$(uname -r)"
    printf '# platform=windows\n'
    printf '# date=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$LC_RESULTS"
  lc_snapshot
  echo "[lockcheck] Windows $agent: ${version:-unknown}, results in $LC_RESULTS"
  agent_checks
  # Put the settings back on the machine too, not only in staging.
  lc_restore_snapshot
  rm -rf "$LC_HOME/alt"
  if ! lc_win_handoff restore 0 "" >/dev/null; then
    echo "[lockcheck] the final restore got no answer" >&2
  fi
  echo
  lc_summarize "$LC_RESULTS"
  lc_validate "$LC_RESULTS"
  echo "results: $LC_RESULTS"
  echo "agent output: $LC_LOG"
}
