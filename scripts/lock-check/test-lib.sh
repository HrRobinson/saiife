#!/usr/bin/env bash
# Offline tests for the live lock-check harness (scripts/lock-check/).
#
# Runs everything that can be checked without Docker, network, agent logins
# or root: the summarizer and label rule, result-file validation, the stub
# saiife modes, the observation rules, and a full `in-container.sh run`
# against a fake agent (testdata/fake-agent.sh, checks-fake.sh). Each test
# gets its own `mktemp -d` dir as LC_ROOT, so every container path (/etc,
# /run/lockcheck, /work/project, /home/agent, /out) lands under that dir.
# Nothing outside TMPDIR is written; the host wrapper is only run with
# --print and a stub `docker` on PATH.
#
#   bash scripts/lock-check/test-lib.sh [test-name ...]
#
# Prints `ok <name>` / `FAIL <name>` (with the test's output indented) and
# exits 1 if any test failed. Tests are the functions named `test_<name>`;
# later tasks add theirs (e.g. `test_claude_checks_static`) and they are
# picked up automatically.
set -euo pipefail
# Tests are called by name ("test_$name"), never directly.
# shellcheck disable=SC2317,SC2329

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TESTDATA="$HERE/testdata"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
# Nothing here may touch the real home: tests get a throwaway HOME.
REAL_HOME="${HOME:-}"
export HOME="$SCRATCH/home"
mkdir -p "$HOME"

# --- helpers -----------------------------------------------------------------

fail() {
  echo "assertion failed: $*" >&2
  exit 1
}

assert_eq() {
  if [[ "$1" != "$2" ]]; then
    fail "${3:-values differ}: expected '$2', got '$1'"
  fi
}

# Fresh LC_ROOT for one test, with lib.sh sourced against it.
new_root() {
  LC_ROOT="$(mktemp -d "$SCRATCH/root.XXXXXX")"
  export LC_ROOT
  # shellcheck source=/dev/null
  source "$HERE/lib.sh"
}

# The row of results file $1 whose id is $2, as "class expect observed status".
row_of() {
  awk -F'\t' -v id="$2" '!/^#/ && $1 == id { print $2, $3, $4, $5 }' "$1"
}

# Run in-container.sh for agent $1 with checks from dir $2 under $LC_ROOT;
# prints the result file path.
run_fake() {
  local agent="$1" checks="$2"
  LC_CHECKS_DIR="$checks" bash "$HERE/in-container.sh" run "$agent" >"$LC_ROOT/run.out" 2>&1 ||
    fail "in-container.sh run $agent failed: $(cat "$LC_ROOT/run.out")"
  local f
  f="$(find "$LC_ROOT/out" -maxdepth 1 -name "$agent-*.tsv" 2>/dev/null | head -n1)"
  [[ -n "$f" ]] || fail "no result file for $agent: $(cat "$LC_ROOT/run.out")"
  printf '%s\n' "$f"
}

# A checks dir holding checks-<name>.sh that sources the fake's contract and
# then the body given on stdin (usually an agent_checks override).
custom_checks() {
  local name="$1" dir
  dir="$(mktemp -d "$SCRATCH/checks.XXXXXX")"
  {
    printf '# shellcheck shell=bash\nsource %q\n' "$TESTDATA/checks-fake.sh"
    cat
  } >"$dir/checks-$name.sh"
  printf '%s\n' "$dir"
}

# --- summarizer --------------------------------------------------------------

test_status_table() {
  new_root
  assert_eq "$(lc_status gate blocked blocked)" PASS
  assert_eq "$(lc_status gate blocked ran)" FAIL
  assert_eq "$(lc_status gate blocked inconclusive)" ERROR
  assert_eq "$(lc_status gap ran ran)" PASS
  assert_eq "$(lc_status gap ran blocked)" FAIL
  assert_eq "$(lc_status info blocked ran)" INFO
  assert_eq "$(lc_status gate blocked unsupported)" SKIP
}

test_label_fixtures() {
  new_root
  assert_eq "$(lc_label "$TESTDATA/claude-lockable.tsv")" lockable
  assert_eq "$(lc_label "$TESTDATA/codex-gaps.tsv")" lockable-with-gaps
  assert_eq "$(lc_label "$TESTDATA/gemini-caveats.tsv")" lockable-with-caveats
  assert_eq "$(lc_label "$TESTDATA/gate-fail.tsv")" not-lockable
  assert_eq "$(lc_label "$TESTDATA/gate-error.tsv")" unverified
  assert_eq "$(lc_label "$TESTDATA/no-control.tsv")" unverified
  assert_eq "$(lc_label_text lockable-with-gaps)" "lockable, fail-open gaps listed"
  assert_eq "$(lc_label_text lockable-with-caveats)" "lockable with caveats"
  assert_eq "$(lc_label_text not-lockable)" "not lockable"
  assert_eq "$(lc_label_text lockable)" "lockable"
}

test_validate() {
  new_root
  local f bad="$LC_ROOT/bad.tsv"
  for f in "$TESTDATA"/*.tsv; do
    lc_validate "$f" || fail "$f does not validate"
  done
  sed 's/^# label=.*/# label=lockable-with-caveats/' "$TESTDATA/claude-lockable.tsv" >"$bad"
  if lc_validate "$bad" 2>/dev/null; then fail "wrong label accepted"; fi
  awk -F'\t' -v OFS='\t' '!/^#/ && !done { NF = 5; done = 1 } { print }' \
    "$TESTDATA/claude-lockable.tsv" >"$bad"
  if lc_validate "$bad" 2>/dev/null; then fail "5-field row accepted"; fi
  grep -v '^# agent_version=' "$TESTDATA/claude-lockable.tsv" >"$bad"
  if lc_validate "$bad" 2>/dev/null; then fail "missing agent_version accepted"; fi
}

test_summarize_appends_label() {
  new_root
  local f="$LC_ROOT/r.tsv" out
  grep -v '^# label=' "$TESTDATA/codex-gaps.tsv" >"$f"
  out="$(lc_summarize "$f")"
  assert_eq "$(grep -c '^# label=' "$f")" 1 "label lines"
  assert_eq "$(sed -n 's/^# label=//p' "$f")" lockable-with-gaps
  [[ "$out" == *"label: lockable, fail-open gaps listed"* ]] || fail "summary: $out"
  lc_validate "$f" || fail "summarized file does not validate"
}

# --- stub and witness --------------------------------------------------------

test_stub_modes() {
  new_root
  local run="$LC_ROOT/run/lockcheck" mode want rc start elapsed n=0
  mkdir -p "$run"
  # LC_ROOT is set, so segv/kill9 only exit 139/137: no real signal, no core
  # dump on the host. The real signals run only inside the container.
  ulimit -c 0
  for mode in allow:0 deny:2 exit1:1 exit3:3 panic:101 segv:139 kill9:137 hang:0; do
    want="${mode#*:}"
    mode="${mode%%:*}"
    printf '%s\n' "$mode" >"$run/mode"
    rc=0
    start="$(date +%s%N)"
    printf '{"tool_name":"Bash",\n"n":"%s"}\n' "$mode" |
      LOCKCHECK_HANG_SECS=1 bash "$HERE/stub-saiife.sh" check --managed --hook-exit --agent fake \
        >/dev/null 2>"$LC_ROOT/err" || rc=$?
    elapsed=$((($(date +%s%N) - start) / 1000000))
    n=$((n + 1))
    assert_eq "$rc" "$want" "exit code of mode $mode"
    if [[ "$mode" == deny ]]; then
      grep -q 'blocked by stub' "$LC_ROOT/err" || fail "deny stderr: $(cat "$LC_ROOT/err")"
    fi
    if [[ "$mode" == hang ]] && ((elapsed < 1000)); then
      fail "hang returned after ${elapsed}ms"
    fi
    assert_eq "$(wc -l <"$run/calls.log")" "$n" "calls.log lines after $mode"
    assert_eq "$(tail -n1 "$run/calls.log" | cut -f2,3)" "pre-tool	$mode" "calls.log row for $mode"
    tail -n1 "$run/calls.log" | cut -f4 | grep -q "\"n\":\"$mode\"" ||
      fail "calls.log stdin field for $mode: $(tail -n1 "$run/calls.log")"
  done
  printf 'allow\n' >"$run/mode"
  printf 'deny\n' >"$run/mode.config-change"
  rc=0
  echo '{}' | bash "$HERE/stub-saiife.sh" check --managed --agent claude --event config-change \
    2>/dev/null || rc=$?
  assert_eq "$rc" 2 "config-change reads mode.config-change"
  assert_eq "$(tail -n1 "$run/calls.log" | cut -f2,3)" "config-change	deny"
}

test_witness_logs_stdin() {
  new_root
  mkdir -p "$LC_ROOT/run/lockcheck"
  printf 'a\nb-abc123\n' | bash "$HERE/witness.sh" >"$LC_ROOT/out.txt"
  [[ ! -s "$LC_ROOT/out.txt" ]] || fail "witness printed output"
  assert_eq "$(cut -f2 "$LC_ROOT/run/lockcheck/witness.log")" "ab-abc123"
}

# --- observation -------------------------------------------------------------

observe_root() {
  new_root
  mkdir -p "$LC_MARKERS" "$LC_RUN"
  : >"$LC_RUN/witness.log"
  : >"$LC_RUN/calls.log"
  LC_RESULTS="$LC_ROOT/results.tsv"
  : >"$LC_RESULTS"
}

test_observe_ran() {
  observe_root
  touch "$LC_MARKERS/0123456789ab"
  printf '1\t{"command":"touch 0123456789ab"}\n' >>"$LC_RUN/witness.log"
  assert_eq "$(lc_observe 0123456789ab)" ran
}

test_observe_blocked() {
  observe_root
  printf '1\t{"tool_name":"Bash","tool_input":{"command":"touch /work/project/markers/0123456789ab"}}\n' \
    >>"$LC_RUN/witness.log"
  assert_eq "$(lc_observe 0123456789ab)" blocked
}

# The nonce in a prompt or model event (no tool key) is not a tool call.
test_witness_needs_tool_key() {
  observe_root
  printf '1\t{"prompt":"touch /work/project/markers/0123456789ab"}\n' >>"$LC_RUN/witness.log"
  assert_eq "$(lc_observe 0123456789ab)" inconclusive
  printf '2\t{"tool_name":"Bash","tool_input":{"command":"echo hi"}}\n' >>"$LC_RUN/witness.log"
  assert_eq "$(lc_observe 0123456789ab)" inconclusive "nonce and key on different lines"
  assert_eq "$(LC_WITNESS_TOOL_KEY='"toolName"' lc_observe 0123456789ab)" inconclusive
  printf '3\t{"toolName":"x","args":"0123456789ab"}\n' >>"$LC_RUN/witness.log"
  assert_eq "$(LC_WITNESS_TOOL_KEY='"toolName"' lc_observe 0123456789ab)" blocked "custom tool key"
}

test_observe_without_witness_is_inconclusive() {
  observe_root
  printf '1\t{"command":"touch ffffffffffff"}\n' >>"$LC_RUN/witness.log"
  assert_eq "$(lc_observe 0123456789ab)" inconclusive
}

test_observe_unavailable_needs_control_ran() {
  observe_root
  printf 'x.mcp.control\tdesign\tran\tblocked\tFAIL\t-\n' >>"$LC_RESULTS"
  assert_eq "$(lc_observe 0123456789ab x.mcp.control)" inconclusive
  printf 'y.mcp.control\tdesign\tran\tran\tPASS\t-\n' >>"$LC_RESULTS"
  assert_eq "$(lc_observe 0123456789ab y.mcp.control)" unavailable
  assert_eq "$(lc_observe 0123456789ab)" inconclusive
}

test_hook_fired() {
  observe_root
  printf '1\tpre-tool\tallow\t{"command":"touch 0123456789ab"}\n' >>"$LC_RUN/calls.log"
  lc_hook_fired 0123456789ab || fail "nonce not seen"
  if lc_hook_fired ffffffffffff; then fail "other nonce seen"; fi
  if lc_hook_fired - config-change; then fail "config-change seen"; fi
  printf '2\tconfig-change\tallow\t{}\n' >>"$LC_RUN/calls.log"
  lc_hook_fired - config-change || fail "config-change not seen"
}

# --- runner, end to end with the fake agent ----------------------------------

test_fake_end_to_end() {
  new_root
  local f
  f="$(run_fake fake "$TESTDATA")"
  lc_validate "$f" || fail "result does not validate: $(cat "$f")"
  assert_eq "$(row_of "$f" fake.control)" "control ran ran PASS"
  assert_eq "$(row_of "$f" fake.fires)" "gate fired fired PASS"
  assert_eq "$(row_of "$f" fake.deny)" "gate blocked blocked PASS"
  assert_eq "$(row_of "$f" fake.disabled)" "gate blocked ran FAIL"
  assert_eq "$(row_of "$f" fake.version)" "info - found INFO"
  assert_eq "$(sed -n 's/^# label=//p' "$f")" not-lockable
  grep -q $'^fake.deny\t.*stub=seen' "$f" || fail "deny detail: $(cat "$f")"
  [[ -s "${f%.tsv}.log" ]] || fail "no agent log next to $f"
  grep -q 'label: not lockable' "$LC_ROOT/run.out" || fail "summary not printed"
}

test_control_failure_skips_checks() {
  new_root
  local dir f
  dir="$(custom_checks ctl <<'EOF'
refuse() { LC_AGENT_ARGS=(--refuse); }
agent_checks() {
  lc_check ctl.control control ran allow refuse
  lc_check ctl.deny gate blocked deny
}
EOF
)"
  f="$(run_fake ctl "$dir")"
  assert_eq "$(row_of "$f" ctl.control)" "control ran inconclusive ERROR"
  assert_eq "$(row_of "$f" ctl.deny)" "gate blocked inconclusive ERROR"
  grep -q $'ctl.deny\t.*control failed: log in with --setup' "$f" || fail "detail: $(cat "$f")"
  assert_eq "$(sed -n 's/^# label=//p' "$f")" unverified
}

test_reset_restores_settings_snapshot() {
  new_root
  local dir f
  mkdir -p "$LC_HOME/.fake"
  printf 'original\n' >"$LC_HOME/.fake/settings.json"
  dir="$(custom_checks snap <<'EOF'
mutate() { lc_as_agent_write "$LC_HOME/.fake/settings.json" '{"disabled": true}'; }
capture() { cp "$LC_HOME/.fake/settings.json" "$LC_ROOT/seen"; }
agent_checks() {
  lc_check snap.control control ran allow
  lc_check snap.mutate gate blocked deny mutate
  lc_check snap.capture gate blocked deny capture
}
EOF
)"
  f="$(run_fake snap "$dir")"
  assert_eq "$(row_of "$f" snap.mutate)" "gate blocked ran FAIL"
  assert_eq "$(cat "$LC_ROOT/seen")" original "settings seen by the next check"
  assert_eq "$(row_of "$f" snap.capture)" "gate blocked blocked PASS"
  assert_eq "$(cat "$LC_HOME/.fake/settings.json")" original "settings after the run"
  [[ ! -e "$LC_ROOT/etc/fake/disabled" ]] || fail "absent settings file left behind"
}

test_missing_stub_detail_says_unseen() {
  new_root
  local dir f
  dir="$(custom_checks miss <<'EOF'
agent_checks() {
  lc_check miss.control control ran allow
  lc_check miss.missing gate blocked missing fake_fail_closed
}
EOF
)"
  f="$(run_fake miss "$dir")"
  assert_eq "$(row_of "$f" miss.missing)" "gate blocked blocked PASS"
  grep -q $'^miss.missing\t.*stub=unseen' "$f" || fail "detail: $(cat "$f")"
  grep -q $'^miss.control\t.*stub=seen' "$f" || fail "control detail: $(cat "$f")"
}

# A run killed mid-check leaves a mutated settings file and the snapshot in
# the home volume; the next run restores it before snapshotting.
test_interrupted_run_is_restored_next_time() {
  new_root
  local f
  mkdir -p "$LC_HOME/.fake"
  printf 'original\n' >"$LC_HOME/.fake/settings.json"
  (
    # shellcheck source=/dev/null
    source "$TESTDATA/checks-fake.sh"
    lc_snapshot
  )
  printf '{"disabled": true}\n' >"$LC_HOME/.fake/settings.json"
  f="$(run_fake fake "$TESTDATA")"
  assert_eq "$(row_of "$f" fake.deny)" "gate blocked blocked PASS"
  assert_eq "$(cat "$LC_HOME/.fake/settings.json")" original "settings after the run"
  [[ ! -e "$LC_SNAPSHOT" ]] || fail "snapshot left in the home volume"
  grep -q 'interrupted run' "$LC_ROOT/run.out" || fail "no restore message"
}

test_term_restores_settings() {
  new_root
  local dir rc=0
  mkdir -p "$LC_HOME/.fake"
  printf 'original\n' >"$LC_HOME/.fake/settings.json"
  dir="$(custom_checks term <<'EOF'
mutate_and_die() {
  lc_as_agent_write "$LC_HOME/.fake/settings.json" '{"disabled": true}'
  kill -TERM $$
}
agent_checks() {
  lc_check term.control control ran allow
  lc_check term.cut gate blocked deny mutate_and_die
}
EOF
)"
  LC_CHECKS_DIR="$dir" bash "$HERE/in-container.sh" run term >"$LC_ROOT/run.out" 2>&1 || rc=$?
  assert_eq "$rc" 143 "exit code after TERM"
  assert_eq "$(cat "$LC_HOME/.fake/settings.json")" original "settings after TERM"
}

test_reset_keeps_login_files() {
  new_root
  local f
  mkdir -p "$LC_HOME/.fake"
  head -c 64 /dev/urandom >"$LC_HOME/.fake/credentials.json"
  chmod 0600 "$LC_HOME/.fake/credentials.json"
  cp -p "$LC_HOME/.fake/credentials.json" "$LC_ROOT/creds.orig"
  f="$(run_fake fake "$TESTDATA")"
  cmp -s "$LC_HOME/.fake/credentials.json" "$LC_ROOT/creds.orig" || fail "login file changed"
  assert_eq "$(stat -c %a "$LC_HOME/.fake/credentials.json")" 600 "login file mode"
}

test_unknown_flag_is_unsupported() {
  new_root
  local dir f
  dir="$(custom_checks flags <<'EOF'
bogus() { LC_AGENT_ARGS=(--bogus); }
refuse() { LC_AGENT_ARGS=(--refuse); }
agent_checks() {
  lc_check flags.control control ran allow
  lc_check flags.bogus gate blocked deny bogus
  lc_check flags.refuse gate blocked deny refuse
}
EOF
)"
  f="$(run_fake flags "$dir")"
  assert_eq "$(row_of "$f" flags.bogus)" "gate blocked unsupported SKIP"
  assert_eq "$(row_of "$f" flags.refuse)" "gate blocked inconclusive ERROR"
}

test_agent_timeout_still_records_row() {
  new_root
  local dir f start
  dir="$(custom_checks slow <<'EOF'
slow() { LC_AGENT_ENV=(LOCKCHECK_HANG_SECS=5); }
agent_checks() {
  lc_check slow.control control ran allow
  lc_check slow.hang gate blocked hang slow
  lc_check slow.after gate blocked deny
}
EOF
)"
  start="$SECONDS"
  f="$(AGENT_TIMEOUT=1 run_fake slow "$dir")"
  [[ -n "$(row_of "$f" slow.hang)" ]] || fail "no row for the timed-out check"
  grep -q $'^slow.hang\t.*exit=124' "$f" || fail "timeout not in detail: $(cat "$f")"
  assert_eq "$(row_of "$f" slow.after)" "gate blocked blocked PASS"
  ((SECONDS - start < 15)) || fail "run took $((SECONDS - start))s"
}

test_lib_refuses_bad_roots() {
  local r rc
  for r in / // /. /tmp/.. "$SCRATCH/does-not-exist"; do
    rc=0
    LC_ROOT="$r" bash -c 'source "$1"' lib "$HERE/lib.sh" >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" 2 "lib.sh with LC_ROOT=$r"
    rc=0
    LC_ROOT="$r" bash "$HERE/in-container.sh" run fake >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" 2 "in-container.sh with LC_ROOT=$r"
  done
  if [[ ! -e /.dockerenv ]]; then
    rc=0
    env -u LC_ROOT bash -c 'source "$1"' lib "$HERE/lib.sh" >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" 2 "lib.sh with no LC_ROOT on the host"
  fi
  new_root
  assert_eq "$HOME" "$LC_ROOT/root" "HOME after sourcing lib.sh"
}

test_paths_outside_root_are_refused() {
  new_root
  local outside="$SCRATCH/outside.json" rc
  printf 'owner\n' >"$outside"
  lc_require_path "$LC_HOME/.fake/settings.json" || fail "path inside refused"
  for p in "$outside" /etc/passwd "$LC_ROOT/../outside.json" "$REAL_HOME/.claude/settings.json"; do
    if lc_require_path "$p" 2>/dev/null; then fail "accepted $p"; fi
  done
  rc=0
  (lc_as_agent_write "$outside" changed) 2>/dev/null || rc=$?
  [[ "$rc" != 0 ]] || fail "lc_as_agent_write outside LC_ROOT succeeded"
  # A checks script whose settings path escapes LC_ROOT: snapshot refuses
  # before touching anything.
  agent_settings_files() { printf '%s\n' "$outside"; }
  agent_login_files() { :; }
  rc=0
  (lc_snapshot) 2>/dev/null || rc=$?
  [[ "$rc" != 0 ]] || fail "lc_snapshot accepted an outside path"
  assert_eq "$(cat "$outside")" owner "outside file"
}

# Offline agent runs must never find a real agent CLI, even one on PATH.
test_offline_env_has_no_agents() {
  new_root
  local bin="$SCRATCH/realbin" out
  mkdir -p "$bin" "$LC_PROJECT" "$LC_RUN"
  for out in claude codex gemini node; do
    printf '#!/bin/sh\necho REAL\n' >"$bin/$out"
    chmod +x "$bin/$out"
  done
  PATH="$bin:$PATH"
  LC_LOG="$LC_ROOT/agent.log"
  agent_invoke() {
    for c in claude codex gemini node; do
      if command -v "$c" >/dev/null 2>&1; then echo "FOUND $c"; fi
    done
    echo "HOME=$HOME"
  }
  lc_run_agent "x"
  out="$(cat "$LC_RUN/last-output")"
  [[ "$out" != *FOUND* ]] || fail "agent CLI reachable offline: $out"
  [[ "$out" == *"HOME=$LC_HOME"* ]] || fail "agent HOME: $out"
}

test_in_container_refuses_on_host() {
  if [[ -e /.dockerenv ]]; then
    echo "skip: /.dockerenv exists"
    return 0
  fi
  local dir rc=0
  dir="$(mktemp -d "$SCRATCH/host.XXXXXX")"
  (cd "$dir" && env -u LC_ROOT bash "$HERE/in-container.sh" run fake) >"$dir.out" 2>&1 || rc=$?
  assert_eq "$rc" 2 "exit code"
  grep -qi 'container' "$dir.out" || fail "no message: $(cat "$dir.out")"
  assert_eq "$(find "$dir" -mindepth 1)" "" "files created"
  rc=0
  LC_ROOT=/ bash "$HERE/in-container.sh" run fake >/dev/null 2>&1 || rc=$?
  assert_eq "$rc" 2 "LC_ROOT=/ exit code"
}

# --- host wrapper and Dockerfile ---------------------------------------------

test_wrapper_print_mounts_exactly() {
  local bin out vols item
  bin="$(mktemp -d "$SCRATCH/bin.XXXXXX")"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$bin/docker"
  chmod +x "$bin/docker"
  out="$(PATH="$bin:$PATH" bash "$REPO/scripts/live-check-locked.sh" --print claude)" ||
    fail "wrapper --print failed"
  vols="$(printf '%s\n' "$out" | awk 'prev == "-v" { print } { prev = $0 }')"
  assert_eq "$vols" "$REPO/scripts/lock-check:/lockcheck:ro
$REPO/crates/agents/tests/fixtures/managed:/lockcheck-managed:ro
$REPO/target/lock-check:/out
saiife-lockcheck-home:/home/agent" "mounts"
  while IFS= read -r item; do
    if [[ -n "$REAL_HOME" && "$item" == "$REAL_HOME/"* && "$item" != "$REPO/"* ]]; then
      fail "argv item under \$HOME outside the repo: $item"
    fi
    case "$item" in
      --privileged* | --network=host | --net=host | --pid=host | --cap-add*)
        fail "forbidden docker option: $item" ;;
    esac
  done <<<"$out"
  if printf '%s\n' "$out" | grep -qxE -- '--network|--net' &&
    printf '%s\n' "$out" | grep -qx host; then
    fail "--network host"
  fi
  printf '%s\n' "$out" | grep -qx -- '--name' || fail "no --name"
  printf '%s\n' "$out" | grep -qx 'saiife-lockcheck-claude' || fail "container name"
  printf '%s\n' "$out" | grep -qx '/lockcheck/in-container.sh' || fail "entrypoint script"
  printf '%s\n' "$out" | awk 'prev == "--ulimit" && $0 == "core=0" { f = 1 } { prev = $0 } END { exit !f }' ||
    fail "no --ulimit core=0"
  printf '%s\n' "$out" | awk 'prev == "--security-opt" && $0 == "no-new-privileges" { f = 1 } { prev = $0 } END { exit !f }' ||
    fail "no --security-opt no-new-privileges"
  printf '%s\n' "$out" | grep -qx "LOCKCHECK_HOST_UID=$(id -u)" || fail "no host uid"
  # No docker on PATH: refuse.
  local rc=0 nobin
  nobin="$(mktemp -d "$SCRATCH/nobin.XXXXXX")"
  ln -s "$(command -v bash)" "$nobin/bash"
  ln -s "$(command -v dirname)" "$nobin/dirname"
  PATH="$nobin" "$nobin/bash" "$REPO/scripts/live-check-locked.sh" --print claude \
    >"$nobin.out" 2>&1 || rc=$?
  assert_eq "$rc" 2 "exit code without docker"
  grep -q 'docker' "$nobin.out" || fail "no docker message: $(cat "$nobin.out")"
}

test_dockerfile_has_no_context_use() {
  local df="$HERE/Dockerfile"
  [[ -f "$df" ]] || fail "no Dockerfile"
  if grep -qiE '^\s*(COPY|ADD)\b' "$df"; then fail "Dockerfile uses COPY/ADD"; fi
  grep -qE '^FROM ubuntu:24\.04$' "$df" || fail "base image"
  if grep -qiE '^\s*ENV\b.*(KEY|TOKEN|SECRET)' "$df"; then fail "ENV holds a key"; fi
  grep -qE '^\s*docker build .* - < "\$dockerfile"$' "$REPO/scripts/live-check-locked.sh" ||
    fail "wrapper build does not read the Dockerfile from stdin"
  grep -qE '^dockerfile="\$repo/scripts/lock-check/Dockerfile"$' "$REPO/scripts/live-check-locked.sh" ||
    fail "wrapper Dockerfile path"
}

# --- MCP test server ---------------------------------------------------------

test_mcp_marker_server() {
  if ! command -v node >/dev/null 2>&1; then
    echo "skip: node not installed"
    return 0
  fi
  local dir out
  dir="$(mktemp -d "$SCRATCH/mcp.XXXXXX")"
  mkdir "$dir/markers"
  out="$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"touch_marker","arguments":{"name":"0123456789ab"}}}' |
    LOCKCHECK_MARKERS="$dir/markers" node "$HERE/mcp-marker.js")"
  assert_eq "$(printf '%s\n' "$out" | wc -l)" 3 "response count"
  assert_eq "$(printf '%s\n' "$out" | jq -r .id | tr '\n' ' ')" "1 2 3 " "ids"
  assert_eq "$(printf '%s\n' "$out" | jq -r 'select(.id==1) | .result.protocolVersion')" 2025-06-18
  assert_eq "$(printf '%s\n' "$out" | jq -r 'select(.id==1) | .result.serverInfo.name')" lockcheck
  printf '%s\n' "$out" | jq -e 'select(.id==1) | .result.capabilities.tools' >/dev/null ||
    fail "no tools capability"
  assert_eq "$(printf '%s\n' "$out" | jq -r 'select(.id==2) | .result.tools[0].name')" touch_marker
  assert_eq "$(printf '%s\n' "$out" | jq -r 'select(.id==3) | .result.content[0].text')" ok
  [[ -e "$dir/markers/0123456789ab" ]] || fail "marker not created"
  out="$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"touch_marker","arguments":{"name":"../x"}}}' |
    LOCKCHECK_MARKERS="$dir/markers" node "$HERE/mcp-marker.js")"
  printf '%s\n' "$out" | jq -e '.id == 4 and (.error.code | type) == "number"' >/dev/null ||
    fail "bad name not refused: $out"
  [[ ! -e "$dir/x" ]] || fail "../x created"
  assert_eq "$(find "$dir/markers" -mindepth 1 -printf '%f\n')" 0123456789ab "markers"
}

# --- runner ------------------------------------------------------------------

main() {
  local names=("$@") name rc failed=0
  if ((${#names[@]} == 0)); then
    mapfile -t names < <(declare -F | awk '$3 ~ /^test_/ { sub(/^test_/, "", $3); print $3 }')
  fi
  for name in "${names[@]}"; do
    set +e
    (
      set -euo pipefail
      cd "$SCRATCH"
      "test_$name"
    ) >"$SCRATCH/$name.log" 2>&1
    rc=$?
    set -e
    if ((rc == 0)); then
      echo "ok $name"
    else
      echo "FAIL $name"
      sed 's/^/    /' "$SCRATCH/$name.log"
      failed=1
    fi
  done
  return "$failed"
}

main "$@"
