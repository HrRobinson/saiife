# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 35 smoke: the Cloud Hypervisor driver. The pinned VMM, the doctor's
# boxes section, a box's VMM up (its API socket answers vmm.ping) and down
# again, pause and resume, Landlock on, the cold boot time and the VMM's idle
# memory. Defines smoke_vmm; no top-level effects.
#
# Needs a saiife built with `--features boxes` (plan 35 R38: off by default
# and in every release until plan 41). The VMM's files are in the runtime
# dirs (personal <state>/box-run/<id>, locked /var/lib/saiife-box/boxes/<id>);
# the box records stay in the daemon's state dir (R37).
#
# Locked mode: the runtime dirs, the vault and the VMM's /proc files belong
# to saiife / saiife-box, so every read there goes through `sudo -n` (or run
# it as a member of the saiife-box group with sudo configured not to ask);
# a refused `sudo -n` is a FAIL naming the read, never a prompt. Personal
# mode reads everything as you.
#
# Run it in personal mode first, then again after
#   sudo saiife system install --boxes
# in locked mode (the fragment sees /etc/systemd/system/saiife-box@.service
# and adds the locked checks).
#
# Before plan 38 a box never reaches `running` (that needs the guest's Ready):
# it is discarded by the 90 s boot timeout with an error naming it, which is
# what this fragment checks then. The VMM process is never signalled: "gone"
# is /proc/<pid> missing, the pid read from the box's pid record (personal)
# or `systemctl show -p MainPID` (locked; read-only).
#
# RECORD=1 re-records the Cloud Hypervisor API fixtures (vm.info and
# vmm.ping with `curl --unix-socket`; a snapshot's file names and its
# config.json from the sealed vault copy <vault>/<id>.snap/) into
# crates/boxhost/tests/fixtures/ch-v54.0/ for the owner to review and commit.
#
# Results keys: boot_cold_ms_median, boot_cold_ms_all, rss_idle_kib.
#
# Owner checks this fragment prints but cannot decide (as-built item 8):
#   - CH v54 snapshot file names and VmConfig fields against check_config
#     (compare the RECORD=1 capture with crates/boxhost/src/snapshot.rs);
#   - Landlock with the pre-made snapshot dir (a `pause` + `stop --keep`
#     writes a snapshot under --landlock: ch.log must show no landlock error);
#   - the next boot restores from the vault copy under Landlock (and, locked,
#     through the unit's read-only bind of vault/<id>.snap);
#   - locked: the unit's box dir bind is writable under ProtectSystem=strict.

P35_UNIT=/etc/systemd/system/saiife-box@.service
P35_BOOT_LIMIT_S=90
P35_STOP_LIMIT_S=95
P35_BOX=""
P35_LOCKED=""
P35_FIXTURES=""

p35_log() { printf '%s\n' "$*" >&2; }

p35_result() { RESULTS+=("$1=${2-}"); }

p35_now_ms() { date +%s%3N; }

p35_median() {
  local n=$# sorted
  [ "$n" -gt 0 ] || { printf '\n'; return 0; }
  # shellcheck disable=SC2207
  sorted=($(printf '%s\n' "$@" | sort -n))
  if [ $((n % 2)) -eq 1 ]; then
    printf '%s\n' "${sorted[$((n / 2))]}"
  else
    printf '%s\n' "$(((sorted[n / 2 - 1] + sorted[n / 2]) / 2))"
  fi
}

# p35_as CMD...: run a read under /var/lib/saiife-box or of the VMM's /proc
# entry: `sudo -n` in locked mode (never prompts), as you in personal mode.
p35_as() {
  if [ -n "$P35_LOCKED" ]; then
    sudo -n "$@"
  else
    "$@"
  fi
}

# The box dirs of this mode (what crates/boxhost/src/layout.rs says).
p35_boxes_dir() {
  if [ -n "$P35_LOCKED" ]; then
    printf '%s\n' /var/lib/saiife-box/boxes
  else
    printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/saiife/broker/box-run"
  fi
}

p35_vault_dir() {
  if [ -n "$P35_LOCKED" ]; then
    printf '%s\n' /var/lib/saiife-box/vault
  else
    printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/saiife/broker/box-vault"
  fi
}

p35_box_dir() { printf '%s/%s\n' "$(p35_boxes_dir)" "$1"; }

# 1. every pinned file present and matching
p35_vmm_status() {
  local out
  out=$(saiife box vmm status) || return 1
  printf '%s\n' "$out" >&2
  printf '%s\n' "$out" | grep -q '^cloud-hypervisor v54.0 ok$' &&
    printf '%s\n' "$out" | grep -q '^CLOUDHV.fd ch-97eeb7b09 ok$'
}

# 2. the doctor's boxes section: at least one PASS, nothing else
p35_doctor_boxes() {
  local out
  out=$(saiife doctor 2>&1) || true
  printf '%s\n' "$out" | grep '  boxes\.' >&2 || true
  printf '%s\n' "$out" | grep -Eq '^PASS  boxes\.' &&
    ! printf '%s\n' "$out" | grep -Eq '^(FAIL|WARN|INFO)  boxes\.'
}

# p35_spawn: a box from the default image with an empty task; sets P35_BOX
# (exactly one id from "box <id> <state>", nothing guessed).
p35_spawn() {
  local out ids n
  P35_BOX=""
  out=$(timeout 60 saiife box spawn --now --task "" --repo "$SMOKE_WORK") || return 1
  ids=$(printf '%s\n' "$out" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p35_log "box spawn printed $n box ids, expected 1"; return 1; }
  [[ "$ids" =~ ^b[0-9]+$ ]] || return 1
  P35_BOX=$ids
}

# p35_ping BOX: the VMM's API answers vmm.ping (read-only, for information)
p35_ping() {
  local sock
  sock="$(p35_box_dir "$1")/api.sock"
  p35_as test -S "$sock" || return 1
  p35_as curl -fsS --max-time 2 --unix-socket "$sock" http://localhost/api/v1/vmm.ping >/dev/null 2>&1
}

# p35_wait_vmm BOX: api.sock answers within the boot limit; prints the ms
p35_wait_vmm() {
  local t0 deadline
  t0=$(p35_now_ms)
  deadline=$((t0 + P35_BOOT_LIMIT_S * 1000))
  while [ "$(p35_now_ms)" -lt "$deadline" ]; do
    if p35_ping "$1"; then
      printf '%s\n' "$(($(p35_now_ms) - t0))"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# p35_pid BOX: the VMM's pid, read only (never signalled)
p35_pid() {
  local pid=""
  if [ -n "$P35_LOCKED" ]; then
    pid=$(systemctl show -p MainPID --value "saiife-box@$1.service" 2>/dev/null || true)
  else
    local rec
    rec="$(p35_vault_dir)/$1.pid"
    [ -r "$rec" ] && pid=$(sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p' "$rec")
  fi
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$pid"
}

p35_state() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .state' 2>/dev/null
}

p35_error() {
  saiife box ls --json 2>/dev/null |
    jq -r --arg id "$1" '.boxes[]? | select(.id == $id) | .error // ""' 2>/dev/null
}

# Before plan 38 the box stays starting and the boot timeout discards it
# with an error naming the timeout; after plan 38 it reaches running.
p35_running_or_timed_out() {
  local deadline st
  deadline=$(($(p35_now_ms) + (P35_BOOT_LIMIT_S + 20) * 1000))
  while [ "$(p35_now_ms)" -lt "$deadline" ]; do
    st=$(p35_state "$1")
    case "$st" in
      running) return 0 ;;
      discarded)
        p35_error "$1" | grep -qi 'boot\|timed out\|timeout' && return 0
        p35_log "discarded without a boot timeout error: $(p35_error "$1")"
        return 1
        ;;
    esac
    sleep 1
  done
  return 1
}

# ch.log names no Landlock failure (needs a readable box dir)
p35_landlock_on() {
  local log
  log="$(p35_box_dir "$1")/ch.log"
  local text
  text=$(p35_as cat "$log") || { p35_log "cannot read $log"; return 1; }
  ! printf '%s\n' "$text" | grep -qi 'landlock' ||
    ! printf '%s\n' "$text" | grep -i 'landlock' | grep -qi 'error\|fail'
}

# p35_gone PID: /proc/PID disappears within the stop limit
p35_gone() {
  local deadline
  deadline=$(($(p35_now_ms) + P35_STOP_LIMIT_S * 1000))
  while [ "$(p35_now_ms)" -lt "$deadline" ]; do
    [ -e "/proc/$1" ] || return 0
    sleep 0.5
  done
  return 1
}

# the VMM's resident memory, idle, from smaps_rollup (KiB)
p35_rss() {
  p35_as cat "/proc/$1/smaps_rollup" 2>/dev/null | awk '/^Rss:/ {print $2; exit}'
}

p35_end_box() {
  [ -z "$P35_BOX" ] || {
    saiife box stop "$P35_BOX" >/dev/null 2>&1 || true
    saiife box discard "$P35_BOX" --yes >/dev/null 2>&1 || true
  }
  P35_BOX=""
}

# RECORD=1: the API's answers for the fixtures (owner reviews, commits)
p35_record() {
  local sock dir
  sock="$(p35_box_dir "$1")/api.sock"
  dir="$P35_FIXTURES"
  mkdir -p "$dir"
  p35_as curl -fsS --max-time 2 --unix-socket "$sock" http://localhost/api/v1/vmm.ping >"$dir/vmm.ping.json" &&
    p35_as curl -fsS --max-time 2 --unix-socket "$sock" http://localhost/api/v1/vm.info >"$dir/vm.info.json"
}

# The snapshot as the daemon sealed it: ChVmm copies the VMM's snapshot into
# <vault>/<id>.snap/ and empties the runtime snapshot/, so the capture reads
# the vault copy. An empty listing or a missing config.json is a FAIL.
p35_record_snapshot() {
  local snap names
  snap="$(p35_vault_dir)/$1.snap"
  names=$(p35_as ls -1 "$snap") || { p35_log "cannot list $snap"; return 1; }
  [ -n "$names" ] || { p35_log "$snap is empty"; return 1; }
  printf '%s\n' "$names" | grep -qx 'config.json' || { p35_log "no config.json in $snap"; return 1; }
  mkdir -p "$P35_FIXTURES"
  printf '%s\n' "$names" >"$P35_FIXTURES/snapshot-files.txt" &&
    p35_as cat "$snap/config.json" >"$P35_FIXTURES/snapshot-config.json" &&
    [ -s "$P35_FIXTURES/snapshot-config.json" ]
}

# p35_refused CMD...: CMD fails
p35_refused() { ! "$@" >/dev/null 2>&1; }

# locked: the unit runs as saiife-box
p35_unit_user() {
  [ "$(systemctl show -p User --value "saiife-box@$1.service" 2>/dev/null)" = saiife-box ]
}

smoke_vmm() {
  local ms pid rss i all=() t0 bt
  P35_FIXTURES="$(cd "$SMOKE_DIR/../.." && pwd)/crates/boxhost/tests/fixtures/ch-v54.0"
  P35_LOCKED=""
  [ -e "$P35_UNIT" ] && P35_LOCKED=1
  if [ -n "$P35_LOCKED" ]; then p35_log "locked mode ($P35_UNIT exists)"; fi
  command -v jq >/dev/null || { check "jq is installed (the fragment reads box ls --json)" false; return 0; }

  check "box vmm status: all pinned" p35_vmm_status
  check "doctor: boxes section ok" p35_doctor_boxes

  # one box: VMM up, pause/resume, Landlock, stop, VMM gone
  if ! check "box spawn --task \"\"" p35_spawn; then
    return 0
  fi
  if ms=$(p35_wait_vmm "$P35_BOX"); then
    check "VMM up within ${P35_BOOT_LIMIT_S} s (api.sock answers vmm.ping)" true
    p35_log "VMM API up after $ms ms"
  else
    check "VMM up within ${P35_BOOT_LIMIT_S} s (api.sock answers vmm.ping)" false
  fi
  pid=$(p35_pid "$P35_BOX") || pid=""
  check "VMM pid known (read, never signalled)" test -n "$pid"
  check "ch.log shows Landlock on (no landlock error)" p35_landlock_on "$P35_BOX"
  if [ -n "$P35_LOCKED" ]; then
    check "locked: the unit runs as saiife-box" p35_unit_user "$P35_BOX"
  fi
  if [ "${RECORD:-}" = 1 ]; then
    check "RECORD=1: API fixtures captured" p35_record "$P35_BOX"
  fi
  if [ -n "$pid" ]; then
    sleep 10
    rss=$(p35_rss "$pid")
    p35_result rss_idle_kib "$rss"
    check "VMM Rss read from smaps_rollup" test -n "$rss"
  fi
  # pause and resume need a running box, which needs plan 38's Ready
  if [ "$(p35_state "$P35_BOX")" = running ]; then
    check "box pause" saiife box pause "$P35_BOX"
    if [ "${RECORD:-}" = 1 ]; then
      # a kept stop writes the snapshot under --landlock (as-built item 8)
      check "box stop --keep (snapshot under Landlock)" saiife box stop --keep "$P35_BOX"
      check "RECORD=1: snapshot file names captured" p35_record_snapshot "$P35_BOX"
      check "ch.log: no Landlock error after the snapshot" p35_landlock_on "$P35_BOX"
    else
      check "box resume" saiife box resume "$P35_BOX"
      check "box stop" saiife box stop "$P35_BOX"
    fi
  else
    check "box pause and resume (needs plan 38: the box is not running yet)" false
    check "box stop" saiife box stop "$P35_BOX"
  fi
  if [ -n "$pid" ]; then
    check "VMM process gone within ${P35_STOP_LIMIT_S} s (/proc/$pid)" p35_gone "$pid"
  fi
  p35_end_box

  # readiness before plan 38: running, or discarded by the boot timeout
  if check "box spawn for the readiness check" p35_spawn; then
    check "box running, or discarded by the ${P35_BOOT_LIMIT_S} s boot timeout (before plan 38)" \
      p35_running_or_timed_out "$P35_BOX"
  fi
  p35_end_box

  # cold boot: spawn to VMM API up, 5 fresh boxes
  for i in 1 2 3 4 5; do
    t0=$(p35_now_ms)
    p35_spawn || break
    p35_wait_vmm "$P35_BOX" >/dev/null || { p35_end_box; break; }
    bt=$(($(p35_now_ms) - t0))
    all+=("$bt")
    p35_log "cold boot $i: $bt ms"
    p35_end_box
  done
  if [ "${#all[@]}" = 5 ]; then
    p35_result boot_cold_ms_median "$(p35_median "${all[@]}")"
    p35_result boot_cold_ms_all "$(IFS=,; printf '%s' "${all[*]}")"
    check "5 cold boots (spawn to VMM API up)" true
  else
    check "5 cold boots (spawn to VMM API up)" false
  fi

  if [ -n "$P35_LOCKED" ]; then
    # polkit lets only the daemon user start saiife-box@b<digits> units:
    # neither you nor the daemon user can start a unit of another shape
    check "locked: you cannot start saiife-box@x1.service (polkit refuses)" \
      p35_refused systemctl start --no-ask-password saiife-box@x1.service
    if [ "${SAIIFE_SMOKE_SUDO_DAEMON:-}" = 1 ]; then
      check "locked: the daemon user cannot start saiife-box@x1.service" \
        p35_refused sudo -n -u saiife systemctl start --no-ask-password saiife-box@x1.service
    else
      check "locked: the daemon user cannot start saiife-box@x1.service (owner step: rerun with SAIIFE_SMOKE_SUDO_DAEMON=1)" false
    fi
  fi
  p35_log "owner checks (by hand): snapshot names/VmConfig vs check_config, restore from the vault copy under Landlock, the unit's writable box dir bind"
  return 0
}
