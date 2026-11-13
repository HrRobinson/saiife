# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 37 smoke: the repo disk (snapshot, mkfs, /work in the guest), the root
# overlay's growth, free page reporting and the slot count. Defines
# smoke_disks; no top-level effects.
#
# Re-run advice from the spike: run this on a QUIET host. The spike's
# anomalies A and B came from parallel builds on the host (agent builds, cargo,
# docker); with them running, the overlay sizes and the RSS numbers mean nothing.
#
# Variables:
#   REPO   the repo to put in the boxes (default: this checkout)
#   SAIIFE_SMOKE_BUSYBOX_DIGEST   when set (64 hex), the 200 MiB build is plan
#          36's Docker build (busybox@sha256:<digest> + a 200 MiB random RUN);
#          otherwise the build is a 200 MiB write of random data in the guest
#          (plan 36's fragment may not be on this branch; same effect on the
#          overlay: 200 MiB of fresh blocks).
#
# Result keys: repo_snapshot_ms repo_mkfs_ms repo_img_bytes repo_files
# repo_files_in_guest overlay_after_boot overlay_after_build
# rss_after_build_kib rss_after_drop_kib slots_total slots_queued_sixth
#
# Not tested here: filling the host disk (destructive); the free-space floor
# is unit-tested.
#
# Layout assumptions (read from the code, plan 35/37): box dirs are
# <state>/saiife/broker/boxes/<id>/ with repo.img (the ext4 repo disk, `/work`
# in the guest), base.json (the base manifest) and api.sock (the VMM's API
# socket, on its command line).

P37_BIG=$((200 << 20))
P37_BOX=""
P37_BOXES=()

p37_log() { printf '%s\n' "$*" >&2; }

# p37_result KEY VALUE: append KEY=VALUE to RESULTS (newlines become \n).
p37_result() {
  local v=${2-}
  v=${v//$'\n'/\\n}
  RESULTS+=("$1=$v")
}

p37_now_ms() { date +%s%3N; }

# p37_in_box BOX CMD...: run CMD in the box, print its output.
# TODO(plan 38/40): same single adaptation point as p36_in_box in
# 05-image.sh: `saiife box say` must return the command output once plan
# 38's channel exists. Until then the call fails and the checks record FAIL.
p37_in_box() {
  local box=$1
  shift
  timeout "${P37_SAY_T:-120}" saiife box say "$box" "$*"
}

p37_wait_ready() {
  local deadline=$(($(p37_now_ms) + 180000))
  while [ "$(p37_now_ms)" -lt "$deadline" ]; do
    if P37_SAY_T=10 p37_in_box "$1" true >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# p37_box_id OUT: the one id of the "box <id> <state>" line of `box spawn`.
p37_box_id() {
  local ids n
  ids=$(printf '%s\n' "$1" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p37_log "box spawn printed $n box ids, expected 1; not guessing"; return 1; }
  [[ "$ids" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  printf '%s\n' "$ids"
}

p37_box_dir() {
  printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/saiife/broker/boxes/$1"
}

# p37_timing ERRFILE STEP: milliseconds of `saiife: timing <step> <n> ms`.
p37_timing() {
  sed -n "s/^saiife: timing $2 \\([0-9][0-9]*\\) ms\$/\\1/p" "$1" | head -n1
}

# p37_end_all: stop and discard every box this fragment started.
p37_end_all() {
  local b
  for b in "${P37_BOXES[@]+"${P37_BOXES[@]}"}"; do
    saiife box stop "$b" >/dev/null 2>&1 || true
    saiife box discard "$b" --yes >/dev/null 2>&1 || true
  done
  P37_BOXES=()
  P37_BOX=""
}

# p37_disk_mib BOX: the entry's disk_mib from `box ls --json`.
p37_disk_mib() {
  saiife box ls --json | jq -er --arg id "$1" '.boxes[] | select(.id == $id) | .disk_mib'
}

# p37_vmm_rss_kib BOX: VmRSS of the VMM, found by the box's api.sock on its
# command line (read-only scan of /proc; exactly one match or failure).
p37_vmm_rss_kib() {
  local sock d pid hits=() rss
  sock="$(p37_box_dir "$1")/api.sock"
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    if tr '\0' ' ' <"$d/cmdline" 2>/dev/null | grep -qF -- "$sock"; then
      hits+=("$pid")
    fi
  done
  [ "${#hits[@]}" = 1 ] || { p37_log "expected 1 VMM for $sock, found ${#hits[@]}"; return 1; }
  rss=$(awk '/^VmRSS:/ {print $2}' "/proc/${hits[0]}/status") || return 1
  [[ "$rss" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$rss"
}

# p37_build_200: the 200 MiB build in the guest (see the header).
p37_build_200() {
  local box=$1 d=${SAIIFE_SMOKE_BUSYBOX_DIGEST:-}
  if [[ "$d" =~ ^[0-9a-f]{64}$ ]]; then
    P37_SAY_T=120 p37_in_box "$box" "mkdir -p /root/b && printf 'FROM busybox@sha256:$d\nRUN head -c $P37_BIG /dev/urandom > /big\nRUN echo built > /done\n' > /root/b/Dockerfile" || return 1
    P37_SAY_T=900 p37_in_box "$box" "cd /root/b && docker build -q -t p37-big ." >/dev/null || return 1
  else
    P37_SAY_T=300 p37_in_box "$box" "head -c $P37_BIG /dev/urandom > /root/p37-big" >/dev/null || return 1
  fi
  p37_in_box "$box" sync >/dev/null
}

p37_files_match() {
  [ -n "$P37_FILES" ] && [ -n "$P37_GUEST_FILES" ] && [ "$P37_FILES" = "$P37_GUEST_FILES" ]
}

p37_overlay_grew() {
  [ -n "$P37_OV_BOOT" ] && [ -n "$P37_OV_BUILD" ] && [ "$P37_OV_BUILD" -gt "$P37_OV_BOOT" ]
}

p37_rss_dropped() {
  [ -n "$P37_RSS_BUILD" ] && [ -n "$P37_RSS_DROP" ] && [ "$P37_RSS_DROP" -lt "$P37_RSS_BUILD" ]
}

# the sixth box queues on a 32 GiB host (slots_total = 5)
p37_slots() {
  local i out id total state
  total=$(saiife box ls --json | jq -er .slots_total) || return 1
  p37_result slots_total "$total"
  [ "$total" = 5 ] || { p37_log "slots_total is $total; the 32 GiB host check expects 5"; return 1; }
  for i in 1 2 3 4 5 6; do
    out=$(timeout 120 saiife box spawn --repo "$P37_REPO") || return 1
    id=$(p37_box_id "$out") || return 1
    P37_BOXES+=("$id")
  done
  state=$(saiife box ls --json | jq -er --arg id "${P37_BOXES[5]}" '.boxes[] | select(.id == $id) | .state') || return 1
  p37_result slots_queued_sixth "$state"
  [ "$state" = queued ] || return 1
  [ "$(saiife box ls --json | jq -er .slots_free)" = 0 ]
}

smoke_disks() {
  local out id err dir drop_s=20
  P37_REPO=$(cd "${REPO:-$SMOKE_DIR/../..}" && pwd) || { check "REPO is a directory" false; return 0; }
  P37_FILES="" P37_GUEST_FILES="" P37_OV_BOOT="" P37_OV_BUILD="" P37_RSS_BUILD="" P37_RSS_DROP=""
  P37_BOXES=()
  if ! saiife box ls --json >/dev/null 2>&1; then
    check "box daemon answers (needs plans 35/37)" false
    return 0
  fi
  p37_log "disks smoke on $P37_REPO: run on a quiet host (no agent builds, no cargo, no docker)"
  err="$SMOKE_WORK/disks-spawn.err"

  # 1. spawn with the hidden --timings; parse the step lines from stderr.
  # Steps (crates/cli/src/box_cmd.rs Clock::step): snapshot, image (the ext4
  # image made by mke2fs), snapshot commit, spawn, base ref, cleanup.
  if ! out=$(timeout 180 saiife box spawn --now --timings --repo "$P37_REPO" 2>"$err"); then
    cat "$err" >&2
    check "spawn with --timings" false
    return 0
  fi
  cat "$err" >&2
  check "spawn with --timings" true
  id=$(p37_box_id "$out") || { check "spawn printed one box id" false; return 0; }
  P37_BOX=$id
  P37_BOXES+=("$id")
  p37_result repo_snapshot_ms "$(p37_timing "$err" snapshot)"
  p37_result repo_mkfs_ms "$(p37_timing "$err" image)"
  dir=$(p37_box_dir "$id")
  # the image's apparent size, and the file count from the base manifest
  # (BaseManifest.files = entries, files and symlinks)
  p37_result repo_img_bytes "$(stat -c %s "$dir/repo.img" 2>/dev/null || true)"
  P37_FILES=$(jq -er .files "$dir/base.json" 2>/dev/null || true)
  p37_result repo_files "$P37_FILES"
  check "snapshot and mkfs step times were printed" \
    test -n "$(p37_timing "$err" snapshot)" -a -n "$(p37_timing "$err" image)"

  # 2. the box boots; /work holds the repo
  if ! p37_wait_ready "$id"; then
    p37_end_all
    check "box answers commands (needs plans 38/40)" false
    return 0
  fi
  # entries of the manifest are files and symlinks, never .git or directories
  P37_GUEST_FILES=$(p37_in_box "$id" "find /work -path /work/.git -prune -o \\( -type f -o -type l \\) -print | wc -l" | tr -d '[:space:]' || true)
  p37_result repo_files_in_guest "$P37_GUEST_FILES"
  check "file count under /work equals repo_files" p37_files_match

  # 3. overlay sizes (MiB, box ls --json disk_mib) and free page reporting
  P37_OV_BOOT=$(p37_disk_mib "$id" || true)
  p37_result overlay_after_boot "$P37_OV_BOOT"
  check "200 MiB build in the guest" p37_build_200 "$id"
  P37_OV_BUILD=$(p37_disk_mib "$id" || true)
  p37_result overlay_after_build "$P37_OV_BUILD"
  check "overlay grew with the build" p37_overlay_grew
  P37_RSS_BUILD=$(p37_vmm_rss_kib "$id" || true)
  p37_result rss_after_build_kib "$P37_RSS_BUILD"
  p37_in_box "$id" "sync && echo 3 > /proc/sys/vm/drop_caches" >/dev/null 2>&1 || true
  sleep "$drop_s"
  P37_RSS_DROP=$(p37_vmm_rss_kib "$id" || true)
  p37_result rss_after_drop_kib "$P37_RSS_DROP"
  check "VMM RSS fell 20 s after drop_caches (free page reporting)" p37_rss_dropped

  # 4. capacity: five run, the sixth queues. Start from a clean slate.
  p37_end_all
  check "sixth box queues (slots_total = 5)" p37_slots
  p37_end_all
  return 0
}
