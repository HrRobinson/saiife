# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 36 smoke: the base image build, its manifest, import, audit record, the
# cold-boot trim list, in-box settings, the Docker growth check and the direct
# kernel stretch. Defines smoke_image; no top-level effects.
#
# Owner prerequisites (each missing one is a FAIL with the step to do):
#   - assets/box/ubuntu-cloudimage-keyring.gpg exported (verify the Ubuntu key
#     fingerprint first)
#   - the Claude Code pin filled in assets/box/recipe.toml (no UNPINNED left)
#   - SAIIFE_SMOKE_BUSYBOX_DIGEST set to the busybox sha256 digest (64 hex) you
#     chose for the Docker growth check; this script never invents one
#
# Steps that need other plans record "FAIL: <label> (needs plan N)" until that
# plan lands: plan 36 Task 5 (image import), plans 37/38/40 (booting a box and
# running commands in it).
#
# Audit dir used for the image_import check: $SAIIFE_AUDIT_DIR when absolute,
# else <data base>/saiife/audit (what crates/audit/src/store.rs does), where the
# data base is $XDG_DATA_HOME or ~/.local/share.

# The pinned Ubuntu cloud-image signing key (UBUNTU_CLOUD_FPR in
# crates/boxhost/src/image/ubuntu.rs).
P36_UBUNTU_FPR="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
P36_MAX_ACTUAL=$((5 << 30))
P36_BIG=$((200 << 20))

P36_IMG_DIR=""
P36_MANIFEST=""
P36_RAW=""
P36_KIMG_DIR=""
P36_KMANIFEST=""
P36_KRAW=""
P36_BOX=""
P36_ONE_MS=""

p36_log() { printf '%s\n' "$*" >&2; }

# p36_result KEY VALUE: append KEY=VALUE to RESULTS (newlines become \n).
p36_result() {
  local v=${2-}
  v=${v//$'\n'/\\n}
  RESULTS+=("$1=$v")
}

p36_now_ms() { date +%s%3N; }

# p36_median N...: floor of the middle (mean of the two middle when even).
p36_median() {
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

# p36_need LABEL PLAN CMD...: if CMD fails, record "FAIL: LABEL (needs plan
# PLAN)" through check and return 1 so the caller skips the step.
p36_need() {
  local label=$1 plan=$2
  shift 2
  if "$@" >/dev/null 2>&1; then
    return 0
  fi
  check "$label (needs plan $plan)" false
  return 1
}

p36_audit_dir() {
  case "${SAIIFE_AUDIT_DIR:-}" in
    /*) printf '%s\n' "$SAIIFE_AUDIT_DIR" ;;
    *) printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/saiife/audit" ;;
  esac
}

# p36_in_box BOX CMD...: run CMD inside the box, print its output.
# TODO(plan 38/40): needs plan 38's channel or plan 40's `saiife box say`
# returning the command output; this is the single place to adapt once the
# interface exists. Until then the call fails and the step records its plan.
p36_in_box() {
  local box=$1
  shift
  timeout "${P36_SAY_T:-120}" saiife box say "$box" "$*"
}

# p36_spawn: start a box from the default image; sets P36_BOX. Needs plans
# 37/38 (booting a box on the imported image). `box spawn` prints one line
# "box <id> <state>" (crates/cli/src/box_cmd.rs print_box); exactly one id must
# come out of it, otherwise nothing is guessed and nothing is discarded.
p36_spawn() {
  local out ids n
  P36_BOX=""
  out=$(timeout 120 saiife box spawn --now --repo "$SMOKE_WORK") || return 1
  ids=$(printf '%s\n' "$out" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p36_log "box spawn printed $n box ids, expected 1; not guessing"; return 1; }
  [[ "$ids" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  P36_BOX=$ids
}

# p36_wait_ready BOX: poll until a command answers inside the box (180 s).
p36_wait_ready() {
  local deadline=$(($(p36_now_ms) + 180000))
  while [ "$(p36_now_ms)" -lt "$deadline" ]; do
    if P36_SAY_T=10 p36_in_box "$1" true >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# p36_end_box: stop and discard the current box through saiife; never by pid.
p36_end_box() {
  [ -z "$P36_BOX" ] || {
    saiife box stop "$P36_BOX" >/dev/null 2>&1 || true
    saiife box discard "$P36_BOX" --yes >/dev/null 2>&1 || true
  }
  P36_BOX=""
}

# p36_boot_once: fresh box to ready; P36_ONE_MS is spawn -> first answer, the
# box stays up in P36_BOX. Needs plans 37/38/40.
p36_boot_once() {
  local t0
  P36_ONE_MS=""
  t0=$(p36_now_ms)
  p36_spawn || return 1
  p36_wait_ready "$P36_BOX" || return 1
  P36_ONE_MS=$(($(p36_now_ms) - t0))
}

# p36_series N: N cold boots (fresh box each); sets P36_SERIES_MEDIAN and
# P36_SERIES_ALL. Returns 1 if any boot failed.
p36_series() {
  local i ms=()
  for i in $(seq 1 "$1"); do
    if ! p36_boot_once; then
      p36_end_box
      return 1
    fi
    ms+=("$P36_ONE_MS")
    p36_end_box
  done
  P36_SERIES_MEDIAN=$(p36_median "${ms[@]}")
  P36_SERIES_ALL=$(IFS=,; printf '%s' "${ms[*]}")
}

# the firmware boots only run when this import (as default) succeeded
p36_import_fw() {
  saiife box image import --default "$P36_RAW" && P36_FW_OK=1
}

p36_manifest_get() { jq -er "$2" "$1"; }

p36_build() { # DIR [extra build args...]
  local dir=$1 t0 out
  shift
  P36_LAST_RAW=""
  t0=$(date +%s)
  out=$(saiife box image build --recipe "$P36_RECIPE" --out "$dir" "$@") || return 1
  printf '%s\n' "$out" >&2
  P36_LAST_BUILD_S=$(($(date +%s) - t0))
  # the output is "image <id>", the raw and manifest paths, and a next: hint
  local raw
  raw=$(printf '%s\n' "$out" | sed -n 's/^next: saiife box image import //p' | head -n1)
  [ -n "$raw" ] && [ -f "$raw" ] && [ -f "${raw%.raw}.json" ] || return 1
  P36_LAST_RAW=$raw
}

p36_owner_pins_ok() {
  local ok=0
  if [ ! -s "$P36_ROOT/assets/box/ubuntu-cloudimage-keyring.gpg" ]; then
    p36_log "owner step: verify UBUNTU_CLOUD_FPR against Ubuntu's published key and export the keyring to assets/box/ubuntu-cloudimage-keyring.gpg"
    ok=1
  fi
  if grep -q UNPINNED "$P36_RECIPE"; then
    p36_log "owner step: fill the Claude Code pin (version, url, sha256) in assets/box/recipe.toml"
    ok=1
  fi
  return "$ok"
}

p36_check_signer() {
  [ "$(p36_manifest_get "$P36_MANIFEST" .ubuntu.sums_signer)" = "$P36_UBUNTU_FPR" ]
}

p36_check_size() {
  local b
  b=$(p36_manifest_get "$P36_MANIFEST" .actual_bytes) || return 1
  p36_result image_actual_bytes "$b"
  [ "$b" -le "$P36_MAX_ACTUAL" ]
}

p36_check_audit() {
  local dir sha
  dir=$(p36_audit_dir)
  sha=$(p36_manifest_get "$P36_MANIFEST" .sha256) || return 1
  compgen -G "$dir/*.jsonl" >/dev/null || return 1
  jq -en --arg s "$sha" \
    '[inputs | select(.kind == "box" and .extra.action == "image_import" and .extra.sha256 == $s)] | length > 0' \
    "$dir"/*.jsonl >/dev/null
}

# the first cold boot: capture the trim list (systemd-analyze, blame)
p36_cold_capture() {
  local a b
  p36_boot_once || { p36_end_box; return 1; }
  p36_result boot_first_ms "$P36_ONE_MS"
  # systemd-analyze needs the boot finished; wait (bounded) for it first
  P36_SAY_T=180 p36_in_box "$P36_BOX" 'systemctl is-system-running --wait' >/dev/null 2>&1 || true
  a=$(p36_in_box "$P36_BOX" systemd-analyze) || { p36_end_box; return 1; }
  b=$(p36_in_box "$P36_BOX" 'systemd-analyze blame | head -15') || { p36_end_box; return 1; }
  p36_result systemd_analyze_cold "$a"
  p36_result systemd_blame_cold "$b"
  # in-box settings, on the same cold boot
  P36_CONTAINERD=$(p36_in_box "$P36_BOX" systemctl is-enabled containerd.service || true)
  P36_JOURNAL=$(p36_in_box "$P36_BOX" journalctl --header || true)
  P36_TARGET=$(p36_in_box "$P36_BOX" systemctl get-default || true)
  # the Docker growth check also runs here, inside the same box
}

p36_in_box_containerd() { [ "$(printf '%s' "$P36_CONTAINERD" | tr -d '[:space:]')" = disabled ]; }
# volatile storage: the journal header names the volatile file under /run
p36_in_box_journal() { printf '%s\n' "$P36_JOURNAL" | grep -qi 'volatile\|/run/log/journal'; }
p36_in_box_target() { [ "$(printf '%s' "$P36_TARGET" | tr -d '[:space:]')" = multi-user.target ]; }

# p36_overlay_file BOX: the box's root overlay on the host. Personal layout
# (plan 35 layout.rs/paths.rs): <state_dir>/boxes/<id>/root.qcow2 with
# state_dir = $XDG_STATE_HOME or ~/.local/state, then saiife/broker.
p36_overlay_file() {
  printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/saiife/broker/boxes/$1/root.qcow2"
}

# p36_alloc FILE: allocated bytes (st_blocks * 512, as the spike's
# disk_actual_bytes). Fails on a missing file or a non-numeric result.
p36_alloc() {
  local out
  out=$(stat -c '%b %B' "$1" 2>/dev/null) || return 1
  [[ "$out" =~ ^([0-9]+)\ ([0-9]+)$ ]] || return 1
  printf '%s\n' $((BASH_REMATCH[1] * BASH_REMATCH[2]))
}

# Docker growth: busybox@sha256:<pin> plus a 200 MiB random RUN, as the spike's.
# Growth is the host overlay file's allocated bytes before and after the build
# (what the spike measured: 2.03 with the containerd image store); limit 1.3.
p36_docker_growth() {
  local digest=$SAIIFE_SMOKE_BUSYBOX_DIGEST ov before after ratio
  ov=$(p36_overlay_file "$P36_BOX")
  before=$(p36_alloc "$ov") || { p36_log "cannot stat the overlay at $ov"; return 1; }
  P36_SAY_T=120 p36_in_box "$P36_BOX" "mkdir -p /root/b && printf 'FROM busybox@sha256:$digest\nRUN head -c $P36_BIG /dev/urandom > /big\nRUN echo built > /done\n' > /root/b/Dockerfile" || return 1
  P36_SAY_T=900 p36_in_box "$P36_BOX" "cd /root/b && docker build -q -t p36-big ." >/dev/null || return 1
  p36_in_box "$P36_BOX" sync >/dev/null || return 1
  after=$(p36_alloc "$ov") || { p36_log "cannot stat the overlay at $ov"; return 1; }
  ratio=$(awk -v a="$after" -v b="$before" -v big="$P36_BIG" 'BEGIN {printf "%.2f", (a - b) / big}')
  p36_result overlay_growth_ratio "$ratio"
  # below 1.0 cannot be: the 200 MiB of random data is written at least once
  awk -v r="$ratio" 'BEGIN {exit !(r >= 1.0 && r <= 1.3)}'
}

p36_busybox_digest_ok() {
  case "${SAIIFE_SMOKE_BUSYBOX_DIGEST:-}" in
    "") p36_log "owner step: export SAIIFE_SMOKE_BUSYBOX_DIGEST=<64 hex sha256 of the busybox image you pin>"; return 1 ;;
  esac
  [[ "$SAIIFE_SMOKE_BUSYBOX_DIGEST" =~ ^[0-9a-f]{64}$ ]]
}

smoke_image() {
  P36_ROOT="$(cd "$SMOKE_DIR/../.." && pwd)"
  P36_RECIPE="$P36_ROOT/assets/box/recipe.toml"
  P36_IMG_DIR="$SMOKE_WORK/image"
  P36_KIMG_DIR="$SMOKE_WORK/image-kernel"
  P36_CONTAINERD="" P36_JOURNAL="" P36_TARGET=""
  P36_FW_OK="" P36_SERIES_MEDIAN="" P36_SERIES_ALL="" P36_LAST_BUILD_S="" P36_LAST_RAW=""
  mkdir -p "$P36_IMG_DIR" "$P36_KIMG_DIR"

  # 1. build with the owner-pinned recipe (needs the owner's keyring and pin)
  if ! p36_owner_pins_ok; then
    check "image build (owner pins missing: keyring export and Claude pin)" false
    return 0
  fi
  check "image build with the pinned recipe" p36_build "$P36_IMG_DIR"
  if [ -z "$P36_LAST_RAW" ]; then
    return 0
  fi
  P36_RAW=$P36_LAST_RAW
  P36_MANIFEST=${P36_RAW%.raw}.json
  p36_result image_build_s "$P36_LAST_BUILD_S"

  # 2. manifest: signer and size
  check "manifest ubuntu.sums_signer is UBUNTU_CLOUD_FPR" p36_check_signer
  check "image actual size <= 5 GiB" p36_check_size

  # 3. import as the default (plan 36 Task 5)
  P36_FW_OK=""
  if p36_need "image import --default" 36 saiife box image import --help; then
    check "image import --default" p36_import_fw
    # 4. the audit record (plan 27: `saiife audit` has no JSON output, so jq)
    check "audit has image_import with the image sha256" p36_check_audit
  else
    check "audit image_import record (needs plan 36 task 5)" false
  fi

  # 5. cold boot: trim list and in-box settings (plans 37/38/40)
  if [ -z "$P36_FW_OK" ]; then
    check "firmware boots skipped: image import --default failed" false
  elif p36_need "cold boot and in-box checks" "37/38/40" saiife box say --help; then
    if p36_cold_capture; then
      check "containerd.service is disabled" p36_in_box_containerd
      check "journal storage is volatile" p36_in_box_journal
      check "default target is multi-user.target" p36_in_box_target
      # 6. Docker growth check (same box)
      if p36_busybox_digest_ok; then
        check "docker build grows the overlay <= 1.3 x 200 MiB" p36_docker_growth
      else
        check "docker growth (set SAIIFE_SMOKE_BUSYBOX_DIGEST to a 64 hex digest)" false
      fi
      p36_end_box
    else
      p36_end_box
      check "cold boot reaches ready and answers commands (plans 37/38/40)" false
    fi

    # 7. firmware series for the comparison (5 cold boots)
    if p36_series 5; then
      p36_result boot_cold_ms_median "$P36_SERIES_MEDIAN"
      p36_result boot_cold_ms_all "$P36_SERIES_ALL"
      check "5 firmware cold boots" true
    else
      check "5 firmware cold boots (plans 37/38/40)" false
    fi

    # 8. direct kernel stretch: the owner decides, this only reports. Boots
    # are only recorded when the kernel image is the imported default.
    check "image build --direct-kernel" p36_build "$P36_KIMG_DIR" --direct-kernel
    if [ -n "$P36_LAST_RAW" ]; then
      P36_KRAW=$P36_LAST_RAW
      p36_result image_build_kernel_s "$P36_LAST_BUILD_S"
      if p36_need "import direct-kernel image" 36 saiife box image import --help; then
        if saiife box image import --default "$P36_KRAW" >/dev/null 2>&1; then
          check "import direct-kernel image as default" true
          if p36_series 5; then
            p36_result boot_kernel_ms_median "$P36_SERIES_MEDIAN"
            p36_result boot_kernel_ms_all "$P36_SERIES_ALL"
            check "5 direct-kernel cold boots" true
          else
            check "5 direct-kernel cold boots reach ready" false
          fi
          # put the firmware image back as the default
          check "restore the firmware image as default" saiife box image import --default "$P36_RAW"
        else
          check "import direct-kernel image as default (kernel boots skipped)" false
        fi
      fi
    fi
  fi
  p36_end_box
  return 0
}
