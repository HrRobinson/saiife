# OWNER-RUN ONLY (sourced by scripts/box-smoke.sh; never run by agents).
# Plan 39 smoke: `saiife box diff`, `land`, `apply` and `push`. Defines
# smoke_land; no top-level effects. Run it with: scripts/box-smoke.sh --only land
#
# Needs (each missing one is a FAIL or a recorded skip with the step to do):
#   - a running box daemon and the `bash` smoke template (`saiife box templates`)
#   - a way to run commands in a box: p39_in_box is the single adaptation
#     point (`saiife box say`, as p36_in_box and p37_in_box)
#   - an enrolled key for the touch: a build with --features fido-hid, or plan
#     41's packaged helper. Without one `saiife box land` exits 5 with the
#     Workspace pointer: the landing checks record land_ok=skipped_no_key and
#     the rest (diff, protected_flagged, hostile_refused) still run.
#   - web_land_applied also needs a paired phone (`saiife workspace pair`).
#
# The land checks use a throwaway git repo under $SMOKE_WORK, never your
# repo. Landing only moves refs/heads/saiife/box-<id> there; nothing is
# checked out. The fake filter of git_config_needs_flag is configured in that
# repo's local config only. HOME and your global git config are not touched.
#
# Result keys (value ok, FAIL, or skipped_<why>): diff_ok land_ok
# land_hash_matches multi_land_ok partial_land_ok git_config_needs_flag
# protected_flagged hostile_refused push_ok web_land_applied
#
# Audit dirs read: as 30-guest (SAIIFE_AUDIT_DIR or the CLI's, the personal
# daemon's broker dir and, when locked, /var/log/saiife/audit).

P39_REPO=""
P39_BOX=""
P39_BOXES=()
P39_RC=0
P39_OUT=""
P39_NOKEY=0
P39_LOCKED_UNIT=/etc/systemd/system/saiife-box@.service
P39_LOCKED_AUDIT=/var/log/saiife/audit

p39_log() { printf '%s\n' "$*" >&2; }

# p39_result KEY VALUE: append KEY=VALUE to RESULTS (newlines become \n).
p39_result() {
  local v=${2-}
  v=${v//$'\n'/\\n}
  RESULTS+=("$1=$v")
}

p39_now_ms() { date +%s%3N; }

# p39_in_box BOX CMD...: run CMD in the box, print its output.
# TODO(plan 38/40): same single adaptation point as p36_in_box / p37_in_box.
p39_in_box() {
  local box=$1
  shift
  timeout "${P39_SAY_T:-120}" saiife box say "$box" "$*"
}

p39_wait_ready() {
  local deadline=$(($(p39_now_ms) + 180000))
  while [ "$(p39_now_ms)" -lt "$deadline" ]; do
    if P39_SAY_T=10 p39_in_box "$1" true >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

p39_box_id() {
  local ids n
  ids=$(printf '%s\n' "$1" | awk '$1 == "box" && $2 != "" {print $2}')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || { p39_log "box spawn printed $n box ids, expected 1; not guessing"; return 1; }
  [[ "$ids" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  printf '%s\n' "$ids"
}

p39_audit_dirs() {
  local data=${XDG_DATA_HOME:-$HOME/.local/share}
  case "${SAIIFE_AUDIT_DIR:-}" in
    /*) printf '%s\n' "$SAIIFE_AUDIT_DIR" ;;
    *) printf '%s\n' "$data/saiife/audit" ;;
  esac
  printf '%s\n' "$data/saiife/broker/audit"
  [ ! -e "$P39_LOCKED_UNIT" ] || printf '%s\n' "$P39_LOCKED_AUDIT"
}

# p39_audit JQ_FILTER [--arg k v ...]: every readable audit record as input,
# print jq's output for the filter (records are one JSON object per line).
p39_audit() {
  local filter=$1 dir f files=()
  shift
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    if [ -d "$dir" ] && [ ! -r "$dir" ]; then
      p39_log "audit dir $dir is not readable by you (locked: rerun as a user who can read it)"
      continue
    fi
    for f in "$dir"/*.jsonl; do
      [ -r "$f" ] && files+=("$f")
    done
  done < <(p39_audit_dirs)
  [ "${#files[@]}" -gt 0 ] || return 1
  jq -rn "$@" "$filter" "${files[@]}"
}

# p39_end_all: stop and discard every box this fragment started.
p39_end_all() {
  local b
  for b in "${P39_BOXES[@]+"${P39_BOXES[@]}"}"; do
    saiife box stop "$b" >/dev/null 2>&1 || true
    saiife box discard "$b" --yes --force >/dev/null 2>&1 || true
  done
  P39_BOXES=()
  P39_BOX=""
}

# p39_new_repo: a throwaway repo with the files the checks change. Local
# config only (the filter of git_config_needs_flag must never leak elsewhere).
p39_new_repo() {
  local d=$SMOKE_WORK/land-repo
  rm -rf "$d"
  mkdir -p "$d"
  (
    cd "$d"
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
    git init -q -b main .
    git config user.name smoke
    git config user.email smoke@example.invalid
    printf 'one\n' >a.txt
    printf 'two\n' >b.txt
    printf 'gone\n' >d.txt
    printf 'p1\n' >p1.txt
    printf 'p2\n' >p2.txt
    printf '# rules\n' >CLAUDE.md
    git add -A
    git commit -q -m base
  ) || return 1
  P39_REPO=$d
}

# p39_spawn: a new bash-template box on the repo; sets P39_BOX.
p39_spawn() {
  local out id
  out=$(timeout 180 saiife box spawn --template bash --now --repo "$P39_REPO") || return 1
  id=$(p39_box_id "$out") || return 1
  P39_BOXES+=("$id")
  P39_BOX=$id
  p39_wait_ready "$id"
}

# p39_run_land ARGS...: run `saiife box land`, keep rc and output. Exit 5
# with the Workspace pointer means no enrolled key.
p39_run_land() {
  P39_OUT=$(timeout 300 saiife box land "$@" 2>&1) && P39_RC=0 || P39_RC=$?
  printf '%s\n' "$P39_OUT" >&2
  if [ "$P39_RC" = 5 ] && printf '%s\n' "$P39_OUT" | grep -q 'saiife box apply'; then
    P39_NOKEY=1
  fi
  return 0
}

# p39_land_rc_ok: the last p39_run_land landed.
p39_land_rc_ok() { [ "$P39_RC" = 0 ]; }

# p39_commits BOX: commits on saiife/box-BOX beyond main in the smoke repo.
p39_commits() {
  git -C "$P39_REPO" rev-list --count "main..refs/heads/saiife/box-$1" 2>/dev/null
}

p39_tip_file() { # BOX PATH: the file at the branch tip
  git -C "$P39_REPO" show "refs/heads/saiife/box-$1:$2" 2>/dev/null
}

# the guest edits of the first diff: two edited, one added, one deleted, a
# symlink and a binary file
p39_first_edits() {
  p39_in_box "$1" "cd /work && printf 'one edited\n' > a.txt && printf 'two edited\n' > b.txt && printf 'new\n' > new.txt && rm d.txt && ln -s a.txt link-to-a && head -c 4096 /dev/urandom > blob.bin && sync" >/dev/null
}

p39_diff_shows() {
  local o=$1 p
  for p in a.txt b.txt new.txt d.txt link-to-a blob.bin; do
    printf '%s\n' "$o" | grep -qF -- "$p" || { p39_log "diff misses $p"; return 1; }
  done
  printf '%s\n' "$o" | grep -q 'blob.bin.*binary' || { p39_log "diff does not mark blob.bin binary"; return 1; }
}

p39_hash_matches() {
  local box=$1 trailer rec
  trailer=$(git -C "$P39_REPO" log -1 --format='%(trailers:key=Saiife-Diff-Sha256,valueonly)' "refs/heads/saiife/box-$box" | tr -d '[:space:]')
  rec=$(p39_audit 'last(inputs | select(.kind == "box" and .extra.action == "land" and .extra.box == $b) | .extra.diff_sha256) // empty' --arg b "$box") || return 1
  [[ "$trailer" =~ ^[0-9a-f]{64}$ ]] && [ "$trailer" = "$rec" ]
}

p39_audit_count() { # BOX ACTION
  p39_audit '[inputs | select(.kind == "box" and .extra.action == $a and .extra.box == $b)] | length' --arg a "$2" --arg b "$1"
}

# p39_skip KEY WHY: record a skipped key.
p39_skip() { p39_result "$1" "skipped_$2"; }

# p39_step KEY LABEL CMD...: run CMD once; record the check line and KEY
# (ok or FAIL).
p39_step() {
  local key=$1 label=$2 rc=0
  shift 2
  "$@" || rc=$?
  case "$rc" in
    0) p39_result "$key" ok ;;
    3) p39_result "$key" partial_no_key; label="$label (partial: no key)"; rc=0 ;;
    *) p39_result "$key" FAIL ;;
  esac
  check "$label" test "$rc" = 0
}

# ---- the checks

p39_check_diff() {
  local o
  o=$(saiife box diff "$P39_BOX" 2>&1) || return 1
  p39_diff_shows "$o"
}

p39_run_land_first() { p39_run_land "$P39_BOX"; }

p39_check_land_result() {
  p39_land_rc_ok || return 1
  printf '%s\n' "$P39_OUT" | grep -q 'touch your key.*code' || { p39_log "no short code asked for"; return 1; }
  [ "$(p39_commits "$P39_BOX")" = 1 ] || return 1
  [ "$(p39_tip_file "$P39_BOX" a.txt)" = "one edited" ]
}

p39_check_multi() {
  saiife box revise "$P39_BOX" "second round" >/dev/null || return 1
  p39_in_box "$P39_BOX" "cd /work && printf 'two edited again\n' > b.txt && sync" >/dev/null || return 1
  p39_run_land "$P39_BOX"
  p39_land_rc_ok || return 1
  [ "$(p39_commits "$P39_BOX")" = 2 ]
}

p39_check_partial() {
  p39_in_box "$P39_BOX" "cd /work && printf 'p1 edited\n' > p1.txt && printf 'p2 edited\n' > p2.txt && sync" >/dev/null || return 1
  p39_run_land "$P39_BOX" --files p1.txt
  p39_land_rc_ok || return 1
  [ "$(p39_tip_file "$P39_BOX" p1.txt)" = "p1 edited" ] || return 1
  [ "$(p39_tip_file "$P39_BOX" p2.txt)" = p2 ] || return 1
  local o
  o=$(saiife box diff "$P39_BOX" --stat 2>&1) || return 1
  printf '%s\n' "$o" | grep -qF p2.txt && ! printf '%s\n' "$o" | grep -qF p1.txt
}

p39_check_protected() {
  local o
  p39_in_box "$P39_BOX" "cd /work && printf '# rules\nbe nice\n' > CLAUDE.md && sync" >/dev/null || return 1
  o=$(saiife box diff "$P39_BOX" 2>&1) || return 1
  printf '%s\n' "$o" | grep -q '^! CLAUDE.md' || { p39_log "CLAUDE.md is not flagged in the review"; return 1; }
  # the land prints the same review (and the touch summary) before the
  # touch; with no key that half did not run: return 3 (partial)
  [ "$P39_NOKEY" = 1 ] && return 3
  p39_run_land "$P39_BOX" --files CLAUDE.md
  printf '%s\n' "$P39_OUT" | grep -q '^! CLAUDE.md' && p39_land_rc_ok
}

# a delta changing .gitattributes lands only with --allow-git-config, and a
# filter set in the user repo's local config never runs
p39_check_git_config() {
  local marker=$SMOKE_WORK/land-filter-ran
  rm -f "$marker"
  git -C "$P39_REPO" config filter.p39evil.clean "touch $marker; cat"
  git -C "$P39_REPO" config filter.p39evil.smudge "touch $marker; cat"
  p39_in_box "$P39_BOX" "cd /work && printf '* filter=p39evil\n' > .gitattributes && sync" >/dev/null || return 1
  p39_run_land "$P39_BOX" --files .gitattributes
  { [ "$P39_RC" != 0 ] && [ "$P39_RC" != 5 ]; } || { p39_log "land without the flag was not refused (rc $P39_RC)"; return 1; }
  git -C "$P39_REPO" cat-file -e "refs/heads/saiife/box-$P39_BOX:.gitattributes" 2>/dev/null && return 1
  p39_run_land "$P39_BOX" --files .gitattributes --allow-git-config
  p39_land_rc_ok || return 1
  git -C "$P39_REPO" cat-file -e "refs/heads/saiife/box-$P39_BOX:.gitattributes" || return 1
  # saiife runs no git porcelain that applies filters: the marker is absent
  [ ! -e "$marker" ]
}

# p39_hostile NAME CMD: a box whose work holds a hostile name; the review
# refuses (diff fails) and the audit has a diff_rejected record for it.
p39_hostile_one() {
  local label=$1 cmd=$2 before after
  p39_end_all
  p39_spawn || { p39_log "hostile ($label): spawn failed"; return 1; }
  before=$(p39_audit_count "$P39_BOX" diff_rejected 2>/dev/null || echo 0)
  p39_in_box "$P39_BOX" "$cmd" >/dev/null 2>&1 || true
  if saiife box diff "$P39_BOX" >/dev/null 2>&1; then
    p39_log "hostile ($label): the review did not refuse"
    return 1
  fi
  after=$(p39_audit_count "$P39_BOX" diff_rejected 2>/dev/null || echo 0)
  [ "$after" -gt "$before" ] || { p39_log "hostile ($label): no diff_rejected record"; return 1; }
}

# Names the guest really exports (it reads /work, never .git, and cannot
# name a path outside it: `../escape` and `.git/hooks/x` are unit-tested, not
# smoked) and the host refuses. One hostile file per box, so each must give
# its own diff_rejected record.
# Quoting, layer by layer: the four backslashes in this file's double quotes
# become two in the command text sent to the guest
# (`printf "e\\314\\201.txt"`); the guest shell's double quotes reduce them to
# one, and printf turns the octal escapes (portable, unlike \x) into the bytes
# 0x65 0xcc 0x81: "e" plus a combining acute accent, a non-NFC name.
p39_check_hostile() {
  local bad=0
  p39_hostile_one "trailing dot" "cd /work && printf x > 'notes.' && sync" || bad=1
  p39_hostile_one "non-NFC name" "cd /work && printf x > \"\$(printf \"e\\\\314\\\\201.txt\")\" && sync" || bad=1
  p39_hostile_one "8.3 name" "cd /work && printf x > 'CLAUDE~1.MD' && sync" || bad=1
  [ "$bad" = 0 ]
}

p39_check_push() {
  local bare=$SMOKE_WORK/land-remote.git out rc=0 a b
  rm -rf "$bare"
  git init -q --bare "$bare" || return 1
  out=$(timeout 300 saiife box push "$P39_BOX" --remote "$bare" 2>&1) || rc=$?
  printf '%s\n' "$out" >&2
  [ "$rc" = 0 ] || return 1
  a=$(git -C "$P39_REPO" rev-parse "refs/heads/saiife/box-$P39_BOX") || return 1
  b=$(git --git-dir="$bare" rev-parse "refs/heads/saiife/box-$P39_BOX") || return 1
  [ "$a" = "$b" ]
}

p39_have_pairing() {
  local o
  o=$(saiife workspace devices 2>/dev/null) || return 1
  [ -n "$o" ] && ! printf '%s\n' "$o" | grep -q 'no paired browsers'
}

p39_check_web_land() {
  local before
  before=$(p39_commits "$P39_BOX") || return 1
  p39_in_box "$P39_BOX" "cd /work && printf 'via web\n' > web.txt && sync" >/dev/null || return 1
  printf '%s\n' "Approve the land of box $P39_BOX in the Workspace (the phone), then press Enter." >&2
  [ -t 0 ] || { p39_log "no terminal to wait for the approval on"; return 1; }
  read -r _
  saiife box apply "$P39_BOX" || return 1
  [ "$(p39_commits "$P39_BOX")" = "$((before + 1))" ] && [ "$(p39_tip_file "$P39_BOX" web.txt)" = "via web" ]
}

smoke_land() {
  local did_land=0
  P39_BOXES=()
  P39_NOKEY=0
  if ! saiife box ls --json >/dev/null 2>&1; then
    check "box daemon answers (needs plans 35/39)" false
    return 0
  fi
  check "a throwaway repo for the land checks" p39_new_repo || return 0
  [ -n "$P39_REPO" ] || return 0
  check "box on the bash template, ready" p39_spawn || { p39_end_all; return 0; }
  check "guest edits (two edited, one added, one deleted, symlink, binary)" p39_first_edits "$P39_BOX" || { p39_end_all; return 0; }

  # 1. diff
  p39_step diff_ok "diff shows the edits, the binary line and the symlink" p39_check_diff

  # 2. land with a touch (short code), the hash trailer. Exit 5 with the
  # Workspace pointer is no enrolled key: skip what needs a land.
  p39_run_land_first
  if [ "$P39_NOKEY" = 1 ]; then
    p39_log "no enrolled key: the checks that need a land are skipped (build with --features fido-hid, or plan 41's helper; or land in the Workspace and run saiife box apply)"
    p39_skip land_ok no_key
    p39_skip land_hash_matches no_key
    p39_skip multi_land_ok no_key
    p39_skip partial_land_ok no_key
    p39_skip git_config_needs_flag no_key
    p39_skip push_ok no_key
  else
    did_land=1
    p39_step land_ok "land asked for the touch with a code and made one commit on saiife/box-<id>" p39_check_land_result
    p39_step land_hash_matches "Saiife-Diff-Sha256 trailer equals the audit land record" p39_hash_matches "$P39_BOX"
    p39_step multi_land_ok "revise, more edits, a second land: two commits" p39_check_multi
    p39_step partial_land_ok "--files lands one of two changes; the next diff shows the other" p39_check_partial
    p39_step git_config_needs_flag "git config changes need --allow-git-config; the filter never ran" p39_check_git_config
  fi

  # 3. protected path (the review flags CLAUDE.md; the land names it)
  p39_step protected_flagged "CLAUDE.md is flagged in the review and the touch summary" p39_check_protected

  # 4. push (after a touch; needs a land)
  if [ "$did_land" = 1 ]; then
    p39_step push_ok "push to a local bare repo after a touch" p39_check_push
  fi

  # 5. a phone-approved land, applied by the CLI
  if p39_have_pairing; then
    p39_step web_land_applied "Workspace-approved land written by saiife box apply" p39_check_web_land
  else
    p39_log "no paired phone (saiife workspace pair): web_land_applied skipped"
    p39_skip web_land_applied no_pairing
  fi

  # 6. hostile names refused by the host (own boxes, one per name)
  p39_step hostile_refused "hostile names refused with diff_rejected in the audit" p39_check_hostile
  p39_end_all
  return 0
}
