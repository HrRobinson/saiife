#!/usr/bin/env bash
# OWNER-RUN ONLY. Never run this from CI or from a build agent.
# It talks to a real FIDO2 key and asks you to touch it, type its PIN and pull it out.
# Run it at the logged-in seat (not over SSH), so the key's hidraw node is yours.
#
# Needs:
#   - a FIDO2 key with a PIN set, plugged in;
#   - optionally a second key (steps 6 and 7 are skipped without it);
#   - a running personal broker (`saiife daemon --user`) or a locked daemon, whose
#     config has a test service with a deploy mark on one operation:
#
#       [services.smoke]
#       connector = "http"
#       base_url = "https://example.invalid"
#       secret = "smoke-token"
#       auth = { kind = "bearer" }
#       allow = ["smoke:write"]
#       deploy = ["smoke:write"]
#
#       [[services.smoke.operation]]
#       id = "send"
#       capability = "smoke:write"
#       kind = "write"
#       method = "POST"
#       path = "/"
#       body = "json"
#
#     SAIIFE_SMOKE_SERVICE (default smoke) and SAIIFE_SMOKE_OP (default send) name
#     the service and operation; SAIIFE_SMOKE_ARGS holds the call's parameters,
#     as `k=v` words (default none).
#   - the binary: SAIIFE=${SAIIFE:-target/debug/saiife}, built with
#       cargo build -p saiife --features fido-hid
#     or an installed deb/rpm with its release binary (the FIDO helper at
#     /usr/libexec/saiife/saiife-fido does the key work).
#   - jq.
#
# Audit: the script reads the audit log's month files (*.jsonl) with jq, because
# `saiife audit` prints a table only. The directory is the personal broker's,
# $XDG_DATA_HOME/saiife/broker/audit. For a locked daemon set SAIIFE_SMOKE_LOCKED=1
# and SAIIFE_SMOKE_AUDIT_DIR (the daemon's audit dir, readable by you).
#
#   bash scripts/touch-smoke.sh
#
# Expect 11 "ok:" lines (9 without the second key; one more when the helper is installed) and exit 0. Step 8's optional
# --host removal needs root and is never run here; the script prints the line.
set -euo pipefail

SAIIFE=${SAIIFE:-target/debug/saiife}
# A relative path is made absolute; a bare name (saiife, on PATH) is kept.
case $SAIIFE in /*) ;; */*) SAIIFE=$PWD/$SAIIFE ;; esac
SERVICE=${SAIIFE_SMOKE_SERVICE:-smoke}
OP=${SAIIFE_SMOKE_OP:-send}
read -r -a CALL_ARGS <<<"${SAIIFE_SMOKE_ARGS:-}"
LOCKED=${SAIIFE_SMOKE_LOCKED:-0}
if [ "$LOCKED" = 1 ]; then
  AUDIT_DIR=${SAIIFE_SMOKE_AUDIT_DIR:?set SAIIFE_SMOKE_AUDIT_DIR for a locked daemon}
  VERIFY=(audit verify)
else
  AUDIT_DIR=${SAIIFE_SMOKE_AUDIT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/saiife/broker/audit}
  VERIFY=(audit verify --broker)
fi

WORK=$(mktemp -d)
# Audit checks look only at records written from here on (`ts` is UTC,
# `2026-11-11T09:30:00.000Z`, so the strings compare in time order).
START=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
OKS=0
FAILS=0
ENROLLED=0

ok() {
  echo "ok: $1"
  OKS=$((OKS + 1))
}
bad() {
  echo "bad: $1"
  FAILS=$((FAILS + 1))
}

# The ids of the enrolled devices whose label starts with smoke-.
SMOKE_IDS='.[] | select(.label | startswith("smoke-")) | .id'
smoke_ids() {
  "$SAIIFE" touch ls --json 2>/dev/null | jq -r "$SMOKE_IDS" || true
}

# Called by the EXIT trap below. Removes what the script enrolled (a touch may be
# needed), so no smoke device is left behind.
# shellcheck disable=SC2329
cleanup() {
  local id left=0
  if [ "$ENROLLED" = 1 ]; then
    for id in $(smoke_ids); do
      echo "cleanup: removing the smoke device ${id:0:8} (touch your key if it blinks)"
      "$SAIIFE" touch rm "$id" >/dev/null 2>&1 || left=1
    done
    if [ "$left" = 1 ]; then
      echo "cleanup: a smoke-* device is still enrolled; remove it with: $SAIIFE touch rm <id> (or sudo ... --host)"
    else
      echo "cleanup: no smoke-* device is left enrolled"
    fi
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# The id of a new pending request: a call of the marked operation exits 3 and
# prints "pending approval #<id>". Prints the id; returns 1 if it did not go pending.
new_pending() {
  local rc=0 out
  out=$("$SAIIFE" api "$SERVICE" "$OP" "${CALL_ARGS[@]+"${CALL_ARGS[@]}"}" 2>&1) || rc=$?
  [ "$rc" = 3 ] || return 1
  grep -oE '#[0-9]+' <<<"$out" | head -n 1 | tr -d '#'
}

# The audit records of the month files written since the run started, one
# JSON object per line.
audit_records() {
  cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | jq -c --arg start "$START" 'select(.ts >= $start)' || true
}

# 0. with the package's helper installed, doctor shows touch-helper PASS.
doc=$("$SAIIFE" doctor 2>&1 || true)
if [ -e /usr/libexec/saiife/saiife-fido ]; then
  if grep -iE 'touch[- ]helper' <<<"$doc" | grep -q 'PASS'; then
    ok "doctor: touch helper PASS"
  else
    bad "doctor: touch helper PASS (reinstall the saiife deb or rpm)"
  fi
fi

# 1. doctor knows the key check and it passes.
if grep -iE 'touch[- ]key' <<<"$doc" | grep -q 'PASS'; then
  ok "doctor: touch key PASS"
else
  bad "doctor: touch key PASS (plug the key in, at the seat)"
fi

# 2. enrol the first key.
echo "step 2: type the key's PIN and touch it, twice"
# Set first: cleanup looks for smoke-* devices even if enrol fails half way.
ENROLLED=1
if "$SAIIFE" touch enrol --label smoke-1; then
  ok "touch enrol smoke-1"
else
  bad "touch enrol smoke-1"
fi

# 3. it is listed.
if "$SAIIFE" touch ls --json | jq -e 'any(.[]; .label == "smoke-1")' >/dev/null; then
  ok "touch ls --json shows smoke-1"
else
  bad "touch ls --json shows smoke-1"
fi

# 4. a test touch.
echo "step 4: PIN, then touch"
if "$SAIIFE" touch test 2>&1 | tee "$WORK/test.out" && grep -q 'ok: "smoke-1" answered (user verified: yes' "$WORK/test.out"; then
  ok "touch test answered, user verified"
else
  bad "touch test answered, user verified"
fi

# 5. a marked call goes pending, approve asks for a touch, the record says how.
id=$(new_pending || true)
if [ -z "$id" ]; then
  bad "api $SERVICE $OP gives pending (exit 3); is the deploy mark in the config?"
else
  echo "step 5: request #$id is pending; PIN, then touch"
  rc=0
  "$SAIIFE" approve "$id" 2> >(tee "$WORK/approve.err" >&2) || rc=$?
  sleep 1
  if [ "$rc" = 0 ] && grep -qE 'touch needed \([a-z:_]+\); code [0-9]{6}; check that the same code shows wherever you started this' "$WORK/approve.err"; then
    ok "approve #$id: 6-digit code shown, approved after the touch"
  else
    bad "approve #$id: 6-digit code shown, approved after the touch (exit $rc)"
  fi
  if audit_records | jq -e -s --argjson id "$id" \
    'any(.[]; .kind == "approval" and .action == "approved" and .approval == $id and .touch.via == "local" and .touch.uv == true)' >/dev/null; then
    ok "audit: approved record with touch.via local and touch.uv true"
  else
    bad "audit: approved record with touch.via local and touch.uv true (in $AUDIT_DIR)"
  fi
  if "$SAIIFE" "${VERIFY[@]}" >/dev/null; then
    ok "audit verify exits 0"
  else
    bad "audit verify exits 0"
  fi
fi

# 6 and 7 need a second key, not enrolled.
read -r -p "Step 6: unplug the first key and plug in the second, NOT enrolled, alone. Enter to go, 's' to skip steps 6 and 7: " ans || ans=s
if [ "$ans" = s ]; then
  echo "skip: steps 6 and 7 (no second key)"
else
  # 6. an unenrolled key is refused.
  id=$(new_pending || true)
  if [ -z "$id" ]; then
    bad "step 6: no pending request"
  else
    rc=0
    "$SAIIFE" approve "$id" 2> >(tee "$WORK/mismatch.err" >&2) || rc=$?
    sleep 1
    if [ "$rc" = 2 ] && grep -qE 'touch_mismatch|not enrolled' "$WORK/mismatch.err"; then
      ok "unenrolled key refused: exit 2, touch_mismatch or not enrolled"
    else
      bad "unenrolled key refused: exit 2, touch_mismatch or not enrolled (exit $rc)"
    fi
  fi
  # 7. a key pulled mid-prompt: exit 5, never later than 125 s.
  id=$(new_pending || true)
  if [ -z "$id" ]; then
    bad "step 7: no pending request"
  else
    echo "step 7: PULL THE KEY OUT when asked to touch; do not touch it"
    rc=0
    timeout --foreground 125 "$SAIIFE" approve "$id" || rc=$?
    if [ "$rc" = 5 ]; then
      ok "pulled key: approve exits 5 within 125 s"
    else
      bad "pulled key: approve exits 5 within 125 s (exit $rc; 124 means it hung)"
    fi
  fi
  read -r -p "Plug the first key back in alone, then Enter: " _ || true
fi

# 8. remove smoke-1 with a touch.
rid=$(smoke_ids | head -n 1)
if [ -z "$rid" ]; then
  bad "touch rm: smoke-1 is not enrolled"
else
  echo "step 8: PIN, then touch, to remove smoke-1"
  # Not smoke_ids: a failed `touch ls` must not read as "none left".
  if "$SAIIFE" touch rm "$rid" && left=$("$SAIIFE" touch ls --json | jq -r "$SMOKE_IDS") && [ -z "$left" ]; then
    ok "touch rm removed smoke-1"
    ENROLLED=0
  else
    bad "touch rm removed smoke-1"
  fi
fi
echo "step 8 (optional, by hand, the only sudo): enrol a second device, then"
echo "  sudo $SAIIFE touch rm <id-prefix> --host    # recorded with approved_by = root"

# 9. both events are in the audit log.
if audit_records | jq -e -s \
  '(any(.[]; .kind == "touch" and .action == "touch_enrolled" and .label == "smoke-1" and .cred_kind == "fido2"))
   and (any(.[]; .kind == "touch" and .action == "touch_removed" and .label == "smoke-1"))' >/dev/null; then
  ok "audit shows touch_enrolled (cred_kind fido2) and touch_removed for smoke-1"
else
  bad "audit shows touch_enrolled (cred_kind fido2) and touch_removed for smoke-1 (in $AUDIT_DIR)"
fi

echo "$OKS ok, $FAILS bad"
[ "$FAILS" = 0 ]
