#!/usr/bin/env bash
# OWNER-RUN ONLY. Never run this from CI or from a build agent.
# It needs a phone (Face ID or a fingerprint) or a security key with a PIN, and it
# asks you to touch it. The Workspace page in the browser asks for the touch.
#
# Steps 2 to 4 use the browser touch prompt (touch.js): the page shows the
# 6-digit code first, then the passkey dialog (Face ID, fingerprint or PIN;
# it times out after 120 s and then says "Not approved").
#
# Needs:
#   - a running daemon: the personal broker (`saiife daemon --user`) or a locked
#     daemon. For the "fake land" it must run with the demo boxes:
#       SAIIFE_WORKSPACE_FAKE_BOXES=1 saiife daemon --user      (a --features fake-boxes build)
#   - `saiife workspace serve` in another terminal (127.0.0.1, port 47810, or
#     SAIIFE_SMOKE_PORT);
#   - the browser: on this machine, `http://localhost:<port>` (the default origin).
#     `serve` listens on 127.0.0.1 only. A phone needs an https origin: put your own
#     https proxy in front (for example `tailscale serve`), add that origin to
#     `[workspace] origins` in the system config, and build the pairing link by
#     hand with that host (`pair --local` prints a localhost link).
#   - the binary: SAIIFE=${SAIIFE:-target/debug/saiife}; jq.
#
# Audit: the script reads the month files (*.jsonl) with jq, as touch-smoke.sh does.
# The directory is the personal broker's, $XDG_DATA_HOME/saiife/broker/audit. For a
# locked daemon set SAIIFE_SMOKE_LOCKED=1 and SAIIFE_SMOKE_AUDIT_DIR.
#
#   bash scripts/workspace-smoke.sh
#
# Expect 9 "ok:" lines and exit 0. The browser steps are done by you, by hand;
# the script waits for Enter and then checks the audit log.
set -euo pipefail

SAIIFE=${SAIIFE:-target/debug/saiife}
case $SAIIFE in /*) ;; */*) SAIIFE=$PWD/$SAIIFE ;; esac
PORT=${SAIIFE_SMOKE_PORT:-47810}
LOCKED=${SAIIFE_SMOKE_LOCKED:-0}
if [ "$LOCKED" = 1 ]; then
  AUDIT_DIR=${SAIIFE_SMOKE_AUDIT_DIR:?set SAIIFE_SMOKE_AUDIT_DIR for a locked daemon}
  VERIFY=(audit verify)
else
  AUDIT_DIR=${SAIIFE_SMOKE_AUDIT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/saiife/broker/audit}
  VERIFY=(audit verify --broker)
fi

# Audit checks look only at records written from here on (`ts` is UTC).
START=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
OKS=0
FAILS=0
DEVICE=

ok() {
  echo "ok: $1"
  OKS=$((OKS + 1))
}
bad() {
  echo "bad: $1"
  FAILS=$((FAILS + 1))
}

audit_records() {
  cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | jq -c --arg start "$START" 'select(.ts >= $start)' || true
}

# Called by the EXIT trap. Revokes the smoke device if the script left it paired.
# shellcheck disable=SC2329
cleanup() {
  if [ -n "$DEVICE" ] && "$SAIIFE" workspace devices 2>/dev/null | grep -qF "$DEVICE"; then
    echo "cleanup: revoking $DEVICE"
    "$SAIIFE" workspace revoke "$DEVICE" >/dev/null 2>&1 ||
      echo "cleanup: still paired; run: $SAIIFE workspace revoke $DEVICE"
  fi
}
trap cleanup EXIT

wait_enter() {
  read -r -p "$1 Enter to go on: " _ || true
}

# 1. pair, with the passkey made at pairing.
echo "step 1: pairing. Open the link below in the browser (the phone, or this machine)."
echo "  Use the label 'smoke-ws' when the page asks for a name. The page asks for the"
echo "  passkey first (Face ID, a fingerprint or the key's PIN). Check that the code on"
echo "  the page matches the terminal, then accept here; the machine stores the passkey"
echo "  only when you accept."
"$SAIIFE" workspace pair --local --port "$PORT" --label smoke-ws || true
DEVICE=$("$SAIIFE" workspace devices 2>/dev/null | grep -oE 'd-[A-Za-z0-9_-]+' | tail -n 1 || true)
if [ -n "$DEVICE" ]; then
  ok "paired device $DEVICE"
else
  bad "no paired device in 'saiife workspace devices'"
fi
if audit_records | jq -e -s 'any(.[]; .kind == "workspace" and (.action | test("pair")) and .decision == "allow")' >/dev/null; then
  ok "audit: the pairing is recorded"
else
  bad "audit: the pairing is recorded (in $AUDIT_DIR)"
fi

# 2. approve the fake land with a touch.
wait_enter "step 2: in the page, open the finished demo box, press Approve with touch, check the 6-digit code, and touch."
if audit_records | jq -e -s 'any(.[]; .kind == "workspace" and .action == "box.land" and .decision == "allow" and .touch.via == "web" and .touch.uv == true and (.touch.preimage | length > 0))' >/dev/null; then
  ok "audit: box.land carries a touch object (via web, uv true)"
else
  bad "audit: box.land carries a touch object (via web, uv true) (in $AUDIT_DIR)"
fi
if "$SAIIFE" "${VERIFY[@]}" >/dev/null; then
  ok "audit verify exits 0"
else
  bad "audit verify exits 0"
fi

# 3. the same land again is refused. The page cannot resend an assertion
# (a replayed one is refused by the daemon: workspace_link
# assertion_reuse_is_refused); here the land is simply gone.
wait_enter "step 3: in the page, press Approve with touch on the same box again. It must not land again: the page shows the machine command."
if audit_records | jq -e -s '[.[] | select(.kind == "workspace" and .action == "box.land" and .decision == "deny")] | length > 0' >/dev/null; then
  ok "audit: the replayed land is refused"
else
  bad "audit: the replayed land is refused (in $AUDIT_DIR)"
fi

# 4. one touch, two steers inside 10 minutes.
wait_enter "step 4: on a running demo box, send a steer message and touch once. Within 10 minutes, send a second message. The second must ask for no touch."
if audit_records | jq -e -s '
   ([.[] | select(.kind == "workspace" and .action == "box.steer" and .decision == "allow")]) as $s
   | (any($s[]; .touch != null)) and (any($s[]; .window == true))' >/dev/null; then
  ok "audit: one steer with a touch, one covered by the window"
else
  bad "audit: one steer with a touch, one covered by the window (in $AUDIT_DIR)"
fi

# 5. revoke the browser; the next frame is refused.
echo "step 5: revoking the browser on the machine"
if [ -n "$DEVICE" ] && "$SAIIFE" workspace revoke "$DEVICE"; then
  ok "revoked $DEVICE"
  wait_enter "In the page, wait for the next refresh. It must show 'This browser is no longer paired.' (a frame from a revoked device is refused and not audited)."
  if audit_records | jq -e -s --arg d "$DEVICE" 'any(.[]; .kind == "workspace" and .action == "revoked" and .device == $d)' >/dev/null; then
    ok "audit: the revoke is recorded"
  else
    bad "audit: the revoke is recorded (in $AUDIT_DIR)"
  fi
  # touch_removed is written only when the device held a passkey.
  if audit_records | jq -e -s --arg d "$DEVICE" 'any(.[]; .kind == "workspace" and .action == "touch_removed" and .device == $d)' >/dev/null; then
    ok "audit: the passkey was removed with the revoke (touch_removed)"
  else
    bad "audit: the passkey was removed with the revoke (touch_removed) (in $AUDIT_DIR)"
  fi
else
  bad "revoke $DEVICE"
fi

echo "$OKS ok, $FAILS bad"
[ "$FAILS" = 0 ]
