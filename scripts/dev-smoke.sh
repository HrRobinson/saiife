#!/usr/bin/env bash
# OWNER-RUN ONLY. Never run this from CI or from a build agent.
# It uses the real Docker, pulls images (traefik, traefik/whoami, busybox),
# and binds ports 80 and 443 on 127.0.0.1. Linux, Docker Compose 2.0.0 or later.
#
#   cargo build -p saiife && bash scripts/dev-smoke.sh
#
# Expect 8 "ok:" lines and exit 0. Override the binary with SAIIFE=...
set -euo pipefail

SAIIFE=${SAIIFE:-target/debug/saiife}
case $SAIIFE in /*) ;; *) SAIIFE=$PWD/$SAIIFE ;; esac

WORK=$(mktemp -d)
export XDG_STATE_HOME=$WORK/state
export XDG_CONFIG_HOME=$WORK/config
REPO=$WORK/smokeapp
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME" "$REPO"
P=smokeapp
CA=$XDG_STATE_HOME/saiife/dev/ca/ca.pem
FAILS=0

# Called by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
  "$SAIIFE" dev down "$P" --volumes --yes >/dev/null 2>&1 || true
  docker rm -f smoke-canary >/dev/null 2>&1 || true
  docker network rm smoke-canary-net >/dev/null 2>&1 || true
  docker volume rm smoke-canary-vol >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ok() { echo "ok: $1"; }
fail() {
  echo "FAIL: $1"
  FAILS=$((FAILS + 1))
}

cat >"$REPO/compose.yaml" <<'YAML'
services:
  web:
    image: traefik/whoami:v1.10.1
    ports: ["8080:80"]
    volumes:
      - data:/data
  worker:
    image: busybox:1.36
    command: ["sleep", "3600"]
volumes:
  data: {}
YAML

# Unlabelled canaries: nothing saiife does may remove them.
docker network create smoke-canary-net >/dev/null
docker volume create smoke-canary-vol >/dev/null
docker create --name smoke-canary busybox:1.36 >/dev/null

listing() { (cd "$REPO" && find . -printf '%p %s %T@\n' | sort); }
before=$(listing)

# 1. up prints the URL.
up_out=$(cd "$REPO" && "$SAIIFE" dev up 2>&1) || true
echo "$up_out"
if grep -q "https://web.$P.localhost" <<<"$up_out"; then
  ok "up prints https://web.$P.localhost"
else
  fail "up prints https://web.$P.localhost"
fi

# 2. HTTPS works with the CA, and whoami answers.
sleep 3
if curl -fsS --cacert "$CA" "https://web.$P.localhost/" | grep -q '^Hostname:'; then
  ok "https answers with the CA (whoami Hostname:)"
else
  fail "https answers with the CA (whoami Hostname:)"
fi

# 3. The host port was stripped.
if curl -fsS --max-time 3 http://127.0.0.1:8080 >/dev/null 2>&1; then
  fail "host port 8080 is closed"
else
  ok "host port 8080 is closed"
fi

# 4. The repo is unchanged.
after=$(listing)
if [ "$before" = "$after" ]; then ok "the repo is unchanged"; else fail "the repo is unchanged"; fi

# The state of project $P from `ls --json` (whitespace removed first).
state_of() {
  "$SAIIFE" dev ls --json | tr -d ' \n' |
    grep -o "\"name\":\"$P\"[^}]*\"state\":\"[a-z]*\"" |
    grep -o '"state":"[a-z]*"' | head -n1 || true
}

# 5. ls --json says running.
if [ "$(state_of)" = '"state":"running"' ]; then
  ok "ls --json: $P is running"
else
  fail "ls --json: $P is running"
fi

# 6. down keeps the project (stopped) and its volume.
"$SAIIFE" dev down "$P" >/dev/null 2>&1 || true
vol_count=$(docker volume ls -q --filter label=saiife.managed=true --filter "label=saiife.dev.project=$P" | wc -l)
if [ "$(state_of)" = '"state":"stopped"' ] && [ "$vol_count" -ge 1 ]; then
  ok "down: $P is stopped and its volume remains"
else
  fail "down: $P is stopped and its volume remains"
fi

# 7. gc --volumes --yes leaves only the shared network, and the canaries.
gc_out=$("$SAIIFE" dev gc --volumes --yes 2>&1) || true
echo "$gc_out"
ps_left=$(docker ps -a -q --filter label=saiife.managed=true | wc -l)
vol_left=$(docker volume ls -q --filter label=saiife.managed=true | wc -l)
net_left=$(docker network ls --filter label=saiife.managed=true --format '{{.Name}}')
canaries=0
if docker container inspect smoke-canary >/dev/null 2>&1; then canaries=$((canaries + 1)); fi
if docker network inspect smoke-canary-net >/dev/null 2>&1; then canaries=$((canaries + 1)); fi
if docker volume inspect smoke-canary-vol >/dev/null 2>&1; then canaries=$((canaries + 1)); fi
if [ "$ps_left" -eq 0 ] && [ "$vol_left" -eq 0 ] &&
  { [ -z "$net_left" ] || [ "$net_left" = saiife-dev ]; } && [ "$canaries" -eq 3 ]; then
  ok "gc left only the shared network, and all 3 canaries"
else
  fail "gc left only the shared network, and all 3 canaries (ps=$ps_left vol=$vol_left net=$net_left canaries=$canaries)"
fi

# 8. gc says images are not touched.
if grep -q 'Dangling images are not touched' <<<"$gc_out"; then
  ok "gc says dangling images are not touched"
else
  fail "gc says dangling images are not touched"
fi

if [ "$FAILS" -gt 0 ]; then
  echo "$FAILS check(s) failed"
  exit 1
fi
exit 0
