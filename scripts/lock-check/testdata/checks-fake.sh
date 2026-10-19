#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034,SC2154,SC2317,SC2329
# Per-agent contract for the fake agent (testdata/fake-agent.sh), used only
# by the offline tests (test-lib.sh): `in-container.sh run fake` with
# LC_ROOT set and LC_CHECKS_DIR pointing here. It doubles as the smallest
# worked example of a checks-<agent>.sh. Sourced after lib.sh; writes only
# under $LC_ROOT (etc/fake, usr/local/bin, home/agent/.fake).
#
#   LC_ROOT=$(mktemp -d) LC_CHECKS_DIR=$PWD/scripts/lock-check/testdata \
#     bash scripts/lock-check/in-container.sh run fake

if [[ -z "${LC_ROOT:-}" ]]; then
  echo "checks-fake.sh: the fake agent runs only with LC_ROOT set" >&2
  return 2
fi
FAKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

agent_version() {
  echo "fake-agent 1.0"
}

agent_invoke() {
  fake-agent "$@"
}

agent_baseline() {
  rm -rf "$LC_ROOT/etc/fake"
  mkdir -p "$LC_ROOT/etc/fake" "$LC_ROOT/usr/local/bin"
  install -m 0755 "$FAKE_DIR/fake-agent.sh" "$LC_ROOT/usr/local/bin/fake-agent"
  printf '%s\n' "$LC_STUB check --managed --hook-exit --agent fake" "$LC_WITNESS" \
    >"$LC_ROOT/etc/fake/hooks"
}

agent_settings_files() {
  printf '%s\n' "$LC_ROOT/etc/fake/disabled" "$LC_HOME/.fake/settings.json"
}

agent_login_files() {
  printf '%s\n' "$LC_HOME/.fake/credentials.json"
}

fake_fail_closed() {
  : >"$LC_ROOT/etc/fake/fail-closed"
}

fake_disable_user() {
  lc_as_agent_write "$LC_HOME/.fake/settings.json" '{"disabled": true}'
}

agent_checks() {
  lc_check fake.control control ran allow -
  lc_check fake.fires gate fired allow -
  lc_check fake.deny gate blocked deny fake_fail_closed
  lc_check fake.disabled gate blocked deny fake_disable_user
  lc_probe fake.version found "$(agent_version)"
}
