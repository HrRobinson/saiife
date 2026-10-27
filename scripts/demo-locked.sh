#!/usr/bin/env bash
# The 5-minute locked demo (plan 12, Task 9; spec §14 point 12). CI ONLY.
#
# Not a program of its own: scripts/locked-linux/run.sh sources this file
# (after its CI gate and after lib.sh) and calls `phase_demo` on the
# `locked-linux` runner, as the runner user with sudo, on a throwaway
# machine. Run directly it refuses before doing anything.
#
# The flow, against the installed locked system:
#   1. a `shop` generic http connector on a loopback HTTPS mock; the mock's
#      CA is copied, root-owned, to /etc/saiife/ca;
#   2. as agent-ci: remove the managed hook, kill the daemon (by the unit's
#      MainPID only), read the vault key. Each must fail; each is recorded
#      in $WORK/demo-attempts.txt and in the job log;
#   3. `saiife api shop orders.list` is allowed and prints JSON;
#   4. `saiife api shop products.update ...` is pending; approver-ci approves;
#      `saiife api result <id>` is done;
#   5. `saiife audit verify` says intact;
#   6. `saiife audit --report` writes an HTML file with the connector and
#      approvals sections.
# The whole demo must take under 5 minutes.
#
# Needs from lib.sh/run.sh: BIN, OPT_BIN, AUDIT_DIR, AGENT_USER, AGENT_HOME,
# APPROVER_USER, WORK, and the helpers (as_root, ok, fail, phase, wait_diag,
# reload_checked, expect_denied, saiife_as, records, daemon_pid, ...).

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "refusing: scripts/demo-locked.sh runs only from scripts/locked-linux/run.sh in the GitHub Actions locked-linux job" >&2
    exit 2
fi

DEMO_PORT=18443
DEMO_URL="https://127.0.0.1:$DEMO_PORT"
DEMO_BUDGET_SECS=300
DEMO_MOCK_PID=""
DEMO_ACTIVE=0
DEMO_CFG_BACKUP=""
# Set at the start of phase_demo (the demo has no install step of its own:
# the system install is phase 1 of run.sh, outside the budget).
DEMO_STARTED=0

# Fails once the demo has run longer than its budget.
check_budget() {
    local used=$((SECONDS - DEMO_STARTED))
    ((used <= DEMO_BUDGET_SECS)) || fail "the demo is over its ${DEMO_BUDGET_SECS}s budget after $1 (${used}s)"
}

# The mock: a tiny static HTTPS server (python3 stdlib) on loopback. One
# JSON line per request goes to $WORK/mock.log, with the credential header
# it saw.
demo_write_mock() {
    cat >"$WORK/mock.py" <<'PY'
import http.server, json, ssl, sys

work, port = sys.argv[1], int(sys.argv[2])

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        with open(work + "/mock.log", "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path,
                                "key": self.headers.get("X-Api-Key"),
                                "body": body}) + "\n")
        if self.command == "GET" and self.path.split("?")[0] == "/orders":
            out = {"orders": [{"id": 1001, "status": "open", "total": "49.00"},
                              {"id": 1002, "status": "open", "total": "12.50"}]}
        elif self.command == "PATCH" and self.path.startswith("/products/"):
            out = {"id": self.path.rsplit("/", 1)[1], "updated": True}
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_PATCH = do_POST = do_PUT = do_DELETE = answer

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(work + "/mock-cert.pem", work + "/mock-key.pem")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
open(work + "/mock.ready", "w").write("ready\n")
srv.serve_forever()
PY
}

# A CI-only CA and a server certificate for 127.0.0.1 signed by it.
demo_make_certs() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=saiife demo CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$WORK/demo-ca-key.pem" -out "$WORK/demo-ca.pem" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
        -keyout "$WORK/mock-key.pem" -out "$WORK/mock.csr" 2>/dev/null
    printf '%s\n' "basicConstraints=CA:FALSE" "keyUsage=digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth" "subjectAltName=IP:127.0.0.1" >"$WORK/mock.ext"
    openssl x509 -req -in "$WORK/mock.csr" -CA "$WORK/demo-ca.pem" -CAkey "$WORK/demo-ca-key.pem" \
        -CAcreateserial -days 2 -extfile "$WORK/mock.ext" -out "$WORK/mock-cert.pem" 2>/dev/null
    openssl verify -CAfile "$WORK/demo-ca.pem" "$WORK/mock-cert.pem" >/dev/null ||
        fail "the demo server certificate does not verify against the demo CA"
}

demo_mock_ready() {
    [[ -e "$WORK/mock.ready" ]]
}

# `demo_api <user> <stdin file or /dev/null> <args...>`: `saiife api ...` as
# `user` in its home. Sets SA_CODE, SA_OUT and SA_ERR (like saiife_as).
demo_api() {
    local user="$1" in="$2" home="$AGENT_HOME"
    shift 2
    [[ "$user" == "$AGENT_USER" ]] || home=/
    SA_CODE=0
    # The runner's shell opens the input and output files on purpose.
    # shellcheck disable=SC2024
    sudo -n -u "$user" env -C "$home" timeout 120 "$OPT_BIN" api "$@" \
        <"$in" >"$WORK/sa.out" 2>"$WORK/sa.err" || SA_CODE=$?
    SA_OUT="$(cat "$WORK/sa.out")"
    SA_ERR="$(cat "$WORK/sa.err")"
}

# `demo_attempt <what> <command...>`: an attack as agent-ci. It must fail
# with a permission error; the attempt is appended to the transcript.
demo_attempt() {
    local what="$1"
    expect_denied "$@"
    printf 'DENIED  %s  ->  %s\n' "$what" "$(tr '\n' ' ' <"$WORK/attack.out")" >>"$WORK/demo-attempts.txt"
}

# Put everything back. Idempotent; also runs from on_exit.
cleanup_demo() {
    [[ "$DEMO_ACTIVE" == 1 ]] || return 0
    DEMO_ACTIVE=0
    if [[ -n "$DEMO_MOCK_PID" ]]; then
        # Our own child (the mock), by the PID the shell gave it.
        kill "$DEMO_MOCK_PID" >/dev/null 2>&1 || true
        wait "$DEMO_MOCK_PID" 2>/dev/null || true
        DEMO_MOCK_PID=""
    fi
    as_root "$OPT_BIN" secret remove shop-key >/dev/null 2>&1 || true
    as_root rm -f /etc/saiife/policy.d/shop.toml || true
    as_root rm -rf /etc/saiife/ca || true
    if [[ -n "$DEMO_CFG_BACKUP" && -e "$DEMO_CFG_BACKUP" ]]; then
        as_root cp -p "$DEMO_CFG_BACKUP" /etc/saiife/config.toml || true
        as_root rm -f "$DEMO_CFG_BACKUP" || true
        DEMO_CFG_BACKUP=""
    fi
    if getent passwd "$APPROVER_USER" >/dev/null 2>&1; then
        as_root userdel -r "$APPROVER_USER" >/dev/null 2>&1 || true
    fi
}

demo_policy() {
    cat <<'EOF'
[services.shop]
connector = "http"
base_url = "https://127.0.0.1:18443"
secret = "shop-key"
auth = { kind = "header", name = "X-Api-Key" }

allow = ["orders:read"]
ask   = ["products:write"]

[[services.shop.operation]]
id = "orders.list"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders"
query = ["status"]

[[services.shop.operation]]
id = "products.update"
capability = "products:write"
kind = "write"
method = "PATCH"
path = "/products/{product_id}"
body = "json"
EOF
}

phase_demo() {
    phase "6d. the 5-minute locked demo (shop connector, approvals, audit report)"
    DEMO_STARTED=$SECONDS
    local started=$DEMO_STARTED key id body hookfile pid rec n
    DEMO_ACTIVE=1
    : >"$WORK/demo-attempts.txt"

    # 1. The mock, its CA, the secret, the service and the scope.
    demo_make_certs
    demo_write_mock
    python3 "$WORK/mock.py" "$WORK" "$DEMO_PORT" >"$WORK/mock.out" 2>&1 &
    DEMO_MOCK_PID=$!
    if ! wait_until_quiet 20 demo_mock_ready; then
        cat "$WORK/mock.out" >&2 || true
        fail "the HTTPS mock did not start within 20s"
    fi
    ok "loopback HTTPS mock on $DEMO_URL"

    as_root install -d -m 755 -o root -g root /etc/saiife/ca
    as_root install -m 644 -o root -g root "$WORK/demo-ca.pem" /etc/saiife/ca/demo-ca.pem
    expect_stat /etc/saiife/ca "root:root 755"
    expect_stat /etc/saiife/ca/demo-ca.pem "root:root 644"

    key="$(openssl rand -hex 16)"
    printf '%s' "$key" >"$WORK/shop.key"
    as_root "$OPT_BIN" secret add shop-key --kind header --service shop --from-file "$WORK/shop.key" ||
        fail "secret add shop-key failed"
    rm -f "$WORK/shop.key"
    ok "secret shop-key in the vault (allowed for service shop only)"

    as_root useradd -m -s /bin/bash "$APPROVER_USER"
    DEMO_CFG_BACKUP="$WORK/config.pre-demo"
    as_root cp -p /etc/saiife/config.toml "$DEMO_CFG_BACKUP"
    as_root chmod a+r "$DEMO_CFG_BACKUP"
    as_root cat /etc/saiife/config.toml | awk '
        /^[ \t]*\[/ { skip = ($0 ~ /^[ \t]*\[approval(\.[^]]*)?\][ \t]*(#.*)?$/) }
        !skip { print }
    ' | sed "s/^users = \[\"$AGENT_USER\"\]\$/&\nservices = [\"shop\"]/" >"$WORK/config.demo"
    grep -qx 'services = \["shop"\]' "$WORK/config.demo" || fail "the scope of $AGENT_USER was not found in the installed config"
    cat >>"$WORK/config.demo" <<EOF

[approval]
approvers = ["$APPROVER_USER"]
same_user = "deny"
EOF
    as_root tee /etc/saiife/config.toml <"$WORK/config.demo" >/dev/null
    demo_policy >"$WORK/shop.toml"
    as_root install -m 644 -o root -g root "$WORK/shop.toml" /etc/saiife/policy.d/shop.toml
    # The CA is read at the daemon's start: restart, not reload.
    as_root systemctl restart saiifed
    wait_diag 30 "the daemon after the restart" daemon_ready
    rec="$(records | jq -r 'select(.kind == "policy") | .result' | tail -n 1)"
    [[ "$rec" != rejected ]] || fail "the daemon rejected the demo config"
    ok "shop connector configured (policy $rec): scope $AGENT_USER, ask products:write, approver $APPROVER_USER"

    check_budget "the setup"

    # 2. Three attacks as agent-ci; each must fail and is recorded.
    echo "-- attacks as $AGENT_USER (recorded in $WORK/demo-attempts.txt)"
    hookfile=/etc/claude-code/managed-settings.d/50-saiife.json
    demo_attempt "remove the managed hook $hookfile" rm -f "$hookfile"
    as_root test -s "$hookfile" || fail "the managed hook is gone"
    pid="$(daemon_pid)"
    [[ "$pid" -gt 0 ]] || fail "no daemon MainPID"
    # By the unit's MainPID only, never by name.
    demo_attempt "kill the daemon (MainPID $pid)" kill -s KILL "$pid"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon MainPID changed"
    demo_attempt "read the vault key" cat /etc/saiife/credstore/vault-key
    cat "$WORK/demo-attempts.txt"
    [[ "$(wc -l <"$WORK/demo-attempts.txt")" -eq 3 ]] || fail "the attempts were not all recorded"

    check_budget "the attacks"

    # 3. A read: allowed, JSON on stdout, no credential in the output.
    demo_api "$AGENT_USER" /dev/null shop orders.list status=open
    [[ "$SA_CODE" == 0 ]] || fail "orders.list exited $SA_CODE, want 0: $SA_ERR"
    jq -e '.orders | length == 2' <<<"$SA_OUT" >/dev/null || fail "orders.list printed no orders: $SA_OUT"
    [[ "$SA_OUT$SA_ERR" != *"$key"* ]] || fail "the credential reached the agent"
    echo "$SA_OUT"
    ok "saiife api shop orders.list: allowed, JSON printed ($SA_ERR)"
    n="$(jq -s --arg k "$key" 'map(select(.method == "GET" and .path == "/orders?status=open" and .key == $k)) | length' "$WORK/mock.log")"
    [[ "$n" == 1 ]] || fail "the mock saw the GET /orders with the vault credential $n times, want 1: $(cat "$WORK/mock.log")"
    ok "the mock saw the vault credential; the agent never did"

    check_budget "the read"

    # 4. A write: pending, approved by approver-ci, then done.
    body="$WORK/product.json"
    printf '{"price":"19.90"}' >"$body"
    demo_api "$AGENT_USER" "$body" shop products.update product_id=42 --body -
    [[ "$SA_CODE" == 3 ]] || fail "products.update exited $SA_CODE, want 3 (pending): $SA_OUT $SA_ERR"
    id="$(sed -n 's/.*pending approval #\([0-9][0-9]*\).*/\1/p' <<<"$SA_ERR" | head -n 1)"
    [[ -n "$id" ]] || fail "no request id in: $SA_ERR"
    ok "saiife api shop products.update: pending, request #$id"
    n="$(jq -s 'map(select(.method == "PATCH")) | length' "$WORK/mock.log")"
    [[ "$n" == 0 ]] || fail "the write reached the mock before it was approved"
    saiife_as "$APPROVER_USER" / approve "$id" --note "locked demo"
    [[ "$SA_CODE" == 0 ]] || fail "$APPROVER_USER: approve #$id exited $SA_CODE: $SA_ERR"
    ok "$APPROVER_USER approved #$id"
    demo_api "$AGENT_USER" /dev/null result "$id" --wait 60s
    [[ "$SA_CODE" == 0 ]] || fail "api result $id exited $SA_CODE, want 0 (done): $SA_OUT $SA_ERR"
    jq -e '.updated == true' <<<"$SA_OUT" >/dev/null || fail "api result $id: unexpected body: $SA_OUT"
    ok "saiife api result $id: done ($SA_OUT)"
    n="$(jq -s --arg k "$key" 'map(select(.method == "PATCH" and .path == "/products/42" and .key == $k and .body == "{\"price\":\"19.90\"}")) | length' "$WORK/mock.log")"
    [[ "$n" == 1 ]] || fail "the mock saw the approved PATCH $n times, want 1: $(cat "$WORK/mock.log")"
    ok "the approved write reached the mock exactly once, with the vault credential"

    check_budget "the write"

    # 5. The chain is intact.
    audit_verify
    grep -q 'intact' "$WORK/verify.out" || fail "audit verify did not say intact: $(cat "$WORK/verify.out")"

    check_budget "audit verify"

    # 6. The HTML report.
    as_root env SAIIFE_AUDIT_DIR="$AUDIT_DIR" "$OPT_BIN" audit --report "$WORK/demo-report.html" ||
        fail "saiife audit --report failed"
    as_root test -s "$WORK/demo-report.html" || fail "no report at $WORK/demo-report.html"
    as_root chmod a+r "$WORK/demo-report.html"
    grep -q '<h2>Connector activity</h2>' "$WORK/demo-report.html" || fail "the report has no connector section"
    grep -q '<h2>Approvals</h2>' "$WORK/demo-report.html" || fail "the report has no approvals section"
    grep -q 'shop' "$WORK/demo-report.html" || fail "the report does not mention the shop connector"
    if grep -q 'No connector requests in this period' "$WORK/demo-report.html"; then
        fail "the report's connector section is empty"
    fi
    if grep -q 'No approvals in this period' "$WORK/demo-report.html"; then
        fail "the report's approvals section is empty"
    fi
    ok "report written ($(wc -c <"$WORK/demo-report.html") bytes) with the connector and approvals sections"

    check_budget "the report"

    # Keep the evidence for the job log, then put everything back.
    if mkdir -p "$LOGS"; then
        cp "$WORK/demo-report.html" "$WORK/demo-attempts.txt" "$LOGS/" 2>/dev/null || true
    fi
    cleanup_demo
    reload_checked
    wait_diag 30 "the daemon after restoring the config" daemon_ready
    n=$((SECONDS - started))
    echo "  demo took ${n}s (budget ${DEMO_BUDGET_SECS}s)"
    ((n < DEMO_BUDGET_SECS)) || fail "the demo took ${n}s, over the ${DEMO_BUDGET_SECS}s budget"
    ok "demo done in ${n}s; config restored, $APPROVER_USER and the mock removed"
}
