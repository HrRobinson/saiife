# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 45 smoke: the real sandboxed calculator (`saiife __blind-calc`,
# release build) on the 3 M customer snapshot that 10-data built. Runs
# after `data` (bash scripts/blind-smoke.sh --only calc reuses its output).
#
# Jobs, each one frame on the calculator's stdin, built from the dataset's
# manifest (schema, public values, snapshot hash):
#   - balance: SUM of customer 1's invoices -> one row, a number;
#   - list: 250 invoices of one public status -> 100 rows shown, the cap
#     note's total 250;
#   - heavy: the heaviest join the grammar allows (every invoice joined to
#     its customer, COUNT(DISTINCT) grouped by month) with a 2 s wall cap
#     -> time_cap (a literal CROSS JOIN is outside the grammar: refused as
#     construct_not_allowed, checked too);
#   - the wrong snapshot hash -> snapshot_mismatch.
# Prints the Confinement the owner's kernel gave (`netns` shows whether
# unprivileged user namespaces are allowed).
#
# The answer is piped (never redirected to a file): the calculator runs
# with RLIMIT_FSIZE 0, so a write to a regular file would kill it.
#
# The seccomp allowlist was traced on the glibc build; the release binary
# is static musl. This smoke is where the allowlist meets musl: an answer of
# runtime_error on every job (with "internal error" or nothing on stderr)
# means musl makes a call the allowlist lacks (see CALC_ALLOWED in
# crates/system/src/sandbox.rs).
# Defines smoke_calc; no top-level effects. Needs python3.

P45_WORK=""
P45_LIVE=""
P45_BIN=""

p45_log() { printf '%s\n' "$*" >&2; }

p45_result() { RESULTS+=("$1=${2-}"); }

p45_step() {
  local before="$FAILED"
  check "$@"
  [ "$FAILED" = "$before" ]
}

p45_have_snapshot() {
  [ -f "$P45_LIVE/snapshot.sqlite" ] && [ -f "$P45_LIVE/manifest.json" ] || {
    p45_log "no $P45_LIVE/snapshot.sqlite: run the data fragment first"
    return 1
  }
}

p45_build() {
  (cd "$REPO_ROOT" && cargo build --release -q -p saiife) || return 1
  P45_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/saiife"
  [ -x "$P45_BIN" ] || { p45_log "no $P45_BIN"; return 1; }
}

# p45_job NAME: write $P45_WORK/NAME.job (one frame) from the manifest.
p45_job() {
  python3 - "$P45_LIVE" "$1" "$P45_WORK/$1.job" <<'PY'
import json, struct, sys
live, name, out = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(live + "/manifest.json"))
ent = next(e for e in m["schema"]["entities"] if e["table"] == "customers")
status = next((p["passing"][0] for p in m["public"]
               if p["column"] == "invoices.status" and p["passing"]), None)
if status is None:
    sys.exit("invoices.status is not public in the manifest")
fk = ent["word"] + "_" + ent["key"]
join = f"FROM invoices i JOIN customers c ON c.{ent['key']} = i.{fk}"
customer = {"name": "p1", "ty": {"entity": {"table": "customers", "word": ent["word"]}},
            "bound": {"keys": [1]}, "display": ""}
caps = {"wall_ms": 10000, "steps": 2000000000, "heap_bytes": 512 * 1024 * 1024, "list_cap": 100}
sha = m["snapshot_sha256"]
if name == "balance":
    method, params = f"SELECT SUM(i.amount) AS owed {join} WHERE c.{ent['key']} = :p1", [customer]
elif name == "list":
    method, params = f"SELECT i.amount, i.issued FROM invoices i WHERE i.status = '{status}' LIMIT 250", []
elif name == "heavy":
    method = (f"SELECT strftime('%Y-%m', i.issued) AS month, COUNT(DISTINCT i.amount) AS n {join} "
              f"GROUP BY strftime('%Y-%m', i.issued)")
    params, caps = [], dict(caps, wall_ms=2000)
elif name == "cross":
    method, params = "SELECT COUNT(*) AS n FROM invoices i CROSS JOIN customers c", []
elif name == "badhash":
    method, params = f"SELECT SUM(i.amount) AS owed {join} WHERE c.{ent['key']} = :p1", [customer]
    sha = "sha256:" + "0" * 64
else:
    sys.exit("unknown job " + name)
job = {"v": 1, "snapshot": live + "/snapshot.sqlite", "snapshot_sha256": sha,
       "schema": m["schema"], "public": m["public"], "method": method, "checks": [],
       "params": params, "caps": caps}
body = json.dumps(job).encode()
with open(out, "wb") as f:
    f.write(struct.pack(">I", len(body)) + body)
PY
}

# p45_run NAME: run the calculator on NAME.job; NAME.answer holds the frame.
p45_run() {
  local t0 t1
  p45_job "$1" || return 1
  t0="$(date +%s%N)"
  "$P45_BIN" __blind-calc <"$P45_WORK/$1.job" 2>"$P45_WORK/$1.err" | cat >"$P45_WORK/$1.answer" ||
    return 1
  t1="$(date +%s%N)"
  p45_result "calc_${1}_ms" "$(((t1 - t0) / 1000000))"
}

# p45_expect NAME WHAT: check NAME.answer (WHAT: balance, list, time_cap,
# construct_not_allowed, snapshot_mismatch); print its confinement.
p45_expect() {
  python3 - "$P45_WORK/$1.answer" "$2" <<'PY'
import json, struct, sys
data = open(sys.argv[1], "rb").read()
(n,) = struct.unpack(">I", data[:4])
a = json.loads(data[4:4 + n])
want = sys.argv[2]
kind, body = next(iter(a.items()))
print("answer", kind, {k: v for k, v in body.items() if k != "result"}, file=sys.stderr)
if want == "balance":
    rows = body["result"]["rows"] if kind == "ok" else []
    # CellValue is externally tagged: {"Real": 1234.5} or {"Int": 12}.
    ok = len(rows) == 1 and any(k in rows[0][0] for k in ("Real", "Int"))
    if ok:
        print("balance", rows[0][0], file=sys.stderr)
elif want == "list":
    r = body.get("result")
    ok = kind == "ok" and len(r["rows"]) == 100 and r["truncated"] and r["total_rows"] == 250
    if ok:
        print("cap note: showing 100 of", r["total_rows"], file=sys.stderr)
else:
    ok = kind == "err" and body["class"] == want
c = body.get("confinement")
if c:
    print("confinement", c, file=sys.stderr)
sys.exit(0 if ok else 1)
PY
}

p45_confinement() {
  python3 - "$P45_WORK/balance.answer" <<'PY'
import json, struct, sys
data = open(sys.argv[1], "rb").read()
(n,) = struct.unpack(">I", data[:4])
a = json.loads(data[4:4 + n])
c = next(iter(a.values())).get("confinement") or {}
print(" ".join(f"{k}={str(v).lower()}" for k, v in c.items()))
sys.exit(0 if c.get("landlock_abi", 0) > 0 and c.get("seccomp") else 1)
PY
}

p45_case() {
  p45_run "$1" && p45_expect "$1" "$2"
}

smoke_calc() {
  P45_WORK="$SMOKE_WORK/calc"
  P45_LIVE="$SMOKE_WORK/data/out/smoke/live"
  mkdir -p "$P45_WORK"
  chmod 700 "$P45_WORK"
  p45_step "calc: the data fragment's snapshot is there" p45_have_snapshot || return 0
  p45_step "calc: release saiife built" p45_build || return 0
  check "calc: customer balance answered" p45_case balance balance
  check "calc: 250-row list capped at 100, total 250" p45_case list list
  check "calc: heavy join hits the time cap" p45_case heavy time_cap
  check "calc: CROSS JOIN refused by the validator" p45_case cross construct_not_allowed
  check "calc: wrong snapshot hash refused" p45_case badhash snapshot_mismatch
  check "calc: confinement reported (Landlock and seccomp)" p45_confinement
  p45_result calc_confinement "$(p45_confinement 2>/dev/null || true)"
}
