# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 48 smoke: the whole stage-1 flow on real hardware, with the real
# planner, the real name model and your touch key. In a personal daemon
# (`saiife daemon --user`, HOME and XDG_* inside $SMOKE_WORK) it
#   1. builds a sqlite database from the 3 M customers / 9 M invoices that the
#      `data` fragment generated, plus a few synthetic people of its own
#      (two "Anna Brandtholm", one "Katrine Vestergaard" with 150 open
#      invoices, one "Bodil Noerregaard" with no invoices);
#   2. stores your API key, enrols your touch key (a PIN and a touch), and runs
#      `saiife blind init` with flags, fetching and pinning the name model
#      (the progress shows on the terminal);
#   3. asks an English and a Danish question about a customer (a pick list for
#      the two Annas), a typo ("did you mean"), a list over 100 rows (the cap
#      note) and a customer with no invoices (a refusal);
#   4. approves the Katrine method (a touch), asks the same question again and
#      counts the outbox lines (no new entry: no cloud call), runs
#      `data refresh` (the method stays active), `keys rotate` (a touch) and
#      `audit`;
#   5. greps the audit log and the outbox for every synthetic name it asked
#      about. None may appear.
# Run after `data` has run: bash scripts/blind-smoke.sh --only data, then
# --only ask. Defines smoke_ask; no top-level effects.
#
# The prompts (pick list, did-you-mean, Run it?) are driven through the
# debug-only SAIIFE_TEST_BLIND_STDIN seam, so this smoke needs the debug
# build (never a release one) and does not test the real-terminal path; the
# touch key, model, planner and calculator are real.
#
# Needs: python3 (sqlite3 module), the debug `saiife` build (it reads the
# prompts' answers from stdin: SAIIFE_TEST_BLIND_STDIN=1, debug builds only),
# a FIDO2 key, and these variables:
#   SAIIFE_BLIND_SMOKE_KEY_FILE            a file holding your Anthropic API key
#   SAIIFE_BLIND_SMOKE_NER_{MODEL,VOCAB,LABELS}_{URL,SHA256}   as for `ner`
# Anything asked about is synthetic. The key file is read by the vault import
# and never printed. The questions go to the real planner (parameterized, no
# names): that is what is being tested.

P48_WORK=""
P48_PID=""
P48_BIN=""
P48_ME=""
# The synthetic names the questions use; none may reach the audit log or outbox.
P48_NAMES=("Anna Brandtholm" "Brandtholm" "Katrine Vestergaard" "Vestergaard" "Vestergard" "Bodil Noerregaard" "Noerregaard")

p48_log() { printf '%s\n' "$*" >&2; }

# p48_step DESC CMD...: check, and return 1 when the step failed.
p48_step() {
  local before="$FAILED"
  check "$@"
  [ "$FAILED" = "$before" ]
}

p48_result() { RESULTS+=("$1=${2-}"); }

p48_need() {
  local v missing=0
  for v in SAIIFE_BLIND_SMOKE_KEY_FILE \
    SAIIFE_BLIND_SMOKE_NER_MODEL_URL SAIIFE_BLIND_SMOKE_NER_MODEL_SHA256 \
    SAIIFE_BLIND_SMOKE_NER_VOCAB_URL SAIIFE_BLIND_SMOKE_NER_VOCAB_SHA256 \
    SAIIFE_BLIND_SMOKE_NER_LABELS_URL SAIIFE_BLIND_SMOKE_NER_LABELS_SHA256; do
    [ -n "${!v:-}" ] || { p48_log "set $v"; missing=1; }
  done
  [ -f "${SAIIFE_BLIND_SMOKE_KEY_FILE:-/nonexistent}" ] || { p48_log "SAIIFE_BLIND_SMOKE_KEY_FILE is not a file"; missing=1; }
  [ -f "$SMOKE_WORK/data/csv/customers.csv" ] || { p48_log "run the data fragment first (no $SMOKE_WORK/data/csv)"; missing=1; }
  command -v python3 >/dev/null || { p48_log "python3 is needed"; missing=1; }
  [ "$missing" = 0 ]
}

p48_build() {
  (cd "$REPO_ROOT" && cargo build --locked -q -p saiife &&
    cargo build --locked -q -p saiife-shield-ner --bin saiife-ner) || return 1
  P48_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/saiife"
  [ -x "$P48_BIN" ] || { p48_log "no $P48_BIN"; return 1; }
  # A personal daemon looks for the name helper beside its own executable.
  [ -x "$(dirname "$P48_BIN")/saiife-ner" ] || { p48_log "no saiife-ner beside $P48_BIN"; return 1; }
}

p48_env() {
  export HOME="$P48_WORK/home"
  export XDG_CONFIG_HOME="$P48_WORK/xdg/config"
  export XDG_DATA_HOME="$P48_WORK/xdg/data"
  export XDG_STATE_HOME="$P48_WORK/xdg/state"
  export XDG_RUNTIME_DIR="$P48_WORK/run"
  # Off the owner's login keyring; the touch key is a real hardware key.
  export DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent
  export SAIIFE_TEST_BLIND_STDIN=1
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR"
}

# The 3 M customers and 9 M invoices as one sqlite file, plus the synthetic
# people the questions are about.
p48_sqlite() {
  local db="$P48_WORK/shop.sqlite"
  [ -f "$db.done" ] && return 0
  rm -f "$db"
  python3 - "$SMOKE_WORK/data/csv" "$db" <<'PY' || return 1
import csv, sqlite3, sys
src, dbp = sys.argv[1], sys.argv[2]
db = sqlite3.connect(dbp)
db.execute("""CREATE TABLE customers (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT,
  email TEXT, phone TEXT, city TEXT, postcode TEXT, birth_date TEXT, segment TEXT,
  credit_limit REAL, ref_code TEXT)""")
db.execute("""CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL,
  status TEXT, issued TEXT, notes TEXT)""")
def load(table, name, width):
    with open(f"{src}/{name}.csv", newline="", encoding="utf-8") as f:
        r = csv.reader(f); next(r)
        q = f"INSERT INTO {table} VALUES ({','.join('?' * width)})"
        batch = []
        for row in r:
            batch.append(row)
            if len(batch) == 50000:
                db.executemany(q, batch); batch = []
        db.executemany(q, batch)
load("customers", "customers", 11)
load("invoices", "invoices", 6)
base = 4_000_000
people = [
    (base + 1, "Anna", "Brandtholm", "Aarhus"),
    (base + 2, "Anna", "Brandtholm", "Odense"),
    (base + 3, "Katrine", "Vestergaard", "Aalborg"),
    (base + 4, "Bodil", "Noerregaard", "Esbjerg"),
]
for cid, first, last, city in people:
    db.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (cid, first, last, f"{first}.{cid}@example.invalid", "+45 00 00 00 00", city,
         "8000", "1980-01-01", "retail", 15000.0, f"ref-{cid}"))
inv = 20_000_000
for cid in (base + 1, base + 2):
    for i in range(3):
        inv += 1
        db.execute("INSERT INTO invoices VALUES (?,?,?,?,?,?)",
            (inv, cid, 1000.0 + i * 25, "open", "2025-03-01", ""))
for i in range(150):
    inv += 1
    db.execute("INSERT INTO invoices VALUES (?,?,?,?,?,?)",
        (inv, base + 3, 100.0 + i, "open", "2025-04-01", ""))
db.commit()
db.close()
PY
  : >"$db.done"
}

p48_daemon_start() {
  "$P48_BIN" daemon --user >"$P48_WORK/daemon.log" 2>&1 &
  P48_PID=$!
  local i
  for i in $(seq 1 50); do
    if find "$P48_WORK/xdg" "$P48_WORK/home" -maxdepth 5 -type d -name blind 2>/dev/null | grep -q .; then
      return 0
    fi
    kill -0 "$P48_PID" 2>/dev/null || { p48_log "the daemon stopped; see $P48_WORK/daemon.log"; return 1; }
    sleep 0.2
  done
  p48_log "the daemon made no blind state dir; see $P48_WORK/daemon.log"
  return 1
}

p48_daemon_stop() {
  if [ -n "$P48_PID" ]; then
    kill "$P48_PID" 2>/dev/null || true
    wait "$P48_PID" 2>/dev/null || true
    P48_PID=""
  fi
}

p48_dir() { find "$P48_WORK/xdg" "$P48_WORK/home" -maxdepth 6 -type d -name "$1" 2>/dev/null | head -n 1; }

p48_setup() {
  "$P48_BIN" secret add anthropic --kind token --service blind-model \
    --from-file "$SAIIFE_BLIND_SMOKE_KEY_FILE" || return 1
  if [ "$("$P48_BIN" touch ls --json 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)" = 0 ]; then
    p48_log "enrolling your touch key (PIN, then touch)"
    "$P48_BIN" touch enrol --label smoke-key || return 1
  fi
  "$P48_BIN" blind init --dataset shop --file "$P48_WORK/shop.sqlite" \
    --accept-guesses \
    --entity customers:id:first_name+last_name:city:customer:kunde \
    --identifier invoices:customer_id \
    --users "$P48_ME" --approvers "$P48_ME" \
    --ner-model-url "$SAIIFE_BLIND_SMOKE_NER_MODEL_URL" --ner-model-sha256 "$SAIIFE_BLIND_SMOKE_NER_MODEL_SHA256" \
    --ner-vocab-url "$SAIIFE_BLIND_SMOKE_NER_VOCAB_URL" --ner-vocab-sha256 "$SAIIFE_BLIND_SMOKE_NER_VOCAB_SHA256" \
    --ner-labels-url "$SAIIFE_BLIND_SMOKE_NER_LABELS_URL" --ner-labels-sha256 "$SAIIFE_BLIND_SMOKE_NER_LABELS_SHA256" \
    --cloud-secret anthropic --skip-test --yes 2>&1 | tee "$P48_WORK/init.out"
  [ "${PIPESTATUS[0]}" = 0 ]
}

# p48_ask NAME INPUT QUESTION [FLAGS...]: runs `saiife blind ask` with INPUT
# on stdin (the answers to its prompts); the output goes to $P48_WORK/NAME.out,
# the exit code to NAME.rc.
p48_ask() {
  local name="$1" input="$2" q="$3"
  shift 3
  local rc=0
  printf '%b' "$input" | "$P48_BIN" blind ask "$q" "$@" >"$P48_WORK/$name.out" 2>&1 || rc=$?
  printf '%s' "$rc" >"$P48_WORK/$name.rc"
  cat "$P48_WORK/$name.out"
  return 0
}

p48_rc_is() { [ "$(cat "$P48_WORK/$1.rc")" = "$2" ]; }
p48_out_has() { grep -q -- "$2" "$P48_WORK/$1.out"; }

p48_outbox_lines() {
  local d
  d="$(p48_dir outbox)"
  [ -n "$d" ] || { echo 0; return; }
  cat "$d"/*.jsonl 2>/dev/null | wc -l
}

p48_approve() {
  local id
  id="$(sed -n 's/.*saiife blind methods approve \([0-9a-f]\{32\}\).*/\1/p' "$P48_WORK/q_katrine.out" | head -n 1)"
  [ -n "$id" ] || { p48_log "no approve hint in the Katrine answer"; return 1; }
  p48_log "approving: touch your key"
  "$P48_BIN" blind methods approve "$id"
}

p48_reused() {
  # The Katrine question was asked once before approval; after it, the same
  # question must not add an outbox entry (no cloud call).
  local before
  before="$(p48_outbox_lines)"
  p48_ask q_katrine_again "y\n" "What do we have open for Katrine Vestergaard?" --dataset shop
  p48_result ask_outbox_lines "before=$before after=$(p48_outbox_lines)"
  [ "$(p48_outbox_lines)" = "$before" ] && p48_out_has q_katrine_again "(approved)"
}

p48_refresh_keeps_method() {
  "$P48_BIN" blind data refresh --dataset shop --file "$P48_WORK/shop.sqlite" || return 1
  "$P48_BIN" blind methods ls --dataset shop | tee "$P48_WORK/methods.out"
  # The state word of a method line (every line also says "approved by").
  grep -qwE "active" "$P48_WORK/methods.out"
}

# No asked name in anything under $1 (the audit log, the outbox).
p48_no_names_in() {
  local dir="$1" n
  [ -n "$dir" ] && [ -d "$dir" ] || { p48_log "no directory to search"; return 1; }
  # Not vacuous: there must be something there to search.
  [ -n "$(find "$dir" -type f -size +0 2>/dev/null | head -n 1)" ] || { p48_log "$dir holds no records"; return 1; }
  for n in "${P48_NAMES[@]}"; do
    if grep -rqiF -- "$n" "$dir"; then
      p48_log "found \"$n\" under $dir"
      return 1
    fi
  done
}

smoke_ask() {
  P48_WORK="$SMOKE_WORK/ask"
  mkdir -p "$P48_WORK"
  chmod 700 "$P48_WORK"
  P48_ME="$(id -un)"
  p48_step "ask: the key, the name model and the 3 M data are in place" p48_need || return 0
  p48_step "ask: build saiife" p48_build || return 0
  p48_step "ask: the sqlite database (3 M customers, 9 M invoices, synthetic people)" p48_sqlite || return 0

  # Not a subshell: the checks write RESULTS and FAILED. The daemon's
  # environment is undone at the end.
  local saved_env
  saved_env="$(export -p | grep -E '^declare -x (HOME|XDG_[A-Z_]*|DBUS_SESSION_BUS_ADDRESS|SAIIFE_TEST_BLIND_STDIN)=' || true)"
  p48_env
  if p48_daemon_start && sleep 1 && p48_step "ask: init with flags, the model fetched and pinned" p48_setup; then
    p48_run
  else
    p48_log "the daemon or init failed: see $P48_WORK/daemon.log"
  fi
  p48_daemon_stop
  unset SAIIFE_TEST_BLIND_STDIN
  eval "$saved_env"
}

p48_run() {
    check "ask: the model fetch showed progress, or the model was ready" grep -qE "MB of|Ready|ready" "$P48_WORK/init.out"
    check "ask: status shows the calculator's weaker label" bash -c \
      "\"$P48_BIN\" blind status | grep -q 'calculator not in a box (weaker)'"

    p48_ask q_anna "1\ny\n" "What does Anna Brandtholm owe us?" --dataset shop
    check "ask: English question, pick list, answered" p48_rc_is q_anna 0
    check "ask: the pick list names both Annas" p48_out_has q_anna "Which one?"
    check "ask: the answer ends with the footer" p48_out_has q_anna "0 personal values sent"

    p48_ask q_dansk "1\nj\n" "Hvad skylder Anna Brandtholm?" --dataset shop --lang da
    check "ask: Danish question, pick list, answered" p48_rc_is q_dansk 0
    check "ask: the Danish pick prompt" p48_out_has q_dansk "Hvilken?"

    p48_ask q_typo "y\ny\n" "What does Katrine Vestergard owe us?" --dataset shop
    check "ask: a typo gets a did-you-mean" p48_out_has q_typo "Did you mean"

    p48_ask q_katrine "y\n" "What do we have open for Katrine Vestergaard?" --dataset shop
    check "ask: a customer question answers" p48_rc_is q_katrine 0

    p48_ask q_list "y\n" "List all open invoices for Katrine Vestergaard" --dataset shop
    check "ask: a list over 100 rows says so" p48_out_has q_list "showing 100 of 150"

    p48_ask q_none "y\n" "What does Bodil Noerregaard owe us?" --dataset shop
    check "ask: a customer with no invoices is a refusal (exit 2)" p48_rc_is q_none 2

    p48_step "ask: methods approve with your touch" p48_approve || true
    check "ask: the same question again is reused (no new outbox entry)" p48_reused
    check "ask: data refresh keeps the approved method" p48_refresh_keeps_method
    p48_log "rotating keys: touch your key"
    check "ask: keys rotate" "$P48_BIN" blind keys rotate --dataset shop
    check "ask: audit lists the asks" bash -c "\"$P48_BIN\" blind audit --since 1d | grep -q ."

    local audit outbox
    audit="$(p48_dir audit)"
    outbox="$(p48_dir outbox)"
    check "ask: no asked name in the audit log" p48_no_names_in "$audit"
    check "ask: no asked name in the outbox" p48_no_names_in "$outbox"
}
