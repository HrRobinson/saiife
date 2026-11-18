# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 43 smoke: the dataset build at full size. Generates 3 000 000
# synthetic customers and 9 000 000 invoices (blind_fixture), builds them
# with the blind_build example (stage, propose, accept all, finish), and
# checks: the run took under 20 minutes and under 4 GiB peak RSS
# (/usr/bin/time -v), the manifest's row counts and bands, and that the
# live set is complete. Prints the build time, peak memory and index size.
# Defines smoke_data; no top-level effects.
#
# Owner prerequisites: GNU time at /usr/bin/time (package `time`), python3
# (reads the manifest), about 10 GB free under $SMOKE_WORK.

P43_CUSTOMERS=3000000
P43_INVOICES=9000000
P43_MAX_SECS=$((20 * 60))
P43_MAX_KB=$((4 * 1024 * 1024))

P43_WORK=""
P43_OUT=""
P43_TIME_LOG=""
P43_SECS=""

p43_log() { printf '%s\n' "$*" >&2; }

# p43_result KEY VALUE: append KEY=VALUE to RESULTS.
p43_result() { RESULTS+=("$1=${2-}"); }

# p43_step LABEL CMD...: check, and return 1 when that check failed (the
# later steps need it).
p43_step() {
  local before="$FAILED"
  check "$@"
  [ "$FAILED" = "$before" ]
}

p43_have_time() {
  [ -x /usr/bin/time ] || { p43_log "install GNU time (/usr/bin/time)"; return 1; }
  /usr/bin/time -v true >/dev/null 2>&1 || { p43_log "/usr/bin/time is not GNU time"; return 1; }
}

p43_fixture() {
  rm -rf "$P43_WORK/csv"
  (cd "$REPO_ROOT" && cargo run --release -q -p saiife-shield --example blind_fixture -- \
    --rows "$P43_CUSTOMERS" --invoices "$P43_INVOICES" --seed 43 --out "$P43_WORK/csv")
}

p43_build() {
  local t0 t1
  rm -rf "$P43_OUT"
  (cd "$REPO_ROOT" && cargo build --release -q -p saiife-shield --example blind_build) || return 1
  # Time the example itself, not cargo: GNU time's peak RSS is then the build's.
  local bin="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/examples/blind_build"
  [ -x "$bin" ] || { p43_log "no $bin"; return 1; }
  t0="$(date +%s)"
  /usr/bin/time -v -o "$P43_TIME_LOG" "$bin" "$P43_WORK/csv" "$P43_OUT" \
    | tee "$P43_WORK/build.log" || return 1
  t1="$(date +%s)"
  P43_SECS=$((t1 - t0))
  p43_result data_build_secs "$P43_SECS"
}

p43_under_time() {
  [ -n "$P43_SECS" ] && [ "$P43_SECS" -lt "$P43_MAX_SECS" ]
}

p43_peak_kb() {
  sed -n 's/^[[:space:]]*Maximum resident set size (kbytes): \([0-9][0-9]*\)$/\1/p' "$P43_TIME_LOG"
}

p43_under_memory() {
  local kb
  kb="$(p43_peak_kb)"
  p43_result data_peak_rss_kb "$kb"
  [ -n "$kb" ] && [ "$kb" -lt "$P43_MAX_KB" ]
}

# The manifest's exact counts and one-significant-figure bands.
p43_manifest_rows() {
  python3 - "$P43_OUT/live/manifest.json" "$P43_CUSTOMERS" "$P43_INVOICES" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
rows = {t["name"]: t["rows"] for t in m["schema"]["tables"]}
want = {"customers": int(sys.argv[2]), "invoices": int(sys.argv[3])}
bands = {"customers": "about 3 million", "invoices": "about 9 million"}
ok = rows == want and all(m["rows_bands"][t] == b for t, b in bands.items())
print("rows", rows, "bands", m["rows_bands"], file=sys.stderr)
sys.exit(0 if ok else 1)
PY
}

p43_live_complete() {
  local f
  for f in snapshot.sqlite lexicon.sqlite index.bin index.bloom allow.json manifest.json; do
    [ -f "$P43_OUT/live/$f" ] || { p43_log "missing live/$f"; return 1; }
  done
  [ ! -e "$P43_OUT/stage" ] && [ ! -e "$P43_OUT/old" ]
}

p43_index_size() {
  local bin bloom
  bin="$(stat -c %s "$P43_OUT/live/index.bin")" || return 1
  bloom="$(stat -c %s "$P43_OUT/live/index.bloom")" || return 1
  p43_result data_index_bytes "$bin"
  p43_result data_bloom_bytes "$bloom"
  printf 'index.bin %s bytes, index.bloom %s bytes\n' "$bin" "$bloom"
}

smoke_data() {
  P43_WORK="$SMOKE_WORK/data"
  P43_OUT="$P43_WORK/out/smoke"
  P43_TIME_LOG="$P43_WORK/time.log"
  mkdir -p "$P43_WORK"
  chmod 700 "$P43_WORK"
  p43_step "data: GNU time is installed" p43_have_time || return 0
  p43_step "data: 3M customers / 9M invoices generated" p43_fixture || return 0
  p43_step "data: blind_build finished" p43_build || return 0
  check "data: build under 20 minutes" p43_under_time
  check "data: peak RSS under 4 GiB" p43_under_memory
  check "data: manifest row counts and bands" p43_manifest_rows
  check "data: live set complete, no stage or old left" p43_live_complete
  check "data: index size reported" p43_index_size
  p43_log "build ${P43_SECS}s, peak RSS $(p43_peak_kb) kB"
}
