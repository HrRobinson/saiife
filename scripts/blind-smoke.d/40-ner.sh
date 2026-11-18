# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 46 smoke: the real name detector (`saiife-ner`, release build, no
# `fake` feature) with the owner's pinned model (Q1: ScandiNER int8, verified
# with tract here and nowhere else). Downloads model, vocab and labels over
# https into $SMOKE_WORK, checks their SHA-256, runs the helper on 20 fixed
# English and Danish questions (names of synthetic people, Danish letters, a
# typo, a nickname, a question with no names) and prints recall and
# precision against the expected spans, plus load time, peak RSS and
# per-question latency.
# Defines smoke_ner; no top-level effects. Needs curl, sha256sum and python3.
#
# Required environment (the fragment refuses to run without all six):
#   SAIIFE_BLIND_SMOKE_NER_MODEL_URL   SAIIFE_BLIND_SMOKE_NER_MODEL_SHA256
#   SAIIFE_BLIND_SMOKE_NER_VOCAB_URL   SAIIFE_BLIND_SMOKE_NER_VOCAB_SHA256
#   SAIIFE_BLIND_SMOKE_NER_LABELS_URL  SAIIFE_BLIND_SMOKE_NER_LABELS_SHA256
# (the URLs must be https).

P46_WORK=""
P46_BIN=""

p46_log() { printf '%s\n' "$*" >&2; }

# p46_result KEY VALUE: append KEY=VALUE to RESULTS.
p46_result() { RESULTS+=("$1=${2-}"); }

p46_env() {
  local v missing=0
  for v in MODEL VOCAB LABELS; do
    local u="SAIIFE_BLIND_SMOKE_NER_${v}_URL" s="SAIIFE_BLIND_SMOKE_NER_${v}_SHA256"
    [ -n "${!u:-}" ] || { p46_log "set $u"; missing=1; }
    [ -n "${!s:-}" ] || { p46_log "set $s"; missing=1; }
    case "${!u:-}" in https://* | "") ;; *) p46_log "$u must be an https URL"; missing=1 ;; esac
    case "${!s:-}" in *[!0-9a-f]* | "") [ -z "${!s:-}" ] || { p46_log "$s must be 64 lowercase hex"; missing=1; } ;; esac
  done
  [ "$missing" = 0 ]
}

# p46_fetch KIND: download one file and check its SHA-256.
p46_fetch() {
  local k="$1" u s f
  u="SAIIFE_BLIND_SMOKE_NER_${k^^}_URL"
  s="SAIIFE_BLIND_SMOKE_NER_${k^^}_SHA256"
  f="$P46_WORK/$k.bin"
  if ! [ -f "$f" ] || [ "$(sha256sum "$f" | cut -d' ' -f1)" != "${!s}" ]; then
    curl --fail --silent --show-error --location --proto =https --proto-redir =https \
      --retry 3 --connect-timeout 20 -o "$f" "${!u}" || return 1
  fi
  [ "$(sha256sum "$f" | cut -d' ' -f1)" = "${!s}" ] || { p46_log "$k: sha256 mismatch"; return 1; }
}

p46_build() {
  (cd "$REPO_ROOT" && cargo build --release -q -p saiife-shield-ner --bin saiife-ner) || return 1
  P46_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/saiife-ner"
  [ -x "$P46_BIN" ] || { p46_log "no $P46_BIN"; return 1; }
}

# The 20 questions and their expected name spans (the exact substrings).
p46_run() {
  python3 - "$P46_BIN" "$P46_WORK" <<'PY'
import json, os, resource, subprocess, sys, time

bin_, work = sys.argv[1], sys.argv[2]
CASES = [
    ("What does Alice Johnson owe us?", ["Alice Johnson"]),
    ("Show the invoices for Bob Martinez from last month.", ["Bob Martinez"]),
    ("Did Charlotte Whitfield pay the March invoice?", ["Charlotte Whitfield"]),
    ("Email Daniel Okafor about the renewal.", ["Daniel Okafor"]),
    ("How much did Eleanor Brandt and Frank Osei spend in total?", ["Eleanor Brandt", "Frank Osei"]),
    ("Is Grace Lindqvist still a customer?", ["Grace Lindqvist"]),
    ("List open orders for Henry Castellano.", ["Henry Castellano"]),
    ("Hvad skylder Søren Kjærgaard os?", ["Søren Kjærgaard"]),
    ("Vis fakturaerne for Åse Mølgaard fra sidste måned.", ["Åse Mølgaard"]),
    ("Har Bjørn Østergaard betalt for marts?", ["Bjørn Østergaard"]),
    ("Send en mail til Lærke Thygesen om fornyelsen.", ["Lærke Thygesen"]),
    ("Hvor meget har Mette Hvidberg og Jens Ravnkilde brugt i alt?", ["Mette Hvidberg", "Jens Ravnkilde"]),
    ("Er Gunhild Aaboe stadig kunde?", ["Gunhild Aaboe"]),
    ("What did Alise Jonhson order last week?", ["Alise Jonhson"]),
    ("Hvad har Sørne Kjergaard købt?", ["Sørne Kjergaard"]),
    ("How many orders did Bobby Martinez place?", ["Bobby Martinez"]),
    ("Hvad har Søren K. købt i år?", ["Søren K."]),
    ("What is the total of all open invoices?", []),
    ("Hvor mange kunder har vi i alt?", []),
    ("Show the ten largest invoices from the last quarter.", []),
]
assert len(CASES) == 20

def spans_of(text, names):
    out = []
    for n in names:
        i = text.index(n)
        b = len(text[:i].encode()); out.append((b, b + len(n.encode())))
    return out

argv = [bin_]
for k in ("model", "vocab", "labels"):
    argv += [f"--{k}", os.path.join(work, f"{k}.bin")]
for k in ("model", "vocab", "labels"):
    argv += [f"--sha256-{k}", os.environ[f"SAIIFE_BLIND_SMOKE_NER_{k.upper()}_SHA256"]]
t0 = time.monotonic()
p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
hello = json.loads(p.stdout.readline())
load_s = time.monotonic() - t0
if hello.get("t") != "hello":
    print("no hello:", hello); sys.exit(1)
tp = fp = fn = 0
lat = []
for i, (text, names) in enumerate(CASES, 1):
    t = time.monotonic()
    p.stdin.write((json.dumps({"op": "detect", "id": i, "text": text}) + "\n").encode())
    p.stdin.flush()
    ans = json.loads(p.stdout.readline())
    lat.append((time.monotonic() - t) * 1000)
    if ans.get("t") != "spans":
        print(f"q{i}: {ans}"); fn += len(names); continue
    got = {(s["start"], s["end"]) for s in ans["spans"] if s["label"] == "PER"}
    want = set(spans_of(text, names))
    tp += len(got & want); fp += len(got - want); fn += len(want - got)
    if got != want:
        print(f"q{i}: want {sorted(want)} got {sorted(got)}")
p.stdin.close(); p.wait()
rss_mb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
rec = tp / (tp + fn) if tp + fn else 1.0
prec = tp / (tp + fp) if tp + fp else 1.0
lat.sort()
print(f"ner_recall={rec:.3f}")
print(f"ner_precision={prec:.3f}")
print(f"ner_load_secs={load_s:.2f}")
print(f"ner_peak_rss_mb={rss_mb:.0f}")
print(f"ner_latency_ms_median={lat[len(lat)//2]:.1f}")
print(f"ner_latency_ms_max={lat[-1]:.1f}")
sys.exit(0 if p.returncode == 0 else 1)
PY
}

smoke_ner() {
  p46_env || { p46_log "ner smoke: set the six SAIIFE_BLIND_SMOKE_NER_* variables (the owner's model choice)"; return 1; }
  P46_WORK="$SMOKE_WORK/ner"
  mkdir -p "$P46_WORK"
  chmod 700 "$P46_WORK"
  check "ner: build saiife-ner (release, no fake feature)" p46_build || return 0
  local k
  for k in model vocab labels; do
    check "ner: fetch and verify the $k" p46_fetch "$k" || return 0
  done
  local out="$P46_WORK/run.out"
  local rc=0
  p46_run >"$out" 2>&1 || rc=$?
  cat "$out"
  check "ner: the helper answered the 20 questions" test "$rc" = 0
  local line
  while IFS= read -r line; do
    case "$line" in ner_*=*) p46_result "${line%%=*}" "${line#*=}" ;; esac
  done <"$out"
}
