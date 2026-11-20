# Plan 46: Data Shield local name detector (ONNX NER, stage 1): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A small, non-LLM, local name and entity detector for English and Danish questions: a separate helper binary `saiife-ner` that loads a pinned ONNX token-classification model with the pure-Rust `tract` runtime inside a Landlock + seccomp sandbox, and answers `detect` requests over a line protocol; plus a fake helper for tests and the packaging entry.

**Architecture:** New crate `crates/shield-ner` (lib + bins `saiife-ner` and, with feature `fake`, `saiife-fake-ner`). The protocol types live in `saiife_shield::ner_proto` (serde only), so the daemon (plan 47) speaks the protocol without linking `tract`. The helper is model-agnostic within one family: BERT-style WordPiece models with a BIO tag head; the model file, `vocab.txt` and a small `labels.json` are each pinned by sha256 in `[blind.ner]` (plan 43 Task 2), fetched and checked by the daemon (plan 47 Task 4), and checked again by the helper before loading. The daemon keeps one helper alive and restarts it on exit.

**Tech Stack:** Rust; `tract-onnx = "=0.23.9"` (published 2026-10-15, MIT OR Apache-2.0). Already in the lock: `serde`, `serde_json`, `sha2`, `unicode-normalization`, `zeroize`. Sandbox from plan 45 Task 7 (`saiife_system::sandbox::confine_helper`, `apply_rlimits`). Integrity check reused from plan 41 (`saiife_fido::client::check_helper`, `crates/fido/src/client.rs:58`) on the daemon side (plan 47).

**ONNX runtime choice (recorded for the owner):** **`tract-onnx =0.23.9`**. Pure Rust (its `tract-linalg` compiles a few assembly kernels through `cc`; no C++, no CMake, no download), MIT OR Apache-2.0, runs ONNX BERT/DistilBERT token classification on CPU, a few MB of binary. Rejected: **`ort`** (the Microsoft ONNX Runtime bindings): the 2.x line is still release-candidate (`2.0.0-rc.15`, 2026-10-19), it links the C++ ONNX Runtime (MIT, ~20 MB shared library) that its build script downloads at build time (network in the build, an artifact outside `Cargo.lock`), and it would need its own packaging of `libonnxruntime.so`. Speed is not the constraint here (one short question per ask). `tract` lives only in `crates/shield-ner` and the `saiife-ner` binary, never in `saiife` (CI gate below), so the hook binary does not grow.

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` §1.4 (detection is never perfect), §2.1.7 [owner], §2.2.5 (names in the firewall), §5.1 (models fetched on the host, pinned), §9 constraints (the ONNX runtime "lives in its own crate or a separate `saiife-ner` process"), §10 Q1 (which model is the owner's call).

## Plan rulings (refinements of spec [call]s)

- **R46-1 Separate process.** `saiife-ner` is a separate binary and process (spec §9 allows either; the process also gives the model parser its own sandbox: an ONNX file is untrusted input to `tract`). Linux only in stage 1.
- **R46-2 Model family.** BERT-style WordPiece tokenization only (BERT, DistilBERT, ELECTRA; cased or uncased), BIO or IOB2 labels with `PER`/`ORG`/`LOC`/`MISC` (case-insensitive; Danish/Scandinavian label names `PER`, `ORG`, `LOC`, `MISC` as used by ScandiNER-style models). SentencePiece models (XLM-R) are out of stage 1. `labels.json`: `{"id2label": {"0": "O", "1": "B-PER", …}, "do_lower_case": false, "max_len": 512, "inputs": ["input_ids", "attention_mask"] | [… , "token_type_ids"], "strip_accents": false}`; unknown keys refuse.
- **R46-3 Which model** is the owner's (spec §10 Q1, open). Nothing is compiled in: until `[blind.ner]` is set, plan 48's `ask` refuses with `no name detector is set up: saiife blind init sets one (the model is pinned in [blind.ner])` (fail closed). The smoke fragment takes the owner's URLs and hashes. Owner shortlist to check (licence and size first): ScandiNER (`saattrupdan/nbailab-base-ner-scandi`, MIT, Danish/Norwegian/Swedish/Icelandic/Faroese + English; ~700 MB at fp32, so an int8 or fp16 export is needed to reach the spec's ~100 MB; tract's support for the quantized ops must be checked in the smoke), or a multilingual DistilBERT NER fine-tune with a commercial-use licence that covers Danish.
- **R46-4 Protocol `saiife-ner/1`** (newline-delimited JSON, one object per line, ≤ 65 536 bytes per line): helper → `{"t":"hello","proto":1,"version":"<CARGO_PKG_VERSION>","labels":["PER","ORG","LOC","MISC"]}` once the model is loaded; daemon → `{"op":"detect","id":<u64>,"text":"…"}` (text ≤ 8 192 bytes); helper → `{"t":"spans","id":…,"spans":[{"start":…,"end":…,"label":"PER","score":0.97}]}` or `{"t":"error","id":…,"error":"<≤ 256 chars, no input text>"}`. Byte offsets into the request text, on char boundaries. Unknown fields refuse (`deny_unknown_fields`). The helper never logs or echoes request text.
- **R46-5 Long text.** Token windows of `max_len − 2` with a stride of half a window; a span found in two windows is kept once (first window wins on overlap). Words are re-joined from WordPiece pieces (`##`) and a span is the union of a `B-X` and following `I-X` words; a stray `I-X` starts a span (IOB1 tolerance). Score = mean softmax probability of the span's first-piece labels.
- **R46-6 Sandbox.** Before loading: `apply_rlimits(cpu 0 = unlimited for a long-lived helper; AS 4 GiB; NOFILE 32)`, then `confine_helper(&[model, vocab, labels], &[])`, then the helper re-hashes the three files (sha256 against `--sha256-model/--sha256-vocab/--sha256-labels` args) before parsing them. Exec, sockets and every other path are denied as for the calculator (plan 45 R45-12).

## Global Constraints

- **Tokio-free.** `saiife-shield-ner` has no tokio (`ci.yml:208` gate gets `-p saiife-shield-ner`). `cargo tree -e normal -p saiife | grep -c tract` = 0 (new CI step).
- **Dependencies** pinned with `=` and older than 14 days: `tract-onnx =0.23.9` (2026-10-15; `0.23.10` is from 2026-11-05 and too new). `[lints] workspace = true` (no unsafe in our code).
- **Tests fully offline with fakes:** the tract test builds a tiny synthetic ONNX graph in code (no model file checked in, no download); the protocol and client tests use `saiife-fake-ner`. The real model is owner smoke only. Danish names (æ, ø, å) in fixtures.
- **No token-shaped literals.**
- **Every task** (worktree `.worktrees/p46`, branch `shield-p46` off `shield-dev`): plan 43's commands with `TMPDIR` named `p46-tN-…`; crates `saiife-shield-ner`, `saiife-shield`, `saiife-system` as touched; `bash scripts/check-windows.sh -p <crates>` (the crate's binaries are `cfg(target_os = "linux")` with a stub `main` that prints `saiife-ner runs on Linux only` and exits 2). Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit staging, no push, smoke `bash -n` only. tract builds slowly: build it once with `-j 4` and keep the single target dir.

### Fixed values

| Name | Value |
|---|---|
| helper path | `/usr/libexec/saiife/saiife-ner` (`saiife_system::layout::NER_HELPER`) |
| protocol | `saiife_shield::ner_proto::PROTO = 1`, `MAX_LINE = 65_536`, `MAX_TEXT = 8_192`, `MAX_ERROR = 256` |
| hello timeout | 60 s (model load); answer timeout 5 s per request (plan 47) |
| args | `saiife-ner --model <path> --vocab <path> --labels <path> --sha256-model <hex> --sha256-vocab <hex> --sha256-labels <hex>` |

## Review Focus

1. **A hostile or broken model file** (truncated ONNX, a graph with unsupported ops, a 4 GiB tensor). Expected: the helper exits with an `error` hello replacement (`{"t":"error","id":0,…}`) or a non-zero exit before hello; nothing outside the three files was readable; the daemon (plan 47) reports "name detector unavailable" and `ask` refuses (Task 2: `broken_model_refuses`; Task 3: `helper_refuses_bad_hash`).
2. **Danish letters and offsets** (`"Hvad skylder Åse Østergård?"`, combining accents, emoji before the name). Expected: spans on char boundaries with byte offsets that slice the original text exactly (Task 1: `offsets_survive_normalization`).
3. **A question longer than one window.** Expected: names in the second window are found, none twice (Task 1: `windows_overlap_once`).
4. **The helper echoing input** into stderr or an error line. Expected: never (Task 3: `errors_never_echo_text`).
5. **`tract` ending up in the `saiife` binary** through a stray dependency. Expected: CI fails (Task 4 gate).

---

### Task 1: protocol types, the WordPiece tokenizer and BIO decoding (size M)

**Files:**
- Fill: `crates/shield/src/ner_proto.rs`
- Create: `crates/shield-ner/Cargo.toml`, `crates/shield-ner/src/lib.rs`, `crates/shield-ner/src/wordpiece.rs`, `crates/shield-ner/src/bio.rs`, `crates/shield-ner/src/labels.rs`

**Interfaces:**
- Produces (`saiife_shield::ner_proto`):
```rust
pub const PROTO: u32 = 1; pub const MAX_LINE: usize = 65_536; pub const MAX_TEXT: usize = 8_192; pub const MAX_ERROR: usize = 256;
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)] pub enum Request { Detect { id: u64, text: String } }
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)] pub enum Answer { Hello { proto: u32, version: String, labels: Vec<String> }, Spans { id: u64, spans: Vec<WireSpan> }, Error { id: u64, error: String } }
pub struct WireSpan { pub start: usize, pub end: usize, pub label: String, pub score: f32 }
pub fn encode<T: Serialize>(v: &T) -> Vec<u8>;                         // one line + '\n'
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, String>;  // refuses > MAX_LINE
impl WireSpan { pub fn to_span(&self, text: &str) -> Option<NameSpan> }  // checks bounds and char boundaries; maps PER/ORG/LOC/MISC to SpanLabel
```
- Produces (`saiife_shield_ner`):
```rust
pub struct LabelsFile { pub id2label: BTreeMap<u32, String>, pub do_lower_case: bool, pub max_len: usize, pub inputs: Vec<String>, pub strip_accents: bool }
pub fn parse_labels(bytes: &[u8]) -> Result<LabelsFile, NerError>;
pub struct WordPiece { /* vocab: HashMap<String, u32>, unk, cls, sep, pad ids */ }
impl WordPiece { pub fn from_vocab(bytes: &[u8], lower: bool, strip_accents: bool) -> Result<WordPiece, NerError>; pub fn encode(&self, text: &str) -> Encoding; }
pub struct Encoding { pub ids: Vec<i64>, pub word_of_piece: Vec<Option<usize>>, pub words: Vec<(usize, usize) /* byte range in text */> }
pub fn windows(enc: &Encoding, max_len: usize) -> Vec<(usize, usize)>;   // R46-5, piece ranges
pub fn decode_bio(enc: &Encoding, labels: &[String], probs_per_piece: &[(usize /* label id */, f32)]) -> Vec<WireSpan>;
#[derive(thiserror::Error)] pub enum NerError { #[error("bad labels file: {0}")] Labels(&'static str), #[error("bad vocab file")] Vocab, #[error("model: {0}")] Model(String), #[error("hash mismatch for {0}")] Hash(&'static str) }
```
  Basic tokenization as BERT's: split on whitespace, split punctuation into its own words, optional lower-case and accent strip (NFD minus combining marks), then greedy longest-match WordPiece with `##`; a word over 100 chars is `[UNK]`.

- [ ] **Step 1: Write the failing tests:** `proto_round_trip` (each variant; unknown field refused; `MAX_LINE + 1` refused), `wordpiece_vocab` (a tiny synthetic vocab in the test: `[PAD] [UNK] [CLS] [SEP] hvad skylder s ##ø ##ren å ##se ?` → ids and word ranges for `"Hvad skylder Søren?"` with `lower = true`), `offsets_survive_normalization` (`"Hvad skylder Åse Østergård?"` and a decomposed `"A\u{030a}se"`: every word range slices the original), `bio_spans` (pieces labelled `B-PER I-PER O B-LOC` → two spans with the right byte ranges; a stray `I-ORG` starts a span), `windows_overlap_once` (a 1 200-piece encoding with `max_len 512` → windows overlapping by half; a name in the overlap appears once after `decode_bio` over the merged probabilities), `labels_file_rules` (missing `id2label` refused, unknown key refused).
- [ ] **Step 2: Run** `cargo test -p saiife-shield ner_proto -p saiife-shield-ner` → FAIL.
- [ ] **Step 3: Implement** (crate deps: `saiife-shield`, `serde`, `serde_json`, `thiserror`, `unicode-normalization =0.1.25`, `sha2`; `tract-onnx` is added in Task 2).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield-ner): the saiife-ner protocol, WordPiece and BIO decoding (plan 46 T1)`.

### Task 2: the tract runtime (size M)

**Files:** Create `crates/shield-ner/src/model.rs`; Modify `crates/shield-ner/Cargo.toml` (`tract-onnx = "=0.23.9"`); Test: `crates/shield-ner/tests/model.rs`

**Interfaces:**
- Consumes: Task 1.
- Produces:
```rust
pub struct NerModel { /* tract runnable plan, WordPiece, LabelsFile */ }
impl NerModel {
    pub fn load(model: &[u8], vocab: &[u8], labels: &[u8]) -> Result<NerModel, NerError>;   // bytes already hash-checked by the caller
    pub fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError>;
    pub fn labels(&self) -> Vec<String>;                                                     // distinct entity types, for the hello
}
```
  Load with tract's documented flow for 0.23.x (`tract_onnx::onnx().model_for_read(&mut &bytes[..])` → input facts `i64` of shape `[1, S]` with a symbolic `S` for each input named in `labels.inputs` → `into_optimized()` → `into_runnable()`; confirm the exact names against the 0.23.9 docs and its BERT example and note them in the task report). Output: the first output, `[1, S, num_labels]` logits; softmax per piece.

- [ ] **Step 1: Write the failing tests:** `synthetic_graph_tags_tokens` (the test builds a `tract_onnx::pb::ModelProto` in code: inputs `input_ids [1,S] i64` and `attention_mask [1,S] i64`, a `Gather` of an initializer `E[V, L]` (one-hot rows chosen so the vocab ids of `søren`/`##ø…` map to `B-PER`/`I-PER`, `aarhus` to `B-LOC`, everything else to `O`) giving `logits [1,S,L]`, serialized with `prost::Message::encode_to_vec` through tract's re-export; `NerModel::load` + `detect("Hvad skylder Søren i Aarhus?")` → PER `Søren`, LOC `Aarhus`), `token_type_ids_input` (the same graph with a third input that it ignores, `inputs` naming it), `broken_model_refuses` (truncated bytes → `NerError::Model`, no panic), `labels_mismatch_refuses` (`id2label` with fewer entries than the output's last dimension → `Model`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield-ner): ONNX token classification with tract (plan 46 T2)`.

### Task 3: the `saiife-ner` helper and the fake helper (size M)

**Files:**
- Create: `crates/shield-ner/src/serve.rs`, `crates/shield-ner/src/bin/saiife-ner.rs`, `crates/shield-ner/src/bin/saiife-fake-ner.rs` (`[[bin]] required-features = ["fake"]`), `crates/shield-ner/tests/helper.rs`

**Interfaces:**
- Consumes: Tasks 1–2; plan 45 Task 7 `confine_helper`, `apply_rlimits`.
- Produces:
```rust
pub trait Detect { fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError>; fn labels(&self) -> Vec<String>; }
impl Detect for NerModel {}
pub fn serve(d: &dyn Detect, input: &mut dyn BufRead, output: &mut dyn Write) -> io::Result<()>;   // hello first, then one answer per request until EOF; a bad line answers Error{id: 0} and continues; > MAX_TEXT answers Error
pub struct PhraseDetector { pub phrases: Vec<(String, String /* label */)> }                       // the fake: exact, case-insensitive phrase matches
impl PhraseDetector { pub fn from_file(p: &Path) -> io::Result<PhraseDetector> /* lines "PER<TAB>Søren Ærø" */ }
```
  `saiife-ner` main: parse args (R46-4 fixed values), `apply_rlimits`, `confine_helper(&[model, vocab, labels], &[])`, read the three files, sha256-check each against its arg (mismatch → stderr `hash mismatch for model` and exit 3, before parsing), `NerModel::load`, `serve(stdin, stdout)`. A load failure writes `{"t":"error","id":0,"error":"cannot load the model"}` and exits 4. `saiife-fake-ner --phrases <file>`: same protocol, `PhraseDetector`, confined the same way.

- [ ] **Step 1: Write the failing tests:** `serve_hello_then_spans` (in-process `serve` with `PhraseDetector`: hello, then two requests answered in order with ids), `serve_bad_line_continues`, `oversize_text_errors`, `errors_never_echo_text` (a request whose text is a rare fixture name and that fails: neither stdout nor stderr of the fake helper process holds it), `helper_refuses_bad_hash` (spawns `CARGO_BIN_EXE_saiife-ner` with three small files and a wrong `--sha256-model` → exit 3, no hello, nothing parsed), `fake_helper_end_to_end` (spawn `saiife-fake-ner` with a phrases file: Danish name found with correct byte offsets).
- [ ] **Step 2: Run** `cargo test -p saiife-shield-ner --features fake` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield-ner): the sandboxed saiife-ner helper and its fake (plan 46 T3)`.

### Task 4: layout, packaging, CI gates and the smoke fragment (size S)

**Files:**
- Modify: `crates/system/src/layout.rs:58` (add `pub const NER_HELPER: &str = "/usr/libexec/saiife/saiife-ner";` beside `FIDO_HELPER`), `packaging/linux/nfpm.yaml:37-39` (a `saiife-ner` entry like `saiife-fido`, mode 0755), `crates/system/tests/packaging.rs:12,101` (assert the new dst), `.github/workflows/ci.yml` (build `-p saiife-shield-ner --release` on ubuntu; the `tract`-not-in-`saiife` gate; the tokio gate list), `scripts/package-linux/*` (stage the binary next to `saiife-fido`; read the script first and follow its pattern), `docs/data-shield.md` (a "Name detector" section: what it is, where the helper lives, that the model is pinned in `[blind.ner]`; plan 48 Task 7 writes the rest of the page)
- Create: `scripts/blind-smoke.d/40-ner.sh`

- [ ] **Step 1: Write the failing test:** `packaging.rs` `ner_helper_is_packaged` (nfpm has `dst: /usr/libexec/saiife/saiife-ner`; `layout::NER_HELPER` equals it).
- [ ] **Step 2: Run** `cargo test -p saiife-system --test packaging` → FAIL. **Step 3: Implement**; `40-ner.sh`: `smoke_ner` needs `SAIIFE_BLIND_SMOKE_NER_MODEL_URL`, `…_VOCAB_URL`, `…_LABELS_URL` and the three `…_SHA256` values (the owner's Q1 choice; the fragment refuses to run without them), downloads with `curl --fail --proto =https` into the smoke work dir, checks the hashes, runs the release `saiife-ner` on 20 fixed English and Danish questions (names of synthetic people, Danish letters, a typo, a nickname, a question with no names) and prints recall/precision against the expected spans, plus load time, RSS and per-question latency.
- [ ] **Step 4: Run** → PASS; `bash -n scripts/blind-smoke.d/40-ner.sh`; `cargo tree -e normal -p saiife | grep -c tract` → `0`.
- [ ] **Step 5: Commit** `build(shield-ner): package saiife-ner, CI gates, the ner smoke (plan 46 T4)`.

---

## Owner smoke fragment (plan 46)

`scripts/blind-smoke.d/40-ner.sh` (`bash scripts/blind-smoke.sh --only ner`): the owner's pinned model (Q1), downloaded and hash-checked, recall/precision on 20 fixed en/da questions, memory and latency. Builders: `bash -n` only. Packaging the helper into the deb/rpm in a release is an owner release step.

## Stage-1 dependency and parallel map (plans 43–48)

```
W1  43.T1 crate + shared types
W2  43.T2 policy/touch · 43.T3 snapshot · 44.T1 lang · 44.T2 stand-ins/sessions · 45.T1 validator · 46.T1 tokenizer · 46.T2 tract runtime
W3  43.T4 classify · 43.T5 lexicon · 43.T6 index · 44.T4 synthetic rows (needs 43.T4) · 45.T2 preview · 45.T4 templates · 45.T5 checker (need 44.T1) · 45.T3 executor (needs 43.T3) · 45.T6 approved methods
W4  43.T7 dataset build · 44.T3 parameterize (needs 43.T5) · 45.T7 calculator process + sandbox (needs 45.T3)
W5  44.T5 envelope + firewall (needs 43.T6, 44.T3, 44.T4) · 46.T3 helper binary (needs 45.T7 sandbox) · 46.T4 packaging
W6  47.T1 then 47.T2–T6 in parallel, then 47.T7   (needs all of 43, 44.T2, 44.T5, 45.T7, 46.T3)
W7  48.T1 → 48.T2 → 48.T3; 48.T4/T5 after 48.T3; 48.T6 after 48.T5; 48.T7 last
```
