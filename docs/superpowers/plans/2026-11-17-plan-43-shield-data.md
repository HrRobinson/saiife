# Plan 43: Data Shield core I, the data side (stage 1): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new tokio-free crate `saiife-shield` that turns a CSV, xlsx or SQLite file (and, through the daemon in plan 47, a Postgres table) into a per-dataset directory: a read-only SQLite snapshot, column classes with the k-floor public values, a local lexicon for entity resolution and "did you mean", and the on-disk keyed-hash known-value index; plus the `[blind]` policy and the six `blind:*` touch classes everything else uses.

**Architecture:** `crates/shield` holds pure logic and file formats only (no sockets, no tokio, no vault). Every later Data Shield plan (44–48) builds on the types declared in Task 1. A dataset build always writes into `stage/` and replaces `live/` with one `rename` when every part is done, so nothing ever reads a half-built snapshot or index (spec §2.1.1). Policy (`[blind]`, `[[blind.dataset]]`) lives in `crates/policy`, merged from `policy.d/` like `[services.*]`; it is left out of the serialised config while empty, so today's policy hashes do not change.

**Tech Stack:** Rust 2021; new pinned crates (all older than 14 days on 2026-11-17, cut-off 2026-11-03): `rusqlite = { version = "=0.41.1", features = ["bundled"] }` (2026-10-28, MIT; bundled SQLite C, ~1 min build, no C++), `csv = "=1.4.0"` (2025-10-17, Unlicense/MIT), `calamine = "=0.37.0"` (2026-10-18, MIT, pure Rust). Already in `Cargo.lock`: `ring =0.17.14` (HMAC-SHA-256), `unicode-normalization =0.1.25`, `strsim =0.11.1`, `serde`, `serde_json`, `thiserror`, `getrandom`.

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` (owner-approved 2026-11-17) §2.1.1–2.1.6, §2.2.5 (index), §6.5, §8 stage 1, §9 Constraints, §11. Read §1.3 and §9 anti-goals first.

**Stage-1 plan set:** 43 data (this) · 44 question and firewall · 45 method, calculator and checker · 46 name detector · 47 daemon core · 48 ask flow and CLI. The cross-plan map is at the end of this file and repeated in each plan.

## Plan rulings (refinements of spec [call]s, ledgered here)

- **R43-1 Crate name** `saiife-shield`, path `crates/shield`, lib `saiife_shield`. `[lints] workspace = true` (no unsafe). Added to the CI tokio gate (`.github/workflows/ci.yml:208`).
- **R43-2 Dataset names** `^[a-z][a-z0-9-]{0,31}$`. Table and column names in the snapshot are the source's names lower-cased, non `[a-z0-9_]` turned into `_`, made unique with `_2`, `_3`; the original name is kept in the manifest for display only.
- **R43-3 Snapshot format:** one SQLite file `snapshot.sqlite`, `PRAGMA journal_mode=OFF`, written once, then `chmod 0400`. Column types: `INTEGER`, `REAL`, `TEXT`, `DATE` (stored as ISO `TEXT`, declared type `DATE`), `BOOL` (stored 0/1, declared `BOOL`). Type inference: a column is INTEGER/REAL/DATE/BOOL when every non-empty cell parses as that type (dates: `YYYY-MM-DD`, `DD-MM-YYYY`, `DD.MM.YYYY`, `DD/MM/YYYY`; xlsx date cells), else TEXT. Empty cell = NULL. Each table gets the hidden column `_rowid INTEGER PRIMARY KEY`. The snapshot hash is `sha256:` of the file bytes after the final close.
- **R43-4 Source limits:** at most 64 tables, 512 columns per table, 50 000 000 rows per table, 64 KiB per cell (longer refuses the import, naming table and column, never the value), files at most 16 GiB. Over a limit is an error, never a truncation.
- **R43-5 Classifier rules** (Task 4) and **"uncertain"** = the classifier's top guess has confidence < 0.8, or the guess is `public` (public is never applied without the user, spec §2.1.2 [owner]).
- **R43-6 Lexicon** is a second local SQLite file `lexicon.sqlite` (0400) with plaintext normalized names and literal values: it never leaves the daemon and lives beside the snapshot, which holds the same values. The known-value index (spec §2.2.5) is the keyed-hash file pair `index.bin` / `index.bloom` and is the only structure the firewall uses.
- **R43-7 Normalization** for names and values: NFKD, drop combining marks, but map `æ→ae`, `ø→oe`, `å→aa`, `ß→ss` first (so `Søren`/`Soeren`/`Soren`... see Review Focus 3), lower-case, every run of non-alphanumerics to one space, trim. Name order: a person name's tokens are also indexed sorted (`berg anna` = `anna berg`). Initials (`a berg`) are not expanded in stage 1.
- **R43-8 "Did you mean"** (spec §2.1.7 [call: method]): Damerau-Levenshtein (`strsim::damerau_levenshtein`) on normalized full names; a candidate qualifies when distance ≤ 2 **and** ≤ 25 % of the query's length (rounded down, minimum 1); the suggestion is given only when exactly one distinct normalized name has the smallest distance. Search space: names sharing the first 2 characters of any token with the query (an index on token prefixes), capped at 50 000 candidates per lookup; over the cap gives no suggestion (refusal), never a guess.
- **R43-9 Index layout:** `index.bin` = 32-byte header (`magic "SAIIFEKI"`, u32 version 1, u64 entry count, 12 bytes zero) then sorted 16-byte entries `HMAC-SHA-256(index_key, domain ‖ 0x00 ‖ normalized)[..16]`; `index.bloom` = header (`"SAIIFEKB"`, u32 version, u64 bits, u32 hash count) then the bit array; 20 bits per entry, 14 hashes (false-positive rate about 1e-4), hashes from double hashing on bytes 0..8 and 8..16 of the entry. Lookup: bloom, then binary search with `FileExt::read_exact_at` (no mmap: mmap needs `unsafe`). `domain` is `n` for names and identifier/quasi values, `p` for free-text phrases. 30 M entries = 480 MB + 75 MB; the build sorts in 64 MB runs written to `stage/` and k-way merges them.
- **R43-10 Frequency floor** (spec §2.2.5 [owner]): an identifier or quasi value enters the index only if it occurs in ≤ k records of its column (k from the dataset policy). Free-text cells are split into phrases at `. ! ? ; \n` and each phrase of 3 to 40 tokens enters whole (domain `p`). Schema words, aliases and k-floor public values are written to `allow.json` in the dataset dir and never enter the index.
- **R43-11 Policy layout:** the global block `[blind]` (k default, list cap, session minutes, `[blind.ner]`, `[blind.cloud]`) and the dataset blocks `[[blind.dataset]]` may be in `config.toml` or any drop-in; the global scalars and each sub-table may be set in only one file (a second is `Invalid`, naming both files), dataset names are unique across files. `mode` accepts only `"exact"` in stage 1 (`"judgment"` is `Invalid: judgment mode is a later stage`).
- **R43-12 Touch classes:** the six `blind:*` classes (spec §2.1.4) are added to `saiife_touch::TouchClass` now. All need user verification (`needs_uv() == true`). Stage 1 issues `blind:name`, `blind:approve`, `blind:keys`, `blind:loosen` (plan 48); `blind:release` and `blind:reveal` exist for the audit vocabulary and plan 48's refusal text, but no stage-1 path sends a real value (exact mode, spec §3.1), so they are never issued.

## Global Constraints

- **Tokio-free core.** `saiife-shield` has no tokio, no network, no vault, no process spawning. `cargo tree -e normal -p saiife-shield | grep -c tokio` = 0 (added to the CI gate `ci.yml:208`).
- **Dependencies** pinned with `=` to versions older than 14 days at build time; prefer what `Cargo.lock` has. New in this plan: `rusqlite =0.41.1` (bundled), `csv =1.4.0`, `calamine =0.37.0`. Each is reviewed for C/C++ build cost in the task report (rusqlite: bundled SQLite C only).
- **ONNX runtime (plan 46, recorded in every plan):** `tract-onnx = "=0.23.9"` (2026-10-15, MIT OR Apache-2.0, pure Rust, no C++, no download at build time), in its own crate `crates/shield-ner` and its own helper binary `saiife-ner`, never linked into `saiife`. `ort` was rejected: its 2.x line is release-candidate only, it links Microsoft's C++ ONNX Runtime (MIT) and downloads a prebuilt ~20 MB library at build time (network in the build, a C++ artifact outside the pinned lock).
- **Tests fully offline with fakes.** No network, no real model, no real API key, no sudo, no docker. Fixtures are synthetic and generated in code; they include Danish names with æ, ø, å (`Søren Ærø`, `Åse Østergård`) and Danish number words. No real personal data anywhere in the repo.
- **No token-shaped literals** in code or tests; build fake keys and tokens with `concat!`.
- **Every task** (worktree `.worktrees/p43`, branch `shield-p43` off `shield-dev`):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p43-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
  cargo test -p <crates touched> -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  bash scripts/check-windows.sh -p <crates touched>
  ```
  Remove `$TMPDIR` by its literal path at the end. Never commit `.superpowers/`. Stage explicit paths. Commit trailer exactly `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push. Smoke scripts: `bash -n` (and shellcheck if installed) only; builders never run them.

### Fixed values

| Name | Value |
|---|---|
| default k | `10` (`[blind] k`, per dataset override `k`, minimum 2) |
| default list cap | `100` (`[blind] list_cap`, 1..=10 000) |
| default session | `30` minutes (`[blind] session_minutes`, 5..=480) |
| dataset dir | `<root>/<name>/{stage,live}/`, files `snapshot.sqlite`, `lexicon.sqlite`, `index.bin`, `index.bloom`, `allow.json`, `manifest.json` |
| rows bands | `<100`, `about 100`, `about 1 thousand`, … one significant figure: `about 3 million` |
| entity words | `[[blind.dataset.entity]] word` (en) and `word_da` (da), defaults `record` / `post` |

## Review Focus

1. **A partial build reached by a reader** (crash, disk full or kill in the middle of a refresh). Expected: `live/` is the old complete set or the new complete set, never a mix; a leftover `stage/` is deleted at the next build (Task 7: `interrupted_build_leaves_live_intact`, `stale_stage_is_removed`).
2. **A cell or column name holding a real value lands in an error message or the manifest** (a CSV with a malformed row where the bad cell is a name). Expected: errors name file, table, column and row number only (Task 3: `errors_never_quote_cells`).
3. **Danish spelling variants and order** ("Søren Ærø" asked as "Soeren Aeroe", "Ærø, Søren", "soren aero"). Expected: the first two resolve to the same key; "soren aero" is not equal but is the one "did you mean" suggestion (Task 5: `danish_variants_resolve`, `danish_ascii_fold_is_suggested`).
4. **A `public` mark on a column that holds names, IDs or amounts** (the user marks `customers.email` public at init). Expected: refused with the classifier's reason; no k-floor list is computed for it (Task 4: `public_refused_for_identifiers_and_amounts`).
5. **Common values in the index** (a first name in 40 000 records, a large city). Expected: not in the index (frequency floor), while a value in 3 records is (Task 6: `frequency_floor_excludes_common_values`).

---

### Task 1: the `saiife-shield` crate and the shared vocabulary (size S)

**Files:**
- Create: `crates/shield/Cargo.toml`, `crates/shield/src/lib.rs`, `crates/shield/src/schema.rs`, `crates/shield/src/ner.rs`, `crates/shield/src/error.rs`, and empty module files for the later plans: `norm.rs source.rs snapshot.rs classify.rs public.rs lexicon.rs index.rs dataset.rs` (this plan), `lang.rs standin.rs session.rs question.rs synth.rs envelope.rs firewall.rs` (plan 44), `plan.rs sql.rs preview.rs calc.rs calc_proto.rs template.rs checker.rs methods.rs` (plan 45), `ner_proto.rs` (plan 46). Each empty file holds one `//!` line naming its plan, so parallel plans add no module declarations.
- Modify: `.github/workflows/ci.yml:208` (add `-p saiife-shield`), `Cargo.toml` (workspace members are `crates/*`: nothing to add).

**Interfaces:**
- Produces (`saiife_shield::schema`):
```rust
pub struct DatasetName(String);            // R43-2; impl FromStr (Err = ShieldError::BadName), Display, Serialize/Deserialize as string
#[serde(rename_all = "snake_case")] pub enum ColumnClass { Identifier, Quasi, Sensitive, FreeText, Public }
impl ColumnClass { pub fn strictness(self) -> u8 /* Public 0, Quasi 1, Identifier 2, FreeText 3, Sensitive 4 */ ; pub fn is_looser_than(self, o: ColumnClass) -> bool }
#[serde(rename_all = "lowercase")] pub enum ColType { Integer, Real, Text, Date, Bool }
pub struct ColumnInfo { pub name: String, pub ty: ColType, pub class: ColumnClass, pub alias: Option<String> }
pub struct TableInfo { pub name: String, pub alias: Option<String>, pub rows: u64, pub columns: Vec<ColumnInfo> }
pub struct EntitySpec { pub table: String, pub key: String, pub names: Vec<String>, pub show: Vec<String>, pub word: String, pub word_da: String }
pub struct Schema { pub dataset: DatasetName, pub tables: Vec<TableInfo>, pub entities: Vec<EntitySpec> }
impl Schema { pub fn table(&self, t: &str) -> Option<&TableInfo>; pub fn column(&self, t: &str, c: &str) -> Option<&ColumnInfo>; pub fn entity_for(&self, table: &str) -> Option<&EntitySpec>; pub fn cloud_name(&self, t: &str, c: Option<&str>) -> String /* alias or name */ }
pub fn rows_band(n: u64) -> String;        // fixed table above
#[serde(rename_all = "lowercase")] pub enum Lang { En, Da }
// The parameter vocabulary (spec §2.1.6, §2.3.1), shared by plans 44 (who fills it) and 45 (who checks and binds it):
pub struct Decimal { pub units: i128, pub scale: u8 }        // exact decimal; impl Decimal { pub fn parse_plain(s: &str) -> Option<Decimal>; pub fn to_plain(&self) -> String; pub fn round_half_even(&self, places: u8) -> Decimal } and Eq/Ord by value (1.50 == 1.5)
pub enum ParamType { Entity { table: String, word: String }, Amount, Integer, Percent, Date, DateRange, Text { table: String, column: String } }
impl ParamType { pub fn tag(&self) -> String /* "entity:customers", "amount", "date_range", "text:customers.city", … */ }
pub enum Bound { Keys(Vec<i64>), Amount(Decimal), Integer(i64), Percent(Decimal), Date(String), DateRange(String, String), Text(String) }
pub struct Param { pub name: String /* "p1" */, pub ty: ParamType, pub bound: Option<Bound>, pub display: String /* local only */ }
```
- Produces (`saiife_shield::ner`): the name-detector seam plan 44 calls and plan 46/47 implement:
```rust
#[serde(rename_all = "lowercase")] pub enum SpanLabel { Person, Org, Location, Misc }
pub struct NameSpan { pub start: usize, pub end: usize, pub label: SpanLabel }   // byte offsets into the question, on char boundaries
pub trait NameDetector: Send + Sync { fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError>; }
#[derive(thiserror::Error)] pub enum DetectError { #[error("the name detector is not available: {0}")] Unavailable(String), #[error("the name detector failed")] Failed }
pub struct ListDetector { /* test fake: exact phrases -> label */ }  impl ListDetector { pub fn new(entries: &[(&str, SpanLabel)]) -> Self }
```
- Produces (`saiife_shield::error`): `pub enum ShieldError { BadName, Source { file: String, table: Option<String>, column: Option<String>, row: Option<u64>, why: &'static str }, Limit(&'static str), Io(String), Sqlite(String), Corrupt(&'static str) }` with `thiserror` texts that never carry a cell value.

- [ ] **Step 1: Write the failing tests** in `schema.rs`/`ner.rs`: `dataset_names` (`crm`, `crm-2024` ok; `Crm`, `2crm`, `crm_x`, 33 chars refused), `class_strictness_order` (`Public.is_looser_than(Sensitive)`, not the reverse, `Identifier.is_looser_than(FreeText)`), `rows_band_values` (`0`→`<100`, `99`→`<100`, `100`→`about 100`, `3_041_227`→`about 3 million`, `1_500`→`about 2 thousand`), `class_serde_names` (`"free_text"`, `"public"`), `list_detector_finds_utf8_spans` (`ListDetector::new(&[("Søren Ærø", Person)])` on `"Hvad skylder Søren Ærø?"` gives start 13, end 25), `decimal_value_eq` (`1.50 == 1.5`, `parse_plain("-0.30")`, half-even `2.345 → 2.34`, `2.355 → 2.36`), `param_tags` (`entity:customers`, `text:customers.city`).
- [ ] **Step 2: Run** `cargo test -p saiife-shield` → FAIL (crate missing).
- [ ] **Step 3: Implement** the crate (`Cargo.toml`: deps `serde`, `serde_json`, `thiserror = "1"`, `ring = "=0.17.14"`, `unicode-normalization = "=0.1.25"`, `strsim = "=0.11.1"`, `getrandom = "0.3"`, `zeroize = "=1.9.1"`, `rusqlite`, `csv`, `calamine` as pinned above; `[lints] workspace = true`) and the types.
- [ ] **Step 4: Run** the tests → PASS; `cargo tree -e normal -p saiife-shield | grep -c tokio` → `0`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-shield` (if the stand-in C compiler cannot build bundled SQLite, gate `rusqlite` and the modules that use it behind `cfg(target_os = "linux")` with a stub `ShieldError::Unsupported` elsewhere, and say so in the report).
- [ ] **Step 5: Commit** `feat(shield): the saiife-shield crate and its shared types (plan 43 T1)`.

### Task 2: `[blind]` policy and the `blind:*` touch classes (size M)

**Files:**
- Create: `crates/policy/src/blind.rs`
- Modify: `crates/policy/src/lib.rs:10-25` (`pub mod blind;` and re-exports), `crates/policy/src/system.rs:17-62` (field `blind`), `crates/policy/src/load.rs:77-101` (`DropIn` gets `blind`), `crates/policy/src/load.rs:160-213` (merge), `crates/policy/src/load.rs:246-250` (validate), `crates/touch/src/action.rs:14-55` (six classes), `crates/touch/src/action.rs:187` (`ALL` grows to 14)

**Interfaces:**
- Produces (`saiife_policy::blind`, re-exported from `saiife_policy`):
```rust
#[serde(deny_unknown_fields)] pub struct BlindCfg {
    pub k: Option<u32>, pub list_cap: Option<u32>, pub session_minutes: Option<u32>,
    pub outbox_days: Option<u32>,                // default 365
    pub ner: Option<NerCfg>, pub cloud: Option<CloudModelCfg>,
    #[serde(default)] pub dataset: Vec<BlindDataset>,
}
impl BlindCfg { pub fn is_default(&self) -> bool; pub fn k_for(&self, d: &BlindDataset) -> u32; pub fn list_cap(&self) -> u32; pub fn session(&self) -> Duration; pub fn validate(&self) -> Result<(), String> }
#[serde(deny_unknown_fields)] pub struct NerCfg { pub model_url: String, pub model_sha256: String, pub vocab_url: String, pub vocab_sha256: String, pub labels_url: String, pub labels_sha256: String, pub max_bytes: Option<u64> /* default 1 GiB */ }
#[serde(deny_unknown_fields)] pub struct CloudModelCfg { pub secret: String /* vault token secret allowing service "blind-model" */, pub model: Option<String> /* default "claude-opus-5-5" */ }
#[serde(deny_unknown_fields)] pub struct BlindDataset {
    pub name: String, pub source: BlindSource, #[serde(default)] pub users: Vec<String>, #[serde(default)] pub approvers: Vec<String>,
    #[serde(default = "exact")] pub mode: String, pub k: Option<u32>, #[serde(default)] pub preview_required: bool,
    pub list_cap: Option<u32>, #[serde(default)] pub tables: BTreeMap<String, TableCfg>, #[serde(default)] pub columns: BTreeMap<String, ColumnCfg> /* "table.column" */,
    #[serde(default)] pub entity: Vec<EntityCfg>,
}
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)] pub enum BlindSource { Csv { file_name: String }, Xlsx { file_name: String }, Sqlite { file_name: String }, Postgres { host: String, port: Option<u16>, dbname: String, user: String, password_secret: String, tables: Vec<String> } }
pub struct TableCfg { pub alias: Option<String> }
pub struct ColumnCfg { pub class: String /* the five class names */, pub alias: Option<String> }
pub struct EntityCfg { pub table: String, pub key: String, pub names: Vec<String>, #[serde(default)] pub show: Vec<String>, pub word: Option<String>, pub word_da: Option<String> }
```
  Validation (`BlindCfg::validate`, called from `load_system_with` after `cfg.audit.validate()`, `load.rs:246-248`): dataset name per R43-2; unique names; `mode == "exact"`; `k ≥ 2`; class strings are the five names; `users`/`approvers` entries as `ApprovalCfg::check_approvers` (`system.rs:411`); every `columns` key is `table.column`; Postgres `host` is a Unix socket path (starts with `/`) or `localhost`/`127.0.0.1`/`::1` (R47-4: no TLS client in stage 1; anything else is `Invalid: remote Postgres needs TLS, which is a later stage`); the sha256 fields are 64 lowercase hex; `model_url`/`vocab_url`/`labels_url` start with `https://`.
- Produces (`saiife_touch::TouchClass`): `BlindRelease "blind:release"`, `BlindReveal "blind:reveal"`, `BlindKeys "blind:keys"`, `BlindLoosen "blind:loosen"`, `BlindApprove "blind:approve"`, `BlindName "blind:name"`; `needs_uv()` true for all six.

- [ ] **Step 1: Write the failing tests:** policy `blind_absent_keeps_hash` (the hash of a config without `[blind]` equals today's pinned value in `effective.rs` tests: `SystemConfig.blind` is `#[serde(default, skip_serializing_if = "BlindCfg::is_default")]`, as `workspace` is at `system.rs:40-41`), `blind_dataset_in_dropin` (a drop-in `policy.d/blind-crm.toml` with one `[[blind.dataset]]` loads; a second file with `name = "crm"` is `Invalid` naming both files), `blind_global_once` (`[blind.ner]` in two files is `Invalid`), `blind_judgment_refused`, `blind_remote_postgres_refused`, `blind_bad_class_refused` (`class = "secret"`), `blind_changes_hash` (adding a dataset changes the policy hash); touch `class_names_round_trip` over the grown `ALL`, `blind_classes_need_uv`.
- [ ] **Step 2: Run** `cargo test -p saiife-policy blind -p saiife-touch` → FAIL.
- [ ] **Step 3: Implement.** In the drop-in merge (`load.rs:160-213`): `cfg.blind.dataset.extend(d.blind.dataset)` with a name→file origin map as `scope_origin` does; for `k`, `list_cap`, `session_minutes`, `outbox_days`, `ner`, `cloud`: set if unset, else `Invalid("blind.<key> is already set in <first>")`. `blind` is not added to `CONFIG_ONLY` (`load.rs:61`).
- [ ] **Step 4: Run** the tests and `cargo test -p saiife-policy -p saiife-touch -p saiife-daemon touch` → PASS (the daemon's exhaustive matches on `TouchClass`, if any, get the new arms).
- [ ] **Step 5: Commit** `feat(policy,touch): [blind] policy and the blind:* touch classes (plan 43 T2)`.

### Task 3: sources and the snapshot (size L)

**Files:**
- Create/fill: `crates/shield/src/source.rs`, `crates/shield/src/snapshot.rs`, `crates/shield/examples/blind_fixture.rs`, `crates/shield/tests/fixtures.rs` (shared synthetic generator, `#[path]`-included by tests)

**Interfaces:**
- Consumes: Task 1 `ColType`, `ShieldError`.
- Produces:
```rust
// source.rs
pub enum Cell { Null, Int(i64), Real(f64), Text(String), Date(String /* ISO */), Bool(bool) }
pub struct SourceTable { pub name: String, pub columns: Vec<String> }
pub trait RowSource { fn tables(&self) -> Vec<SourceTable>; fn rows(&mut self, table: &str) -> Result<Box<dyn Iterator<Item = Result<Vec<Cell>, ShieldError>> + '_>, ShieldError>; }
pub struct CsvSource;  impl CsvSource { pub fn open(r: Box<dyn std::io::Read + Send>, file_name: &str) -> Result<CsvSource, ShieldError> }   // one table named after the file stem; delimiter sniffed among , ; \t from the first 64 KiB; UTF-8 or UTF-8 BOM, anything else refuses
pub struct XlsxSource; impl XlsxSource { pub fn open(r: std::fs::File, file_name: &str) -> Result<XlsxSource, ShieldError> }      // one table per sheet; row 1 is the header
pub struct SqliteSource; impl SqliteSource { pub fn open(path: &Path) -> Result<SqliteSource, ShieldError> }                      // opened `mode=ro&immutable=1`; user tables only (no sqlite_*), views skipped
pub struct VecSource { pub tables: Vec<(SourceTable, Vec<Vec<Cell>>)> }   // tests and the Postgres bridge (plan 47)
// snapshot.rs
pub struct SnapshotInfo { pub path: PathBuf, pub sha256: String, pub tables: Vec<(String /* snapshot name */, String /* source name */, u64 /* rows */, Vec<(String, String, ColType)>)> }
pub fn build_snapshot(src: &mut dyn RowSource, out: &Path, progress: &mut dyn FnMut(Progress)) -> Result<SnapshotInfo, ShieldError>;
pub struct Progress { pub table: String, pub rows_done: u64 }
pub fn open_ro(path: &Path) -> Result<rusqlite::Connection, ShieldError>;   // `file:<path>?mode=ro&immutable=1`, SQLITE_OPEN_READ_ONLY | URI | NO_MUTEX
```
  Type inference is two-pass (first pass over the source to infer, second to insert), so `RowSource::rows` is called twice per table; `CsvSource` and `XlsxSource` keep the bytes they need in memory only for xlsx (calamine reads the sheet), and CSV re-reads from a temp copy the source writes into the `out` dir's parent (removed at the end).
- `examples/blind_fixture.rs`: `cargo run -p saiife-shield --example blind_fixture -- --rows N --seed S --out DIR` writes `customers.csv` (`id,first_name,last_name,email,phone,city,postcode,birth_date,segment,credit_limit,ref_code`) and `invoices.csv` (`id,customer_id,amount,status,issued,notes`) with synthetic Danish and English names (fixed lists incl. `Søren`, `Åse`, `Ærø`, `Østergård`, `Anna`, `Berg`), `@example.invalid` emails, Danish CPR-shaped `ref_code` values with a valid modulus-11 check (synthetic, from the fixed seed). Same generator in `tests/fixtures.rs` for tests (small N).

- [ ] **Step 1: Write the failing tests** (`crates/shield/tests/snapshot.rs`): `csv_round_trip_types` (a 5-row CSV with `id,amount,issued,flag,name` → INTEGER, REAL, DATE, BOOL, TEXT; `SELECT amount FROM t WHERE id=3` gives the cell), `semicolon_csv_and_bom`, `xlsx_two_sheets_two_tables` (the xlsx is written by the test itself: a helper assembles the minimal OOXML parts (`[Content_Types].xml`, `xl/workbook.xml`, two sheets, shared strings) with the `zip` crate as a dev-dependency, pinned to the exact version `calamine =0.37.0` already pulls into the lock; no binary fixture is checked in), `sqlite_source_skips_views`, `names_are_cleaned` (`"Kunde Nr."` → `kunde_nr`, collision gets `_2`), `limits_refuse` (a 64 KiB + 1 cell refuses with `Limit`), `errors_never_quote_cells` (a ragged CSV row whose cell is `Søren Ærø`: the error's `Display` names the row number and not the name), `snapshot_is_read_only_and_hashed` (mode 0400, `sha256:` + 64 hex, `open_ro` refuses `INSERT`), `danish_text_survives` (æøå round-trip).
- [ ] **Step 2: Run** `cargo test -p saiife-shield --test snapshot` → FAIL.
- [ ] **Step 3: Implement** `source.rs`, `snapshot.rs` (`BEGIN; CREATE TABLE …; INSERT … ; COMMIT` with prepared statements, batches of 10 000 rows), the example.
- [ ] **Step 4: Run** → PASS; `cargo run -p saiife-shield --example blind_fixture -- --rows 1000 --seed 1 --out "$TMPDIR/fx"` writes the two files.
- [ ] **Step 5: Commit** `feat(shield): CSV, xlsx and SQLite sources and the read-only snapshot (plan 43 T3)`.

### Task 4: column classifier, public marks and the k-floor (size M)

**Files:** Create/fill: `crates/shield/src/classify.rs`, `crates/shield/src/public.rs`; Test: in-module tests plus `crates/shield/tests/classify.rs`

**Interfaces:**
- Consumes: Task 3 `open_ro`, `SnapshotInfo`; Task 1 types.
- Produces:
```rust
pub struct Guess { pub class: ColumnClass, pub confidence: f32, pub reason: &'static str }
pub struct ColumnStats { pub rows: u64, pub non_null: u64, pub distinct: u64, pub max_len: usize, pub numeric: bool }
pub fn stats(conn: &rusqlite::Connection, table: &str, column: &str, ty: ColType) -> Result<ColumnStats, ShieldError>;
pub fn guess(name: &str, ty: ColType, st: &ColumnStats, sample: &[String] /* ≤ 200 distinct values, read locally */) -> Guess;
pub fn uncertain(g: &Guess) -> bool;                                   // R43-5
pub fn public_refusal(name: &str, ty: ColType, st: &ColumnStats, sample: &[String]) -> Option<&'static str>;
pub struct PublicValues { pub column: String, pub passing: Vec<String>, pub total_distinct: u64 }
pub fn public_values(conn: &rusqlite::Connection, table: &str, column: &str, k: u32) -> Result<PublicValues, ShieldError>;
pub mod checks { pub fn email(s: &str) -> bool; pub fn iban(s: &str) -> bool /* mod-97 */; pub fn phone(s: &str) -> bool /* 8 digits DK, or +CC and 7-15 digits */; pub fn cpr(s: &str) -> bool /* DDMMYY-SSSS or DDMMYYSSSS, valid date; modulus-11 not required (post-2007 CPRs need not pass it) */; pub fn luhn(s: &str) -> bool; pub fn amount_name(col: &str) -> bool; }
```
  `guess` rules, first that holds: name matches an identifier word (`name navn first_name fornavn last_name efternavn email mail phone telefon tlf cpr ssn national_id customer_no kundenr account konto iban`) or ≥ 80 % of the sample pass `email`/`iban`/`phone`/`cpr`/`luhn` → `Identifier` (0.95); name matches a quasi word (`postcode postnr zip city by birth fodsel født gender køn title stilling age alder`) or DATE named like birth → `Quasi` (0.9); REAL/INTEGER with an amount word (`amount beløb balance saldo salary løn price pris limit total sum`) → `Sensitive` (0.95); TEXT with mean length > 40 or max_len > 200 → `FreeText` (0.9); TEXT/INTEGER with distinct ≤ 50 and distinct/non_null ≤ 0.01 → `Public` suggestion (0.6, always uncertain); INTEGER named `id` or `*_id` with distinct = non_null → `Identifier` (0.85); else `Sensitive` (0.5: unknown means sensitive, uncertain).
  `public_refusal` returns `Some` for any column that `guess` would class `Identifier` with confidence ≥ 0.85, or whose name is an amount word, or REAL type: "holds names or IDs" / "holds amounts".
  `public_values`: `SELECT col, COUNT(*) FROM t WHERE col IS NOT NULL GROUP BY col HAVING COUNT(*) >= ?k ORDER BY col`, values as text, at most 1000 (more refuses the mark: "too many values to be a category").

- [ ] **Step 1: Write the failing tests:** `guesses_on_fixture` (on the Task 3 fixture: `email`, `phone`, `ref_code`, `first_name` → Identifier; `city`, `postcode`, `birth_date` → Quasi; `amount`, `credit_limit` → Sensitive; `notes` → FreeText; `status`, `segment` → Public suggestion and `uncertain`; an unnamed column `x9` of random reals → Sensitive uncertain), `checks_vectors` (synthetic valid/invalid IBAN, Luhn, CPR `010190-1234` shape), `public_refused_for_identifiers_and_amounts` (`email`, `credit_limit`, `id` refused; `status` allowed), `k_floor_counts` (statuses `open` ×12, `paid` ×30, `disputed` ×3 with k = 10 → passing `["open","paid"]`, total_distinct 3).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): column classifier, public refusals and the k-floor (plan 43 T4)`.

### Task 5: normalization, the lexicon, entity resolution and "did you mean" (size L)

**Files:** Create/fill: `crates/shield/src/norm.rs`, `crates/shield/src/lexicon.rs`; Test: `crates/shield/tests/lexicon.rs`

**Interfaces:**
- Consumes: Task 3 snapshot, Task 1 `Schema`, `EntitySpec`.
- Produces:
```rust
// norm.rs
pub fn normalize(s: &str) -> String;                 // R43-7
pub fn tokens(s: &str) -> Vec<String>;               // of normalize(s)
pub fn sorted_key(s: &str) -> String;                // tokens sorted, joined by ' '
// lexicon.rs
pub struct Lexicon { /* rusqlite::Connection on lexicon.sqlite, read-only */ }
pub struct Candidate { pub key: i64, pub table: String, pub display: String /* the name as stored */, pub show: Vec<(String, String)> /* EntitySpec.show columns */ }
pub enum Resolve { None, One(Candidate), Many(Vec<Candidate>) /* ≤ 20, more is Many(first 20) + too_many = true */ }
pub struct LiteralHit { pub column: (String, String), pub value: String, pub count: u64 }
pub fn build_lexicon(snapshot: &Path, schema: &Schema, out: &Path) -> Result<(), ShieldError>;
impl Lexicon {
    pub fn open(path: &Path) -> Result<Lexicon, ShieldError>;
    pub fn resolve(&self, entity_table: &str, phrase: &str) -> Result<(Resolve, bool /* too_many */), ShieldError>;
    pub fn find_spans(&self, question: &str, max_tokens: usize /* 4 */) -> Result<Vec<SpanHit>, ShieldError>;   // longest match first, non-overlapping
    pub fn did_you_mean(&self, phrase: &str) -> Result<Option<Candidate>, ShieldError>;                         // R43-8
}
pub enum SpanHit { Entity { start: usize, end: usize, table: String }, Literal { start: usize, end: usize, hit: LiteralHit } }
```
  `lexicon.sqlite` tables: `entity(norm TEXT, sorted TEXT, key INTEGER, tbl TEXT, display TEXT)` with indexes on `norm` and `sorted`; `prefix(p TEXT, norm TEXT)` (first two chars of each token); `literal(norm TEXT, tbl TEXT, col TEXT, value TEXT, count INTEGER)` for every distinct value of `identifier` and `quasi` columns that are not entity name columns, and of `public` columns. Entity display = the `names` columns joined by a space in their order. `show` columns are read from the snapshot at resolve time, only for the candidates returned.

- [ ] **Step 1: Write the failing tests:** `normalize_rules` (`"Søren  ÆRØ"`→`"soeren aeroe"`, `"Åse-Østergård"`→`"aase oestergaard"`, `"Anna Berg"`=`"anna  berg "`), `resolve_one_many_none` (fixture with two `Anna Berg` in Aarhus/Odense → `Many` of 2 with `city` in `show`; one `Søren Ærø` → `One`; `Nobody Here` → `None`), `name_order_resolves` (`"Berg, Anna"` → the same two), `danish_variants_resolve` (`"Soeren Aeroe"` → One), `danish_ascii_fold_is_suggested` (`"soren aero"` → `did_you_mean` = Søren Ærø), `typo_suggested_once` (`"Ana Berg"` → `Anna Berg`; two equally close names → `None`), `spans_in_question` (`"What does Anna Berg in Aarhus owe?"` → Entity span `Anna Berg`, Literal span `Aarhus` for `customers.city`), `candidates_capped` (25 identical names → 20 and `too_many`), `prefix_search_capped` (R43-8 cap returns `None`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): lexicon, local entity resolution and did-you-mean (plan 43 T5)`.

### Task 6: the known-value index (size M)

**Files:** Create/fill: `crates/shield/src/index.rs`; Test: `crates/shield/tests/index.rs`

**Interfaces:**
- Consumes: Task 3 snapshot, Task 5 `normalize`, `tokens`.
- Produces:
```rust
pub struct IndexKey(pub Zeroizing<[u8; 32]>);   // Debug prints "IndexKey(..)"; built by the daemon from the sealed key set (plan 47)
pub struct BuildStats { pub entries: u64, pub left_out_common: u64, pub phrases: u64 }
pub fn build_index(snapshot: &Path, schema: &Schema, k: u32, key: &IndexKey, out_dir: &Path, progress: &mut dyn FnMut(u64)) -> Result<BuildStats, ShieldError>;
pub struct KnownIndex { /* File handles, entry count, bloom bits in memory */ }
impl KnownIndex {
    pub fn open(dir: &Path, key: IndexKey) -> Result<KnownIndex, ShieldError>;
    pub fn contains_value(&self, s: &str) -> Result<bool, ShieldError>;        // domain 'n', normalized
    pub fn contains_phrase(&self, s: &str) -> Result<bool, ShieldError>;       // domain 'p'
}
pub struct AllowList { pub words: BTreeSet<String> /* normalized schema words, aliases, k-floor values */ }
pub fn write_allow(schema: &Schema, public: &[PublicValues], out: &Path) -> Result<AllowList, ShieldError>;
pub fn read_allow(path: &Path) -> Result<AllowList, ShieldError>;
```
  Which cells enter: R43-9/R43-10. Integer and REAL identifier/quasi cells enter as their canonical text (`4411`, no grouping). Free-text cells: phrases (domain `p`), never single tokens.

- [ ] **Step 1: Write the failing tests:** `values_and_phrases_found` (a rare email and a rare name hit; a note phrase "the lady who runs the bakery on main street" hits as a phrase, its single words do not), `frequency_floor_excludes_common_values` (first name in 40 rows with k = 10 not in; one in 3 rows in), `allow_words_never_indexed` (`status` values `open`/`paid` and column names are in `allow.json`, not in the index), `bloom_false_positive_rate` (100 000 synthetic entries, 100 000 random misses → < 0.05 % positives after the binary search, and the bloom's own rate < 0.05 %), `different_key_misses` (an index opened with another key finds nothing), `external_sort_runs` (force a 4 KiB run size seam `build_index_with_run_bytes`: same file as the default), `no_plaintext_on_disk` (none of the fixture names appear as bytes in `index.bin`/`index.bloom`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (HMAC with `ring::hmac::Key::new(HMAC_SHA256, key)`). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): the keyed-hash known-value index with a Bloom filter (plan 43 T6)`.

### Task 7: the dataset build and the smoke runner (size M)

**Files:**
- Create/fill: `crates/shield/src/dataset.rs`; Test: `crates/shield/tests/dataset.rs`
- Create: `scripts/blind-smoke.sh` (runner, the `scripts/box-smoke.sh` pattern: sources `scripts/blind-smoke.d/[0-9][0-9]-*.sh`, `check LABEL CMD`, refuses root, work dir `${SAIIFE_BLIND_SMOKE_WORK:-${XDG_STATE_HOME:-$HOME/.local/state}/saiife-blind-smoke}`), `scripts/blind-smoke.d/10-data.sh`

**Interfaces:**
- Consumes: Tasks 3–6.
- Produces:
```rust
pub struct DatasetDir { pub root: PathBuf /* <state>/blind/datasets/<name> */ }
impl DatasetDir { pub fn stage(&self) -> PathBuf; pub fn live(&self) -> PathBuf; pub fn snapshot(&self) -> PathBuf /* live */; pub fn lexicon(&self) -> PathBuf; pub fn manifest(&self) -> PathBuf; pub fn clean_stage(&self) -> io::Result<()> }
pub struct Manifest { pub v: u32, pub dataset: DatasetName, pub built_at: String, pub snapshot_sha256: String, pub schema: Schema, pub public: Vec<PublicValues>, pub formats: BTreeMap<String /* table.column */, Format>, pub index: BuildStats, pub source_names: BTreeMap<String, String> }
pub enum Format { Plain, Email, Phone, Iban, Cpr }   // from classify::checks on the column sample (≥ 80 % pass), for synthetic rows (plan 44 Task 4)
pub enum Phase { Snapshot, Lexicon, Index, Validate, Swap }
pub struct BuildProgress { pub phase: Phase, pub done: u64, pub total: Option<u64> }
/// Stage 1 of a build: source -> stage/snapshot.sqlite; returns the proposal the init wizard shows.
pub fn stage_snapshot(dir: &DatasetDir, src: &mut dyn RowSource, progress: &mut dyn FnMut(BuildProgress)) -> Result<SnapshotInfo, ShieldError>;
pub struct Proposal { pub table: String, pub column: String, pub ty: ColType, pub guess: Guess, pub uncertain: bool, pub public_refusal: Option<&'static str>, pub public_preview: Option<PublicValues> }
pub fn propose(snapshot: &Path, k: u32) -> Result<Vec<Proposal>, ShieldError>;
/// Stage 2: with the policy's classes (as a Schema), build lexicon, public values, allow list and index in stage/,
/// run `validate` (plan 47 passes the approved-method re-validation), write the manifest, then swap stage -> live.
pub fn finish(dir: &DatasetDir, schema: &Schema, k: u32, key: &IndexKey, validate: &mut dyn FnMut(&Manifest) -> Result<(), String>, progress: &mut dyn FnMut(BuildProgress)) -> Result<Manifest, ShieldError>;
pub fn load_manifest(dir: &DatasetDir) -> Result<Manifest, ShieldError>;
```
  Swap: `live` → `old` (rename), `stage` → `live` (rename), fsync the dataset dir, remove `old`. A crash between the two renames leaves `old` and `stage`: `DatasetDir::recover()` (called by `load_manifest`) renames `old` back to `live` when `live` is missing, then removes `stage`. Every dir 0700, every file 0400 (snapshot, lexicon, index) or 0600 (manifest).

- [ ] **Step 1: Write the failing tests:** `build_end_to_end` (fixture 2 000 customers, 6 000 invoices → manifest with both tables, `about 2 thousand`, the public values of `status`), `interrupted_build_leaves_live_intact` (a `validate` closure that returns `Err` after a first good build: live still has the first manifest's snapshot hash; and a simulated crash seam `finish_crash_after_first_rename` then `recover()` gives the old live), `stale_stage_is_removed`, `classes_come_from_schema` (a column marked `public` in the schema but refused by `public_refusal` makes `finish` fail with `ShieldError::Corrupt("a public column holds names, IDs or amounts")`: defence in depth for a hand-edited policy), `modes_are_tight` (0700 dirs, 0400 files).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**, then write the runner and `10-data.sh`: `smoke_data` generates 3 000 000 customers and 9 000 000 invoices with the example, times `cargo run --release -p saiife-shield --example blind_build -- <csv dir> <out>` (add this example: stage + propose + finish with every proposal accepted and a fixed test key from `concat!`), checks the manifest row counts and that the run took under 20 minutes and under 4 GiB RSS (`/usr/bin/time -v`), and prints index size.
- [ ] **Step 4: Run** the tests → PASS; `bash -n scripts/blind-smoke.sh scripts/blind-smoke.d/10-data.sh` (and shellcheck if installed).
- [ ] **Step 5: Commit** `feat(shield): atomic dataset builds, the blind smoke runner (plan 43 T7)`.

---

## Follow-up (branch `shield-p43-followup`): I4, `_p_` names, `Schema.joins`

- **I4 (owner ruling): floors count people.** `public::people_count(table, entity_key, links)` is the one counting rule of every frequency floor (the index's k-floor, `public_values`, `propose`'s preview; `table_people_count(schema, table)` for a schema table). An EntitySpec counts distinct keys (R-14). Otherwise the count is the smallest distinct count of these candidates: each Identifier column that is not a part of a person's name, each FK column of `Schema.joins`, and the full name (the person-name parts — `first_name`, `efternavn`, `name`, ... exact names — together). The smallest, not one composite: a per-row `order_id` beside `customer_id` or a name must not count orders as people, and every extra candidate only lowers the count (fails closed). TEXT values compare after `lower(trim())`. No candidate but a Quasi column: the build is refused with `public::NO_IDENTIFIER` ("... choose the column that identifies the person"). No Identifier, Quasi or link: rows ("personal data" = an Identifier or Quasi column or a link; a table of only Sensitive/Public columns counts rows — owner to confirm). Known limit: a table whose only identifier is a per-row id counts rows; plan 48's wizard must ask for the identifying column. `public_values` takes a `&PeopleCount`. `propose` counts by the guessed classes: a table it cannot count gets no public preview (`public_refusal = NO_IDENTIFIER`).
- **`_p_` is reserved (plan 45 S1).** Import refuses a source table or column name starting with `_p_` (any case); `finish` refuses a snapshot name or a policy alias with it. `schema::is_reserved_name`, `RESERVED_PREFIX`.
- **`Schema.joins: Vec<KeyJoin>`** (`entity`, `key`, `table`, `column`, snapshot names, sorted). `finish` checks the joins a policy declares (an EntitySpec key ↔ an INTEGER column of another table) and adds `Schema::conventional_joins()` (ruling C-G1 on cloud names, exactly as plan 45's validator: `<word>_<cloud key name>` ASCII-lower-cased, compared with the FK's cloud name, both INTEGER). Manifest v2 stores them; `load_manifest` still reads v1 and derives them, and checks the `_p_` rule for every version. A v1 dataset was built with row-counted floors: rebuild it (`data refresh`) to get I4. `Schema::key_join(a, b)` looks a pair up.
- **For plan 45:** switch `sql.rs`'s `key_pair`/`fk_name` to `schema.key_join((t, c), (t, c))` (the link's `a_is_key` flag is the returned bool); preview's `JoinEdge`s can name `KeyJoin`s. Struct literals of `Schema` need `joins: vec![]` (or `schema.conventional_joins()` where a test relies on C-G1). The planner's `_p_` names can no longer collide with a snapshot name or alias of a dataset that `finish` built or `load_manifest` loaded; keep the collision check as a backstop for schemas built by hand (tests).
- **For plan 47:** the daemon loads joins from the manifest (`v` 1 or 2); the policy file may declare `joins` (checked by `finish`). A policy for a personal table must give it an identifier column (plan 48's wizard asks "choose the column that identifies the person"); the build error names the table. `CloudSchema` does not carry joins: if the planner prompt should list them, render them with cloud names.

## Owner smoke fragment (plan 43)

`scripts/blind-smoke.d/10-data.sh` (owner-run: `bash scripts/blind-smoke.sh --only data`): 3 M synthetic customers, build time, peak memory, index size, manifest row bands. Builders: `bash -n` only.

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
Integration branch `shield-dev` off `v3-dev`; each plan's branch `shield-pNN` off `shield-dev` after its dependencies are merged there.
