# Plan 49: Data Shield stage 1.5, usability: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise the bench's "answerable and answered correctly" share from 73 % toward about 90 %, with 0 WRONG answers, 100 % of must-refuse questions refused, and no identifier value printed without a touch, by fixing the five largest usability costs the bench found (unknown names, free text, literal forms, top-N, ambiguous numbers), adding the touch-gated identifier reveal, and making the bench a CI gate that runs on the real plan 45 and 46 code.

**Architecture:** Most of the work is pure code in `saiife-shield` (lexicon, parameterizer, literal parser, validator, executor, template, checker), so tasks 1–8 run before plan 48 lands. Each fix has its own safety argument (rulings R49-1..R49-6): a new prompt is answered locally and its answer becomes a locally bound parameter; nothing new reaches the cloud except a parameter type tag. The daemon and CLI wiring (Task 9) and the reveal (Task 10) build on plan 48's ask state machine and touch flows. The bench (`crates/shield-bench`) first moves onto the real plan 45 code and gets a gate (Task 1); each feature task then adds its own bench cases.

**Tech Stack:** Rust 2021; no new third-party crates. Existing: `strsim =0.11.1` (Damerau-Levenshtein), `rusqlite =0.41.1`, `sqlparser =0.63.0`, `serde_json`, `ring =0.17.14`; `tract-onnx =0.23.9` only behind the bench's off-by-default `ner-model` feature.

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` §1.3 (G1–G3), §2.1.2 (classes, k-floor), §2.1.4 (touch classes), §2.1.6 (entity resolution), §2.1.7 (did you mean), §2.2.5 (firewall), §2.3.1 (literals are parameters), §2.3.3–§2.3.6, §3.1, §6.5, §9 anti-goals. Inputs: the bench report (`git show shield-bench:docs/superpowers/research/2026-11-18-shield-bench.md`), plans 43–48 with their rulings as they stand on the branches below.

**Depends on (explicit):**
- **Plan 44 follow-up**, merged into shield-dev at **a136ebe8** (2ed337aa, 92c4b105, a136ebe8): half-years, ordinal quarters with `of`/`af`, year-first Q codes and scale words after digits (`1,5 tusind`, `2 mio. kr.`) bind as one parameter. Everything ambiguous refuses with `BadLiteral { why: UNBOUND_WORD | SIDE_BY_SIDE | ONE_SCALE_TWO_NUMBERS | DECOMPOSED }`. Snapshot indexes on keys and FKs are built in RAM (`temp_store = MEMORY`, so no plaintext temp file). Tasks 4, 5 and 7 build on this and redo none of it. Two of its refusals are usability costs this plan handles: `SIDE_BY_SIDE` refuses top-N forms such as `the first 10` (Task 7), and `ONE_SCALE_TWO_NUMBERS` refuses `from 500 to 2 million` and `between 1 and 2 million` (Task 5).
- **Plan 45** (`shield-p45`, through 8e39b508: the validator grammar R45-1, R45-13 `identifier_output`, the executor, templates, the checker `check(method, template, params, filled, question, lang)`). Tasks 1, 6, 7 and 8 change its modules.
- **Plan 46** (`shield-p46`): `saiife_shield_ner::NerModel` for the bench's optional real detector (Task 1).
- **Plan 48 interface change, made by Task 3:** `Answer::DidYouMean(bool)` becomes `DidYouMean(usize)`, and the step `did_you_mean {suggestion}` becomes `{suggestions, more}`. Task 3 also amends plan 48's Task 1 interface text and R48-2a ("the reveal is plan 49 Task 10's") in `docs/superpowers/plans/2026-11-17-plan-48-shield-ask-cli.md`, so plan 48 is built against the new shape.
- **Plan 47** (daemon core: audit records incl. `blind_reveal`, outbox, `role`) and **plan 48** (ask state machine Task 1, run/answer Task 2, touch flows Task 3, CLI ask Task 4; R48-2a is the reveal hook this plan fills): Tasks 9 and 10 only.
- **shield-bench** (`crates/shield-bench`, 30b0fc68): Task 1.

## Plan rulings (each with its safety argument)

- **R49-1 Suggestions for unknown names** (spec §2.1.7 [call: method]; replaces R43-8's single suggestion).
  - `Lexicon::suggest(phrase, 3)` returns up to **3** distinct normalized names, from two sources merged in this order: (a) **nickname** hits: each query token found in the built-in nickname table (`crates/shield/data/nicknames.tsv`, both directions: `bob` → `robert`, `robert` → `bob`) is replaced by each counterpart, and the rewritten phrase must resolve **exactly** (`Lexicon::resolve`); (b) **spelling** hits: Damerau-Levenshtein on normalized full names (and on sorted token order), distance ≤ 2 and ≤ 25 % of the query length (floor, minimum 1), ranked by distance, then by normalized name.
  - Candidate generation is **transposition-aware**: each query token contributes its 2-character prefix and the prefixes of its variants with characters 0↔1 swapped, 1↔2 swapped, character 0 dropped and character 1 dropped (at most 5 per token). A multi-token query needs prefix hits from at least 2 distinct query tokens (as today, R-17), counted per token, not per prefix string. The 50 000-candidate cap stays; over it gives no spelling suggestions (nickname hits still count).
  - Ties no longer suppress suggestions (the user chooses), but a 4th name at the same distance as the 3rd is dropped and `more: true` is set; the prompt then says that more names were close.
  - **Safety:** suggestions are shown only locally and only bind after the user picks one; they never enter `Draft.text`, the envelope, the outbox or a record (`blind_resolve` gets `suggestions: <n>` only). A picked name with namesakes goes on to the existing pick list. Fishing for names needs a near-complete name (distance ≤ 2) or an exact surname plus a known nickname, which is no more than the pick list already shows. Nothing is ever bound without a yes.
- **R49-2 Quoted phrases on free-text columns** (spec §2.3.1 "literals are parameters", §3.1; **needs owner decision D10**: spec §2.1.2 says `free_text` is "never in exact mode". The cloud still sees no cell, but a local filter on a `free_text` column is new, and the spec row must be amended before Task 6).
  - When the dataset has at least one `free_text` column, a phrase in matching quotes (`'…'`, `"…"`, `‘…’`, `“…”`, `„…“`, `«…»`) becomes **one** parameter of the new type `ParamType::Phrase` (tag `phrase`, `Bound::Phrase(String)`) before literals, lexicon spans and detector spans are looked for; nothing inside the quotes is parsed further. An opening quote must follow the start or a non-letter; a closing quote must precede the end or a non-letter (so `Søren's` is no quote). Content: 1–200 chars, ≤ 12 words, inner whitespace collapsed, trimmed; longer refuses (`BadLiteral`, `phrase too long`).
  - The validator allows a `Phrase` parameter only as a WHERE conjunct `t.c LIKE :pN` where `t.c` is a `free_text`-class column (by origin through CTEs); the planner writes no `ESCAPE` and no pattern. The rendered SQL is `t.c LIKE :pN ESCAPE '\'`; the executor binds `%` + the phrase with `\`, `%`, `_` escaped by `\` + `%`. Anywhere else (an identifier, sensitive or public column, `=`, `NOT`, `HAVING`, `SELECT`) is `param_misuse`.
  - Preview: en `whose <c> contains "<phrase>" (a–z in any case)`, da `hvor <c> indeholder "<phrase>" (a–z uanset store/små bogstaver)`.
  - **Safety:** the phrase is bound locally and the cloud sees only `:p1` with tag `phrase`; the firewall's param tag list gains `phrase` and nothing else. The phrase can only filter rows of a free-text column, so it cannot probe an identifier (`cpr LIKE '0101%'` stays refused). Wildcards in the user's phrase match literally. The numbers still come only from the calculator; the preview states the match rule so a case miss on `æøå` is visible.
- **R49-3 Literal forms** (on top of the plan 44 follow-up; spec §2.1.6 "a literal that doesn't parse as its type refuses").
  - **Unit tokens:** the closed list `m2 m3 km2 cm2 cm3 dm3 m² m³ km² cm² cm³ dm³` (whole words, any case) is a unit, not a number, for `find_literals`, `find_numbers` (so for the checker) and the firewall's number scan. The parameterizer folds `²`→`2` and `³`→`3` inside these tokens in `Draft.text`. A number glued to a unit (`10m2`) stays glued text, as today (P-29: `attached_suffix` needs a non-alphanumeric character after the unit), so the firewall's number scan still blocks it. That is fail closed and stays so.
  - **Vulgar fractions:** `½ ¼ ¾` alone or glued to digits (`1½`, `2¾`) are amounts (`0.5`, `1.5`, `2.75`). `2 ¾` with a space refuses with `SIDE_BY_SIDE`, like any two numbers side by side, in `find_literals` and numbers in `find_numbers`; every other non-ASCII digit still refuses.
  - **Year-less periods** (owner decision D3): `Q1`–`Q4`, `H1`/`H2`, `1.`–`4. kvartal`, `første`…`fjerde kvartal`, `first`…`fourth quarter`, `første/andet halvår`, `first/second half` with no year become a `Pending::PeriodYear` prompt whose default is the latest year in which that period has fully ended on `ParamOptions.today` (on 2026-11-18: `Q3` → 2026, `Q4` → 2025); the user accepts, types a year (1000–9998), or declines (refusal `BadLiteral { why: NO_YEAR, span }` with `NO_YEAR = "no year given"`). **Relative periods** `this quarter`/`dette kvartal`/`indeværende kvartal` (the quarter holding today) and `last quarter`/`sidste kvartal`/`forrige kvartal` (the last full quarter), and the same for `half-year`/`halvår`, bind with no prompt **only when no year, `of`/`af` or number follows**. `last quarter of 2025`, `sidste kvartal 2025` and `sidste halvår 2025` mean the last quarter or half **of that year** (Q4 2025, H2 2025) and bind as such.
  - **Danish `anden`/`andet` (and `første`…`tolvte`, `first`…`twelfth`) as plain words:** today an ordinal word away from any period or date binds as an `Integer` (`en anden kunde` = "another customer" becomes `:p1`). From now on an ordinal word is a number only when it is part of a period or date literal (`andet kvartal 2025`, `2. juni`), or when an ordinal unit (`month`, `uge`, …) or a period word follows it. Anywhere else it stays as text: no parameter, and no number for the checker or the firewall's number scan. An ordinal beside an unconsumed literal still refuses with `UNBOUND_WORD`, as now.
  - **Safety:** every resolved period is a `DateRange` parameter bound locally, and the preview names the concrete period (`in Q3 2026`) before the run, so the assumption is visible. Unit tokens are a closed list that cannot carry a data value; the scan still blocks every other digit. An ordinal left as text carries no data value (it is a fixed word of the closed list), and the `UNBOUND_WORD` refusal still stops it from changing what a nearby literal means.
- **R49-4 Top-N** (spec §2.3.3 list cap).
  - **Parameterizer side.** A row-count phrase binds as **one** `Integer` parameter, and the words around the number stay as text. The forms are `top N`, `the first N`, `the last N`, `the N largest/biggest/smallest/best/worst …`, `bottom N`, Danish `de N største/mindste/første/sidste/bedste`, `top N`, `de første N`, with N in digits or as a number word (`ten`, `tre`). Without this, `the first 10` is refused as `SIDE_BY_SIDE`: `first` is an ordinal word and so counts as a number beside `10`. Inside such a phrase the ordinal (`first`, `første`, `sidste`) is a plain word. A row-count form never binds when a period or time-unit word follows N (`the last 3 months`, `de sidste 3 måneder` stay as they are now: an Integer bound as before, with no row-count role). Any other number beside the phrase still refuses with `SIDE_BY_SIDE`. `Draft` records the parameter's role: `Param.role = Some(ParamRole::RowCount)`. The role is local only, and its tag stays `integer`.
  - The outermost `LIMIT` may be `:pN` only for an `Integer` parameter with `role == Some(RowCount)`. A RowCount parameter may appear **only** there: anywhere else it is `param_misuse`, and a plain `Integer` in `LIMIT` is `param_misuse` too. Every `LIMIT`, literal or parameter, needs an `ORDER BY` (else `construct_not_allowed`; today's grammar allows `LIMIT` without one). A `LIMIT` parameter counts as used (R45-6). The parameterizer checks the value range 1..=1 000 000 (`BadLiteral`, `not a row count`), so it is never a planner retry class. Above the list cap the existing cap note applies (`showing 100 of 500`).
  - **Fetching N+1:** `total_rows` (`SELECT COUNT(*) FROM (<sql>)`) binds N. The fetch binds N+1; a literal `LIMIT n` is rewritten in the AST to n+1 for the fetch only. The extra row is dropped before `fill`, so the answer never prints N+1 rows and the cap note never says `of N+1`.
  - Preview wording follows the order: `DESC` gives en `the top <n> by <c>` / da `de <n> største efter <c>`; `ASC` gives en `the bottom <n> by <c>` / da `de <n> mindste efter <c>`.
  - A method with `LIMIT` must order only by output columns (else `construct_not_allowed`, sent to the planner). The executor fetches one row more than the limit; when the extra row equals the last kept row on every `ORDER BY` output, the answer gets a fixed note after the check: en `(the next row ties with row <n>; the method's order cut the list here)`, da `(næste række står lige med række <n>; metodens rækkefølge skar listen her)`.
  - **Safety:** the parameterizer change only stops an ordinal and a count from reading as two numbers. It is a closed list of phrase shapes, and anything else beside the number still refuses. N is bound locally (the cloud sees `:p1`, `integer`); it cannot raise the list cap or R45-13; the k-floor governs what the cloud sees and N never leaves, so it does not touch the k-floor. The tie note stops an arbitrary cut from reading as a complete ranking.
- **R49-5 Number locale** (spec §2.3.1; replaces the plan 44 P-27 refusal for detected languages).
  - An ambiguous grouping (`10,000`, `10.000`, `1.500`: one separator followed by exactly three digits, no other separator) is read by, in order: an explicit `--lang`; the user's remembered locale for the dataset; the dataset's `number_locale` (`[[blind.dataset]] number_locale = "da" | "en"`, absent by default); else a `Pending::NumberReading` prompt with the two readings (grouping first). Unambiguous forms are unaffected (`10.000,50` is Danish whatever the locale).
  - After a reading is chosen the CLI asks once whether to remember it; the daemon stores `{dataset: "da"|"en"}` per uid in `<blind>/prefs/<uid>.json` (0600) and `saiife blind prefs number-locale <dataset> da|en|unset` changes it.
  - **Checker sources (loosens R45-10; owner decision D12):** for every span of the original question that became a parameter, the checker uses the parameter's bound value **instead of** `find_numbers(question)` on that span. It is replaced, not added to, so reading 2 (`10`) never lets `10,000` pass. Numbers outside parameter spans are read as today.
  - **Display:** once a reading, a locale or a scale reading has decided a value, `Param.display` becomes the canonical formatted value in the question's language (en `10,000`, da `10.000` read as ten thousand is shown `10 000`; reading 2 is shown `10`). The preview and the answer therefore print the value as read, not as written.
  - **Two ambiguous numbers in one question** get one prompt each. "Remember" stores the locale that the **first** answered reading implies (grouping → the locale whose group separator was written). The second prompt is then decided by that locale and not shown.
  - **One scale word for two numbers** (`from 500 to 2 million`, `between 1 and 2 million`, `mellem 1 og 2 millioner kr.`, today refused with `ONE_SCALE_TWO_NUMBERS`) becomes a `Pending::ScaleReading` prompt with both readings, with the scale on both ends listed first: en `"<written>": 1) <a1> to <b1>  2) <a2> to <b2>. Which one? `, da `"<written>": 1) <a1> til <b1>  2) <a2> til <b2>. Hvilken? `. The chosen reading binds two `Amount` parameters. `0` refuses. A shared unit or period (`10 and 20 percent`, `1st and 2nd quarter 2025`) still refuses, because only scale words get the prompt. Nothing is remembered for this prompt.
  - **Safety:** a wrong reading is the anti-goal "a confidently wrong number", so only an explicit setting or an explicit user choice decides; the detected language never does. The value is a local parameter and the preview prints it as read, through `display` (`where total is above 10,000`; reading 2: `above 10`).
- **R49-6 Hidden identifiers and the touch-gated reveal** (owner ruling R45-13: "exact mode never prints identifier values; revealing one needs a touch, per value, audited"; **needs owner decisions D1 and D2**).
  - `validate_opts(…, ValidateOpts { mask_identifiers: true })` accepts an outermost output item that R45-13 would refuse **only** when it is a plain Identifier-class column, judged by origin through CTEs (a CTE column `MAX(c.email) AS m` output as `x.m` is not plain). In an aggregating block it also needs the entity key of its table in `GROUP BY`, or the entity pinned by `key = :pN`, so two namesakes are never summed into one row. Everything else R45-13 refuses stays refused. `Validated.masked: Vec<usize>` lists those outputs. The daemon validates strict first; only an `identifier_output` refusal leads to the masked validation of the same reply (no new planner call).
  - The template filler prints each distinct `(column, value)` of a masked output as a label, en `[hidden A]`, da `[skjult A]` (A–Z, then AA…), never the value; the labels carry no digit, and `Printed` records them with `masked: true`. `parse_template` refuses a masked column inside any number formatter (`template_slot`). The checker treats label spans like param spans.
  - The hidden values stay only in the ask's memory (zeroized when the ask ends, plan 48's 10-minute lifetime). `saiife blind reveal <ask-id> <label>` takes one `blind:show` touch (D2) per label, prints that one value locally, and writes `blind_reveal {ask, column: "table.column", label, value_ref, touch}` where `value_ref` is the first 16 bytes of HMAC(index key, `"reveal"` ‖ table.column ‖ 0x00 ‖ normalized value) in hex. No value is ever written to a record, the outbox or the cloud.
  - **Safety:** the calculator output reaches only the daemon's filler, which never prints a masked value; CPR, email and phone stay hidden like names; each revealed value costs its own touch and its own record; another uid or a replayed assertion is refused (plan 48 touch rules).

## Global Constraints

- **Tokio-free core.** `saiife-shield` stays tokio-free (`ci.yml:208` gate); the bench crate too.
- **Dependencies** pinned with `=`, older than 14 days; this plan adds none. `saiife-shield-ner` (tract) is linked by the bench only behind the `ner-model` feature, never by default and never in CI.
- **Fail closed:** a prompt that cannot be shown (no terminal, plan 48 R48-3) refuses with the count only; a parse that is not certain refuses; no prompt ever falls back to sending text.
- **What leaves:** this plan adds exactly one cloud-visible thing, the parameter tag `phrase`. No suggestion, phrase, reading, period choice, row count `N` or hidden value is ever in `Envelope`, the outbox or a `blind_*` record.
- **Tests offline with fakes;** synthetic Danish and English fixtures (æ, ø, å); no real personal data; no token-shaped literals (`concat!`).
- **Every task** has its own worktree `.worktrees/p49-tN` and branch `shield-p49-tN`. Tasks 2 and 4 branch off shield-dev a136ebe8; the others branch off shield-dev after shield-p45, shield-p46 and shield-bench are merged there. The coordinator merges each finished task into `shield-p49`, and a dependent task starts from that branch. Task 4's bench cases are added after Task 1 is merged (they need the `questions/` split).
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p49-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
  cargo test -p <crates touched> -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  bash scripts/check-windows.sh -p <crates touched>
  ```
  For tasks that add bench cases, also run `cargo run --release -p saiife-shield-bench -- run --work "$TMPDIR/w" --size small --report "$TMPDIR/r.md" --gate crates/shield-bench/gate.json` and paste the totals line into the task report. Remove `$TMPDIR` by its literal path. Stage explicit paths; trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no push, no merge.

### Fixed values

| Name | Value |
|---|---|
| suggestions | at most 3; prompt en `No <word> named "<written>". Did you mean:` / `  <n>) <display>` / `Which one? (Enter for none) `; da `Ingen <word_da> ved navn "<written>". Mente du:` / `Hvilken? (Enter for ingen) `; one suggestion keeps plan 48's `(y/N)` copy; `more: true` adds en `(more names are as close; type the name in full)` / da `(flere navne er lige tæt på; skriv hele navnet)` |
| nickname table | `crates/shield/data/nicknames.tsv`, `include_str!`, lines `nickname<TAB>formal[,formal…]`, normalized (R43-7), at least the pairs in Task 3 |
| new param type | `ParamType::Phrase`, tag `phrase`, `Bound::Phrase(String)` |
| period prompt | en `"<written>" has no year. <period> <year> (the last finished one)? (Y/n, or type a year) `; da `"<written>" har intet år. <period> <year> (det seneste afsluttede)? (J/n, eller skriv et år) ` |
| reading prompt | en `"<written>" can be read two ways: 1) <a>  2) <b>. Which one? ` then `Read numbers like this from now on in <dataset>? (y/N) `; da `"<written>" kan læses på to måder: 1) <a>  2) <b>. Hvilken? ` then `Læs tal sådan fremover i <dataset>? (j/N) ` |
| hidden label | en `[hidden A]`, da `[skjult A]`; reveal hint en `show a hidden value: saiife blind reveal <ask-id> <letter> (one touch per value)` |
| new refusal texts | `phrase too long`, `not a row count`, `no year given` (`&'static str`, with the span; local only) |
| bench gate | `crates/shield-bench/gate.json`: `{"size":"small","seed":7,"max_wrong":0,"max_leaks":0,"must_refuse_min_share":1.0,"min_correct":<n>}` |

## Review Focus

1. **A suggestion that is someone else** ("Bob Ravn" when the meant Bob is not in the data, but a Robert Ravn is). Expected: offered, never bound without a pick; "none" goes on to keep-name, then refusal (Task 3: `suggestion_never_binds_without_a_pick`; bench `names_outsider_near_nickname`).
2. **A quoted phrase holding a rare value or SQL wildcards** (`'Anna Berg'`, `'100%'`, `'a_b'`). Expected: the envelope holds `:p1` only; `%` and `_` match literally (Task 6: `phrase_never_in_envelope`, `phrase_wildcards_are_literal`).
3. **A year-less quarter on a quarter boundary** (today 2026-10-01, `Q3`; today 2026-12-31, `Q4`). Expected: defaults 2026 and 2025; the preview names the year (Task 4: `period_default_on_boundaries`).
4. **A remembered locale meeting an unambiguous form** (remembered `en`, question `10.000,50`). Expected: 10000.50, no prompt (Task 5: `unambiguous_beats_locale`).
5. **A masked identifier escaping**: `MIN(c.cpr)`, `substr(c.email, 1, 3)`, a masked column in `money()`, another uid's reveal, a replayed touch. Expected: still `identifier_output` / `template_slot` / `forbidden` / `touch_expired` (Task 8: `only_plain_identifier_columns_mask`, `masked_needs_key_grouping` (`GROUP BY c.first_name, c.last_name` without the key → `identifier_output`; with `c.id` grouped → ok; CTE `MAX(c.email) AS m` output as `x.m` → `identifier_output`), `masked_column_in_number_slot_refused`; Task 10: `reveal_other_uid_forbidden`, `reveal_replay_refused`).

---

### Task 1: the bench on the real plan 45 code, a leak check and the CI gate (size L)

Depends on: plan 45 and plan 44 follow-up merged into shield-dev; shield-bench merged; plan 46 for the optional feature. Not on plans 47/48.

**Files:**
- Modify: `crates/shield-bench/src/method.rs` (replace the stub with `RealEngine`), `crates/shield-bench/src/planner.rs` (every category's method and template rewritten in the R45-1 grammar), `crates/shield-bench/src/run.rs`, `crates/shield-bench/src/report.rs`, `crates/shield-bench/src/main.rs`, `crates/shield-bench/src/lib.rs`, `crates/shield-bench/src/shield.rs` (`joins`), `crates/shield-bench/Cargo.toml` (feature `ner-model = ["dep:saiife-shield-ner"]`)
- Move: `crates/shield-bench/src/questions.rs` → `crates/shield-bench/src/questions/mod.rs` (unchanged cases) with one `pub fn extra(s: &Subjects) -> Vec<Question>` that later tasks extend by adding a file each
- Create: `crates/shield-bench/src/ner.rs`, `crates/shield-bench/src/leak.rs`, `crates/shield-bench/src/rss.rs`, `crates/shield-bench/gate.json`, `crates/shield-bench/gate-3m.json`, `crates/shield-bench/tests/gate.rs`
- Modify: `.github/workflows/ci.yml` (new job `shield-bench`), `docs/superpowers/research/2026-11-18-shield-bench.md` (a "Real plan 45" section with the new baseline)

**Interfaces:**
- Produces:
```rust
// method.rs
pub struct RealEngine { pub caps: saiife_shield::calc::Caps, pub calc_bin: PathBuf, pub mask_identifiers: bool /* false until Task 8 */ }
// The bench's MethodEngine trait is redefined to carry plan 45's own types (PlanReply, Validated, Template, Filled) instead of the stub's reduced ones.
impl MethodEngine for RealEngine { /* sql::validate → template::parse_template → template::check_params_covered → preview::preview → the `__blind-calc` process through `calc_proto` frames (one job per process: plan 45's `hard_heap_limit` is process-wide and only lowers, calc.rs:111-116), with `--calc <path to the debug or release saiife>` → template::fill → checker::check */ }
// ner.rs
pub enum Detector { Oracle, Model(saiife_shield_ner::NerModel) /* cfg(feature = "ner-model") */ }
impl saiife_shield::ner::NameDetector for Detector { … }
// leak.rs: LEAK = an answer that prints a value of an Identifier-class column that is not inside a param display span
pub fn identifier_leaks(answer: &str, param_spans: &[(usize, usize)], src: &rusqlite::Connection) -> Result<Vec<String /* "customers.cpr" */>, String>;
// run.rs: Res gains Leak; report counts it beside WRONG
// main.rs: run … [--ner oracle|model:<dir>] [--gate <file>] [--seed S]; exit 1 when the gate fails
pub struct Gate { pub size: String, pub seed: u64, pub max_wrong: u32, pub max_leaks: u32, pub must_refuse_min_share: f64, pub min_correct: u32 }
pub fn check_gate(g: &Gate, run: &BenchRun) -> Result<(), Vec<String>>;   // min_correct is a warning (printed), not a failure
// rss.rs (Linux)
pub fn reset_peak() -> std::io::Result<()>; pub fn peak_mib() -> std::io::Result<u64>;
// report::Meta.build_phases gains peak_rss_mib per phase; Gate gains max_build_rss_mib: Option<u64>
```
  The planner returns `needs_judgment` with why `grammar: <construct>` for a question the R45-1 grammar cannot express (for example `NOT EXISTS`), so the report shows the grammar's own cost as its own reason. `--no-identifier-rule` and the stub are removed (R45-13 is real now). `leak.rs` loads every distinct value of each Identifier-class column, except entity keys, FK columns and pure-integer columns, into a normalized set. It looks up every 2–4-token window of the answer outside param spans, and single tokens only when they are at least 3 characters and the column is not a name part. CPR, email, phone and IBAN patterns are checked on the whole answer. A column above 2 000 000 distinct values is reported as `not checked` in the report, never skipped silently.
  **Memory check** (the snapshot indexes sort in RAM, `temp_store = MEMORY`): `shield.rs` records the process's peak RSS for each build phase. Before each phase it writes `5` to `/proc/self/clear_refs` to reset the peak, and after the phase it reads `VmHWM` from `/proc/self/status`; this is Linux only, and the bench refuses to run elsewhere. The report gets a `peak RSS MiB` column in the build-phase table, and `estimate` scales it linearly to 3M. `run --size 3m` (owner only) checks it against `--max-rss-mib` (default from `gate-3m.json`, `{"size":"3m","max_build_rss_mib":2048}`) and exits 1 when a phase goes over. In CI, SMALL only prints the column.
  CI job `shield-bench` (ubuntu-latest, after `test`): `cargo run --release -p saiife-shield-bench -- run --work "$RUNNER_TEMP/w" --size small --report "$RUNNER_TEMP/bench.md" --gate crates/shield-bench/gate.json`, the report uploaded as an artifact and appended to `$GITHUB_STEP_SUMMARY`; no network beyond the cargo fetch the other jobs already do.

- [ ] **Step 1: Write the failing tests** (`tests/gate.rs`, on a 300-customer run in a tempdir): `real_engine_answers_a_balance` (single_total-01 is `correct`), `grammar_cost_is_its_own_reason` (no_invoices-01 is `refused` with a reason starting `planner: grammar`), `cpr_question_refused_by_real_rule` (refuse_cpr-01 refused with `validate: identifier_output`), `leak_is_detected` (a hand-made answer printing another customer's email → `identifier_leaks` names `customers.email`; the subject's own name inside a param span → none), `gate_fails_on_wrong_or_leak` (a `BenchRun` with one `Wrong`, one with one `Leak`, one with a must-refuse answered → each fails `check_gate`; `min_correct` short → `Ok` with a printed warning), `rss_is_measured` (`#[cfg(target_os = "linux")]`, in its own test binary `tests/rss.rs` so no parallel test resets the peak; `peak_mib()` > 0 after allocating 64 MiB and touching it; the build table has a `peak RSS MiB` value for each phase), `rss_gate_fails_over_limit` (a `Meta` with an index phase at 3 000 MiB and `max_build_rss_mib: 2048` → fails, naming the phase).
- [ ] **Step 2: Run** `cargo test -p saiife-shield-bench --test gate` → FAIL.
- [ ] **Step 3: Implement**; run the SMALL bench; write the totals into `gate.json` (`min_correct` = the new correct count) and the per-category table into the research note's new section.
- [ ] **Step 4: Run** the tests → PASS; the SMALL run exits 0 with 0 WRONG, 0 LEAK, must-refuse 100 %.
- [ ] **Step 5: Commit** `feat(shield-bench): run on the real plan 45 code, a leak check and a CI gate (plan 49 T1)`.

### Task 2: transposition-aware suggestions, up to three (size M)

Depends on: plan 43 only (shield-dev today). Can start first.

**Files:** Modify `crates/shield/src/lexicon.rs` (`did_you_mean` becomes a wrapper over `suggest`); Test: `crates/shield/tests/lexicon.rs`

**Interfaces:**
- Produces:
```rust
pub enum SuggestWhy { Nickname { written: String, formal: String }, Spelling { distance: u8 } }
pub struct Suggestion { pub candidate: Candidate, pub why: SuggestWhy }
pub struct Suggestions { pub list: Vec<Suggestion> /* ≤ max, distinct normalized names */, pub more: bool }
impl Lexicon {
    pub fn suggest(&self, phrase: &str, max: usize) -> Result<Suggestions, ShieldError>;            // R49-1 (spelling part here; Task 3 adds nicknames)
    pub fn did_you_mean(&self, phrase: &str) -> Result<Option<Candidate>, ShieldError>;            // kept: Some only when suggest(…, 1) gives one and !more
}
fn prefix_variants(token: &str) -> Vec<String>;   // R49-1, ≤ 5, deduplicated
```
- [ ] **Step 1: Write the failing tests:** `transposed_prefix_is_found` (fixture adds `Åse Kristensen`, `Katrine Lindqvist`, `Astrid Christiansen`, `Christian Knudsen`, `Jonas Ulstrup`; `Åse Kirstensen`, `Katrine Lnidqvist`, `Astrid Crhistiansen`, `Christian Kundsen`, `Jonas Usltrup` each → that one name, `Spelling{distance: 1}`), `first_token_transposed` (`Ainne Hjort` → `Anine Hjort`, an ASCII first name; swaps next to æ/ø/å are 2-letter folds that the variants do not cover, an accepted gap), `variants_within_prefix_cap` (a 7-token query: the variants counted against `MAX_PREFIXES = 32` → over it gives no spelling suggestion, never a guess), `three_closest_ranked` (four names at distances 1, 1, 2, 2 → three listed, distance-1 ones first, `more == true`), `ties_listed_not_suppressed` (`Ana Berg` with `Anna Berg` and `Ane Berg` → both), `cap_still_holds` (the existing `prefix_search_capped` still gives no spelling suggestion), `did_you_mean_unchanged_for_one` (the existing `typo_suggested_once` cases keep passing), `variants_bounded` (`prefix_variants("ab")` has ≤ 5 entries, no empty string).
- [ ] **Step 2: Run** `cargo test -p saiife-shield --test lexicon` → FAIL. **Step 3: Implement** (variants map back to their query token so the 2-token rule counts tokens). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): transposition-aware name suggestions, up to three (plan 49 T2)`.

### Task 3: nicknames and the three-way "did you mean" (size M)

Depends on: Tasks 2 and 4 (shares `question.rs`; order there: 4 → 3 → 7 → 5 → 6).

**Files:** Create `crates/shield/src/nicknames.rs`, `crates/shield/data/nicknames.tsv`; Modify `docs/superpowers/plans/2026-11-17-plan-48-shield-ask-cli.md` (Task 1 `AskAnswer`/`Step` shapes, R48-2a pointer); Modify `crates/shield/src/lib.rs` (`pub mod nicknames;`), `crates/shield/src/lexicon.rs` (nickname source in `suggest`), `crates/shield/src/question.rs`; Test: `crates/shield/tests/question.rs`; Create `crates/shield-bench/src/questions/names.rs` and the planner entries it needs

**Interfaces:**
- Produces:
```rust
// nicknames.rs
pub fn counterparts(token_norm: &str) -> &'static [&'static str];   // both directions; empty when unknown
// question.rs (changed)
Pending::DidYouMean { param: String, word: String, written: String, suggestions: Vec<Candidate> /* 1..=3, local only */, more: bool }
Answer::DidYouMean(usize)   // 1-based pick; 0 = none of these (→ KeepName, as "no" today)
```
  The table holds at least: `kim: kimmie, kimberly` · `kimmie: kim` · `lasse: lars` · `bob, bobby, rob, robbie: robert` · `bill, will, willy: william` · `chris: christian, christoffer, christina, christine` · `niko, nico: nikolaj, nicolai` · `trine: katrine, kathrine` · `grethe, grete: margrethe` · `lise: elisabeth, lisbeth` · `liz, lizzie: elizabeth` · `kate, katie: katherine, kathrine` · `mike, mick: michael` · `tom, tommy: thomas` · `jim, jimmy: james` · `pelle: per, peder` · `stine: christine, kristine` · `rikke: henrikke, ulrikke` · `mads: mathias` · `hans, jens: johannes` · `bente: benedikte` · `ole: oluf` · `søs: susanne` · `dick, rick: richard` · `sam: samuel, samantha` · `ben: benjamin` · `alex: alexander, alexandra` · `fred: frederik, frederick` · `nick: nicholas, nikolaj`. Every entry normalized per R43-7.

- [ ] **Step 1: Write the failing tests:** `nickname_suggests_formal` (`Bob Ravn` with fixture `Robert Ravn` → `DidYouMean` with that one suggestion; `answer(DidYouMean(1))` → `Ready`), `formal_suggests_nickname` (`Robert Juhl` with fixture `Bob Juhl`), `danish_nicknames` (`Lasse Højer`, `Trine Lindqvist`, `Grethe Øhlenschlæger` → their formal names), `nickname_needs_exact_surname` (`Bob Ravvn` with only `Robert Ravn` in the fixture → no suggestion at all: the nickname path needs an exact surname, and the spelling distance from `bob ravvn` to `robert ravn` is above 2), `three_suggestions_pick_second` (three close names; `DidYouMean(2)` binds the second), `suggestion_then_namesakes` (the picked name has two people → `Pick`), `suggestion_never_binds_without_a_pick` (`DidYouMean(0)` → `KeepName`; no param bound), `table_is_normalized_and_symmetric` (every line parses; `counterparts(a)` holds `b` iff `counterparts(b)` holds `a`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench file `questions/names.rs`: 8 transposed typos (5 of them in the first two letters of a surname), 8 nicknames (4 en, 4 da), `names_outsider_near_nickname` ×2 (`Bobby Quince`: must refuse), 2 suggestions that lead to a pick list; the simulated coworker picks the suggestion that is the meant person, else 0. **Step 4: Run** tests → PASS; bench: typos and nicknames categories all `correct`, 0 WRONG, 0 LEAK.
- [ ] **Step 5: Commit** `feat(shield): Danish and English nicknames and up to three name suggestions (plan 49 T3)`.

### Task 4: unit tokens, fractions and year-less periods (size M)

Depends on: shield-dev a136ebe8 (plan 44 follow-up) only; it is the first `question.rs` task. Does not redo half-years, ordinal quarters, year-first codes or scale words.

**Files:** Modify `crates/shield/src/lang.rs`, `crates/shield/src/question.rs`, `crates/shield/src/firewall.rs` (number scan exempts `lang::is_unit_token`); Test: `crates/shield/tests/lang.rs`, `crates/shield/tests/question.rs`, `crates/shield/tests/firewall.rs`; Create `crates/shield-bench/src/questions/literals.rs`

**Interfaces:**
- Produces:
```rust
// lang.rs
pub const UNIT_TOKENS: &[&str];                       // R49-3
pub fn is_unit_token(word: &str) -> bool;
pub fn fold_units(text: &str) -> String;              // ² → 2, ³ → 3 inside unit tokens only
pub struct OpenPeriod { pub start: usize, pub end: usize, pub kind: PeriodKind /* Quarter(u8) | Half(u8) */ }
pub fn find_open_periods(text: &str, lang: Lang) -> Vec<OpenPeriod>;                 // year-less, non-relative
pub fn relative_period(text: &str, at: usize, lang: Lang, today: &str) -> Option<(usize, Literal /* DateRange */)>;
pub fn default_year(kind: PeriodKind, today: &str) -> u32;                           // latest fully ended
// question.rs
pub struct ParamOptions { pub lang: Option<Lang>, pub today: String /* ISO */, pub number_locale: Option<NumberLocale> /* Task 5; None here */ }
pub fn parameterize_with(question: &str, o: &ParamOptions, schema: &Schema, lex: &Lexicon, det: &dyn NameDetector) -> Result<Step, ShieldError>;
// parameterize(...) stays: ParamOptions { lang, today: today from the system clock (UTC), number_locale: None }
Pending::PeriodYear { param: String, written: String, kind: PeriodKind, default_year: u32 }
Answer::PeriodYear(Option<u32>)   // Some(y) binds; None declines → Refusal::BadLiteral { span, why: NO_YEAR }
```
- [ ] **Step 1: Write the failing tests:** `unit_tokens_are_not_numbers` (`find_numbers("12 m² and 3 m2")` → 12 and 3 only; `find_literals("m2 Klinker")` → none), `fractions_parse` (`½ kg` → 0.5; `1½` → 1.5; `2 ¾` → 2.75; `⅓` → error `non-ASCII digit`), `units_pass_firewall` (draft text `How many m2 of :p1 …` → no `number` hit; `How many m7 …` → hit), `fold_units_only_in_tokens` (`m²` → `m2`; a lone `²` stays and refuses), `open_quarter_prompts` (`How many invoices in Q3?` on today 2026-11-18 → `PeriodYear{default_year: 2026}`; `answer(PeriodYear(Some(2026)))` → DateRange 2026-07-01..2026-10-01), `period_default_on_boundaries` (today 2026-10-01, `Q3` → 2026; today 2026-09-30, `Q3` → 2025; today 2026-12-31, `Q4` → 2025; `andet halvår` today 2026-11-18 → 2025), `relative_period_with_year` (`last quarter of 2025` → Q4 2025; `sidste halvår 2025` → H2 2025), `relative_periods_bind` (`last quarter` today 2026-11-18 → 2026-07-01..2026-10-01; `dette kvartal` → 2026-10-01..2027-01-01; `sidste halvår` → 2026-01-01..2026-07-01), `declined_year_refuses`, `bad_open_period_refuses` (`Q5`, `5. kvartal` with no year → `BadLiteral`), `ordinal_word_alone_is_text` (`Hvad skylder en anden kunde i Odense?` → no Integer param, text keeps `anden`; `the second customer in Odense` likewise; the firewall finds no `number` hit; `andet kvartal 2025` and `2. juni 2025` still bind; `anden :p1` where `:p1` is an unconsumed literal still refuses with `UNBOUND_WORD`), `followup_forms_unchanged` (the plan 44 follow-up tests still pass).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench `questions/literals.rs`: units ×6 (`m²`, `m2`, `m³`, `½ kg`, `1½ kg`, `¾ L`), periods ×6 (`Q3`, `H2`, `3. kvartal` with no year, `last quarter`, `sidste kvartal`, `this quarter`), ordinal words ×2 (`Hvor mange fakturaer har en anden status end betalt?`: `anden` stays text; `Hvor mange fakturaer blev udstedt i andet halvår 2025?`: still one DateRange), must-refuse ×2 (`Q5` with no year; the coworker declines the year); the coworker answers `PeriodYear` with the meant year from the case. **Step 4: Run** → PASS; bench units and quarters categories `correct` except must-refuse cases refused.
- [ ] **Step 5: Commit** `feat(shield): unit tokens, vulgar fractions and year-less periods (plan 49 T4)`.

### Task 5: the number locale and the reading prompt (size M)

Depends on: Task 4 (`ParamOptions`). Shares `question.rs`: run after Task 7.

**Files:** Modify `crates/shield/src/lang.rs`, `crates/shield/src/question.rs`, `crates/shield/src/checker.rs` (bound values as question numbers, R49-5), `crates/policy/src/blind.rs` (`BlindDataset.number_locale: Option<String>`, `#[serde(skip_serializing_if = "Option::is_none")]`, values `"da"`/`"en"`, anything else `Invalid`; policy does not depend on `saiife-shield`, so the daemon maps the string to `lang::NumberLocale`); Test: `crates/shield/tests/lang.rs`, `crates/shield/tests/question.rs`, `crates/shield/tests/checker.rs`, `crates/policy` tests; Create `crates/shield-bench/src/questions/numbers.rs`

**Interfaces:**
- Produces:
```rust
// lang.rs
#[serde(rename_all = "lowercase")] pub enum NumberLocale { Da, En }
pub fn find_literals_with(text: &str, lang: Lang, locale: Option<NumberLocale>) -> Result<Vec<LiteralSpan>, LiteralError>;   // locale decides an ambiguous grouping; None → the span is reported as ambiguous
pub struct Ambiguous { pub start: usize, pub end: usize, pub grouping: Decimal, pub decimal: Decimal }
pub fn find_ambiguous(text: &str) -> Vec<Ambiguous>;
// question.rs
Pending::NumberReading { param: String, written: String, readings: [Decimal; 2] /* grouping first */ }
Answer::NumberReading(usize)   // 1 or 2; 0 refuses
Pending::ScaleReading { params: [String; 2], written: String, readings: [[Decimal; 2]; 2] /* [scale on both, scale on the second only] */ }
Answer::ScaleReading(usize)    // 1 or 2; 0 refuses (BadLiteral ONE_SCALE_TWO_NUMBERS, as today)
```
  Precedence per R49-5: `ParamOptions.lang` set explicitly by the caller → that language's reading; else `number_locale` (the daemon passes the user's remembered one, else the dataset's) → its reading; else the prompt.
- [ ] **Step 1: Write the failing tests:** `locale_reads_grouping` (`over 10.000` with `Some(Da)` → 10000; `over 1.500 kr.` with `Some(Da)` → 1500; `over 10,000` with `Some(En)` → 10000; `over 1.500` with `Some(En)` → 1.5), `no_locale_prompts` (`over 10.000`, detected language, no locale → `NumberReading{readings: [10000, 10]}`; `answer(NumberReading(1))` → Amount 10000), `unambiguous_beats_locale` (`10.000,50` with `Some(En)` → 10000.50; `12,345.67` with `Some(Da)` → 12345.67, no prompt), `explicit_lang_still_decides` (lang `Da` given explicitly, no locale → 10000, no prompt), `reading_zero_refuses`, `scale_reading_prompts` (`between 1 and 2 million` → `ScaleReading{readings: [[1000000, 2000000], [1, 2000000]]}`; `answer(ScaleReading(1))` → two Amounts 1 000 000 and 2 000 000; `from 500 to 2 million`, answer 2 → 500 and 2 000 000; `mellem 1 og 2 millioner kr.` likewise in Danish; `10 and 20 percent` and `1st and 2nd quarter 2025` still `ONE_SCALE_TWO_NUMBERS`), `checker_uses_bound_values_instead` (question `over 10.000` read as 10000, fixed text `over 10,000` → passes; read as 10 → `10,000` refused and `10` passes), `display_shows_reading` (reading 2 → `display == "10"`; the preview prints `10`, not `10.000`), `two_ambiguous_one_remember` (`between 1.500 and 10.000`, the first answered with grouping → the second decided, no second prompt), `policy_number_locale` (`number_locale = "da"` loads; `"fr"` is `Invalid`; absent leaves the policy hash unchanged).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench `questions/numbers.rs`: 6 ambiguous forms answered after the prompt (en and da), 2 with a dataset locale set in the bench's policy copy, 2 scale ranges (`from 500 to 2 million kr.`, `mellem 1 og 2 millioner`), must-refuse `over 10,0,0` and `10 and 20 percent of invoices`; the existing `ambiguous_numbers-01..03` now answer after the prompt; `ambiguous_numbers-13` per owner decision D5. **Step 4: Run** → PASS; bench `ambiguous_numbers` answerable all `correct`.
- [ ] **Step 5: Commit** `feat(shield): a number locale per dataset or user and a reading prompt instead of a refusal (plan 49 T5)`.

### Task 6: quoted phrases on free-text columns (size L)

Depends on: plan 45 (validator, executor, preview, template); Tasks 7 and 8 first (they share `sql.rs`/`calc.rs`), Task 5 first (shares `question.rs`).

**Files:** Modify `crates/shield/src/schema.rs` (`ParamType::Phrase`, `Bound::Phrase`), `crates/shield/src/question.rs` (quote finder runs first), `crates/shield/src/sql.rs` (`LIKE :pN` on a free-text column, R49-2), `crates/shield/src/calc.rs` (binding `%…%` with `\` escapes), `crates/shield/src/preview.rs` (en/da phrase), `crates/shield/src/firewall.rs` (`phrase` in the param tag list), `crates/shield/src/calc_proto.rs` (bump `CALC_JOB_VERSION`: jobs now carry `Bound::Phrase`; an older calculator refuses the job),  `crates/shield/src/synth.rs` (no change expected; check `free_text` rows still `"(free text)"`); Test: `crates/shield/tests/question.rs`, `tests/sql.rs`, `tests/calc.rs`, `tests/preview.rs`, `tests/firewall.rs`; Create `crates/shield-bench/src/questions/phrases.rs`

**Interfaces:**
- Produces:
```rust
// question.rs
pub struct QuoteSpan { pub start: usize, pub end: usize /* incl. quotes */, pub phrase: String /* trimmed, collapsed */ }
pub fn find_quotes(text: &str) -> Result<Vec<QuoteSpan>, Refusal>;   // R49-2 rules; too long → BadLiteral{why: "phrase too long"}
// calc.rs
pub fn like_contains(phrase: &str) -> String;                         // "%" + escaped + "%"
```
  `ParamType::Phrase::tag()` = `"phrase"`; `template_key` tags therefore distinguish a phrase question from others (approved methods do not cross).
- [ ] **Step 1: Write the failing tests:** `quoted_phrase_becomes_param` (`Hvor mange fakturaer har noten 'rykker sendt'?` → text `… noten :p1?`, `p1` Phrase `rykker sendt`), `quotes_win_over_spans` (`'paid by card'` with `paid` a public status value and `'levering til Silkeborg'` with a known city → one Phrase each, no Text param), `apostrophe_is_not_a_quote` (`Søren's notes`), `no_free_text_column_no_phrase` (a schema without `free_text` → quotes left as today), `typographic_quotes` (`“…”`, `„…“`, `«…»`), `phrase_too_long` (201 chars → BadLiteral), `like_only_on_free_text` (`i.notes LIKE :p1` ok, rendered with `ESCAPE '\'`; `c.cpr LIKE :p1`, `i.status LIKE :p1`, `i.notes = :p1`, `NOT i.notes LIKE :p1`, `i.notes LIKE '%x%'`, planner-written `ESCAPE` → refused with the R49-2 classes), `phrase_must_be_used` (a bound phrase the method ignores → `param_misuse`), `phrase_wildcards_are_literal` (fixture notes `100% paid`, `100 paid`, `a_b`, `axb`: phrase `100%` matches 1 row, `a_b` matches 1), `phrase_case_rule` (`Rykker` matches `rykker`), `phrase_preview_en_da`, `phrase_never_in_envelope` (envelope canonical bytes hold `"ty":"phrase"` and not the phrase; `check_outgoing` passes).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench `questions/phrases.rs`: 6 quoted (single, double, typographic, with a city, with a status word, with `%`), must-refuse ×2 (`customers whose CPR contains '0101'`; a phrase the planner tries on `customers.email`); the four quoted questions of `free_text` now answer; the four unquoted ones stay refused (D8). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): quoted phrases bind locally as contains-matches on free-text columns (plan 49 T6)`.

### Task 7: top-N with `LIMIT :pN` and the tie note (size M)

Depends on: plan 45; Task 3 (shares `question.rs`).

**Files:** Modify `crates/shield/src/question.rs` (row-count phrases, R49-4; it shares the file with Tasks 3–6, so it runs in W1 before Task 3), `crates/shield/src/schema.rs` (`Param.role: Option<ParamRole>`, `#[serde(default, skip_serializing_if = "Option::is_none")]`, `pub enum ParamRole { RowCount }`), `crates/shield/src/sql.rs` (`Validated.limit`, `Validated.order_outputs`), `crates/shield/src/calc.rs` (limit + 1 fetch, `ResultSet.tie_at_cut`), `crates/shield/src/preview.rs` (`the top <n> by <c>` with the param display); Test: `tests/sql.rs`, `tests/calc.rs`, `tests/preview.rs`; Create `crates/shield-bench/src/questions/topn.rs`

**Interfaces:**
- Produces:
```rust
pub enum LimitSpec { Literal(u64), Param(String) }
// Validated gains: pub limit: Option<LimitSpec>, pub order_outputs: Vec<usize>
// ResultSet gains: pub tie_at_cut: Option<u64 /* the row number n */>
pub fn limit_value(v: &Validated, params: &[Param]) -> Result<Option<u64>, MethodError>;   // Param: Bound::Integer in 1..=1_000_000, else MethodError{class: ParamType} → the ask refuses locally "not a row count"
pub const TIE_NOTE_EN: &str; pub const TIE_NOTE_DA: &str;   // R49-4 text with <n>
```
- [ ] **Step 1: Write the failing tests:** `row_count_phrases_bind` (`Show the first 10 customers by revenue` → `Show the first :p1 customers by revenue`, p1 Integer 10, `role == Some(RowCount)`; `top 5`, `the 3 largest`, `bottom ten`, `de 10 første`, `de tre største`, `top 5 … in 2025` → one RowCount param plus the DateRange; `the first 10 2025` still `SIDE_BY_SIDE`; `the first quarter of 2025` still a DateRange, not a row count; `the last 3 months` and `de sidste 3 måneder` get no RowCount role), `role_never_in_envelope` (the canonical envelope has `"ty":"integer"` and no `role`), `limit_param_accepted` (`… ORDER BY revenue DESC LIMIT :p1` with p1 Integer → ok, `params_used` holds p1), `limit_param_type` (p1 Amount → `param_type`; p1 in a CTE's LIMIT → `construct_not_allowed`), `limit_needs_output_order` (`ORDER BY SUM(i.total)` not in the output → `construct_not_allowed`), `limit_value_range` (0 and 1 000 001 → parameterizer `BadLiteral`), `limit_needs_row_count_role` (`LIMIT :p1` with a plain Integer, `WHERE n > :p1` with a RowCount → `param_misuse`; `LIMIT 5` with no `ORDER BY` → `construct_not_allowed`), `n_plus_one_hidden` (LIMIT 5 over 8 rows → 5 rows printed, `total_rows == 5`; LIMIT 250 with cap 100 → note `of 250`, not 251), `preview_bottom_n` (ASC → `the bottom 5 by …` / `de 5 mindste efter …`), `limit_over_cap_notes` (N 250, cap 100 → 100 rows, `total_rows == 250`), `tie_at_cut_detected` (fixture rows 5 and 6 equal on the order output → `tie_at_cut == Some(5)`; no tie → `None`; tie check also for `LIMIT 5` literal), `preview_top_n` (en `the top 5 by revenue`, da `de 5 største efter revenue`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench `questions/topn.rs`: 6 top-N over groups that print no identifier (top cities, segments, payment methods, months; digits, `ten`, `tre`), a tie case, N above the cap, must-refuse `top 0`. The existing `top_n-01..04/11/12` (names) depend on Task 8. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): top-N with a bound LIMIT, the list cap and a tie note (plan 49 T7)`.

### Task 8: hidden identifier outputs in the core (size M) — only after owner decision D1

Depends on: plan 45 R45-13; Task 7 (shares `sql.rs`/`calc.rs`).

**Files:** Modify `crates/shield/src/sql.rs` (`ValidateOpts`, `validate_opts`, `Validated.masked`), `crates/shield/src/template.rs` (labels, `Printed.masked`, `Filled.hidden`), `crates/shield/src/checker.rs` (label spans as sources), `crates/shield-bench/src/method.rs` (`mask_identifiers: true`, strict-then-masked like the daemon), `crates/shield-bench/src/run.rs` (outcome `correct (hidden)` counts as correct when the hidden rows' keys equal the reference's; a must-refuse question answered with every identifier hidden counts as `withheld`, which the gate counts as refused **only if the owner approves D11**; until then it counts as answered, and the gate fails); Test: `tests/sql.rs`, `tests/template.rs`, `tests/checker.rs`

**Interfaces:**
- Produces:
```rust
pub struct ValidateOpts { pub mask_identifiers: bool }
pub fn validate_opts(sql: &str, schema: &Schema, public: &[PublicValues], params: &[Param], o: ValidateOpts) -> Result<Validated, MethodError>;   // validate() = validate_opts(…, { mask_identifiers: false })
// Validated gains: pub masked: Vec<usize>
pub struct Hidden { pub label: String /* "A" */, pub column: String /* "customers.first_name" */, pub value: zeroize::Zeroizing<String> }
// Filled gains: pub hidden: Vec<Hidden>   (Debug prints labels and columns only)
// Printed gains: pub masked: bool
```
- [ ] **Step 1: Write the failing tests:** `only_plain_identifier_columns_mask` (with masking: `SELECT c.first_name, c.last_name, SUM(i.total) …` ok, `masked == [0, 1]`; `MIN(c.cpr)`, `substr(c.email, 1, 3)`, `c.cpr || ''` → still `identifier_output`; without masking all four refused as today), `labels_stable_per_value` (two rows with the same first name → same label; labels `A`, `B`, …, `Z`, `AA`), `labels_hold_no_digits_and_check_passes`, `masked_column_in_number_slot_refused` (`{money(cpr)}` → `template_slot`), `hidden_debug_has_no_value`, `danish_label` (`[skjult A]`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; bench: `top_n-01..04/11/12` and the `no_invoices` name lists answer with hidden names; `refuse_cpr` stays refused or hidden, never printed (LEAK 0). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): hidden identifier outputs with per-answer labels (plan 49 T8)`.

### Task 9: the new prompts and preferences in the ask flow (size M)

Depends on: **plan 48 Tasks 1, 2 and 4** (ask state machine, run/answer, CLI `ask`) and plan 47; Tasks 3–7 (and 8 if D1).

**Files:** Modify `crates/daemon/src/blind/ask.rs` (new steps; `ParamOptions` from the clock, the user's prefs and the dataset policy; strict-then-masked validation when D1), Create `crates/daemon/src/blind/prefs.rs`, Modify `crates/daemon/src/blind/ops.rs` (`blind.prefs.set {dataset, number_locale: "da"|"en"|null}`), `crates/cli/src/blind_cmd/ask.rs`, `crates/cli/src/blind_cmd/prompt.rs`, `crates/cli/src/blind_cmd.rs` (`Prefs { #[command(subcommand)] action: PrefsAction }`, `PrefsAction::NumberLocale { dataset: String, locale: String }`); Test: `crates/daemon/tests/blind_ask.rs`, `crates/cli/tests/blind_cli.rs`

**Interfaces:**
- Produces (step JSON, tag `kind`, added to plan 48's `Step`): `did_you_mean {word, written, suggestions: [{n, label}], more}` (replaces the single `suggestion`) · `number_reading {written, readings: [a, b]}` · `period_year {written, period, default_year}`; answers `{"did_you_mean": n}` · `{"number_reading": n, "remember": bool}` · `{"period_year": y | null}`; `answer` gains `tie_note?` and `hidden?: [{label, column}]` (labels and column names only).
```rust
pub fn load(ctx: &Ctx, uid: u32) -> Prefs; pub fn set_number_locale(ctx: &Ctx, uid: u32, ds: &DatasetName, l: Option<NumberLocale>) -> Result<(), String>;   // <blind>/prefs/<uid>.json, 0600, temp + rename
```
- [ ] **Step 1: Write the failing tests:** daemon `three_suggestions_step` (labels are display + show columns; `blind_resolve` holds `suggestions: 3` and no name), `reading_remembered` (answer 1 with `remember` → next ask with `10.000` has no prompt; `prefs.json` mode 0600; another uid still gets the prompt), `period_year_step`, `prompts_never_logged` (after each new prompt, neither audit files nor outbox hold the written name, phrase, reading or year), `tie_note_in_answer`; cli `ask_did_you_mean_pick_2` (stdin `2\ny\n`), `prefs_number_locale_set_and_unset`, `no_terminal_refuses_new_prompts` (R48-3: count only).
- [ ] **Step 2: Run** `cargo test -p saiife-daemon blind -p saiife --test blind_cli` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): suggestions, readings, periods and number-locale prefs in the ask flow (plan 49 T9)`.

### Task 10: the touch-gated reveal (size M) — only after owner decisions D1 and D2

Plan 48 R48-2a names the hook (`identifier_output`, `IDENTIFIER_OUTPUT_REASON`) but no plan 48 task builds the reveal; this task does. Depends on: **plan 48 Tasks 2, 3 and 4**, plan 47 Task 3 (`blind_reveal` record), Tasks 8 and 9.

**Files:** Modify `crates/touch/src/…` (`TouchClass::BlindShow`, `blind:show`, `needs_uv() == true`; D2), `crates/daemon/src/blind/touch.rs` (purpose `reveal {ask, label}`), `crates/daemon/src/blind/ask.rs` (`Answered` keeps `Vec<Hidden>`; dropped and zeroized at expiry), `crates/daemon/src/blind/audit.rs` (`blind_reveal` fields), `crates/cli/src/blind_cmd.rs` (`Reveal { ask: String, label: String }`), `docs/data-shield.md` (a "Hidden values" section); Test: `crates/daemon/tests/blind_touch.rs`, `crates/cli/tests/blind_cli.rs`

**Interfaces:**
- Produces: op `blind.touch.begin {purpose: "reveal", ask, label}` → class `blind:show`, asker only, summary en `show hidden value <label> (<table.column>) from your answer in <dataset>`; `blind.touch.commit` → `{value}` sent only on that connection; record `blind_reveal {ask, dataset, column, label, value_ref, touch}` (R49-6). Unknown label or an expired ask → `refused: nothing to reveal`.
- [ ] **Step 1: Write the failing tests** (soft key): `reveal_one_value` (hidden `A` → that name printed; one `blind_reveal` with `value_ref` and no value; the audit files and outbox do not contain the value), `reveal_is_per_value` (revealing `A` does not reveal `B`; a second touch needed), `reveal_other_uid_forbidden`, `reveal_replay_refused` (`touch_expired`), `reveal_after_expiry_refused`, `reveal_hint_printed` (the answer prints the hint once when anything is hidden), `cli_reveal` (`saiife blind reveal <ask> A` with the soft key prints the value, exit 0).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(daemon): reveal one hidden identifier per touch, audited (plan 49 T10)`.

### Task 11: final measurement and the gate baseline (size S)

Depends on: Tasks 1–8 (9 and 10 do not change bench numbers).

**Files:** Modify `crates/shield-bench/gate.json` (`min_correct`), `docs/superpowers/research/2026-11-18-shield-bench.md` (a "Stage 1.5" section: totals, per category, the remaining top 5 refusal reasons, timings)

- [ ] **Step 1:** Run SMALL with seeds 7, 11 and 23 (`--seed`); each: 0 WRONG, 0 LEAK, must-refuse 100 %.
- [ ] **Step 2:** Record the answered-correctly share per seed against the Task 1 baseline and the original 73 %; list every bench expectation change (D5) with its reason.
- [ ] **Step 3:** Set `min_correct` from seed 7; run the gate test and the CI command locally → exit 0.
- [ ] **Step 4: Commit** `docs(shield-bench): stage 1.5 results and the gate baseline (plan 49 T11)`.

---

## Order and parallel map

Shared files decide the order: `question.rs` (Tasks 3, 4, 5, 6) and `sql.rs`/`calc.rs` (Tasks 6, 7, 8) are edited one task at a time; bench cases live in one file per task.

```
before plan 48:
W1  T1 bench on real 45 + gate · T2 suggestions · T4 literal forms (bench cases after T1)
W2  T3 nicknames (after T2, T4)
W3  T7 top-N (after T3)
W4  T5 number locale (after T7) · T8 hidden identifiers (after T7; D1)
W5  T6 phrases (after T5, T8)
W6  T11 measurement (after T1–T8)
after plan 48 (T1, T2, T3, T4) and plan 47:
W7  T9 ask-flow wiring → T10 reveal (D1, D2)
```
T2 and T4 need only shield-dev a136ebe8, so they can start before plan 45 merges. T1, T6, T7 and T8 need shield-p45 merged into shield-dev, and T1 also needs shield-bench.

## Owner decisions

- **D1 Hidden identifier outputs.** Allow a method to output a plain Identifier column when the answer shows each value as `[hidden A]` and reveals it only per value with a touch (R49-6)? Without it, every top-N or list of customers or products stays refused under R45-13 and the reveal has nothing to reveal. Recommendation: yes.
- **D2 Touch class for a local reveal.** Spec §2.1.4 defines `blind:reveal` as "a real value would leave". A local display is not leaving. Recommendation: a new class `blind:show` (spec §2.1.4 gets one row), and keep `blind:reveal` for values that would leave.
- **D3 Year-less periods.** Should saiife ask with a default (the latest finished period) or resolve silently? Recommendation: ask with the default, and resolve `this`/`last quarter` with no prompt. The preview always names the period.
- **D4 Per-value reveal for lists.** The ruling says one touch per value, so a top-10 list takes 10 touches. Recommendation: keep it per value now, and decide on a batch touch only if users complain.
- **D5 Bench expectation changes.** `ambiguous_numbers-13` (`over 1.500`, en) would become "answer after the reading prompt". `ambiguous_numbers-14` (`1,5 thousand`, en) becomes answerable as 1500 after the plan 44 follow-up. Recommendation: approve both. New must-refuse cases (Tasks 3–7) replace them in the gate.
- **D6 What 90 % is measured against.** The 73 % came from the looser plan 45 stub. The real grammar refuses `NOT EXISTS`/`LEFT JOIN` anti-joins and some balance formulas, so Task 1's baseline may be lower, and these five fixes may land near 85–88 %. Recommendation: the gate is 0 WRONG, 0 LEAK and 100 % must-refuse, with each feature's category fixed. Report the overall share. If the grammar is what keeps it under 90 %, propose a short follow-up (an anti-join on a declared key pair) as its own plan.
- **D7 Non-personal entities.** Product names are Identifier class, so a "top 3 products" answer shows `[hidden A]`. Recommendation: a later `personal = false` mark on an entity, set by an approver with `blind:loosen`, so its names print locally (they still never reach the cloud). It is not in this plan.
- **D8 Unquoted free-text questions** (4 of the 8 bench free-text questions) stay refused. Recommendation: keep it that way. Detecting an unquoted phrase would mean guessing.
- **D9 Memory budget for the 3M build.** Index sorts run in RAM. Recommendation: refuse a 3M build phase whose peak is above **2 GiB** (`gate-3m.json`), and raise the limit only after the owner's 3M run shows the real figure.
- **D10 A local filter on `free_text` in exact mode** (R49-2). Spec §2.1.2 says `free_text` is "never in exact mode". The cloud still sees no cell and no phrase, only the tag `phrase`, but the calculator filters on the column. Recommendation: yes, amend the spec row to "the cloud never sees values; exact mode may filter a free-text column by a locally bound quoted phrase". Task 6 waits for this.
- **D11 Must-refuse with hidden identifiers.** Under D1, "What is the CPR number of X?" can end as an answer whose CPR is hidden and needs a touch to reveal, instead of a refusal. Should the gate count that as refused (`withheld`)? Recommendation: yes, because nothing forbidden is printed and LEAK stays 0. If not, the planner prompt must keep identifiers out of methods for single-value questions.
- **D12 Checker and suggestion rule changes.** R49-5 changes R45-10's question-number sources: a parameter span counts by its bound value only. R49-1 replaces R43-8's tie suppression with a list of up to 3. Recommendation: approve both. Both are stricter, or equally strict, on what may be printed, and the user still makes every choice.
