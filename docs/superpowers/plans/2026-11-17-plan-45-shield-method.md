# Plan 45: Data Shield core III, method, calculator and checker (stage 1): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everything between the planner's reply and a checked answer: the `SELECT`-only SQL subset validator, the plain-words method preview generated from the SQL AST (English and Danish), the executor on the read-only snapshot with the 100-row list cap and self-checks, the Landlock + seccomp sandboxed calculator process `saiife __blind-calc`, the template filler with deterministic formatters, the strict number checker, and the approved-method store with its reuse rule.

**Architecture:** Pure modules in `saiife-shield` (`plan`, `sql`, `preview`, `calc`, `calc_proto`, `template`, `checker`, `methods`, declared by plan 43 Task 1) plus two thin wrappers outside it: `saiife_system::sandbox::confine_helper` (Landlock read-only on named files, Landlock network denial, scopes, seccomp without sockets or exec, a best-effort empty network namespace, rlimits) and the hidden CLI subcommand `saiife __blind-calc` that reads one job frame, confines itself, re-validates the method, runs it and writes one answer frame. The daemon (plan 47) spawns it; tests run the executor in-process and the subprocess end to end.

**Tech Stack:** Rust; new pinned crates: `sqlparser = "=0.63.0"` (2026-09-13, Apache-2.0, pure Rust) in `saiife-shield`; `seccompiler = "=0.5.0"` (2025-03-07, Apache-2.0 OR BSD-3-Clause, pure Rust, no libseccomp) in `saiife-system` on Linux. Already present: `rusqlite =0.41.1` (plan 43), `landlock =0.4.7`, `rustix 1.1.6`.

**Spec:** `docs/superpowers/specs/2026-11-17-saiife-data-shield-design.md` §1.3 (G2 and what it does not say), §2.1.6 (0 rows refuses), §2.3.2–2.3.6, §3.1, §6.2, §9 constraints and anti-goals ("anything that could produce a confidently wrong number", "an answer of 0 for someone who isn't there").

**Depends on:** plan 43 Task 1 (types, including `Param`, `ParamType`, `Bound`, `Decimal`) for every task, plan 43 Task 3 (`open_ro`) for Tasks 3 and 7; plan 44 Task 1 (`find_numbers`, `find_dates`) for Tasks 2, 4 and 5. Task 6 matches on plain strings and needs nothing from plan 44.

## Plan rulings (refinements of spec [call]s)

- **R45-1 SQL subset** (narrowed by coordinator ruling C-G, 2026-11-17: an allow-listed shape, not masking detection). One statement, `Statement::Query` only, parsed with `sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, sql)`. Allowed, and nothing else: `WITH` (≤ 2 CTEs, not recursive, each of this same shape; outermost only); `SELECT [DISTINCT]` items that are a plain column `t.c`, `COUNT(*)`, `COUNT([DISTINCT] t.c)`, `SUM|AVG|MIN|MAX([DISTINCT] t.c)` over one plain column (`SUM`/`AVG` only over an `INTEGER`/`REAL` column, judged by origin through CTEs, else `construct_not_allowed`: final review I2), `date(t.c, mods…)` / `strftime('<fmt>', t.c, mods…)` over a plain `DATE` column, or (ruling C-CAP) in the outermost `SELECT` only, **one** `+ - * /` between two numeric aggregates over base-table columns or `COUNT(*)` (never over a CTE column; a CTE has no arithmetic output; a non-numeric operand is `construct_not_allowed`); **[final review I1, ruling F-b]** the rendered SQL casts the left operand of `/` to REAL (`CAST(SUM(x) AS REAL) / COUNT(*)`), so a division is never SQLite integer division and its output is REAL; the planner's grammar has no `CAST`; no literal or parameter in the list; `AS alias`; ≤ 32 items with unique names; `FROM` a table or a CTE with `[INNER] JOIN … ON` an `AND` of equalities, each on a declared key pair (entity key `E.table.E.key` ↔ a column in another table whose **cloud name** is `<E.word>_<cloud name of E.key>`, ASCII-lowercased, both `INTEGER`; decided on cloud names only, so a snapshot name behind an alias never changes the outcome; checked by column origin through CTEs, where only a plain grouped CTE column joins), ≤ 4 joins in total; **no join fan-out** (review F3): no table or CTE twice in a block; the key side of a join is one row per key (a base table, or a CTE grouped by that column alone); the FK sides of the one-to-many joins form one chain (never two children of one key, nor of two keys); `SUM`/`AVG`/`COUNT(col)` over a column whose value a one-to-many join repeats (the key side, also through a CTE column) is refused, while `COUNT(*)`, `COUNT(DISTINCT col)`, `MIN` and `MAX` stay; two-child totals use CTEs grouped by the FK column (this also refuses the safe two-parent join `customers c JOIN payments p ON c.id = p.customer_id JOIN invoices i ON i.id = p.invoice_id`, an accepted over-strictness of stage 1); `WHERE` an `AND` of `col op (:pN | literal)` (op `= <> < <= > >=`) and `col IN (items)`, `col` a plain column or a date expression over one; entity key and FK columns are **structural** (judged by origin through CTEs): they appear only in a key-pair `ON`, the entity pin `key = :pN` / `key IN (:pN)`, `GROUP BY`, a plain output column, or `COUNT(DISTINCT col)`; anywhere else (a comparison with a literal, a non-entity parameter or a column; inside `MIN`/`MAX`/`SUM`/`AVG` or `COUNT(col)`; `ORDER BY`) they are refused (`literal_not_allowed` against a literal, `param_misuse` against a parameter, `param_type` for a `Text` parameter typed on one, else `construct_not_allowed`); no number against a `TEXT`/`DATE` column, no string against a numeric one; `GROUP BY` plain columns or date expressions; `HAVING` an `AND` of `aggregate op (:pN | literal)`; `ORDER BY` items and aliases, `ASC`/`DESC`; `LIMIT n` with an integer literal `n ≥ 1` (outermost block only: a CTE body has no `ORDER BY`/`LIMIT`); no `OFFSET` anywhere (`LIMIT 0` and `OFFSET` give a false "no rows" for an existing entity); the two operands of the one operator have disjoint normalised leaves (`AVG(x)` = {`SUM(x)`, `COUNT(*)`}, `COUNT(col)` = `COUNT(*)`; `DISTINCT` kept), so `SUM(x) - sum(x)`, `AVG(x) / SUM(x)` and `AVG(x) / COUNT(x)` are refused and `SUM(DISTINCT x) / SUM(x)` stays; expressions are compared by a structural fingerprint (aggregate kind, `DISTINCT`, column origin through CTEs, operands of `+`/`*` sorted; never rendered text), and no two outputs of one block share one (also through CTE columns); `MIN`/`MAX` `DISTINCT` is refused; `COUNT(DISTINCT key/FK)` is an outermost output item only (no arithmetic operand, no `HAVING`, no CTE column); the rendered SQL is canonical (aggregate names upper-case, parentheses only around arithmetic). In an aggregating block a plain column must be grouped, except, in the outermost block, a column of the entity table pinned there by `key = :pN`. Refused: `CASE`, `IIF`, `COALESCE`, `IFNULL`, `NULLIF`, `IS [NOT] NULL`, `BETWEEN`, `LIKE`/`GLOB`, `OR`, `NOT`, subqueries anywhere, `EXISTS`, set operations, window functions, `LEFT`/`RIGHT`/`FULL`/`CROSS`/comma joins, column-to-column comparisons, functions on parameters, any literal in the `SELECT` list (`construct_not_allowed`, `literal_not_allowed` for literals). Functions allow-list: `count sum avg min max date strftime` (anything else is `function_not_allowed`). (Plans 43/47 should add an explicit `Schema.joins` list later.)
  - **[call: coordinator, 2026-11-17] Fan-out and the preview** (anti-goal "anything that could produce a confidently wrong number", spec §9): an aggregate over the key side of a one-to-many join is refused (`SUM(i.amount)` over `invoices i JOIN invoice_lines l ON l.invoice_id = i.id` counts each invoice once per line); a many-to-one lookup (aggregate the child, join its parent) is allowed. The validator exposes its join edges, block sources and pinned sources in `Validated` (`sources`, `joins: Vec<JoinEdge>`, `pinned_sources`), and the method preview describes joins from those edges only (parent, child, or a counted fragment), never from a guessed relation. The planner prompt and the synthetic examples (plans 44/47) must teach the fan-out rule.
- **R45-2 Names.** The planner writes cloud names (aliases where set, spec §2.1.2); the validator maps them back to snapshot names and renders the SQL it runs from the AST (`Display` of the rewritten AST), never from the planner's string.
- **R45-3 Parameters.** `:pN` placeholders only for parameters of the draft. Entity params only in `<entity table>.<key> = :pN` (either side) or `<entity table>.<key> IN (:pN)`; their `Bound::Keys` has exactly one key in stage 1 (a pick is one candidate). `DateRange` params are used as `:pN_from` / `:pN_to` (inclusive / exclusive) against a `DATE` column. Other params must be compared with a column whose type fits (`Amount`/`Integer`/`Percent` with INTEGER or REAL, `Date` with DATE, `Text` with its own column only). Binding uses rusqlite named parameters; the SQL text never holds a value.
- **R45-4 Literals in methods.** Numeric literals are allowed (planner constants such as `90`, shown in the preview). String literals only when they are (a) a k-floor public value of the column they are compared with, or (b) an ISO date. Anything else is `literal_not_allowed`.
- **R45-5 No null masking.** Masking is prevented by the R45-1 grammar: no `COALESCE`/`IFNULL`/`NULLIF`/`TOTAL`, no `CASE`, no `IS NULL`, no constants in the `SELECT` list, no `LEFT JOIN`, no subqueries; an empty result reaches the executor as NULL or as zero rows. The `null_masking` class stays in R45-8 as a secondary lint but the stage-1 validator no longer produces it. The primary control is the existence check of R45-6.
- **R45-6 Empty for key** (spec §2.1.6, §2.3.4 [owner]). With an entity param bound, a result of zero rows, or one row whose every cell from an aggregate other than `COUNT` is NULL, is a refusal `empty_for_key` naming the entity's display ("the method found no rows for Anna Berg (customer #4411)"). A `COUNT` of 0 is a computed number and is allowed. **Existence check (primary control, ruling C-G):** before the method, for each `Validated::entity_filters` entry the executor runs its own fixed query, built by saiife (never the planner's text), counting the rows that match the resolved key in the entity's base table and in each linked table: base-table zero → `empty_for_key` always; a linked-table zero → `empty_for_key` unless `Validated::count_only`. A bound entity parameter the method does not use is `param_misuse`. **[final review I3, ruling F-c]** Every other bound parameter must be used by the method (`Validated::params_used`) or shown by a `{param(pN)}` slot of the template, else `param_misuse` (`template::check_params_covered`, called once method and template both parse, before the preview).
- **R45-7 Caps** (spec "estimated cost" is enforced at run time, not estimated): wall time 10 s, SQLite VM steps 2 000 000 000 (progress handler every 10 000 ops), `PRAGMA hard_heap_limit = 512 MiB`, process `RLIMIT_AS` 1 GiB, `RLIMIT_CPU` 15 s; result ≤ `list_cap` rows (default 100) after which the executor runs `SELECT COUNT(*) FROM (<method>)` for the "showing 100 of N" note; any cap hit is an error class, never a partial answer.
- **R45-8 Error classes** sent back to the planner (≤ 3 retries, spec §2.3.3): `syntax`, `not_select`, `multiple_statements`, `unknown_table`, `unknown_column`, `function_not_allowed`, `construct_not_allowed`, `literal_not_allowed`, `param_misuse`, `param_type`, `null_masking`, `too_many_joins`, `too_deep`, `too_many_columns`, `template_slot`, `runtime_error`, `time_cap`, `memory_cap`, `step_cap`, `check_failed`. The text sent is the class and, for `unknown_column`/`unknown_table`/`template_slot`, the cloud name that failed (structure, ≤ 120 chars). Only the classes up to `template_slot` can go back to the planner: they are found before the preview. The run-time classes (`runtime_error` and after) happen after the user said "run" and end the ask (plan 48 R48-2); `empty_for_key` is never sent either.
- **R45-9 Template grammar.** Fixed text with slots `{fn(args)}`; a literal brace is refused (`{{`/`}}` give `{`/`}`, which the fixed-text charset of R45-10 does not allow), so fixed text never holds a brace. Cell args: `col` (row 0), `rN.col` (N < `list_cap`), `pN` (parameter display). Functions: `money(x[, code])`, `number(x)`, `int(x)`, `percent(x)` (x already in percent), `ratio_percent(x)` (x × 100), `round(x, n)` (n a digit 0–6 written in the slot), `date(x)`, `cmp(a, b)` (en `above` / `below` / `equal to`, da `over` / `under` / `lig med`), `param(pN)`, `rows()`, `total_rows()`, `list(col, …)` (one line per row, `- a · b`). Locale by question language: en `18,420.00`, da `18.420,00`; dates en `1 July 2026`, da `1. juli 2026`. The cap note (`showing 100 of 2,314` / `viser 100 af 2.314`) and the method line are added by saiife after the check, not by the template.
- **R45-10 Checker scope and sources** (spec §2.3.4 [call: strict]): the checker reads the filled template (the only model-shaped text). Every number found by `lang::find_numbers` and every date by `find_dates` must equal, as a decimal, a number produced by a slot (each slot records the exact values it printed) or a number written in the user's question; numbers inside `param(pN)` output spans (the resolved display, a deterministic local lookup) are sources too. Fixed-text digits not in the question refuse ("Q3" counts). Number words count (R44-3). Any miss refuses the whole answer. **[call: controller, 2026-11-17]** The template's fixed text is a small allow-listed grammar (charset, numbers set off by spaces, a closed set of words that may not sit next to a number plus any word containing a scale stem `hundred thousand illion milliard tusind mio mia` (final review M6), no Roman numerals, quantity words checked in both languages); `parse_template` enforces it (`template_slot`) and the checker re-checks it. Semantic claims without numbers ("owes nothing") are covered by the method preview, the answer's method line and approved methods, not by the checker.
- **R45-11 Approved-method match** (spec §2.3.5 reuse rule [owner]): equal `template_key` text, equal param type tags, same dataset and language. Deterministic string equality, nothing fuzzy. Store: `<dataset dir>/methods.json` (plan 47 owns the path and the touch); ids `m-<slug>-v<n>` (slug from the first 4 words of the template key, `[a-z0-9-]`); `n` is one more than the highest version ever issued for the slug, kept as a per-slug high-water mark (`issued`, serde default) that survives `remove`, so an id is never reused (final review M1).
- **R45-12 Calculator process** (spec §2.3.3 stage 1 [call]): hidden subcommand `saiife __blind-calc` of the one `saiife` binary (as `__mcp-spawn` is), so there is no new binary to package and sign. Order: read one job frame from stdin → rlimits → `confine_helper(&[snapshot])` → open the snapshot read-only → re-validate the method against the job's schema and public values → run → write one answer frame → exit 0. **Network namespace:** attempted with rustix's deprecated safe `thread::unshare(NEWUSER | NEWNET)` under `#[allow(deprecated)]` (sound here: single-threaded, no `FILES` flag; `unshare_unsafe` would need `unsafe`, which the workspace forbids); `EPERM` (unprivileged user namespaces disabled) continues without it and the answer says `netns: false`. Seccomp denies (`EPERM`) `socket socketpair connect bind listen accept accept4 sendto sendmsg sendmmsg recvfrom recvmsg recvmmsg ptrace process_vm_readv process_vm_writev execve execveat`. Landlock ABI 0 refuses to start (`sandbox_unavailable`, spec §9: fail closed).

## Global Constraints

- **Tokio-free core.** `saiife-shield` and `saiife-system` stay tokio-free (`ci.yml:208` gate).
- **Dependencies** pinned with `=`, older than 14 days: `sqlparser =0.63.0`, `seccompiler =0.5.0`. ONNX runtime for the name detector: `tract-onnx =0.23.9`, pure Rust, MIT OR Apache-2.0, only in `crates/shield-ner` (plan 46); `ort` rejected.
- **Tests fully offline with fakes**: executor in-process on synthetic fixtures (plan 43 generator); the subprocess test runs the debug `saiife` binary; no network, no sudo, no docker. Danish fixtures and number words in the checker tests.
- **No token-shaped literals.**
- **Every task** (worktree `.worktrees/p45`, branch `shield-p45` off `shield-dev`): plan 43's commands with `TMPDIR` named `p45-tN-…`; crates touched `saiife-shield`, and for Task 7 `saiife-system`, `saiife`; `bash scripts/check-windows.sh -p <crates>` (the sandbox code and `__blind-calc` are `cfg(target_os = "linux")`; other OSes print `saiife: Data Shield runs on Linux in this release` and exit 5). Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit staging, no push, smoke `bash -n` only.

### Fixed values

| Name | Value |
|---|---|
| refusal head | en `I could not produce a verified answer.` · da `Jeg kunne ikke give et verificeret svar.` |
| weaker label | `calculator not in a box (weaker)` (status and every `blind_run`) |
| frame | 4-byte big-endian length + JSON; job ≤ 1 MiB, answer ≤ 64 MiB |
| retries | the first try plus at most 3 retries per ask, before the preview |
| preview prompt | en `Run it? (Y/n)` · da `Kør den? (J/n)` |
| planner label | en `the planner says:` · da `planlæggeren siger:` |

## Review Focus

1. **"Anna Berg owes 0"** through any route: SUM over no rows, a LEFT JOIN that yields NULLs, `COALESCE(SUM(x), 0)`, `TOTAL()` (returns 0.0 on no rows), a constant column, `CASE` arms, `COUNT(*) + 0`, `IN` over an empty subquery. Expected: outside the grammar (`function_not_allowed`, `construct_not_allowed` or `literal_not_allowed`), whether an entity param is bound or not; what the grammar allows is caught by the existence check or the 0-rows rule (`empty_for_key`) (Task 1: `grammar_refuses_masking_routes`, `bare_columns_only_grouped_or_pinned`; Task 3: `existence_check_refuses_crafted_method`, `empty_sum_for_key_refuses`).
2. **A method that reads around the validator**: `sqlite_master`, a CTE named like a real table, `"customers"` quoted, `customers AS c` with `c.email`, a column name in another case, `load_extension(…)`. A join on two columns that are not a declared key pair (`ON c.id = i.amount`, `ON 1 = 1`). Expected: names resolve only to schema tables/columns; joins only on declared key pairs by column origin; everything else refused (Task 1: `escape_attempts_refused`, `joins_only_on_declared_key_pairs`).
3. **Floating sums printed with spurious digits** (`0.1 + 0.2`). Expected: `money` prints `0.30`; the checker compares the printed decimal, so the answer and the check agree (Task 4: `float_sum_prints_two_decimals`; Task 5: `checker_uses_printed_values`).
4. **A template sneaking a number** in fixed text, as a word, or as a date ("in 2025", "three times", "Q3"). Expected: refused unless the question has it (Task 5: `fixed_text_numbers_refused`, `question_numbers_allowed`).
5. **The calculator touching anything but its snapshot** (reading `/etc/passwd`, opening a socket, exec of `/bin/sh`, writing a file). Expected: each fails inside the sandbox; the job still answers or errors cleanly (Task 7: `calc_cannot_escape`).
6. **An "equivalent expression" that evades the constant checks** (`SUM(x) - sum(x)`, `AVG(x) / COUNT(x)`, commutative chains through CTE columns). Ruling C-CAP: the validator's job is a small, predictable grammar, not a proof of semantic equivalence. It caps arithmetic at one operator over base-table aggregates in the outermost `SELECT`. The residual risk of a semantically odd method is covered by (1) the runtime existence check (R45-6), (2) the plain-language preview the user sees before the method runs, and (3) approved methods. Future findings of this class are triaged against this rule, not answered with more equivalence analysis (Task 1: `arithmetic_is_capped`).

---

### Task 1: plan reply types and the SQL validator (size L)

**Files:** Fill `crates/shield/src/plan.rs`, `crates/shield/src/sql.rs`; Test: `crates/shield/tests/sql.rs`

**Interfaces:**
- Consumes: plan 43 `Schema`, `PublicValues`, `Param`, `ParamType`, `Bound`.
- Produces:
```rust
// plan.rs
pub struct PlanReply { pub method: String, pub template: String, #[serde(default)] pub checks: Vec<SelfCheck>, pub intent: String, #[serde(default)] pub needs_judgment: bool /* spec §3.1: the planner says exact mode cannot answer; method and template may then be empty */ }
#[serde(tag = "kind", rename_all = "snake_case")] pub enum SelfCheck { RowsBetween { min: u64, max: u64 }, Equal { a: String, b: String } }
pub const PLAN_SCHEMA: &str;   // JSON Schema of PlanReply for output_config.format (plan 47); additionalProperties false; method ≤ 8 KiB, template ≤ 4 KiB, intent ≤ 300 chars, ≤ 4 checks
pub fn parse_reply(text: &str) -> Result<PlanReply, ErrorClass>;
// sql.rs
pub enum ErrorClass { Syntax, NotSelect, /* … all of R45-8 */ }
impl ErrorClass { pub fn as_str(self) -> &'static str; pub fn from_str(s: &str) -> Option<ErrorClass>; }
pub struct MethodError { pub class: ErrorClass, pub detail: Option<String> /* cloud name only */ }
pub struct EntityFilter { pub param: String /* pN */, pub table: String /* snapshot entity table */, pub key: String /* snapshot key column */, pub linked: Vec<(String, String)> /* (snapshot table, FK column) of every key pair the method joins to the key, by origin */ }
pub struct Validated { pub ast: sqlparser::ast::Query /* rewritten to snapshot names */, pub sql: String /* rendered from ast */, pub cloud_sql: String, pub params_used: Vec<String>, pub entity_params: Vec<String>, pub aggregates_nullable: Vec<usize> /* output column indexes that can be NULL over no rows: SUM/AVG/MIN/MAX (directly or through a CTE column), arithmetic with such an operand, or any division */, pub entity_filters: Vec<EntityFilter> /* one per entity param */, pub count_only: bool /* every output column is a COUNT or a plain grouping column */ }
pub fn validate(sql: &str, schema: &Schema, public: &[PublicValues], params: &[Param]) -> Result<Validated, MethodError>;
pub fn validate_check(c: &SelfCheck, schema: &Schema, public: &[PublicValues], params: &[Param]) -> Result<ValidatedCheck, MethodError>;   // `Equal` sides must each give one scalar column
```

- [ ] **Step 1: Write the failing tests** (fixture schema: `customers(id, first_name, last_name, city, credit_limit, segment)`, `invoices(id, customer_id, amount, status, issued)`, `status` public values `open`, `paid`): `accepts_balance_method` (`SELECT SUM(i.amount) AS owed, c.credit_limit FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'`), `aliases_map_back` (with `customers` aliased `clients` in the schema, `FROM clients` validates and `sql` says `customers`), `refuses_by_class` (table-driven: `PRAGMA x` → not_select; two statements → multiple_statements; `SELECT * FROM sqlite_master` → unknown_table; `load_extension('x')` → function_not_allowed; window `OVER ()` → construct_not_allowed; `UNION` → construct_not_allowed; 5 joins → too_many_joins; a subquery → construct_not_allowed; `WHERE status = 'disputed'` (below k) → literal_not_allowed; `WHERE last_name = 'Berg'` → literal_not_allowed; `WHERE c.first_name = :p1` (entity param not on the key) → param_misuse; `:p9` unknown → param_misuse; `issued >= :p2` with p2 Amount → param_type), `grammar_refuses_masking_routes` (`COALESCE(SUM(amount),0)`, `TOTAL(amount)`, `IFNULL(MAX(amount), 0)` → function_not_allowed; `SUM(CASE …)`, `CASE WHEN SUM(x) > 0 …`, `IN (SUM(…), 1)`, `BETWEEN`, `ON 1 = 1`, `ON c.id = i.amount` → construct_not_allowed; `0 AS owed`, `COUNT(*) + 0`, a CTE re-exposing a constant → literal_not_allowed; with or without an entity param), `legitimate_methods_pass` (balance, Q3 sum, open count, top-10, per-month `strftime`, `HAVING COUNT(*) > 2`), `joins_only_on_declared_key_pairs`, `bare_columns_only_grouped_or_pinned`, `entity_filters_and_count_only` (balance: `linked == [(invoices, customer_id)]`, not count-only; a COUNT-only method is), `entity_param_positions` (CTE, HAVING, CTE column → param_misuse; a bound entity param the method does not use → param_misuse), `key_columns_are_structural` (`HAVING MIN(c.id) = 7`, also in a CTE → construct_not_allowed; `i.customer_id = :p6` with p6 Integer → param_misuse; a `Text` param on `c.id` → param_type), `no_offset_and_limit_at_least_one` (`OFFSET`, `LIMIT 0` → construct_not_allowed), `no_constant_differences` (duplicate output expressions, `(SUM(a) + MAX(a)) - (MAX(a) + SUM(a))` → construct_not_allowed), `constants_compared_by_structure` (case, parentheses, reordered leaves, any repeated fingerprint, identical CTE bodies → construct_not_allowed; different origins ok), `count_distinct_key_only_as_outer_output`, `arithmetic_is_capped` (arithmetic over a CTE column, a CTE arithmetic output, two operators, overlapping AVG/COUNT leaves, `a + b` and `b + a` as outputs → construct_not_allowed; `SUM(a) / SUM(b)`, `SUM(a) - SUM(b)` over base columns ok), `escape_attempts_refused` (R-focus 2 list), `date_range_params` (`issued >= :p2_from AND issued < :p2_to` ok; `:p2` alone → param_misuse), `parse_reply_schema` (missing `intent` → syntax; extra field → syntax), `plan_schema_is_json` (`PLAN_SCHEMA` parses as JSON with `additionalProperties: false`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** with `sqlparser::ast::Visit`/manual walk; rendering via `Display` of the rewritten AST. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): the SELECT-only SQL subset validator (plan 45 T1)`.

### Task 2: the method preview from the AST (size M)

**Files:** Fill `crates/shield/src/preview.rs`; Test: `crates/shield/tests/preview.rs`

**Interfaces:**
- Consumes: Task 1 `Validated`; plan 43 `Param.display`, `Lang`, `Schema`, `EntitySpec.word`/`word_da`.
- Produces: `pub struct Preview { pub text: String, pub fragments: usize /* parts shown as SQL */, pub sha256: String }` and `pub fn preview(v: &Validated, params: &[Param], schema: &Schema, lang: Lang) -> Preview;`
  Phrase tables (en / da), one per clause and function; unphrased parts are shown as the query fragment in backticks (spec §2.3.6), counted in `fragments`:
  | AST | en | da |
  |---|---|---|
  | `SUM(t.c)` | `summing all <t plural> (<c>)` | `lægger alle <t> (<c>) sammen` |
  | `COUNT(*)` / `COUNT(DISTINCT t.c)` | `counting <t plural>` / `counting distinct <c>` | `tæller <t>` / `tæller forskellige <c>` |
  | `AVG/MIN/MAX(c)` | `the average / lowest / highest <c>` | `gennemsnittet / den laveste / den højeste <c>` |
  | `key = :pN` | `for <display>` | `for <display>` |
  | `c = 'v'` | `with <c> '<v>'` | `med <c> '<v>'` |
  | `c >/>=/</<= x` | `where <c> is above / at least / below / at most <x>` | `hvor <c> er over / mindst / under / højst <x>` |
  | `c >= :pN_from AND c < :pN_to` | `in <range words>` (Q3 2026, July 2026, 2026, or `from … to …`) | `i <range words>` (3. kvartal 2026, juli 2026) |
  | `GROUP BY c` | `per <c>` | `pr. <c>` |
  | `ORDER BY c DESC LIMIT n` | `the top <n> by <c>` | `de <n> største efter <c>` |
  | JOIN | (implicit: tables named once) | |
  | a second output column `t.c` | `and comparing it with <t>.<c>` | `og sammenligner med <t>.<c>` |
  Sentence: en `I'm <select part> <where parts joined by ", "> <group/order>.` · da `Jeg <…>.`. `<display>` is the parameter's local display (real name locally; the preview never goes to the cloud). `sha256` over the text (the audit keeps only the hash, spec §6.5).

- [ ] **Step 1: Write the failing tests:** `spec_example_en` (the balance method with p1 Anna Berg (customer #4411), status 'open', p2 Q3 2026 → `I'm summing all invoices (amount) for Anna Berg (customer #4411) with status 'open' in Q3 2026, and comparing it with customers.credit_limit.`), `spec_example_da`, `unknown_part_shows_fragment` (`HAVING COUNT(*) > 2` → backticked fragment, `fragments == 1`), `never_model_text` (the preview of a method is identical whatever `intent` says), `hash_is_of_text`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): method preview from the SQL AST in English and Danish (plan 45 T2)`.

### Task 3: the executor, the list cap and self-checks (size M)

**Files:** Fill `crates/shield/src/calc.rs`; Test: `crates/shield/tests/calc.rs`

**Interfaces:**
- Consumes: Task 1 `Validated` (with `entity_filters`, `count_only`), `ValidatedCheck`; plan 43 `open_ro`, `Param`, `Bound`.
- Produces:
```rust
pub struct Caps { pub wall_ms: u64 /* 10_000 */, pub steps: u64 /* 2_000_000_000 */, pub heap_bytes: i64 /* 512 MiB */, pub list_cap: u32 }
pub enum CellValue { Null, Int(i64), Real(f64), Text(String) }
pub struct ResultSet { pub columns: Vec<String>, pub rows: Vec<Vec<CellValue>>, pub truncated: bool, pub total_rows: Option<u64>, pub ms: u64, pub row_band: String /* rows_band of total */ }
pub struct CalcFailure { pub class: ErrorClass /* runtime_error, time_cap, memory_cap, step_cap, check_failed */, pub empty_for: Option<String> /* param name for empty_for_key */ }
pub fn run(conn: &rusqlite::Connection, v: &Validated, checks: &[ValidatedCheck], params: &[Param], caps: &Caps) -> Result<ResultSet, CalcFailure>;
```
  `empty_for_key` is `CalcFailure { class: ErrorClass::CheckFailed, empty_for: Some(p) }` and is never sent to the planner (R45-8).
  Before the method, `run` performs the R45-6 existence check for each `EntityFilter`: saiife's own `SELECT COUNT(*) FROM "<table>" WHERE "<key>" IN (<keys>)` and, per linked pair, `SELECT COUNT(*) FROM "<linked table>" WHERE "<fk>" IN (<keys>)`, keys bound as parameters; base zero → `empty_for_key`; linked zero → `empty_for_key` unless `count_only`.

- [ ] **Step 1: Write the failing tests** (fixture snapshot): `runs_balance` (Søren's open invoices sum equals the sum computed in the test from the fixture rows), `list_cap_and_total` (a list of 250 rows with cap 100 → 100 rows, `truncated`, `total_rows == 250`), `empty_sum_for_key_refuses` (a customer without invoices), `existence_check_refuses_crafted_method` (a grammar-valid method for a key with no linked rows refuses before it runs; the same as COUNT-only gives 0), `count_zero_allowed`, `time_cap` (a cross join with a 50 ms cap → `time_cap`), `step_cap`, `heap_cap` (`hard_heap_limit` small + big GROUP BY → `memory_cap`), `checks_run` (`RowsBetween{min:1,max:1}` on a 2-row result → `check_failed`; `Equal` with two equal sums passes), `read_only` (a connection from `open_ro` after the executor's pragmas refuses `CREATE TABLE x(a)` run directly on it).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (`conn.progress_handler(10_000, Some(…))` checks steps and the wall clock; `PRAGMA query_only = 1; PRAGMA hard_heap_limit = …`). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): the method executor with caps, list cap and self-checks (plan 45 T3)`.

### Task 4: templates and formatters (size M)

**Files:** Fill `crates/shield/src/template.rs`; Test: `crates/shield/tests/template.rs`

**Interfaces:**
- Consumes: Task 3 `ResultSet`; plan 43 `Decimal`, `Lang`, `Param`.
- Produces:
```rust
pub struct Template { /* parsed: fixed text and slots */ }
pub fn parse_template(s: &str, columns: &[String], params: &[Param], list_cap: u32) -> Result<Template, MethodError>;   // unknown fn/column/param → template_slot
pub struct Printed { pub start: usize, pub end: usize, pub values: Vec<Decimal>, pub dates: Vec<String>, pub from_param: bool }
pub struct Filled { pub text: String, pub printed: Vec<Printed> }
pub fn fill(t: &Template, r: &ResultSet, params: &[Param], lang: Lang) -> Result<Filled, MethodError>;
pub fn format_money(x: &CellValue, lang: Lang) -> Option<(String, Decimal)>;   // and number/int/percent/round/date: each returns the text and the exact decimal it shows
```
  `Real` cells are converted to `Decimal` from Rust's shortest round-trip `Display` of the `f64`, then rounded half-even to the formatter's places; the `Decimal` recorded in `Printed` is the rounded one.

- [ ] **Step 1: Write the failing tests:** `spec_example_fill_en` (`"{param(p1)} owes {money(owed, NOK)} across {int(n)} open invoices. That is {cmp(owed, credit_limit)} her limit of {money(credit_limit, NOK)}."` → `Anna Berg (customer #4411) owes 18,420.00 NOK across 3 open invoices. That is above her limit of 15,000.00 NOK.`), `spec_example_fill_da` (`18.420,00`, `over`), `float_sum_prints_two_decimals` (0.1 + 0.2 → `0.30`), `list_rows` (`list(name, owed)` over 3 rows → 3 lines), `bad_slot_is_template_slot` (unknown column, unknown fn, `r200.x` beyond cap, `round(x, 9)`), `braces_escape`, `null_cell_refuses` (a NULL in a slot → `MethodError{class: CheckFailed}`: never printed as 0 or empty).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): answer templates and deterministic formatters (plan 45 T4)`.

### Task 5: the strict number checker (size M)

**Files:** Fill `crates/shield/src/checker.rs`; Test: `crates/shield/tests/checker.rs`

**Interfaces:**
- Consumes: Task 4 `Filled`, `Printed`; plan 44 `find_numbers`, `find_dates`; plan 43 `Decimal`.
- Produces:
```rust
pub struct CheckReport { pub numbers: usize, pub from_calc: usize, pub from_question: usize, pub from_params: usize }
pub struct CheckRefusal { pub reason: String /* "the number 2025 is not from the calculator or your question" */ }
pub fn check(f: &Filled, question: &str, lang: Lang) -> Result<CheckReport, CheckRefusal>;   // R45-10
```
  The refusal reason may quote the offending number (it is from the template's fixed text, not data) but never a param display.

- [ ] **Step 1: Write the failing tests:** `spec_answer_passes` (3/3 numbers from calc; footer count source), `checker_uses_printed_values`, `fixed_text_numbers_refused` (`"in Q3"`, `"three times"`, `"tre gange"`, `"since 2025"`, `"15%"` not printed by a slot), `question_numbers_allowed` (question has `10 000` and the template says `over 10,000` in fixed text → allowed as a question literal; spec "a literal in the user's own question"), `param_display_numbers_allowed` (`customer #4411`), `dates_checked` (`1 July 2026` must equal a printed date or a question date), `articles_not_numbers` (`a`, `en`, `et` ignored; `one` checked).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): the strict English and Danish number checker (plan 45 T5)`.

### Task 6: approved methods (size S)

**Files:** Fill `crates/shield/src/methods.rs`; Test: in-module

**Interfaces:**
- Consumes: Task 1 `validate`, `PlanReply`. The template key and tags are plain strings (plan 44's `template_key` makes them; plan 48 passes them).
- Produces:
```rust
pub enum MethodStatus { Active, Suspended { reason: String /* error class + cloud name */ } }
pub struct ApprovedMethod { pub id: String, pub version: u32, pub dataset: DatasetName, pub lang: Lang, pub template_key: String, pub param_tags: Vec<String>, pub reply: PlanReply, pub preview_sha256: String, pub approved_by: String, pub approved_at: String, pub touch: String /* credential label + sign count, from plan 48 */, pub status: MethodStatus }
pub struct MethodStore { pub methods: Vec<ApprovedMethod> }
impl MethodStore {
    pub fn load(path: &Path) -> Result<MethodStore, ShieldError>; pub fn save(&self, path: &Path) -> Result<(), ShieldError>;   // temp + fsync + rename, 0600
    pub fn find(&self, ds: &DatasetName, lang: Lang, key: &str, tags: &[String]) -> Option<&ApprovedMethod>;   // R45-11, Active only
    pub fn add(&mut self, m: ApprovedMethod) -> &ApprovedMethod;      // same key+tags → new version, old one kept as history with status Suspended{"replaced by vN"}
    pub fn remove(&mut self, id: &str) -> bool;
    pub fn revalidate(&mut self, schema: &Schema, public: &[PublicValues]) -> Vec<(String, Result<(), MethodError>)>;   // spec §2.1.1: every refresh; a failure suspends
}
pub fn method_id(key: &str, version: u32) -> String;
```

- [ ] **Step 1: Write the failing tests:** `exact_match_only` (same key+tags found; a different tag order, another language, or one extra word → none), `revalidate_suspends` (drop the `status` column from the schema → suspended with `unknown_column status`), `versions` (`m-balance-of-a-v1` then `-v2`), `save_is_atomic_and_0600`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(shield): approved methods and the reuse rule (plan 45 T6)`.

### Task 7: the sandboxed calculator process (size L)

**Files:**
- Modify: `crates/system/src/sandbox.rs` (new section after `apply`, `:392-410`; reuses `landlock_abi` `:297`, `abi_of` `:378`, `Strength` `:314`), `crates/system/Cargo.toml` (Linux target deps: `seccompiler = "=0.5.0"`; rustix features already include `process` and `thread`)
- Fill: `crates/shield/src/calc_proto.rs`
- Create: `crates/cli/src/blind_calc.rs`; Modify: `crates/cli/src/main.rs:112` (hidden `#[command(name = "__blind-calc", hide = true)] BlindCalc`, dispatched before any config is read, like `__mcp-spawn`), `crates/cli/Cargo.toml` (Linux target dep `saiife-shield`)
- Test: `crates/system/src/sandbox.rs` tests, `crates/cli/tests/blind_calc.rs`
- Create: `scripts/blind-smoke.d/30-calc.sh`

**Interfaces:**
- Produces (`saiife_system::sandbox`, Linux):
```rust
pub struct Confinement { pub landlock_abi: u32, pub net_denied: bool /* ABI ≥ 4 */, pub scopes: bool /* ABI ≥ 6 */, pub seccomp: bool, pub netns: bool }
pub struct Rlimits { pub cpu_secs: u64 /* 0 = no CPU limit (the long-lived name helper) */, pub as_bytes: u64, pub nofile: u64 }
pub fn apply_rlimits(r: &Rlimits) -> Result<(), SandboxError>;                     // also FSIZE 0, CORE 0, NPROC 0
pub fn confine_helper(read_files: &[&Path], read_dirs: &[&Path]) -> Result<Confinement, SandboxError>;   // R45-12 order: no_new_privs, netns try, Landlock (FullyEnforced or NotEnforced), seccomp
pub fn confine_helper_with_abi(abi: u32, …) -> …;                                  // test seam: abi 0 → Unavailable
pub const CALC_LABEL: &str = "calculator not in a box (weaker)";
```
- Produces (`saiife_shield::calc_proto`):
```rust
pub struct CalcJob { pub v: u32, pub snapshot: PathBuf, pub snapshot_sha256: String, pub schema: Schema, pub public: Vec<PublicValues>, pub method: String /* cloud SQL */, pub checks: Vec<SelfCheck>, pub params: Vec<Param>, pub caps: Caps }
pub enum CalcAnswer { Ok { result: ResultSet, confinement: ConfinementInfo }, Err { class: String, empty_for: Option<String>, confinement: Option<ConfinementInfo> } }
pub struct ConfinementInfo { pub landlock_abi: u32, pub net_denied: bool, pub scopes: bool, pub seccomp: bool, pub netns: bool }
pub fn write_frame<T: Serialize>(w: &mut dyn Write, v: &T, max: usize) -> io::Result<()>;
pub fn read_frame<T: DeserializeOwned>(r: &mut dyn Read, max: usize) -> io::Result<T>;
```
  The calculator checks `snapshot_sha256` against the file before running (the job names the snapshot the audit will name). `Param.display` is stripped by the daemon before the job is written (the calculator needs no names): `display` is `""` in jobs.
- Produces (`crates/cli/src/blind_calc.rs`): `pub fn run() -> ExitCode` (exit 0 with an answer frame for every handled outcome, including errors; exit 70 only when no frame could be written).

- [ ] **Step 1: Write the failing tests:** system `confine_refuses_without_landlock` (`confine_helper_with_abi(0, …)` → `Unavailable`), `seccomp_filter_builds` (the BPF program compiles for `x86_64` and `aarch64`); cli integration `calc_answers_a_job` (spawn `env!("CARGO_BIN_EXE_saiife") __blind-calc` with a fixture snapshot and the balance method → `CalcAnswer::Ok` with the sum, `landlock_abi > 0`, `seccomp`), `calc_rejects_bad_method` (a method that fails re-validation → `Err{class: "unknown_table"}`), `calc_checks_snapshot_hash`, `calc_cannot_escape` (a test-only job kind compiled under `#[cfg(debug_assertions)]`, `CalcJob.v == 999`, that after confinement tries to read `/etc/passwd`, open a TCP socket, write `$TMPDIR/x` and exec `/bin/true`, and reports each outcome: all four denied), `calc_frames_are_bounded` (a 2 MiB job → exit with `Err{class: "runtime_error"}` before confinement work).
- [ ] **Step 2: Run** `cargo test -p saiife-system sandbox -p saiife --test blind_calc` → FAIL.
- [ ] **Step 3: Implement**; then `30-calc.sh`: `smoke_calc` runs the release `saiife __blind-calc` against the 3 M snapshot from `10-data` with three methods (a customer balance, a 250-row list, a cross join that must hit `time_cap`) and checks answers, the cap note and the time cap, and prints the `Confinement` fields (`netns` shows whether user namespaces were allowed on the owner's kernel).
- [ ] **Step 4: Run** the tests → PASS (on a kernel without Landlock the escape test is skipped with a printed reason; the refusal test always runs); `bash -n scripts/blind-smoke.d/30-calc.sh`; `bash scripts/check-windows.sh -p saiife-system -p saiife`.
- [ ] **Step 5: Commit** `feat(shield): the Landlock and seccomp sandboxed calculator process (plan 45 T7)`.

---

## Owner smoke fragment (plan 45)

`scripts/blind-smoke.d/30-calc.sh` (`bash scripts/blind-smoke.sh --only calc`, after `data`): the real sandboxed calculator on the 3 M snapshot, caps, list note, confinement report. Builders: `bash -n` only.

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
