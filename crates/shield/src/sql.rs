//! Plan 45: the SELECT-only SQL validator (spec §2.3.3; R45-1..R45-5, R45-8;
//! coordinator ruling C-G).
//!
//! Stage 1 accepts one narrow, allow-listed shape and nothing else:
//!
//! - `WITH`: at most 2 non-recursive CTEs, each of the same shape.
//! - `SELECT [DISTINCT]` items: a plain column `t.c`; `COUNT(*)`,
//!   `COUNT([DISTINCT] t.c)`, `SUM|AVG|MIN|MAX([DISTINCT] t.c)` over one
//!   plain column (`SUM`/`AVG` over a number column only); `date(t.c,
//!   mods…)` / `strftime('<fmt>', t.c, mods…)` over a plain DATE column; in
//!   the outermost block only, one `+ - * /` between two numeric aggregates
//!   over base-table columns (ruling C-CAP). No literal and no parameter in
//!   the list. `AS alias`; at most 32 items, unique names.
//! - `/` is rendered with its left operand cast to REAL (ruling F-b), so it
//!   is never SQLite integer division; the planner cannot write `CAST`.
//! - `FROM` a base table or a CTE, `[INNER] JOIN … ON` an AND of equalities
//!   each on a declared key pair (ruling C-G1), checked by column origin
//!   through CTE provenance; at most 4 joins in all.
//! - `WHERE`: an AND of `col op (:pN | literal)`, `col IN (items)` and
//!   (ruling F-k) `t.c IS [NOT] NULL` over a plain non-key column, where
//!   `col` is a plain column or a date expression over one.
//! - Owner ruling 2026-11-18 (R45-13): no outermost output column yields an
//!   Identifier-class value (judged by column origin through CTEs): a plain
//!   Identifier column, `date`/`strftime`/`MIN`/`MAX`/`SUM`/`AVG` over one,
//!   or arithmetic over such an aggregate is `identifier_output`. Only
//!   `COUNT(*)`, `COUNT(col)` and `COUNT(DISTINCT col)` over an Identifier
//!   are allowed (ruling F-j); WHERE comparisons, key-pair joins and GROUP BY
//!   on one stay allowed when it is not output.
//! - `GROUP BY` plain columns or date expressions; `HAVING` an AND of
//!   `aggregate op (:pN | literal)`; `ORDER BY` any item above, ASC/DESC;
//!   `LIMIT n` with an integer literal `n >= 1`; no `OFFSET`.
//! - In an aggregating block a plain column must be grouped, except (in the
//!   outermost block) a column of the entity table its `key = :pN` pins.
//! - Entity key and C-G1 FK columns are structural (judged by origin through
//!   CTEs): only in a key-pair ON, the entity pin, GROUP BY, a plain output
//!   column, or `COUNT(DISTINCT col)`.
//! - Expressions are compared by a structural fingerprint (aggregate kind,
//!   DISTINCT, column origin through CTEs; operands of `+` and `*` sorted),
//!   never by rendered text: no two outputs of a block with one fingerprint.
//!   The two operands of an operator have disjoint normalised leaves
//!   (`AVG(x)` = {`SUM(x)`, `COUNT(*)`}, `COUNT(col)` = `COUNT(*)`).
//!   `COUNT(DISTINCT key)` is an outermost output only.
//! - The validator keeps a small, predictable grammar; it does not prove
//!   semantic equivalence (ruling C-CAP). The existence check, the preview
//!   and approved methods cover the rest.
//! - The rendered SQL is canonical: aggregate names upper-case, `date` /
//!   `strftime` lower-case, no redundant parentheses.
//!
//! Every `match` over the parser's AST ends in a refusal, never in an
//! accept. Masking routes (CASE, COALESCE, IS NULL outside a WHERE
//! conjunct, constants, subqueries, LEFT JOIN, …) are outside the grammar,
//! so `null_masking` is no longer produced here; the primary control is the
//! executor's existence check over [`Validated::entity_filters`] (R45-6,
//! Task 3).
//!
//! Names resolve case-exact against the cloud names of the schema (aliases
//! where set) and are rewritten to snapshot names; every planner-chosen
//! reference name renders under a reserved prefix; the SQL that runs is
//! rendered from the rewritten AST, never taken from the planner's string
//! (R45-2). Errors come from fixed strings and carry, for `unknown_table` /
//! `unknown_column`, only the cloud name that failed. Parser error texts are
//! never kept: they can quote the input.

use crate::plan::{SelfCheck, METHOD_MAX};
use crate::public::PublicValues;
use crate::schema::{Bound, ColType, ColumnClass, EntitySpec, Param, ParamType, Schema, TableInfo};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, Distinct, DuplicateTreatment, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, JoinConstraint,
    JoinOperator, LimitClause, ObjectName, ObjectNamePart, OrderBy, OrderByKind, OrderBySort,
    Query, Select, SelectFlavor, SelectItem, SetExpr, Statement, TableAlias, TableFactor,
    UnaryOperator, Value,
};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

/// Caps (R45-1, ruling C-G).
pub const MAX_JOINS: usize = 4;
pub const MAX_COLUMNS: usize = 32;
pub const MAX_CTES: usize = 2;
/// Longest planner-written name (alias, CTE name).
const NAME_MAX: usize = 64;
/// Longest `detail` sent back to the planner (R45-8).
const DETAIL_MAX: usize = 120;
/// Most arguments of `date` / `strftime` (value, format and modifiers).
const DATE_ARGS_MAX: usize = 6;
/// Every planner-chosen reference name (CTE or table alias) is rendered
/// under this prefix, which no snapshot table or column may use, so SQLite
/// can never bind a planner name to a name the cloud never saw.
const RESERVED: &str = "_p_";
/// Names SQLite binds to a table's implicit rowid.
const IMPLICIT: [&str; 3] = ["rowid", "oid", "_rowid_"];

/// The stage-1 function allow-list (ruling C-G).
const FUNCTIONS: [&str; 7] = ["count", "sum", "avg", "min", "max", "date", "strftime"];

fn reserved(s: &str) -> bool {
    s.get(..RESERVED.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(RESERVED))
}

fn implicit(s: &str) -> bool {
    IMPLICIT.iter().any(|x| x.eq_ignore_ascii_case(s))
}

fn render_ref(name: &str) -> String {
    format!("{RESERVED}{name}")
}

fn schema_uses_reserved(s: &Schema) -> bool {
    s.tables
        .iter()
        .any(|t| reserved(&t.name) || t.columns.iter().any(|c| reserved(&c.name)))
}

/// R45-8 error classes. Those up to `TemplateSlot` go back to the planner;
/// the run-time classes after it end the ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Syntax,
    NotSelect,
    MultipleStatements,
    UnknownTable,
    UnknownColumn,
    FunctionNotAllowed,
    ConstructNotAllowed,
    LiteralNotAllowed,
    ParamMisuse,
    ParamType,
    /// R45-8; the stage-1 grammar leaves no masking construct to detect, so
    /// the validator no longer produces it.
    NullMasking,
    TooManyJoins,
    /// R45-8; unreachable in stage 1 (no subqueries; CTEs are one level).
    TooDeep,
    TooManyColumns,
    /// Owner ruling 2026-11-18 (R45-13): the method would output a value of
    /// an Identifier-class column. Sent to the planner as the class only
    /// (no detail); the user sees [`IDENTIFIER_OUTPUT_REASON`]. Plan 48
    /// hooks its touch-gated reveal on this class.
    IdentifierOutput,
    TemplateSlot,
    RuntimeError,
    TimeCap,
    MemoryCap,
    StepCap,
    CheckFailed,
    /// The entity exists but the method found nothing for it (zero rows, or
    /// every nullable aggregate NULL): a refusal distinct from `empty_for_key`
    /// (the entity has no rows). Run-time class: never sent to the planner.
    EmptyResult,
}

const ALL_CLASSES: [ErrorClass; 22] = [
    ErrorClass::Syntax,
    ErrorClass::NotSelect,
    ErrorClass::MultipleStatements,
    ErrorClass::UnknownTable,
    ErrorClass::UnknownColumn,
    ErrorClass::FunctionNotAllowed,
    ErrorClass::ConstructNotAllowed,
    ErrorClass::LiteralNotAllowed,
    ErrorClass::ParamMisuse,
    ErrorClass::ParamType,
    ErrorClass::NullMasking,
    ErrorClass::TooManyJoins,
    ErrorClass::TooDeep,
    ErrorClass::TooManyColumns,
    ErrorClass::IdentifierOutput,
    ErrorClass::TemplateSlot,
    ErrorClass::RuntimeError,
    ErrorClass::TimeCap,
    ErrorClass::MemoryCap,
    ErrorClass::StepCap,
    ErrorClass::CheckFailed,
    ErrorClass::EmptyResult,
];

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Syntax => "syntax",
            ErrorClass::NotSelect => "not_select",
            ErrorClass::MultipleStatements => "multiple_statements",
            ErrorClass::UnknownTable => "unknown_table",
            ErrorClass::UnknownColumn => "unknown_column",
            ErrorClass::FunctionNotAllowed => "function_not_allowed",
            ErrorClass::ConstructNotAllowed => "construct_not_allowed",
            ErrorClass::LiteralNotAllowed => "literal_not_allowed",
            ErrorClass::ParamMisuse => "param_misuse",
            ErrorClass::ParamType => "param_type",
            ErrorClass::NullMasking => "null_masking",
            ErrorClass::TooManyJoins => "too_many_joins",
            ErrorClass::TooDeep => "too_deep",
            ErrorClass::TooManyColumns => "too_many_columns",
            ErrorClass::IdentifierOutput => "identifier_output",
            ErrorClass::TemplateSlot => "template_slot",
            ErrorClass::RuntimeError => "runtime_error",
            ErrorClass::TimeCap => "time_cap",
            ErrorClass::MemoryCap => "memory_cap",
            ErrorClass::StepCap => "step_cap",
            ErrorClass::CheckFailed => "check_failed",
            ErrorClass::EmptyResult => "empty_result",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<ErrorClass> {
        ALL_CLASSES.iter().copied().find(|c| c.as_str() == s)
    }

    /// The plain-language refusal the user sees for a class that has a
    /// fixed one (owner ruling 2026-11-18: `identifier_output`).
    pub fn user_reason(self) -> Option<&'static str> {
        match self {
            ErrorClass::IdentifierOutput => Some(IDENTIFIER_OUTPUT_REASON),
            _ => None,
        }
    }
}

/// Owner ruling 2026-11-18, verbatim: the refusal reason of
/// [`ErrorClass::IdentifierOutput`].
pub const IDENTIFIER_OUTPUT_REASON: &str =
    "Data Shield doesn't show ID numbers. Revealing one needs a touch on your key.";

/// A refused method: the class and, for `unknown_table` / `unknown_column` /
/// `template_slot`, the cloud name that failed (at most 120 characters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodError {
    pub class: ErrorClass,
    pub detail: Option<String>,
}

impl MethodError {
    fn bare(class: ErrorClass) -> MethodError {
        MethodError {
            class,
            detail: None,
        }
    }

    /// `name` is always a name the planner wrote, never a value.
    fn named(class: ErrorClass, name: &str) -> MethodError {
        MethodError {
            class,
            detail: Some(name.chars().take(DETAIL_MAX).collect()),
        }
    }
}

type R<T> = Result<T, MethodError>;

fn construct<T>() -> R<T> {
    Err(MethodError::bare(ErrorClass::ConstructNotAllowed))
}

fn fail<T>(class: ErrorClass) -> R<T> {
    Err(MethodError::bare(class))
}

/// One bound entity parameter of a method: the input of the executor's
/// existence check (R45-6, Task 3), which counts, with its own fixed query,
/// the rows matching the resolved key in `table` and in every `linked`
/// table, before the method runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityFilter {
    /// The parameter (`pN`).
    pub param: String,
    /// The entity's snapshot table.
    pub table: String,
    /// The entity's snapshot key column.
    pub key: String,
    /// `(snapshot table, snapshot FK column)` of every declared key pair the
    /// method joins to `table.key` (outer block and CTEs), by column origin;
    /// first-seen order, no duplicates. Empty when the method reads the
    /// entity table alone.
    pub linked: Vec<(String, String)>,
}

/// One join of the outermost block, as the validator checked it against the
/// declared key pairs (ruling C-G1). The preview reads joins from here and
/// nowhere else (one source of truth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinEdge {
    /// The index in [`Validated::sources`] of the table this `JOIN` adds
    /// (the first `JOIN` adds source 1; source 0 is the `FROM` table).
    pub joined: usize,
    /// Source index of the key side (the entity key, one row per key).
    pub key: usize,
    /// Source index of the FK side.
    pub fk: usize,
    /// Snapshot table (or CTE) name of the key side.
    pub key_table: String,
    /// Snapshot table (or CTE) name of the FK side.
    pub fk_table: String,
    /// One-to-many: the FK side has several rows per key (a plain FK table,
    /// not a CTE grouped by that column).
    pub fan: bool,
}

/// A validated method.
#[derive(Debug, Clone, PartialEq)]
pub struct Validated {
    /// The outermost block's sources in `FROM` order: snapshot table or CTE
    /// name. Indexes in [`JoinEdge`] and `pinned_sources` refer to it.
    pub sources: Vec<String>,
    /// One edge per `JOIN` of the outermost block, in order.
    pub joins: Vec<JoinEdge>,
    /// Sources of the outermost block that an entity parameter pins
    /// (`key = :pN` / `key IN (:pN)` on that very source).
    pub pinned_sources: Vec<usize>,
    /// Rewritten to snapshot names.
    pub ast: Query,
    /// Rendered from `ast`: the SQL that runs.
    pub sql: String,
    /// The planner's SQL as written (cloud names).
    pub cloud_sql: String,
    /// Parameter names (`pN`) the method uses, in first-use order.
    pub params_used: Vec<String>,
    /// The entity parameters among them.
    pub entity_params: Vec<String>,
    /// Output column indexes that can be NULL over no rows: a `SUM`, `AVG`,
    /// `MIN` or `MAX` (directly or through a CTE column), or arithmetic over
    /// one or with `/`.
    pub aggregates_nullable: Vec<usize>,
    /// One entry per entity parameter in `entity_params`, same order.
    pub entity_filters: Vec<EntityFilter>,
    /// Every output column is a `COUNT` (`COUNT(*)` / `COUNT([DISTINCT] c)`)
    /// or a plain column the outermost block groups by. Then a linked table
    /// with no rows for the key gives a computed 0, not `empty_for_key`.
    pub count_only: bool,
}

/// A validated self-check, ready for the executor.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatedCheck {
    RowsBetween {
        min: u64,
        max: u64,
    },
    /// Two scalar queries (one output column each) that must agree.
    Equal {
        a: Box<Validated>,
        b: Box<Validated>,
    },
}

/// Validate one planner method against the schema, the public values and the
/// draft's parameters. Every bound entity parameter must be used.
pub fn validate(
    sql: &str,
    schema: &Schema,
    public: &[PublicValues],
    params: &[Param],
) -> Result<Validated, MethodError> {
    validate_cols(sql, schema, public, params, true).map(|(v, _)| v)
}

/// Validate a self-check; each side of `Equal` must give one column. A side
/// need not use the bound entity parameters (a check feeds no answer).
pub fn validate_check(
    c: &SelfCheck,
    schema: &Schema,
    public: &[PublicValues],
    params: &[Param],
) -> Result<ValidatedCheck, MethodError> {
    match c {
        SelfCheck::RowsBetween { min, max } => {
            if min > max {
                return fail(ErrorClass::Syntax);
            }
            Ok(ValidatedCheck::RowsBetween {
                min: *min,
                max: *max,
            })
        }
        SelfCheck::Equal { a, b } => {
            let scalar = |s: &str| -> R<Validated> {
                let (v, n) = validate_cols(s, schema, public, params, false)?;
                if n != 1 {
                    return fail(ErrorClass::TooManyColumns);
                }
                Ok(v)
            };
            Ok(ValidatedCheck::Equal {
                a: Box::new(scalar(a)?),
                b: Box::new(scalar(b)?),
            })
        }
    }
}

fn validate_cols(
    sql: &str,
    schema: &Schema,
    public: &[PublicValues],
    params: &[Param],
    all_entities: bool,
) -> R<(Validated, usize)> {
    if sql.len() > METHOD_MAX {
        return fail(ErrorClass::Syntax);
    }
    // A schema using the reserved prefix is refused before anything else
    // (plan 43's import refuses such names; this is the second wall).
    if schema_uses_reserved(schema) {
        return fail(ErrorClass::RuntimeError);
    }
    let stmts = Parser::parse_sql(&SQLiteDialect {}, sql)
        .map_err(|_| MethodError::bare(ErrorClass::Syntax))?;
    match stmts.len() {
        0 => return fail(ErrorClass::Syntax),
        1 => {}
        _ => return fail(ErrorClass::MultipleStatements),
    }
    let Some(Statement::Query(mut q)) = stmts.into_iter().next() else {
        return fail(ErrorClass::NotSelect);
    };
    let mut w = Walk {
        schema,
        public,
        params,
        joins: 0,
        ctes: Vec::new(),
        params_used: Vec::new(),
        entity_params: Vec::new(),
        range_halves: Vec::new(),
        links: Vec::new(),
        agg_seen: false,
        outer: true,
        outer_view: None,
    };
    let out = w.query(&mut q, true)?;
    // Plan 45 final review part 3 (ruling F-h): a date range applied by one
    // half ("in Q3 2026" as `issued >= :pN_from` alone) is another question.
    // Either half needs the other, anywhere in the method.
    for (base, _) in &w.range_halves {
        let has = |s: Suffix| w.range_halves.iter().any(|(b, x)| b == base && *x == s);
        if !(has(Suffix::From) && has(Suffix::To)) {
            return fail(ErrorClass::ParamMisuse);
        }
    }
    // A bound entity the method ignores answers another question.
    if all_entities {
        let unused = params.iter().any(|p| {
            matches!(p.ty, ParamType::Entity { .. })
                && p.bound.is_some()
                && !w.entity_params.contains(&p.name)
        });
        if unused {
            return fail(ErrorClass::ParamMisuse);
        }
    }
    let mut entity_filters = Vec::new();
    for name in &w.entity_params {
        let ent = params
            .iter()
            .find(|p| &p.name == name)
            .and_then(|p| match &p.ty {
                ParamType::Entity { table, .. } => schema.entity_for(table),
                _ => None,
            });
        let Some(ent) = ent else {
            return fail(ErrorClass::ParamMisuse);
        };
        let mut linked: Vec<(String, String)> = Vec::new();
        for l in w.links.iter().filter(|l| l.entity == ent.table) {
            let pair = (l.table.clone(), l.column.clone());
            if !linked.contains(&pair) {
                linked.push(pair);
            }
        }
        entity_filters.push(EntityFilter {
            param: name.clone(),
            table: ent.table.clone(),
            key: ent.key.clone(),
            linked,
        });
    }
    let aggregates_nullable = out
        .iter()
        .enumerate()
        .filter(|(_, c)| c.nullable)
        .map(|(i, _)| i)
        .collect();
    let count_only = !out.is_empty() && out.iter().all(|c| c.counted);
    let rendered = q.to_string();
    let (sources, joins, pinned_sources) = w.outer_view.take().unwrap_or_default();
    Ok((
        Validated {
            sources,
            joins,
            pinned_sources,
            ast: *q,
            sql: rendered,
            cloud_sql: sql.to_string(),
            params_used: w.params_used,
            entity_params: w.entity_params,
            aggregates_nullable,
            entity_filters,
            count_only,
        },
        out.len(),
    ))
}

// ---- the walk ----

/// The shape of an allowed expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A plain column reference.
    Col,
    /// `date(col, …)` / `strftime(fmt, col, …)` over a plain DATE column.
    DateOf,
    /// An aggregate over one plain column (or `COUNT(*)`).
    Agg { count: bool },
    /// One `+ - * /` between two aggregates (outermost block only).
    Arith,
}

/// What the walk knows about an allowed expression.
#[derive(Debug, Clone)]
struct Item {
    kind: Kind,
    ty: Option<ColType>,
    /// `Col` only: the snapshot `(table, column)` it reads, through CTE
    /// provenance. `None` for a CTE column that is not a plain column.
    origin: Option<(String, String)>,
    /// `Col` / `DateOf`: the index of its source in the block.
    src: Option<usize>,
    /// `Col` read straight from a base table.
    base: bool,
    /// Can be NULL over no rows (a non-COUNT aggregate, directly or through
    /// a CTE column or arithmetic, or a division).
    nullable: bool,
    /// A CTE column whose value repeated across rows of its block's join
    /// (review F3): a sum over it would count it more than once.
    repeats: bool,
    /// A CTE column that is the CTE's only GROUP BY item: one row per value.
    unique: bool,
    /// The structural fingerprint (round 5): built from the aggregate kind,
    /// DISTINCT, date-function arguments and column origins (snapshot names,
    /// through CTEs), never from rendered text.
    fp: String,
    /// `Agg` over a base-table column (or `COUNT(*)`): its normalised
    /// leaves, the only kind of arithmetic operand (ruling C-CAP).
    norm: Option<Vec<String>>,
    /// `COUNT(DISTINCT key/FK)`: allowed only as an outermost output (M2).
    key_count: bool,
    /// Yields an Identifier-class value (R45-13, ruling F-j): a plain
    /// Identifier column (by origin through CTEs), or a date function,
    /// non-COUNT aggregate or arithmetic over one.
    ident: bool,
}

impl Item {
    fn new(kind: Kind, ty: Option<ColType>, fp: String) -> Item {
        Item {
            kind,
            ty,
            origin: None,
            src: None,
            base: false,
            nullable: false,
            repeats: false,
            unique: false,
            fp,
            norm: None,
            key_count: false,
            ident: false,
        }
    }

    fn is_col(&self) -> bool {
        matches!(self.kind, Kind::Col | Kind::DateOf)
    }
}

fn is_num(t: Option<ColType>) -> bool {
    matches!(t, Some(ColType::Integer | ColType::Real))
}

fn num_ty(a: Option<ColType>, b: Option<ColType>) -> Option<ColType> {
    match (a, b) {
        (Some(ColType::Integer), Some(ColType::Integer)) => Some(ColType::Integer),
        (x, y) if is_num(x) && is_num(y) => Some(ColType::Real),
        _ => None,
    }
}

/// An output column of a block.
#[derive(Debug, Clone)]
struct OutCol {
    /// The output name (planner alias, or the cloud column name). `None`
    /// for an unnamed expression: it cannot be referenced.
    name: Option<String>,
    ty: Option<ColType>,
    /// A plain column (grouped, when the block aggregates): the snapshot
    /// column it reads. Only such a column can join (addendum (b)).
    origin: Option<(String, String)>,
    nullable: bool,
    /// A COUNT, or a plain column this block groups by.
    counted: bool,
    /// A plain column whose value repeats across the block's rows (F3).
    repeats: bool,
    /// The block's only GROUP BY item: one row per value (F3).
    unique: bool,
    /// The fingerprint of the expression it exposes.
    fp: String,
    /// It yields an Identifier-class value (R45-13).
    ident: bool,
}

#[derive(Debug)]
enum Cols {
    /// Index into `schema.tables`.
    Base(usize),
    Cte(Vec<OutCol>),
}

#[derive(Debug)]
struct Source {
    /// The reference name the planner wrote.
    name: String,
    /// The reference name in the rendered SQL (reserved prefix).
    render: String,
    /// Which table or CTE it reads: no source twice in a block (F3).
    ident: String,
    cols: Cols,
}

#[derive(Debug, Default)]
struct Scope {
    sources: Vec<Source>,
    /// Planner-written output aliases and their (rewritten) expressions, for
    /// GROUP BY / HAVING / ORDER BY. A reference renders as the expression,
    /// never as a bare name SQLite would resolve itself.
    aliases: Vec<(String, Expr, Item)>,
    /// Per source: its rows repeat through a one-to-many join (F3).
    repeated: Vec<bool>,
}

/// One join of a block as (key-side source, FK-side source, fan): `fan`
/// unless the FK side is one row per key (a CTE grouped by that column).
type Edge = (usize, usize, bool);

struct Cte {
    name: String,
    cols: Vec<OutCol>,
}

/// A declared key pair the method joins on (ruling C-G1).
struct Link {
    /// The entity's snapshot table.
    entity: String,
    /// The FK side: snapshot table and column.
    table: String,
    column: String,
}

/// `partner OP operand`, after flipping when the operand is on the left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// `IN` with one item.
    In,
    /// `IN` with more items.
    InMany,
}

impl Cmp {
    fn of(op: &BinaryOperator) -> Option<Cmp> {
        Some(match op {
            BinaryOperator::Eq => Cmp::Eq,
            BinaryOperator::NotEq => Cmp::Ne,
            BinaryOperator::Lt => Cmp::Lt,
            BinaryOperator::LtEq => Cmp::Le,
            BinaryOperator::Gt => Cmp::Gt,
            BinaryOperator::GtEq => Cmp::Ge,
            _ => return None,
        })
    }

    fn flip(self) -> Cmp {
        match self {
            Cmp::Lt => Cmp::Gt,
            Cmp::Le => Cmp::Ge,
            Cmp::Gt => Cmp::Lt,
            Cmp::Ge => Cmp::Le,
            x => x,
        }
    }
}

/// Which clause a condition sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clause {
    /// WHERE; `outer`: of the outermost block (entity keys allowed).
    Where {
        outer: bool,
    },
    Having,
}

fn quoted(s: &str) -> Ident {
    Ident::with_quote('"', s)
}

fn tcloud(t: &TableInfo) -> &str {
    t.alias.as_deref().unwrap_or(&t.name)
}

fn plain_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= NAME_MAX
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// `YYYY-MM-DD` with a plausible month and day.
fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if !(digits(0..4) && digits(5..7) && digits(8..10)) {
        return false;
    }
    let m = (b[5] - b'0') * 10 + (b[6] - b'0');
    let d = (b[8] - b'0') * 10 + (b[9] - b'0');
    (1..=12).contains(&m) && (1..=31).contains(&d)
}

/// A `strftime` format: `%` directives from a fixed set and separators.
fn strftime_format_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            '%' => match it.next() {
                Some('Y' | 'm' | 'd' | 'j' | 'W' | 'w' | 'H' | 'M' | 'S') => {}
                _ => return false,
            },
            '-' | '/' | ':' | ' ' => {}
            _ => return false,
        }
    }
    true
}

/// A date-function modifier: `start of month|year|day`, `weekday N`,
/// `±N day(s)|month(s)|year(s)`.
fn modifier_ok(s: &str) -> bool {
    if matches!(s, "start of month" | "start of year" | "start of day") {
        return true;
    }
    if let Some(n) = s.strip_prefix("weekday ") {
        return n.len() == 1 && (b'0'..=b'6').contains(&n.as_bytes()[0]);
    }
    let Some((num, unit)) = s.split_once(' ') else {
        return false;
    };
    let digits = num.strip_prefix(['+', '-']).unwrap_or("");
    !digits.is_empty()
        && digits.len() <= 4
        && digits.bytes().all(|b| b.is_ascii_digit())
        && matches!(unit, "day" | "days" | "month" | "months" | "year" | "years")
}

/// `digits[.digits]` only.
fn number_ok(s: &str) -> bool {
    let (i, f) = s.split_once('.').unwrap_or((s, "0"));
    !i.is_empty()
        && !f.is_empty()
        && i.bytes().all(|b| b.is_ascii_digit())
        && f.bytes().all(|b| b.is_ascii_digit())
}

/// A `LIMIT` count: an integer literal of at least 1 (G2: `LIMIT 0` gives a
/// false "no rows" for an existing entity).
fn limit_literal(e: &Expr) -> R<()> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Number(s, false)
                if !s.is_empty()
                    && s.len() <= 9
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && s.bytes().any(|b| b != b'0') =>
            {
                Ok(())
            }
            _ => construct(),
        },
        _ => construct(),
    }
}

/// A literal or placeholder operand: `Value`, or `-<number>`.
fn is_value(e: &Expr) -> bool {
    match e {
        Expr::Value(_) => true,
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => matches!(&**expr, Expr::Value(v) if matches!(v.value, Value::Number(..))),
        _ => false,
    }
}

fn is_placeholder(e: &Expr) -> bool {
    matches!(e, Expr::Value(v) if matches!(v.value, Value::Placeholder(_)))
}

/// The closed set of placeholder suffixes: none, `_from`, `_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suffix {
    None,
    From,
    To,
}

/// `:pN`, `:pN_from`, `:pN_to` → (`pN`, suffix). The one splitter the
/// validator and the executor share; the caller looks the base up by exact
/// name and checks the suffix against the parameter's type.
pub fn split_placeholder(t: &str) -> Option<(&str, Suffix)> {
    let rest = t.strip_prefix(':')?;
    let (base, sfx) = if let Some(b) = rest.strip_suffix("_from") {
        (b, Suffix::From)
    } else if let Some(b) = rest.strip_suffix("_to") {
        (b, Suffix::To)
    } else {
        (rest, Suffix::None)
    };
    let n = base.strip_prefix('p')?;
    let ok = !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit());
    ok.then_some((base, sfx))
}

/// The top-level AND conjuncts of an expression (through parentheses).
fn conjuncts<'e>(e: &'e mut Expr, out: &mut Vec<&'e mut Expr>) {
    match e {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            conjuncts(left, out);
            conjuncts(right, out);
        }
        Expr::Nested(i) => conjuncts(i, out),
        other => out.push(other),
    }
}

/// The sources of one block reachable from `start` without edge `skip`
/// (the joins of a block form a tree: each join links one new source).
fn side(n: usize, edges: &[Edge], skip: usize, start: usize) -> Vec<bool> {
    let mut seen = vec![false; n];
    let mut todo = vec![start];
    while let Some(x) = todo.pop() {
        if seen.get(x) != Some(&false) {
            continue;
        }
        seen[x] = true;
        for (i, &(k, f, _)) in edges.iter().enumerate() {
            if i != skip && (k == x || f == x) {
                todo.push(if k == x { f } else { k });
            }
        }
    }
    seen
}

/// Review F3: which sources' rows the joins repeat. A fan edge (one key row,
/// many FK rows) repeats every source on its key side. The FK sides of all
/// fan edges must nest (one chain), else rows multiply across branches (two
/// children of one key, or of two keys) and even COUNT(*) is inflated.
fn fan_out(n: usize, edges: &[Edge]) -> R<Vec<bool>> {
    let fans: Vec<(Vec<bool>, Vec<bool>)> = edges
        .iter()
        .enumerate()
        .filter(|(_, e)| e.2)
        .map(|(i, &(k, f, _))| (side(n, edges, i, k), side(n, edges, i, f)))
        .collect();
    let subset = |a: &[bool], b: &[bool]| a.iter().zip(b).all(|(x, y)| !*x || *y);
    for (i, a) in fans.iter().enumerate() {
        for b in &fans[..i] {
            if !subset(&a.1, &b.1) && !subset(&b.1, &a.1) {
                return construct();
            }
        }
    }
    Ok((0..n).map(|s| fans.iter().any(|f| f.0[s])).collect())
}

struct Walk<'a> {
    schema: &'a Schema,
    public: &'a [PublicValues],
    params: &'a [Param],
    joins: usize,
    ctes: Vec<Cte>,
    params_used: Vec<String>,
    entity_params: Vec<String>,
    /// The `DateRange` halves seen, as (`pN`, `_from` or `_to`).
    range_halves: Vec<(String, Suffix)>,
    links: Vec<Link>,
    /// An aggregate was seen in the block being walked.
    agg_seen: bool,
    /// The block being walked is the outermost one.
    outer: bool,
    /// The outermost block's sources, join edges and pinned sources.
    outer_view: Option<(Vec<String>, Vec<JoinEdge>, Vec<usize>)>,
}

impl<'a> Walk<'a> {
    /// One query: an optional WITH (outermost only) and one SELECT block.
    fn query(&mut self, q: &mut Query, outer: bool) -> R<Vec<OutCol>> {
        let Query {
            with,
            body,
            order_by,
            limit_clause,
            fetch,
            locks,
            for_clause,
            settings,
            format_clause,
            pipe_operators,
        } = q;
        if fetch.is_some()
            || !locks.is_empty()
            || for_clause.is_some()
            || settings.is_some()
            || format_clause.is_some()
            || !pipe_operators.is_empty()
        {
            return construct();
        }
        if let Some(with) = with {
            if !outer || with.recursive || with.cte_tables.len() > MAX_CTES {
                return construct();
            }
            for cte in &mut with.cte_tables {
                if !cte.alias.columns.is_empty()
                    || cte.alias.at.is_some()
                    || cte.from.is_some()
                    || cte.materialized.is_some()
                {
                    return construct();
                }
                let name = cte.alias.name.value.clone();
                self.check_ref_name(&name, None, &Scope::default())?;
                let cols = self.query(&mut cte.query, false)?;
                cte.alias.name = quoted(&render_ref(&name));
                self.ctes.push(Cte { name, cols });
            }
        }
        let SetExpr::Select(sel) = body.as_mut() else {
            return construct();
        };
        // A CTE cut by LIMIT or ordered for it can drop the key's rows (F4).
        if !outer && (order_by.is_some() || limit_clause.is_some()) {
            return construct();
        }
        let saved = std::mem::replace(&mut self.agg_seen, false);
        let saved_outer = std::mem::replace(&mut self.outer, outer);
        let r = self.select(sel, order_by.as_mut(), outer);
        self.agg_seen = saved;
        self.outer = saved_outer;
        let out = r?;
        // G2: an OFFSET can skip the entity's only row; none in stage 1.
        let limit = match limit_clause {
            None => None,
            Some(LimitClause::LimitOffset {
                limit,
                offset: None,
                limit_by,
            }) if limit_by.is_empty() => limit.as_ref(),
            Some(_) => return construct(),
        };
        if let Some(l) = limit {
            limit_literal(l)?;
        }
        Ok(out)
    }

    fn select(
        &mut self,
        sel: &mut Select,
        order_by: Option<&mut OrderBy>,
        outer: bool,
    ) -> R<Vec<OutCol>> {
        // Every field is named: a field a newer parser adds is a compile
        // error here, not silently accepted (review F6).
        let Select {
            select_token: _,
            optimizer_hints,
            distinct,
            select_modifiers,
            top,
            top_before_distinct: _,
            projection,
            exclude,
            into,
            from,
            lateral_views,
            prewhere,
            selection,
            connect_by,
            group_by,
            cluster_by,
            distribute_by,
            sort_by,
            having,
            named_window,
            qualify,
            window_before_qualify: _,
            value_table_mode,
            flavor,
        } = sel;
        if !optimizer_hints.is_empty()
            || select_modifiers.is_some()
            || top.is_some()
            || exclude.is_some()
            || into.is_some()
            || !lateral_views.is_empty()
            || prewhere.is_some()
            || !connect_by.is_empty()
            || !cluster_by.is_empty()
            || !distribute_by.is_empty()
            || !sort_by.is_empty()
            || !named_window.is_empty()
            || qualify.is_some()
            || value_table_mode.is_some()
            || !matches!(flavor, SelectFlavor::Standard)
            || !matches!(distinct, None | Some(Distinct::Distinct))
            || from.len() > 1
        {
            return construct();
        }
        if projection.len() > MAX_COLUMNS {
            return fail(ErrorClass::TooManyColumns);
        }
        let mut sc = Scope::default();
        let mut view_edges: Vec<JoinEdge> = Vec::new();

        // FROM and JOIN: register every source, then check each ON.
        if let Some(twj) = from.first_mut() {
            self.joins += twj.joins.len();
            if self.joins > MAX_JOINS {
                return fail(ErrorClass::TooManyJoins);
            }
            self.factor(&mut twj.relation, &mut sc)?;
            for j in &mut twj.joins {
                let inner = matches!(
                    j.join_operator,
                    JoinOperator::Join(JoinConstraint::On(_))
                        | JoinOperator::Inner(JoinConstraint::On(_))
                );
                if j.global || !inner {
                    return construct();
                }
                self.factor(&mut j.relation, &mut sc)?;
            }
            // F3 (b): no table or CTE twice in a block.
            let idents: Vec<&str> = sc.sources.iter().map(|x| x.ident.as_str()).collect();
            for (i, a) in idents.iter().enumerate() {
                if idents[..i].contains(a) {
                    return construct();
                }
            }
            let mut edges = Vec::with_capacity(twj.joins.len());
            for (k, j) in twj.joins.iter_mut().enumerate() {
                let (JoinOperator::Join(JoinConstraint::On(on))
                | JoinOperator::Inner(JoinConstraint::On(on))) = &mut j.join_operator
                else {
                    return construct();
                };
                // Source k + 1 is the joined one; 0..=k come before it.
                edges.push(self.on_clause(on, k + 1, &sc)?);
            }
            sc.repeated = fan_out(sc.sources.len(), &edges)?;
            let label = |i: usize| -> String {
                sc.sources
                    .get(i)
                    .map_or_else(String::new, |x| match &x.cols {
                        Cols::Base(ti) => self.schema.tables[*ti].name.clone(),
                        Cols::Cte(_) => {
                            x.ident.strip_prefix("cte:").unwrap_or(&x.ident).to_string()
                        }
                    })
            };
            view_edges = edges
                .iter()
                .enumerate()
                .map(|(k, &(key, fk, fan))| JoinEdge {
                    joined: k + 1,
                    key,
                    fk,
                    key_table: label(key),
                    fk_table: label(fk),
                    fan,
                })
                .collect();
        }

        // The output columns.
        let mut items: Vec<(Option<String>, Item)> = Vec::new();
        let mut aliases = Vec::new();
        for item in projection.iter_mut() {
            match item {
                SelectItem::UnnamedExpr(e) => {
                    let written = match e {
                        Expr::Identifier(i) => Some(i.value.clone()),
                        Expr::CompoundIdentifier(p) => p.last().map(|i| i.value.clone()),
                        _ => None,
                    };
                    let it = self.output(e, &sc, outer)?;
                    // The outermost output names reach the template and the
                    // result set: a computed item needs its own `AS alias`.
                    if written.is_none() && outer {
                        return construct();
                    }
                    if let Some(name) = &written {
                        // Keep the cloud name as the output name.
                        *item = SelectItem::ExprWithAlias {
                            expr: e.clone(),
                            alias: quoted(name),
                        };
                    }
                    items.push((written, it));
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    let name = alias.value.clone();
                    if !plain_name(&name) || implicit(&name) {
                        return construct();
                    }
                    let it = self.output(expr, &sc, outer)?;
                    *alias = quoted(&name);
                    aliases.push((name.clone(), expr.clone(), it.clone()));
                    items.push((Some(name), it));
                }
                _ => return construct(),
            }
        }
        if from.is_empty() {
            return construct();
        }
        // Templates and the outer block read columns by name: names are
        // unique (ignoring case, as SQLite does).
        let names: Vec<&str> = items.iter().filter_map(|c| c.0.as_deref()).collect();
        for (i, a) in names.iter().enumerate() {
            if names[..i].iter().any(|b| b.eq_ignore_ascii_case(a)) {
                return construct();
            }
        }
        // G3 / H2: two outputs with one fingerprint feed a constant `x - x`
        // later (also through a CTE, whose columns carry the fingerprint).
        for (i, a) in items.iter().enumerate() {
            if items[..i].iter().any(|b| b.1.fp == a.1.fp) {
                return construct();
            }
        }

        let mut pinned = Vec::new();
        if let Some(e) = selection {
            let mut cs = Vec::new();
            conjuncts(e, &mut cs);
            for c in cs {
                self.condition(c, &sc, Clause::Where { outer }, &mut pinned)?;
            }
        }
        sc.aliases = aliases;
        let mut groups = Vec::new();
        match group_by {
            GroupByExpr::Expressions(es, mods) if mods.is_empty() => {
                for e in es {
                    let it = self.term(e, &sc, true)?;
                    if !it.is_col() {
                        return construct();
                    }
                    groups.push((it.src, it.fp));
                }
            }
            _ => return construct(),
        }
        if let Some(e) = having.as_mut() {
            let mut cs = Vec::new();
            conjuncts(e, &mut cs);
            for c in cs {
                self.condition(c, &sc, Clause::Having, &mut pinned)?;
            }
        }
        if let Some(ob) = order_by {
            if ob.interpolate.is_some() {
                return construct();
            }
            let OrderByKind::Expressions(obs) = &mut ob.kind else {
                return construct();
            };
            for o in obs {
                let sort_ok = matches!(
                    o.options.sort,
                    None | Some(OrderBySort::Asc | OrderBySort::Desc)
                );
                if o.with_fill.is_some() || o.options.nulls_first.is_some() || !sort_ok {
                    return construct();
                }
                let it = self.term(&mut o.expr, &sc, true)?;
                if self.structural(&it) {
                    return construct();
                }
            }
        }

        if outer {
            let names = sc
                .sources
                .iter()
                .map(|x| match &x.cols {
                    Cols::Base(ti) => self.schema.tables[*ti].name.clone(),
                    Cols::Cte(_) => x.ident.strip_prefix("cte:").unwrap_or(&x.ident).to_string(),
                })
                .collect();
            let mut pins = pinned.clone();
            pins.sort_unstable();
            pins.dedup();
            self.outer_view = Some((names, view_edges, pins));
        }

        // Addendum (a): in an aggregating block a plain column is grouped,
        // or (outermost only) a column of the source a `key = :pN` pins.
        let aggregating = self.agg_seen || !groups.is_empty() || having.is_some();
        let mut out = Vec::with_capacity(items.len());
        for (name, it) in items {
            // M2: COUNT(DISTINCT key) is not a value a CTE passes on.
            if it.key_count && !outer {
                return construct();
            }
            let grouped = it.is_col() && groups.contains(&(it.src, it.fp.clone()));
            if aggregating && it.is_col() && !grouped {
                let pin_ok = outer && it.src.is_some_and(|s| pinned.contains(&s));
                if !pin_ok {
                    return construct();
                }
            }
            out.push(OutCol {
                name,
                ty: it.ty,
                origin: if it.kind == Kind::Col {
                    it.origin.clone()
                } else {
                    None
                },
                nullable: it.nullable,
                counted: grouped || it.kind == (Kind::Agg { count: true }),
                repeats: it.is_col() && (it.repeats || it.src.is_some_and(|s| sc.repeated[s])),
                unique: it.kind == Kind::Col && groups.len() == 1 && grouped,
                fp: it.fp,
                ident: it.ident,
            });
        }
        Ok(out)
    }

    /// One FROM / JOIN source: a schema table or a CTE.
    fn factor(&mut self, tf: &mut TableFactor, sc: &mut Scope) -> R<()> {
        let TableFactor::Table {
            name,
            alias,
            args,
            with_hints,
            version,
            with_ordinality,
            partitions,
            json_path,
            sample,
            index_hints,
        } = tf
        else {
            return construct();
        };
        if args.is_some()
            || !with_hints.is_empty()
            || version.is_some()
            || *with_ordinality
            || !partitions.is_empty()
            || json_path.is_some()
            || sample.is_some()
            || !index_hints.is_empty()
        {
            return construct();
        }
        let written = match name.0.as_slice() {
            [ObjectNamePart::Identifier(i)] => i.value.clone(),
            parts => {
                let joined: Vec<String> = parts.iter().map(|p| p.to_string()).collect();
                return Err(MethodError::named(
                    ErrorClass::UnknownTable,
                    &joined.join("."),
                ));
            }
        };
        let (cols, rendered, ident) = if let Some(c) = self.ctes.iter().find(|c| c.name == written)
        {
            (
                Cols::Cte(c.cols.clone()),
                render_ref(&written),
                format!("cte:{written}"),
            )
        } else if let Some(ti) = self.schema.tables.iter().position(|t| tcloud(t) == written) {
            (
                Cols::Base(ti),
                self.schema.tables[ti].name.clone(),
                format!("table:{ti}"),
            )
        } else {
            return Err(MethodError::named(ErrorClass::UnknownTable, &written));
        };
        *name = ObjectName::from(vec![quoted(&rendered)]);
        let refname = match alias {
            Some(a) => {
                if !a.columns.is_empty() || a.at.is_some() {
                    return construct();
                }
                let n = a.name.value.clone();
                self.check_ref_name(&n, None, sc)?;
                a.name = quoted(&render_ref(&n));
                n
            }
            None => {
                self.check_ref_name(&written, Some(&written), sc)?;
                if matches!(cols, Cols::Base(_)) {
                    // A base table is referenced under the prefixed cloud
                    // name; a CTE already renders prefixed.
                    *alias = Some(TableAlias {
                        explicit: true,
                        name: quoted(&render_ref(&written)),
                        columns: Vec::new(),
                        at: None,
                    });
                }
                written
            }
        };
        let render = render_ref(&refname);
        sc.sources.push(Source {
            name: refname,
            render,
            ident,
            cols,
        });
        sc.repeated.push(false);
        Ok(())
    }

    /// A planner-chosen reference name (CTE name, table alias, or an
    /// unaliased table's own name `own`). It must be a plain identifier, not
    /// a rowid name and, ignoring case as SQLite does, must not collide with
    /// a cloud-visible table name, a CTE, or a source in scope. Only names
    /// the cloud was shown are compared (review S1): the outcome never
    /// depends on a hidden snapshot name. An unaliased table or CTE may
    /// carry its own name.
    fn check_ref_name(&self, name: &str, own: Option<&str>, sc: &Scope) -> R<()> {
        if !plain_name(name) || implicit(name) {
            return construct();
        }
        let eq = |x: &str| x.eq_ignore_ascii_case(name);
        if own != Some(name) {
            let schema_hit = self.schema.tables.iter().any(|t| eq(tcloud(t)));
            if schema_hit || self.ctes.iter().any(|c| eq(&c.name)) {
                return construct();
            }
        }
        if sc.sources.iter().any(|s| eq(&s.name)) {
            return construct();
        }
        Ok(())
    }

    /// ON: an AND of `a = b`, each a declared key pair between the joined
    /// source and one before it, by column origin (ruling C-G1), all between
    /// the same two sources. The key side must be one row per key: a base
    /// table, or a CTE grouped by that column alone (review F3).
    fn on_clause(&mut self, on: &mut Expr, joined: usize, sc: &Scope) -> R<Edge> {
        let mut cs = Vec::new();
        conjuncts(on, &mut cs);
        let mut edge: Option<Edge> = None;
        for c in cs {
            let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = c
            else {
                return construct();
            };
            if is_value(left) || is_value(right) {
                return construct();
            }
            let a = self.term(left, sc, false)?;
            let b = self.term(right, sc, false)?;
            let (Kind::Col, Kind::Col) = (a.kind, b.kind) else {
                return construct();
            };
            let (Some(sa), Some(sb)) = (a.src, b.src) else {
                return construct();
            };
            let crosses = (sa == joined && sb < joined) || (sb == joined && sa < joined);
            let (Some(oa), Some(ob)) = (&a.origin, &b.origin) else {
                return construct();
            };
            let Some((link, a_is_key)) = self.key_pair(oa, ob) else {
                return construct();
            };
            let (key, fk) = if a_is_key { (&a, &b) } else { (&b, &a) };
            if !crosses || !(key.base || key.unique) {
                return construct();
            }
            let this = (key.src.unwrap_or(0), fk.src.unwrap_or(0), !fk.unique);
            match edge {
                Some(e) if e != this => return construct(),
                _ => edge = Some(this),
            }
            self.links.push(link);
        }
        edge.map_or_else(construct, Ok)
    }

    /// The C-G1 FK name of an entity, from cloud names only (review F1):
    /// `<word>_<cloud name of the key>`, ASCII-lowercased.
    fn fk_name(&self, e: &EntitySpec) -> String {
        let key = self.schema.cloud_name(&e.table, Some(&e.key));
        format!("{}_{}", e.word, key).to_ascii_lowercase()
    }

    fn is_int(&self, (t, c): &(String, String)) -> bool {
        self.schema
            .column(t, c)
            .is_some_and(|x| x.ty == ColType::Integer)
    }

    fn is_entity_key(e: &EntitySpec, x: &(String, String)) -> bool {
        x.0 == e.table && x.1 == e.key
    }

    fn is_fk_of(&self, e: &EntitySpec, x: &(String, String)) -> bool {
        x.0 != e.table && self.schema.cloud_name(&x.0, Some(&x.1)) == self.fk_name(e)
    }

    /// Ruling C-G1 on cloud names: entity key `E.table.E.key` ↔ a column in
    /// another table whose cloud name is [`Self::fk_name`], both INTEGER. The
    /// outcome never depends on a snapshot name behind an alias. Returns the
    /// link and whether `a` is the key side.
    fn key_pair(&self, a: &(String, String), b: &(String, String)) -> Option<(Link, bool)> {
        if !self.is_int(a) || !self.is_int(b) {
            return None;
        }
        self.schema.entities.iter().find_map(|e| {
            let (other, a_is_key) = if Self::is_entity_key(e, a) && self.is_fk_of(e, b) {
                (b, true)
            } else if Self::is_entity_key(e, b) && self.is_fk_of(e, a) {
                (a, false)
            } else {
                return None;
            };
            let link = Link {
                entity: e.table.clone(),
                table: other.0.clone(),
                column: other.1.clone(),
            };
            Some((link, a_is_key))
        })
    }

    /// An entity key or a C-G1 FK column.
    fn is_key_col(&self, x: &(String, String)) -> bool {
        self.is_int(x)
            && self
                .schema
                .entities
                .iter()
                .any(|e| Self::is_entity_key(e, x) || self.is_fk_of(e, x))
    }

    /// G1: a plain column whose origin (through CTEs) is an entity key or a
    /// C-G1 FK column is structural. It may appear only in a key-pair ON,
    /// the entity pin (`key = :pN` / `key IN (:pN)`), GROUP BY, a plain
    /// output column, or `COUNT(DISTINCT col)`. Anywhere else (a comparison
    /// with a literal, a non-entity parameter or a column; inside another
    /// aggregate; ORDER BY) it can defeat the pin, so it is refused.
    fn structural(&self, it: &Item) -> bool {
        it.kind == Kind::Col && it.origin.as_ref().is_some_and(|o| self.is_key_col(o))
    }

    // ---- names ----

    /// The column `name` of one source as (rendered name, item): exactly one
    /// case-insensitive match, and it must be the exact name.
    fn column_in(&self, src: &Source, name: &str) -> Option<Result<(String, Item), ()>> {
        let cols: Vec<(String, String, Item)> = match &src.cols {
            Cols::Base(ti) => {
                let t = &self.schema.tables[*ti];
                t.columns
                    .iter()
                    .map(|c| {
                        let fp = format!("{}.{}", t.name, c.name);
                        let mut it = Item::new(Kind::Col, Some(c.ty), fp);
                        it.origin = Some((t.name.clone(), c.name.clone()));
                        it.base = true;
                        it.ident = c.class == ColumnClass::Identifier;
                        let cloud = c.alias.clone().unwrap_or_else(|| c.name.clone());
                        (cloud, c.name.clone(), it)
                    })
                    .collect()
            }
            Cols::Cte(cols) => cols
                .iter()
                .filter_map(|c| {
                    let n = c.name.clone()?;
                    let mut it = Item::new(Kind::Col, c.ty, c.fp.clone());
                    it.origin = c.origin.clone();
                    it.nullable = c.nullable;
                    it.repeats = c.repeats;
                    it.unique = c.unique;
                    it.ident = c.ident;
                    Some((n.clone(), n, it))
                })
                .collect(),
        };
        let ci: Vec<_> = cols
            .into_iter()
            .filter(|(cloud, _, _)| cloud.eq_ignore_ascii_case(name))
            .collect();
        match ci.as_slice() {
            [] => None,
            [(cloud, rendered, it)] if cloud == name => Some(Ok((rendered.clone(), it.clone()))),
            _ => Some(Err(())),
        }
    }

    fn qualified(&self, parts: &[Ident], sc: &Scope) -> R<(Expr, Item)> {
        let [q, c] = parts else {
            let head: Vec<&str> = parts
                .iter()
                .take(parts.len().saturating_sub(1))
                .map(|i| i.value.as_str())
                .collect();
            return Err(MethodError::named(
                ErrorClass::UnknownTable,
                &head.join("."),
            ));
        };
        let Some((at, src)) = sc
            .sources
            .iter()
            .enumerate()
            .find(|(_, s)| s.name == q.value)
        else {
            return Err(MethodError::named(ErrorClass::UnknownTable, &q.value));
        };
        match self.column_in(src, &c.value) {
            Some(Ok((rendered, mut it))) => {
                it.src = Some(at);
                Ok((
                    Expr::CompoundIdentifier(vec![quoted(&src.render), quoted(&rendered)]),
                    it,
                ))
            }
            _ => Err(MethodError::named(ErrorClass::UnknownColumn, &c.value)),
        }
    }

    fn bare(&self, id: &Ident, sc: &Scope, alias_ok: bool) -> R<(Expr, Item)> {
        let name = id.value.as_str();
        let unknown = || MethodError::named(ErrorClass::UnknownColumn, name);
        let hits: Vec<_> = sc
            .sources
            .iter()
            .enumerate()
            .filter_map(|(at, src)| self.column_in(src, name).map(|r| (at, src, r)))
            .collect();
        let col = match hits.as_slice() {
            [] => None,
            [(at, src, Ok((rendered, it)))] => {
                let mut it = it.clone();
                it.src = Some(*at);
                Some((src.render.clone(), rendered.clone(), it))
            }
            _ => return Err(unknown()),
        };
        let aliases: &[(String, Expr, Item)] = if alias_ok { &sc.aliases } else { &[] };
        let alias_ci: Vec<_> = aliases
            .iter()
            .filter(|(a, _, _)| a.eq_ignore_ascii_case(name))
            .collect();
        match (col, alias_ci.as_slice()) {
            (Some((src, rendered, it)), []) => Ok((
                Expr::CompoundIdentifier(vec![quoted(&src), quoted(&rendered)]),
                it,
            )),
            // The alias renders as its expression: no bare name is left for
            // SQLite to bind to a source column the cloud never saw.
            (None, [(a, expr, it)]) if a == name => Ok((expr.clone(), it.clone())),
            _ => Err(unknown()),
        }
    }

    // ---- expressions ----

    /// One SELECT item. R45-13 (owner ruling 2026-11-18, ruling F-j): the
    /// outermost block outputs no Identifier value (`identifier_output`); a
    /// CTE may carry one (to join, group or count), flagged on its column.
    ///
    /// Class precedence (fail closed either way): in the outermost block,
    /// `MIN`/`MAX`/`SUM`/`AVG`/`date`/`strftime` straight over an Identifier
    /// column is `identifier_output` before the key-column rule (G1) can
    /// call it `construct_not_allowed`; and in any block, an item the
    /// grammar refuses as `function_not_allowed` or `construct_not_allowed`
    /// that names an Identifier column of the block (`substr(cpr, 1, 6)`,
    /// `lower(email)`, `cpr || ''`, `CASE`) is `identifier_output`: "any
    /// expression whose inputs include an Identifier column counts as
    /// yielding it" (owner), so the planner learns that no rewrite will
    /// print it and plan 48 can offer its reveal. Name and literal classes
    /// (`unknown_column`, `literal_not_allowed`, ...) keep their class.
    fn output(&mut self, e: &mut Expr, sc: &Scope, outer: bool) -> R<Item> {
        if outer && self.over_ident(e, sc) {
            return fail(ErrorClass::IdentifierOutput);
        }
        let names_ident = self.names_ident(&e.to_string(), sc);
        match self.term(e, sc, false) {
            Ok(it) if outer && it.ident => fail(ErrorClass::IdentifierOutput),
            Ok(it) => Ok(it),
            Err(err)
                if names_ident
                    && matches!(
                        err.class,
                        ErrorClass::FunctionNotAllowed | ErrorClass::ConstructNotAllowed
                    ) =>
            {
                fail(ErrorClass::IdentifierOutput)
            }
            Err(err) => Err(err),
        }
    }

    /// `MIN|MAX|SUM|AVG(col)`, `date(col, …)` or `strftime(fmt, col, …)`
    /// whose column argument is a plain Identifier column.
    fn over_ident(&self, e: &Expr, sc: &Scope) -> bool {
        let mut e = e;
        while let Expr::Nested(i) = e {
            e = i;
        }
        let Expr::Function(f) = e else {
            return false;
        };
        let [ObjectNamePart::Identifier(n)] = f.name.0.as_slice() else {
            return false;
        };
        let at = match n.value.to_ascii_lowercase().as_str() {
            "min" | "max" | "sum" | "avg" | "date" => 0,
            "strftime" => 1,
            _ => return false,
        };
        let FunctionArguments::List(list) = &f.args else {
            return false;
        };
        let col = match list.args.get(at) {
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id)))) => {
                self.bare(id, sc, false)
            }
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::CompoundIdentifier(p)))) => {
                self.qualified(p, sc)
            }
            _ => return false,
        };
        col.is_ok_and(|(_, it)| it.ident)
    }

    /// Any name token of `text` (outside single-quoted strings) that is a
    /// column of a source in scope yielding an Identifier value. Used only
    /// to choose the class of an item that is refused anyway.
    fn names_ident(&self, text: &str, sc: &Scope) -> bool {
        let mut tokens: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut quote: Option<char> = None;
        for ch in text.chars() {
            match quote {
                Some('\'') if ch == '\'' => quote = None,
                Some('\'') => {}
                Some(q) if ch == q => {
                    quote = None;
                    tokens.push(std::mem::take(&mut cur));
                }
                Some(_) => cur.push(ch),
                None if ch == '\'' || ch == '"' || ch == '`' => {
                    tokens.push(std::mem::take(&mut cur));
                    quote = Some(ch);
                }
                None if ch.is_alphanumeric() || ch == '_' => cur.push(ch),
                None => tokens.push(std::mem::take(&mut cur)),
            }
        }
        tokens.push(cur);
        tokens.iter().filter(|t| !t.is_empty()).any(|t| {
            sc.sources
                .iter()
                .any(|s| matches!(self.column_in(s, t), Some(Ok((_, it))) if it.ident))
        })
    }

    /// An allowed expression: a column, a date expression, an aggregate, or
    /// arithmetic between aggregates. A literal is `literal_not_allowed`, a
    /// placeholder `param_misuse`; anything else is refused.
    fn term(&mut self, e: &mut Expr, sc: &Scope, alias_ok: bool) -> R<Item> {
        match e {
            Expr::Identifier(id) => {
                let (new, it) = self.bare(id, sc, alias_ok)?;
                *e = new;
                Ok(it)
            }
            Expr::CompoundIdentifier(parts) => {
                let (new, it) = self.qualified(parts, sc)?;
                *e = new;
                Ok(it)
            }
            Expr::Nested(inner) => {
                let it = self.term(inner, sc, alias_ok)?;
                // Canonical rendering: parentheses stay only where they carry
                // precedence (around arithmetic).
                if !matches!(**inner, Expr::BinaryOp { .. }) {
                    let new = (**inner).clone();
                    *e = new;
                }
                Ok(it)
            }
            Expr::Function(f) => self.function(f, sc),
            Expr::BinaryOp { left, op, right } => {
                let sym = match op {
                    BinaryOperator::Plus => "+",
                    BinaryOperator::Minus => "-",
                    BinaryOperator::Multiply => "*",
                    BinaryOperator::Divide => "/",
                    _ => return construct(),
                };
                let divide = sym == "/";
                let a = self.term(left, sc, alias_ok)?;
                let b = self.term(right, sc, alias_ok)?;
                // Ruling C-CAP: one operator, in the outermost block, between
                // two aggregates over base-table columns whose normalised
                // leaves are disjoint (`x - x`, `AVG(x) / SUM(x)` refused).
                // COUNT(DISTINCT key) is no operand (M2).
                let (Some(na), Some(nb)) = (&a.norm, &b.norm) else {
                    return construct();
                };
                if !self.outer || a.key_count || b.key_count || na.iter().any(|l| nb.contains(l)) {
                    return construct();
                }
                // `+` and `*` commute: sort the operands of the fingerprint.
                let (fa, fb) = if matches!(sym, "+" | "*") && b.fp < a.fp {
                    (&b.fp, &a.fp)
                } else {
                    (&a.fp, &b.fp)
                };
                // Plan 45 final review I2: arithmetic is between numbers only
                // (`MIN(t.date) - MAX(t.date)` would be a number SQLite makes
                // up from text).
                let Some(ty) = num_ty(a.ty, b.ty) else {
                    return construct();
                };
                // Plan 45 final review I1 (ruling F-b): SQLite divides two
                // INTEGERs as integers (`SUM(a) / COUNT(*)` = 2 for 1, 2, 4).
                // Saiife's rendered SQL casts the left operand to REAL, so the
                // division is always real and the output is REAL. The
                // planner's grammar has no CAST; only the rendering does.
                let ty = if divide {
                    let inner = (**left).clone();
                    **left = Expr::Cast {
                        kind: CastKind::Cast,
                        expr: Box::new(inner),
                        data_type: DataType::Real,
                        format: None,
                    };
                    ColType::Real
                } else {
                    ty
                };
                let fp = format!("({fa} {sym} {fb})");
                let mut it = Item::new(Kind::Arith, Some(ty), fp);
                it.nullable = a.nullable || b.nullable || divide;
                it.ident = a.ident || b.ident;
                Ok(it)
            }
            Expr::Value(v) => match v.value {
                Value::Placeholder(_) => fail(ErrorClass::ParamMisuse),
                Value::Boolean(_) => construct(),
                _ => fail(ErrorClass::LiteralNotAllowed),
            },
            _ => construct(),
        }
    }

    fn function(&mut self, f: &mut Function, sc: &Scope) -> R<Item> {
        let lname = match f.name.0.as_slice() {
            [ObjectNamePart::Identifier(i)] if i.quote_style.is_none() => {
                i.value.to_ascii_lowercase()
            }
            _ => return fail(ErrorClass::FunctionNotAllowed),
        };
        if !FUNCTIONS.contains(&lname.as_str()) {
            return fail(ErrorClass::FunctionNotAllowed);
        }
        if f.uses_odbc_syntax
            || f.over.is_some()
            || f.filter.is_some()
            || f.null_treatment.is_some()
            || !f.within_group.is_empty()
            || !matches!(f.parameters, FunctionArguments::None)
        {
            return construct();
        }
        let FunctionArguments::List(list) = &mut f.args else {
            return construct();
        };
        if !list.clauses.is_empty() {
            return construct();
        }
        let date = matches!(lname.as_str(), "date" | "strftime");
        let item = if date {
            self.date_fn(lname == "strftime", list, sc)?
        } else {
            self.aggregate(&lname, list, sc)?
        };
        // Canonical rendering of the name.
        let canon = if date {
            lname
        } else {
            lname.to_ascii_uppercase()
        };
        f.name = ObjectName::from(vec![Ident::new(canon)]);
        Ok(item)
    }

    /// `COUNT(*)`, or an aggregate over one plain column.
    fn aggregate(&mut self, l: &str, list: &mut FunctionArgumentList, sc: &Scope) -> R<Item> {
        let distinct = match list.duplicate_treatment {
            None => false,
            Some(DuplicateTreatment::Distinct) => true,
            Some(_) => return construct(),
        };
        let count = l == "count";
        // MIN / MAX DISTINCT means nothing more than MIN / MAX.
        if distinct && matches!(l, "min" | "max") {
            return construct();
        }
        let [arg] = list.args.as_mut_slice() else {
            return construct();
        };
        let mut key_count = false;
        let (arg_ty, arg_fp, base, arg_ident) = match arg {
            FunctionArg::Unnamed(FunctionArgExpr::Wildcard) if count && !distinct => {
                (None, "*".to_string(), true, false)
            }
            FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) => {
                // An output alias is not a column here.
                let it = self.term(x, sc, false)?;
                if it.kind != Kind::Col {
                    return construct();
                }
                // G1: a key or FK column is counted distinct, never summed,
                // compared through MIN/MAX, or counted per row.
                if self.structural(&it) {
                    if !(count && distinct) {
                        return construct();
                    }
                    key_count = true;
                }
                // F3 (c): a SUM / AVG / COUNT(col) over a value the join
                // repeats counts it once per repeat. COUNT(*), COUNT(DISTINCT)
                // and MIN / MAX are not changed by repeats.
                let repeated = it.repeats || it.src.is_some_and(|s| sc.repeated[s]);
                let inflates = matches!(l, "sum" | "avg") || (count && !distinct);
                if repeated && inflates {
                    return construct();
                }
                // Plan 45 final review I2: SUM / AVG add numbers. Over a TEXT
                // or DATE column (by origin through CTEs) SQLite sums leading
                // digits (`'2026-07-01'` is 2026) or gives 0.0: refused
                // (`construct_not_allowed`). MIN / MAX / COUNT stay.
                if matches!(l, "sum" | "avg") && !is_num(it.ty) {
                    return construct();
                }
                (it.ty, it.fp, it.base, it.ident)
            }
            _ => return construct(),
        };
        self.agg_seen = true;
        let ty = match l {
            "count" => Some(ColType::Integer),
            "sum" | "avg" => Some(ColType::Real),
            _ => arg_ty,
        };
        let d = if distinct { " distinct" } else { "" };
        let fp = format!("{l}{d}({arg_fp})");
        // C-CAP leaves: AVG(x) is SUM(x) and COUNT(x); COUNT(x) is COUNT(*).
        let counted = if distinct {
            format!("count distinct({arg_fp})")
        } else {
            "count(*)".to_string()
        };
        let norm = match l {
            "count" => vec![counted],
            "avg" => vec![format!("sum{d}({arg_fp})"), counted],
            _ => vec![fp.clone()],
        };
        let mut it = Item::new(Kind::Agg { count }, ty, fp);
        it.norm = base.then_some(norm);
        it.key_count = key_count;
        it.nullable = !count;
        // Ruling F-j: only the COUNTs hide an Identifier; MIN / MAX (and
        // SUM / AVG) return one of its values.
        it.ident = arg_ident && !count;
        Ok(it)
    }

    /// `date(col, mods…)` / `strftime(fmt, col, mods…)` over a plain DATE
    /// column; the format and modifiers are literals from a fixed grammar.
    fn date_fn(&mut self, strftime: bool, list: &mut FunctionArgumentList, sc: &Scope) -> R<Item> {
        if list.duplicate_treatment.is_some() {
            return construct();
        }
        let col_at = usize::from(strftime);
        let n = list.args.len();
        if n <= col_at || n > DATE_ARGS_MAX {
            return construct();
        }
        let mut src = None;
        let mut ident = false;
        let mut parts = Vec::with_capacity(n);
        for (i, a) in list.args.iter_mut().enumerate() {
            let FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) = a else {
                return construct();
            };
            if i == col_at {
                let it = self.term(x, sc, false)?;
                if it.kind != Kind::Col || it.ty != Some(ColType::Date) {
                    return construct();
                }
                src = it.src;
                ident = it.ident;
                parts.push(it.fp);
                continue;
            }
            let Expr::Value(v) = x else {
                return construct();
            };
            let ok = match &v.value {
                Value::SingleQuotedString(s) if strftime && i == 0 => strftime_format_ok(s),
                Value::SingleQuotedString(s) => modifier_ok(s),
                _ => false,
            };
            if !ok {
                return fail(ErrorClass::LiteralNotAllowed);
            }
            parts.push(v.value.to_string());
        }
        let ty = if strftime {
            ColType::Text
        } else {
            ColType::Date
        };
        let name = if strftime { "strftime" } else { "date" };
        let fp = format!("{name}({})", parts.join(","));
        let mut it = Item::new(Kind::DateOf, Some(ty), fp);
        it.src = src;
        it.ident = ident;
        Ok(it)
    }

    // ---- conditions ----

    /// One WHERE / HAVING conjunct: `subject op operand` or (WHERE only)
    /// `subject IN (operands)`. The subject is a column or date expression
    /// in WHERE, an aggregate in HAVING; an operand is a placeholder or a
    /// literal.
    fn condition(
        &mut self,
        c: &mut Expr,
        sc: &Scope,
        clause: Clause,
        pinned: &mut Vec<usize>,
    ) -> R<()> {
        let having = clause == Clause::Having;
        let entity_ok = clause == Clause::Where { outer: true };
        match c {
            Expr::BinaryOp { left, op, right } => {
                let Some(cmp) = Cmp::of(op) else {
                    return construct();
                };
                let (subject, operand, cmp) = match (is_value(left), is_value(right)) {
                    (false, true) => (left, right, cmp),
                    (true, false) => (right, left, cmp.flip()),
                    (true, true) if is_placeholder(left) || is_placeholder(right) => {
                        return fail(ErrorClass::ParamType)
                    }
                    _ => return construct(),
                };
                let it = self.subject(subject, sc, having)?;
                self.operand(operand, &it, cmp, entity_ok, pinned)
            }
            Expr::InList {
                expr,
                list,
                negated: false,
            } if !having && !list.is_empty() => {
                let it = self.subject(expr, sc, false)?;
                let cmp = if list.len() == 1 {
                    Cmp::In
                } else {
                    Cmp::InMany
                };
                for item in list {
                    if !is_value(item) {
                        return construct();
                    }
                    self.operand(item, &it, cmp, entity_ok, pinned)?;
                }
                Ok(())
            }
            // Ruling F-k: `t.c IS [NOT] NULL` on a plain column ("customers
            // without a phone"), WHERE only. A key or FK column stays
            // structural (G1): it could defeat the pin.
            Expr::IsNull(x) | Expr::IsNotNull(x) if !having => {
                let it = self.term(x, sc, false)?;
                if it.kind != Kind::Col || self.structural(&it) {
                    return construct();
                }
                Ok(())
            }
            _ => construct(),
        }
    }

    fn subject(&mut self, e: &mut Expr, sc: &Scope, having: bool) -> R<Item> {
        let it = self.term(e, sc, having)?;
        let ok = if having {
            matches!(it.kind, Kind::Agg { .. }) && !it.key_count
        } else {
            it.is_col()
        };
        if !ok {
            return construct();
        }
        Ok(it)
    }

    /// The literal or placeholder compared with `partner`.
    fn operand(
        &mut self,
        e: &Expr,
        partner: &Item,
        cmp: Cmp,
        entity_ok: bool,
        pinned: &mut Vec<usize>,
    ) -> R<()> {
        let v = match e {
            Expr::Value(v) => &v.value,
            Expr::UnaryOp { expr, .. } => match &**expr {
                Expr::Value(v) => &v.value,
                _ => return construct(),
            },
            _ => return construct(),
        };
        // F2 / G1: no literal on an entity key or an FK column (it would
        // defeat the pin), and no number against text or a string against a
        // number.
        let key = self.structural(partner);
        let text = matches!(partner.ty, Some(ColType::Text | ColType::Date));
        let literal_ok = |ok: bool| {
            if ok && !key {
                Ok(())
            } else {
                fail(ErrorClass::LiteralNotAllowed)
            }
        };
        match v {
            Value::Placeholder(p) if matches!(e, Expr::Value(_)) => {
                self.param(p, partner, cmp, entity_ok, pinned)
            }
            Value::SingleQuotedString(s) if matches!(e, Expr::Value(_)) => {
                literal_ok(!is_num(partner.ty))?;
                self.literal(s, partner)
            }
            Value::Number(s, false) if number_ok(s) => literal_ok(!text),
            Value::Boolean(_) => construct(),
            _ => fail(ErrorClass::LiteralNotAllowed),
        }
    }

    /// R45-4: a k-floor public value of the compared plain column, or an ISO
    /// date.
    fn literal(&self, s: &str, partner: &Item) -> R<()> {
        if is_iso_date(s) {
            return Ok(());
        }
        if let (Kind::Col, Some((t, c))) = (partner.kind, &partner.origin) {
            let key = format!("{t}.{c}");
            let public = self
                .public
                .iter()
                .any(|pv| pv.column == key && pv.passing.iter().any(|v| v == s));
            if public {
                return Ok(());
            }
        }
        fail(ErrorClass::LiteralNotAllowed)
    }

    /// R45-3: a placeholder compared with `partner` (as `partner OP param`).
    fn param(
        &mut self,
        text: &str,
        partner: &Item,
        cmp: Cmp,
        entity_ok: bool,
        pinned: &mut Vec<usize>,
    ) -> R<()> {
        let misuse = || fail(ErrorClass::ParamMisuse);
        let Some((base, sfx)) = split_placeholder(text) else {
            return misuse();
        };
        let Some(p) = self.params.iter().find(|p| p.name == base) else {
            return misuse();
        };
        // G1: on a key or FK column only the entity pin below is allowed.
        if self.structural(partner) {
            match &p.ty {
                ParamType::Entity { .. } => {}
                ParamType::Text { .. } => return fail(ErrorClass::ParamType),
                _ => return misuse(),
            }
        }
        let type_ok = match (&p.ty, sfx) {
            (ParamType::Entity { table, .. }, Suffix::None) => {
                let Some(ent) = self.schema.entity_for(table) else {
                    return misuse();
                };
                // `key = :pN` / `key IN (:pN)` on the entity table's own key,
                // read straight from the base table, in the outermost WHERE.
                let on_key = partner.origin.as_ref() == Some(&(ent.table.clone(), ent.key.clone()));
                if !entity_ok
                    || partner.kind != Kind::Col
                    || !partner.base
                    || !on_key
                    || !matches!(cmp, Cmp::Eq | Cmp::In)
                {
                    return misuse();
                }
                // Stage 1 is exactly one key. An unbound draft param passes
                // here; the executor asserts one key at run time (F7, Task 3).
                match &p.bound {
                    None => {}
                    Some(Bound::Keys(k)) if k.len() == 1 => {}
                    Some(_) => return misuse(),
                }
                if let Some(s) = partner.src {
                    pinned.push(s);
                }
                if !self.entity_params.iter().any(|n| n == base) {
                    self.entity_params.push(base.to_string());
                }
                true
            }
            (ParamType::DateRange, s @ (Suffix::From | Suffix::To)) => {
                if partner.ty != Some(ColType::Date) {
                    return fail(ErrorClass::ParamType);
                }
                let op_ok = match s {
                    Suffix::From => cmp == Cmp::Ge,
                    Suffix::To => cmp == Cmp::Lt,
                    Suffix::None => false,
                };
                if !op_ok {
                    return misuse();
                }
                if !self.range_halves.iter().any(|(b, x)| b == base && *x == s) {
                    self.range_halves.push((base.to_string(), s));
                }
                true
            }
            (ParamType::DateRange, Suffix::None) | (_, Suffix::From | Suffix::To) => {
                return misuse()
            }
            (ParamType::Date, Suffix::None) => partner.ty == Some(ColType::Date),
            (ParamType::Amount | ParamType::Integer | ParamType::Percent, Suffix::None) => {
                is_num(partner.ty)
            }
            (ParamType::Text { table, column }, Suffix::None) => {
                partner.kind == Kind::Col
                    && partner.origin.as_ref() == Some(&(table.clone(), column.clone()))
            }
        };
        if !type_ok {
            return fail(ErrorClass::ParamType);
        }
        if !self.params_used.iter().any(|n| n == base) {
            self.params_used.push(base.to_string());
        }
        Ok(())
    }
}
