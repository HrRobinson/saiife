//! Plan 45: the SELECT-only SQL subset validator (spec §2.3.3; R45-1..R45-5,
//! R45-8).
//!
//! The planner's method is parsed with the SQLite dialect and walked by
//! hand. Every construct the walk does not explicitly allow is refused
//! (`construct_not_allowed`): each `match` over the parser's AST ends in a
//! refusal, never in an accept. Names resolve case-exact against the cloud
//! names of the schema (aliases where set) and are rewritten to snapshot
//! names; the SQL that runs is rendered from the rewritten AST, never taken
//! from the planner's string (R45-2).
//!
//! Errors carry a class and, for `unknown_table` / `unknown_column`, the
//! cloud name that failed. Parser error texts are never kept: they can quote
//! the input.

use crate::plan::{SelfCheck, METHOD_MAX};
use crate::public::PublicValues;
use crate::schema::{Bound, ColType, Param, ParamType, Schema, TableInfo};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, Distinct, DuplicateTreatment, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, JoinConstraint, JoinOperator,
    LimitClause, ObjectName, ObjectNamePart, OrderBy, OrderByKind, Query, Select, SelectFlavor,
    SelectItem, SetExpr, Statement, TableAlias, TableFactor, UnaryOperator, Value,
};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

/// R45-1 caps.
pub const MAX_JOINS: usize = 4;
pub const MAX_DEPTH: usize = 2;
pub const MAX_COLUMNS: usize = 32;
pub const MAX_CTES: usize = 2;
/// Longest planner-written name (alias, CTE name).
const NAME_MAX: usize = 64;
/// Longest `detail` sent back to the planner (R45-8).
const DETAIL_MAX: usize = 120;

/// R45-1 function allow-list (`cast` is the `CAST` expression, checked apart).
const FUNCTIONS: [&str; 19] = [
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "total",
    "abs",
    "round",
    "coalesce",
    "ifnull",
    "nullif",
    "lower",
    "upper",
    "length",
    "substr",
    "trim",
    "date",
    "strftime",
    "julianday",
];

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
    NullMasking,
    TooManyJoins,
    TooDeep,
    TooManyColumns,
    TemplateSlot,
    RuntimeError,
    TimeCap,
    MemoryCap,
    StepCap,
    CheckFailed,
}

const ALL_CLASSES: [ErrorClass; 20] = [
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
    ErrorClass::TemplateSlot,
    ErrorClass::RuntimeError,
    ErrorClass::TimeCap,
    ErrorClass::MemoryCap,
    ErrorClass::StepCap,
    ErrorClass::CheckFailed,
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
            ErrorClass::TemplateSlot => "template_slot",
            ErrorClass::RuntimeError => "runtime_error",
            ErrorClass::TimeCap => "time_cap",
            ErrorClass::MemoryCap => "memory_cap",
            ErrorClass::StepCap => "step_cap",
            ErrorClass::CheckFailed => "check_failed",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<ErrorClass> {
        ALL_CLASSES.iter().copied().find(|c| c.as_str() == s)
    }
}

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

/// A validated method.
#[derive(Debug, Clone, PartialEq)]
pub struct Validated {
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
    /// Output column indexes produced by aggregates other than `COUNT`.
    pub aggregates_nullable: Vec<usize>,
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
/// draft's parameters.
pub fn validate(
    sql: &str,
    schema: &Schema,
    public: &[PublicValues],
    params: &[Param],
) -> Result<Validated, MethodError> {
    validate_cols(sql, schema, public, params).map(|(v, _)| v)
}

/// Validate a self-check; each side of `Equal` must give one column.
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
                let (v, n) = validate_cols(s, schema, public, params)?;
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
) -> R<(Validated, usize)> {
    if sql.len() > METHOD_MAX {
        return fail(ErrorClass::Syntax);
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
        masking: false,
    };
    let out = w.query(&mut q, 0, &mut Vec::new())?;
    let entity_bound = params
        .iter()
        .any(|p| matches!(p.ty, ParamType::Entity { .. }) && p.bound.is_some());
    if w.masking && (entity_bound || !w.entity_params.is_empty()) {
        return fail(ErrorClass::NullMasking);
    }
    let aggregates_nullable = out
        .iter()
        .enumerate()
        .filter(|(_, c)| c.info.nullable_agg)
        .map(|(i, _)| i)
        .collect();
    let rendered = q.to_string();
    Ok((
        Validated {
            ast: *q,
            sql: rendered,
            cloud_sql: sql.to_string(),
            params_used: w.params_used,
            entity_params: w.entity_params,
            aggregates_nullable,
        },
        out.len(),
    ))
}

// ---- the walk ----

/// What the walk knows about an expression.
#[derive(Debug, Clone, Default)]
struct Info {
    ty: Option<ColType>,
    /// `(snapshot table, snapshot column)` of a plain column reference.
    origin: Option<(String, String)>,
    /// Reads a column somewhere.
    col: bool,
    /// Holds an aggregate (directly, or through a derived table's column).
    agg: bool,
    /// Holds an aggregate other than `COUNT`.
    nullable_agg: bool,
}

impl Info {
    fn typed(ty: ColType) -> Info {
        Info {
            ty: Some(ty),
            ..Info::default()
        }
    }

    /// Flags of both, no type, no origin.
    fn join(a: &Info, b: &Info) -> Info {
        Info {
            ty: None,
            origin: None,
            col: a.col || b.col,
            agg: a.agg || b.agg,
            nullable_agg: a.nullable_agg || b.nullable_agg,
        }
    }

    fn join_all(xs: &[Info]) -> Info {
        xs.iter()
            .fold(Info::default(), |acc, x| Info::join(&acc, x))
    }

    fn with_ty(mut self, ty: Option<ColType>) -> Info {
        self.ty = ty;
        self.origin = None;
        self
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

#[derive(Debug, Clone)]
struct OutCol {
    /// The output name (planner alias, or the cloud column name). `None`
    /// for an unnamed expression: it cannot be referenced.
    name: Option<String>,
    info: Info,
}

#[derive(Debug)]
enum Cols {
    /// Index into `schema.tables`.
    Base(usize),
    Derived(Vec<OutCol>),
}

#[derive(Debug)]
struct Source {
    /// The reference name: the same in the planner's SQL and the rendered SQL.
    name: String,
    cols: Cols,
}

#[derive(Debug, Default)]
struct Scope {
    sources: Vec<Source>,
    /// Planner-written output aliases, for ORDER BY / GROUP BY / HAVING.
    aliases: Vec<(String, Info)>,
}

struct Cte {
    name: String,
    cols: Vec<OutCol>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Cx {
    depth: usize,
    alias_ok: bool,
    in_agg: bool,
    in_case_when: bool,
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
    Between,
    In,
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

enum Side {
    Param,
    Str,
    Other,
}

fn side(e: &Expr) -> Side {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Placeholder(_) => Side::Param,
            Value::SingleQuotedString(_) => Side::Str,
            _ => Side::Other,
        },
        _ => Side::Other,
    }
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

/// A string literal in a date function's argument `i`: a format (strftime's
/// first), a time value (`now` or an ISO date), or a modifier.
fn date_arg_ok(f: &str, i: usize, s: &str) -> bool {
    let (fmt, time) = if f == "strftime" {
        (Some(0), 1)
    } else {
        (None, 0)
    };
    if fmt == Some(i) {
        strftime_format_ok(s)
    } else if i == time {
        s == "now" || is_iso_date(s)
    } else {
        i > time && modifier_ok(s)
    }
}

/// `-?digits[.digits]` only.
fn number_ok(s: &str) -> bool {
    let (i, f) = s.split_once('.').unwrap_or((s, "0"));
    !i.is_empty()
        && !f.is_empty()
        && i.bytes().all(|b| b.is_ascii_digit())
        && f.bytes().all(|b| b.is_ascii_digit())
}

fn int_literal(e: &Expr) -> R<()> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Number(s, false)
                if !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit()) =>
            {
                Ok(())
            }
            _ => construct(),
        },
        _ => construct(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suffix {
    From,
    To,
}

/// `:pN`, `:pN_from`, `:pN_to` → (`pN`, suffix).
fn split_placeholder(t: &str) -> Option<(&str, Option<Suffix>)> {
    let rest = t.strip_prefix(':')?;
    let (base, sfx) = if let Some(b) = rest.strip_suffix("_from") {
        (b, Some(Suffix::From))
    } else if let Some(b) = rest.strip_suffix("_to") {
        (b, Some(Suffix::To))
    } else {
        (rest, None)
    };
    let n = base.strip_prefix('p')?;
    let ok = !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit());
    ok.then_some((base, sfx))
}

struct Walk<'a> {
    schema: &'a Schema,
    public: &'a [PublicValues],
    params: &'a [Param],
    joins: usize,
    ctes: Vec<Cte>,
    params_used: Vec<String>,
    entity_params: Vec<String>,
    /// A null-masking construct was seen (R45-5); refused at the end if an
    /// entity parameter is in play.
    masking: bool,
}

impl<'a> Walk<'a> {
    fn query(&mut self, q: &mut Query, depth: usize, sc: &mut Vec<Scope>) -> R<Vec<OutCol>> {
        if depth > MAX_DEPTH {
            return fail(ErrorClass::TooDeep);
        }
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
            if depth != 0 || with.recursive || with.cte_tables.len() > MAX_CTES {
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
                self.check_ref_name(&name, None, &[])?;
                let cols = self.query(&mut cte.query, depth + 1, &mut Vec::new())?;
                cte.alias.name = quoted(&name);
                self.ctes.push(Cte { name, cols });
            }
        }
        let SetExpr::Select(sel) = body.as_mut() else {
            return construct();
        };
        sc.push(Scope::default());
        let r = self.select(sel, order_by.as_mut(), depth, sc);
        sc.pop();
        let out = r?;
        match limit_clause {
            None => {}
            Some(LimitClause::LimitOffset {
                limit,
                offset,
                limit_by,
            }) => {
                if !limit_by.is_empty() {
                    return construct();
                }
                if let Some(l) = limit {
                    int_literal(l)?;
                }
                if let Some(o) = offset {
                    int_literal(&o.value)?;
                }
            }
            Some(LimitClause::OffsetCommaLimit { offset, limit }) => {
                int_literal(offset)?;
                int_literal(limit)?;
            }
        }
        Ok(out)
    }

    fn select(
        &mut self,
        sel: &mut Select,
        order_by: Option<&mut OrderBy>,
        depth: usize,
        sc: &mut Vec<Scope>,
    ) -> R<Vec<OutCol>> {
        let s = &*sel;
        if !s.optimizer_hints.is_empty()
            || s.select_modifiers.is_some()
            || s.top.is_some()
            || s.exclude.is_some()
            || s.into.is_some()
            || !s.lateral_views.is_empty()
            || s.prewhere.is_some()
            || !s.connect_by.is_empty()
            || !s.cluster_by.is_empty()
            || !s.distribute_by.is_empty()
            || !s.sort_by.is_empty()
            || !s.named_window.is_empty()
            || s.qualify.is_some()
            || s.value_table_mode.is_some()
            || !matches!(s.flavor, SelectFlavor::Standard)
            || !matches!(s.distinct, None | Some(Distinct::Distinct))
            || s.from.len() > 1
        {
            return construct();
        }
        if s.projection.len() > MAX_COLUMNS {
            return fail(ErrorClass::TooManyColumns);
        }
        let cx = Cx {
            depth,
            ..Cx::default()
        };
        let acx = Cx {
            alias_ok: true,
            ..cx
        };

        // FROM and JOIN: register every source, then resolve the ON clauses.
        if let Some(twj) = sel.from.first_mut() {
            self.joins += twj.joins.len();
            if self.joins > MAX_JOINS {
                return fail(ErrorClass::TooManyJoins);
            }
            self.factor(&mut twj.relation, depth, sc)?;
            for j in &mut twj.joins {
                if j.global {
                    return construct();
                }
                match &j.join_operator {
                    JoinOperator::Join(JoinConstraint::On(_))
                    | JoinOperator::Inner(JoinConstraint::On(_))
                    | JoinOperator::Left(JoinConstraint::On(_))
                    | JoinOperator::LeftOuter(JoinConstraint::On(_)) => {}
                    _ => return construct(),
                }
                self.factor(&mut j.relation, depth, sc)?;
            }
            for j in &mut twj.joins {
                match &mut j.join_operator {
                    JoinOperator::Join(JoinConstraint::On(e))
                    | JoinOperator::Inner(JoinConstraint::On(e))
                    | JoinOperator::Left(JoinConstraint::On(e))
                    | JoinOperator::LeftOuter(JoinConstraint::On(e)) => {
                        self.expr(e, sc, cx)?;
                    }
                    _ => return construct(),
                }
            }
        }

        // The output columns.
        let mut out = Vec::with_capacity(sel.projection.len());
        let mut aliases = Vec::new();
        for item in &mut sel.projection {
            match item {
                SelectItem::UnnamedExpr(e) => {
                    let written = match e {
                        Expr::Identifier(i) => Some(i.value.clone()),
                        Expr::CompoundIdentifier(p) => p.last().map(|i| i.value.clone()),
                        _ => None,
                    };
                    let info = self.expr(e, sc, cx)?;
                    if let Some(name) = &written {
                        // Keep the cloud name as the output name.
                        *item = SelectItem::ExprWithAlias {
                            expr: e.clone(),
                            alias: quoted(name),
                        };
                    }
                    out.push(OutCol {
                        name: written,
                        info,
                    });
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    let name = alias.value.clone();
                    if !plain_name(&name) {
                        return construct();
                    }
                    let info = self.expr(expr, sc, cx)?;
                    *alias = quoted(&name);
                    aliases.push((name.clone(), info.clone()));
                    out.push(OutCol {
                        name: Some(name),
                        info,
                    });
                }
                _ => return construct(),
            }
        }

        if let Some(e) = &mut sel.selection {
            self.expr(e, sc, cx)?;
        }
        if let Some(top) = sc.last_mut() {
            top.aliases = aliases;
        }
        match &mut sel.group_by {
            GroupByExpr::Expressions(es, mods) if mods.is_empty() => {
                for e in es {
                    self.expr(e, sc, acx)?;
                }
            }
            _ => return construct(),
        }
        if let Some(e) = &mut sel.having {
            self.expr(e, sc, acx)?;
        }
        if let Some(ob) = order_by {
            if ob.interpolate.is_some() {
                return construct();
            }
            let OrderByKind::Expressions(items) = &mut ob.kind else {
                return construct();
            };
            for o in items {
                if o.with_fill.is_some() {
                    return construct();
                }
                self.expr(&mut o.expr, sc, acx)?;
            }
        }
        Ok(out)
    }

    /// One FROM / JOIN source: a schema table, a CTE, or a subquery.
    fn factor(&mut self, tf: &mut TableFactor, depth: usize, sc: &mut [Scope]) -> R<()> {
        match tf {
            TableFactor::Table {
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
            } => {
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
                let (cols, rendered) = if let Some(c) = self.ctes.iter().find(|c| c.name == written)
                {
                    (Cols::Derived(c.cols.clone()), written.clone())
                } else if let Some(ti) =
                    self.schema.tables.iter().position(|t| tcloud(t) == written)
                {
                    (Cols::Base(ti), self.schema.tables[ti].name.clone())
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
                        a.name = quoted(&n);
                        n
                    }
                    None => {
                        self.check_ref_name(&written, Some(&written), sc)?;
                        if rendered != written {
                            // The rendered SQL keeps the planner's reference name.
                            *alias = Some(TableAlias {
                                explicit: true,
                                name: quoted(&written),
                                columns: Vec::new(),
                                at: None,
                            });
                        }
                        written
                    }
                };
                self.push_source(sc, refname, cols);
                Ok(())
            }
            TableFactor::Derived {
                lateral,
                subquery,
                alias,
                sample,
            } => {
                if *lateral || sample.is_some() {
                    return construct();
                }
                let Some(a) = alias else {
                    return construct();
                };
                if !a.columns.is_empty() || a.at.is_some() {
                    return construct();
                }
                let n = a.name.value.clone();
                self.check_ref_name(&n, None, sc)?;
                a.name = quoted(&n);
                // A FROM subquery cannot see the enclosing query's sources.
                let cols = self.query(subquery, depth + 1, &mut Vec::new())?;
                self.push_source(sc, n, Cols::Derived(cols));
                Ok(())
            }
            _ => construct(),
        }
    }

    fn push_source(&self, sc: &mut [Scope], name: String, cols: Cols) {
        if let Some(s) = sc.last_mut() {
            s.sources.push(Source { name, cols });
        }
    }

    /// A planner-chosen reference name (CTE name, table alias, or an
    /// unaliased table's own name `own`). It must be a plain identifier and,
    /// ignoring case as SQLite does, must not collide with a schema table
    /// (snapshot or cloud name), a CTE, or a source in scope. An unaliased
    /// table or CTE may of course carry its own name.
    fn check_ref_name(&self, name: &str, own: Option<&str>, sc: &[Scope]) -> R<()> {
        if !plain_name(name) {
            return construct();
        }
        let eq = |x: &str| x.eq_ignore_ascii_case(name);
        if own != Some(name) {
            let schema_hit = self
                .schema
                .tables
                .iter()
                .any(|t| eq(&t.name) || eq(tcloud(t)));
            if schema_hit || self.ctes.iter().any(|c| eq(&c.name)) {
                return construct();
            }
        }
        if sc.iter().flat_map(|s| &s.sources).any(|s| eq(&s.name)) {
            return construct();
        }
        Ok(())
    }

    // ---- names ----

    /// The columns of a source as (cloud name, rendered name, info).
    fn columns_of(&self, src: &Source) -> Vec<(String, String, Info)> {
        match &src.cols {
            Cols::Base(ti) => {
                let t = &self.schema.tables[*ti];
                t.columns
                    .iter()
                    .map(|c| {
                        let info = Info {
                            ty: Some(c.ty),
                            origin: Some((t.name.clone(), c.name.clone())),
                            col: true,
                            agg: false,
                            nullable_agg: false,
                        };
                        let cloud = c.alias.clone().unwrap_or_else(|| c.name.clone());
                        (cloud, c.name.clone(), info)
                    })
                    .collect()
            }
            Cols::Derived(cols) => cols
                .iter()
                .filter_map(|c| {
                    let n = c.name.clone()?;
                    let mut info = c.info.clone();
                    info.col = true;
                    Some((n.clone(), n, info))
                })
                .collect(),
        }
    }

    /// Look `name` up in one source: exactly one case-insensitive match,
    /// and it must be the exact name.
    fn column_in(&self, src: &Source, name: &str) -> Option<Result<(String, Info), ()>> {
        let cols = self.columns_of(src);
        let ci: Vec<_> = cols
            .into_iter()
            .filter(|(cloud, _, _)| cloud.eq_ignore_ascii_case(name))
            .collect();
        match ci.as_slice() {
            [] => None,
            [(cloud, rendered, info)] if cloud == name => {
                Some(Ok((rendered.clone(), info.clone())))
            }
            _ => Some(Err(())),
        }
    }

    fn qualified(&self, parts: &[Ident], sc: &[Scope]) -> R<(Expr, Info)> {
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
        let Some(src) = sc
            .iter()
            .rev()
            .flat_map(|s| s.sources.iter())
            .find(|s| s.name == q.value)
        else {
            return Err(MethodError::named(ErrorClass::UnknownTable, &q.value));
        };
        match self.column_in(src, &c.value) {
            Some(Ok((rendered, info))) => Ok((
                Expr::CompoundIdentifier(vec![quoted(&src.name), quoted(&rendered)]),
                info,
            )),
            _ => Err(MethodError::named(ErrorClass::UnknownColumn, &c.value)),
        }
    }

    fn bare(&self, id: &Ident, sc: &[Scope], cx: Cx) -> R<(Expr, Info)> {
        let name = id.value.as_str();
        let unknown = || MethodError::named(ErrorClass::UnknownColumn, name);
        // Source columns, innermost scope first; the first scope with any
        // case-insensitive match decides.
        let mut col = None;
        for s in sc.iter().rev() {
            let hits: Vec<_> = s
                .sources
                .iter()
                .filter_map(|src| self.column_in(src, name).map(|r| (src, r)))
                .collect();
            match hits.as_slice() {
                [] => continue,
                [(src, Ok((rendered, info)))] => {
                    col = Some((src.name.clone(), rendered.clone(), info.clone()));
                    break;
                }
                _ => return Err(unknown()),
            }
        }
        let aliases: &[(String, Info)] = match (cx.alias_ok, sc.last()) {
            (true, Some(s)) => &s.aliases,
            _ => &[],
        };
        let alias_ci: Vec<_> = aliases
            .iter()
            .filter(|(a, _)| a.eq_ignore_ascii_case(name))
            .collect();
        match (col, alias_ci.as_slice()) {
            (Some((src, rendered, info)), []) => Ok((
                Expr::CompoundIdentifier(vec![quoted(&src), quoted(&rendered)]),
                info,
            )),
            (None, [(a, info)]) if a == name => {
                // SQLite must not find a source column of this name first.
                let shadowed = sc.iter().flat_map(|s| &s.sources).any(|src| {
                    self.columns_of(src)
                        .iter()
                        .any(|(_, r, _)| r.eq_ignore_ascii_case(name))
                });
                if shadowed {
                    return Err(unknown());
                }
                Ok((Expr::Identifier(quoted(a)), info.clone()))
            }
            _ => Err(unknown()),
        }
    }

    // ---- expressions ----

    fn expr(&mut self, e: &mut Expr, sc: &mut Vec<Scope>, cx: Cx) -> R<Info> {
        match e {
            Expr::Identifier(id) => {
                let (new, info) = self.bare(id, sc, cx)?;
                *e = new;
                Ok(info)
            }
            Expr::CompoundIdentifier(parts) => {
                let (new, info) = self.qualified(parts, sc)?;
                *e = new;
                Ok(info)
            }
            Expr::Value(v) => self.value(&v.value),
            Expr::Nested(inner) => self.expr(inner, sc, cx),
            Expr::BinaryOp { left, op, right } => {
                if let Some(cmp) = Cmp::of(op) {
                    return self.compare(left, cmp, right, sc, cx);
                }
                let a = self.expr(left, sc, cx)?;
                let b = self.expr(right, sc, cx)?;
                match op {
                    BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
                    | BinaryOperator::Modulo => Ok(Info::join(&a, &b).with_ty(num_ty(a.ty, b.ty))),
                    BinaryOperator::And | BinaryOperator::Or => {
                        Ok(Info::join(&a, &b).with_ty(Some(ColType::Integer)))
                    }
                    _ => construct(),
                }
            }
            Expr::UnaryOp { op, expr: inner } => {
                let i = self.expr(inner, sc, cx)?;
                match op {
                    UnaryOperator::Plus | UnaryOperator::Minus => {
                        let ty = if is_num(i.ty) { i.ty } else { None };
                        Ok(i.with_ty(ty))
                    }
                    UnaryOperator::Not => Ok(i.with_ty(Some(ColType::Integer))),
                    _ => construct(),
                }
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                if cx.in_case_when {
                    self.masking = true;
                }
                let i = self.expr(inner, sc, cx)?;
                Ok(i.with_ty(Some(ColType::Integer)))
            }
            Expr::Between {
                expr: x,
                negated: _,
                low,
                high,
            } => {
                let i = self.expr(x, sc, cx)?;
                self.operand(low, &i, Cmp::Between, sc, cx)?;
                self.operand(high, &i, Cmp::Between, sc, cx)?;
                Ok(i.with_ty(Some(ColType::Integer)))
            }
            Expr::InList {
                expr: x,
                list,
                negated,
            } => {
                let i = self.expr(x, sc, cx)?;
                let op = if *negated { Cmp::Ne } else { Cmp::In };
                for item in list {
                    self.operand(item, &i, op, sc, cx)?;
                }
                Ok(i.with_ty(Some(ColType::Integer)))
            }
            Expr::InSubquery {
                expr: x,
                subquery,
                negated: _,
            } => {
                let i = self.expr(x, sc, cx)?;
                self.query(subquery, cx.depth + 1, sc)?;
                Ok(i.with_ty(Some(ColType::Integer)))
            }
            Expr::Exists {
                subquery,
                negated: _,
            } => {
                self.query(subquery, cx.depth + 1, sc)?;
                Ok(Info::typed(ColType::Integer))
            }
            Expr::Function(f) => self.function(f, sc, cx),
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                let op_info = match operand {
                    Some(o) => Some(self.expr(o, sc, cx)?),
                    None => None,
                };
                let mut results = Vec::new();
                for cw in conditions {
                    match &op_info {
                        Some(oi) => {
                            if let Expr::Value(v) = &cw.condition {
                                if matches!(v.value, Value::Null) {
                                    self.masking = true;
                                }
                            }
                            self.operand(&mut cw.condition, oi, Cmp::Eq, sc, cx)?;
                        }
                        None => {
                            let wcx = Cx {
                                in_case_when: true,
                                ..cx
                            };
                            results.push(self.expr(&mut cw.condition, sc, wcx)?.with_ty(None));
                        }
                    }
                    let r = self.expr(&mut cw.result, sc, cx)?;
                    results.push(r);
                }
                if let Some(e) = else_result {
                    results.push(self.expr(e, sc, cx)?);
                }
                let ty = results.iter().find_map(|r| r.ty);
                let mut all = results;
                if let Some(oi) = op_info {
                    all.push(oi);
                }
                Ok(Info::join_all(&all).with_ty(ty))
            }
            Expr::Cast {
                kind: CastKind::Cast,
                expr: x,
                data_type,
                format: None,
            } => {
                let ty = match data_type {
                    DataType::Integer(None) => ColType::Integer,
                    DataType::Real => ColType::Real,
                    DataType::Text => ColType::Text,
                    _ => return construct(),
                };
                Ok(self.expr(x, sc, cx)?.with_ty(Some(ty)))
            }
            Expr::Substring {
                expr: x,
                substring_from: Some(from),
                substring_for,
                special: _,
                shorthand: true,
            } => {
                let mut infos = vec![self.expr(x, sc, cx)?, self.expr(from, sc, cx)?];
                if let Some(f) = substring_for {
                    infos.push(self.expr(f, sc, cx)?);
                }
                Ok(Info::join_all(&infos).with_ty(Some(ColType::Text)))
            }
            Expr::Trim {
                expr: x,
                trim_where: None,
                trim_what: None,
                trim_characters,
            } => {
                let mut infos = vec![self.expr(x, sc, cx)?];
                for c in trim_characters.iter_mut().flatten() {
                    infos.push(self.expr(c, sc, cx)?);
                }
                Ok(Info::join_all(&infos).with_ty(Some(ColType::Text)))
            }
            _ => construct(),
        }
    }

    /// A literal or placeholder outside a comparison.
    fn value(&self, v: &Value) -> R<Info> {
        match v {
            Value::Number(s, false) if number_ok(s) => Ok(Info::typed(if s.contains('.') {
                ColType::Real
            } else {
                ColType::Integer
            })),
            Value::SingleQuotedString(s) if is_iso_date(s) => Ok(Info::typed(ColType::Date)),
            Value::Null => Ok(Info::default()),
            Value::Placeholder(_) => fail(ErrorClass::ParamMisuse),
            Value::Boolean(_) => construct(),
            _ => fail(ErrorClass::LiteralNotAllowed),
        }
    }

    fn compare(
        &mut self,
        left: &mut Expr,
        cmp: Cmp,
        right: &mut Expr,
        sc: &mut Vec<Scope>,
        cx: Cx,
    ) -> R<Info> {
        let info = match (side(left), side(right)) {
            (Side::Other, Side::Other) => {
                let a = self.expr(left, sc, cx)?;
                let b = self.expr(right, sc, cx)?;
                Info::join(&a, &b)
            }
            (Side::Other, _) => {
                let a = self.expr(left, sc, cx)?;
                self.operand(right, &a, cmp, sc, cx)?;
                a
            }
            (_, Side::Other) => {
                let b = self.expr(right, sc, cx)?;
                self.operand(left, &b, cmp.flip(), sc, cx)?;
                b
            }
            (Side::Param, _) | (_, Side::Param) => return fail(ErrorClass::ParamMisuse),
            _ => return fail(ErrorClass::LiteralNotAllowed),
        };
        Ok(info.with_ty(Some(ColType::Integer)))
    }

    /// The other side of a comparison with `partner`: a placeholder and a
    /// string literal are checked against it; anything else is an expression.
    fn operand(
        &mut self,
        e: &mut Expr,
        partner: &Info,
        cmp: Cmp,
        sc: &mut Vec<Scope>,
        cx: Cx,
    ) -> R<()> {
        if let Expr::Value(v) = e {
            match &v.value {
                Value::Placeholder(p) => return self.param(p, partner, cmp),
                Value::SingleQuotedString(s) => return self.literal(s, partner),
                _ => {}
            }
        }
        self.expr(e, sc, cx).map(|_| ())
    }

    /// R45-4: a k-floor public value of the compared column, or an ISO date.
    fn literal(&self, s: &str, partner: &Info) -> R<()> {
        if is_iso_date(s) {
            return Ok(());
        }
        if let (Some((t, c)), false) = (&partner.origin, partner.agg) {
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
    fn param(&mut self, text: &str, partner: &Info, cmp: Cmp) -> R<()> {
        let misuse = || fail(ErrorClass::ParamMisuse);
        let Some((base, sfx)) = split_placeholder(text) else {
            return misuse();
        };
        let Some(p) = self.params.iter().find(|p| p.name == base) else {
            return misuse();
        };
        let type_ok = match (&p.ty, sfx) {
            (ParamType::Entity { table, .. }, None) => {
                let Some(ent) = self.schema.entity_for(table) else {
                    return misuse();
                };
                let on_key = partner.origin.as_ref() == Some(&(ent.table.clone(), ent.key.clone()));
                if !matches!(cmp, Cmp::Eq | Cmp::In) || partner.agg || !on_key {
                    return misuse();
                }
                match &p.bound {
                    None => {}
                    Some(Bound::Keys(k)) if k.len() == 1 => {}
                    Some(_) => return misuse(),
                }
                if !self.entity_params.iter().any(|n| n == base) {
                    self.entity_params.push(base.to_string());
                }
                true
            }
            (ParamType::DateRange, Some(s)) => {
                if partner.ty != Some(ColType::Date) {
                    return fail(ErrorClass::ParamType);
                }
                let op_ok = match s {
                    Suffix::From => cmp == Cmp::Ge,
                    Suffix::To => cmp == Cmp::Lt,
                };
                if !op_ok {
                    return misuse();
                }
                true
            }
            (ParamType::DateRange, None) | (_, Some(_)) => return misuse(),
            (ParamType::Date, None) => partner.ty == Some(ColType::Date),
            (ParamType::Amount | ParamType::Integer | ParamType::Percent, None) => {
                is_num(partner.ty)
            }
            (ParamType::Text { table, column }, None) => {
                partner.origin.as_ref() == Some(&(table.clone(), column.clone())) && !partner.agg
            }
        };
        // A parameter compared with a constant says nothing about the data.
        if !type_ok || !(partner.col || partner.agg) {
            return fail(ErrorClass::ParamType);
        }
        if !self.params_used.iter().any(|n| n == base) {
            self.params_used.push(base.to_string());
        }
        Ok(())
    }

    fn function(&mut self, f: &mut Function, sc: &mut Vec<Scope>, cx: Cx) -> R<Info> {
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
        let n = list.args.len();
        let l = lname.as_str();
        let is_agg = matches!(l, "count" | "sum" | "avg" | "total")
            || (matches!(l, "min" | "max") && n == 1);
        let arity_ok = match l {
            "count" | "sum" | "avg" | "total" | "abs" | "lower" | "upper" | "length" => n == 1,
            "min" | "max" => (1..=8).contains(&n),
            "round" | "trim" => (1..=2).contains(&n),
            "coalesce" => (2..=8).contains(&n),
            "ifnull" | "nullif" => n == 2,
            "substr" => (2..=3).contains(&n),
            "date" | "julianday" => (1..=8).contains(&n),
            "strftime" => (2..=8).contains(&n),
            _ => false,
        };
        if !arity_ok {
            return construct();
        }
        match list.duplicate_treatment {
            None => {}
            Some(DuplicateTreatment::Distinct) if is_agg => {}
            Some(_) => return construct(),
        }
        if is_agg && cx.in_agg {
            return construct();
        }
        let acx = Cx {
            in_agg: cx.in_agg || is_agg,
            ..cx
        };
        let date_fn = matches!(l, "date" | "strftime" | "julianday");
        let mut infos = Vec::with_capacity(n);
        for (i, a) in list.args.iter_mut().enumerate() {
            match a {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => {
                    if let (true, Expr::Value(v)) = (date_fn, &*e) {
                        if let Value::SingleQuotedString(s) = &v.value {
                            if !date_arg_ok(l, i, s) {
                                return fail(ErrorClass::LiteralNotAllowed);
                            }
                            infos.push(Info::typed(ColType::Text));
                            continue;
                        }
                    }
                    infos.push(self.expr(e, sc, acx)?);
                }
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard) if l == "count" => {
                    infos.push(Info::default());
                }
                _ => return construct(),
            }
        }
        let first_ty = infos.first().and_then(|i| i.ty);
        let mut info = Info::join_all(&infos);
        if is_agg {
            info.agg = true;
            if l != "count" {
                info.nullable_agg = true;
            }
            if l == "total" {
                // TOTAL() is 0.0 over no rows (R45-5, review focus 1).
                self.masking = true;
            }
        }
        if matches!(l, "coalesce" | "ifnull" | "nullif") && infos.iter().any(|i| i.agg) {
            self.masking = true;
        }
        let ty = match l {
            "count" | "length" => Some(ColType::Integer),
            "sum" | "avg" | "total" | "julianday" => Some(ColType::Real),
            "min" | "max" | "abs" | "round" | "coalesce" | "ifnull" | "nullif" => first_ty,
            "date" => Some(ColType::Date),
            _ => Some(ColType::Text),
        };
        Ok(info.with_ty(ty))
    }
}
