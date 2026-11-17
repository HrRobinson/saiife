//! Plan 45: the method preview (spec §2.3.6), in plain words, English and
//! Danish.
//!
//! The text is generated deterministically from the validated SQL AST: a
//! fixed phrase per clause and function, parameters filled in with their
//! local display (the preview never goes to the cloud). It is never model
//! text: the planner's intent line is not an input here. A part of the AST
//! without a phrase is shown as the query fragment in backticks and counted
//! in [`Preview::fragments`]; no clause of the method is dropped silently.
//!
//! The validated AST renames every planner-chosen reference (aliases, CTE
//! names) under a reserved `_p_` prefix; fragments are cleaned back to
//! snapshot names (`invoices.amount`), and an alias resolves to the table it
//! stands for. Nothing here slices a string by byte offsets: text is walked
//! by characters, dates are parsed from ASCII bytes with `get`.

use crate::schema::{Bound, Lang, Param, ParamType, Schema};
use crate::sql::Validated;
use ring::digest;
use sqlparser::ast::{
    BinaryOperator, DuplicateTreatment, Expr, FunctionArg, FunctionArgExpr, FunctionArguments,
    GroupByExpr, LimitClause, ObjectNamePart, OrderByKind, OrderBySort, Query, Select, SelectItem,
    SetExpr, TableFactor, TableWithJoins, UnaryOperator, Value,
};

/// The reserved prefix of planner-chosen reference names (see `sql.rs`).
const RESERVED: &str = "_p_";

/// The plain-words description of a method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub text: String,
    /// Parts shown as query fragments (no phrase for them).
    pub fragments: usize,
    /// Lowercase hex SHA-256 of `text` (the audit keeps only the hash).
    pub sha256: String,
}

/// Describe a validated method. `params` are the draft's parameters (their
/// local displays fill the text).
pub fn preview(v: &Validated, params: &[Param], _schema: &Schema, lang: Lang) -> Preview {
    let mut cx = Cx {
        lang,
        params,
        aliases: Vec::new(),
        tables: Vec::new(),
        fragments: 0,
    };
    let body = describe(&mut cx, &v.ast, &v.sql);
    let text = match lang {
        Lang::En => format!("I'm {body}."),
        Lang::Da => format!("Jeg {body}."),
    };
    let sha256 = hex(digest::digest(&digest::SHA256, text.as_bytes()).as_ref());
    Preview {
        text,
        fragments: cx.fragments,
        sha256,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

struct Cx<'a> {
    lang: Lang,
    params: &'a [Param],
    /// `(reference name, table)` of the block being described.
    aliases: Vec<(String, String)>,
    /// The tables of the block's `FROM` and joins, in order, no duplicates.
    tables: Vec<String>,
    fragments: usize,
}

impl Cx<'_> {
    fn en(&self) -> bool {
        self.lang == Lang::En
    }

    /// `en` or `da` text by language.
    fn t(&self, en: &str, da: &str) -> String {
        if self.en() { en } else { da }.to_string()
    }

    /// A part with no phrase: the query fragment in backticks.
    fn frag(&mut self, rendered: &str) -> String {
        self.fragments += 1;
        format!("`{}`", clean(rendered, &self.aliases))
    }

    fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name == name)
    }

    /// `a, b and c`.
    fn list(&self, items: &[String]) -> String {
        let and = if self.en() { "and" } else { "og" };
        match items {
            [] => String::new(),
            [one] => one.clone(),
            [init @ .., last] => format!("{} {and} {last}", init.join(", ")),
        }
    }
}

// ---- names ----

fn reserved(s: &str) -> bool {
    s.get(..RESERVED.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(RESERVED))
}

fn strip_reserved(s: &str) -> &str {
    if reserved(s) {
        s.get(RESERVED.len()..).unwrap_or(s)
    } else {
        s
    }
}

fn resolve_ident(name: &str, aliases: &[(String, String)]) -> String {
    if reserved(name) {
        if let Some((_, t)) = aliases.iter().find(|(a, _)| a == name) {
            return t.clone();
        }
        return strip_reserved(name).to_string();
    }
    let simple = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if simple {
        name.to_string()
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

/// Rendered SQL with its quoted identifiers resolved to snapshot names.
/// String literals pass through untouched.
fn clean(s: &str, aliases: &[(String, String)]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' => {
                out.push(c);
                while let Some(x) = it.next() {
                    out.push(x);
                    if x == '\'' {
                        if it.peek() == Some(&'\'') {
                            out.push('\'');
                            it.next();
                        } else {
                            break;
                        }
                    }
                }
            }
            '"' => {
                let mut name = String::new();
                while let Some(x) = it.next() {
                    if x == '"' {
                        if it.peek() == Some(&'"') {
                            name.push('"');
                            it.next();
                        } else {
                            break;
                        }
                    } else {
                        name.push(x);
                    }
                }
                out.push_str(&resolve_ident(&name, aliases));
            }
            _ => out.push(c),
        }
    }
    out
}

fn block_tables(sel: &Select) -> (Vec<(String, String)>, Vec<String>) {
    let mut aliases = Vec::new();
    let mut tables: Vec<String> = Vec::new();
    let mut add = |f: &TableFactor| {
        if let TableFactor::Table { name, alias, .. } = f {
            let tname = name
                .0
                .last()
                .and_then(|p| match p {
                    ObjectNamePart::Identifier(i) => Some(i.value.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            let shown = strip_reserved(tname).to_string();
            let key = alias.as_ref().map_or(tname, |a| a.name.value.as_str());
            aliases.push((key.to_string(), shown.clone()));
            aliases.push((tname.to_string(), shown.clone()));
            if !tables.contains(&shown) {
                tables.push(shown);
            }
        }
    };
    for TableWithJoins { relation, joins } in &sel.from {
        add(relation);
        for j in joins {
            add(&j.relation);
        }
    }
    (aliases, tables)
}

// ---- expression helpers ----

fn unnest(mut e: &Expr) -> &Expr {
    while let Expr::Nested(i) = e {
        e = i;
    }
    e
}

/// `(table, column)` of a qualified column.
fn col_of(cx: &Cx, e: &Expr) -> Option<(String, String)> {
    match unnest(e) {
        Expr::CompoundIdentifier(p) if p.len() == 2 => {
            Some((resolve_ident(&p[0].value, &cx.aliases), p[1].value.clone()))
        }
        _ => None,
    }
}

fn placeholder(e: &Expr) -> Option<&str> {
    match unnest(e) {
        Expr::Value(v) => match &v.value {
            Value::Placeholder(p) => Some(p.strip_prefix(':').unwrap_or(p)),
            _ => None,
        },
        _ => None,
    }
}

fn number_of(e: &Expr) -> Option<String> {
    match unnest(e) {
        Expr::Value(v) => match &v.value {
            Value::Number(s, _) => Some(s.clone()),
            _ => None,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => number_of(expr).map(|n| format!("-{n}")),
        _ => None,
    }
}

/// A literal as it reads in the text: `100`, `'open'`.
fn literal(e: &Expr) -> Option<String> {
    if let Some(n) = number_of(e) {
        return Some(n);
    }
    match unnest(e) {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) => Some(format!("'{s}'")),
            _ => None,
        },
        _ => None,
    }
}

/// A literal, or a parameter's local display.
fn operand(cx: &Cx, e: &Expr) -> Option<String> {
    if let Some(l) = literal(e) {
        return Some(l);
    }
    let p = cx.param(placeholder(e)?)?;
    if p.display.is_empty() {
        return None;
    }
    Some(match p.ty {
        ParamType::Text { .. } => format!("'{}'", p.display),
        _ => p.display.clone(),
    })
}

fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    match e {
        Expr::Nested(i) => conjuncts(i, out),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            conjuncts(left, out);
            conjuncts(right, out);
        }
        _ => out.push(e),
    }
}

// ---- dates ----

const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const MONTHS_DA: [&str; 12] = [
    "januar",
    "februar",
    "marts",
    "april",
    "maj",
    "juni",
    "juli",
    "august",
    "september",
    "oktober",
    "november",
    "december",
];

/// `(year, month 1..=12, day)` of an ISO date `YYYY-MM-DD`.
fn parse_iso(s: &str) -> Option<(i32, u32, u32)> {
    let b = s.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<u32> {
        let part = b.get(from..to)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0u32, |a, d| Some(a * 10 + u32::from(d - b'0')))
    };
    let y = i32::try_from(num(0, 4)?).ok()?;
    let m = num(5, 7)?;
    let d = num(8, 10)?;
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some((y, m, d))
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// The day before `(y, m, d)`.
fn day_before(y: i32, m: u32, d: u32) -> (i32, u32, u32) {
    if d > 1 {
        (y, m, d - 1)
    } else if m > 1 {
        (y, m - 1, days_in_month(y, m - 1))
    } else {
        (y - 1, 12, 31)
    }
}

fn month_name(lang: Lang, m: u32) -> &'static str {
    let names = if lang == Lang::En {
        &MONTHS_EN
    } else {
        &MONTHS_DA
    };
    usize::try_from(m)
        .ok()
        .and_then(|i| names.get(i.wrapping_sub(1)))
        .copied()
        .unwrap_or("")
}

fn date_words(lang: Lang, (y, m, d): (i32, u32, u32)) -> String {
    match lang {
        Lang::En => format!("{d} {} {y}", month_name(lang, m)),
        Lang::Da => format!("{d}. {} {y}", month_name(lang, m)),
    }
}

/// The words of a date range (`to` exclusive): a whole quarter, month or
/// year after `in`, any other range as `from … to …` (`to` inclusive).
fn range_words(lang: Lang, from: &str, to: &str) -> Option<String> {
    let f = parse_iso(from)?;
    let t = parse_iso(to)?;
    if t <= f {
        return None;
    }
    let en = lang == Lang::En;
    if f.2 == 1 && t.2 == 1 {
        let months =
            (i64::from(t.0) * 12 + i64::from(t.1)) - (i64::from(f.0) * 12 + i64::from(f.1));
        let y = f.0;
        if months == 12 && f.1 == 1 {
            return Some(format!("{} {y}", if en { "in" } else { "i" }));
        }
        if months == 3 && (f.1 - 1) % 3 == 0 {
            let q = (f.1 - 1) / 3 + 1;
            return Some(if en {
                format!("in Q{q} {y}")
            } else {
                format!("i {q}. kvartal {y}")
            });
        }
        if months == 1 {
            return Some(format!(
                "{} {} {y}",
                if en { "in" } else { "i" },
                month_name(lang, f.1)
            ));
        }
    }
    let last = day_before(t.0, t.1, t.2);
    Some(if en {
        format!("from {} to {}", date_words(lang, f), date_words(lang, last))
    } else {
        format!("fra {} til {}", date_words(lang, f), date_words(lang, last))
    })
}

// ---- aggregates ----

enum Arg {
    Star,
    Col(String, String),
    Other,
}

struct Agg {
    name: String,
    distinct: bool,
    arg: Arg,
}

fn agg_of(cx: &Cx, e: &Expr) -> Option<Agg> {
    let Expr::Function(f) = unnest(e) else {
        return None;
    };
    let name = match f.name.0.as_slice() {
        [ObjectNamePart::Identifier(i)] => i.value.to_ascii_lowercase(),
        _ => return None,
    };
    if !matches!(name.as_str(), "count" | "sum" | "avg" | "min" | "max") {
        return None;
    }
    let FunctionArguments::List(l) = &f.args else {
        return None;
    };
    let [a] = l.args.as_slice() else {
        return None;
    };
    let arg = match a {
        FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => Arg::Star,
        FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) => match col_of(cx, x) {
            Some((t, c)) => Arg::Col(t, c),
            None => Arg::Other,
        },
        _ => Arg::Other,
    };
    Some(Agg {
        name,
        distinct: l.duplicate_treatment == Some(DuplicateTreatment::Distinct),
        arg,
    })
}

/// The tables a `COUNT(*)` counts rows of.
fn star_tables(cx: &Cx) -> Option<String> {
    match cx.tables.as_slice() {
        [] => None,
        [one] => Some(cx.t(&format!("counting {one}"), &format!("tæller {one}"))),
        many => {
            let l = cx.list(many);
            Some(cx.t(
                &format!("counting rows across {l}"),
                &format!("tæller rækker på tværs af {l}"),
            ))
        }
    }
}

/// The phrase of one output aggregate, or `None` (no phrase).
fn agg_phrase(cx: &Cx, a: &Agg) -> Option<String> {
    match (a.name.as_str(), a.distinct, &a.arg) {
        ("sum", false, Arg::Col(t, c)) => Some(cx.t(
            &format!("summing all {t} ({c})"),
            &format!("lægger alle {t} ({c}) sammen"),
        )),
        ("count", false, Arg::Star) => star_tables(cx),
        ("count", true, Arg::Col(_, c)) => Some(cx.t(
            &format!("counting distinct {c}"),
            &format!("tæller forskellige {c}"),
        )),
        ("avg", false, Arg::Col(t, c)) => Some(cx.t(
            &format!("finding the average {c} in {t}"),
            &format!("finder gennemsnittet af {c} i {t}"),
        )),
        ("min", false, Arg::Col(t, c)) => Some(cx.t(
            &format!("finding the lowest {c} in {t}"),
            &format!("finder den laveste {c} i {t}"),
        )),
        ("max", false, Arg::Col(t, c)) => Some(cx.t(
            &format!("finding the highest {c} in {t}"),
            &format!("finder den højeste {c} i {t}"),
        )),
        _ => None,
    }
}

/// How an `ORDER BY` expression reads after `by`.
fn order_noun(cx: &mut Cx, e: &Expr) -> String {
    if let Some((_, c)) = col_of(cx, e) {
        return c;
    }
    if let Some(a) = agg_of(cx, e) {
        let noun = match (a.name.as_str(), a.distinct, &a.arg) {
            ("sum", false, Arg::Col(_, c)) => {
                Some(cx.t(&format!("total {c}"), &format!("samlet {c}")))
            }
            ("avg", false, Arg::Col(_, c)) => {
                Some(cx.t(&format!("average {c}"), &format!("gennemsnitlig {c}")))
            }
            ("min", false, Arg::Col(_, c)) => {
                Some(cx.t(&format!("lowest {c}"), &format!("laveste {c}")))
            }
            ("max", false, Arg::Col(_, c)) => {
                Some(cx.t(&format!("highest {c}"), &format!("højeste {c}")))
            }
            ("count", false, Arg::Star) => Some(cx.t("number of rows", "antal rækker")),
            _ => None,
        };
        if let Some(n) = noun {
            return n;
        }
    }
    cx.frag(&e.to_string())
}

// ---- clauses ----

/// The phrase of one `WHERE` conjunct, or `None` (no phrase).
fn pred_phrase(cx: &Cx, e: &Expr) -> Option<String> {
    match unnest(e) {
        Expr::BinaryOp { left, op, right } => {
            let (col, op, rhs) = if col_of(cx, left).is_some() {
                (left, op.clone(), right)
            } else if col_of(cx, right).is_some() {
                let flipped = match op {
                    BinaryOperator::Gt => BinaryOperator::Lt,
                    BinaryOperator::GtEq => BinaryOperator::LtEq,
                    BinaryOperator::Lt => BinaryOperator::Gt,
                    BinaryOperator::LtEq => BinaryOperator::GtEq,
                    other => other.clone(),
                };
                (right, flipped, left)
            } else {
                return None;
            };
            let (_, c) = col_of(cx, col)?;
            if op == BinaryOperator::Eq {
                if let Some(p) = placeholder(rhs).and_then(|n| cx.param(n)) {
                    if matches!(p.ty, ParamType::Entity { .. }) && !p.display.is_empty() {
                        return Some(format!("{} {}", cx.t("for", "for"), p.display));
                    }
                }
                let x = operand(cx, rhs)?;
                return Some(cx.t(&format!("with {c} {x}"), &format!("med {c} {x}")));
            }
            let (en, da) = match op {
                BinaryOperator::Gt => ("above", "over"),
                BinaryOperator::GtEq => ("at least", "mindst"),
                BinaryOperator::Lt => ("below", "under"),
                BinaryOperator::LtEq => ("at most", "højst"),
                _ => return None,
            };
            let x = operand(cx, rhs)?;
            Some(cx.t(
                &format!("where {c} is {en} {x}"),
                &format!("hvor {c} er {da} {x}"),
            ))
        }
        // The entity pin `key IN (:pN)`.
        Expr::InList {
            expr,
            list,
            negated: false,
        } => {
            col_of(cx, expr)?;
            let [one] = list.as_slice() else {
                return None;
            };
            let p = cx.param(placeholder(one)?)?;
            (matches!(p.ty, ParamType::Entity { .. }) && !p.display.is_empty())
                .then(|| format!("for {}", p.display))
        }
        _ => None,
    }
}

/// A `col >= :pN_from` / `col < :pN_to` conjunct: `(column, N, is_from)`.
fn range_bound(cx: &Cx, e: &Expr) -> Option<(String, String, bool)> {
    let Expr::BinaryOp { left, op, right } = unnest(e) else {
        return None;
    };
    let (col, ph) = (col_of(cx, left)?, placeholder(right)?);
    let (base, from) = match (op, ph.strip_suffix("_from"), ph.strip_suffix("_to")) {
        (BinaryOperator::GtEq, Some(b), _) => (b, true),
        (BinaryOperator::Lt, _, Some(b)) => (b, false),
        _ => return None,
    };
    Some((format!("{}.{}", col.0, col.1), base.to_string(), from))
}

fn range_phrase(cx: &Cx, base: &str) -> Option<String> {
    let p = cx.param(base)?;
    if let Some(Bound::DateRange(f, t)) = &p.bound {
        if let Some(w) = range_words(cx.lang, f, t) {
            return Some(w);
        }
    }
    (!p.display.is_empty()).then(|| format!("{} {}", cx.t("in", "i"), p.display))
}

fn where_phrases(cx: &mut Cx, e: &Expr) -> Vec<String> {
    let mut cs = Vec::new();
    conjuncts(e, &mut cs);
    let bounds: Vec<Option<(String, String, bool)>> =
        cs.iter().map(|c| range_bound(cx, c)).collect();
    let mut used = vec![false; cs.len()];
    let mut out = Vec::new();
    for i in 0..cs.len() {
        if used[i] {
            continue;
        }
        // A from/to pair on one column and one range parameter.
        if let Some((col, base, from)) = &bounds[i] {
            let mate = (i + 1..cs.len()).find(|&j| {
                !used[j]
                    && bounds[j]
                        .as_ref()
                        .is_some_and(|(c2, b2, f2)| c2 == col && b2 == base && f2 != from)
            });
            if let Some(j) = mate {
                if let Some(w) = range_phrase(cx, base) {
                    used[i] = true;
                    used[j] = true;
                    out.push(w);
                    continue;
                }
            }
        }
        used[i] = true;
        match pred_phrase(cx, cs[i]) {
            Some(p) => out.push(p),
            None => {
                let f = cx.frag(&cs[i].to_string());
                out.push(cx.t(&format!("where {f}"), &format!("hvor {f}")));
            }
        }
    }
    out
}

fn limit_of(q: &Query) -> Option<String> {
    match &q.limit_clause {
        Some(LimitClause::LimitOffset { limit: Some(l), .. }) => number_of(l),
        _ => None,
    }
}

fn order_phrase(cx: &mut Cx, q: &Query) -> Option<String> {
    let limit = limit_of(q);
    let exprs = match q.order_by.as_ref().map(|o| &o.kind) {
        Some(OrderByKind::Expressions(es)) if !es.is_empty() => Some(es),
        Some(_) => {
            let f = cx.frag("ORDER BY");
            return Some(cx.t(&format!("ordered as {f}"), &format!("sorteret som {f}")));
        }
        None => None,
    };
    let limited = |cx: &Cx, n: &str| {
        cx.t(
            &format!("limited to the first {n} rows"),
            &format!("begrænset til de første {n} rækker"),
        )
    };
    let Some(exprs) = exprs else {
        return limit.map(|n| limited(cx, &n));
    };
    if let [o] = exprs.as_slice() {
        let sort = match &o.options.sort {
            None | Some(OrderBySort::Asc) => Some(false),
            Some(OrderBySort::Desc) => Some(true),
            Some(OrderBySort::Using(_)) => None,
        };
        if let (Some(desc), None) = (sort, &o.with_fill) {
            let noun = order_noun(cx, &o.expr);
            return Some(match (limit, desc) {
                (Some(n), true) => cx.t(
                    &format!("the top {n} by {noun}"),
                    &format!("de {n} største efter {noun}"),
                ),
                (Some(n), false) => cx.t(
                    &format!("the bottom {n} by {noun}"),
                    &format!("de {n} mindste efter {noun}"),
                ),
                (None, true) => cx.t(
                    &format!("ordered by {noun}, highest first"),
                    &format!("sorteret efter {noun}, højeste først"),
                ),
                (None, false) => cx.t(
                    &format!("ordered by {noun}"),
                    &format!("sorteret efter {noun}"),
                ),
            });
        }
    }
    // Several keys (or an unusual form): the clause itself.
    let items: Vec<String> = exprs
        .iter()
        .map(|o| {
            let mut s = o.expr.to_string();
            match &o.options.sort {
                Some(OrderBySort::Desc) => s.push_str(" DESC"),
                Some(OrderBySort::Asc) => s.push_str(" ASC"),
                Some(OrderBySort::Using(op)) => s.push_str(&format!(" USING {op}")),
                None => {}
            }
            s
        })
        .collect();
    let f = cx.frag(&items.join(", "));
    let mut s = cx.t(&format!("ordered by {f}"), &format!("sorteret efter {f}"));
    if let Some(n) = limit {
        s.push_str(", ");
        s.push_str(&limited(cx, &n));
    }
    Some(s)
}

fn group_phrase(cx: &mut Cx, g: &GroupByExpr) -> Option<String> {
    match g {
        GroupByExpr::Expressions(es, mods) if mods.is_empty() => {
            if es.is_empty() {
                return None;
            }
            let items: Vec<String> = es
                .iter()
                .map(|e| match col_of(cx, e) {
                    Some((_, c)) => c,
                    None => cx.frag(&e.to_string()),
                })
                .collect();
            let l = cx.list(&items);
            Some(cx.t(&format!("per {l}"), &format!("pr. {l}")))
        }
        _ => {
            let f = cx.frag("GROUP BY");
            Some(cx.t(&format!("grouped as {f}"), &format!("grupperet som {f}")))
        }
    }
}

/// The whole sentence body after `I'm` / `Jeg`.
fn describe(cx: &mut Cx, q: &Query, sql: &str) -> String {
    let SetExpr::Select(sel) = q.body.as_ref() else {
        let f = cx.frag(sql);
        return cx.t(&format!("running {f}"), &format!("kører {f}"));
    };
    let (aliases, tables) = block_tables(sel);
    cx.aliases = aliases;
    cx.tables = tables;

    // The grouped plain columns are said by the `per` phrase.
    let grouped: Vec<(String, String)> = match &sel.group_by {
        GroupByExpr::Expressions(es, _) => es.iter().filter_map(|e| col_of(cx, e)).collect(),
        GroupByExpr::All(_) => Vec::new(),
    };

    let mut phrases: Vec<String> = Vec::new();
    let mut extras: Vec<String> = Vec::new();
    for item in &sel.projection {
        let e = match item {
            SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => e,
            other => {
                let f = cx.frag(&other.to_string());
                let p = cx.t(&format!("listing {f}"), &format!("viser {f}"));
                (if phrases.is_empty() {
                    &mut phrases
                } else {
                    &mut extras
                })
                .push(p);
                continue;
            }
        };
        let target = |phrases: &Vec<String>| phrases.is_empty();
        if let Some(a) = agg_of(cx, e) {
            let p = match agg_phrase(cx, &a) {
                Some(p) => p,
                None => {
                    let f = cx.frag(&e.to_string());
                    cx.t(&format!("computing {f}"), &format!("beregner {f}"))
                }
            };
            if target(&phrases) {
                phrases.push(p);
            } else {
                extras.push(p);
            }
        } else if let Some((t, c)) = col_of(cx, e) {
            if grouped.contains(&(t.clone(), c.clone())) {
                continue;
            }
            if target(&phrases) {
                let f = cx.frag(&e.to_string());
                phrases.push(cx.t(&format!("listing {f}"), &format!("viser {f}")));
            } else {
                extras.push(cx.t(
                    &format!("comparing it with {t}.{c}"),
                    &format!("sammenligner med {t}.{c}"),
                ));
            }
        } else {
            let f = cx.frag(&e.to_string());
            let p = cx.t(&format!("computing {f}"), &format!("beregner {f}"));
            if target(&phrases) {
                phrases.push(p);
            } else {
                extras.push(p);
            }
        }
    }
    if phrases.is_empty() {
        let l = cx.list(&cx.tables.clone());
        phrases.push(cx.t(
            &format!("listing the rows of {l}"),
            &format!("viser rækkerne fra {l}"),
        ));
    }

    let mut head = phrases.remove(0);
    extras.splice(0..0, phrases);
    if sel.distinct.is_some() {
        head.push(' ');
        head.push_str(&cx.t("without duplicate rows", "uden dublerede rækker"));
    }
    if let Some(w) = &sel.selection {
        for p in where_phrases(cx, w) {
            head.push(' ');
            head.push_str(&p);
        }
    }
    if let Some(g) = group_phrase(cx, &sel.group_by) {
        head.push(' ');
        head.push_str(&g);
    }
    let mut tails: Vec<String> = Vec::new();
    if let Some(h) = &sel.having {
        let f = cx.frag(&h.to_string());
        tails.push(cx.t(
            &format!("keeping only groups where {f}"),
            &format!("og beholder kun grupper hvor {f}"),
        ));
    }
    if let Some(o) = order_phrase(cx, q) {
        tails.push(o);
    }
    let and = if cx.en() { "and" } else { "og" };
    for x in extras {
        tails.push(format!("{and} {x}"));
    }
    if let Some(w) = &q.with {
        for cte in &w.cte_tables {
            let (cte_aliases, _) = match cte.query.body.as_ref() {
                SetExpr::Select(s) => block_tables(s),
                _ => (Vec::new(), Vec::new()),
            };
            let saved = std::mem::replace(&mut cx.aliases, cte_aliases);
            let text = format!("\"{}\" AS ({})", cte.alias.name.value, cte.query);
            let f = cx.frag(&text);
            cx.aliases = saved;
            tails.push(cx.t(&format!("using {f}"), &format!("ved hjælp af {f}")));
        }
    }
    for t in tails {
        head.push_str(", ");
        head.push_str(&t);
    }
    head
}
