//! Plan 45 Task 3: the executor. Runs a validated method on a read-only
//! snapshot with run-time caps (R45-7), the list cap, saiife's own existence
//! check per bound entity (R45-6, the primary control against "Anna Berg owes
//! 0") and the planner's self-checks. Error classes only: no rusqlite error
//! text is ever kept (it can quote data).
//!
//! `PRAGMA hard_heap_limit` is process-wide in SQLite: the calculator process
//! runs one job.

use crate::schema::{rows_band, Bound, Param};
use crate::sql::{EntityFilter, ErrorClass, Validated, ValidatedCheck};
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, ErrorCode, Statement};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Run-time caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    pub wall_ms: u64,
    /// SQLite VM steps (counted by the progress handler, 10 000 at a time).
    pub steps: u64,
    pub heap_bytes: i64,
    pub list_cap: u32,
}

impl Default for Caps {
    fn default() -> Caps {
        Caps {
            wall_ms: 10_000,
            steps: 2_000_000_000,
            heap_bytes: 512 * 1024 * 1024,
            list_cap: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<CellValue>>,
    pub truncated: bool,
    /// Set when `truncated`: the full row count.
    pub total_rows: Option<u64>,
    pub ms: u64,
    /// `rows_band` of the total.
    pub row_band: String,
}

/// A refusal. `empty_for` names the entity parameter for `empty_for_key`
/// (`check_failed`) and `empty_result`; never sent to the planner (R45-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalcFailure {
    pub class: ErrorClass,
    pub empty_for: Option<String>,
}

fn class(class: ErrorClass) -> CalcFailure {
    CalcFailure {
        class,
        empty_for: None,
    }
}

fn empty_for(class: ErrorClass, param: &str) -> CalcFailure {
    CalcFailure {
        class,
        empty_for: Some(param.to_string()),
    }
}

const TRIP_TIME: u8 = 1;
const TRIP_STEPS: u8 = 2;
const OPS_PER_TICK: i32 = 10_000;

struct Ctx<'a> {
    params: &'a [Param],
    trip: Arc<AtomicU8>,
    start: Instant,
}

impl Ctx<'_> {
    /// Map a rusqlite error to a class by code only.
    fn map_err(&self, e: &rusqlite::Error) -> CalcFailure {
        let code = match e {
            rusqlite::Error::SqliteFailure(f, _) => Some(f.code),
            _ => None,
        };
        match code {
            Some(ErrorCode::OperationInterrupted) => match self.trip.load(Ordering::Relaxed) {
                TRIP_TIME => class(ErrorClass::TimeCap),
                TRIP_STEPS => class(ErrorClass::StepCap),
                _ => class(ErrorClass::RuntimeError),
            },
            Some(ErrorCode::OutOfMemory) => class(ErrorClass::MemoryCap),
            _ => class(ErrorClass::RuntimeError),
        }
    }
}

/// Run `v` on `conn`, then the `checks`. `conn` is `&mut` because SQLite's
/// progress handler is installed on it for the duration of the run.
pub fn run(
    conn: &mut Connection,
    v: &Validated,
    checks: &[ValidatedCheck],
    params: &[Param],
    caps: &Caps,
) -> Result<ResultSet, CalcFailure> {
    let trip = Arc::new(AtomicU8::new(0));
    let ctx = Ctx {
        params,
        trip: Arc::clone(&trip),
        start: Instant::now(),
    };
    conn.pragma_update(None, "query_only", 1)
        .map_err(|e| ctx.map_err(&e))?;
    let wall = std::time::Duration::from_millis(caps.wall_ms);
    let max_steps = caps.steps;
    let mut steps: u64 = 0;
    let t = Arc::clone(&trip);
    let start = ctx.start;
    conn.progress_handler(
        OPS_PER_TICK,
        Some(move || {
            steps = steps.saturating_add(OPS_PER_TICK as u64);
            if start.elapsed() >= wall {
                t.store(TRIP_TIME, Ordering::Relaxed);
                return true;
            }
            if steps > max_steps {
                t.store(TRIP_STEPS, Ordering::Relaxed);
                return true;
            }
            false
        }),
    )
    .map_err(|e| ctx.map_err(&e))?;
    // Last: a limit below what the connection already holds makes SQLite
    // fail with NOMEM, which is the memory cap.
    if let Err(e) = conn.pragma_update(None, "hard_heap_limit", caps.heap_bytes) {
        let _ = conn.progress_handler(0, None::<fn() -> bool>);
        return Err(ctx.map_err(&e));
    }
    let out = run_all(conn, v, checks, &ctx, caps);
    let _ = conn.progress_handler(0, None::<fn() -> bool>);
    out
}

fn run_all(
    conn: &Connection,
    v: &Validated,
    checks: &[ValidatedCheck],
    ctx: &Ctx<'_>,
    caps: &Caps,
) -> Result<ResultSet, CalcFailure> {
    let rs = run_one(conn, v, ctx, caps)?;
    let n = rs.total_rows.unwrap_or(rs.rows.len() as u64);
    for c in checks {
        match c {
            ValidatedCheck::RowsBetween { min, max } => {
                if n < *min || n > *max {
                    return Err(class(ErrorClass::CheckFailed));
                }
            }
            ValidatedCheck::Equal { a, b } => {
                let two = Caps {
                    list_cap: 2,
                    ..caps.clone()
                };
                let ra = run_one(conn, a, ctx, &two)?;
                let rb = run_one(conn, b, ctx, &two)?;
                if !scalars_equal(&ra, &rb) {
                    return Err(class(ErrorClass::CheckFailed));
                }
            }
        }
    }
    Ok(rs)
}

fn scalar(rs: &ResultSet) -> Option<&CellValue> {
    match (rs.columns.len(), rs.rows.as_slice(), rs.truncated) {
        (1, [row], false) => row.first(),
        _ => None,
    }
}

fn scalars_equal(a: &ResultSet, b: &ResultSet) -> bool {
    let (Some(x), Some(y)) = (scalar(a), scalar(b)) else {
        return false;
    };
    let num = |c: &CellValue| match c {
        CellValue::Int(i) => Some(*i as f64),
        CellValue::Real(r) => Some(*r),
        _ => None,
    };
    match (x, y) {
        (CellValue::Null, _) | (_, CellValue::Null) => false,
        (CellValue::Int(p), CellValue::Int(q)) => p == q,
        (CellValue::Text(p), CellValue::Text(q)) => p == q,
        _ => match (num(x), num(y)) {
            // Sums in another order differ in the last bits only.
            (Some(p), Some(q)) => (p - q).abs() <= 1e-9 * p.abs().max(q.abs()).max(1.0),
            _ => false,
        },
    }
}

fn run_one(
    conn: &Connection,
    v: &Validated,
    ctx: &Ctx<'_>,
    caps: &Caps,
) -> Result<ResultSet, CalcFailure> {
    for f in &v.entity_filters {
        existence_check(conn, f, v.count_only, ctx)?;
    }
    let started = Instant::now();
    let mut stmt = conn.prepare(&v.sql).map_err(|e| ctx.map_err(&e))?;
    bind_all(&mut stmt, ctx.params)?;
    let columns: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
    let ncols = columns.len();
    let mut rows: Vec<Vec<CellValue>> = Vec::new();
    let mut truncated = false;
    {
        let mut q = stmt.raw_query();
        loop {
            let row = match q.next() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) => return Err(ctx.map_err(&e)),
            };
            if rows.len() >= caps.list_cap as usize {
                truncated = true;
                break;
            }
            let mut cells = Vec::with_capacity(ncols);
            for i in 0..ncols {
                let c = match row.get_ref(i).map_err(|e| ctx.map_err(&e))? {
                    ValueRef::Null => CellValue::Null,
                    ValueRef::Integer(n) => CellValue::Int(n),
                    ValueRef::Real(r) => CellValue::Real(r),
                    ValueRef::Text(t) => match std::str::from_utf8(t) {
                        Ok(s) => CellValue::Text(s.to_string()),
                        Err(_) => return Err(class(ErrorClass::RuntimeError)),
                    },
                    ValueRef::Blob(_) => return Err(class(ErrorClass::RuntimeError)),
                };
                cells.push(c);
            }
            rows.push(cells);
        }
    }
    drop(stmt);
    let total_rows = if truncated {
        let sql = format!("SELECT COUNT(*) FROM ({})", v.sql);
        let mut st = conn.prepare(&sql).map_err(|e| ctx.map_err(&e))?;
        bind_all(&mut st, ctx.params)?;
        let mut q = st.raw_query();
        let n = match q.next() {
            Ok(Some(r)) => r.get::<_, i64>(0).map_err(|e| ctx.map_err(&e))?,
            Ok(None) => return Err(class(ErrorClass::RuntimeError)),
            Err(e) => return Err(ctx.map_err(&e)),
        };
        Some(u64::try_from(n).map_err(|_| class(ErrorClass::RuntimeError))?)
    } else {
        None
    };
    // The entity exists (checked above); an empty answer is its own refusal.
    if let Some(first) = v.entity_filters.first() {
        let all_null = rows.len() == 1
            && !v.aggregates_nullable.is_empty()
            && v.aggregates_nullable
                .iter()
                .all(|&i| matches!(rows[0].get(i), Some(CellValue::Null)));
        if rows.is_empty() || all_null {
            return Err(empty_for(ErrorClass::EmptyResult, &first.param));
        }
    }
    let band = rows_band(total_rows.unwrap_or(rows.len() as u64));
    Ok(ResultSet {
        columns,
        rows,
        truncated,
        total_rows,
        ms: started.elapsed().as_millis() as u64,
        row_band: band,
    })
}

fn quote(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// saiife's own fixed query per bound entity (R45-6): never the planner's
/// text, identifiers from the schema, the key bound as a parameter.
fn existence_check(
    conn: &Connection,
    f: &EntityFilter,
    count_only: bool,
    ctx: &Ctx<'_>,
) -> Result<(), CalcFailure> {
    let key = single_key(ctx.params, &f.param)?;
    let count = |table: &str, col: &str| -> Result<i64, CalcFailure> {
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE {} = ?",
            quote(table),
            quote(col)
        );
        conn.query_row(&sql, [key], |r| r.get::<_, i64>(0))
            .map_err(|e| ctx.map_err(&e))
    };
    if count(&f.table, &f.key)? == 0 {
        return Err(empty_for(ErrorClass::CheckFailed, &f.param));
    }
    if !count_only {
        for (t, fk) in &f.linked {
            if count(t, fk)? == 0 {
                return Err(empty_for(ErrorClass::CheckFailed, &f.param));
            }
        }
    }
    Ok(())
}

fn single_key(params: &[Param], name: &str) -> Result<i64, CalcFailure> {
    match params.iter().find(|p| p.name == name).map(|p| &p.bound) {
        Some(Some(Bound::Keys(k))) if k.len() == 1 => Ok(k[0]),
        _ => Err(class(ErrorClass::RuntimeError)),
    }
}

fn bound_value(b: &Bound, part: Option<&str>) -> Option<Value> {
    Some(match (b, part) {
        (Bound::Keys(k), None) if k.len() == 1 => Value::Integer(k[0]),
        (Bound::Amount(d), None) | (Bound::Percent(d), None) => {
            Value::Real(d.to_plain().parse::<f64>().ok()?)
        }
        (Bound::Integer(i), None) => Value::Integer(*i),
        (Bound::Date(s), None) | (Bound::Text(s), None) => Value::Text(s.clone()),
        (Bound::DateRange(from, _), Some("from")) => Value::Text(from.clone()),
        (Bound::DateRange(_, to), Some("to")) => Value::Text(to.clone()),
        _ => return None,
    })
}

/// Bind every named parameter the statement holds (`:pN`, `:pN_from`,
/// `:pN_to`) from `params`; an unknown or unbound one is a `runtime_error`.
fn bind_all(stmt: &mut Statement<'_>, params: &[Param]) -> Result<(), CalcFailure> {
    let bad = || class(ErrorClass::RuntimeError);
    for i in 1..=stmt.parameter_count() {
        let name = stmt.parameter_name(i).ok_or_else(bad)?;
        let name = name.strip_prefix(':').ok_or_else(bad)?.to_string();
        let value = params
            .iter()
            .find_map(|p| {
                let b = p.bound.as_ref()?;
                if p.name == name {
                    bound_value(b, None)
                } else if let Some(rest) = name.strip_prefix(&p.name) {
                    bound_value(b, rest.strip_prefix('_'))
                } else {
                    None
                }
            })
            .ok_or_else(bad)?;
        stmt.raw_bind_parameter(i, value).map_err(|_| bad())?;
    }
    Ok(())
}
