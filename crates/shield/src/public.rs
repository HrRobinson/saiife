//! Plan 43 T4: public marks. A `public` column is refused when it holds names,
//! IDs or amounts; otherwise only values seen at least `k` times are listed.

use crate::classify::{
    checks, guess, identifier_share, looks_like_identifier, sqlite_err, ColumnStats,
};
use crate::error::ShieldError;
use crate::schema::{ColType, ColumnClass};
use crate::source::quote_ident as quote;
use rusqlite::Connection;

const MAX_VALUES: usize = 1000;

/// Why a `public` mark must be refused for this column, or `None`.
pub fn public_refusal(
    name: &str,
    ty: ColType,
    st: &ColumnStats,
    sample: &[String],
) -> Option<&'static str> {
    let g = guess(name, ty, st, sample);
    if g.class == ColumnClass::Identifier && g.confidence >= 0.85 {
        return Some("holds names or IDs");
    }
    if identifier_share(sample) >= 0.2 {
        return Some("holds names or IDs");
    }
    if checks::amount_name(name) || ty == ColType::Real {
        return Some("holds amounts");
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicValues {
    pub column: String,
    pub passing: Vec<String>,
    pub total_distinct: u64,
}

fn refuse(table: &str, column: &str, why: &'static str) -> ShieldError {
    ShieldError::Source {
        file: "snapshot".into(),
        table: Some(table.into()),
        column: Some(column.into()),
        row: None,
        why,
    }
}

/// The values that occur at least `k` times, as text, in memory only. More
/// than 1000 of them is not a category: the mark is refused with a fixed reason.
/// The caller runs `public_refusal` first; the name check here is a backstop.
pub fn public_values(
    conn: &Connection,
    table: &str,
    column: &str,
    k: u32,
) -> Result<PublicValues, ShieldError> {
    if checks::amount_name(column) {
        return Err(refuse(table, column, "holds amounts"));
    }
    let name_guess = guess(
        column,
        ColType::Text,
        &ColumnStats {
            rows: 0,
            non_null: 0,
            distinct: 0,
            max_len: 0,
            numeric: false,
        },
        &[],
    );
    if name_guess.class == ColumnClass::Identifier {
        return Err(refuse(table, column, "holds names or IDs"));
    }
    let (t, c) = (quote(table), quote(column));
    let total_distinct: i64 = conn
        .query_row(&format!("SELECT COUNT(DISTINCT {c}) FROM {t}"), [], |r| {
            r.get(0)
        })
        .map_err(|_| sqlite_err())?;
    let sql = format!(
        "SELECT CAST({c} AS TEXT), COUNT(*) FROM {t} WHERE {c} IS NOT NULL \
         GROUP BY {c} HAVING COUNT(*) >= ?1 ORDER BY {c} LIMIT ?2"
    );
    let mut st = conn.prepare(&sql).map_err(|_| sqlite_err())?;
    let rows = st
        .query_map([i64::from(k), MAX_VALUES as i64 + 1], |r| {
            r.get::<_, String>(0)
        })
        .map_err(|_| sqlite_err())?;
    let passing = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| sqlite_err())?;
    if passing.len() > MAX_VALUES {
        return Err(refuse(table, column, "too many values to be a category"));
    }
    if passing.iter().any(|v| looks_like_identifier(v)) {
        return Err(refuse(
            table,
            column,
            "a value looks like a name, ID or contact detail",
        ));
    }
    Ok(PublicValues {
        column: column.to_string(),
        passing,
        total_distinct: total_distinct.max(0) as u64,
    })
}
