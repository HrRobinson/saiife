//! Plan 43 T4: public marks. A `public` column is refused when it holds names,
//! IDs or amounts; otherwise only values seen at least `k` times are listed.

use crate::classify::{
    checks, guess, id_shaped, identifier_share, looks_like_identifier, sqlite_err, ColumnStats,
    UNKNOWN,
};
use crate::error::ShieldError;
use crate::norm::normalize;
use crate::schema::EntitySpec;
use crate::schema::{ColType, ColumnClass};
use crate::source::quote_ident as quote;
use rusqlite::Connection;

const MAX_VALUES: usize = 1000;

/// The most distinct values an unknown column may have and still pass as a
/// category (S4).
const UNKNOWN_MAX_DISTINCT: u64 = 50;

/// Why a `public` mark must be refused for this column, or `None`. The
/// gate (S4), first rule that holds wins:
/// 1. an ID-shaped name ([`id_shaped`]): "holds names or IDs";
/// 2. the guess is Identifier at confidence >= 0.85, or at least 20 % of
///    the sample passes an identifier check: "holds names or IDs";
/// 3. an amount name or a REAL column: "holds amounts";
/// 4. the guess is FreeText: "holds free text";
/// 5. the guess is the unknown fallback (Sensitive 0.5, [`UNKNOWN`]) and
///    the column is not a small category (TEXT, INTEGER or BOOL, at most
///    50 distinct values, each on at least 2 rows on average): "unknown
///    means sensitive".
///
/// The Public, Quasi and other Sensitive guesses pass on to the k-floor.
/// [`public_gate`] adds the entity columns; `propose` and `finish` both
/// go through it with the same seeded sample.
pub fn public_refusal(
    name: &str,
    ty: ColType,
    st: &ColumnStats,
    sample: &[String],
) -> Option<&'static str> {
    if id_shaped(name) {
        return Some("holds names or IDs");
    }
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
    if g.class == ColumnClass::FreeText {
        return Some("holds free text");
    }
    let small_category = matches!(ty, ColType::Text | ColType::Integer | ColType::Bool)
        && st.non_null > 0
        && st.distinct <= UNKNOWN_MAX_DISTINCT
        && st.distinct.saturating_mul(2) <= st.non_null;
    if g.class == ColumnClass::Sensitive && g.reason == UNKNOWN && !small_category {
        return Some("unknown means sensitive");
    }
    None
}

/// C1 (spec §2.1.2): an entity's key or name column, or a foreign key
/// named `<entity table stem>_id`, is never public.
pub(crate) fn entity_column(entities: &[EntitySpec], table: &str, column: &str) -> bool {
    let col = column.to_lowercase();
    entities.iter().any(|e| {
        if e.table == table && (e.key == column || e.names.iter().any(|n| n == column)) {
            return true;
        }
        let t = e.table.to_lowercase();
        let mut stems = vec![t.clone(), normalize(&e.word).replace(' ', "_")];
        stems.extend(t.strip_suffix("es").map(str::to_string));
        stems.extend(t.strip_suffix('s').map(str::to_string));
        stems
            .iter()
            .any(|s| !s.is_empty() && col == format!("{s}_id"))
    })
}

/// S4: the one public gate. [`public_refusal`], then the policy's entity
/// columns (`propose` has no policy yet and passes none).
pub(crate) fn public_gate(
    entities: &[EntitySpec],
    table: &str,
    name: &str,
    ty: ColType,
    st: &ColumnStats,
    sample: &[String],
) -> Option<&'static str> {
    public_refusal(name, ty, st, sample).or_else(|| {
        entity_column(entities, table, name).then_some("an entity's key or name column")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicValues {
    /// R-18: `table.column`, in a proposal and in the manifest alike.
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
    if name_guess.class == ColumnClass::Identifier || id_shaped(column) {
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
        column: format!("{table}.{column}"),
        passing,
        total_distinct: total_distinct.max(0) as u64,
    })
}
