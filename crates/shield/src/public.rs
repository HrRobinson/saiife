//! Plan 43 T4: public marks. A `public` column is refused when it holds names,
//! IDs or amounts; otherwise only values seen at least `k` times are listed.

use crate::classify::{
    checks, guess, id_shaped, identifier_share, looks_like_identifier, source_id_shaped,
    sqlite_err, ColumnStats, UNKNOWN,
};
use crate::error::ShieldError;
use crate::norm::normalize;
use crate::schema::{ColType, ColumnClass, EntitySpec, Schema, TableInfo};
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

/// S4: the one public gate. The source name (R-22: `CustomerID`, which
/// the snapshot calls `customerid`) through [`source_id_shaped`], then
/// [`public_refusal`], then the policy's entity columns (`propose` has no
/// policy yet and passes none).
pub(crate) fn public_gate(
    entities: &[EntitySpec],
    table: &str,
    name: &str,
    source: Option<&str>,
    ty: ColType,
    st: &ColumnStats,
    sample: &[String],
) -> Option<&'static str> {
    if source.is_some_and(source_id_shaped) {
        return Some("holds names or IDs");
    }
    public_refusal(name, ty, st, sample).or_else(|| {
        entity_column(entities, table, name).then_some("an entity's key or name column")
    })
}

/// I4 (owner ruling): why a table's frequency floors cannot be counted.
pub const NO_IDENTIFIER: &str = "holds personal data but no column identifies the person; \
                                 choose the column that identifies the person";

/// How the frequency floors of one table count people: an SQL aggregate
/// over the table's rows, made only by [`people_count`] (or
/// [`PeopleCount::rows`] for a table without personal data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeopleCount(String);

impl PeopleCount {
    /// `COUNT(*)`: for a table that holds no personal data.
    pub fn rows() -> PeopleCount {
        PeopleCount("COUNT(*)".to_string())
    }

    /// The aggregate, for `SELECT v, <it> ... GROUP BY v`.
    pub fn sql(&self) -> &str {
        &self.0
    }
}

/// A name column (`name`, `first_name`, `navn`, `efternavn`, ...): it
/// names a person but two people can share it.
fn name_column(n: &str) -> bool {
    ["name", "navn", "fornavn", "efternavn"]
        .iter()
        .any(|w| crate::classify::name_part(n, w))
}

/// I4 (owner ruling), the one counting rule of every frequency floor (the
/// index's k-floor, `public_values`, the wizard's preview). A table's
/// floors count, first that applies:
/// 1. with an EntitySpec: distinct entity keys (R-14);
/// 2. else, with id columns (Identifier columns that are not name columns,
///    and `links`: FK columns of declared joins): the smallest of their
///    distinct counts. The smallest, not a composite: a per-row id
///    (`order_id`) beside a per-person one (`customer_id`) must not count
///    every order as a person, and undercounting only keeps more values
///    rare (fails closed). A value of an id column counts as 1: an
///    identifier is never a common value;
/// 3. else, with name columns of class Identifier: distinct full names
///    (the composite of the name columns, NULLs ignored);
/// 4. else, a table with personal data (an Identifier or Quasi column, or
///    a link) is refused with [`NO_IDENTIFIER`];
/// 5. else rows.
pub fn people_count(
    t: &TableInfo,
    entity_key: Option<&str>,
    links: &[&str],
) -> Result<PeopleCount, ShieldError> {
    if let Some(k) = entity_key {
        return Ok(PeopleCount(format!("COUNT(DISTINCT {})", quote(k))));
    }
    let ident = |c: &&crate::schema::ColumnInfo| c.class == ColumnClass::Identifier;
    let mut ids: Vec<&str> = t
        .columns
        .iter()
        .filter(|c| ident(c) && !name_column(&c.name))
        .map(|c| c.name.as_str())
        .collect();
    for l in links {
        if !ids.contains(l) {
            ids.push(l);
        }
    }
    let distinct = |c: &str| format!("COUNT(DISTINCT {})", quote(c));
    match ids.len() {
        0 => {}
        1 => return Ok(PeopleCount(distinct(ids[0]))),
        _ => {
            let parts: Vec<String> = ids.iter().map(|c| distinct(c)).collect();
            return Ok(PeopleCount(format!("MIN({})", parts.join(", "))));
        }
    }
    let names: Vec<String> = t
        .columns
        .iter()
        .filter(ident)
        .map(|c| quote(&c.name))
        .collect();
    match names.len() {
        0 => {}
        1 => return Ok(PeopleCount(format!("COUNT(DISTINCT {})", names[0]))),
        _ => {
            // `quote()` renders each value as an SQL literal, so the
            // joined text is unambiguous; all NULL is no name at all.
            let all_null = names
                .iter()
                .map(|n| format!("{n} IS NULL"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let joined = names
                .iter()
                .map(|n| format!("quote({n})"))
                .collect::<Vec<_>>()
                .join(" || ',' || ");
            return Ok(PeopleCount(format!(
                "COUNT(DISTINCT CASE WHEN {all_null} THEN NULL ELSE {joined} END)"
            )));
        }
    }
    if t.columns.iter().any(|c| c.class == ColumnClass::Quasi) {
        return Err(ShieldError::Source {
            file: "policy".into(),
            table: Some(t.name.clone()),
            column: None,
            row: None,
            why: NO_IDENTIFIER,
        });
    }
    Ok(PeopleCount::rows())
}

/// [`people_count`] for a schema table: its EntitySpec key and the FK
/// columns of the schema's joins.
pub fn table_people_count(schema: &Schema, table: &str) -> Result<PeopleCount, ShieldError> {
    let t = schema.table(table).ok_or(ShieldError::Corrupt(
        "the schema does not match the snapshot",
    ))?;
    let links: Vec<&str> = schema
        .joins
        .iter()
        .filter(|j| j.table == table)
        .map(|j| j.column.as_str())
        .collect();
    people_count(t, schema.entity_for(table).map(|e| e.key.as_str()), &links)
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

/// The values held by at least `k` people (`count`, from [`people_count`]),
/// as text, in memory only. More than 1000 of them is not a category: the
/// mark is refused with a fixed reason. The caller runs `public_refusal`
/// first; the name check here is a backstop.
pub fn public_values(
    conn: &Connection,
    table: &str,
    column: &str,
    k: u32,
    count: &PeopleCount,
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
    let people = count.sql();
    let sql = format!(
        "SELECT CAST({c} AS TEXT) FROM {t} WHERE {c} IS NOT NULL \
         GROUP BY {c} HAVING {people} >= ?1 ORDER BY {c} LIMIT ?2"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ColumnInfo;

    fn table(cols: &[(&str, ColumnClass)]) -> TableInfo {
        TableInfo {
            name: "t".into(),
            alias: None,
            rows: 0,
            columns: cols
                .iter()
                .map(|(n, c)| ColumnInfo {
                    name: (*n).into(),
                    ty: ColType::Text,
                    class: *c,
                    alias: None,
                })
                .collect(),
        }
    }

    /// I4: the one counting rule, case by case.
    #[test]
    fn people_count_rules() {
        use ColumnClass::*;
        let sql = |t: &TableInfo, key: Option<&str>, links: &[&str]| {
            people_count(t, key, links).map(|c| c.sql().to_string())
        };
        let cust = table(&[("id", Identifier), ("name", Identifier), ("city", Quasi)]);
        assert_eq!(
            sql(&cust, Some("id"), &[]).unwrap(),
            "COUNT(DISTINCT \"id\")"
        );
        // Name columns are not ids: `name` is left out.
        assert_eq!(sql(&cust, None, &[]).unwrap(), "COUNT(DISTINCT \"id\")");
        let orders = table(&[
            ("order_id", Identifier),
            ("email", Identifier),
            ("first_name", Identifier),
            ("city", Quasi),
        ]);
        assert_eq!(
            sql(&orders, None, &["customer_id"]).unwrap(),
            "MIN(COUNT(DISTINCT \"order_id\"), COUNT(DISTINCT \"email\"), \
             COUNT(DISTINCT \"customer_id\"))"
        );
        let names = table(&[
            ("fornavn", Identifier),
            ("efternavn", Identifier),
            ("by", Quasi),
        ]);
        assert_eq!(
            sql(&names, None, &[]).unwrap(),
            "COUNT(DISTINCT CASE WHEN \"fornavn\" IS NULL AND \"efternavn\" IS NULL \
             THEN NULL ELSE quote(\"fornavn\") || ',' || quote(\"efternavn\") END)"
        );
        // A link alone is enough.
        let visits = table(&[("customer_id", Sensitive), ("city", Quasi)]);
        assert_eq!(
            sql(&visits, None, &["customer_id"]).unwrap(),
            "COUNT(DISTINCT \"customer_id\")"
        );
        let e = people_count(&visits, None, &[]).unwrap_err();
        assert!(matches!(
            e,
            ShieldError::Source {
                why: NO_IDENTIFIER,
                ..
            }
        ));
        // No personal data: rows.
        let plain = table(&[("status", Public), ("amount", Sensitive), ("n", FreeText)]);
        assert_eq!(sql(&plain, None, &[]).unwrap(), "COUNT(*)");
        assert_eq!(PeopleCount::rows().sql(), "COUNT(*)");
    }

    /// The composite never merges two different name pairs.
    #[test]
    fn composite_names_do_not_collide() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE t (first_name TEXT, last_name TEXT, s TEXT);
             INSERT INTO t VALUES ('x,y', 'z', 's'), ('x', 'y,z', 's'),
                                  ('x''', 'y', 's'), ('x', NULL, 's'),
                                  (NULL, 'x', 's'), (NULL, NULL, 's');",
        )
        .unwrap();
        let t = TableInfo {
            name: "t".into(),
            alias: None,
            rows: 0,
            columns: ["first_name", "last_name"]
                .iter()
                .map(|n| crate::schema::ColumnInfo {
                    name: (*n).into(),
                    ty: ColType::Text,
                    class: ColumnClass::Identifier,
                    alias: None,
                })
                .chain(std::iter::once(crate::schema::ColumnInfo {
                    name: "s".into(),
                    ty: ColType::Text,
                    class: ColumnClass::Public,
                    alias: None,
                }))
                .collect(),
        };
        let count = people_count(&t, None, &[]).unwrap();
        let n: i64 = c
            .query_row(&format!("SELECT {} FROM t", count.sql()), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 5, "all-NULL is nobody; every other pair is distinct");
    }
}
