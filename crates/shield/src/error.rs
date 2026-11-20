//! Shield errors. No variant carries a cell value: only names, positions and
//! fixed reasons.

#[derive(Debug, thiserror::Error)]
pub enum ShieldError {
    #[error("a dataset name is 1 to 32 characters: a lowercase letter, then lowercase letters, digits or '-'")]
    BadName,
    #[error("{}", source_text(file, table, column, row, why))]
    Source {
        file: String,
        table: Option<String>,
        column: Option<String>,
        row: Option<u64>,
        why: &'static str,
    },
    #[error("over a limit: {0}")]
    Limit(&'static str),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("SQLite error: {0}")]
    Sqlite(String),
    #[error("corrupt data: {0}")]
    Corrupt(&'static str),
    /// Plan 48 C5 (D51-4): a key-side column (an entity key, or the key
    /// side of a join) holds repeated or empty values. Names and a count
    /// only, never a value: the text is [`repeated_key_reason`].
    #[error("{}", repeated_key_reason(table, column, *rows))]
    RepeatedKey {
        table: String,
        column: String,
        /// The rows without a key of their own: every row whose key is
        /// empty, or shared with another row.
        rows: u64,
    },
}

/// The fixed refusal of a build whose key-side column `table.column` has
/// repeated or empty values in `rows` rows (plan 48 C5, D51-4). It holds
/// names and a count only, so it is safe to show and to send anywhere.
pub fn repeated_key_reason(table: &str, column: &str, rows: u64) -> String {
    format!(
        "{table}.{column} has repeated or empty values; each row needs its own {column} \
         ({rows} rows affected)"
    )
}

/// `file, table t, column c, row 7: why`: names and positions only.
fn source_text(
    file: &str,
    table: &Option<String>,
    column: &Option<String>,
    row: &Option<u64>,
    why: &str,
) -> String {
    let mut s = file.to_string();
    if let Some(t) = table {
        s.push_str(", table ");
        s.push_str(t);
    }
    if let Some(c) = column {
        s.push_str(", column ");
        s.push_str(c);
    }
    if let Some(r) = row {
        s.push_str(&format!(", row {r}"));
    }
    s.push_str(": ");
    s.push_str(why);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_text_has_no_cell() {
        let e = ShieldError::Source {
            file: "a.csv".into(),
            table: Some("t".into()),
            column: Some("c".into()),
            row: Some(3),
            why: "bad date",
        };
        assert_eq!(e.to_string(), "a.csv, table t, column c, row 3: bad date");
        let e = ShieldError::Source {
            file: "a.csv".into(),
            table: None,
            column: None,
            row: Some(9),
            why: "bad date",
        };
        assert_eq!(e.to_string(), "a.csv, row 9: bad date");
    }
}
