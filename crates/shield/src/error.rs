//! Shield errors. No variant carries a cell value: only names, positions and
//! fixed reasons.

#[derive(Debug, thiserror::Error)]
pub enum ShieldError {
    #[error("a dataset name is 1 to 32 characters: a lowercase letter, then lowercase letters, digits or '-'")]
    BadName,
    #[error("{file}: {why}")]
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
        assert_eq!(e.to_string(), "a.csv: bad date");
    }
}
