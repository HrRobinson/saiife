//! Plan 43: public (filled in by a later task of plan 43).

use serde::{Deserialize, Serialize};

/// The k-floor public values of one column.
/// Provisional copy of plan 43 Task 4's type; plan 43's file wins at merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicValues {
    /// `"<snapshot table>.<snapshot column>"`.
    pub column: String,
    /// The values that pass the k-floor, as text.
    pub passing: Vec<String>,
    pub total_distinct: u64,
}
