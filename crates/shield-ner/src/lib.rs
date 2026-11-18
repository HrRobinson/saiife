//! saiife Data Shield local name detector: labels file, WordPiece tokenizer,
//! BIO decoding and the tract (ONNX) runtime. Tokio-free.
#![forbid(unsafe_code)]

pub mod bio;
pub mod labels;
pub mod model;
pub mod serve;
pub mod wordpiece;

pub use bio::{decode_bio, merge_windows, windows};
pub use labels::{parse_labels, LabelsFile};
pub use model::NerModel;
pub use wordpiece::{Encoding, WordPiece};

/// Errors carry fixed texts only: never input text or parser messages.
#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("bad labels file: {0}")]
    Labels(&'static str),
    #[error("bad vocab file")]
    Vocab,
    #[error("model: {0}")]
    Model(&'static str),
    #[error("hash mismatch for {0}")]
    Hash(&'static str),
}
