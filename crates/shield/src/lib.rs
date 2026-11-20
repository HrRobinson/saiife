//! saiife Data Shield: the schema vocabulary, snapshot, index and method
//! checking behind the blind-data path. Tokio-free (spec §4.2).
#![forbid(unsafe_code)]

pub mod answer;
pub mod calc;
pub mod calc_proto;
pub mod checker;
pub mod classify;
pub mod dataset;
pub mod envelope;
pub mod error;
pub mod firewall;
pub(crate) mod grammar;
pub mod index;
pub mod lang;
pub mod lexicon;
pub mod methods;
pub mod ner;
pub mod ner_proto;
pub mod norm;
pub mod plan;
pub mod preview;
pub mod public;
pub mod question;
pub mod schema;
pub mod session;
pub mod snapshot;
pub mod source;
pub mod sql;
pub mod standin;
pub mod synth;
pub mod template;

pub use error::ShieldError;
