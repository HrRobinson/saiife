//! `labels.json`: the id-to-label table and tokenizer/runtime settings (R46-2).

use crate::NerError;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Largest accepted labels file.
pub const LABELS_MAX_BYTES: usize = 64 * 1024;
/// Most labels a file may declare, and the exclusive bound of a label id.
pub const LABELS_MAX_COUNT: usize = 1024;
pub const MAX_LEN_RANGE: std::ops::RangeInclusive<usize> = 8..=4096;
const LABEL_MAX_CHARS: usize = 64;
const KNOWN_INPUTS: [&str; 3] = ["input_ids", "attention_mask", "token_type_ids"];

fn default_max_len() -> usize {
    512
}
fn default_inputs() -> Vec<String> {
    vec!["input_ids".to_string(), "attention_mask".to_string()]
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelsFile {
    pub id2label: BTreeMap<u32, String>,
    #[serde(default)]
    pub do_lower_case: bool,
    #[serde(default = "default_max_len")]
    pub max_len: usize,
    #[serde(default = "default_inputs")]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub strip_accents: bool,
}

impl LabelsFile {
    /// Labels indexed by id; ids the file leaves out read as "O".
    pub fn label_table(&self) -> Vec<String> {
        let n = self
            .id2label
            .keys()
            .next_back()
            .map_or(0, |m| *m as usize + 1);
        let mut t = vec!["O".to_string(); n];
        for (id, l) in &self.id2label {
            if let Some(slot) = t.get_mut(*id as usize) {
                *slot = l.clone();
            }
        }
        t
    }
}

pub fn parse_labels(bytes: &[u8]) -> Result<LabelsFile, NerError> {
    if bytes.len() > LABELS_MAX_BYTES {
        return Err(NerError::Labels("file too large"));
    }
    let f: LabelsFile =
        serde_json::from_slice(bytes).map_err(|_| NerError::Labels("not a valid labels file"))?;
    if f.id2label.is_empty() || f.id2label.len() > LABELS_MAX_COUNT {
        return Err(NerError::Labels("label count out of range"));
    }
    if f.id2label.keys().any(|k| *k as usize >= LABELS_MAX_COUNT) {
        return Err(NerError::Labels("label id out of range"));
    }
    if f.id2label
        .values()
        .any(|l| l.is_empty() || l.chars().count() > LABEL_MAX_CHARS)
    {
        return Err(NerError::Labels("label text out of range"));
    }
    if !MAX_LEN_RANGE.contains(&f.max_len) {
        return Err(NerError::Labels("max_len out of range"));
    }
    if f.inputs.len() > KNOWN_INPUTS.len()
        || !f.inputs.iter().any(|i| i == "input_ids")
        || f.inputs.iter().any(|i| !KNOWN_INPUTS.contains(&i.as_str()))
        || (1..f.inputs.len()).any(|i| f.inputs[..i].contains(&f.inputs[i]))
    {
        return Err(NerError::Labels("unsupported inputs"));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_file_rules() {
        let ok = br#"{"id2label":{"0":"O","1":"B-PER","2":"I-PER"},"do_lower_case":true,"max_len":512,"inputs":["input_ids","attention_mask"],"strip_accents":false}"#;
        let f = parse_labels(ok).unwrap();
        assert_eq!(f.id2label.len(), 3);
        assert!(f.do_lower_case);
        assert_eq!(f.label_table(), vec!["O", "B-PER", "I-PER"]);
        assert!(parse_labels(br#"{"do_lower_case":true,"max_len":512}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{"0":"O"},"extra":1}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{"0":"O"},"max_len":2}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{"0":"O"},"max_len":99999}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{"0":"O"},"inputs":["bogus"]}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{"5000":"O"}}"#).is_err());
        assert!(parse_labels(br#"{"id2label":{}}"#).is_err());
        assert!(parse_labels(&vec![b' '; LABELS_MAX_BYTES + 1]).is_err());
        assert!(parse_labels(b"\xff\xfe").is_err());
    }
}
