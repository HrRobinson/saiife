//! The name-detector seam: plan 44 calls it, plans 46 and 47 implement it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpanLabel {
    Person,
    Org,
    Location,
    Misc,
}

/// Byte offsets into the question, on char boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameSpan {
    pub start: usize,
    pub end: usize,
    pub label: SpanLabel,
}

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("the name detector is not available: {0}")]
    Unavailable(String),
    #[error("the name detector failed")]
    Failed,
}

pub trait NameDetector: Send + Sync {
    fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError>;
}

/// Test fake: exact phrases to a label.
pub struct ListDetector {
    entries: Vec<(String, SpanLabel)>,
}

impl ListDetector {
    pub fn new(entries: &[(&str, SpanLabel)]) -> Self {
        ListDetector {
            entries: entries
                .iter()
                .filter(|(p, _)| !p.is_empty())
                .map(|(p, l)| ((*p).to_string(), *l))
                .collect(),
        }
    }
}

impl NameDetector for ListDetector {
    fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError> {
        let mut all: Vec<NameSpan> = Vec::new();
        for (phrase, label) in &self.entries {
            for (start, _) in text.match_indices(phrase.as_str()) {
                all.push(NameSpan {
                    start,
                    end: start + phrase.len(),
                    label: *label,
                });
            }
        }
        // Leftmost first, the longer phrase on a tie; overlapping spans dropped.
        all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut out: Vec<NameSpan> = Vec::new();
        for s in all {
            if out.last().is_none_or(|l| s.start >= l.end) {
                out.push(s);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_detector_finds_utf8_spans() {
        let d = ListDetector::new(&[("Søren Ærø", SpanLabel::Person)]);
        let spans = d.detect("Hvad skylder Søren Ærø?").unwrap();
        assert_eq!(
            spans,
            vec![NameSpan {
                start: 13,
                end: 25,
                label: SpanLabel::Person
            }]
        );
    }

    #[test]
    fn list_detector_drops_overlaps() {
        let d = ListDetector::new(&[("Ann", SpanLabel::Person), ("Ann Lee", SpanLabel::Person)]);
        let spans = d.detect("Ann Lee and Ann").unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!((spans[0].start, spans[0].end), (0, 7));
        assert_eq!((spans[1].start, spans[1].end), (12, 15));
    }
}
