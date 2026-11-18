//! Window planning and BIO/IOB decoding (R46-5).

use crate::wordpiece::Encoding;
use saiife_shield::ner_proto::WireSpan;

/// Piece ranges of token windows of `max_len - 2` (room for `[CLS]` and
/// `[SEP]`) with a stride of half a window. The last window ends at the
/// last piece.
pub fn windows(enc: &Encoding, max_len: usize) -> Vec<(usize, usize)> {
    let n = enc.ids.len();
    let size = max_len.saturating_sub(2).max(1);
    let stride = (size / 2).max(1);
    let mut out = Vec::new();
    let mut start = 0;
    while start < n {
        let end = (start + size).min(n);
        out.push((start, end));
        if end == n {
            break;
        }
        start += stride;
    }
    out
}

/// Merge per-window predictions (one `(label id, prob)` per piece of the
/// window) into one list over all `total` pieces. The first window wins on
/// overlap; pieces no window covers get `(0, 0.0)`.
pub fn merge_windows(
    total: usize,
    windows: &[(usize, usize)],
    per_window: &[Vec<(usize, f32)>],
) -> Vec<(usize, f32)> {
    let mut out: Vec<Option<(usize, f32)>> = vec![None; total];
    for ((start, end), preds) in windows.iter().zip(per_window) {
        let end = (*end).min(total);
        for (k, p) in preds.iter().enumerate() {
            let Some(i) = start.checked_add(k) else { break };
            if i >= end {
                break;
            }
            if let Some(slot) = out.get_mut(i) {
                if slot.is_none() {
                    *slot = Some(*p);
                }
            }
        }
    }
    out.into_iter().map(|s| s.unwrap_or((0, 0.0))).collect()
}

fn wire_label(x: &str) -> Option<&'static str> {
    match x.to_ascii_uppercase().as_str() {
        "PER" => Some("PER"),
        "ORG" => Some("ORG"),
        "LOC" => Some("LOC"),
        "MISC" => Some("MISC"),
        _ => None,
    }
}

/// `(is_begin, wire label)` of a model label, `None` for O and anything else.
fn parse_tag(l: &str) -> Option<(bool, &'static str)> {
    if let Some(x) = l.strip_prefix("B-").or_else(|| l.strip_prefix("b-")) {
        wire_label(x).map(|w| (true, w))
    } else if let Some(x) = l.strip_prefix("I-").or_else(|| l.strip_prefix("i-")) {
        wire_label(x).map(|w| (false, w))
    } else {
        wire_label(l).map(|w| (false, w))
    }
}

/// The wire entity kind of a model label (`B-PER` -> `PER`), `None` for O
/// and unknown kinds.
pub(crate) fn wire_kind(l: &str) -> Option<&'static str> {
    parse_tag(l).map(|(_, w)| w)
}

struct Open {
    label: &'static str,
    start: usize,
    end: usize,
    sum: f32,
    n: u32,
}

fn close(cur: &mut Option<Open>, out: &mut Vec<WireSpan>) {
    if let Some(o) = cur.take() {
        let mean = o.sum / o.n.max(1) as f32;
        out.push(WireSpan {
            start: o.start,
            end: o.end,
            label: o.label.to_string(),
            score: if mean.is_finite() { mean } else { 0.0 },
        });
    }
}

/// Spans from per-piece `(label id, probability)`. Only each word's first
/// piece votes. A `B-X` starts a span, a following `I-X` extends it, a
/// stray `I-X` starts one (IOB1 tolerance). Score = mean first-piece prob.
/// Tolerates any length mismatch: pieces without a prediction end a span,
/// unknown label ids and unknown entity kinds read as outside.
pub fn decode_bio(
    enc: &Encoding,
    labels: &[String],
    probs_per_piece: &[(usize, f32)],
) -> Vec<WireSpan> {
    let mut out = Vec::new();
    let mut cur: Option<Open> = None;
    for (i, w) in enc.word_of_piece.iter().enumerate() {
        let Some(w) = w else { continue };
        let tag = probs_per_piece
            .get(i)
            .and_then(|(id, p)| Some((labels.get(*id)?, *p)))
            .and_then(|(l, p)| parse_tag(l).map(|t| (t, p)));
        let range = enc.words.get(*w).copied();
        let (Some(((begin, label), p)), Some((ws, we))) = (tag, range) else {
            close(&mut cur, &mut out);
            continue;
        };
        let p = if p.is_finite() { p } else { 0.0 };
        match cur.as_mut() {
            Some(o) if !begin && o.label == label => {
                o.end = we;
                o.sum += p;
                o.n += 1;
            }
            _ => {
                close(&mut cur, &mut out);
                cur = Some(Open {
                    label,
                    start: ws,
                    end: we,
                    sum: p,
                    n: 1,
                });
            }
        }
    }
    close(&mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels() -> Vec<String> {
        ["O", "B-PER", "I-PER", "B-LOC", "I-LOC", "B-ORG", "I-ORG"]
            .map(String::from)
            .to_vec()
    }

    fn enc_words(n: usize) -> Encoding {
        // one piece per word, words "a" at 2-byte stride
        Encoding {
            ids: vec![1; n],
            word_of_piece: (0..n).map(Some).collect(),
            words: (0..n).map(|i| (i * 2, i * 2 + 1)).collect(),
        }
    }

    #[test]
    fn bio_spans() {
        // B-PER I-PER O B-LOC
        let e = enc_words(4);
        let p = [(1, 0.9), (2, 0.7), (0, 0.99), (3, 0.5)];
        let s = decode_bio(&e, &labels(), &p);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].start, s[0].end, s[0].label.as_str()), (0, 3, "PER"));
        assert!((s[0].score - 0.8).abs() < 1e-6);
        assert_eq!((s[1].start, s[1].end, s[1].label.as_str()), (6, 7, "LOC"));
        // a stray I-ORG starts a span
        let s = decode_bio(&e, &labels(), &[(0, 1.0), (6, 0.6), (6, 0.8), (0, 1.0)]);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].start, s[0].end, s[0].label.as_str()), (2, 5, "ORG"));
        // B after B of the same kind splits; I of another kind splits
        let s = decode_bio(&e, &labels(), &[(1, 1.0), (1, 1.0), (4, 1.0), (4, 1.0)]);
        assert_eq!(s.len(), 3);
        // continuation pieces do not vote
        let mut e2 = enc_words(2);
        e2.ids.push(1);
        e2.word_of_piece.push(None);
        let s = decode_bio(&e2, &labels(), &[(1, 0.9), (0, 1.0), (2, 0.1)]);
        assert_eq!(s.len(), 1);
        assert!((s[0].score - 0.9).abs() < 1e-6);
        // mismatched lengths and bad ids never panic
        assert!(decode_bio(&e, &labels(), &[]).is_empty());
        assert_eq!(decode_bio(&e, &labels(), &[(1, 1.0)]).len(), 1);
        assert!(decode_bio(&e, &labels(), &[(999, 1.0), (usize::MAX, f32::NAN)]).is_empty());
        let lc = ["O".to_string(), "b-per".to_string()];
        assert_eq!(decode_bio(&e, &lc, &[(1, f32::NAN)])[0].score, 0.0);
    }

    #[test]
    fn windows_overlap_once() {
        let e = enc_words(1200);
        let ws = windows(&e, 512);
        assert_eq!(ws[0], (0, 510));
        assert_eq!(ws[1], (255, 765));
        assert_eq!(ws.last().unwrap().1, 1200);
        for pair in ws.windows(2) {
            assert_eq!(pair[1].0 - pair[0].0, 255);
        }
        assert!(windows(&Encoding::default(), 512).is_empty());
        assert_eq!(windows(&enc_words(5), 512), vec![(0, 5)]);
        // a name (B-PER I-PER) at pieces 300..302 lies in windows 0 and 1
        let per_window: Vec<Vec<(usize, f32)>> = ws
            .iter()
            .map(|(a, b)| {
                (*a..*b)
                    .map(|i| match i {
                        300 => (1, 0.9),
                        301 => (2, 0.8),
                        _ => (0, 0.99),
                    })
                    .collect()
            })
            .collect();
        let merged = merge_windows(1200, &ws, &per_window);
        assert_eq!(merged.len(), 1200);
        let spans = decode_bio(&e, &labels(), &merged);
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start, spans[0].end), (600, 603));
        // short or empty window predictions never panic
        let m = merge_windows(10, &[(0, 20), (5, 8)], &[vec![(1, 1.0)], vec![]]);
        assert_eq!(m.len(), 10);
        assert!(!windows(&e, 0).is_empty());
    }
}
