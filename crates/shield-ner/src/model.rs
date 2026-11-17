//! ONNX token classification with the pure-Rust `tract` runtime (R46-2,
//! R46-5).
//!
//! The model file is untrusted input to tract: every tract error maps to a
//! fixed text (tract's own messages never leave this module), tract calls
//! run under `catch_unwind`, and the output shape is checked before any
//! value is read.

use crate::bio::{decode_bio, merge_windows, windows, wire_kind};
use crate::labels::{parse_labels, LabelsFile};
use crate::wordpiece::WordPiece;
use crate::NerError;
use saiife_shield::ner_proto::{WireSpan, MAX_TEXT};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tract_onnx::prelude::*;

/// Largest accepted model file (fp32 BERT-base NER exports are ~700 MB).
pub const MODEL_MAX_BYTES: usize = 2 * 1024 * 1024 * 1024;

const PARSE: NerError = NerError::Model("cannot parse the model");
const GRAPH: NerError = NerError::Model("unsupported model graph");
const INPUTS: NerError = NerError::Model("model inputs do not match the labels file");
const MISMATCH: NerError = NerError::Model("labels do not match the model output");
const FAILED: NerError = NerError::Model("inference failed");

/// What each model input is fed, in the model's input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Feed {
    Ids,
    Mask,
    TypeIds,
}

pub struct NerModel {
    plan: Arc<TypedRunnableModel>,
    feeds: Vec<Feed>,
    wp: WordPiece,
    labels: LabelsFile,
    table: Vec<String>,
}

/// Runs `f`, turning a panic inside tract into a fixed-text error.
fn guarded<T>(f: impl FnOnce() -> Result<T, NerError>, on_panic: NerError) -> Result<T, NerError> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(on_panic))
}

fn build_plan(
    bytes: &[u8],
    names: &[String],
    n_labels: usize,
) -> Result<(Arc<TypedRunnableModel>, Vec<Feed>), NerError> {
    let mut m = tract_onnx::onnx()
        .model_for_read(&mut &bytes[..])
        .map_err(|_| PARSE)?;
    let outlets = m.input_outlets().map_err(|_| GRAPH)?.to_vec();
    if outlets.len() != names.len() {
        return Err(INPUTS);
    }
    let s = m.symbols.sym("S");
    let mut feeds = Vec::with_capacity(outlets.len());
    for (ix, o) in outlets.iter().enumerate() {
        let name = m.nodes.get(o.node).map(|n| n.name.as_str()).ok_or(GRAPH)?;
        if !names.iter().any(|n| n == name) {
            return Err(INPUTS);
        }
        let feed = match name {
            "input_ids" => Feed::Ids,
            "attention_mask" => Feed::Mask,
            "token_type_ids" => Feed::TypeIds,
            _ => return Err(INPUTS),
        };
        if feeds.contains(&feed) {
            return Err(INPUTS);
        }
        feeds.push(feed);
        let fact = InferenceFact::dt_shape(i64::datum_type(), tvec![1.to_dim(), s.to_dim()]);
        m.set_input_fact(ix, fact).map_err(|_| GRAPH)?;
    }
    // Only the first output (the logits) is used.
    let first = *m
        .output_outlets()
        .map_err(|_| GRAPH)?
        .first()
        .ok_or(GRAPH)?;
    m.select_output_outlets(&[first]).map_err(|_| GRAPH)?;
    let typed = m.into_optimized().map_err(|_| GRAPH)?;
    let fact = typed.output_fact(0).map_err(|_| GRAPH)?;
    if fact.shape.rank() != 3 {
        return Err(GRAPH);
    }
    if let Some(last) = fact.shape.dims().get(2).and_then(TDim::as_i64) {
        if usize::try_from(last).ok() != Some(n_labels) {
            return Err(MISMATCH);
        }
    }
    let plan = typed.into_runnable().map_err(|_| GRAPH)?;
    Ok((plan, feeds))
}

/// `(argmax, softmax probability of it)` for one piece's logits. Safe on
/// NaN and infinities: NaN reads as the lowest value, infinities clamp to
/// the finite range, and the max is subtracted before `exp`.
fn best_label(row: &[f32]) -> (usize, f32) {
    let clean = |x: f32| {
        if x.is_nan() {
            f32::MIN
        } else {
            x.clamp(f32::MIN, f32::MAX)
        }
    };
    let mut best = (0usize, f32::MIN);
    for (i, x) in row.iter().map(|x| clean(*x)).enumerate() {
        if x > best.1 {
            best = (i, x);
        }
    }
    let sum: f32 = row.iter().map(|x| (clean(*x) - best.1).exp()).sum();
    let p = if sum.is_finite() && sum >= 1.0 {
        1.0 / sum
    } else {
        0.0
    };
    (best.0, p)
}

impl NerModel {
    /// Bytes are already hash-checked by the caller.
    pub fn load(model: &[u8], vocab: &[u8], labels: &[u8]) -> Result<NerModel, NerError> {
        let labels = parse_labels(labels)?;
        let wp = WordPiece::from_vocab(vocab, labels.do_lower_case, labels.strip_accents)?;
        if model.len() > MODEL_MAX_BYTES {
            return Err(NerError::Model("model file too large"));
        }
        let table = labels.label_table();
        let (plan, feeds) = guarded(|| build_plan(model, &labels.inputs, table.len()), PARSE)?;
        Ok(NerModel {
            plan,
            feeds,
            wp,
            labels,
            table,
        })
    }

    /// Distinct entity types the labels file declares (PER, ORG, LOC, MISC
    /// order), for the helper's hello.
    pub fn labels(&self) -> Vec<String> {
        ["PER", "ORG", "LOC", "MISC"]
            .into_iter()
            .filter(|k| self.table.iter().any(|l| wire_kind(l) == Some(*k)))
            .map(String::from)
            .collect()
    }

    pub fn detect(&self, text: &str) -> Result<Vec<WireSpan>, NerError> {
        if text.len() > MAX_TEXT {
            return Err(NerError::Model("text too long"));
        }
        let enc = self.wp.encode(text);
        if enc.ids.is_empty() {
            return Ok(Vec::new());
        }
        let ws = windows(&enc, self.labels.max_len);
        let mut per_window = Vec::with_capacity(ws.len());
        for (a, b) in &ws {
            let content = enc.ids.get(*a..*b).ok_or(FAILED)?;
            per_window.push(guarded(|| self.run_window(content), FAILED)?);
        }
        let merged = merge_windows(enc.ids.len(), &ws, &per_window);
        Ok(decode_bio(&enc, &self.table, &merged))
    }

    /// `[CLS] content [SEP]` through the model; one `(label id, prob)` per
    /// content piece.
    fn run_window(&self, content: &[i64]) -> Result<Vec<(usize, f32)>, NerError> {
        let mut ids = Vec::with_capacity(content.len() + 2);
        ids.push(self.wp.cls_id());
        ids.extend_from_slice(content);
        ids.push(self.wp.sep_id());
        let s = ids.len();
        let mut inputs: TVec<TValue> = tvec![];
        for feed in &self.feeds {
            let data = match feed {
                Feed::Ids => ids.clone(),
                Feed::Mask => vec![1i64; s],
                Feed::TypeIds => vec![0i64; s],
            };
            let t = Tensor::from_shape(&[1, s], &data).map_err(|_| FAILED)?;
            inputs.push(t.into_tvalue());
        }
        let out = self.plan.run(inputs).map_err(|_| FAILED)?;
        let logits = out.into_iter().next().ok_or(FAILED)?;
        let logits = logits.cast_to::<f32>().map_err(|_| FAILED)?;
        let n = self.table.len();
        match logits.shape() {
            [1, rows, labels] if *rows == s && *labels == n && n > 0 => {}
            [1, rows, _] if *rows == s => return Err(MISMATCH),
            _ => return Err(FAILED),
        }
        let view = logits.to_plain_array_view::<f32>().map_err(|_| FAILED)?;
        let flat: Vec<f32> = view.iter().copied().collect();
        if flat.len() != s.saturating_mul(n) {
            return Err(FAILED);
        }
        // Row 0 is [CLS], the last row is [SEP].
        Ok(flat
            .chunks_exact(n)
            .skip(1)
            .take(content.len())
            .map(best_label)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::best_label;

    #[test]
    fn softmax_is_safe() {
        let (i, p) = best_label(&[0.0, 10.0, 0.0]);
        assert_eq!(i, 1);
        assert!(p > 0.99 && p <= 1.0);
        let (i, p) = best_label(&[1e30, 1e30 + 1.0, -1e30]);
        assert!(i < 3 && p.is_finite() && p > 0.0);
        let (i, p) = best_label(&[f32::NAN, f32::INFINITY, f32::NEG_INFINITY]);
        assert_eq!(i, 1);
        assert!((p - 1.0).abs() < 1e-6);
        let (_, p) = best_label(&[f32::NAN, f32::NAN]);
        assert!((p - 0.5).abs() < 1e-6);
        let (_, p) = best_label(&[f32::INFINITY, f32::INFINITY]);
        assert!((p - 0.5).abs() < 1e-6);
        assert_eq!(best_label(&[]), (0, 0.0));
    }
}
